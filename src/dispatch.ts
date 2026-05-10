#!/usr/bin/env bun
// Tripwire — Claude Code hooks dispatcher.
//
// Reads a hook event JSON payload on stdin, routes by hook_event_name +
// Tool_name, runs rules with per-rule timeouts, merges decisions
// (most-restrictive wins), wraps allowed Bash commands through rtk for
// Token-saver rewriting, scans PostToolUse output for secrets via
// Betterleaks, and writes Claude Code's expected JSON response on stdout.
//
// Design rules:
//   - A buggy or slow rule must never block the agent. Every rule runs
//     Under a timeout; any defect or timeout collapses to `allow`, logged.
//   - Block messages address the agent in second person and name the
//     Concrete alternative tool / approach. No vague "denied for safety".
//   - One bypass token: `tripwire-allow` (any comment syntax) on a code
//     Line, or `# tripwire-allow` in a bash command.

import { BunRuntime } from '@effect/platform-bun';
import { Cause, Effect, Exit, Schema } from 'effect';

import { parseCommand } from './lib/bash';
import { loadConfig, type Config } from './lib/config';
import { type Decision, allow, merge } from './lib/decision';
import {
  type BashInput,
  type EditInput,
  type HookEvent,
  HookEventSchema,
  type ReadInput,
  type WriteInput,
  isBashInput,
  isEditInput,
  isReadInput,
  isWriteInput,
} from './lib/event.ts';
import { logError } from './lib/log';
import { runRtkRewrite } from './lib/rtk';
import { bashDeny } from './rules/bash-deny';
import { bashGit } from './rules/bash-git';
import { bashNetworkInstall } from './rules/bash-network-install';
import { bashRedirect } from './rules/bash-redirect';
import { bashScopedRm } from './rules/bash-scoped-rm';
import { bashTarExplosion } from './rules/bash-tar-explosion';
import { bashToolPolicy } from './rules/bash-tool-policy';
import { configCustom } from './rules/config-custom';
import { lazyCode } from './rules/lazy-code';
import { pathProtect } from './rules/path-protect';
import { postSecretScrub } from './rules/post-secret-scrub';
import { readProtect } from './rules/read-protect';

const RULE_TIMEOUT_MS = 250;
const POST_RULE_TIMEOUT_MS = 5000; // Betterleaks subprocess can take longer

const readStdin = async (): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
};

const writeAllow = (): void => {
  process.stdout.write('{"continue": true}\n');
};

// Codex's PreToolUse hook rejects `hookSpecificOutput.additionalContext`
// (openai/codex issue #19385) and `updatedInput` (#18491). Detect Codex
// Via its `turn_id` extension and downgrade output accordingly. Claude
// Code accepts both, so we only narrow when we can confirm we're on Codex.
const isCodex = (event: HookEvent): boolean => event.turn_id !== undefined;

const writeRewriteAllow = (event: HookEvent, command: string, _reason?: string): void => {
  // Codex's PreToolUse parser strict-rejects `updatedInput` (openai/codex
  // #18491 — parsed but unimplemented as of codex-cli 0.12x). On Codex we
  // Can't transparently rewrite, so pass the original command through
  // Silently. Until #18491 lands, RTK savings are Claude-only.
  if (isCodex(event)) {
    writeAllow();
    return;
  }
  // Claude Code: rewrite silently. We deliberately omit
  // `permissionDecisionReason` so the model's context isn't polluted with
  // "rtk rewrote your command" chatter every Bash call.
  const out = {
    continue: true,
    hookSpecificOutput: { hookEventName: event.hook_event_name, updatedInput: { command } },
  };
  process.stdout.write(`${JSON.stringify(out)}\n`);
};

interface WarnOutput {
  hookEventName: string;
  additionalContext?: string;
  updatedInput?: { command: string };
}

const writeWarn = (event: HookEvent, decision: Decision): void => {
  const eventName = event.hook_event_name;
  const reason = `[tripwire:${decision.rule}] ${decision.message}`;
  if (isCodex(event)) {
    // Codex rejects both `additionalContext` and `updatedInput` on
    // PreToolUse. Send only `systemMessage`; the rewrite (if any) is
    // Dropped and the original command runs.
    process.stdout.write(`${JSON.stringify({ continue: true, systemMessage: reason })}\n`);
    return;
  }
  const hookSpecificOutput: WarnOutput = { hookEventName: eventName, additionalContext: reason };
  if (decision.rewriteCommand !== undefined) {
    hookSpecificOutput.updatedInput = { command: decision.rewriteCommand };
  }
  process.stdout.write(`${JSON.stringify({ continue: true, hookSpecificOutput })}\n`);
};

const writePreToolGate = (eventName: string, decision: Decision): void => {
  const out = {
    hookSpecificOutput: {
      hookEventName: eventName,
      permissionDecision: decision.kind === 'deny' ? 'deny' : 'ask',
      permissionDecisionReason: `[tripwire:${decision.rule}] ${decision.message}`,
    },
  };
  process.stdout.write(`${JSON.stringify(out)}\n`);
};

const writePostToolBlock = (decision: Decision): void => {
  const out = {
    continue: true,
    decision: 'block',
    reason: `[tripwire:${decision.rule}] ${decision.message}`,
  };
  process.stdout.write(`${JSON.stringify(out)}\n`);
};

// Tool names vary across hosts. Claude Code uses `Bash`/`Read`/`Write`/
// `Edit`/`MultiEdit`. Codex sends `apply_patch` for file edits. Devin sends
// `exec` for shell. Pi (via pi-hooks) sends lowercase `bash`/`read`/`write`/
// `edit`. Normalize everything to the Claude vocabulary so the rest of the
// Dispatcher only deals with one set of names.
const normalizeToolName = (name: string): string => {
  const n = name.toLowerCase();
  if (n === 'bash' || n === 'exec' || n === 'shell' || n === 'run_command') {
    return 'Bash';
  }
  if (n === 'read' || n === 'read_file') {
    return 'Read';
  }
  if (n === 'write' || n === 'write_file') {
    return 'Write';
  }
  if (n === 'edit' || n === 'edit_file' || n === 'multiedit' || n === 'apply_patch') {
    return 'Edit';
  }
  if (n === 'webfetch' || n === 'web_fetch' || n === 'fetch') {
    return 'WebFetch';
  }
  return name;
};

type RuleFn = () => Decision;

const runRule = (name: string, fn: RuleFn, timeoutMs: number): Effect.Effect<Decision> =>
  Effect.gen(function* () {
    const exit = yield* Effect.exit(
      Effect.try({ try: fn, catch: (e) => e }).pipe(Effect.timeout(timeoutMs)),
    );
    if (Exit.isSuccess(exit)) {
      return exit.value;
    }
    logError(name, Cause.pretty(exit.cause));
    return allow(name);
  });

interface Rule {
  readonly name: string;
  readonly fn: RuleFn;
}

const collectPreToolUseRules = (tool: string, input: unknown, config: Config): Rule[] => {
  const rules: Rule[] = [];
  if (tool === 'Bash' && isBashInput(input)) {
    const i: BashInput = input;
    const segments = parseCommand(i.command);
    rules.push({ name: 'bash-deny', fn: () => bashDeny(segments, i.command) });
    rules.push({
      name: 'bash-git',
      fn: () => bashGit(segments, i.command, config.git ?? { enforceConventionalCommits: true }),
    });
    rules.push({
      name: 'bash-scoped-rm',
      fn: () => bashScopedRm(segments, i.command, config.safePaths ?? {}),
    });
    rules.push({ name: 'bash-redirect', fn: () => bashRedirect(segments, i.command) });
    rules.push({ name: 'bash-network-install', fn: () => bashNetworkInstall(segments, i.command) });
    rules.push({ name: 'bash-tar-explosion', fn: () => bashTarExplosion(segments, i.command) });
    rules.push({ name: 'bash-tool-policy', fn: () => bashToolPolicy(segments, i.command) });
    rules.push({
      name: 'config-custom',
      fn: () =>
        configCustom(
          segments,
          i.command,
          config.blockedCommands ?? [],
          config.allowedCommands ?? [],
        ),
    });
    return rules;
  }
  if (tool === 'Read' && isReadInput(input)) {
    const i: ReadInput = input;
    rules.push({ name: 'read-protect', fn: () => readProtect(i) });
    return rules;
  }
  const isEdit = (tool === 'Edit' || tool === 'MultiEdit') && isEditInput(input);
  const isWrite = tool === 'Write' && isWriteInput(input);
  if (isEdit) {
    const i: EditInput = input;
    rules.push({ name: 'path-protect', fn: () => pathProtect(i) });
    rules.push({ name: 'lazy-code', fn: () => lazyCode(i) });
  } else if (isWrite) {
    const i: WriteInput = input;
    rules.push({ name: 'path-protect', fn: () => pathProtect(i) });
    rules.push({ name: 'lazy-code', fn: () => lazyCode(i) });
  }
  return rules;
};

const collectPostToolUseRules = (tool: string, response: unknown): Rule[] => {
  if (tool === 'Bash' || tool === 'Read' || tool === 'WebFetch') {
    return [{ name: 'post-secret-scrub', fn: () => postSecretScrub({ toolName: tool, response }) }];
  }
  return [];
};

const runRules = (rules: readonly Rule[], timeoutMs: number): Effect.Effect<Decision> =>
  Effect.gen(function* () {
    if (rules.length === 0) {
      return allow('no-rules');
    }
    const decisions: Decision[] = [];
    for (const r of rules) {
      decisions.push(yield* runRule(r.name, r.fn, timeoutMs));
    }
    return merge(decisions);
  });

const handleBashAllow = (event: HookEvent, decision: Decision, config: Config): void => {
  // After the gate passes (allow or warn), apply rtk command-rewrite. If
  // Rtk doesn't change the command, fall through to normal allow / warn.
  const rtk = runRtkRewrite(event, config.rtk ?? { enabled: false });
  const original = (event.tool_input as { command?: string } | undefined)?.command ?? '';
  const rewritten =
    rtk.updatedCommand !== undefined && rtk.updatedCommand !== original ? rtk.updatedCommand : null;

  if (decision.kind === 'warn') {
    if (rewritten !== null) {
      writeWarn(event, { ...decision, rewriteCommand: rewritten });
      return;
    }
    writeWarn(event, decision);
    return;
  }
  if (rewritten !== null) {
    writeRewriteAllow(event, rewritten, rtk.reason);
    return;
  }
  writeAllow();
};

const handleAllow = (event: HookEvent, decision: Decision, config: Config): void => {
  const eventName = event.hook_event_name;
  const tool = normalizeToolName(event.tool_name ?? '');
  if (eventName === 'PreToolUse' && tool === 'Bash') {
    handleBashAllow(event, decision, config);
    return;
  }
  if (decision.kind === 'warn') {
    writeWarn(event, decision);
    return;
  }
  writeAllow();
};

const program = Effect.gen(function* () {
  const config = yield* loadConfig();
  const raw = yield* Effect.promise(readStdin);

  const parseExit = yield* Effect.exit(
    Effect.try({ try: () => JSON.parse(raw) as unknown, catch: (e) => e }),
  );
  if (Exit.isFailure(parseExit)) {
    logError('parse', Cause.pretty(parseExit.cause));
    writeAllow();
    return;
  }

  const decodeExit = yield* Effect.exit(
    Schema.decodeUnknownEffect(HookEventSchema)(parseExit.value),
  );
  if (Exit.isFailure(decodeExit)) {
    logError('decode', Cause.pretty(decodeExit.cause));
    writeAllow();
    return;
  }
  const event = decodeExit.value;
  const tool = normalizeToolName(event.tool_name ?? '');

  if (event.hook_event_name === 'PreToolUse') {
    const rules = collectPreToolUseRules(tool, event.tool_input, config);
    const decision = yield* runRules(rules, RULE_TIMEOUT_MS);
    if (decision.kind === 'deny' || decision.kind === 'ask') {
      writePreToolGate(event.hook_event_name, decision);
      return;
    }
    handleAllow(event, decision, config);
    return;
  }

  if (event.hook_event_name === 'PostToolUse') {
    const rules = collectPostToolUseRules(tool, event.tool_response);
    const decision = yield* runRules(rules, POST_RULE_TIMEOUT_MS);
    if (decision.kind === 'deny') {
      writePostToolBlock(decision);
      return;
    }
    writeAllow();
    return;
  }

  writeAllow();
});

const handled = program.pipe(
  Effect.catchCause((cause) => {
    logError('dispatch-fatal', Cause.pretty(cause));
    writeAllow();
    return Effect.void;
  }),
);

BunRuntime.runMain(handled);
