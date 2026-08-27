#!/usr/bin/env bun
// Tripwire — Claude Code hooks dispatcher.
//
// Reads a hook event JSON payload on stdin, routes by hook_event_name +
// Tool_name, runs rules with per-rule timeouts, merges decisions
// (most-restrictive wins), scans PostToolUse output for secrets via
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
import { Cause, Data, Effect, Exit, Schema } from 'effect';

import { parseCommand } from './lib/bash';
import {
  CONFIG_PATH,
  loadConfigResult,
  mergeWithDefaults,
  type Config,
  type ResolvedConfig,
} from './lib/config';
import { cursorHost, normalizeHookInput, type HookHost } from './lib/cursor';
import { type Decision, allow, deny, merge } from './lib/decision';
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
import { bashDeny } from './rules/bash-deny';
import { bashGit } from './rules/bash-git';
import { bashNetworkInstall } from './rules/bash-network-install';
import { bashRedirect } from './rules/bash-redirect';
import { bashScopedRm } from './rules/bash-scoped-rm';
import { bashTarExplosion } from './rules/bash-tar-explosion';
import { configCustom } from './rules/config-custom';
import { lazyCode } from './rules/lazy-code';
import { pathProtect } from './rules/path-protect';
import { postSecretScrub } from './rules/post-secret-scrub';
import { readProtect } from './rules/read-protect';
import { toolPolicy } from './rules/tool-policy';

const readStdin = async (): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
};

const NATIVE_HOST: HookHost = { kind: 'native' };

const writeAllow = (host: HookHost = NATIVE_HOST): void => {
  if (host.kind === 'cursor' && !host.post) {
    process.stdout.write('{"continue":true,"permission":"allow"}\n');
    return;
  }
  process.stdout.write('{"continue": true}\n');
};

const cursorReason = (decision: Decision): string =>
  `[tripwire:${decision.rule}] ${decision.message}`;

const writeCursorPreGate = (decision: Decision): void => {
  const reason =
    decision.kind === 'ask'
      ? `${cursorReason(decision)} This unattended Cursor run cannot ask a human, so the action is denied.`
      : cursorReason(decision);
  process.stdout.write(
    `${JSON.stringify({
      continue: true,
      permission: 'deny',
      user_message: reason,
      agent_message: reason,
    })}\n`,
  );
};

// Codex's PreToolUse hook rejects `hookSpecificOutput.additionalContext`
// (openai/codex issue #19385). Detect Codex via its `turn_id` extension
// And downgrade output accordingly. Claude Code accepts it, so we only
// Narrow when we can confirm we're on Codex.
const isCodex = (event: HookEvent): boolean => event.turn_id !== undefined;

interface WarnOutput {
  hookEventName: string;
  additionalContext?: string;
}

const writeWarn = (event: HookEvent, decision: Decision, host: HookHost): void => {
  if (host.kind === 'cursor') {
    process.stdout.write(
      `${JSON.stringify({
        continue: true,
        permission: 'allow',
        agent_message: cursorReason(decision),
      })}\n`,
    );
    return;
  }
  const eventName = event.hook_event_name;
  const reason = `[tripwire:${decision.rule}] ${decision.message}`;
  if (isCodex(event)) {
    // Codex rejects `additionalContext` on PreToolUse. Send only
    // `systemMessage`.
    process.stdout.write(`${JSON.stringify({ continue: true, systemMessage: reason })}\n`);
    return;
  }
  const hookSpecificOutput: WarnOutput = { hookEventName: eventName, additionalContext: reason };
  process.stdout.write(`${JSON.stringify({ continue: true, hookSpecificOutput })}\n`);
};

const writePreToolGate = (
  eventName: string,
  decision: Decision,
  host: HookHost = NATIVE_HOST,
): void => {
  if (host.kind === 'cursor') {
    writeCursorPreGate(decision);
    return;
  }
  const out = {
    hookSpecificOutput: {
      hookEventName: eventName,
      permissionDecision: decision.kind === 'deny' ? 'deny' : 'ask',
      permissionDecisionReason: `[tripwire:${decision.rule}] ${decision.message}`,
    },
  };
  process.stdout.write(`${JSON.stringify(out)}\n`);
};

const writePostToolBlock = (decision: Decision, host: HookHost): void => {
  if (host.kind === 'cursor') {
    // The tool already ran. Cursor has no post-event rollback channel.
    writeAllow(host);
    return;
  }
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

class RuleExecutionError extends Data.TaggedError('RuleExecutionError')<{
  readonly cause: unknown;
}> {}

class HookInputParseError extends Data.TaggedError('HookInputParseError')<{
  readonly cause: unknown;
}> {}

const runRule = (name: string, fn: RuleFn, timeoutMs: number): Effect.Effect<Decision> =>
  Effect.gen(function* () {
    const exit = yield* Effect.exit(
      Effect.try({ try: fn, catch: (cause) => new RuleExecutionError({ cause }) }).pipe(
        Effect.timeout(timeoutMs),
      ),
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

const collectPreToolUseRules = (tool: string, input: unknown, config: ResolvedConfig): Rule[] => {
  const rules: Rule[] = [];
  if (tool === 'Bash' && isBashInput(input)) {
    const i: BashInput = input;
    const segments = parseCommand(i.command);
    rules.push({ name: 'bash-deny', fn: () => bashDeny(segments, i.command) });
    rules.push({ name: 'bash-git', fn: () => bashGit(segments, i.command, config.git) });
    rules.push({
      name: 'bash-scoped-rm',
      fn: () => bashScopedRm(segments, i.command, config.safePaths),
    });
    rules.push({ name: 'bash-redirect', fn: () => bashRedirect(segments, i.command) });
    rules.push({ name: 'bash-network-install', fn: () => bashNetworkInstall(segments, i.command) });
    rules.push({ name: 'bash-tar-explosion', fn: () => bashTarExplosion(segments, i.command) });
    rules.push({
      name: 'tool-policy',
      fn: () => toolPolicy(segments, i.command, config.toolPolicies),
    });
    rules.push({
      name: 'config-custom',
      fn: () => configCustom(segments, i.command, config.blockedCommands, config.allowedCommands),
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

const runRulesSync = (rules: readonly Rule[]): Decision => {
  if (rules.length === 0) {
    return allow('no-rules');
  }
  return merge(rules.map((r) => r.fn()));
};

const decide = (event: HookEvent, config: Config = {}): Decision => {
  const mergedConfig = mergeWithDefaults(config);
  const tool = normalizeToolName(event.tool_name ?? '');
  if (event.hook_event_name === 'PreToolUse') {
    return runRulesSync(collectPreToolUseRules(tool, event.tool_input, mergedConfig));
  }
  if (event.hook_event_name === 'PostToolUse') {
    return runRulesSync(collectPostToolUseRules(tool, event.tool_response));
  }
  return allow('no-rules');
};

const handleAllow = (event: HookEvent, decision: Decision, host: HookHost): void => {
  const eventName = event.hook_event_name;
  const tool = normalizeToolName(event.tool_name ?? '');
  if (eventName === 'PreToolUse' && tool === 'Bash') {
    if (decision.kind === 'warn') {
      writeWarn(event, decision, host);
      return;
    }
    writeAllow(host);
    return;
  }
  if (decision.kind === 'warn') {
    writeWarn(event, decision, host);
    return;
  }
  writeAllow(host);
};

// A broken config (bad JSON / unknown field / decode failure) silently dropping
// All custom policy is the dangerous case this guards. Fail closed: deny the
// Pending PreToolUse call with the decode error inline so the agent halts and
// The user sees it, rather than running on bare defaults unannounced.
const configErrorMessage = (error: string): string =>
  `tripwire config at ${CONFIG_PATH} failed to load, so ALL custom safety policy is ` +
  `inactive. Failing closed until it is fixed. Fix the JSON, then this clears on the next ` +
  `call (the shim daemon caches config at warm — restart it there). Error: ${error}`;

const cursorEventNameFromArgs = (): string | undefined => {
  const index = process.argv.indexOf('--cursor-event');
  if (index !== -1) {
    return process.argv[index + 1] ?? '';
  }
  const value = process.argv.find((arg) => arg.startsWith('--cursor-event='));
  return value?.slice('--cursor-event='.length);
};

const cursorHostFromArgs = (): HookHost => {
  const eventName = cursorEventNameFromArgs();
  return eventName === undefined ? NATIVE_HOST : cursorHost(eventName);
};

const writeHookFailure = (stage: string): void => {
  const host = cursorHostFromArgs();
  if (host.kind === 'cursor' && !host.post) {
    writeCursorPreGate(
      deny(
        'cursor-hook-error',
        `Cursor hook input could not be processed (${stage}). Failing closed.`,
      ),
    );
    return;
  }
  writeAllow(host);
};

const program = Effect.gen(function* () {
  const configLoad = yield* loadConfigResult();
  const raw = yield* Effect.promise(readStdin);

  const parseExit = yield* Effect.exit(
    Effect.try({
      try: () => JSON.parse(raw) as unknown,
      catch: (cause) => new HookInputParseError({ cause }),
    }),
  );
  if (Exit.isFailure(parseExit)) {
    logError('parse', Cause.pretty(parseExit.cause));
    writeHookFailure('invalid JSON');
    return;
  }

  const normalized = normalizeHookInput(parseExit.value, cursorEventNameFromArgs());

  const decodeExit = yield* Effect.exit(
    Schema.decodeUnknownEffect(HookEventSchema)(normalized.event),
  );
  if (Exit.isFailure(decodeExit)) {
    logError('decode', Cause.pretty(decodeExit.cause));
    writeHookFailure('unsupported event shape');
    return;
  }
  const event = decodeExit.value;
  const host = normalized.host;

  if (!configLoad.ok) {
    if (event.hook_event_name === 'PreToolUse') {
      writePreToolGate(
        event.hook_event_name,
        deny('config-error', configErrorMessage(configLoad.error)),
        host,
      );
      return;
    }
    // Config governs PreToolUse gating; PostToolUse secret-scrub is config-
    // Independent and there is always an imminent next PreToolUse to surface the
    // Deny, so don't block already-run output here.
    writeAllow(host);
    return;
  }
  const config = configLoad.config;

  if (event.hook_event_name === 'PreToolUse') {
    const decision = decide(event, config);
    if (decision.kind === 'deny' || decision.kind === 'ask') {
      writePreToolGate(event.hook_event_name, decision, host);
      return;
    }
    handleAllow(event, decision, host);
    return;
  }

  if (event.hook_event_name === 'PostToolUse') {
    const decision = decide(event, config);
    if (decision.kind === 'deny') {
      writePostToolBlock(decision, host);
      return;
    }
    writeAllow(host);
    return;
  }

  writeAllow(host);
});

const handled = program.pipe(
  Effect.catchCause((cause) => {
    logError('dispatch-fatal', Cause.pretty(cause));
    writeHookFailure('dispatcher failure');
    return Effect.void;
  }),
);

const runHook = (): void => {
  BunRuntime.runMain(handled);
};

if (import.meta.main) {
  runHook();
}

export {
  collectPostToolUseRules,
  collectPreToolUseRules,
  decide,
  normalizeToolName,
  runHook,
  runRules,
  runRulesSync,
};
