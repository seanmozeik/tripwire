#!/usr/bin/env bun
// Hook dispatcher: decode stdin, apply timed rules, and write the host response.
// Rule defects and timeouts allow the tool call and write an error log.
// Denials tell the agent which safe alternative to use.

import { BunRuntime } from '@effect/platform-bun';
import { Cause, Data, Effect, Exit, Schema } from 'effect';

import { parseCommand } from './lib/bash';
import {
  CONFIG_PATH,
  getDefaultConfig,
  loadConfigResult,
  mergeWithDefaults,
  type Config,
  type ResolvedConfig,
  type SecretScannerConfig,
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
    const value: unknown = chunk;
    if (value instanceof Uint8Array) {
      chunks.push(Buffer.from(value));
    } else {
      throw new TypeError('Tripwire received a non-byte stdin chunk');
    }
  }
  return Buffer.concat(chunks).toString('utf8');
};

const NATIVE_HOST: HookHost = { kind: 'native' };
const RULE_TIMEOUT_MS = 250;
const PRIVATE_HOOK_FLAG = '--tripwire-hook';
const HookEventBatchSchema = Schema.Array(HookEventSchema).check(Schema.isMinLength(1));

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

// Codex rejects `hookSpecificOutput.additionalContext`. Its `turn_id`
// extension selects the narrower output without changing Claude responses.
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

// Tool names vary across hosts. Normalize Claude Code, Codex, Cursor, Pi, and
// Oh My Pi names to one canonical vocabulary before rules run.
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
  if (n === 'powershell') {
    return 'PowerShell';
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
  Effect.gen(function* runRuleEffect() {
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
  if (tool === 'PowerShell') {
    rules.push({
      name: 'powershell-unsupported',
      fn: () =>
        deny(
          'powershell-unsupported',
          'PowerShell commands are blocked because Tripwire cannot parse PowerShell grammar. Use the Bash tool, or add a PowerShell parser before you enable this tool.',
        ),
    });
    return rules;
  }
  if (tool === 'Bash' && isBashInput(input)) {
    const i: BashInput = input;
    const segments = parseCommand(i.command);
    rules.push(
      { name: 'bash-deny', fn: () => bashDeny(segments, i.command) },
      { name: 'bash-git', fn: () => bashGit(segments, i.command, config.git) },
      { name: 'bash-scoped-rm', fn: () => bashScopedRm(segments, i.command, config.safePaths) },
      { name: 'bash-redirect', fn: () => bashRedirect(segments, i.command) },
      { name: 'bash-network-install', fn: () => bashNetworkInstall(segments, i.command) },
      { name: 'bash-tar-explosion', fn: () => bashTarExplosion(segments, i.command) },
      { name: 'tool-policy', fn: () => toolPolicy(segments, i.command, config.toolPolicies) },
      {
        name: 'config-custom',
        fn: () => configCustom(segments, i.command, config.blockedCommands, config.allowedCommands),
      },
    );
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
    rules.push(
      { name: 'path-protect', fn: () => pathProtect(i) },
      { name: 'lazy-code', fn: () => lazyCode(i) },
    );
  } else if (isWrite) {
    const i: WriteInput = input;
    rules.push(
      { name: 'path-protect', fn: () => pathProtect(i) },
      { name: 'lazy-code', fn: () => lazyCode(i) },
    );
  }
  return rules;
};

const collectPostToolUseRules = (
  tool: string,
  response: unknown,
  secretScanner: SecretScannerConfig,
): Rule[] => {
  if (tool === 'Bash' || tool === 'PowerShell' || tool === 'Read' || tool === 'WebFetch') {
    const scanTool = tool === 'PowerShell' ? 'Bash' : tool;
    return [
      {
        name: 'post-secret-scrub',
        fn: () => postSecretScrub({ toolName: scanTool, response, secretScanner }),
      },
    ];
  }
  return [];
};

const runRules = (rules: readonly Rule[], timeoutMs: number): Effect.Effect<Decision> =>
  Effect.gen(function* runRulesEffect() {
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
  const decisions: Decision[] = [];
  for (const rule of rules) {
    try {
      decisions.push(rule.fn());
    } catch (cause) {
      logError(rule.name, cause);
      decisions.push(allow(rule.name));
    }
  }
  return merge(decisions);
};

const decide = (event: HookEvent, config: Config = {}): Decision => {
  const mergedConfig = mergeWithDefaults(config);
  const tool = normalizeToolName(event.tool_name ?? '');
  if (event.hook_event_name === 'PreToolUse') {
    return runRulesSync(collectPreToolUseRules(tool, event.tool_input, mergedConfig));
  }
  if (event.hook_event_name === 'PostToolUse') {
    return runRulesSync(
      collectPostToolUseRules(tool, event.tool_response, mergedConfig.secretScanner),
    );
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

const isPrivateHookInvocation = (): boolean => process.argv.includes(PRIVATE_HOOK_FLAG);

const cursorHostFromArgs = (): HookHost => {
  const eventName = cursorEventNameFromArgs();
  return eventName === undefined ? NATIVE_HOST : cursorHost(eventName);
};

const writeHookFailure = (stage: string, batch = false): void => {
  const host = cursorHostFromArgs();
  if (batch) {
    writePreToolGate(
      'PreToolUse',
      deny(
        'tripwire-batch-error',
        `Tripwire batch input could not be processed (${stage}). Failing closed.`,
      ),
      host,
    );
    return;
  }
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

const hookHostKey = (event: HookEvent, host: HookHost): string => {
  if (host.kind === 'cursor') {
    return `cursor:${host.eventName}`;
  }
  return isCodex(event) ? 'codex' : 'native';
};

const mergedDecisions = (decisions: readonly Decision[]): Decision =>
  decisions.length === 1 ? (decisions[0] ?? allow('no-rules')) : merge(decisions);

type PreparedHookInput =
  | {
      readonly ok: true;
      readonly events: readonly HookEvent[];
      readonly firstEvent: HookEvent;
      readonly host: HookHost;
      readonly phase: string;
    }
  | { readonly ok: false };

const prepareHookInput = (input: unknown): Effect.Effect<PreparedHookInput> =>
  Effect.gen(function* prepareHookInputEffect() {
    const batchInput = Array.isArray(input);
    if (batchInput && !isPrivateHookInvocation()) {
      logError('decode', 'Batch hook input is only available through --tripwire-hook');
      writeHookFailure('unsupported batch input');
      return { ok: false };
    }

    let events: readonly HookEvent[];
    let host: HookHost;
    if (batchInput) {
      const decodeExit = yield* Effect.exit(Schema.decodeEffect(HookEventBatchSchema)(input));
      if (Exit.isFailure(decodeExit)) {
        logError('decode', Cause.pretty(decodeExit.cause));
        writeHookFailure('unsupported batch event shape', true);
        return { ok: false };
      }
      events = decodeExit.value;
      host = cursorHostFromArgs();
    } else {
      const normalized = normalizeHookInput(input, cursorEventNameFromArgs());
      const decodeExit = yield* Effect.exit(
        Schema.decodeUnknownEffect(HookEventSchema)(normalized.event),
      );
      if (Exit.isFailure(decodeExit)) {
        logError('decode', Cause.pretty(decodeExit.cause));
        writeHookFailure('unsupported event shape');
        return { ok: false };
      }
      events = [decodeExit.value];
      ({ host } = normalized);
    }

    const [firstEvent] = events;
    if (firstEvent === undefined) {
      writeHookFailure('empty batch', true);
      return { ok: false };
    }
    const phase = firstEvent.hook_event_name;
    const hostKey = hookHostKey(firstEvent, host);
    if (events.some((event) => event.hook_event_name !== phase)) {
      logError('decode', 'Batch hook input mixes event phases');
      writeHookFailure('mixed event phases', true);
      return { ok: false };
    }
    if (events.some((event) => hookHostKey(event, host) !== hostKey)) {
      logError('decode', 'Batch hook input mixes hosts');
      writeHookFailure('mixed hosts', true);
      return { ok: false };
    }
    return { ok: true, events, firstEvent, host, phase };
  });

const program = Effect.gen(function* tripwireProgram() {
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

  const prepared = yield* prepareHookInput(parseExit.value);
  if (!prepared.ok) {
    return;
  }
  const { events, firstEvent, host, phase } = prepared;

  if (phase === 'PreToolUse') {
    if (!configLoad.ok) {
      writePreToolGate(phase, deny('config-error', configErrorMessage(configLoad.error)), host);
      return;
    }
    const decisions: Decision[] = [];
    for (const event of events) {
      const tool = normalizeToolName(event.tool_name ?? '');
      decisions.push(
        yield* runRules(
          collectPreToolUseRules(tool, event.tool_input, configLoad.config),
          RULE_TIMEOUT_MS,
        ),
      );
    }
    const decision = mergedDecisions(decisions);
    if (decision.kind === 'deny' || decision.kind === 'ask') {
      writePreToolGate(phase, decision, host);
      return;
    }
    handleAllow(firstEvent, decision, host);
    return;
  }

  if (phase === 'PostToolUse') {
    const secretScanner = configLoad.ok
      ? configLoad.config.secretScanner
      : getDefaultConfig().secretScanner;
    const decisions: Decision[] = [];
    for (const event of events) {
      const tool = normalizeToolName(event.tool_name ?? '');
      decisions.push(
        yield* runRules(
          collectPostToolUseRules(tool, event.tool_response, secretScanner),
          RULE_TIMEOUT_MS,
        ),
      );
    }
    const decision = mergedDecisions(decisions);
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
  // oxlint-disable-next-line de-clank-effect/no-silent-effect-error-swallow -- fatal causes are logged before the host receives its fail-policy response.
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
