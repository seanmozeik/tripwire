import { spawn } from 'node:child_process';
import { once } from 'node:events';
import type { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';

interface PiToolCallEvent {
  readonly input: Record<string, unknown>;
  readonly toolCallId: string;
  readonly toolName: string;
}

type PiToolResultEvent = PiToolCallEvent & {
  readonly content: unknown;
  readonly details: unknown;
  readonly isError: boolean;
};

interface PiExtensionContext {
  readonly abort: () => void;
  readonly cwd: string;
  readonly ui: { readonly notify: (message: string, level: 'error') => void };
}

interface TripwirePiExtensionApi {
  readonly on: {
    (
      event: 'tool_call',
      handler: (
        event: PiToolCallEvent,
        context: PiExtensionContext,
      ) => Promise<{ readonly block: true; readonly reason: string } | undefined>,
    ): void;
    (
      event: 'tool_result',
      handler: (event: PiToolResultEvent, context: PiExtensionContext) => Promise<void>,
    ): void;
  };
}

interface HookResult {
  readonly exitCode: number;
  readonly stderr: string;
  readonly stdout: string;
}

const TIMEOUT_MS = 60_000;
const shippedHookPath = fileURLToPath(new URL('tripwire.js', import.meta.url));

const hookInput = (
  event: PiToolCallEvent | PiToolResultEvent,
  hookEventName: 'PostToolUse' | 'PostToolUseFailure' | 'PreToolUse',
  cwd: string,
) => ({
  cwd,
  hook_event_name: hookEventName,
  tool_input: event.input,
  tool_name: event.toolName,
  tool_use_id: event.toolCallId,
  ...('content' in event
    ? { tool_response: { content: event.content, details: event.details, isError: event.isError } }
    : {}),
});

const readStream = async (stream: Readable): Promise<string> => {
  stream.setEncoding('utf8');
  let output = '';
  for await (const chunk of stream) {
    output += String(chunk);
  }
  return output;
};

const runTripwire = async (hookPath: string, input: unknown): Promise<HookResult> => {
  const child = spawn(hookPath, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  const state = { timedOut: false };
  const timeout = setTimeout(() => {
    state.timedOut = true;
    child.kill('SIGKILL');
  }, TIMEOUT_MS);
  child.stdin.end(JSON.stringify(input));
  try {
    const [closed, stdout, stderr] = await Promise.all([
      once(child, 'close'),
      readStream(child.stdout),
      readStream(child.stderr),
    ]);
    if (state.timedOut) {
      throw new Error(`Tripwire exceeded its ${TIMEOUT_MS}ms timeout`);
    }
    return { exitCode: typeof closed[0] === 'number' ? closed[0] : 1, stderr, stdout };
  } finally {
    clearTimeout(timeout);
  }
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const stringField = (value: Record<string, unknown>, key: string): string | undefined => {
  const field = value[key];
  return typeof field === 'string' ? field : undefined;
};

const tripwirePiDenialReason = (result: HookResult): string | undefined => {
  if (result.exitCode !== 0) {
    return result.stderr.trim() || `Tripwire exited ${result.exitCode}`;
  }
  if (result.stdout.trim().length === 0) {
    return 'Tripwire returned no decision';
  }
  try {
    const value: unknown = JSON.parse(result.stdout);
    if (!isRecord(value)) {
      return 'Tripwire returned invalid JSON';
    }
    const specific = isRecord(value['hookSpecificOutput'])
      ? value['hookSpecificOutput']
      : undefined;
    const decision =
      (specific === undefined ? undefined : stringField(specific, 'permissionDecision')) ??
      stringField(value, 'permissionDecision') ??
      stringField(value, 'permission');
    const reason =
      (specific === undefined ? undefined : stringField(specific, 'permissionDecisionReason')) ??
      stringField(value, 'permissionDecisionReason') ??
      stringField(value, 'reason') ??
      'Blocked by Tripwire';
    if (decision === 'deny' || decision === 'ask') {
      return reason;
    }
    if (stringField(value, 'decision') === 'block' || value['continue'] === false) {
      return reason;
    }
    return value['continue'] === true || decision === 'allow'
      ? undefined
      : 'Tripwire returned an unrecognized response';
  } catch {
    return 'Tripwire returned invalid JSON';
  }
};

const createTripwirePiExtension =
  (hookPath: string) =>
  (pi: TripwirePiExtensionApi): void => {
    pi.on('tool_call', async (event, context) => {
      try {
        const reason = tripwirePiDenialReason(
          await runTripwire(hookPath, hookInput(event, 'PreToolUse', context.cwd)),
        );
        return reason === undefined ? undefined : { block: true, reason };
      } catch (error) {
        return {
          block: true,
          reason: `Tripwire failed closed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    });

    pi.on('tool_result', async (event, context) => {
      try {
        const reason = tripwirePiDenialReason(
          await runTripwire(
            hookPath,
            hookInput(event, event.isError ? 'PostToolUseFailure' : 'PostToolUse', context.cwd),
          ),
        );
        if (reason !== undefined) {
          context.ui.notify(`Tripwire stopped the session: ${reason}`, 'error');
          context.abort();
        }
      } catch (error) {
        context.ui.notify(
          `Tripwire failed closed after tool use: ${error instanceof Error ? error.message : String(error)}`,
          'error',
        );
        context.abort();
      }
    });
  };

export default createTripwirePiExtension(shippedHookPath);

export {
  createTripwirePiExtension,
  tripwirePiDenialReason,
  type PiExtensionContext,
  type PiToolCallEvent,
  type PiToolResultEvent,
  type TripwirePiExtensionApi,
};
