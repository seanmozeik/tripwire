import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { realpathSync } from 'node:fs';
import path from 'node:path';
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
      ) => Promise<{ readonly block?: boolean; readonly reason?: string } | undefined>,
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

/** Resolve the Bun hook next to the built extension, following install symlinks. */
const resolveShippedHookPath = (extensionUrl: string | URL = import.meta.url): string => {
  const extensionPath = fileURLToPath(extensionUrl);
  let resolved = extensionPath;
  try {
    resolved = realpathSync(extensionPath);
  } catch {
    // Keep the unresolved path when the module is not on disk yet (unit tests).
  }
  return path.join(path.dirname(resolved), 'tripwire');
};

const shippedHookPath = resolveShippedHookPath();

const requiredStringField = (
  value: Record<string, unknown>,
  names: readonly string[],
  label: string,
): string => {
  for (const name of names) {
    const field = value[name];
    if (typeof field === 'string') {
      return field;
    }
  }
  throw new Error(`Pi ${label} is missing`);
};

const stringArrayField = (value: Record<string, unknown>, name: string): string[] => {
  const field = value[name];
  return Array.isArray(field) ? field.filter((item) => typeof item === 'string') : [];
};

const editStrings = (
  input: Record<string, unknown>,
): { old_string: string; new_string: string } => {
  const { edits } = input;
  if (Array.isArray(edits)) {
    const oldStrings: string[] = [];
    const newStrings: string[] = [];
    for (const edit of edits) {
      if (!isRecord(edit)) {
        continue;
      }
      const oldText = stringField(edit, 'oldText') ?? stringField(edit, 'old_string');
      const newText = stringField(edit, 'newText') ?? stringField(edit, 'new_string');
      if (oldText !== undefined) {
        oldStrings.push(oldText);
      }
      if (newText !== undefined) {
        newStrings.push(newText);
      }
    }
    return { old_string: oldStrings.join('\n'), new_string: newStrings.join('\n') };
  }
  return {
    old_string: stringField(input, 'oldText') ?? stringField(input, 'old_string') ?? '',
    new_string:
      stringField(input, 'newText') ??
      stringField(input, 'new_string') ??
      stringField(input, 'input') ??
      stringField(input, '_input') ??
      '',
  };
};

const normalizedToolInputs = (event: PiToolCallEvent): readonly Record<string, unknown>[] => {
  const { input, toolName } = event;
  if (toolName === 'bash' || toolName === 'powershell') {
    return [{ command: requiredStringField(input, ['command'], `${toolName} command`) }];
  }
  if (toolName === 'read') {
    return [{ file_path: requiredStringField(input, ['path', 'file_path'], 'read path') }];
  }
  if (toolName === 'write') {
    return [
      {
        content: requiredStringField(input, ['content'], 'write content'),
        file_path: requiredStringField(input, ['path', 'file_path'], 'write path'),
      },
    ];
  }
  if (toolName === 'edit') {
    const directPath = stringField(input, 'path') ?? stringField(input, 'file_path');
    const paths = stringArrayField(input, 'paths');
    let targets = paths;
    if (targets.length === 0 && directPath !== undefined) {
      targets = [directPath];
    }
    if (targets.length === 0) {
      throw new Error('Pi edit path is missing');
    }
    const strings = editStrings(input);
    const inputs: Record<string, unknown>[] = [];
    for (const filePath of targets) {
      inputs.push({ file_path: filePath, ...strings });
    }
    return inputs;
  }
  return [input];
};

const textFromContent = (content: unknown): string => {
  if (typeof content === 'string') {
    return content;
  }
  if (!Array.isArray(content)) {
    return '';
  }
  const texts: string[] = [];
  for (const item of content) {
    if (isRecord(item) && item['type'] === 'text' && typeof item['text'] === 'string') {
      texts.push(item['text']);
    }
  }
  return texts.join('\n');
};

const normalizedToolResponse = (event: PiToolResultEvent): Record<string, unknown> => {
  const text = textFromContent(event.content);
  if (event.toolName === 'bash' || event.toolName === 'powershell') {
    return { stdout: text, stderr: event.isError ? text : '', interrupted: event.isError };
  }
  if (event.toolName === 'read') {
    return { content: text };
  }
  return { content: text, details: event.details, isError: event.isError };
};

const hookInputs = (
  event: PiToolCallEvent | PiToolResultEvent,
  hookEventName: 'PostToolUse' | 'PreToolUse',
  cwd: string,
): readonly Record<string, unknown>[] => {
  const base = {
    cwd,
    hook_event_name: hookEventName,
    tool_name: event.toolName,
    tool_use_id: event.toolCallId,
  };
  if ('content' in event) {
    return [{ ...base, tool_input: event.input, tool_response: normalizedToolResponse(event) }];
  }
  const inputs: Record<string, unknown>[] = [];
  for (const toolInput of normalizedToolInputs(event)) {
    inputs.push({ ...base, tool_input: toolInput });
  }
  return inputs;
};

const readStream = async (stream: Readable): Promise<string> => {
  stream.setEncoding('utf8');
  let output = '';
  for await (const chunk of stream) {
    output += String(chunk);
  }
  return output;
};

const runTripwire = async (hookPath: string, input: unknown): Promise<HookResult> => {
  const child = spawn(hookPath, ['--tripwire-hook'], { stdio: ['pipe', 'pipe', 'pipe'] });
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
        for (const input of hookInputs(event, 'PreToolUse', context.cwd)) {
          const reason = tripwirePiDenialReason(await runTripwire(hookPath, input));
          if (reason !== undefined) {
            return { block: true, reason };
          }
        }
        return {};
      } catch (error) {
        return {
          block: true,
          reason: `Tripwire failed closed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    });

    pi.on('tool_result', async (event, context) => {
      try {
        const [input] = hookInputs(event, 'PostToolUse', context.cwd);
        if (input === undefined) {
          throw new Error('Tripwire could not normalize the Pi tool result');
        }
        const reason = tripwirePiDenialReason(await runTripwire(hookPath, input));
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
  hookInputs,
  resolveShippedHookPath,
  tripwirePiDenialReason,
  type PiExtensionContext,
  type PiToolCallEvent,
  type PiToolResultEvent,
  type TripwirePiExtensionApi,
};
