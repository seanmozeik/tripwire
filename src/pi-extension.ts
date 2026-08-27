import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { realpathSync } from 'node:fs';
import type { Readable } from 'node:stream';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { resolveTripwireCommand, type RuntimeCommand } from './lib/runtime-command';

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

type TripwireProcessRunner = (command: RuntimeCommand, input: unknown) => Promise<HookResult>;
type TripwireCommandInput = RuntimeCommand | string;

const TIMEOUT_MS = 60_000;

/** Resolve the optional native hook or the portable Bun bundle, following install symlinks. */
const resolveShippedHookCommand = (
  extensionUrl: string | URL = import.meta.url,
): RuntimeCommand => {
  const extensionPath = fileURLToPath(extensionUrl);
  let resolved = extensionPath;
  try {
    resolved = realpathSync(extensionPath);
  } catch {
    // Keep the unresolved path when the module is not on disk yet (unit tests).
  }
  return resolveTripwireCommand({ moduleUrl: pathToFileURL(resolved) });
};

const shippedHookCommand = resolveShippedHookCommand();

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

const applyPatchInputs = (patch: string): readonly Record<string, unknown>[] => {
  const fileHeader = /^\*{3}\s+(?:Add|Update|Delete)\s+File\s*:\s*(?<path>\S.*?)\s*$/;
  const moveHeader = /^\*{3}\s+Move\s+to\s*:\s*(?<path>\S.*?)\s*$/;
  const byPath = new Map<string, { newLines: string[]; oldLines: string[] }>();
  let currentPaths: string[] = [];
  const beginMarker = '*** Begin Patch';
  const endMarker = '*** End Patch';
  const lines = patch.split(/\r?\n/);
  const beginIndex = lines.findIndex((line) => line.trim() === beginMarker);
  if (beginIndex === -1) {
    return [];
  }
  const unboundedBody = lines.slice(beginIndex + 1);
  const endIndex = [...unboundedBody, endMarker].findIndex((line) => line.trim() === endMarker);
  const body = unboundedBody.slice(0, endIndex);

  const addCurrentPath = (filePath: string): void => {
    currentPaths.push(filePath);
    if (!byPath.has(filePath)) {
      byPath.set(filePath, { newLines: [], oldLines: [] });
    }
  };

  for (const line of body) {
    const fileMatch = fileHeader.exec(line);
    const filePath = fileMatch?.groups?.['path']?.trim();
    if (filePath !== undefined && filePath.length > 0) {
      currentPaths = [];
      addCurrentPath(filePath);
      continue;
    }
    if (currentPaths.length === 0) {
      continue;
    }
    const moveMatch = moveHeader.exec(line);
    const movePath = moveMatch?.groups?.['path']?.trim();
    if (movePath !== undefined && movePath.length > 0) {
      addCurrentPath(movePath);
      continue;
    }
    let linesKey: 'newLines' | 'oldLines' | undefined;
    if (line.startsWith('+')) {
      linesKey = 'newLines';
    } else if (line.startsWith('-')) {
      linesKey = 'oldLines';
    }
    if (linesKey !== undefined) {
      for (const path of currentPaths) {
        byPath.get(path)?.[linesKey].push(line.slice(1));
      }
    }
  }

  return [...byPath].map(([filePath, strings]) => ({
    file_path: filePath,
    new_string: strings.newLines.join('\n'),
    old_string: strings.oldLines.join('\n'),
  }));
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
    const patchInputs = applyPatchInputs(stringField(input, 'input') ?? '');
    if (patchInputs.length > 0) {
      return patchInputs;
    }
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

const runTripwire = async (command: RuntimeCommand, input: unknown): Promise<HookResult> => {
  const child = spawn(command.executable, [...command.arguments, '--tripwire-hook'], {
    stdio: ['pipe', 'pipe', 'pipe'],
  });
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

const createTripwirePiExtension = (
  commandInput: TripwireCommandInput,
  processRunner: TripwireProcessRunner = runTripwire,
) => {
  const command: RuntimeCommand =
    typeof commandInput === 'string'
      ? { arguments: [], executable: commandInput, kind: 'native' }
      : commandInput;
  return (pi: TripwirePiExtensionApi): void => {
    pi.on('tool_call', async (event, context) => {
      try {
        const inputs = hookInputs(event, 'PreToolUse', context.cwd);
        const input = inputs.length === 1 ? inputs[0] : inputs;
        if (input === undefined) {
          throw new Error('Tripwire could not normalize the Pi tool call');
        }
        const reason = tripwirePiDenialReason(await processRunner(command, input));
        if (reason !== undefined) {
          return { block: true, reason };
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
        const reason = tripwirePiDenialReason(await processRunner(command, input));
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
};

export default createTripwirePiExtension(shippedHookCommand);

export {
  createTripwirePiExtension,
  hookInputs,
  resolveShippedHookCommand,
  tripwirePiDenialReason,
  type HookResult,
  type PiExtensionContext,
  type PiToolCallEvent,
  type PiToolResultEvent,
  type TripwirePiExtensionApi,
  type TripwireCommandInput,
  type TripwireProcessRunner,
};
