import type { HookEvent } from './event';

type JsonRecord = Record<string, unknown>;

type HookHost =
  | { readonly kind: 'native' }
  | { readonly kind: 'cursor'; readonly eventName: string; readonly post: boolean };

interface NormalizedHookInput {
  readonly event: unknown;
  readonly host: HookHost;
}

const CURSOR_PRE_EVENTS = new Set([
  'preToolUse',
  'beforeShellExecution',
  'beforeMCPExecution',
  'beforeReadFile',
  'beforeTabFileRead',
]);

const CURSOR_POST_EVENTS = new Set([
  'postToolUse',
  'postToolUseFailure',
  'afterShellExecution',
  'afterMCPExecution',
  'afterFileEdit',
  'afterTabFileEdit',
]);

const cursorHost = (eventName: string): HookHost => ({
  kind: 'cursor',
  eventName,
  post: CURSOR_POST_EVENTS.has(eventName),
});

const isCursorEventName = (eventName: string): boolean =>
  CURSOR_PRE_EVENTS.has(eventName) || CURSOR_POST_EVENTS.has(eventName);

const isRecord = (value: unknown): value is JsonRecord =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const stringField = (value: JsonRecord, ...names: readonly string[]): string | undefined => {
  for (const name of names) {
    const candidate = value[name];
    if (typeof candidate === 'string') {
      return candidate;
    }
  }
  return undefined;
};

const valueField = (value: JsonRecord, ...names: readonly string[]): unknown => {
  for (const name of names) {
    if (name in value) {
      return value[name];
    }
  }
  return undefined;
};

const inputStringField = (
  raw: JsonRecord,
  input: unknown,
  ...names: readonly string[]
): string | undefined => {
  const fromRaw = stringField(raw, ...names);
  if (fromRaw !== undefined) {
    return fromRaw;
  }
  if (typeof input === 'string' && names.includes('command')) {
    return input;
  }
  return isRecord(input) ? stringField(input, ...names) : undefined;
};

const requiredString = (value: string | undefined, label: string): string => {
  if (value === undefined) {
    throw new Error(`Cursor hook payload missing ${label}`);
  }
  return value;
};

const normalizeCursorToolName = (name: string): string => {
  const normalized = name.toLowerCase();
  if (
    normalized === 'bash' ||
    normalized === 'exec' ||
    normalized === 'shell' ||
    normalized === 'run_command'
  ) {
    return 'Bash';
  }
  if (normalized === 'read' || normalized === 'read_file') {
    return 'Read';
  }
  if (normalized === 'write' || normalized === 'write_file') {
    return 'Write';
  }
  if (
    normalized === 'edit' ||
    normalized === 'edit_file' ||
    normalized === 'multiedit' ||
    normalized === 'apply_patch'
  ) {
    return 'Edit';
  }
  return name;
};

const isFileTool = (tool: string): boolean =>
  tool === 'Read' || tool === 'Write' || tool === 'Edit';

const normalizeBashInput = (input: unknown, required: boolean) => {
  let command: string | undefined;
  if (typeof input === 'string') {
    command = input;
  } else if (isRecord(input)) {
    command = stringField(input, 'command', 'cmd');
  }
  if (required && command === undefined) {
    throw new Error('Cursor hook payload missing command');
  }
  if (typeof input === 'string') {
    return { command: input };
  }
  if (!isRecord(input) || command === undefined) {
    return input;
  }
  return { ...input, command };
};

const normalizeFileInput = (tool: string, input: JsonRecord, required: boolean): JsonRecord => {
  const filePath = stringField(input, 'file_path', 'filePath', 'path');
  if (required && filePath === undefined) {
    throw new Error(`Cursor ${tool} hook payload missing file path`);
  }
  if (tool === 'Read') {
    return { ...input, file_path: filePath ?? '' };
  }
  if (tool === 'Write') {
    const content = stringField(input, 'content', 'fileText', 'text');
    if (required && content === undefined) {
      throw new Error('Cursor Write hook payload missing content');
    }
    return { ...input, file_path: filePath ?? '', content: content ?? '' };
  }
  if (tool === 'Edit') {
    const oldString = stringField(input, 'old_string', 'oldString');
    const newString = stringField(input, 'new_string', 'newString');
    if (required && (oldString === undefined || newString === undefined)) {
      throw new Error('Cursor Edit hook payload missing oldString or newString');
    }
    return {
      ...input,
      file_path: filePath ?? '',
      old_string: oldString ?? '',
      new_string: newString ?? '',
    };
  }
  return input;
};

const normalizeToolInput = (tool: string, input: unknown, required = true): unknown => {
  if (tool === 'Bash') {
    return normalizeBashInput(input, required);
  }
  if (!isFileTool(tool)) {
    return input;
  }
  if (!isRecord(input)) {
    if (required) {
      throw new Error(`Cursor ${tool} hook payload is missing tool input`);
    }
    return input;
  }
  return normalizeFileInput(tool, input, required);
};

const normalizeToolResponse = (tool: string, response: unknown) => {
  if (typeof response !== 'string') {
    return response;
  }
  if (tool === 'Bash') {
    return { stdout: response, stderr: '' };
  }
  if (tool === 'Read') {
    return { content: response };
  }
  return { content: response };
};

const cursorToolName = (eventName: string, raw: JsonRecord): string => {
  if (eventName === 'beforeShellExecution' || eventName === 'afterShellExecution') {
    return 'Bash';
  }
  if (
    eventName === 'beforeReadFile' ||
    eventName === 'beforeTabFileRead' ||
    eventName === 'afterFileEdit' ||
    eventName === 'afterTabFileEdit'
  ) {
    return eventName.startsWith('before') ? 'Read' : 'Edit';
  }
  const rawName = stringField(raw, 'tool_name', 'toolName');
  if (rawName !== undefined) {
    return normalizeCursorToolName(rawName);
  }
  const input = valueField(raw, 'tool_input', 'toolInput');
  if (
    stringField(raw, 'command', 'cmd') !== undefined ||
    typeof input === 'string' ||
    (isRecord(input) && stringField(input, 'command', 'cmd') !== undefined)
  ) {
    return 'Bash';
  }
  if (
    stringField(raw, 'file_path', 'filePath', 'path') !== undefined ||
    (isRecord(input) && stringField(input, 'file_path', 'filePath', 'path') !== undefined)
  ) {
    return 'Read';
  }
  return '';
};

const cursorTopLevelToolInput = (tool: string, raw: JsonRecord): JsonRecord => {
  if (tool === 'Bash') {
    return { command: inputStringField(raw, undefined, 'command', 'cmd') };
  }
  const input: JsonRecord = { file_path: stringField(raw, 'file_path', 'filePath', 'path') };
  if (tool === 'Write') {
    input['content'] = stringField(raw, 'content', 'fileText', 'text');
  }
  if (tool === 'Edit') {
    input['old_string'] = stringField(raw, 'old_string', 'oldString');
    input['new_string'] = stringField(raw, 'new_string', 'newString');
  }
  return input;
};

const cursorToolInput = (eventName: string, tool: string, raw: JsonRecord, post: boolean) => {
  const input = valueField(raw, 'tool_input', 'toolInput');
  const required = !post;
  if (eventName === 'beforeShellExecution' || eventName === 'afterShellExecution') {
    const command = inputStringField(raw, input, 'command', 'cmd');
    return { command: required ? requiredString(command, 'command') : (command ?? '') };
  }
  if (
    eventName === 'beforeReadFile' ||
    eventName === 'beforeTabFileRead' ||
    eventName === 'afterFileEdit' ||
    eventName === 'afterTabFileEdit'
  ) {
    const filePath = inputStringField(raw, input, 'file_path', 'filePath', 'path');
    return normalizeToolInput(
      tool,
      {
        file_path: required ? requiredString(filePath, 'file path') : (filePath ?? ''),
        ...(Array.isArray(raw['edits']) && { edits: raw['edits'] }),
      },
      required,
    );
  }
  if (input === undefined && ['Bash', 'Read', 'Write', 'Edit'].includes(tool)) {
    return normalizeToolInput(tool, cursorTopLevelToolInput(tool, raw), required);
  }
  return normalizeToolInput(tool, input, required);
};

const cursorToolResponse = (eventName: string, tool: string, raw: JsonRecord): unknown => {
  if (eventName === 'afterShellExecution') {
    return normalizeToolResponse(tool, stringField(raw, 'output') ?? '');
  }
  const response = valueField(
    raw,
    'tool_response',
    'toolResponse',
    'tool_output',
    'toolOutput',
    'result',
    'result_json',
  );
  return normalizeToolResponse(tool, response);
};

const normalizeCursorEvent = (
  raw: JsonRecord,
  eventName: string,
  post: boolean,
): { readonly event: HookEvent; readonly host: HookHost } => {
  const tool = cursorToolName(eventName, raw);
  const input = cursorToolInput(eventName, tool, raw, post);
  const response = post ? cursorToolResponse(eventName, tool, raw) : undefined;
  const cwd = stringField(raw, 'cwd');
  const sessionId = stringField(raw, 'conversation_id', 'session_id');
  const toolUseId = stringField(raw, 'tool_use_id');
  const event: HookEvent = {
    hook_event_name: post ? 'PostToolUse' : 'PreToolUse',
    ...(tool.length > 0 && { tool_name: tool }),
    ...(input !== undefined && { tool_input: input }),
    ...(response !== undefined && { tool_response: response }),
    ...(cwd !== undefined && { cwd }),
    ...(sessionId !== undefined && { session_id: sessionId }),
    ...(toolUseId !== undefined && { tool_use_id: toolUseId }),
  };
  return { event, host: cursorHost(eventName) };
};

const normalizeHookInput = (raw: unknown, hintedEventName?: string): NormalizedHookInput => {
  if (hintedEventName !== undefined && !isCursorEventName(hintedEventName)) {
    throw new Error(`Unknown Cursor hook event "${hintedEventName}"`);
  }
  if (!isRecord(raw)) {
    if (hintedEventName !== undefined) {
      throw new Error(`Cursor ${hintedEventName} hook payload must be a JSON object`);
    }
    return { event: raw, host: { kind: 'native' } };
  }
  const eventName = hintedEventName ?? stringField(raw, 'hook_event_name');
  if (eventName !== undefined && CURSOR_PRE_EVENTS.has(eventName)) {
    return normalizeCursorEvent(raw, eventName, false);
  }
  if (eventName !== undefined && CURSOR_POST_EVENTS.has(eventName)) {
    return normalizeCursorEvent(raw, eventName, true);
  }
  return { event: raw, host: { kind: 'native' } };
};

export {
  CURSOR_POST_EVENTS,
  CURSOR_PRE_EVENTS,
  cursorHost,
  normalizeHookInput,
  type HookHost,
  type NormalizedHookInput,
};
