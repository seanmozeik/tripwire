import { Schema } from 'effect';

const HookEvent = Schema.Struct({
  hook_event_name: Schema.String,
  tool_name: Schema.optional(Schema.String),
  tool_input: Schema.optional(Schema.Unknown),
  tool_response: Schema.optional(Schema.Unknown),
  cwd: Schema.optional(Schema.String),
  session_id: Schema.optional(Schema.String),
  // Codex extension: present on every PreToolUse / PostToolUse event.
  turn_id: Schema.optional(Schema.String),
  tool_use_id: Schema.optional(Schema.String),
});
type HookEventType = typeof HookEvent.Type;

interface BashInput {
  readonly command: string;
}

interface EditInput {
  readonly file_path: string;
  readonly old_string: string;
  readonly new_string: string;
}

interface WriteInput {
  readonly file_path: string;
  readonly content: string;
}

interface ReadInput {
  readonly file_path: string;
}

// PostToolUse `tool_response` shape varies by tool. Bash returns
// Stdout/stderr/interrupted; Read returns content; others vary. We extract
// Any string-ish payload we can find for scanning purposes.
interface BashResponse {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly interrupted?: boolean;
}

interface ReadResponse {
  readonly content?: string;
  readonly file?: { readonly content?: string };
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isBashInput = (x: unknown): x is BashInput => isRecord(x) && typeof x['command'] === 'string';

const isEditInput = (x: unknown): x is EditInput =>
  isRecord(x) &&
  typeof x['file_path'] === 'string' &&
  typeof x['old_string'] === 'string' &&
  typeof x['new_string'] === 'string';

const isWriteInput = (x: unknown): x is WriteInput =>
  isRecord(x) && typeof x['file_path'] === 'string' && typeof x['content'] === 'string';

const isReadInput = (x: unknown): x is ReadInput =>
  isRecord(x) && typeof x['file_path'] === 'string';

// Extract any string payload from a tool_response we can scan for secrets.
// Returns concatenated stdout/stderr for Bash, content for Read, or '' if
// Nothing is recognizable.
const extractResponseText = (toolName: string, response: unknown): string => {
  if (!isRecord(response)) {
    return '';
  }
  if (toolName === 'Bash') {
    const stdout = typeof response['stdout'] === 'string' ? response['stdout'] : '';
    const stderr = typeof response['stderr'] === 'string' ? response['stderr'] : '';
    return [stdout, stderr].filter((text) => text.length > 0).join('\n');
  }
  if (toolName === 'Read') {
    if (typeof response['content'] === 'string') {
      return response['content'];
    }
    const { file } = response;
    return isRecord(file) && typeof file['content'] === 'string' ? file['content'] : '';
  }
  // Best-effort fallback: stringify and let the scanner do its thing.
  return typeof response['content'] === 'string' ? response['content'] : '';
};

export type {
  BashInput,
  BashResponse,
  EditInput,
  HookEventType as HookEvent,
  ReadInput,
  ReadResponse,
  WriteInput,
};
export {
  HookEvent as HookEventSchema,
  extractResponseText,
  isBashInput,
  isEditInput,
  isReadInput,
  isWriteInput,
};
