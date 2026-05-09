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

const isBashInput = (x: unknown): x is BashInput =>
  typeof x === 'object' && x !== null && typeof (x as BashInput).command === 'string';

const isEditInput = (x: unknown): x is EditInput =>
  typeof x === 'object' &&
  x !== null &&
  typeof (x as EditInput).file_path === 'string' &&
  typeof (x as EditInput).old_string === 'string' &&
  typeof (x as EditInput).new_string === 'string';

const isWriteInput = (x: unknown): x is WriteInput =>
  typeof x === 'object' &&
  x !== null &&
  typeof (x as WriteInput).file_path === 'string' &&
  typeof (x as WriteInput).content === 'string';

const isReadInput = (x: unknown): x is ReadInput =>
  typeof x === 'object' && x !== null && typeof (x as ReadInput).file_path === 'string';

// Extract any string payload from a tool_response we can scan for secrets.
// Returns concatenated stdout/stderr for Bash, content for Read, or '' if
// Nothing is recognizable.
const extractResponseText = (toolName: string, response: unknown): string => {
  if (typeof response !== 'object' || response === null) {
    return '';
  }
  if (toolName === 'Bash') {
    const r = response as BashResponse;
    return [r.stdout ?? '', r.stderr ?? ''].filter((s) => s.length > 0).join('\n');
  }
  if (toolName === 'Read') {
    const r = response as ReadResponse;
    return r.content ?? r.file?.content ?? '';
  }
  // Best-effort fallback: stringify and let the scanner do its thing.
  if (typeof (response as { content?: string }).content === 'string') {
    return (response as { content?: string }).content ?? '';
  }
  return '';
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
