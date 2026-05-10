import { type Decision, allow, deny } from '../lib/decision';
import { extractResponseText } from '../lib/event';
import { scanAndRedact } from '../lib/secrets';

// PostToolUse: scan whatever string content a tool returned (Bash stdout,
// Read content) for known secret patterns via betterleaks. If anything
// Fires, block the result (so the original output never reaches the
// Model) and surface a redacted version in the block reason — that lets
// The agent see what was returned without leaking the secret itself.

interface PostInput {
  readonly toolName: string;
  readonly response: unknown;
}

const postSecretScrub = (input: PostInput): Decision => {
  const text = extractResponseText(input.toolName, input.response);
  if (text.length === 0) {
    return allow('post-secret-scrub');
  }
  const { hits, redacted } = scanAndRedact(text);
  if (hits.length === 0) {
    return allow('post-secret-scrub');
  }
  const summary = hits.map((h) => `${h.rule}×${h.count}`).join(', ');
  return deny(
    'secrets-in-output',
    [
      `tripwire intercepted ${hits.length} secret pattern(s) in this tool's output (${summary}). The original output was withheld so the secret never enters the model context. A redacted form is below — work from this, do not re-run the same command in a way that re-fetches the underlying secret.`,
      ``,
      `Redacted output:`,
      redacted.slice(0, 16_000) + (redacted.length > 16_000 ? '\n…[truncated]' : ''),
    ].join('\n'),
  );
};

export type { PostInput };
export { postSecretScrub };
