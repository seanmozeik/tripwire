import type { SecretScannerConfig } from '../lib/config';
import { type Decision, allow, deny } from '../lib/decision';
import { extractResponseText } from '../lib/event';
import { scanAndRedact, type ScannerRunner, type ScanFailureCategory } from '../lib/secrets';

// PostToolUse: scan whatever string content a tool returned (Bash stdout,
// Read content) for known secret patterns via betterleaks. If anything
// Fires, block the result (so the original output never reaches the
// Model) and surface a redacted version in the block reason — that lets
// The agent see what was returned without leaking the secret itself.

interface PostInput {
  readonly toolName: string;
  readonly response: unknown;
  readonly secretScanner: SecretScannerConfig;
  readonly scannerRunner?: ScannerRunner;
}

const scannerFailureMessage = (category: ScanFailureCategory): string =>
  `Tripwire could not verify this tool output because the configured secret scanner failed ` +
  `(${category}). The original output was withheld. Install Betterleaks 1.5.0 or later, ` +
  `check secretScanner.executable and secretScanner.timeoutMs, then run the original tool again.`;

const postSecretScrub = (input: PostInput): Decision => {
  const text = extractResponseText(input.toolName, input.response);
  if (text.length === 0) {
    return allow('post-secret-scrub');
  }
  const result = scanAndRedact(text, input.secretScanner, input.scannerRunner);
  if (!result.ok) {
    return deny('secret-scanner-failed', scannerFailureMessage(result.category));
  }
  if (result.hits.length === 0) {
    return allow('post-secret-scrub');
  }
  const summary = result.hits.map((hit) => `${hit.rule}×${hit.count}`).join(', ');
  return deny(
    'secrets-in-output',
    [
      `tripwire intercepted ${result.hits.length} secret pattern(s) in this tool's output (${summary}). The original output was withheld so the secret never enters the model context. A redacted form is below — work from this, do not re-run the same command in a way that re-fetches the underlying secret.`,
      ``,
      `Redacted output:`,
      result.redacted.slice(0, 16_000) + (result.redacted.length > 16_000 ? '\n…[truncated]' : ''),
    ].join('\n'),
  );
};

export type { PostInput };
export { postSecretScrub };
