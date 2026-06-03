import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
// oxlint-disable-next-line unicorn/import-style
import { dirname } from 'node:path';

const LOG_PATH = `${homedir()}/.claude/tripwire.log`;

try {
  mkdirSync(dirname(LOG_PATH), { recursive: true });
} catch {
  // Directory creation failure is non-fatal — logging is best-effort.
}

const logError = (rule: string, err: unknown): void => {
  const stamp = new Date().toISOString();
  const msg = err instanceof Error ? (err.stack ?? err.message) : String(err);
  try {
    appendFileSync(LOG_PATH, `[${stamp}] [${rule}] ${msg}\n`);
  } catch {
    // Never block the agent on a logging failure.
  }
};

export { logError };
