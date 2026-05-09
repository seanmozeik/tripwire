// Wrap the `rtk hook claude` subprocess. After tripwire's gate passes on a
// Bash tool call, we hand the original event to rtk to apply its
// Command-rewrite logic (token-saver). If rtk returns an updatedInput, we
// Merge that into our hook response.

import { spawnSync } from 'node:child_process';

const RTK_BIN = '/opt/homebrew/bin/rtk';

interface RtkOutput {
  readonly updatedCommand?: string;
  readonly reason?: string;
}

const runRtkRewrite = (event: unknown, timeoutMs = 2000): RtkOutput => {
  const payload = JSON.stringify(event);
  const result = spawnSync(RTK_BIN, ['hook', 'claude'], {
    input: payload,
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer: 1024 * 1024,
  });
  if (result.error !== undefined || typeof result.stdout !== 'string') {
    return {};
  }
  try {
    const parsed = JSON.parse(result.stdout) as {
      hookSpecificOutput?: {
        permissionDecisionReason?: string;
        updatedInput?: { command?: string };
      };
    };
    const cmd = parsed.hookSpecificOutput?.updatedInput?.command;
    const reason = parsed.hookSpecificOutput?.permissionDecisionReason;
    if (typeof cmd !== 'string') {
      return {};
    }
    if (typeof reason === 'string') {
      return { updatedCommand: cmd, reason };
    }
    return { updatedCommand: cmd };
  } catch {
    return {};
  }
};

export { runRtkRewrite };
