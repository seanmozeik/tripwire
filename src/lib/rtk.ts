// Wrap the `rtk hook claude` subprocess. After tripwire's gate passes on a
// Bash tool call, we hand the original event to rtk to apply its
// Command-rewrite logic (token-saver). If rtk returns an updatedInput, we
// Merge that into our hook response.

import { spawnSync } from 'node:child_process';

import type { RtkConfig } from './config';

interface RtkOutput {
  readonly updatedCommand?: string;
  readonly reason?: string;
}

const findRtkBin = (config: RtkConfig): string | null => {
  // If config specifies a path, try it first
  if (config.path !== undefined) {
    return config.path;
  }

  // Try common locations
  const home = process.env['HOME'] ?? '';
  const commonPaths = ['/opt/homebrew/bin/rtk', '/usr/local/bin/rtk', `${home}/.local/bin/rtk`];

  for (const path of commonPaths) {
    try {
      spawnSync('test', ['-x', path], { stdio: 'ignore' });
      return path;
    } catch {
      continue;
    }
  }

  // Try searching PATH
  try {
    const whichResult = spawnSync('which', ['rtk'], { stdio: 'pipe' });
    if (whichResult.status === 0) {
      const stdout = whichResult.stdout as string | Buffer | null;
      if (stdout !== null) {
        const path = String(stdout).trim();
        if (path.length > 0) {
          return path;
        }
      }
    }
  } catch {
    // Ignore errors
  }

  return null;
};

const runRtkRewrite = (event: unknown, config: RtkConfig, timeoutMs = 2000): RtkOutput => {
  // If rtk is disabled, skip it
  if (!config.enabled) {
    return {};
  }

  const rtkBin = findRtkBin(config);
  if (rtkBin === null) {
    // Rtk not found, silently continue
    return {};
  }

  const payload = JSON.stringify(event);
  const result = spawnSync(rtkBin, ['hook', 'claude'], {
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
