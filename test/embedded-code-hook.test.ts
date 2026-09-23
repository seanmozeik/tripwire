import * as bunTest from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { hookInputs, tripwirePiDenialReason } from '../src/pi-extension';

bunTest.test.each([
  {
    toolName: 'bash',
    input: { command: 'python3 - <<\'PY\'\nimport os\nos.unlink("/protected")\nPY' },
  },
  { toolName: 'bash', input: { command: 'node -e \'require("fs").rmSync("/protected")\'' } },
  { toolName: 'python', input: { code: 'import shutil; shutil.rmtree("/protected")' } },
  { toolName: 'js_repl', input: { code: 'console.log(1)' } },
  {
    toolName: 'exec_command',
    input: { cmd: 'node -e \'require("fs").unlinkSync("/protected")\'' },
  },
])('Pi/OMP $toolName event reaches the production hook and blocks', ({ toolName, input }) => {
  const home = mkdtempSync(path.join(tmpdir(), 'tripwire-code-hook-'));
  try {
    const payload = hookInputs({ toolName, input, toolCallId: 'code-fixture' }, 'PreToolUse', home);
    // This runs Tripwire only; payload code is JSON data on stdin.
    const result = Bun.spawnSync(
      [process.execPath, new URL('../src/main.ts', import.meta.url).pathname, '--tripwire-hook'],
      {
        env: { ...process.env, HOME: home },
        stdin: new TextEncoder().encode(JSON.stringify(payload)),
        stdout: 'pipe',
        stderr: 'pipe',
        timeout: 10_000,
      },
    );
    bunTest.expect(result.exitCode).toBe(0);
    bunTest
      .expect(
        tripwirePiDenialReason({
          exitCode: result.exitCode,
          stdout: result.stdout.toString(),
          stderr: result.stderr.toString(),
        }),
      )
      .toContain('embedded-code');
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
