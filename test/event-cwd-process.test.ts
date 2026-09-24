import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const entry = new URL('../src/main.ts', import.meta.url).pathname;

bunTest.test('hook and CLI event boundaries use real cwd without the test preload', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'tripwire-event-cwd-'));
  const cwd = path.join(root, 'project');
  const other = path.join(root, 'other');
  const home = path.join(root, 'home');
  for (const directory of [cwd, other, home]) {
    mkdirSync(directory);
  }
  writeFileSync(path.join(cwd, 'fixture.json'), '{"value":"fictional"}');
  const code = 'const value=require("./fixture.json"); console.log(value)';
  const command = `node -e '${code}'`;
  const run = (args: readonly string[], event?: unknown): string => {
    const child = Bun.spawnSync([process.execPath, entry, ...args], {
      cwd,
      env: {
        HOME: home,
        PATH: path.dirname(process.execPath),
        TRIPWIRE_CONFIG: path.join(home, 'config.json'),
      },
      ...(event !== undefined && { stdin: new TextEncoder().encode(JSON.stringify(event)) }),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    bunTest.expect(child.exitCode).toBe(0);
    return child.stdout.toString();
  };
  try {
    for (const [tool, input] of [
      ['Bash', { command }],
      ['javascript', { code }],
      ['exec_command', { cmd: command }],
    ] as const) {
      const event = { hook_event_name: 'PreToolUse', tool_name: tool, tool_input: input };
      bunTest.expect(run(['--tripwire-hook'], event).trim()).toBe('{"continue": true}');
      bunTest.expect(run(['--tripwire-hook'], { ...event, cwd: other })).toContain('"deny"');
    }
    bunTest.expect(run(['test', command])).toContain('"continue": true');
    const script = path.join(cwd, 'example.sh');
    writeFileSync(script, 'cd project-child\nprintf "cwd-boundary-ok"\n');
    mkdirSync(path.join(cwd, 'project-child'));
    bunTest.expect(run(['run-script', script])).toBe('cwd-boundary-ok');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
