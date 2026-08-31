import * as bunTest from 'bun:test';
import { existsSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const fixture = (name: string): string => path.join(import.meta.dirname, 'fixtures', name);

const run = (arguments_: readonly string[], home: string) =>
  Bun.spawnSync([process.execPath, 'src/main.ts', 'run-script', ...arguments_], {
    cwd: path.join(import.meta.dirname, '..'),
    env: { ...process.env, HOME: home },
    stderr: 'pipe',
    stdout: 'pipe',
  });

bunTest.describe('run-script', () => {
  let home = '';

  bunTest.beforeEach(async () => {
    home = await mkdtemp(path.join(tmpdir(), 'tripwire-run-script-home-'));
  });

  bunTest.afterEach(async () => {
    await rm(home, { force: true, recursive: true });
  });

  bunTest.test('executes the exact inspected bytes with positional arguments', () => {
    const result = run([fixture('checked-safe.sh'), '--', 'fixture value'], home);

    bunTest.expect(result.exitCode).toBe(0);
    bunTest.expect(result.stdout.toString()).toBe('safe:fixture value\n');
    bunTest.expect(result.stderr.toString()).toBe('');
  });

  bunTest.test('rejects a destructive script before any byte executes', () => {
    const marker = path.join(home, 'must-not-exist');
    const result = run([fixture('checked-dangerous.sh'), '--', marker], home);

    bunTest.expect(result.exitCode).not.toBe(0);
    bunTest.expect(result.stderr.toString()).toContain('[tripwire:rm-rf-root]');
    bunTest.expect(existsSync(marker)).toBeFalse();
  });

  bunTest.test('applies policy to the actual positional argument values', () => {
    const result = run([fixture('checked-argument-policy.sh'), '--', '--force'], home);

    bunTest.expect(result.exitCode).not.toBe(0);
    bunTest.expect(result.stderr.toString()).toContain('[tripwire:git-force-push]');
  });
});
