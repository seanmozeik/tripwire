import * as bunTest from 'bun:test';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decide } from '../src';
import { analyzeBash } from '../src/lib/bash';
import { bashDeny } from '../src/rules/bash-deny';
import { bashRedirect } from '../src/rules/bash-redirect';
import { bashTarExplosion } from '../src/rules/bash-tar-explosion';
import { lazyCode } from '../src/rules/lazy-code';
import { pathProtect } from '../src/rules/path-protect';
import { readProtect } from '../src/rules/read-protect';

const shellDecision = (command: string) =>
  decide({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } });

const bashDenyDecision = (command: string) => bashDeny(analyzeBash(command));

const lazyCodeDecision = (line: string) =>
  lazyCode({ file_path: 'src/example.ts', old_string: '', new_string: line });

const tarDecision = (command: string) => bashTarExplosion(analyzeBash(command));

bunTest.describe('compound shell commands', () => {
  bunTest.test('treats shell negation as a transparent command prefix', () => {
    const dangerous = [
      '! rm -rf /',
      'if ! rm -rf /; then echo safe; fi',
      'while ! shutdown -h now; do echo safe; done',
    ];

    for (const command of dangerous) {
      bunTest.expect(shellDecision(command).kind, command).toBe('deny');
    }
    bunTest.expect(shellDecision('! test -f file').kind).toBe('allow');
    bunTest.expect(shellDecision('if ! test -f file; then echo missing; fi').kind).toBe('allow');
  });

  bunTest.test('checks executable commands after every supported control keyword', () => {
    const dangerous = [
      'if rm -rf /; then echo safe; fi',
      'if false; then echo safe; elif shutdown -h now; then echo unreachable; fi',
      'if true; then rm -rf /; fi',
      'if false; then echo safe; else shutdown -h now; fi',
      'while shutdown -h now; do echo safe; done',
      'until rm -rf /; do echo safe; done',
      'while true; do rm -rf /; done',
    ];

    for (const command of dangerous) {
      bunTest.expect(shellDecision(command).kind, command).toBe('deny');
    }
  });

  bunTest.test('allows supported compounds only when every executable node is safe', () => {
    const safe = [
      'if test -f file; then echo yes; else echo no; fi',
      'if false; then echo no; elif true; then echo yes; fi',
      'while false; do echo never; done',
      'until true; do echo never; done',
      'if true; then while false; do echo never; done; fi',
    ];

    for (const command of safe) {
      bunTest.expect(shellDecision(command).kind, command).toBe('allow');
    }
  });

  bunTest.test('allows compound structures when every executable node is inspectable', () => {
    const safe = [
      'case value in value) echo safe;; esac',
      'function safe_name { echo safe; }; safe_name',
      'safe_name(){ echo safe; }; safe_name',
      '{ echo safe; }',
      '(echo safe)',
      "alias inspect='git status'; inspect",
    ];

    for (const command of safe) {
      bunTest.expect(shellDecision(command).kind, command).toBe('allow');
    }
  });

  bunTest.test('checks commands inside compounds, local functions, and aliases', () => {
    const dangerous = [
      'case value in value) rm -rf /;; esac',
      '{ git reset --hard HEAD~1; }',
      '(rm -rf /)',
      'cleanup(){ rm -rf /; }; cleanup',
      "alias cleanup='rm -rf /'; cleanup",
    ];

    for (const command of dangerous) {
      bunTest.expect(shellDecision(command).kind, command).toBe('deny');
    }
  });

  bunTest.test('fails closed for dynamic execution and recursive definitions', () => {
    const unsupported = [
      'command_name=$(command -v echo); "$command_name" safe',
      "eval 'echo safe'",
      'again(){ again; }; again',
    ];

    for (const command of unsupported) {
      const decision = shellDecision(command);
      bunTest.expect(decision.kind, command).toBe('deny');
      bunTest.expect(decision.rule, command).toBe('unsupported-shell-structure');
    }
  });

  bunTest.test('does not reparse quoted text or literal heredoc bodies as commands', () => {
    bunTest
      .expect(shellDecision(String.raw`printf '%s\n' 'if true; then rm -rf /; fi'`).kind)
      .toBe('allow');
    bunTest
      .expect(shellDecision("cat <<'EOF'\ncase value in value) rm -rf /;; esac\nEOF").kind)
      .toBe('allow');
  });
});

bunTest.describe('protected path aliases', () => {
  let dir = '';
  let envAlias = '';
  let safeAlias = '';
  let protectedParentAlias = '';
  let source = '';

  bunTest.beforeEach(async () => {
    dir = await mkdtemp(path.join(tmpdir(), 'tripwire-paths-'));
    const envPath = path.join(dir, '.env');
    const safePath = path.join(dir, 'safe-target.txt');
    source = path.join(dir, 'source.txt');
    const sshDir = path.join(dir, '.ssh');
    envAlias = path.join(dir, 'environment.txt');
    safeAlias = path.join(dir, 'safe-alias.txt');
    protectedParentAlias = path.join(dir, 'settings');

    await mkdir(sshDir);
    await writeFile(envPath, 'placeholder');
    await writeFile(safePath, 'safe');
    await writeFile(source, 'source');
    await symlink(envPath, envAlias);
    await symlink(safePath, safeAlias);
    await symlink(sshDir, protectedParentAlias);
  });

  bunTest.afterEach(async () => {
    await rm(dir, { force: true, recursive: true });
  });

  bunTest.test('denies read, edit, and write aliases to a protected file', () => {
    bunTest.expect(readProtect({ file_path: envAlias }).kind).toBe('deny');
    bunTest
      .expect(pathProtect({ file_path: envAlias, old_string: 'before', new_string: 'after' }).kind)
      .toBe('deny');
    bunTest.expect(pathProtect({ file_path: envAlias, content: 'after' }).kind).toBe('deny');
  });

  bunTest.test('denies redirect, copy, and move aliases to a protected file', () => {
    const commands = [
      `echo value > ${JSON.stringify(envAlias)}`,
      `cp ${JSON.stringify(source)} ${JSON.stringify(envAlias)}`,
      `mv ${JSON.stringify(source)} ${JSON.stringify(envAlias)}`,
    ];

    for (const command of commands) {
      bunTest.expect(bashRedirect(analyzeBash(command)).kind, command).toBe('deny');
    }
  });

  bunTest.test('resolves the deepest existing parent for a new write', () => {
    const newProtectedPath = path.join(protectedParentAlias, 'new-config');
    bunTest
      .expect(pathProtect({ file_path: newProtectedPath, content: 'after' }).kind)
      .toBe('deny');

    const command = `echo value > ${JSON.stringify(newProtectedPath)}`;
    bunTest.expect(bashRedirect(analyzeBash(command)).kind).toBe('deny');
  });

  bunTest.test('allows aliases whose resolved target is safe', () => {
    const ordinaryNewPath = path.join(dir, 'new-file.txt');
    bunTest.expect(readProtect({ file_path: safeAlias }).kind).toBe('allow');
    bunTest.expect(pathProtect({ file_path: safeAlias, content: 'after' }).kind).toBe('allow');
    bunTest
      .expect(pathProtect({ file_path: safeAlias, old_string: 'before', new_string: 'after' }).kind)
      .toBe('allow');

    const command = `echo value > ${JSON.stringify(safeAlias)}`;
    bunTest.expect(bashRedirect(analyzeBash(command)).kind).toBe('allow');
    bunTest
      .expect(pathProtect({ file_path: ordinaryNewPath, content: 'after' }).kind)
      .toBe('allow');
  });
});

bunTest.describe('bypass reasons', () => {
  bunTest.test('requires a colon and a non-empty reason for shell bypasses', () => {
    bunTest.expect(bashDenyDecision('rsync --delete src/ dst/ # tripwire-allow').kind).toBe('deny');
    bunTest
      .expect(bashDenyDecision('rsync --delete src/ dst/ # tripwire-allow:   ').kind)
      .toBe('deny');
    bunTest
      .expect(
        bashDenyDecision('rsync --delete src/ dst/ # tripwire-allow:\necho next-command').kind,
      )
      .toBe('deny');
    bunTest
      .expect(bashDenyDecision('rsync --delete src/ dst/ # tripwire-allow: mirror refresh').kind)
      .toBe('allow');
  });

  bunTest.test('keeps catastrophic rules non-bypassable with a reason', () => {
    bunTest.expect(bashDenyDecision('rm -rf / # tripwire-allow: clean machine').kind).toBe('deny');
  });

  bunTest.test('requires a colon and a non-empty reason for lazy-code bypasses', () => {
    bunTest.expect(lazyCodeDecision('const placeholder = 1; // tripwire-allow').kind).toBe('warn');
    bunTest
      .expect(lazyCodeDecision('const placeholder = 1; // tripwire-allow:   ').kind)
      .toBe('warn');
    bunTest
      .expect(lazyCodeDecision('const placeholder = 1; // tripwire-allow: public API field').kind)
      .toBe('allow');
  });
});

bunTest.describe('tar extraction classification', () => {
  bunTest.test('allows listing an archive with a root change-directory argument', () => {
    bunTest.expect(tarDecision('tar -tf archive.tar -C /').kind).toBe('allow');
    bunTest.expect(tarDecision('tar --list -f archive.tar -C /').kind).toBe('allow');
  });

  bunTest.test('denies extraction into root', () => {
    bunTest.expect(tarDecision('tar -xf archive.tar -C /').kind).toBe('deny');
    bunTest.expect(tarDecision('tar --extract -f archive.tar -C /').kind).toBe('deny');
    bunTest.expect(tarDecision('tar xf archive.tar -C /').kind).toBe('deny');
  });
});
