import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import path from 'node:path';

import { decide } from '../src/dispatch';
import { analyzeBash } from '../src/lib/bash';

bunTest.test('tracked cwd reaches inline code, redirects, copies, and deletion', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'example-cwd-'));
  const safe = path.join(root, 'ordinary');
  const protectedDirectory = path.join(root, 'protected');
  try {
    mkdirSync(safe);
    mkdirSync(path.join(root, '~'));
    mkdirSync(protectedDirectory);
    writeFileSync(path.join(protectedDirectory, '.env'), 'example');
    symlinkSync('.env', path.join(protectedDirectory, 'output'));
    symlinkSync('/', path.join(protectedDirectory, 'dist'));
    const inspect = (command: string): string =>
      decide({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        cwd: root,
        tool_input: { command },
      }).kind;
    for (const command of [
      'python3 -c \'open("output","w").write("example")\'',
      'echo example > output',
      'cp example output',
      'tee output',
    ]) {
      bunTest.expect(inspect(`cd ordinary && ${command}`)).toBe('allow');
      bunTest.expect(inspect(`cd protected && ${command}`)).toBe('deny');
      bunTest.expect(inspect(`(cd protected); cd ordinary; ${command}`)).toBe('allow');
      bunTest.expect(inspect(`cd "$DIR"; ${command}`)).toBe('deny');
    }
    bunTest.expect(inspect('cd protected; rm -rf dist')).toBe('deny');
    bunTest.expect(inspect('command cd protected; echo example > output')).toBe('deny');
    bunTest.expect(inspect('builtin cd protected; echo example > output')).toBe('deny');
    bunTest
      .expect(inspect("alias enter='cd protected'; enter; echo example > output"))
      .toBe('deny');
    bunTest.expect(inspect('CDPATH=protected cd ordinary; echo example > output')).toBe('deny');
    bunTest.expect(inspect('cd protected || cd ordinary; echo example > output')).toBe('deny');
    bunTest
      .expect(inspect('for x in 1 2; do cd protected; done; echo example > output'))
      .toBe('deny');
    bunTest.expect(inspect('cd /; tar -xf example.tar -C .')).toBe('deny');
    bunTest.expect(inspect('cd /; unzip example.zip -d .')).toBe('deny');
    bunTest.expect(inspect('cd ordinary; rm -rf dist')).toBe('allow');
    bunTest.expect(inspect('cd ordinary || exit; python3 -c \'open("output","w")\'')).toBe('allow');
    bunTest
      .expect(inspect('if test -f example; then cd protected; fi; echo example > output'))
      .toBe('deny');
    bunTest.expect(inspect('cd missing; python3 -c \'open("output","w")\'')).toBe('deny');
    bunTest.expect(inspect('pushd protected; popd; echo example > output')).toBe('allow');
    bunTest.expect(inspect('direnv exec protected tee output')).toBe('deny');
    bunTest.expect(inspect('mise -C protected exec -- tee output')).toBe('deny');
    const directories = analyzeBash(
      "cd '~'; printf literal; cd ~; printf home; cd ~/..; printf parent",
      { cwd: root },
    );
    bunTest
      .expect(
        directories.invocations
          .filter((invocation) => invocation.head === 'printf')
          .map((invocation) => invocation.cwd),
      )
      .toEqual([path.join(root, '~'), homedir(), path.dirname(homedir())]);
    bunTest
      .expect(inspect('pushd ordinary; pushd ../protected; pushd; echo example > output'))
      .toBe('allow');
    bunTest
      .expect(
        inspect('pushd ordinary; pushd ../protected; pushd missing; popd; echo example > output'),
      )
      .toBe('deny');
    const program = analyzeBash('cd ordinary; (cd ..; printf inside); printf outside', {
      cwd: root,
    });
    bunTest
      .expect(
        program.invocations
          .filter((invocation) => invocation.head === 'printf')
          .map((invocation) => invocation.cwd),
      )
      .toEqual([root, safe]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

const inspect = (command: string, cwd: string): string =>
  decide({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd, tool_input: { command } }).kind;

bunTest.test('relative deletion follows the resolved cwd and symlink target', () => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'example-delete-'));
  try {
    symlinkSync('/', path.join(cwd, 'escape'));
    for (const command of [
      'rm x.log',
      'python3 -c \'import os; os.remove("x.log")\'',
      'node -e \'require("fs").unlinkSync("x.log")\'',
    ]) {
      bunTest.expect(inspect(`cd /tmp && ${command}`, cwd)).toBe('allow');
      bunTest.expect(inspect(`cd / && ${command}`, cwd)).toBe('deny');
      bunTest.expect(inspect(`cd missing && ${command}`, cwd)).toBe('deny');
      bunTest.expect(inspect(`cd "$UNKNOWN" && ${command}`, cwd)).toBe('deny');
      bunTest.expect(inspect(command.replaceAll('x.log', 'escape/x.log'), cwd)).toBe('deny');
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

bunTest.test('a safe cwd cannot authorize an unresolved shell operand', () => {
  bunTest.expect(inspect('cd /tmp; rm "$TARGET"', '/')).toBe('deny');
  bunTest.expect(inspect('cd /tmp; find "$TARGET" -delete', '/')).toBe('deny');
});
