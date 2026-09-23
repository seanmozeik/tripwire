import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decide } from '../src/dispatch';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;
const inspect = (command: string, cwd: string): string =>
  decide({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd, tool_input: { command } }).kind;
const transfers = [
  ['mv', 'python3 -c', 'from pathlib import Path; Path(SOURCE).rename(TARGET)'],
  ['mv', 'python3 -c', 'from pathlib import Path; Path(SOURCE).replace(TARGET)'],
  ['mv', 'python3 -c', 'import os; os.rename(SOURCE,TARGET)'],
  ['mv', 'python3 -c', 'import os; os.replace(SOURCE,TARGET)'],
  ['mv', 'python3 -c', 'import shutil; shutil.move(SOURCE,TARGET)'],
  ['cp', 'python3 -c', 'import shutil; shutil.copy2(SOURCE,TARGET)'],
  ['ln -s', 'python3 -c', 'import os; os.symlink(SOURCE,TARGET)'],
  ['ln -s', 'python3 -c', 'from pathlib import Path; Path(TARGET).symlink_to(SOURCE)'],
  ['mv', 'node -e', 'require("fs").renameSync(SOURCE,TARGET)'],
  ['mv', 'node -e', 'require("fs/promises").rename(SOURCE,TARGET)'],
  ['cp', 'node -e', 'require("fs").copyFileSync(SOURCE,TARGET)'],
  ['cp', 'node -e', 'require("fs/promises").copyFile(SOURCE,TARGET)'],
  ['ln -s', 'node -e', 'require("fs").symlinkSync(SOURCE,TARGET)'],
  ['ln -s', 'node -e', 'require("fs/promises").symlink(SOURCE,TARGET)'],
  ['mv', 'deno eval', 'Deno.rename(SOURCE,TARGET)'],
  ['cp', 'deno eval', 'Deno.copyFile(SOURCE,TARGET)'],
  ['ln -s', 'deno eval', 'Deno.symlink(SOURCE,TARGET)'],
];

bunTest.test.each(transfers)('%s parity through %s: %s', (shell, runner, template) => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'example-transfer-'));
  try {
    mkdirSync(path.join(cwd, 'directory'));
    symlinkSync('.env', path.join(cwd, 'alias'));
    for (const [source, target, expected] of [
      ['a.txt', 'b.txt', 'allow'],
      ['a.txt', '.env', 'deny'],
      ['.env', 'b.txt', 'deny'],
      ['a.txt', 'alias', 'deny'],
      ['.env', 'directory', 'deny'],
      ['a.txt', '/dev/disk0', 'deny'],
    ] as const) {
      const code = template
        .replaceAll('SOURCE', JSON.stringify(source))
        .replaceAll('TARGET', JSON.stringify(target));
      const shellDecision = inspect(`${shell} -- ${quote(source)} ${quote(target)}`, cwd);
      bunTest.expect(shellDecision).toBe(expected);
      bunTest.expect(inspect(`${runner} ${quote(code)}`, cwd)).toBe(shellDecision);
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

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

bunTest.test('resolved paths use the shared filesystem target classification', () => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'example-resolved-'));
  try {
    symlinkSync('a.txt', path.join(cwd, 'link'));
    symlinkSync('.env', path.join(cwd, 'private-link'));
    for (const method of ['resolve', 'readlink']) {
      const source = `from pathlib import Path; Path("link").${method}().write_text("example")`;
      bunTest.expect(inspect(`python3 -c ${quote(source)}`, cwd)).toBe('allow');
      bunTest
        .expect(inspect(`python3 -c ${quote(source.replace('"link"', '"private-link"'))}`, cwd))
        .toBe('deny');
    }
    const changed =
      'from pathlib import Path; Path("link").unlink(); Path("link").resolve().write_text("example")';
    bunTest.expect(inspect(`python3 -c ${quote(changed)}`, cwd)).toBe('deny');
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

bunTest.test.each(['mv', 'cp', 'ln', 'ln -s', 'rsync -a', 'install', 'install -m 600'])(
  '%s checks directory destinations and effective child paths',
  (command) => {
    const cwd = mkdtempSync(path.join(tmpdir(), 'example-directory-transfer-'));
    try {
      mkdirSync(path.join(cwd, '.ssh'));
      mkdirSync(path.join(cwd, '.aws'));
      mkdirSync(path.join(cwd, 'ordinary'));
      symlinkSync('.ssh', path.join(cwd, 'alias'));
      for (const suffix of ['', '/']) {
        for (const destination of ['.ssh', 'alias', '~/.ssh']) {
          bunTest
            .expect(inspect(`${command} /tmp/example-source ${destination}${suffix}`, cwd))
            .toBe('deny');
        }
        bunTest.expect(inspect(`${command} credentials .aws${suffix}`, cwd)).toBe('deny');
        bunTest.expect(inspect(`${command} example.txt ordinary${suffix}`, cwd)).toBe('allow');
      }
      // The slash itself declares a directory even before it exists.
      bunTest.expect(inspect(`${command} credentials absent/.aws/`, cwd)).toBe('deny');
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  },
);

bunTest.test.each(transfers)(
  'protected directory parity for %s via %s: %s',
  (shell, runner, template) => {
    const cwd = mkdtempSync(path.join(tmpdir(), 'example-inline-directory-'));
    try {
      mkdirSync(path.join(cwd, '.ssh'));
      mkdirSync(path.join(cwd, '.aws'));
      mkdirSync(path.join(cwd, 'ordinary'));
      symlinkSync('.ssh', path.join(cwd, 'alias'));
      for (const suffix of ['', '/']) {
        for (const target of ['.ssh', 'alias', 'ordinary']) {
          const destination = `${target}${suffix}`;
          const code = template
            .replaceAll('SOURCE', '"example.txt"')
            .replaceAll('TARGET', JSON.stringify(destination));
          const expected = target === 'ordinary' ? 'allow' : 'deny';
          bunTest.expect(inspect(`${shell} example.txt ${destination}`, cwd)).toBe(expected);
          bunTest.expect(inspect(`${runner} ${quote(code)}`, cwd)).toBe(expected);
        }
        const code = template
          .replaceAll('SOURCE', '"credentials"')
          .replaceAll('TARGET', JSON.stringify(`.aws${suffix}`));
        bunTest.expect(inspect(`${runner} ${quote(code)}`, cwd)).toBe('deny');
      }
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  },
);

bunTest.test('pwd transfer provenance requires a known cwd and an unshadowed builtin', () => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'example-pwd-transfer-'));
  try {
    bunTest
      .expect(inspect('src=$(pwd); dst=$(mktemp -d); rsync -- "$src" "$dst"', cwd))
      .toBe('allow');
    for (const prefix of [
      'pwd() { echo /example/.ssh; };',
      'alias pwd="echo /example/.ssh";',
      'cd "$UNKNOWN";',
    ]) {
      bunTest
        .expect(inspect(`${prefix} src=$(pwd); dst=$(mktemp -d); rsync -- "$src" "$dst"`, cwd))
        .toBe('deny');
    }
    bunTest.expect(inspect('src=$(pwd); rsync -- "$src" .ssh/', cwd)).toBe('deny');
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

bunTest.test('home reassignment cannot redirect a transfer into an unchecked directory', () => {
  bunTest.expect(inspect('HOME=/example/.ssh; cp example.txt ~/record', '/tmp')).toBe('deny');
  bunTest.expect(inspect('HOME="$UNKNOWN"; cp example.txt ~/record', '/tmp')).toBe('deny');
});
