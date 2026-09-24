import * as bunTest from 'bun:test';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decide, decideBash } from '../src/dispatch';
import { analyzeCode } from '../src/lib/code/analyze';
import { writeParityFixtures } from './fixtures/write-parity';

for (const fixture of writeParityFixtures) {
  bunTest.test(fixture.name, () => {
    const decision = decideBash(fixture.command, {}, { cwd: '/tripwire-policy-fixture' });
    bunTest.expect(decision.kind, decision.message).toBe(fixture.allowed ? 'allow' : 'deny');
  });
}

bunTest.test('ordinary writes retain write effects even when the bytes may be empty', () => {
  for (const source of [
    'open("output.json", "w").write("")',
    'from pathlib import Path; Path("output.json").write_text(Path("input.txt").read_text()[0:0])',
  ]) {
    const report = analyzeCode('python', source, [], '/tripwire-policy-fixture');
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(
        report.operations.some(
          (operation) => operation.kind === 'write' && operation.path === 'output.json',
        ),
      )
      .toBe(true);
    bunTest
      .expect(report.operations.some((operation) => operation.kind === 'truncate'))
      .toBe(false);
  }
});

bunTest.test('Python and JS writes match dedicated Write across resolved destinations', () => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'tripwire-write-parity-'));
  try {
    mkdirSync(path.join(cwd, 'src'));
    mkdirSync(path.join(cwd, '.ssh'));
    writeFileSync(path.join(cwd, '.env'), 'fixture sentinel');
    writeFileSync(path.join(cwd, 'src/output.json'), 'ordinary sentinel');
    symlinkSync(path.join(cwd, '.env'), path.join(cwd, 'alias'));
    symlinkSync(path.join(cwd, '.env.new'), path.join(cwd, 'dangling'));
    symlinkSync(path.join(cwd, '.ssh'), path.join(cwd, 'keys'));
    symlinkSync(path.join(cwd, 'src'), path.join(cwd, 'source'));
    for (const [target, expected] of [
      ['src/output.json', 'allow'],
      [path.join(cwd, 'src/output.json'), 'allow'],
      [path.join(cwd, '.env'), 'deny'],
      ['source/new.json', 'allow'],
      ['.env', 'deny'],
      ['src/../.env', 'deny'],
      ['alias', 'deny'],
      ['dangling', 'deny'],
      ['keys/new-file', 'deny'],
    ] as const) {
      const dedicated = decide({
        hook_event_name: 'PreToolUse',
        tool_name: 'Write',
        tool_input: { file_path: path.join(cwd, target), content: '' },
      });
      bunTest.expect(dedicated.kind).toBe(expected);
      for (const command of [
        `python3 -c 'open("${target}","w").write("")'`,
        `node -e 'require("fs").writeFileSync("${target}","")'`,
      ]) {
        bunTest.expect(decideBash(command, {}, { cwd }).kind, command).toBe(dedicated.kind);
      }
    }
    bunTest.expect(readFileSync(path.join(cwd, '.env'), 'utf8')).toBe('fixture sentinel');
    bunTest
      .expect(readFileSync(path.join(cwd, 'src/output.json'), 'utf8'))
      .toBe('ordinary sentinel');
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});
