import * as bunTest from 'bun:test';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decide } from '../../src/dispatch';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

const inspect = (command: string, cwd: string): string =>
  decide({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd, tool_input: { command } }).kind;

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
