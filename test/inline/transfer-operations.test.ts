import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';
import { analyzeCode } from '../../src/lib/code/analyze';
import type { CodeLanguage, CodeOperation } from '../../src/lib/code/types';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

bunTest.test('transfers carry paths directly, including option-shaped filenames', () => {
  const report = analyzeCode(
    'python',
    'import os,shutil\nos.rename("--","target")\nshutil.copy("source","destination")\nos.symlink("source","link")',
    [],
    '/tmp',
  );
  bunTest.expect(report.gap).toBeNull();
  bunTest.expect(report.operations.map(({ range: _range, ...operation }) => operation)).toEqual([
    { kind: 'transfer', command: 'mv', sources: ['--'], destination: 'target', cwd: '/tmp' },
    {
      kind: 'transfer',
      command: 'cp',
      sources: ['source'],
      destination: 'destination',
      cwd: '/tmp',
    },
    { kind: 'transfer', command: 'ln', sources: ['source'], destination: 'link', cwd: '/tmp' },
  ]);
});

bunTest.test.each([
  'Path("source").rename("target")',
  'Path("target").rename("other")',
  'Path("target").symlink_to("source")',
])('resolution rejects overlap after %s', (transfer) => {
  const report = analyzeCode(
    'python',
    `from pathlib import Path\n${transfer}\nPath("target").resolve()`,
    [],
    '/tmp',
  );
  bunTest.expect(report.gap).toContain('Earlier filesystem effects');
});

bunTest.test('unrelated transfers and literal transfer processes retain path resolution', () => {
  const prefix = 'from pathlib import Path\n';
  bunTest
    .expect(
      analyzeCode('python', `${prefix}Path("a").rename("b")\nPath("c").resolve()`, [], '/tmp').gap,
    )
    .toBeNull();
  bunTest
    .expect(
      analyzeCode(
        'python',
        `${prefix}import subprocess\nsubprocess.run(["mv","--","a","b"])\nPath("c").resolve()`,
        [],
        '/tmp',
      ).gap,
    )
    .toBeNull();
});

bunTest.test('unclassified subprocess effects invalidate later resolution', () => {
  const source =
    'from pathlib import Path; import subprocess; subprocess.run(["custom-tool"]); Path("c").resolve()';
  bunTest
    .expect(analyzeCode('python', source, [], '/tmp').gap)
    .toContain('Earlier filesystem effects');
});

const transfers: readonly [CodeLanguage, string, readonly CodeOperation['kind'][]][] = [
  [
    'python',
    'from pathlib import Path\nPath("/tmp/example-a").rename("/tmp/example-b")',
    ['transfer'],
  ],
  [
    'python',
    'from pathlib import Path\nPath("/tmp/example-a").replace("/tmp/example-b")',
    ['transfer'],
  ],
  ['python', 'from pathlib import Path\nPath("example-a").symlink_to("example-b")', ['transfer']],
  ['python', 'import os\nos.rename("/tmp/example-a","/tmp/example-b")', ['transfer']],
  ['python', 'import shutil\nshutil.copy("example-a","example-b")', ['transfer']],
  ['python', 'import shutil\nshutil.move("/tmp/example-a","/tmp/example-b")', ['transfer']],
  ['javascript', 'require("fs").renameSync("/tmp/example-a","/tmp/example-b")', ['transfer']],
  ['javascript', 'require("fs").copyFileSync("example-a","example-b")', ['transfer']],
  ['javascript', 'require("fs").mkdirSync("example")', ['write']],
  ['javascript', 'require("fs").symlinkSync("example-a","example-b")', ['transfer']],
];
bunTest.test.each(transfers)('extracts %s file effects: %s', (language, source, kinds) => {
  const report = analyzeCode(language, source, [], '/tripwire-policy-fixture');
  bunTest.expect(report.gap).toBeNull();
  bunTest.expect(report.operations.map((operation) => operation.kind)).toEqual([...kinds]);
  const runner = language === 'python' ? 'python3 -c' : 'node -e';
  bunTest
    .expect(decideBash(`${runner} ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('allow');
  const dangerous = source
    .replaceAll('example-b', '.env')
    .replaceAll('mkdirSync("example")', 'mkdirSync(".ssh/example")');
  bunTest
    .expect(
      decideBash(`${runner} ${quote(dangerous)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind,
    )
    .toBe('deny');
});
