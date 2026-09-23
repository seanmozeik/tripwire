import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash } from '../src/dispatch';
import { analyzeBash } from '../src/lib/bash';

bunTest.test('recursive globs stay unresolved without scanning the filesystem', () => {
  const program = analyzeBash('ls ~/dev/**/package.json', { home: '/fictional-home' });
  const word = program.invocations[0]?.words[1];
  bunTest.expect(word?.source).toBe('~/dev/**/package.json');
  bunTest.expect(word?.kind).toBe('dynamic');
  bunTest
    .expect(decideBash('ls ~/dev/**/package.json', {}, { home: '/fictional-home' }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash('cp ~/dev/**/package.json /tmp/example-target', {}, { home: '/fictional-home' })
        .kind,
    )
    .toBe('deny');
});

bunTest.test('unknown cwd never expands against the hook directory', () => {
  const program = analyzeBash('ls package.*', { cwd: null });
  bunTest.expect(program.invocations[0]?.cwd).toBeNull();
  bunTest
    .expect(program.invocations[0]?.words[1])
    .toMatchObject({ value: 'package.*', kind: 'dynamic' });
  bunTest.expect(decideBash('cd "$X"; cp package.* /tmp/example-target').kind).toBe('deny');
});

bunTest.test(
  'single-level globs expand up to 128 matches and retain the original above the limit',
  () => {
    const root = mkdtempSync(path.join(tmpdir(), 'example-glob-'));
    try {
      for (let index = 0; index < 128; index += 1) {
        writeFileSync(path.join(root, `entry-${index}`), 'example');
      }
      const before = analyzeBash('ls entry-*', { cwd: root });
      bunTest.expect(before.invocations[0]?.args.length).toBe(128);
      writeFileSync(path.join(root, 'entry-128'), 'example');
      const after = analyzeBash('ls entry-*', { cwd: root });
      bunTest
        .expect(after.invocations[0]?.words[1])
        .toMatchObject({ value: 'entry-*', kind: 'dynamic' });
      bunTest.expect(after.invocations[0]?.args.length).toBe(1);
      bunTest
        .expect(decideBash('cp entry-* /tmp/example-target', {}, { cwd: root }).kind)
        .toBe('deny');
      mkdirSync(path.join(root, 'example-a'));
      mkdirSync(path.join(root, 'example-b'));
      const command = `for d in ${root}/example-*; do git -C $d branch --show-current; done`;
      const program = analyzeBash(command, { cwd: null });
      bunTest
        .expect(
          new Set(
            program.invocations
              .filter((invocation) => invocation.head === 'git')
              .map((invocation) => invocation.tokens[2]),
          ),
        )
        .toEqual(new Set([path.join(root, 'example-a'), path.join(root, 'example-b')]));
      bunTest.expect(decideBash(command, {}, { cwd: null }).kind).toBe('allow');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);
