import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';

bunTest.test.each([
  '--show-current',
  '--list',
  '-v',
  '-a',
  '-r',
  '--contains example',
  '--merged',
  '',
])('computed Git directory with branch read %s', (args) => {
  bunTest
    .expect(
      decideBash(
        `for d in /nonexistent-tripwire-fixture/example-*; do git -C $d branch ${args}; done`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('allow');
});
bunTest.test.each([
  '-D example',
  '-m example other',
  '$FLAGS',
  '--list -D example',
  '--set-upstream-to example',
])('computed Git directory with branch mutation %s', (args) => {
  bunTest
    .expect(
      decideBash(`git -C "$DIR" branch ${args}`, {}, { cwd: '/tripwire-policy-fixture' }).kind,
    )
    .toBe('deny');
});
bunTest.test('xargs forwards argv without reparsing generated data as redirects', () => {
  bunTest
    .expect(
      decideBash(
        'xargs pnpm exec jest < /tmp/example.txt > /tmp/example.log',
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        'xargs pnpm exec rm -rf / < /tmp/example.txt > /tmp/example.log',
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});
