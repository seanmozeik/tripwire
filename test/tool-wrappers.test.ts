import * as bunTest from 'bun:test';
import { tmpdir } from 'node:os';

import { decideBash } from '../src/dispatch';

const wrappers = [
  'corepack',
  'busybox',
  'toybox',
  'uvx',
  'mise exec --',
  'mise exec node@22 --',
  'mise x --',
  'direnv exec .',
  'dotenv --',
  'op run --',
  'doppler run --',
  'infisical run --',
  'aws-vault exec example --',
  'nix develop -c',
  'devbox run --',
  'pixi run',
  'pdm run',
  'hatch run',
  'conda run -n example',
  'fnm exec --',
  'asdf exec',
  'rbenv exec',
  'pyenv exec',
  'volta run',
  'caffeinate -i',
];
bunTest.test.each(wrappers)('unwraps %s for policy', (wrapper) => {
  bunTest
    .expect(decideBash(`${wrapper} rm -rf /`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('deny');
  bunTest
    .expect(decideBash(`${wrapper} git reset --hard`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('deny');
  bunTest
    .expect(decideBash(`${wrapper} printf example`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        `${wrapper} python3 -c 'import os; os.remove("/")'`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});
bunTest.test('shell text wrapper and unknown flags', () => {
  bunTest
    .expect(decideBash('nix-shell --run "rm -rf /"', {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('deny');
  bunTest
    .expect(
      decideBash('nix-shell --run "printf example"', {}, { cwd: '/tripwire-policy-fixture' }).kind,
    )
    .toBe('allow');
  bunTest
    .expect(
      decideBash('mise exec --unknown -- printf example', {}, { cwd: '/tripwire-policy-fixture' })
        .kind,
    )
    .toBe('deny');
  bunTest
    .expect(decideBash('mise exec -- python3 -c "print(1)"', {}, { cwd: tmpdir() }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash('caffeinate -i python3 -c "print(1)"', {}, { cwd: '/tripwire-policy-fixture' })
        .kind,
    )
    .toBe('allow');
});

bunTest.test.each(['nix develop --command', 'caffeinate -dimsu', 'mise -j 4 exec --'])(
  'wrapper metadata recognizes delimiters and flag bundles: %s',
  (wrapper) => {
    bunTest
      .expect(decideBash(`${wrapper} printf example`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe('allow');
    bunTest
      .expect(decideBash(`${wrapper} rm -rf /`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe('deny');
  },
);

bunTest.test.each(['direnv exec /', 'mise --cd=/ exec --', 'conda run --cwd /'])(
  'wrapper metadata selects cwd: %s',
  (wrapper) => {
    bunTest.expect(decideBash(`${wrapper} rm example.txt`, {}, { cwd: '/tmp' }).kind).toBe('deny');
    bunTest
      .expect(
        decideBash(
          `${wrapper.replace(' /', ' /tmp').replace('=/', '=/tmp')} rm example.txt`,
          {},
          { cwd: '/' },
        ).kind,
      )
      .toBe('allow');
  },
);
