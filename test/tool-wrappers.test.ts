import * as bunTest from 'bun:test';

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
  bunTest.expect(decideBash(`${wrapper} rm -rf /`).kind).toBe('deny');
  bunTest.expect(decideBash(`${wrapper} git reset --hard`).kind).toBe('deny');
  bunTest.expect(decideBash(`${wrapper} printf example`).kind).toBe('allow');
  bunTest.expect(decideBash(`${wrapper} python3 -c 'import os; os.remove("/")'`).kind).toBe('deny');
});
bunTest.test('shell text wrapper and unknown flags', () => {
  bunTest.expect(decideBash('nix-shell --run "rm -rf /"').kind).toBe('deny');
  bunTest.expect(decideBash('nix-shell --run "printf example"').kind).toBe('allow');
  bunTest.expect(decideBash('mise exec --unknown -- printf example').kind).toBe('deny');
  bunTest.expect(decideBash('mise exec -- python3 -c "print(1)"').kind).toBe('deny');
  bunTest.expect(decideBash('caffeinate -i python3 -c "print(1)"').kind).toBe('allow');
});

bunTest.test.each(['nix develop --command', 'caffeinate -dimsu', 'mise -j 4 exec --'])(
  'wrapper metadata recognizes delimiters and flag bundles: %s',
  (wrapper) => {
    bunTest.expect(decideBash(`${wrapper} printf example`).kind).toBe('allow');
    bunTest.expect(decideBash(`${wrapper} rm -rf /`).kind).toBe('deny');
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
