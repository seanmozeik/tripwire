import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';

bunTest.describe('script execution policy', () => {
  const command = 'bun .claude/skills/juno/scripts/prod-read.ts --help';

  bunTest.test.each(['', ' # tripwire-allow', ' # tripwire-allow:'])(
    'allows a script without a review marker: %s',
    (suffix) => {
      bunTest.expect(decideBash(command + suffix).kind).toBe('allow');
    },
  );

  bunTest.test('accepts a reviewed script with a reason', () => {
    bunTest
      .expect(decideBash(`${command} # tripwire-allow: user approved the read-only reader`).kind)
      .toBe('allow');
  });

  bunTest.test('script arguments do not require approval', () => {
    bunTest.expect(decideBash(`${command} "# tripwire-allow: data"`).kind).toBe('allow');
  });

  bunTest.test('other interpreter restrictions still need a reason-bearing marker', () => {
    const moduleCommand = 'python3 -m example_module';
    bunTest.expect(decideBash(moduleCommand).kind).toBe('deny');
    bunTest.expect(decideBash(`${moduleCommand} # tripwire-allow:`).kind).toBe('deny');
    bunTest
      .expect(decideBash(`${moduleCommand} "# tripwire-allow: quoted data"`).kind)
      .toBe('deny');
    bunTest
      .expect(decideBash(`${moduleCommand} # tripwire-allow: reviewed module`).kind)
      .toBe('allow');
  });

  bunTest.test.each([
    `${command}; python3 -c 'import os; os.unlink("/protected")'`,
    `${command}; rm -rf /`,
  ])('keeps other rejected operations blocked: %s', (source) => {
    bunTest.expect(decideBash(source).kind).toBe('deny');
    bunTest
      .expect(decideBash(`${source} # tripwire-allow: reviewed script only`).kind)
      .toBe('deny');
  });
});
