import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';

bunTest.describe('script execution policy', () => {
  const command = 'bun .claude/skills/juno/scripts/prod-read.ts --help';

  bunTest.test.each(['', ' # tripwire-allow', ' # tripwire-allow:'])(
    'allows a script without a review marker: %s',
    (suffix) => {
      bunTest
        .expect(decideBash(command + suffix, {}, { cwd: '/tripwire-policy-fixture' }).kind)
        .toBe('allow');
    },
  );

  bunTest.test('accepts a reviewed script with a reason', () => {
    bunTest
      .expect(
        decideBash(
          `${command} # tripwire-allow: user approved the read-only reader`,
          {},
          { cwd: '/tripwire-policy-fixture' },
        ).kind,
      )
      .toBe('allow');
  });

  bunTest.test('script arguments do not require approval', () => {
    bunTest
      .expect(
        decideBash(`${command} "# tripwire-allow: data"`, {}, { cwd: '/tripwire-policy-fixture' })
          .kind,
      )
      .toBe('allow');
  });

  bunTest.test('module execution does not need a review marker', () => {
    const moduleCommand = 'python3 -m example_module';
    bunTest
      .expect(decideBash(moduleCommand, {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe('allow');
    bunTest
      .expect(
        decideBash(`${moduleCommand} # tripwire-allow:`, {}, { cwd: '/tripwire-policy-fixture' })
          .kind,
      )
      .toBe('allow');
    bunTest
      .expect(
        decideBash(
          `${moduleCommand} "# tripwire-allow: quoted data"`,
          {},
          { cwd: '/tripwire-policy-fixture' },
        ).kind,
      )
      .toBe('allow');
    bunTest
      .expect(
        decideBash(
          `${moduleCommand} # tripwire-allow: reviewed module`,
          {},
          { cwd: '/tripwire-policy-fixture' },
        ).kind,
      )
      .toBe('allow');
  });

  bunTest.test.each([
    `${command}; python3 -c 'import os; os.unlink("/protected")'`,
    `${command}; rm -rf /`,
  ])('keeps other rejected operations blocked: %s', (source) => {
    bunTest.expect(decideBash(source, {}, { cwd: '/tripwire-policy-fixture' }).kind).toBe('deny');
    bunTest
      .expect(
        decideBash(
          `${source} # tripwire-allow: reviewed script only`,
          {},
          { cwd: '/tripwire-policy-fixture' },
        ).kind,
      )
      .toBe('deny');
  });
});
