import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';
import { compatibilityPairs } from './fixtures/code-compatibility';
import { compatibilityAttacks } from './fixtures/code-compatibility-attacks';

bunTest.describe('rollout compatibility and paired attacks (inert policy data)', () => {
  for (const pair of compatibilityPairs) {
    bunTest.test(`${pair.name}: allow`, () => {
      const decision = decideBash(pair.allow, {}, { cwd: '/tripwire-policy-fixture' });
      bunTest.expect(decision.kind, `${pair.source}: ${decision.message}`).toBe('allow');
    });
    bunTest.test(`${pair.name}: block`, () => {
      const decision = decideBash(pair.block, {}, { cwd: '/tripwire-policy-fixture' });
      bunTest.expect(decision.kind, `${pair.source}: ${decision.message}`).toBe('deny');
    });
  }
  bunTest.test.each([...compatibilityAttacks])('negative control: %s', (command) => {
    bunTest.expect(decideBash(command, {}, { cwd: '/tripwire-policy-fixture' }).kind).toBe('deny');
  });
});
