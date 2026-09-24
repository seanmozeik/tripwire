import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';
import { inlineScopeFixtures } from '../fixtures/inline-scope';

bunTest.test.each(inlineScopeFixtures)('$name', (fixture) => {
  const result = decideBash(fixture.command, {}, { cwd: '/tripwire-policy-fixture' });
  bunTest
    .expect(result.kind, `${fixture.command}: ${result.message}`)
    .toBe(fixture.allowed ? 'allow' : 'deny');
});

bunTest.test('normal runners retain the independent sudo rule', () => {
  bunTest
    .expect(
      decideBash('sudo --chdir /unverified node --test', {}, { cwd: '/tripwire-policy-fixture' })
        .kind,
    )
    .toBe('ask');
});
