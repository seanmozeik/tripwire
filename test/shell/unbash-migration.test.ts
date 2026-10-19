import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';
import { analyzeBash } from '../../src/lib/bash';

const cwd = '/tripwire-policy-fixture';

bunTest.test.each([
  'printf safe [$(git push origin main)]',
  'printf safe ["$(git push origin main)"]',
  'if true; then printf safe; elif git push origin main; then printf safe; fi',
  'if true; then printf safe; elif true; then git push origin main; fi',
  '[[ safe && $(printf safe) && $(git push origin main) ]]',
  '[[ ! ! $(git push origin main) ]]',
  'A=([$(git push origin main)]=safe)',
  'A[$(git push origin main)]=safe',
  'export A=([$(git push origin main)]=safe)',
  `printf safe "\${value/$(git push origin main)/safe}"`,
  `printf safe "\${value:$(git push origin main):1}"`,
  `printf safe "\${value#$(git push origin main)}"`,
  `printf safe "\${value:=$(git push origin main)}"`,
  '{ git push origin main; } >/tmp/tripwire-migration-output',
])('visits nested commands after the Unbash 6 migration: %s', (source) => {
  const program = analyzeBash(source, { cwd });
  bunTest.expect(program.diagnostics).toEqual([]);
  bunTest
    .expect(program.invocations.filter((invocation) => invocation.head === 'git'))
    .toHaveLength(1);
  bunTest
    .expect(decideBash(source, { git: { protectedBranches: ['main'] } }, { cwd }).kind)
    .toBe('deny');
});

bunTest.test.each(['time', '!', 'time !', '! time -p --'])(
  '%s keeps a single command in the current shell',
  (prefix) => {
    const program = analyzeBash(`${prefix} cd /tmp; printf safe`, { cwd });
    bunTest.expect(program.diagnostics).toEqual([]);
    bunTest
      .expect(program.invocations.find((invocation) => invocation.head === 'printf')?.cwd)
      .toBe('/tmp');
  },
);

bunTest.test('function redirects use the invocation arguments and directory', () => {
  const program = analyzeBash('f() { printf safe; } >"$1"; cd /tmp; f output.txt', { cwd });
  bunTest.expect(program.diagnostics).toEqual([]);
  bunTest
    .expect(program.redirects)
    .toMatchObject([{ cwd: '/tmp', target: { value: 'output.txt', kind: 'literal' } }]);
});

bunTest.test('all elif branch results participate in binding joins', () => {
  const source = 'if true; then P=/; elif true; then P=/; else P=/; fi; rm -rf "$P"';
  const program = analyzeBash(source, { cwd });
  bunTest.expect(program.diagnostics).toEqual([]);
  bunTest
    .expect(program.invocations.find((invocation) => invocation.head === 'rm')?.tokens)
    .toEqual(['rm', '-rf', '/']);
  bunTest.expect(decideBash(source, {}, { cwd }).kind).toBe('deny');
});

bunTest.test.each([
  ['nested script', 'printf safe "$(if true; then printf safe; elif ; then printf safe; fi)"'],
  ['unary nesting', `printf safe "$(( ${'!'.repeat(300)}$(git push origin main) ))"`],
  ['exponent nesting', `printf safe "$(( ${'1**'.repeat(300)}$(git push origin main) ))"`],
])('lazy parse errors and truncated arithmetic fail closed: %s', (_, source) => {
  const program = analyzeBash(source, { cwd });
  bunTest.expect(program.diagnostics.length).toBeGreaterThan(0);
  bunTest.expect(decideBash(source, {}, { cwd }).kind).toBe('deny');
});
