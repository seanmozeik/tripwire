import * as bunTest from 'bun:test';

import { Effect } from 'effect';

import { decide, decideBash, runRules, runRulesSync } from '../src/dispatch';
import { analyzeCode } from '../src/lib/code/analyze';
import { codeFixtures } from './fixtures/embedded-code';

bunTest.describe('embedded executable code policy (never executes fixtures)', () => {
  bunTest.test.each([...codeFixtures])('$name', (fixture) => {
    const decision = decideBash(fixture.command, {}, { cwd: '/tripwire-policy-fixture' });
    bunTest
      .expect(decision.kind === 'allow' || decision.kind === 'warn', decision.message)
      .toBe(fixture.allowed);
  });
  bunTest.test.each(['python', 'python_repl', 'js_repl', 'javascript', 'typescript', 'exec'])(
    'direct %s cannot hide a call in code',
    (tool) => {
      bunTest
        .expect(
          decide({
            cwd: '/tripwire-policy-fixture',
            hook_event_name: 'PreToolUse',
            tool_name: tool,
            tool_input: { code: 'unknown_delete("/protected")' },
          }).kind,
        )
        .toBe('deny');
    },
  );
  bunTest.test('exec_command cmd uses the shell policy', () => {
    bunTest
      .expect(
        decide({
          cwd: '/tripwire-policy-fixture',
          hook_event_name: 'PreToolUse',
          tool_name: 'exec_command',
          tool_input: { cmd: 'python3 -c \'import os; os.unlink("/protected")\'' },
        }).kind,
      )
      .toBe('deny');
  });
  bunTest.test('extracts a resolved deletion rather than only blocking the interpreter', () => {
    const report = analyzeCode(
      'python',
      'from os import remove as discard; target = "/protected"; discard(target)',
      [],
      '/tripwire-policy-fixture',
    );
    bunTest.expect(report.gap).toBeNull();
    bunTest.expect(report.operations.map(({ kind }) => kind)).toEqual(['delete']);
  });
  bunTest.test('fails closed on excessive input', () => {
    bunTest
      .expect(analyzeCode('python', '#'.repeat(70_000), [], '/tripwire-policy-fixture').gap)
      .not.toBeNull();
  });
  bunTest.test('security rule defects fail closed in both dispatch paths', async () => {
    const rules = [
      {
        name: 'embedded-code',
        fn: (): never => {
          throw new Error('injected defect');
        },
      },
    ];
    bunTest.expect(runRulesSync(rules).kind).toBe('deny');
    const decision = await Effect.runPromise(runRules(rules, 250));
    bunTest.expect(decision.kind).toBe('deny');
  });
});
