import * as bunTest from 'bun:test';
import path from 'node:path';

import { parser as pythonParser } from '@lezer/python';

import { decideBash } from '../../src/dispatch';
import { analyzeCode } from '../../src/lib/code/analyze';

bunTest.test.each([
  ['python', 'print(1)\nif :\n print(2)', 'python3 -c'],
  ['javascript', 'console.log(1);\nconst = ;', 'node -e'],
  ['typescript', 'console.log(1);\nconst = ;', 'bun -e'],
] as const)('%s reports first syntax error with bounded excerpt', (language, source, runner) => {
  const { gap } = analyzeCode(language, source);
  bunTest.expect(gap).toContain(`${language} syntax error at line 2, column`);
  bunTest.expect(gap).not.toContain('Internal');
  bunTest.expect(gap?.length).toBeLessThan(220);
  bunTest
    .expect(decideBash(`${runner} '${language === 'python' ? 'print(1)' : 'console.log(1)'}'`).kind)
    .toBe('allow');
  bunTest.expect(decideBash(`${runner} '${source}'`).kind).toBe('deny');
});

bunTest.test.each([
  ['python3', 'print(1)', 'print(2)'],
  ['node', 'console.log(1);', 'console.log(2);'],
])('literal backslash-n in single quotes explains heredoc: %s', (runner, first, second) => {
  const flag = runner === 'python3' ? '-c' : '-e';
  const result = decideBash(`${runner} ${flag} '${first}\\n${second}'`);
  bunTest.expect(result.kind).toBe('deny');
  bunTest.expect(result.message).toContain('two characters, not a newline; use a heredoc');
  bunTest.expect(decideBash(`${runner} - <<'CODE'\n${first}\n${second}\nCODE`).kind).toBe('allow');
});

bunTest.test('syntax diagnostics never include the whole source', () => {
  const source = `const = ;\n${' '.repeat(100)}"fictional-secret-outside-excerpt";`;
  const { gap } = analyzeCode('javascript', source);
  bunTest.expect(gap).not.toContain('fictional-secret-outside-excerpt');
  bunTest.expect(gap).toContain('line 1');
});

bunTest.test(
  'unexpected exceptions report an internal inspector error without exception text',
  () => {
    const spy = bunTest.spyOn(pythonParser, 'startParse').mockImplementation(() => {
      throw new Error('fictional-private-exception-text');
    });
    try {
      const report = analyzeCode('python', 'print(1)');
      bunTest.expect(report.gap).toContain('Internal code inspector error');
      bunTest.expect(report.gap).not.toContain('fictional-private-exception-text');
    } finally {
      spy.mockRestore();
    }
    bunTest.expect(analyzeCode('python', 'print(1)').gap).toBeNull();
  },
);

bunTest.test('unexpected analyzer construction errors also fail closed', () => {
  const spy = bunTest.spyOn(path, 'resolve').mockImplementation(() => {
    throw new Error('fictional-private-directory-error');
  });
  try {
    const report = analyzeCode('python', 'print(1)', [], '/fictional');
    bunTest.expect(report.gap).toContain('Internal code inspector error');
    bunTest.expect(report.gap).not.toContain('fictional-private-directory-error');
  } finally {
    spy.mockRestore();
  }
});
