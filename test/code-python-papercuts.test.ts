import * as bunTest from 'bun:test';

import { analyzeCode } from '../src/lib/code/analyze';

bunTest.describe('Python data operation regressions', () => {
  bunTest.test.each([
    's="abc"; print(s[0:2].replace("a", "b"))',
    's="abc"; print(s[1].upper())',
    'import sys; s=sys.stdin.read(); print(s[:].replace("a", "b"))',
    'print(("a" if True else "b").replace("a", "c"))',
    'print([s for s in ["a", "b"] if s in ["a"]])',
    'from collections import Counter; print(Counter(["a", "a"]).most_common(1))',
    'import collections; c=collections.Counter(); print(c.most_common()); print(c["a"])',
    'from collections import Counter; import json; print(Counter(json.loads("[]")).most_common())',
  ])('accepts inert data: %s', (source) => {
    bunTest.expect(analyzeCode('python', source).gap).toBeNull();
  });

  bunTest.test('records effects in both expression branches', () => {
    const report = analyzeCode(
      'python',
      'import os; os.unlink("dist/a") if True else os.unlink("/protected")',
    );
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(report.operations.map((operation) => operation.kind))
      .toEqual(['delete', 'delete']);
    bunTest
      .expect(report.operations)
      .toEqual([
        bunTest.expect.objectContaining({ path: 'dist/a' }),
        bunTest.expect.objectContaining({ path: '/protected' }),
      ]);
  });

  bunTest.test.each([
    'from collections import Counter; import os; Counter(os.unlink)',
    'from collections import Counter; import os; Counter([]).most_common(os.unlink)',
    'import collections; collections.defaultdict(print)',
    'import os; os.unlink("a" if True else "/protected")',
    'import os; print("a" if True else os.system("id"))',
    'import os; print("a" if os.system("id") else "b")',
    'import os; print("abc"[:os.system("id")])',
    'import os; os.unlink("/protected"[0:3])',
  ])('does not authorize effects through data: %s', (source) => {
    bunTest.expect(analyzeCode('python', source).gap).not.toBeNull();
  });
});
