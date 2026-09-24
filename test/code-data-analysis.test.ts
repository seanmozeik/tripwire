import * as bunTest from 'bun:test';

import { analyzeCode } from '../src/lib/code/analyze';

bunTest.describe('bounded abstract data analysis', () => {
  bunTest.test('preserves read and write effects for the rollout edit', () => {
    const report = analyzeCode(
      'python',
      'from pathlib import Path\np=Path("README.md")\np.write_text(p.read_text().replace("old", "new"))',
      [],
      '/tripwire-policy-fixture',
    );
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(
        report.operations.map((operation) =>
          'path' in operation ? { kind: operation.kind, path: operation.path } : operation,
        ),
      )
      .toEqual([
        { kind: 'read', path: 'README.md' },
        { kind: 'write', path: 'README.md' },
      ]);
  });
  bunTest.test('enumerates every literal loop target', () => {
    const report = analyzeCode(
      'python',
      'from pathlib import Path\nfor target in ["dist/first", "/protected"]:\n Path(target).unlink()',
      [],
      '/tripwire-policy-fixture',
    );
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(
        report.operations.map((operation) => ('path' in operation ? operation.path : operation)),
      )
      .toEqual(['dist/first', '/protected']);
  });
  bunTest.test('records effects in both conditional branches', () => {
    const report = analyzeCode(
      'python',
      'import json,os\nif json.loads("{}").get("flag"):\n os.unlink("dist/first")\nelse:\n os.unlink("/protected")',
      [],
      '/tripwire-policy-fixture',
    );
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(
        report.operations.map((operation) => ('path' in operation ? operation.path : operation)),
      )
      .toEqual(['dist/first', '/protected']);
  });
  bunTest.test('does not resolve JSON bytes as a filesystem target', () => {
    const report = analyzeCode(
      'javascript',
      'const fs=require("fs"); const d=JSON.parse("{}"); fs.rmSync(d.path);',
      [],
      '/tripwire-policy-fixture',
    );
    bunTest.expect(report.gap).toContain('unresolved path');
  });
  bunTest.test('shared data does not cause exponential inspection', () => {
    const source = ['x=[1]', ...Array.from({ length: 45 }, () => 'x=[x,x]'), 'print(x)'].join('\n');
    const report = analyzeCode('python', source, [], '/tripwire-policy-fixture');
    bunTest.expect(report.gap).toBeNull();
  });
  bunTest.test('nested literal iterations stop at the evaluation budget', () => {
    const values = `[${Array.from({ length: 100 }, () => '1').join(',')}]`;
    const report = analyzeCode(
      'python',
      `for a in ${values}:\n for b in ${values}:\n  print(a+b)`,
      [],
      '/tripwire-policy-fixture',
    );
    bunTest.expect(report.gap).toContain('budget');
  });
});
