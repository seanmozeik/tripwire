import * as bunTest from 'bun:test';
import path from 'node:path';

import { decideBash } from '../../src/dispatch';
import { analyzeCode } from '../../src/lib/code/analyze';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

bunTest.test.each(['rm -rf build', 'uv run --no-sync rm -rf build', 'bunx --bun rm -rf build'])(
  'unknown cwd reaches forwarded deletion: %s',
  (command) => {
    bunTest
      .expect(decideBash(`cd $X && ${command}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe('deny');
    bunTest.expect(decideBash(command, {}, { cwd: null }).kind).toBe('deny');
    bunTest.expect(decideBash(command, {}, { cwd: '/tripwire-policy-fixture' }).kind).toBe('allow');
  },
);

bunTest.test(
  'each operation captures its cwd at creation, including nested callback effects',
  () => {
    const source =
      'import os,subprocess\nopen("a.txt").read()\nos.chdir("/tmp")\nsubprocess.run(["printf","example"],cwd="..")\nopen("b.txt","w").write(os.getcwd())';
    const report = analyzeCode('python', source, [], '/');
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(report.operations.map((operation) => operation.cwd))
      .toEqual(['/', '/', '/', '/tmp', '/tmp']);
    const nested = analyzeCode(
      'javascript',
      'process.chdir("/tmp"); [1].map(x=>require("fs").readFileSync("a.txt"));',
      [],
      '/',
    );
    bunTest.expect(nested.gap).toBeNull();
    bunTest.expect(nested.operations[0]?.cwd).toBe('/tmp');
    bunTest
      .expect(
        nested.operations.every(
          (operation) => operation.cwd !== null && path.isAbsolute(operation.cwd),
        ),
      )
      .toBe(true);
  },
);

bunTest.test(
  'unknown cwd permits directory-independent file operations and recovery by absolute chdir',
  () => {
    bunTest
      .expect(analyzeCode('python', 'open("/tmp/example","w").write("example")', [], null).gap)
      .toBeNull();
    bunTest
      .expect(analyzeCode('python', 'open("example","w")', [], null).gap)
      .toContain('working directory');
    bunTest
      .expect(
        analyzeCode('python', 'import os; os.chdir("/tmp"); open("example","w")', [], null)
          .operations[0]?.cwd,
      )
      .toBe('/tmp');
    bunTest
      .expect(
        analyzeCode('python', 'import subprocess; subprocess.run(["printf","example"])', [], null)
          .gap,
      )
      .toContain('working directory');
  },
);

bunTest.test.each([
  'if True:\n os.chdir("/")',
  'True and os.chdir("/")',
  'os.chdir("/") if True else None',
])('cwd joins forget disagreement: %s', (branch) => {
  const report = analyzeCode(
    'python',
    `import os\nos.chdir("/tmp")\n${branch}\nopen("example","w")`,
    [],
    '/',
  );
  bunTest.expect(report.gap).toContain('working directory');
});

bunTest.test('subprocess cwd reaches deletion policy', () => {
  const source = 'import subprocess; subprocess.run(["rm","example.txt"],cwd="/tmp",check=True)';
  bunTest
    .expect(decideBash(`python3 -c ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(source.replace('/tmp', '/'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});
bunTest.test.each([
  ['python3 -c', 'import os; os.chdir("/tmp"); os.remove("example.txt")'],
  ['node -e', 'process.chdir("/tmp"); require("fs").unlinkSync("example.txt")'],
])('inline cwd changes preserve deletion policy for %s', (runner, source) => {
  bunTest
    .expect(decideBash(`${runner} ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        `${runner} ${quote(source.replace('/tmp', '/'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
  bunTest
    .expect(
      decideBash(
        `${runner} ${quote(source.replace('/tmp', '/missing-example-cwd'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});
bunTest.test('branching cwd cannot authorize a later relative delete', () => {
  const source =
    'import os,json\nos.chdir("/tmp")\nif json.loads("true"): os.chdir("/")\nos.remove("example.txt")';
  bunTest
    .expect(decideBash(`python3 -c ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('deny');
});

bunTest.test('absolute operations preserve null cwd and keep their policy decisions', () => {
  const source =
    'import shutil,os\nopen("/tmp/fictional-input").read()\nopen("/tmp/fictional-output","w").write("x")\nshutil.copyfile("/tmp/fictional-input","/tmp/fictional-copy")\nos.remove("/tmp/fictional-old")';
  const report = analyzeCode('python', source, [], null);
  bunTest.expect(report.gap).toBeNull();
  bunTest
    .expect([...new Set(report.operations.map((operation) => operation.kind))])
    .toEqual(['read', 'write', 'transfer', 'delete']);
  bunTest.expect(report.operations.every((operation) => operation.cwd === null)).toBe(true);
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`, {}, { cwd: null }).kind).toBe('allow');
  bunTest
    .expect(decideBash(`python3 -c ${quote('import os; os.remove("/")')}`, {}, { cwd: null }).kind)
    .toBe('deny');
  bunTest
    .expect(
      decideBash(`python3 -c ${quote('open("/fictional/.ssh/id_rsa","w")')}`, {}, { cwd: null })
        .kind,
    )
    .toBe('deny');
});

bunTest.test(
  'path resolution sees earlier absolute mutations with null cwd after directory recovery',
  () => {
    const source =
      'import os\nfrom pathlib import Path\nos.remove("/tmp/fictional-target")\nos.chdir("/tmp")\nPath("fictional-target").resolve()';
    const report = analyzeCode('python', source, [], null);
    bunTest.expect(report.operations[0]?.cwd).toBeNull();
    bunTest.expect(report.gap).toContain('Earlier filesystem effects');
    const unrelated = analyzeCode(
      'python',
      source.replace('Path("fictional-target")', 'Path("fictional-other")'),
      [],
      null,
    );
    bunTest.expect(unrelated.gap).toBeNull();
  },
);
