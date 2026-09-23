import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

bunTest.test.each([
  'python3 -c \'import sys; open(sys.argv[1],"w").write("example")\' report.txt',
  'node -e \'require("fs").writeFileSync(process.argv[1],"example")\' -- report.txt',
  'bun -e \'await Bun.write(process.argv[1],"example")\' report.txt',
])('binds interpreter argv: %s', (command) => {
  bunTest.expect(decideBash(command).kind).toBe('allow');
  bunTest.expect(decideBash(command.replace('report.txt', '.env')).kind).toBe('deny');
});

bunTest.test('stdin argument binding preserves policy targets', () => {
  bunTest
    .expect(
      decideBash(
        'python3 - report.txt <<\'PY\'\nimport sys\nopen(sys.argv[1],"w").write("example")\nPY',
      ).kind,
    )
    .toBe('allow');
  bunTest
    .expect(
      decideBash('python3 - .env <<\'PY\'\nimport sys\nopen(sys.argv[1],"w").write("example")\nPY')
        .kind,
    )
    .toBe('deny');
});
bunTest.test.each([
  [
    'python3 -c',
    'import os,subprocess\nenv=os.environ\nenv["PYTHONPATH"]="/srv/example"\nsubprocess.run(["python3","-c","print(1)"])',
  ],
  [
    'node -e',
    'const env=process.env; env.NODE_OPTIONS="--require /srv/example/payload.js"; require("child_process").execFileSync("node",["-e","console.log(1)"])',
  ],
])('environment aliases cannot change interpreter startup in %s', (runner, source) => {
  bunTest.expect(decideBash(`${runner} ${quote(source)}`).kind).toBe('deny');
});

bunTest.test.each(['$VALUES', '"$@"', `"\${values[@]}"`])(
  'variable-width argv %s cannot shift a checked operand',
  (expansion) => {
    const source = 'import sys,os; os.remove(sys.argv[2])';
    bunTest
      .expect(decideBash(`python3 -c ${quote(source)} ${expansion} /tmp/example`).kind)
      .toBe('deny');
  },
);
bunTest.test('quoted scalar argv can be printed without authorizing a path', () => {
  bunTest
    .expect(decideBash('python3 -c \'import sys; print(sys.argv[1])\' "$VALUE"').kind)
    .toBe('allow');
  bunTest
    .expect(decideBash('python3 -c \'import sys,os; os.remove(sys.argv[1])\' "$VALUE"').kind)
    .toBe('deny');
});

bunTest.test('unknown JavaScript argv cannot supply interpreter startup flags', () => {
  bunTest.expect(decideBash('node -e \'console.log(1)\' "$OPTION" ./payload.js').kind).toBe('deny');
  bunTest
    .expect(decideBash("bun -e 'console.log(1)' example --preload ./payload.js").kind)
    .toBe('deny');
  bunTest
    .expect(decideBash('node -e \'console.log(process.argv[1])\' -- "$VALUE"').kind)
    .toBe('allow');
});
