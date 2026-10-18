import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash } from '../../src/dispatch';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

const root = realpathSync(mkdtempSync(path.join(tmpdir(), 'example-data-modules-')));
const project = path.join(root, 'work/project');
const modules = path.join(project, 'node_modules');
interface ExampleManifest {
  readonly name: string;
  readonly version?: string;
  readonly exports?: Readonly<Record<string, unknown>>;
}

const writePackage = (directory: string, manifest: ExampleManifest): void => {
  mkdirSync(directory, { recursive: true });
  writeFileSync(path.join(directory, 'package.json'), JSON.stringify(manifest));
};
writePackage(project, { name: 'example-project' });
mkdirSync(path.join(project, 'app'));
writePackage(path.join(modules, 'example-pkg'), { name: 'example-pkg', version: '1.2.3' });
writeFileSync(path.join(modules, 'example-pkg/index.js'), 'module.exports = 1;');
writeFileSync(path.join(modules, 'example-pkg/data.json.js'), 'module.exports = 1;');
writePackage(path.join(modules, '@example/scoped'), { name: '@example/scoped' });
writePackage(path.join(modules, 'exported-pkg'), {
  name: 'exported-pkg',
  exports: { '.': './index.js', './package.json': './package.json' },
});
writePackage(path.join(modules, 'mapped-pkg'), {
  name: 'mapped-pkg',
  exports: { './package.json': './payload.js' },
});
writePackage(path.join(modules, 'conditional-pkg'), {
  name: 'conditional-pkg',
  exports: { './package.json': { node: './payload.js', default: './package.json' } },
});
mkdirSync(path.join(modules, 'linked-pkg'));
writeFileSync(path.join(root, 'payload.js'), 'module.exports = 1;');
symlinkSync(path.join(root, 'payload.js'), path.join(modules, 'linked-pkg/package.json'));
writePackage(path.join(root, 'home/.ssh/example-keys'), { name: 'example-keys' });
symlinkSync(path.join(root, 'home/.ssh/example-keys'), path.join(modules, 'example-keys'));
const selfProject = path.join(root, 'work/self');
writePackage(selfProject, { name: 'self-pkg', exports: { './package.json': './payload.js' } });

bunTest.afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

const decide = (
  command: string,
  cwd = project,
): { readonly kind: string; readonly rule: string } => {
  const { kind, rule } = decideBash(command, {}, { cwd });
  return { kind, rule };
};
const allowed = { kind: 'allow', rule: 'none' };
const embeddedDeny = { kind: 'deny', rule: 'embedded-code' };

bunTest.describe('Node require of package JSON', () => {
  bunTest.test('loads a package JSON file found through node_modules as data', () => {
    for (const [source, cwd] of [
      ["require('example-pkg/package.json').version", project],
      ["require('example-pkg/package.json').version", path.join(project, 'app')],
      ["require('@example/scoped/package.json').name", project],
      ["require('exported-pkg/package.json').name", project],
      [`require('${modules}/example-pkg/package.json').version`, root],
    ] as const) {
      bunTest.expect(decide(`node -p ${quote(source)}`, cwd)).toEqual(allowed);
    }
    bunTest
      .expect(
        decide(`cd ${project} && node -p "require('example-pkg/package.json').version"`, root),
      )
      .toEqual(allowed);
  });

  bunTest.test('still denies code modules and unverified JSON targets', () => {
    for (const source of [
      "require('example-pkg')",
      "require('example-pkg/index.js')",
      "require('example-pkg/data.json')",
      "require('missing-pkg/package.json')",
      "require('mapped-pkg/package.json')",
      "require('conditional-pkg/package.json')",
      "require('linked-pkg/package.json')",
      "require('example-pkg/../mapped-pkg/package.json')",
      "require('node:example/package.json')",
    ]) {
      bunTest.expect(decide(`node -p ${quote(source)}`)).toEqual(embeddedDeny);
    }
    bunTest
      .expect(decide(`node -p ${quote("require('self-pkg/package.json')")}`, selfProject))
      .toEqual(embeddedDeny);
    bunTest
      .expect(decide(`bun -e ${quote("require('example-pkg/package.json')")}`))
      .toEqual(embeddedDeny);
  });

  bunTest.test('keeps decoded package data away from paths and calls', () => {
    for (const source of [
      "require('fs').readFileSync(require('example-pkg/package.json').main)",
      "require('example-pkg/package.json').version()",
      "process.chdir(require('example-pkg/package.json').name)",
    ]) {
      bunTest.expect(decide(`node -e ${quote(source)}`)).toEqual(embeddedDeny);
    }
  });

  bunTest.test('applies read protection to the resolved package file', () => {
    bunTest
      .expect(decide(`node -p ${quote("require('example-keys/package.json').name")}`))
      .toEqual({ kind: 'deny', rule: 'read-ssh' });
  });
});

const python = (source: string): string => `python3 - <<'EOF'\n${source}\nEOF`;

bunTest.describe('Python csv', () => {
  bunTest.test('parses and writes rows as inert data', () => {
    for (const source of [
      'import csv, sys\nfor row in csv.reader(sys.stdin):\n    print(row[0])',
      "import csv\nwith open('/scratch/run-1/data.csv', newline='') as f:\n    for row in csv.DictReader(f, delimiter=';'):\n        print(row['name'])",
      "import csv\nrows = list(csv.reader(['a,b', 'c,d']))\nprint(len(rows))",
      "import csv, sys\nwriter = csv.writer(sys.stdout, quoting=csv.QUOTE_ALL)\nwriter.writerow(['a', 'b'])",
      "import csv\nwith open('/scratch/run-1/out.csv', 'w', newline='') as f:\n    out = csv.DictWriter(f, fieldnames=['name'])\n    out.writeheader()\n    out.writerows([{'name': 'example'}])",
      'from csv import reader\nimport sys\nprint(sum(1 for _ in reader(sys.stdin)))',
    ]) {
      bunTest.expect(decide(python(source))).toEqual(allowed);
    }
  });

  bunTest.test('keeps decoded rows away from paths, calls, and unknown streams', () => {
    for (const source of [
      "import csv, sys\nfor row in csv.reader(sys.stdin):\n    open(row[0], 'w')",
      'import csv, os, sys\nfor row in csv.reader(sys.stdin):\n    os.remove(row[0])',
      'import csv\nclass Loud(csv.Dialect):\n    delimiter = ","\nprint(Loud)',
      "import csv\nclass Sink:\n    def write(self, text):\n        return text\ncsv.writer(Sink()).writerow(['a'])",
      'import csv\ncsv.field_size_limit(10)',
    ]) {
      bunTest.expect(decide(python(source))).toEqual(embeddedDeny);
    }
    bunTest
      .expect(decide(python("import csv\nprint(list(csv.reader(open('/scratch/run-1/.env'))))")))
      .toEqual({ kind: 'deny', rule: 'read-env' });
  });
});
