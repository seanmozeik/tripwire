import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { assertIdiomaticFiles } from '../src/lib/mise/idiomatic';

let root = '';
bunTest.beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), 'mise-idiomatic-'));
});
bunTest.afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});
const inspect = (tool: string, filename: string, source: string): (() => void) => {
  const project = mkdtempSync(path.join(root, 'project-'));
  writeFileSync(path.join(project, filename), source);
  return () => {
    assertIdiomaticFiles(new Set([project]), new Set([tool]), path.join(root, 'plugins'));
  };
};
const pkg = (tool: string, data: unknown): (() => void) =>
  inspect(tool, 'package.json', JSON.stringify(data));

bunTest.test.each([
  '22',
  'v22',
  '22.11',
  '22.11.0-rc.1',
  '>=1.4',
  '^22',
  '~3.12',
  '22.x',
  '>=22 <24',
  '>= 22 < 24',
  '^22 || ~24',
  '22 - 24',
  'lts/*',
  'lts/iron',
  'latest',
  'system',
])('accepts version-only node selectors: %s', (version) => {
  bunTest.expect(inspect('node', '.nvmrc', version)).not.toThrow();
  bunTest.expect(pkg('node', { devEngines: { runtime: { name: 'node', version } } })).not.toThrow();
});

bunTest.test.each([
  'path:./payload',
  './payload',
  '/tmp/payload',
  '~/payload',
  'https://example.invalid/payload',
  'file:payload',
  'asdf:fictional',
  'ref:main',
  'prefix:22',
  '$(echo fictional)',
  '`echo fictional`',
  '{{exec(command="fictional")}}',
  '22; echo fictional',
  '22#payload',
  '22 ||',
  '>=',
  'not a version',
  'lts/../../payload',
])('rejects unsafe or unparsed selectors without echoing them: %s', (version) => {
  bunTest.expect(inspect('node', '.nvmrc', version)).toThrow('.nvmrc: version');
  bunTest
    .expect(pkg('node', { devEngines: { runtime: { name: 'node', version } } }))
    .toThrow('package.json: devEngines.runtime.version');
  bunTest
    .expect(pkg('pnpm', { packageManager: `pnpm@${version}` }))
    .toThrow('package.json: packageManager');
});

bunTest.test.each(['node', 'deno', 'bun'])('selects runtime declarations for %s', (tool) => {
  bunTest
    .expect(pkg(tool, { devEngines: { runtime: { name: tool, version: '^22' } } }))
    .not.toThrow();
  bunTest
    .expect(pkg(tool, { devEngines: { runtime: { name: tool, version: 'path:./payload' } } }))
    .toThrow('runtime.version');
});

bunTest.test.each(['bun', 'npm', 'pnpm', 'yarn'])('selects manager declarations for %s', (tool) => {
  bunTest.expect(pkg(tool, { packageManager: `${tool}@9.1.0+sha512.012345abcdef` })).not.toThrow();
  bunTest
    .expect(pkg(tool, { devEngines: { packageManager: { name: tool, version: '^9' } } }))
    .not.toThrow();
  bunTest
    .expect(
      pkg(tool, { devEngines: { packageManager: { name: tool, version: 'path:./payload' } } }),
    )
    .toThrow('packageManager.version');
});

bunTest.test('ignores fields mise does not read and declarations for other tools', () => {
  const data = {
    engines: { bun: '>=1.4', node: '^22 || >=24' },
    scripts: { postinstall: 'echo fictional', clean: 'rm -rf /' },
    dependencies: { fictional: 'file:./fictional' },
    unrelated: '{{exec(command="fictional")}}',
    packageManager: 'pnpm@https://example.invalid/payload',
    devEngines: { runtime: { name: 'deno', version: 'path:./payload' } },
  };
  bunTest.expect(pkg('node', data)).not.toThrow();
  bunTest.expect(pkg('bun', data)).not.toThrow();
  bunTest.expect(pkg('deno', data)).toThrow('runtime.version');
  bunTest.expect(pkg('pnpm', data)).toThrow('packageManager');
});

bunTest.test('matches first-entry and declaration precedence', () => {
  bunTest
    .expect(
      pkg('node', {
        devEngines: {
          runtime: [
            { name: 'deno', version: 'path:./ignored' },
            { name: 'node', version: 'path:./ignored' },
          ],
        },
      }),
    )
    .not.toThrow();
  bunTest
    .expect(
      pkg('pnpm', {
        devEngines: { packageManager: { name: 'pnpm', version: '9' } },
        packageManager: 'pnpm@path:./ignored',
      }),
    )
    .not.toThrow();
  bunTest
    .expect(
      pkg('bun', {
        devEngines: { runtime: { name: 'bun', version: '1.4' } },
        packageManager: 'bun@path:./ignored',
      }),
    )
    .not.toThrow();
  bunTest
    .expect(
      pkg('pnpm', { devEngines: { packageManager: [] }, packageManager: 'pnpm@path:./payload' }),
    )
    .toThrow('packageManager');
});

bunTest.test.each([
  'sha512.$(echo fictional)',
  'sha512../payload',
  'sha512.abc+extra',
  'unknown.abc',
  'sha512.',
  'sha512:abc',
])('rejects unverified checksum options: %s', (checksum) => {
  bunTest
    .expect(pkg('pnpm', { packageManager: `pnpm@9.1.0+${checksum}` }))
    .toThrow('packageManager');
  bunTest
    .expect(
      pkg('bun', {
        devEngines: { runtime: { name: 'bun', version: '1.4' } },
        packageManager: `bun@1.4+${checksum}`,
      }),
    )
    .toThrow('packageManager');
});

bunTest.test.each([
  { data: null },
  { data: [] },
  { data: { packageManager: 9 } },
  { data: { devEngines: [] } },
  { data: { devEngines: { runtime: 'node' } } },
  { data: { devEngines: { runtime: [{ name: 'node', version: '22' }, { version: 22 }] } } },
  { data: { devEngines: { runtime: { name: 'node', version: {} } } } },
])('rejects malformed package data %#', ({ data }) => {
  bunTest.expect(pkg('node', data)).toThrow('package.json');
});

bunTest.test('rejects JSON parse failures without leaking source', () => {
  bunTest
    .expect(inspect('node', 'package.json', '{"private-payload":'))
    .toThrow('package.json: invalid');
});

bunTest.test('normalizes BOMs, comments, empty lines and Python whitespace versions', () => {
  bunTest
    .expect(
      inspect('python', '.python-version', '\uFEFF# fictional\n3.13.1 3.12.8 # compatibility\n\n'),
    )
    .not.toThrow();
  bunTest.expect(inspect('node', '.nvmrc', '\uFEFFv22 # fictional\nlts/iron\n')).not.toThrow();
  bunTest.expect(inspect('python', '.python-versions', '# comment only\n')).not.toThrow();
  bunTest
    .expect(inspect('python', '.python-version', '3.13.1\npath:./payload # comment'))
    .toThrow('.python-version');
  bunTest
    .expect(inspect('python', '.python-version', '3.13.1#not-a-comment'))
    .toThrow('.python-version');
  bunTest
    .expect(
      inspect(
        'node',
        'package.json',
        '\uFEFF{"devEngines":{"runtime":{"name":"node","version":"v22"}}}',
      ),
    )
    .not.toThrow();
});

bunTest.test('preserves installed plugin checks before parsing versions', () => {
  mkdirSync(path.join(root, 'plugins/pnpm'), { recursive: true });
  bunTest.expect(pkg('pnpm', { packageManager: 'pnpm@9.1.0' })).toThrow('plugin');
});

bunTest.test('rejects long malformed ranges without ambiguous whitespace matching', () => {
  bunTest
    .expect(
      pkg('node', {
        devEngines: { runtime: { name: 'node', version: `22${' '.repeat(16_000)}!` } },
      }),
    )
    .toThrow('runtime.version');
});

bunTest.test(
  'Bun takes the first matching checksum, falling through declarations without one',
  () => {
    const data = {
      devEngines: {
        runtime: { name: 'bun', version: '1.4' },
        packageManager: { name: 'bun', version: '1.4+sha512.abcdef' },
      },
      packageManager: 'bun@1.4+sha512.$(echo fictional)',
    };
    bunTest.expect(pkg('bun', data)).not.toThrow();
    data.devEngines.packageManager.version = '1.4';
    bunTest.expect(pkg('bun', data)).toThrow('package.json: packageManager');
  },
);

bunTest.test('uses the registry first-line version capture for Bazel', () => {
  bunTest.expect(inspect('bazel', '.bazelversion', '\uFEFFv8.1.0\n# fictional')).not.toThrow();
  bunTest
    .expect(inspect('bazel', '.bazelversion', 'path:./payload\n8.1.0'))
    .toThrow('.bazelversion');
});
