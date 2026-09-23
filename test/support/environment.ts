import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, realpathSync } from 'node:fs';
import * as os from 'node:os';
import { tmpdir } from 'node:os';
import path from 'node:path';

// A private tree per test process prevents glob, policy and config reads from
// depending on the launch directory or the developer's home and temporary files.
const repository = path.resolve(import.meta.dir, '../..');
const temporary = realpathSync(mkdtempSync(path.join(tmpdir(), 'tripwire-test-')));
const fixture = path.join(temporary, 'fixture');
mkdirSync(fixture);
for (const name of ['home', 'work', 'bin']) {
  mkdirSync(path.join(fixture, name));
}
for (const name of Object.keys(process.env)) {
  if (
    name.startsWith('MISE_') ||
    name.startsWith('__MISE') ||
    name.startsWith('XDG_') ||
    name.startsWith('TRIPWIRE_') ||
    ['NODE_OPTIONS', 'BUN_OPTIONS', 'BUN_PRELOAD'].includes(name)
  ) {
    Reflect.deleteProperty(process.env, name);
  }
}
symlinkSync(process.execPath, path.join(fixture, 'bin/bun'));
process.env['PATH'] = [path.join(fixture, 'bin'), '/usr/bin', '/bin'].join(path.delimiter);
process.env['MISE_CEILING_PATHS'] = `${fixture}${path.delimiter}${temporary}`;
process.env['MISE_SYSTEM_CONFIG_DIR'] = path.join(fixture, 'system-mise');
process.env['HOME'] = path.join(fixture, 'home');
process.env['TMPDIR'] = temporary;
await bunTest.mock.module('node:os', () => ({
  ...os,
  homedir: () => process.env['HOME'] ?? path.join(fixture, 'home'),
  tmpdir: () => process.env['TMPDIR'] ?? temporary,
}));
process.chdir(path.join(fixture, 'work'));
// Policy defaults must not acquire temporary-path privileges from the checkout.
bunTest.spyOn(process, 'cwd').mockReturnValue('/tripwire-policy-fixture');
bunTest.afterAll(() => {
  process.chdir(repository);
  rmSync(temporary, { recursive: true, force: true });
  rmSync(fixture, { recursive: true, force: true });
});
