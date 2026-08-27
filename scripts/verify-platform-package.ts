import { accessSync, constants } from 'node:fs';
import path from 'node:path';

import packageManifest from '../package.json' with { type: 'json' };
import platformManifest from '../packages/darwin-arm64/package.json' with { type: 'json' };

if (platformManifest.version !== packageManifest.version) {
  throw new Error('Tripwire package versions do not match');
}

const executable = path.join(import.meta.dir, '..', 'packages', 'darwin-arm64', 'bin', 'tripwire');
accessSync(executable, constants.X_OK);

const version = Bun.spawnSync([executable, '--version'], { stderr: 'inherit', stdout: 'pipe' });
if (version.exitCode !== 0 || version.stdout.toString().trim() !== platformManifest.version) {
  throw new Error('Tripwire platform executable version does not match its package');
}

process.stdout.write(`${platformManifest.version}\n`);
