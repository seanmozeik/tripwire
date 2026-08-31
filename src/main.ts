#!/usr/bin/env bun

import path from 'node:path';

import pkg from '../package.json' with { type: 'json' };

const INTERNAL_HOOK_FLAG = '--tripwire-hook';
const FORCE_CLI_FLAG = '--tripwire-force-cli';

const forceCliIndex = process.argv.indexOf(FORCE_CLI_FLAG, 2);
const forceCli = forceCliIndex !== -1;
if (forceCli) {
  process.argv.splice(forceCliIndex, 1);
}
const cliArguments = process.argv.slice(2);
const executableName = path.basename(process.argv0);
const isHook =
  !forceCli &&
  (executableName === 'tripwire-hook' ||
    cliArguments.includes(INTERNAL_HOOK_FLAG) ||
    cliArguments.some((argument) => argument.startsWith('--cursor-event')));

if (isHook) {
  const { runHook } = await import('./dispatch');
  runHook();
} else if (cliArguments.length === 1 && cliArguments[0] === '--version') {
  process.stdout.write(`${pkg.version}\n`);
} else {
  const { runCli } = await import('./cli/index');
  await runCli();
}
