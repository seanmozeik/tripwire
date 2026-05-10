import { chmodSync, mkdirSync, rmSync } from 'node:fs';

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });

const hook = Bun.spawnSync(
  [
    'bun',
    'build',
    './src/dispatch.ts',
    '--target',
    'bun',
    '--minify',
    '--bytecode',
    '--outdir',
    'dist',
    '--entry-naming',
    'tripwire.js',
  ],
  { stdout: 'inherit', stderr: 'inherit' },
);
if (hook.exitCode !== 0) {
  process.exit(hook.exitCode || 1);
}

const cli = Bun.spawnSync(
  [
    'bun',
    'build',
    './src/cli.ts',
    '--target',
    'bun',
    '--minify',
    '--bytecode',
    '--external',
    'effect',
    '--external',
    '@effect/platform-bun',
    '--outdir',
    'dist',
    '--entry-naming',
    'tripwire-cli.js',
  ],
  { stdout: 'inherit', stderr: 'inherit' },
);
if (cli.exitCode !== 0) {
  process.exit(cli.exitCode || 1);
}

chmodSync('dist/tripwire.js', 0o755);
chmodSync('dist/tripwire-cli.js', 0o755);
