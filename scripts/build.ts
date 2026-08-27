import { mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const run = (arguments_: readonly string[], label: string, cwd = process.cwd()): void => {
  const result = Bun.spawnSync([...arguments_], { cwd, stderr: 'inherit', stdout: 'inherit' });
  if (result.exitCode !== 0) {
    throw new Error(`${label} failed with exit code ${result.exitCode}`);
  }
};

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist', { recursive: true });

const projectDirectory = process.cwd();
const compileWorkspace = mkdtempSync(path.join(tmpdir(), 'tripwire-build-'));
try {
  run(
    [
      'bun',
      'build',
      path.join(projectDirectory, 'src/main.ts'),
      '--target',
      'bun',
      '--compile',
      '--bytecode',
      '--format',
      'esm',
      '--splitting',
      '--minify',
      '--outfile',
      path.join(projectDirectory, 'dist/tripwire'),
    ],
    'Tripwire executable build',
    compileWorkspace,
  );
} finally {
  rmSync(compileWorkspace, { recursive: true, force: true });
}

run(
  [
    'bun',
    'build',
    './src/pi-extension.ts',
    '--target',
    'node',
    '--minify',
    '--outfile',
    './dist/tripwire-pi.js',
  ],
  'Pi extension build',
);

run(['./dist/tripwire', '--version'], 'Tripwire executable smoke test');

symlinkSync('tripwire', './dist/tripwire-hook');
const hookAlias = './dist/tripwire-hook';

const hookSmoke = (() => {
  try {
    return Bun.spawnSync([hookAlias], {
      stderr: 'inherit',
      stdin: new TextEncoder().encode(
        JSON.stringify({
          cwd: '/tmp',
          hook_event_name: 'PreToolUse',
          session_id: 'build-smoke',
          tool_input: { command: 'printf safe' },
          tool_name: 'Bash',
        }),
      ),
      stdout: 'pipe',
    });
  } finally {
    unlinkSync(hookAlias);
  }
})();
if (hookSmoke.exitCode !== 0 || hookSmoke.stdout.toString().trim() !== '{"continue": true}') {
  throw new Error('Tripwire hook smoke test failed');
}

const cliSmoke = Bun.spawnSync(['./dist/tripwire', 'test', 'printf safe'], {
  stderr: 'inherit',
  stdout: 'pipe',
});
if (cliSmoke.exitCode !== 0 || !cliSmoke.stdout.toString().includes('"continue": true')) {
  throw new Error('Tripwire CLI smoke test failed');
}
