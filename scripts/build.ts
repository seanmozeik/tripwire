import {
  chmodSync,
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const run = (arguments_: readonly string[], label: string, cwd = process.cwd()): void => {
  const result = Bun.spawnSync([...arguments_], { cwd, stderr: 'inherit', stdout: 'inherit' });
  if (result.exitCode !== 0) {
    throw new Error(`${label} failed with exit code ${result.exitCode}`);
  }
};

const publishArtifact = (source: string, target: string, executable = false): void => {
  const pending = `${target}.${process.pid}.next`;
  copyFileSync(source, pending);
  if (executable) {
    chmodSync(pending, 0o755);
  }
  renameSync(pending, target);
};

mkdirSync('dist', { recursive: true });

const projectDirectory = process.cwd();
const compileWorkspace = mkdtempSync(path.join(tmpdir(), 'tripwire-build-'));
const stagedExecutable = path.join(compileWorkspace, 'tripwire');
const stagedExtension = path.join(compileWorkspace, 'tripwire-pi.js');
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
      stagedExecutable,
    ],
    'Tripwire executable build',
    compileWorkspace,
  );
  run(
    [
      'bun',
      'build',
      path.join(projectDirectory, 'src/pi-extension.ts'),
      '--target',
      'node',
      '--minify',
      '--outfile',
      stagedExtension,
    ],
    'Pi extension build',
    compileWorkspace,
  );

  run([stagedExecutable, '--version'], 'Tripwire executable smoke test');

  const hookAlias = path.join(compileWorkspace, 'tripwire-hook');
  symlinkSync('tripwire', hookAlias);
  const hookSmoke = Bun.spawnSync([hookAlias], {
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
  if (hookSmoke.exitCode !== 0 || hookSmoke.stdout.toString().trim() !== '{"continue": true}') {
    throw new Error('Tripwire hook smoke test failed');
  }

  const cliSmoke = Bun.spawnSync([stagedExecutable, 'test', 'printf safe'], {
    stderr: 'inherit',
    stdout: 'pipe',
  });
  if (cliSmoke.exitCode !== 0 || !cliSmoke.stdout.toString().includes('"continue": true')) {
    throw new Error('Tripwire CLI smoke test failed');
  }

  const installSmokeHome = path.join(compileWorkspace, 'home');
  mkdirSync(installSmokeHome, { recursive: true });
  const installSmoke = Bun.spawnSync([stagedExecutable, 'install', 'oh-my-pi'], {
    env: { ...process.env, HOME: installSmokeHome },
    stderr: 'inherit',
    stdout: 'pipe',
  });
  if (installSmoke.exitCode !== 0) {
    throw new Error('Tripwire compiled Pi installer smoke test failed');
  }

  publishArtifact(stagedExecutable, path.join(projectDirectory, 'dist/tripwire'), true);
  publishArtifact(stagedExtension, path.join(projectDirectory, 'dist/tripwire-pi.js'));
} finally {
  rmSync(compileWorkspace, { recursive: true, force: true });
}
