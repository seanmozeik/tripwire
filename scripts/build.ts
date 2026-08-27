import {
  chmodSync,
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  renameSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import packageManifest from '../package.json' with { type: 'json' };
import type {
  PiExtensionContext,
  PiToolCallEvent,
  PiToolResultEvent,
  TripwirePiExtensionApi,
} from '../src/pi-extension';

const packageVersion = packageManifest.version;

const run = (arguments_: readonly string[], label: string, cwd = process.cwd()): void => {
  const result = Bun.spawnSync([...arguments_], { cwd, stderr: 'inherit', stdout: 'inherit' });
  if (result.exitCode !== 0) {
    throw new Error(`${label} failed with exit code ${result.exitCode}`);
  }
};

const publishArtifact = (source: string, target: string, executable = false): void => {
  const pending = `${target}.${process.pid}.next`;
  rmSync(pending, { force: true });
  try {
    copyFileSync(source, pending);
    if (executable) {
      chmodSync(pending, 0o755);
    }
    renameSync(pending, target);
  } finally {
    rmSync(pending, { force: true });
  }
};

const publishDirectory = (source: string, target: string): void => {
  const pending = `${target}.${process.pid}.next`;
  rmSync(pending, { force: true, recursive: true });
  try {
    cpSync(source, pending, { recursive: true });
    rmSync(target, { force: true, recursive: true });
    renameSync(pending, target);
  } finally {
    rmSync(pending, { force: true, recursive: true });
  }
};

interface SyncResult {
  readonly exitCode: number;
  readonly stdout: { readonly toString: () => string };
}

const runWithInput = (
  command: readonly string[],
  input: unknown,
  env: Record<string, string | undefined> = process.env,
): SyncResult =>
  Bun.spawnSync([...command], {
    env,
    stderr: 'pipe',
    stdin: new TextEncoder().encode(JSON.stringify(input)),
    stdout: 'pipe',
  });

const safeHookInput = {
  cwd: '/tmp',
  hook_event_name: 'PreToolUse',
  session_id: 'build-smoke',
  tool_input: { command: 'printf safe' },
  tool_name: 'Bash',
};

const assertAllowed = (result: SyncResult, label: string): void => {
  if (result.exitCode !== 0 || result.stdout.toString().trim() !== '{"continue": true}') {
    throw new Error(`${label} failed`);
  }
};

type SmokeToolCallHandler = (
  event: PiToolCallEvent,
  context: PiExtensionContext,
) => Promise<{ readonly block?: boolean; readonly reason?: string } | undefined>;

type SmokeToolResultHandler = (
  event: PiToolResultEvent,
  context: PiExtensionContext,
) => Promise<void>;

type SmokeHandler = SmokeToolCallHandler | SmokeToolResultHandler;
type SmokeExtension = (api: TripwirePiExtensionApi) => void;

const smokeStagedExtension = async (extensionPath: string): Promise<void> => {
  const loaded: unknown = await import(
    `${pathToFileURL(extensionPath).href}?build=${Date.now().toString()}`
  );
  if (
    typeof loaded !== 'object' ||
    loaded === null ||
    !('default' in loaded) ||
    typeof loaded.default !== 'function'
  ) {
    throw new Error('Compiled Pi extension has no default export');
  }

  // SAFETY: The boundary check proves the staged default is callable. The lifecycle smoke below
  // verifies both registered handler contracts.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the runtime check proves the staged default is callable.
  const extension = loaded.default as SmokeExtension;
  let toolCall: SmokeToolCallHandler | undefined;
  let toolResult: SmokeToolResultHandler | undefined;
  const api: TripwirePiExtensionApi = {
    on: (event: 'tool_call' | 'tool_result', handler: SmokeHandler) => {
      if (event === 'tool_call') {
        // SAFETY: The adapter contract pairs tool_call with this handler type.
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the event discriminator proves the handler type.
        toolCall = handler as SmokeToolCallHandler;
      } else {
        // SAFETY: The adapter contract pairs tool_result with this handler type.
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the event discriminator proves the handler type.
        toolResult = handler as SmokeToolResultHandler;
      }
    },
  };
  extension(api);
  if (toolCall === undefined || toolResult === undefined) {
    throw new Error('Compiled Pi extension did not register both lifecycle handlers');
  }

  const notifications: string[] = [];
  const state = { aborted: false, notifications };
  const context: PiExtensionContext = {
    abort: () => {
      state.aborted = true;
    },
    cwd: '/tmp',
    ui: {
      notify: (message) => {
        state.notifications.push(message);
      },
    },
  };
  const preResult = await toolCall(
    { input: { command: 'printf safe' }, toolCallId: 'build-pre', toolName: 'bash' },
    context,
  );
  await toolResult(
    {
      content: [],
      details: {},
      input: { command: 'printf safe' },
      isError: false,
      toolCallId: 'build-post',
      toolName: 'bash',
    },
    context,
  );
  if (preResult?.block === true || state.aborted || state.notifications.length > 0) {
    throw new Error('Compiled Pi extension lifecycle smoke test failed');
  }
};

const projectDirectory = process.cwd();
const compileWorkspace = mkdtempSync(path.join(tmpdir(), 'tripwire-build-'));
const stagedDist = path.join(compileWorkspace, 'dist');
const stagedNative = path.join(compileWorkspace, 'native', 'tripwire');
const stagedPortable = path.join(stagedDist, 'tripwire.js');
const stagedLibrary = path.join(stagedDist, 'index.js');
const stagedExtension = path.join(stagedDist, 'tripwire-pi.js');
const stagedTypes = path.join(stagedDist, 'types');
const platformExecutable = path.join(
  projectDirectory,
  'packages',
  'darwin-arm64',
  'bin',
  'tripwire',
);

try {
  mkdirSync(stagedDist, { recursive: true });
  mkdirSync(path.dirname(stagedNative), { recursive: true });
  mkdirSync(path.dirname(platformExecutable), { recursive: true });
  symlinkSync(
    path.join(projectDirectory, 'node_modules'),
    path.join(compileWorkspace, 'node_modules'),
  );

  run(
    [
      'bun',
      'build',
      path.join(projectDirectory, 'src/main.ts'),
      '--compile',
      '--bytecode',
      '--format',
      'esm',
      '--minify',
      '--target',
      'bun-darwin-arm64',
      '--outfile',
      stagedNative,
    ],
    'Tripwire native executable build',
    compileWorkspace,
  );
  run(
    [
      'bun',
      'build',
      path.join(projectDirectory, 'src/main.ts'),
      '--target',
      'bun',
      '--format',
      'esm',
      '--minify',
      '--outfile',
      stagedPortable,
    ],
    'Tripwire portable runtime build',
    compileWorkspace,
  );
  run(
    [
      'bun',
      'build',
      path.join(projectDirectory, 'src/index.ts'),
      '--target',
      'bun',
      '--format',
      'esm',
      '--minify',
      '--packages',
      'external',
      '--outfile',
      stagedLibrary,
    ],
    'Tripwire library build',
    compileWorkspace,
  );
  run(
    [
      'bun',
      'build',
      path.join(projectDirectory, 'src/bin/cli.ts'),
      path.join(projectDirectory, 'src/bin/hook.ts'),
      '--target',
      'bun',
      '--format',
      'esm',
      '--minify',
      '--outdir',
      stagedDist,
      '--entry-naming',
      'tripwire-[name].js',
    ],
    'Tripwire launcher build',
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
    'Tripwire Pi extension build',
    compileWorkspace,
  );
  run(
    [
      path.join(projectDirectory, 'node_modules', '.bin', 'tsc'),
      '-p',
      path.join(projectDirectory, 'tsconfig.build.json'),
      '--outDir',
      stagedTypes,
    ],
    'Tripwire declaration build',
    projectDirectory,
  );

  run([stagedNative, '--version'], 'Tripwire native version smoke test');
  assertAllowed(
    runWithInput([stagedNative, '--tripwire-hook'], safeHookInput),
    'Tripwire native hook smoke test',
  );
  const portableVersion = Bun.spawnSync(
    [process.execPath, stagedPortable, '--tripwire-force-cli', '--version'],
    { stderr: 'pipe', stdout: 'pipe' },
  );
  if (
    portableVersion.exitCode !== 0 ||
    portableVersion.stdout.toString().trim() !== packageVersion
  ) {
    throw new Error('Tripwire portable version smoke test failed');
  }
  assertAllowed(
    runWithInput([process.execPath, stagedPortable, '--tripwire-hook'], safeHookInput),
    'Tripwire portable hook smoke test',
  );

  const library: unknown = await import(
    `${pathToFileURL(stagedLibrary).href}?build=${Date.now().toString()}`
  );
  if (
    typeof library !== 'object' ||
    library === null ||
    !('decide' in library) ||
    typeof library.decide !== 'function' ||
    !('loadConfig' in library) ||
    typeof library.loadConfig !== 'function'
  ) {
    throw new Error('Tripwire library export smoke test failed');
  }

  publishArtifact(stagedNative, platformExecutable, true);
  const stagedCliLauncher = path.join(stagedDist, 'tripwire-cli.js');
  const stagedHookLauncher = path.join(stagedDist, 'tripwire-hook.js');
  const nativeLauncherVersion = Bun.spawnSync([stagedCliLauncher, '--version'], {
    stderr: 'pipe',
    stdout: 'pipe',
  });
  if (
    nativeLauncherVersion.exitCode !== 0 ||
    nativeLauncherVersion.stdout.toString().trim() !== packageVersion
  ) {
    throw new Error('Tripwire native launcher smoke test failed');
  }
  const portableEnvironment = { ...process.env, TRIPWIRE_FORCE_PORTABLE: '1' };
  const portableLauncherVersion = Bun.spawnSync([stagedCliLauncher, '--version'], {
    env: portableEnvironment,
    stderr: 'pipe',
    stdout: 'pipe',
  });
  if (
    portableLauncherVersion.exitCode !== 0 ||
    portableLauncherVersion.stdout.toString().trim() !== packageVersion
  ) {
    throw new Error('Tripwire portable launcher smoke test failed');
  }
  assertAllowed(
    runWithInput([stagedHookLauncher], safeHookInput, portableEnvironment),
    'Tripwire portable hook launcher smoke test',
  );
  await smokeStagedExtension(stagedExtension);

  const installSmokeHome = path.join(compileWorkspace, 'home');
  mkdirSync(installSmokeHome, { recursive: true });
  const installSmoke = Bun.spawnSync([stagedCliLauncher, 'install', 'oh-my-pi'], {
    env: { ...process.env, HOME: installSmokeHome },
    stderr: 'inherit',
    stdout: 'pipe',
  });
  if (installSmoke.exitCode !== 0) {
    throw new Error('Tripwire compiled Pi installer smoke test failed');
  }

  mkdirSync(path.join(projectDirectory, 'dist'), { recursive: true });
  publishArtifact(stagedPortable, path.join(projectDirectory, 'dist', 'tripwire.js'), true);
  publishArtifact(stagedLibrary, path.join(projectDirectory, 'dist', 'index.js'));
  publishArtifact(stagedCliLauncher, path.join(projectDirectory, 'dist', 'tripwire-cli.js'), true);
  publishArtifact(
    stagedHookLauncher,
    path.join(projectDirectory, 'dist', 'tripwire-hook.js'),
    true,
  );
  publishArtifact(stagedExtension, path.join(projectDirectory, 'dist', 'tripwire-pi.js'));
  publishDirectory(stagedTypes, path.join(projectDirectory, 'dist', 'types'));
  rmSync(path.join(projectDirectory, 'dist', 'tripwire'), { force: true });
  process.stdout.write(`${packageVersion}\n`);
} finally {
  rmSync(compileWorkspace, { recursive: true, force: true });
}
