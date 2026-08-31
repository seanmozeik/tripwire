import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
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
  const previous = `${target}.${process.pid}.previous`;
  rmSync(pending, { force: true, recursive: true });
  rmSync(previous, { force: true, recursive: true });
  let previousMoved = false;
  try {
    cpSync(source, pending, { recursive: true });
    if (existsSync(target)) {
      renameSync(target, previous);
      previousMoved = true;
    }
    renameSync(pending, target);
    rmSync(previous, { force: true, recursive: true });
  } catch (cause) {
    if (previousMoved && !existsSync(target)) {
      renameSync(previous, target);
    }
    throw cause;
  } finally {
    rmSync(pending, { force: true, recursive: true });
    rmSync(previous, { force: true, recursive: true });
  }
};

interface SyncResult {
  readonly exitCode: number;
  readonly stderr: { readonly toString: () => string };
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

const deniedHookInput = { ...safeHookInput, tool_input: { command: 'rm -rf /' } };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

const assertAllowed = (result: SyncResult, label: string): void => {
  if (result.exitCode !== 0 || result.stdout.toString().trim() !== '{"continue": true}') {
    throw new Error(`${label} failed`);
  }
};

const assertCliAllowed = (result: SyncResult, label: string): void => {
  let output: unknown;
  try {
    output = JSON.parse(result.stdout.toString());
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
  if (
    result.exitCode !== 0 ||
    typeof output !== 'object' ||
    output === null ||
    !('continue' in output) ||
    output.continue !== true
  ) {
    throw new Error(`${label} failed`);
  }
};

const assertDenied = (result: SyncResult, label: string): void => {
  let output: unknown;
  try {
    output = JSON.parse(result.stdout.toString());
  } catch {
    throw new Error(`${label} returned invalid JSON`);
  }
  const hookOutput = isRecord(output) ? output['hookSpecificOutput'] : undefined;
  if (
    result.exitCode !== 0 ||
    !isRecord(hookOutput) ||
    hookOutput['permissionDecision'] !== 'deny'
  ) {
    throw new Error(`${label} did not deny the destructive fixture`);
  }
};

const assertCheckedScriptAllowed = (result: SyncResult, label: string): void => {
  if (result.exitCode !== 0 || result.stdout.toString() !== 'safe:build-smoke\n') {
    throw new Error(`${label} failed`);
  }
};

const assertCheckedScriptDenied = (result: SyncResult, label: string): void => {
  if (result.exitCode === 0 || !result.stderr.toString().includes('[tripwire:rm-rf-root]')) {
    throw new Error(`${label} did not deny the destructive fixture`);
  }
};

interface SmokeToolCallEvent {
  readonly input: Record<string, unknown>;
  readonly toolCallId: string;
  readonly toolName: string;
}

type SmokeToolResultEvent = SmokeToolCallEvent & {
  readonly content: unknown;
  readonly details: unknown;
  readonly isError: boolean;
};

interface SmokeExtensionContext {
  readonly abort: () => void;
  readonly cwd: string;
  readonly ui: { readonly notify: (message: string, level: 'error') => void };
}

type SmokeToolCallHandler = (
  event: SmokeToolCallEvent,
  context: SmokeExtensionContext,
) => Promise<{ readonly block?: boolean; readonly reason?: string } | undefined>;

type SmokeToolResultHandler = (
  event: SmokeToolResultEvent,
  context: SmokeExtensionContext,
) => Promise<void>;

interface SmokeExtensionApi {
  readonly on: {
    (event: 'tool_call', handler: SmokeToolCallHandler): void;
    (event: 'tool_result', handler: SmokeToolResultHandler): void;
  };
}

type SmokeExtension = (api: SmokeExtensionApi) => void;

const isSmokeExtension = (value: unknown): value is SmokeExtension => typeof value === 'function';

const isToolCallHandler = (value: unknown): value is SmokeToolCallHandler =>
  typeof value === 'function';

const isToolResultHandler = (value: unknown): value is SmokeToolResultHandler =>
  typeof value === 'function';

class SmokeApi implements SmokeExtensionApi {
  toolCall: SmokeToolCallHandler | undefined;

  toolResult: SmokeToolResultHandler | undefined;

  on(event: 'tool_call', handler: SmokeToolCallHandler): void;

  on(event: 'tool_result', handler: SmokeToolResultHandler): void;

  on(event: 'tool_call' | 'tool_result', handler: unknown): void {
    if (event === 'tool_call' && isToolCallHandler(handler)) {
      this.toolCall = handler;
    } else if (event === 'tool_result' && isToolResultHandler(handler)) {
      this.toolResult = handler;
    }
  }
}

const smokeStagedExtension = async (extensionPath: string): Promise<void> => {
  const loaded: unknown = await import(
    `${pathToFileURL(extensionPath).href}?build=${Date.now().toString()}`
  );
  if (
    typeof loaded !== 'object' ||
    loaded === null ||
    !('default' in loaded) ||
    !isSmokeExtension(loaded.default)
  ) {
    throw new Error('Compiled Pi extension has no default export');
  }

  const api = new SmokeApi();
  loaded.default(api);
  const { toolCall, toolResult } = api;
  if (toolCall === undefined || toolResult === undefined) {
    throw new Error('Compiled Pi extension did not register both lifecycle handlers');
  }

  const notifications: string[] = [];
  const state = { aborted: false, notifications };
  const context: SmokeExtensionContext = {
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
  const deniedResult = await toolCall(
    { input: { command: 'rm -rf /' }, toolCallId: 'build-deny', toolName: 'bash' },
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
  if (
    preResult?.block === true ||
    deniedResult?.block !== true ||
    state.aborted ||
    state.notifications.length > 0
  ) {
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
const launcherSmokeRoot = path.join(compileWorkspace, 'launcher-smoke');
const launcherSmokeDist = path.join(launcherSmokeRoot, 'dist');
const launcherSmokePackage = path.join(
  launcherSmokeRoot,
  'node_modules',
  '@seanmozeik',
  'tripwire-darwin-arm64',
);
const platformExecutable = path.join(
  projectDirectory,
  'packages',
  'darwin-arm64',
  'bin',
  'tripwire',
);
const checkedSafeScript = path.join(projectDirectory, 'test', 'fixtures', 'checked-safe.sh');
const checkedDangerousScript = path.join(
  projectDirectory,
  'test',
  'fixtures',
  'checked-dangerous.sh',
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

  const stagedCliLauncher = path.join(stagedDist, 'tripwire-cli.js');
  const stagedHookLauncher = path.join(stagedDist, 'tripwire-hook.js');
  chmodSync(stagedPortable, 0o755);
  chmodSync(stagedCliLauncher, 0o755);
  chmodSync(stagedHookLauncher, 0o755);

  run([stagedNative, '--version'], 'Tripwire native version smoke test');
  assertAllowed(
    runWithInput([stagedNative, '--tripwire-hook'], safeHookInput),
    'Tripwire native hook smoke test',
  );
  assertDenied(
    runWithInput([stagedNative, '--tripwire-hook'], deniedHookInput),
    'Tripwire native hook deny smoke test',
  );
  assertCliAllowed(
    Bun.spawnSync([stagedNative, 'test', 'if true; then printf safe; fi'], {
      stderr: 'pipe',
      stdout: 'pipe',
    }),
    'Tripwire native CLI test smoke test',
  );
  assertDenied(
    Bun.spawnSync([stagedNative, 'test', 'rm -rf /'], { stderr: 'pipe', stdout: 'pipe' }),
    'Tripwire native CLI deny smoke test',
  );
  assertCheckedScriptAllowed(
    Bun.spawnSync([stagedNative, 'run-script', checkedSafeScript, '--', 'build-smoke'], {
      stderr: 'pipe',
      stdout: 'pipe',
    }),
    'Tripwire native checked-script smoke test',
  );
  assertCheckedScriptDenied(
    Bun.spawnSync([stagedNative, 'run-script', checkedDangerousScript, '--', '/tmp/blocked'], {
      stderr: 'pipe',
      stdout: 'pipe',
    }),
    'Tripwire native checked-script deny smoke test',
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
  assertDenied(
    runWithInput([process.execPath, stagedPortable, '--tripwire-hook'], deniedHookInput),
    'Tripwire portable hook deny smoke test',
  );
  assertCliAllowed(
    Bun.spawnSync(
      [
        process.execPath,
        stagedPortable,
        '--tripwire-force-cli',
        'test',
        'if true; then printf safe; fi',
      ],
      { stderr: 'pipe', stdout: 'pipe' },
    ),
    'Tripwire portable CLI test smoke test',
  );
  assertDenied(
    Bun.spawnSync([process.execPath, stagedPortable, '--tripwire-force-cli', 'test', 'rm -rf /'], {
      stderr: 'pipe',
      stdout: 'pipe',
    }),
    'Tripwire portable CLI deny smoke test',
  );
  assertCheckedScriptAllowed(
    Bun.spawnSync(
      [
        process.execPath,
        stagedPortable,
        '--tripwire-force-cli',
        'run-script',
        checkedSafeScript,
        '--',
        'build-smoke',
      ],
      { stderr: 'pipe', stdout: 'pipe' },
    ),
    'Tripwire portable checked-script smoke test',
  );
  assertCheckedScriptDenied(
    Bun.spawnSync(
      [
        process.execPath,
        stagedPortable,
        '--tripwire-force-cli',
        'run-script',
        checkedDangerousScript,
        '--',
        '/tmp/blocked',
      ],
      { stderr: 'pipe', stdout: 'pipe' },
    ),
    'Tripwire portable checked-script deny smoke test',
  );

  const library: unknown = await import(
    `${pathToFileURL(stagedLibrary).href}?build=${Date.now().toString()}`
  );
  if (
    typeof library !== 'object' ||
    library === null ||
    !('decide' in library) ||
    typeof library.decide !== 'function' ||
    !('decideBash' in library) ||
    typeof library.decideBash !== 'function' ||
    !('loadConfig' in library) ||
    typeof library.loadConfig !== 'function'
  ) {
    throw new Error('Tripwire library export smoke test failed');
  }

  mkdirSync(launcherSmokeDist, { recursive: true });
  copyFileSync(stagedPortable, path.join(launcherSmokeDist, 'tripwire.js'));
  copyFileSync(stagedCliLauncher, path.join(launcherSmokeDist, 'tripwire-cli.js'));
  copyFileSync(stagedHookLauncher, path.join(launcherSmokeDist, 'tripwire-hook.js'));
  mkdirSync(path.join(launcherSmokePackage, 'bin'), { recursive: true });
  copyFileSync(
    path.join(projectDirectory, 'packages', 'darwin-arm64', 'package.json'),
    path.join(launcherSmokePackage, 'package.json'),
  );
  const smokeNative = path.join(launcherSmokePackage, 'bin', 'tripwire');
  copyFileSync(stagedNative, smokeNative);
  chmodSync(smokeNative, 0o755);
  const smokeCliLauncher = path.join(launcherSmokeDist, 'tripwire-cli.js');
  const smokeHookLauncher = path.join(launcherSmokeDist, 'tripwire-hook.js');
  chmodSync(smokeCliLauncher, 0o755);
  chmodSync(smokeHookLauncher, 0o755);

  const nativeLauncherVersion = Bun.spawnSync([smokeCliLauncher, '--version'], {
    stderr: 'pipe',
    stdout: 'pipe',
  });
  if (
    nativeLauncherVersion.exitCode !== 0 ||
    nativeLauncherVersion.stdout.toString().trim() !== packageVersion
  ) {
    throw new Error('Tripwire native launcher smoke test failed');
  }
  assertAllowed(
    runWithInput([smokeHookLauncher], safeHookInput),
    'Tripwire native hook launcher smoke test',
  );
  assertDenied(
    runWithInput([smokeHookLauncher], deniedHookInput),
    'Tripwire native hook launcher deny smoke test',
  );
  const portableEnvironment = {
    ...process.env,
    TRIPWIRE_BUN: process.execPath,
    TRIPWIRE_FORCE_PORTABLE: '1',
  };
  const portableLauncherVersion = Bun.spawnSync([smokeCliLauncher, '--version'], {
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
    runWithInput([smokeHookLauncher], safeHookInput, portableEnvironment),
    'Tripwire portable hook launcher smoke test',
  );
  assertDenied(
    runWithInput([smokeHookLauncher], deniedHookInput, portableEnvironment),
    'Tripwire portable hook launcher deny smoke test',
  );
  await smokeStagedExtension(stagedExtension);

  const installSmokeHome = path.join(compileWorkspace, 'home');
  mkdirSync(installSmokeHome, { recursive: true });
  const installSmoke = Bun.spawnSync([stagedNative, 'install', 'oh-my-pi'], {
    env: { ...process.env, HOME: installSmokeHome, TRIPWIRE_PACKAGE_DIST: stagedDist },
    stderr: 'inherit',
    stdout: 'pipe',
  });
  if (installSmoke.exitCode !== 0) {
    throw new Error('Tripwire compiled Pi installer smoke test failed');
  }

  publishArtifact(stagedNative, platformExecutable, true);
  publishDirectory(stagedDist, path.join(projectDirectory, 'dist'));
  process.stdout.write(`${packageVersion}\n`);
} finally {
  rmSync(compileWorkspace, { recursive: true, force: true });
}
