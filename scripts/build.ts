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
import { pathToFileURL } from 'node:url';

import type {
  PiExtensionContext,
  PiToolCallEvent,
  PiToolResultEvent,
  TripwirePiExtensionApi,
} from '../src/pi-extension';

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

  // SAFETY: The boundary check above proves that the staged module default is callable. The smoke
  // Test below verifies the extension contract by requiring and invoking both registered handlers.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the runtime check proves the staged default is callable before the lifecycle smoke verifies its contract.
  const extension = loaded.default as SmokeExtension;
  let toolCall: SmokeToolCallHandler | undefined;
  let toolResult: SmokeToolResultHandler | undefined;
  const api: TripwirePiExtensionApi = {
    on: (event: 'tool_call' | 'tool_result', handler: SmokeHandler) => {
      if (event === 'tool_call') {
        // SAFETY: The staged adapter's typed lifecycle contract pairs tool_call with this handler.
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the adapter contract pairs tool_call with this handler type.
        toolCall = handler as SmokeToolCallHandler;
      } else {
        // SAFETY: The staged adapter's typed lifecycle contract pairs tool_result with this handler.
        // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the adapter contract pairs tool_result with this handler type.
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

  await smokeStagedExtension(stagedExtension);

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
