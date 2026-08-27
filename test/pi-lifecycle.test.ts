import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { chmod, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  createTripwirePiExtension,
  type PiExtensionContext,
  type PiToolCallEvent,
  type PiToolResultEvent,
  type TripwirePiExtensionApi,
} from '../src/pi-extension';

type ToolCallHandler = (
  event: PiToolCallEvent,
  context: PiExtensionContext,
) => Promise<{ readonly block?: boolean; readonly reason?: string } | undefined>;

type ToolResultHandler = (event: PiToolResultEvent, context: PiExtensionContext) => Promise<void>;

type Extension = (pi: TripwirePiExtensionApi) => void;

interface LifecycleState {
  readonly context: PiExtensionContext;
  readonly notifications: string[];
  readonly aborted: boolean;
}

const fixtureHook = `#!/usr/bin/env bun
const raw = await Bun.stdin.text();
const parsed = JSON.parse(raw);
const events = Array.isArray(parsed) ? parsed : [parsed];
if (events.some((event) => event?.tool_name === 'dispatcher-failure')) {
  console.error('fixture dispatcher failure');
  process.exit(2);
}
const phase = events[0]?.hook_event_name;
const protectedPath = events.find((event) => event?.tool_input?.file_path === '.env');
if (phase === 'PreToolUse' && protectedPath !== undefined) {
  console.log(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: '[tripwire:path-protect] protected path .env',
    },
  }));
} else if (
  phase === 'PostToolUse' &&
  events.some((event) => String(event?.tool_response?.stdout ?? '').includes('POST_SCANNER_DENY'))
) {
  console.log(JSON.stringify({
    continue: true,
    decision: 'block',
    reason: '[tripwire:secret-scanner-failed] scanner unavailable',
  }));
} else {
  console.log(JSON.stringify({ continue: true }));
}
`;

let root = '';
let hookPath = '';
let compiledExtension: Extension | undefined;

beforeAll(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'tripwire-pi-lifecycle-'));
  hookPath = path.join(root, 'tripwire');
  const stagedExtension = path.join(root, 'tripwire-pi.js');
  await writeFile(hookPath, fixtureHook);
  await chmod(hookPath, 0o755);

  const build = Bun.spawnSync(
    [
      process.execPath,
      'build',
      path.join(process.cwd(), 'src/pi-extension.ts'),
      '--target',
      'node',
      '--minify',
      '--outfile',
      stagedExtension,
    ],
    { stderr: 'pipe', stdout: 'pipe' },
  );
  if (build.exitCode !== 0) {
    throw new Error(`Pi lifecycle fixture build failed: ${build.stderr.toString()}`);
  }
  const loaded: unknown = await import(`${pathToFileURL(stagedExtension).href}?test=${Date.now()}`);
  if (
    typeof loaded !== 'object' ||
    loaded === null ||
    !('default' in loaded) ||
    typeof loaded.default !== 'function'
  ) {
    throw new Error('Compiled Pi lifecycle fixture has no default extension');
  }
  compiledExtension = loaded.default as Extension;
});

afterAll(async () => {
  await rm(root, { force: true, recursive: true });
});

const registerHandlers = (
  extension: Extension,
): { readonly toolCall: ToolCallHandler; readonly toolResult: ToolResultHandler } => {
  let toolCall: ToolCallHandler | undefined;
  let toolResult: ToolResultHandler | undefined;
  const api = {
    on: (event: 'tool_call' | 'tool_result', handler: ToolCallHandler | ToolResultHandler) => {
      if (event === 'tool_call') {
        toolCall = handler as ToolCallHandler;
      } else {
        toolResult = handler as ToolResultHandler;
      }
    },
  } as TripwirePiExtensionApi;
  extension(api);
  if (toolCall === undefined || toolResult === undefined) {
    throw new Error('Pi lifecycle fixture did not register both handlers');
  }
  return { toolCall, toolResult };
};

const lifecycleState = (): LifecycleState => {
  const state = { aborted: false };
  const notifications: string[] = [];
  const context: PiExtensionContext = {
    abort: () => {
      state.aborted = true;
    },
    cwd: root,
    ui: {
      notify: (message) => {
        notifications.push(message);
      },
    },
  };
  return {
    get aborted() {
      return state.aborted;
    },
    context,
    notifications,
  };
};

const toolCallEvent = (toolName: string, input: Record<string, unknown>): PiToolCallEvent => ({
  input,
  toolCallId: `${toolName}-call`,
  toolName,
});

const toolResultEvent = (toolName: string, text: string): PiToolResultEvent => ({
  ...toolCallEvent(toolName, { command: 'printf output' }),
  content: [{ text, type: 'text' }],
  details: {},
  isError: false,
});

const compiledLifecycleExtension = (): Extension => {
  if (compiledExtension === undefined) {
    throw new Error('Compiled Pi extension is not loaded');
  }
  return compiledExtension;
};

const lifecycleTests = (name: string, extension: () => Extension): void => {
  describe(`${name} Pi adapter lifecycle`, () => {
    test('allows a safe pre-tool call', async () => {
      const { toolCall } = registerHandlers(extension());
      const state = lifecycleState();

      const result = await toolCall(
        toolCallEvent('bash', { command: 'printf safe' }),
        state.context,
      );

      expect(result).toEqual({});
      expect(state.aborted).toBe(false);
      expect(state.notifications).toEqual([]);
    });

    test('blocks a denied pre-tool call', async () => {
      const { toolCall } = registerHandlers(extension());
      const state = lifecycleState();

      const result = await toolCall(toolCallEvent('read', { path: '.env' }), state.context);

      expect(result?.block).toBe(true);
      expect(result?.reason).toContain('path-protect');
      expect(state.aborted).toBe(false);
    });

    test('allows a safe post-tool result', async () => {
      const { toolResult } = registerHandlers(extension());
      const state = lifecycleState();

      await toolResult(toolResultEvent('bash', 'safe output'), state.context);

      expect(state.aborted).toBe(false);
      expect(state.notifications).toEqual([]);
    });

    test('aborts on a post-tool scanner denial', async () => {
      const { toolResult } = registerHandlers(extension());
      const state = lifecycleState();

      await toolResult(toolResultEvent('bash', 'POST_SCANNER_DENY'), state.context);

      expect(state.aborted).toBe(true);
      expect(state.notifications).toHaveLength(1);
      expect(state.notifications[0]).toContain('secret-scanner-failed');
    });

    test('fails closed when the dispatcher fails', async () => {
      const handlers = registerHandlers(extension());
      const preState = lifecycleState();
      const preResult = await handlers.toolCall(
        toolCallEvent('dispatcher-failure', {}),
        preState.context,
      );
      expect(preResult?.block).toBe(true);
      expect(preResult?.reason).toContain('fixture dispatcher failure');

      const postState = lifecycleState();
      await handlers.toolResult(
        toolResultEvent('dispatcher-failure', 'unused output'),
        postState.context,
      );
      expect(postState.aborted).toBe(true);
      expect(postState.notifications[0]).toContain('fixture dispatcher failure');
    });
  });
};

lifecycleTests('source', () => createTripwirePiExtension(hookPath));
lifecycleTests('compiled', compiledLifecycleExtension);
