#!/usr/bin/env bun
// CLI commands for testing policy and installing agent integrations.
// Usage examples:
//   Bun src/main.ts test 'rm -rf /etc'
//   Bun src/main.ts test --tool=Read --path=.env
//   Bun src/main.ts test --post --tool=Bash --stdout='ghp_<token>'
//   Bun src/main.ts install claude
//   Bun src/main.ts install codex
//   Bun src/main.ts install cursor
//   Bun src/main.ts install pi
//   Bun src/main.ts install all

import { BunServices } from '@effect/platform-bun';
import { Effect, Option } from 'effect';
import { Argument, Command, Flag } from 'effect/unstable/cli';

import pkg from '../package.json' with { type: 'json' };
import {
  installAll,
  installClaude,
  installCodex,
  installCursor,
  installOhMyPi,
  installPi,
} from './lib/install';

const hookCommand = (): string[] => {
  const isBunCli = /\/bun(?<ext>\.exe)?$/.test(process.execPath);
  if (isBunCli) {
    return [process.execPath, new URL('main.ts', import.meta.url).pathname, '--tripwire-hook'];
  }
  return [process.execPath, '--tripwire-hook'];
};

interface BuiltEvent {
  hook_event_name: string;
  tool_name: string;
  cwd: string;
  session_id: string;
  tool_input?: unknown;
  tool_response?: unknown;
}

const buildToolInput = (
  tool: string,
  command: string | undefined,
  path: string | undefined,
  content: string | undefined,
) => {
  if (tool === 'Bash') {
    return { command: command ?? '' };
  }
  if (tool === 'Read') {
    return { file_path: path ?? '' };
  }
  if (tool === 'Write') {
    return { file_path: path ?? '', content: content ?? '' };
  }
  if (tool === 'Edit' || tool === 'MultiEdit') {
    return { file_path: path ?? '', old_string: '', new_string: content ?? '' };
  }
  return null;
};

interface EventParams {
  readonly tool: string;
  readonly post: boolean;
  readonly command: string | undefined;
  readonly path: string | undefined;
  readonly stdout: string | undefined;
  readonly stderr: string | undefined;
  readonly content: string | undefined;
}

const buildEvent = (params: EventParams): BuiltEvent => {
  const { tool, post, command, path, stdout, stderr, content } = params;
  const eventName = post ? 'PostToolUse' : 'PreToolUse';
  const toolInput = buildToolInput(tool, command, path, content);
  const event: BuiltEvent = {
    hook_event_name: eventName,
    tool_name: tool,
    cwd: process.cwd(),
    session_id: 'tripwire-cli-test',
    ...(toolInput !== null && { tool_input: toolInput }),
  };
  if (post) {
    event.tool_response =
      tool === 'Bash' ? { stdout: stdout ?? '', stderr: stderr ?? '' } : { content: content ?? '' };
  }
  return event;
};

const prettyJson = (output: string): string => {
  try {
    return JSON.stringify(JSON.parse(output) as unknown, null, 2);
  } catch {
    return output;
  }
};

const runTest = (config: {
  readonly command: string | undefined;
  readonly content: string | undefined;
  readonly path: string | undefined;
  readonly post: boolean;
  readonly stderr: string | undefined;
  readonly stdout: string | undefined;
  readonly tool: string;
}): Effect.Effect<void> =>
  Effect.sync(() => {
    const { command, content, path, post, stderr, stdout, tool } = config;
    const event = buildEvent({ tool, post, command, path, stdout, stderr, content });
    const result = Bun.spawnSync(hookCommand(), {
      stdin: new TextEncoder().encode(JSON.stringify(event)),
      timeout: 10_000,
      stdout: 'pipe',
      stderr: 'pipe',
    });
    if (result.exitCode !== 0) {
      const errorOutput = new TextDecoder().decode(result.stderr);
      console.error(`error: ${errorOutput}`);
      process.exit(1);
    }
    const output = new TextDecoder().decode(result.stdout);
    console.log(prettyJson(output));
  });

const testCommand = Command.make(
  'test',
  {
    command: Argument.string('command').pipe(
      Argument.optional,
      Argument.withDescription('Command to test (for Bash tool)'),
    ),
    content: Flag.string('content').pipe(
      Flag.optional,
      Flag.withDescription('Content for Write/Edit tools'),
    ),
    path: Flag.string('path').pipe(
      Flag.optional,
      Flag.withDescription('File path for Read/Write/Edit tools'),
    ),
    post: Flag.boolean('post').pipe(
      Flag.withDefault(false),
      Flag.withDescription('Test PostToolUse instead of PreToolUse'),
    ),
    stderr: Flag.string('stderr').pipe(
      Flag.optional,
      Flag.withDescription('Stderr for PostToolUse Bash'),
    ),
    stdout: Flag.string('stdout').pipe(
      Flag.optional,
      Flag.withDescription('Stdout for PostToolUse Bash'),
    ),
    tool: Flag.string('tool').pipe(
      Flag.withDefault('Bash'),
      Flag.withDescription('Tool name (Bash, Read, Write, Edit, MultiEdit)'),
    ),
  },
  ({ command, content, path, post, stderr, stdout, tool }) =>
    runTest({
      command: Option.getOrUndefined(command),
      content: Option.getOrUndefined(content),
      path: Option.getOrUndefined(path),
      post,
      stderr: Option.getOrUndefined(stderr),
      stdout: Option.getOrUndefined(stdout),
      tool,
    }),
).pipe(Command.withDescription('Test a synthetic hook event'));

const runInstall = (target: string): Effect.Effect<void> =>
  Effect.gen(function* runInstallEffect() {
    if (!['claude', 'codex', 'cursor', 'pi', 'oh-my-pi', 'omp', 'all'].includes(target)) {
      console.error(`error: unknown target "${target}"`);
      console.error('Valid targets: claude, codex, cursor, pi, oh-my-pi, all');
      process.exit(1);
    }

    let results: {
      readonly target: string;
      readonly result: { readonly success: boolean; readonly message: string };
    }[];

    switch (target) {
      case 'claude': {
        const result = yield* Effect.promise(() => installClaude());
        results = [{ target: 'claude', result }];
        break;
      }
      case 'codex': {
        const result = yield* Effect.promise(() => installCodex());
        results = [{ target: 'codex', result }];
        break;
      }
      case 'pi': {
        const result = yield* Effect.promise(() => installPi());
        results = [{ target: 'pi', result }];
        break;
      }
      case 'oh-my-pi':
      case 'omp': {
        const result = yield* Effect.promise(() => installOhMyPi());
        results = [{ target: 'oh-my-pi', result }];
        break;
      }
      case 'cursor': {
        const result = yield* Effect.promise(() => installCursor());
        results = [{ target: 'cursor', result }];
        break;
      }
      case 'all': {
        const installResults = yield* Effect.promise(() => installAll());
        results = installResults.map((r) => ({ target: r.target, result: r }));
        break;
      }
      default: {
        results = [];
        break;
      }
    }

    let hasFailure = false;
    for (const { target: t, result: r } of results) {
      if (r.success) {
        const symbol = r.message.startsWith('Already configured') ? '⊙' : '✓';
        console.log(`${symbol} [${t}] ${r.message}`);
      } else {
        console.error(`✗ [${t}] ${r.message}`);
        hasFailure = true;
      }
    }

    if (hasFailure) {
      process.exit(1);
    }
  });

const installCommand = Command.make(
  'install',
  {
    target: Argument.string('target').pipe(
      Argument.withDescription('Target agent (claude, codex, cursor, pi, oh-my-pi, or all)'),
    ),
  },
  ({ target }) => runInstall(target),
).pipe(Command.withDescription('Install tripwire hooks for AI agents'));

const app = Command.make('tripwire').pipe(
  Command.withDescription('Opinionated hooks dispatcher for AI coding agents'),
  Command.withSubcommands([testCommand, installCommand]),
);

const program = Command.run(app, { version: pkg.version });

const runCli = async (): Promise<void> => {
  try {
    await Effect.runPromise(program.pipe(Effect.provide(BunServices.layer)));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exitCode = 1;
  }
};

if (import.meta.main) {
  // oxlint-disable-next-line no-void -- runCli reports failures through process.exitCode.
  void runCli();
}

export { runCli };
