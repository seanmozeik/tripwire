#!/usr/bin/env bun
// `tripwire test '<command>'` — pipe a synthetic event through the
// Dispatcher and pretty-print the decision. Indispensable for tuning
// Rules without going through Claude Code.
//
// `tripwire install <target>` — install tripwire hooks for AI agents.
//
// Usage:
//   Bun src/cli.ts test 'rm -rf /etc'
//   Bun src/cli.ts test --tool=Read --path=.env
//   Bun src/cli.ts test --post --tool=Bash --stdout='ghp_<token>'
//   Bun src/cli.ts install claude
//   Bun src/cli.ts install codex
//   Bun src/cli.ts install pi
//   Bun src/cli.ts install all

import { spawnSync } from 'node:child_process';

import { installAll, installClaude, installCodex, installPi } from './lib/install';

const DISPATCH_BIN = `${import.meta.dir}/../dist/tripwire.js`;

interface CliArgs {
  readonly tool: string;
  readonly post: boolean;
  readonly path: string | undefined;
  readonly command: string | undefined;
  readonly stdout: string | undefined;
  readonly stderr: string | undefined;
  readonly content: string | undefined;
}

const parseArgs = (argv: readonly string[]): CliArgs => {
  let tool = 'Bash';
  let post = false;
  let path: string | undefined;
  let command: string | undefined;
  let stdout: string | undefined;
  let stderr: string | undefined;
  let content: string | undefined;
  for (const a of argv) {
    if (a === '--post') {
      post = true;
      continue;
    }
    if (a.startsWith('--tool=')) {
      tool = a.slice('--tool='.length);
      continue;
    }
    if (a.startsWith('--path=')) {
      path = a.slice('--path='.length);
      continue;
    }
    if (a.startsWith('--stdout=')) {
      stdout = a.slice('--stdout='.length);
      continue;
    }
    if (a.startsWith('--stderr=')) {
      stderr = a.slice('--stderr='.length);
      continue;
    }
    if (a.startsWith('--content=')) {
      content = a.slice('--content='.length);
      continue;
    }
    command ??= a;
  }
  return { tool, post, path, command, stdout, stderr, content };
};

interface BuiltEvent {
  hook_event_name: string;
  tool_name: string;
  cwd: string;
  session_id: string;
  tool_input?: unknown;
  tool_response?: unknown;
}

const buildToolInput = (tool: string, args: CliArgs): unknown => {
  if (tool === 'Bash') {
    return { command: args.command ?? '' };
  }
  if (tool === 'Read') {
    return { file_path: args.path ?? '' };
  }
  if (tool === 'Write') {
    return { file_path: args.path ?? '', content: args.content ?? '' };
  }
  if (tool === 'Edit' || tool === 'MultiEdit') {
    return { file_path: args.path ?? '', old_string: '', new_string: args.content ?? '' };
  }
  return undefined;
};

const buildEvent = (args: CliArgs): BuiltEvent => {
  const eventName = args.post ? 'PostToolUse' : 'PreToolUse';
  const tool = args.tool;
  const event: BuiltEvent = {
    hook_event_name: eventName,
    tool_name: tool,
    cwd: process.cwd(),
    session_id: 'tripwire-cli-test',
    tool_input: buildToolInput(tool, args),
  };
  if (args.post) {
    event.tool_response =
      tool === 'Bash'
        ? { stdout: args.stdout ?? '', stderr: args.stderr ?? '' }
        : { content: args.content ?? '' };
  }
  return event;
};

const printUsage = (): void => {
  process.stdout.write(
    [
      'tripwire CLI — synthetic-event tester and hook installer',
      '',
      'Usage:',
      "  tripwire test '<command>'                 # PreToolUse Bash",
      '  tripwire test --tool=Read --path=.env     # PreToolUse Read',
      "  tripwire test --tool=Write --path=foo.ts --content='TODO finish'",
      "  tripwire test --post --tool=Bash --stdout='ghp_REAL_TOKEN'  # PostToolUse",
      '',
      '  tripwire install claude                  # Install hooks for Claude Code',
      '  tripwire install codex                   # Install hooks for Codex',
      '  tripwire install pi                      # Install hooks for pi-guardrails',
      '  tripwire install all                     # Install hooks for all agents',
      '',
    ].join('\n'),
  );
};

const handleInstall = async (argv: readonly string[]): Promise<void> => {
  if (argv.length < 2) {
    process.stderr.write('error: install requires a target (claude, codex, pi, or all)\n');
    printUsage();
    process.exit(1);
  }

  const target = argv[1]!;
  switch (target) {
    case 'claude': {
      const result = await installClaude();
      if (result.success) {
        const symbol = result.message.startsWith('Already configured') ? '⊙' : '✓';
        process.stdout.write(`${symbol} ${result.message}\n`);
      } else {
        process.stderr.write(`✗ ${result.message}\n`);
        process.exit(1);
      }
      break;
    }
    case 'codex': {
      const result = await installCodex();
      if (result.success) {
        const symbol = result.message.startsWith('Already configured') ? '⊙' : '✓';
        process.stdout.write(`${symbol} ${result.message}\n`);
      } else {
        process.stderr.write(`✗ ${result.message}\n`);
        process.exit(1);
      }
      break;
    }
    case 'pi': {
      const result = await installPi();
      if (result.success) {
        const symbol = result.message.startsWith('Already configured') ? '⊙' : '✓';
        process.stdout.write(`${symbol} ${result.message}\n`);
      } else {
        process.stderr.write(`✗ ${result.message}\n`);
        process.exit(1);
      }
      break;
    }
    case 'all': {
      const results = await installAll();
      let hasFailure = false;
      for (const result of results) {
        if (result.success) {
          const symbol = result.message.startsWith('Already configured') ? '⊙' : '✓';
          process.stdout.write(`${symbol} [${result.target}] ${result.message}\n`);
        } else {
          process.stderr.write(`✗ [${result.target}] ${result.message}\n`);
          hasFailure = true;
        }
      }
      if (hasFailure) {
        process.exit(1);
      }
      break;
    }
    default: {
      process.stderr.write(`error: unknown target "${target}"\n`);
      process.stderr.write('Valid targets: claude, codex, pi, all\n');
      process.exit(1);
    }
  }
};

const main = async (): Promise<void> => {
  const argv = process.argv.slice(2);
  if (argv.length === 0) {
    printUsage();
    process.exit(0);
  }

  const command = argv[0];

  if (command === 'install') {
    await handleInstall(argv);
    return;
  }

  if (command !== 'test') {
    printUsage();
    process.exit(0);
  }

  const args = parseArgs(argv.slice(1));
  const event = buildEvent(args);
  const result = spawnSync(DISPATCH_BIN, [], {
    input: JSON.stringify(event),
    encoding: 'utf8',
    timeout: 10_000,
  });
  if (result.error !== undefined) {
    process.stderr.write(`error: ${String(result.error)}\n`);
    process.exit(1);
  }
  const stdout: string = result.stdout;
  try {
    const parsed = JSON.parse(stdout) as unknown;
    process.stdout.write(`${JSON.stringify(parsed, null, 2)}\n`);
  } catch {
    process.stdout.write(stdout);
  }
};

// oxlint-disable-next-line no-void, unicorn/prefer-top-level-await
void main();
