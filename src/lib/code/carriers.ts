import path from 'node:path';

import type { ShellInvocation } from '../bash';
import { projectCommand, type ProjectCommand } from './project-commands';
import type { CodeLanguage } from './types';
import { uvInvocation } from './uv';

type CodeInput =
  | ProjectCommand
  | { readonly kind: 'source'; readonly language: CodeLanguage; readonly source: string }
  | { readonly kind: 'command'; readonly argv: readonly string[] }
  | { readonly kind: 'blocked'; readonly reason: string }
  | { readonly kind: 'irrelevant' };

const irrelevant: CodeInput = { kind: 'irrelevant' };
const blocked = (reason: string): CodeInput => ({ kind: 'blocked', reason });
// File execution has the same trust boundary as running a project command.
// This classifies the invocation; it does not inspect the file or its imports.
const scriptFileInput = (args: readonly string[], name: string): boolean => {
  let index = 0;
  if (name === 'bun' && args[index] === '--cwd') {
    const directory = args[index + 1] ?? '';
    if (directory === '' || directory.startsWith('-')) {
      return false;
    }
    index += 2;
  } else if (name === 'bun' && (args[index]?.startsWith('--cwd=') ?? false)) {
    index += 1;
  }
  if (['bun', 'deno'].includes(name) && args[index] === 'run') {
    index += 1;
  }
  const flags = new Set(['-I', '-S', '-E', '-s', '-B', '-u', '-q', '--no-warnings']);
  if (name === 'deno') {
    for (const flag of ['-A', '--allow-all', '--no-check', '--no-config', '--no-prompt']) {
      flags.add(flag);
    }
  }
  while (flags.has(args[index] ?? '')) {
    index += 1;
  }
  if (args[index] === '--') {
    index += 1;
  }
  const file = args[index];
  return (
    file !== undefined &&
    !file.startsWith('-') &&
    !/^\w+:/u.test(file) &&
    /\.(?:py|pyw|mjs|cjs|js|jsx|ts|tsx)$/u.test(file)
  );
};
const interpreterLanguage = (head: string): CodeLanguage | null => {
  const name = path.posix.basename(head);
  if (/^(?:python|pypy)(?:[23](?:\.\d+)*t?)?$/u.test(name)) {
    return 'python';
  }
  if (['node', 'nodejs'].includes(name)) {
    return 'javascript';
  }
  if (['bun', 'deno', 'tsx', 'ts-node'].includes(name)) {
    return 'typescript';
  }
  return null;
};

const PACKAGE_LAUNCHERS = new Set([
  'poetry',
  'pipenv',
  'pipx',
  'npx',
  'bunx',
  'npm',
  'pnpm',
  'yarn',
]);
const CODE_FLAGS = new Set(['--script', '--module', '-m', '-c', '-e', '--eval', '--call']);
const opaqueCodeLauncher = (invocation: ShellInvocation): boolean => {
  const name = path.posix.basename(invocation.head);
  if (!PACKAGE_LAUNCHERS.has(name)) {
    return false;
  }
  return invocation.words
    .slice(1)
    .some(
      (word) =>
        interpreterLanguage(word.value) !== null ||
        CODE_FLAGS.has(word.value.split('=')[0] ?? '') ||
        /\.(?:py|pyw|mjs|cjs|js|jsx|ts|tsx)$/u.test(word.value),
    );
};

const uvCommand = (invocation: ShellInvocation): CodeInput => {
  const child = uvInvocation(invocation);
  if (child.kind !== 'command') {
    return child;
  }
  const head = child.argv[0] ?? '';
  const language = head === '-' ? 'python' : interpreterLanguage(head);
  if (language !== null) {
    if (scriptFileInput(child.argv.slice(1), path.posix.basename(head))) {
      return irrelevant;
    }
    if (!child.noSync) {
      return blocked(
        'Inline code through uv requires --no-sync and an existing trusted environment.',
      );
    }
    if (head === '-') {
      return child.argv.length === 1
        ? standardInput(invocation, language)
        : blocked('Trailing uv stdin arguments require review.');
    }
    return (
      inlineInput(child.argv.slice(1), language, path.posix.basename(head)) ??
      standardInput(invocation, language)
    );
  }
  if (/\.(?:py|pyw|mjs|cjs|js|jsx|ts|tsx)$/u.test(head)) {
    return irrelevant;
  }
  return { kind: 'command', argv: child.argv };
};

const standardInput = (invocation: ShellInvocation, language: CodeLanguage): CodeInput => {
  const inputs = invocation.redirects.filter((redirect) =>
    ['<<', '<<<', '<', '<&'].includes(redirect.op),
  );
  if (inputs.length !== 1) {
    return blocked('Interpreter input is absent, piped, or redirected more than once.');
  }
  const [input] = inputs;
  if (input?.op === '<<' && input.heredoc !== undefined) {
    if (!input.heredoc.quoted && /[$`\\]/u.test(input.heredoc.content)) {
      return blocked('Unquoted interpreter heredoc can change during shell expansion.');
    }
    return { kind: 'source', language, source: input.heredoc.content };
  }
  if (input?.op === '<<<' && input.target.kind === 'literal') {
    return { kind: 'source', language, source: input.target.value };
  }
  return blocked('Interpreter input bytes are not available for inspection.');
};

const inlineInput = (
  args: readonly string[],
  language: CodeLanguage,
  name: string,
): CodeInput | null => {
  const passFlags = new Set(
    language === 'python'
      ? ['-I', '-S', '-E', '-s', '-B', '-u', '-q']
      : ['--input-type=module', '--input-type=commonjs', '--no-warnings'],
  );
  let index = 0;
  while (index < args.length && passFlags.has(args[index] ?? '')) {
    index += 1;
  }
  const value = args[index];
  if (value === undefined || (value === '-' && index === args.length - 1)) {
    return null;
  }
  const codeFlags = language === 'python' ? ['-c'] : ['-e', '--eval', '-p', '--print'];
  if (name === 'deno') {
    codeFlags.push('eval');
  }
  if (codeFlags.includes(value)) {
    const source = args[index + 1];
    if (source === undefined || args.length !== index + 2) {
      return blocked('Interpreter source or trailing arguments are not fully inspected.');
    }
    return { kind: 'source', language, source };
  }
  const prefixes = language === 'python' ? ['-c'] : ['-e', '-p', '--eval=', '--print='];
  const prefix = prefixes.find((candidate) => value.startsWith(candidate));
  if (prefix !== undefined && args.length === index + 1) {
    return { kind: 'source', language, source: value.slice(prefix.length) };
  }
  return blocked(
    'Interpreter flags, script files, modules, and interactive sessions require explicit review.',
  );
};

const interpreterInput = (invocation: ShellInvocation): CodeInput => {
  if (opaqueCodeLauncher(invocation)) {
    return blocked(
      'A package launcher can change the interpreter or load project startup code. Use a directly inspected interpreter.',
    );
  }
  if (path.posix.basename(invocation.head) === 'uv') {
    return uvCommand(invocation);
  }
  const language = interpreterLanguage(invocation.head);
  if (language === null) {
    return irrelevant;
  }
  const args = invocation.words.slice(1);
  const name = path.posix.basename(invocation.head);
  // Project commands remain subject to the existing package and shell policies.
  if (
    name === 'bun' &&
    args[0]?.kind === 'literal' &&
    ['add', 'install', 'remove', 'update', 'outdated', 'pm', 'build', 'test'].includes(
      args[0].value,
    )
  ) {
    return irrelevant;
  }
  if (args.some((word) => word.kind !== 'literal')) {
    return blocked('Interpreter arguments contain runtime substitutions.');
  }
  if (args.length === 1 && ['--version', '-V', '--help', '-h'].includes(args[0]?.value ?? '')) {
    return irrelevant;
  }
  const values = args.map((word) => word.value);
  if (scriptFileInput(values, name)) {
    return irrelevant;
  }
  return (
    projectCommand(name, values) ??
    inlineInput(values, language, name) ??
    standardInput(invocation, language)
  );
};

export { interpreterInput, interpreterLanguage };
