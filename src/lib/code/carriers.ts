import path from 'node:path';

import type { ShellInvocation } from '../bash';
import type { CodeLanguage } from './types';

type CodeInput =
  | { readonly kind: 'source'; readonly language: CodeLanguage; readonly source: string }
  | { readonly kind: 'blocked'; readonly reason: string }
  | { readonly kind: 'irrelevant' };

const irrelevant: CodeInput = { kind: 'irrelevant' };
const blocked = (reason: string): CodeInput => ({ kind: 'blocked', reason });
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
  'uv',
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
  if (!PACKAGE_LAUNCHERS.has(path.posix.basename(invocation.head))) {
    return false;
  }
  return invocation.words
    .slice(1)
    .some(
      (word) =>
        interpreterLanguage(word.value) !== null ||
        CODE_FLAGS.has(word.value) ||
        /\.(?:py|pyw|mjs|cjs|js|jsx|ts|tsx)$/u.test(word.value),
    );
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
  return (
    inlineInput(
      args.map((word) => word.value),
      language,
      name,
    ) ?? standardInput(invocation, language)
  );
};

export { interpreterInput, interpreterLanguage };
