import path from 'node:path';

import type { ShellInvocation, ShellWord } from '../bash';
import { hasScriptOperand, SHELL_WRAPPER_HEADS } from '../bash/wrappers';
import type { CodeLanguage } from './types';
import { uvInvocation, UV_ENVIRONMENT_GUIDANCE } from './uv';

type CarrierInvocation = Pick<ShellInvocation, 'head' | 'words' | 'tokens' | 'redirects'>;

type CodeInput =
  | { readonly kind: 'source'; readonly language: CodeLanguage; readonly source: string }
  | { readonly kind: 'command'; readonly command: string; readonly requiresContext: boolean }
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

const standardInput = (invocation: CarrierInvocation, language: CodeLanguage): CodeInput => {
  const inputs = invocation.redirects.filter((redirect) =>
    ['<<', '<<<', '<', '<&'].includes(redirect.op),
  );
  if (inputs.length !== 1) {
    return blocked('Interpreter input is absent, piped, or redirected more than once.');
  }
  const [input] = inputs;
  if (input?.op === '<' && input.target.kind === 'literal') {
    return irrelevant;
  }
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

// These options own the following token. Other runner flags do not need approval.
const VALUE_OPTIONS = new Set([
  '--require',
  '-r',
  '--import',
  '--loader',
  '--experimental-loader',
  '--preload',
  '--input-type',
  '-X',
  '-W',
  '--config',
  '--stack-trace-limit',
  '--cwd',
  '--filter',
  '-F',
  '--elide-lines',
  '--shell',
  '--test-name-pattern',
  '--test-skip-pattern',
  '--test-reporter',
  '--test-reporter-destination',
  '--test-concurrency',
  '--test-timeout',
  '--conditions',
  '-C',
  '--title',
  '--icu-data-dir',
  '--env-file',
  '--env-file-if-exists',
]);
const STARTUP_OPTIONS = new Set([
  '--require',
  '-r',
  '--import',
  '--loader',
  '--experimental-loader',
  '--preload',
  '--cwd',
  '--env-file',
  '--env-file-if-exists',
]);

const sourceFlag = (token: string, language: CodeLanguage, name: string): string | null => {
  const flags = language === 'python' ? ['-c'] : ['-e', '-p', '--eval', '--print'];
  if (flags.includes(token) || (name === 'deno' && token === 'eval')) {
    return '';
  }
  const prefixes = language === 'python' ? ['-c'] : ['--eval=', '--print=', '-e', '-p'];
  return (
    prefixes.find(
      (prefix) => token.startsWith(prefix) && (prefix.length > 2 || !token.startsWith('--')),
    ) ?? null
  );
};

const sourceInput = (
  invocation: CarrierInvocation,
  index: number,
  prefix: string,
  language: CodeLanguage,
  startup: boolean,
): CodeInput => {
  if (startup) {
    return blocked('Inline source has unverified interpreter startup options.');
  }
  const source = invocation.words[index + (prefix === '' ? 2 : 1)];
  if (source?.kind !== 'literal' || invocation.words.length !== index + (prefix === '' ? 3 : 2)) {
    return blocked('Interpreter source or trailing arguments are not fully inspected.');
  }
  return {
    kind: 'source',
    language,
    source: prefix === '' ? source.value : source.value.slice(prefix.length),
  };
};

const entryInput = (
  invocation: CarrierInvocation,
  token: string,
  next: string | undefined,
  language: CodeLanguage,
): CodeInput | null => {
  if (['-', '/dev/stdin', '/dev/fd/0'].includes(token)) {
    return standardInput(invocation, language);
  }
  if (token === '--') {
    return next === '-' ? standardInput(invocation, language) : irrelevant;
  }
  if (language === 'python' && token.startsWith('-m')) {
    return irrelevant;
  }
  if (!token.startsWith('-')) {
    return irrelevant;
  }
  if (language === 'python' && /^-[^-]*c/u.test(token)) {
    return blocked('Combined Python source flags require inspection.');
  }
  return null;
};

const directInput = (invocation: CarrierInvocation, language: CodeLanguage): CodeInput => {
  const name = path.posix.basename(invocation.head);
  const args = invocation.words.slice(1);
  let startup = false;
  let commandMode = false;
  for (let index = 0; index < args.length; index += 1) {
    const word = args[index];
    if (word?.kind !== 'literal') {
      return blocked('Interpreter arguments contain runtime substitutions.');
    }
    const token = word.value;
    const prefix = sourceFlag(token, language, name);
    if (prefix !== null) {
      return sourceInput(invocation, index, prefix, language, startup);
    }
    if (name === 'bun' && token === 'run' && !commandMode) {
      commandMode = true;
    } else {
      const entry = entryInput(invocation, token, args[index + 1]?.value, language);
      if (entry !== null) {
        return withContext(
          entry,
          startup,
          'Inline stdin source has unverified interpreter startup options.',
        );
      }
      const option = token.split('=')[0] ?? '';
      startup ||= STARTUP_OPTIONS.has(option);
      if (VALUE_OPTIONS.has(option) && !token.includes('=')) {
        index += 1;
      }
    }
  }
  if (
    commandMode ||
    args.some((word) => ['--help', '-h', '--version', '-V', '--test'].includes(word.value))
  ) {
    return irrelevant;
  }
  return withContext(
    standardInput(invocation, language),
    startup,
    'Inline stdin source has unverified interpreter startup options.',
  );
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
const LAUNCHER_VALUES = new Set([
  '--package',
  '-p',
  '--filter',
  '-F',
  '--dir',
  '-C',
  '--prefix',
  '--cwd',
]);
// Keep shell provenance until the child reaches its own script/source boundary.
const forwardedInput = (
  invocation: CarrierInvocation,
  words: readonly ShellWord[],
  depth: number,
): CodeInput => {
  if (words[0]?.kind !== 'literal') {
    return blocked('Forwarded command executable is unresolved.');
  }
  const child: CarrierInvocation = {
    head: words[0].value,
    words,
    tokens: words.map((word) => word.value),
    redirects: invocation.redirects,
  };
  const input = interpreterInput(child, depth + 1);
  const head = path.posix.basename(child.head);
  const requiresContext = SHELL_WRAPPER_HEADS.has(head)
    ? !hasScriptOperand(child)
    : ['rm', 'find', 'env', 'uv'].includes(head);
  return input.kind === 'irrelevant'
    ? {
        kind: 'command',
        command: words
          .map((word) =>
            word.kind === 'literal'
              ? `'${word.value.replaceAll("'", String.raw`'\''`)}'`
              : `\${TRIPWIRE_UNRESOLVED}`,
          )
          .join(' '),
        requiresContext,
      }
    : input;
};

const withContext = (input: CodeInput, unsafe: boolean, reason: string): CodeInput =>
  unsafe && (input.kind === 'source' || (input.kind === 'command' && input.requiresContext))
    ? blocked(reason)
    : input;

const uvInput = (invocation: CarrierInvocation, depth: number): CodeInput => {
  const child = uvInvocation(invocation);
  if (child.kind !== 'command') {
    return child;
  }
  return withContext(
    forwardedInput(invocation, child.words, depth),
    child.unsafeInlineContext,
    `Inline source or command has an unverified uv execution context. ${UV_ENVIRONMENT_GUIDANCE}`,
  );
};

const packageInput = (invocation: CarrierInvocation, depth: number): CodeInput => {
  let index = path.posix.basename(invocation.head) === 'bun' ? 2 : 1;
  let unsafeContext = false;
  let subcommand = false;
  for (; index < invocation.words.length; index += 1) {
    const word = invocation.words[index];
    if (word?.kind !== 'literal') {
      return blocked('Package command contains unresolved arguments.');
    }
    if (word.value === '--') {
      index += 1;
      break;
    }
    if (!subcommand && ['run', 'exec', 'x'].includes(word.value)) {
      subcommand = true;
    } else {
      if (!word.value.startsWith('-')) {
        break;
      }
      if (['-c', '--call'].includes(word.value)) {
        const source = invocation.words[index + 1];
        return source?.kind === 'literal'
          ? withContext(
              { kind: 'command', command: source.value, requiresContext: true },
              unsafeContext,
              'Package shell source has an unverified execution context.',
            )
          : blocked('Package shell source is unresolved.');
      }
      const option = word.value.split('=')[0] ?? '';
      unsafeContext ||= ['--dir', '-C', '--prefix', '--cwd'].includes(option);
      if (LAUNCHER_VALUES.has(option) && !word.value.includes('=')) {
        index += 1;
      }
    }
  }
  const words = invocation.words.slice(index);
  return words.length === 0
    ? irrelevant
    : withContext(
        forwardedInput(invocation, words, depth),
        unsafeContext,
        'Forwarded inline source or command has an unverified package working directory.',
      );
};

const interpreterInput = (invocation: CarrierInvocation, depth = 0): CodeInput => {
  if (depth > 8) {
    return blocked('Interpreter wrapper depth exceeded.');
  }
  const name = path.posix.basename(invocation.head);
  if (name === 'uv') {
    return uvInput(invocation, depth);
  }
  if (name === 'bun' && invocation.tokens[1] === 'exec') {
    const source = invocation.words.at(2);
    return source?.kind === 'literal' && invocation.words.length === 3
      ? { kind: 'command', command: source.value, requiresContext: true }
      : blocked('Bun exec requires one literal shell program.');
  }
  if (PACKAGE_LAUNCHERS.has(name) || (name === 'bun' && invocation.tokens[1] === 'x')) {
    return packageInput(invocation, depth);
  }
  const language = interpreterLanguage(invocation.head);
  return language === null ? irrelevant : directInput(invocation, language);
};

export { interpreterInput, interpreterLanguage };
