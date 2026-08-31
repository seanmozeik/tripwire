import type { ShellInvocation, ShellWord } from './types';

const SHELL_WRAPPER_HEADS: ReadonlySet<string> = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'ash',
]);

const HEAD_RENAMING_HEADS: ReadonlySet<string> = new Set([
  'command',
  'exec',
  'env',
  'time',
  'nohup',
  'setsid',
  'nice',
  'ionice',
  'chronic',
  'stdbuf',
  'unbuffer',
  'taskset',
  'sudo',
  'doas',
  'xargs',
  'watch',
]);

const HEAD_RENAMING_VALUE_FLAGS: Readonly<Record<string, ReadonlySet<string>>> = {
  env: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string', '--block-signal']),
  time: new Set(['-f', '--format', '-o', '--output']),
  nice: new Set(['-n', '--adjustment']),
  ionice: new Set(['-c', '--class', '-n', '--classdata', '-p', '--pid']),
  stdbuf: new Set(['-i', '--input', '-o', '--output', '-e', '--error']),
  sudo: new Set([
    '-u',
    '--user',
    '-g',
    '--group',
    '-C',
    '--close-from',
    '-D',
    '--chdir',
    '-h',
    '--host',
    '-p',
    '--prompt',
    '-r',
    '--role',
    '-t',
    '--type',
    '-U',
    '--other-user',
    '-R',
    '--chroot',
    '-T',
    '--command-timeout',
  ]),
  doas: new Set(['-a', '-C', '-u']),
  xargs: new Set([
    '-I',
    '-i',
    '-J',
    '-n',
    '--max-args',
    '-P',
    '--max-procs',
    '-s',
    '--max-chars',
    '-L',
    '--max-lines',
    '-E',
    '--eof',
    '-d',
    '--delimiter',
    '-a',
    '--arg-file',
    '--replace',
  ]),
  watch: new Set(['-n', '--interval']),
};

const skipOptions = (
  words: readonly ShellWord[],
  start: number,
  valueFlags: ReadonlySet<string>,
): number => {
  let index = start;
  while (index < words.length) {
    const value = words[index]?.value;
    if (value === undefined) {
      break;
    }
    if (valueFlags.has(value)) {
      index += 2;
    } else if (value.includes('=') && valueFlags.has(value.slice(0, value.indexOf('=')))) {
      index += 1;
    } else if (value === '--') {
      return index + 1;
    } else if (value.startsWith('-') && value !== '-') {
      index += 1;
    } else {
      break;
    }
  }
  return index;
};

const skipHeadRenamingPrefix = (invocation: ShellInvocation): number => {
  const valueFlags = Object.hasOwn(HEAD_RENAMING_VALUE_FLAGS, invocation.head)
    ? (HEAD_RENAMING_VALUE_FLAGS[invocation.head] ?? new Set<string>())
    : new Set<string>();
  let index = skipOptions(invocation.words, 1, valueFlags);
  if (invocation.head === 'env') {
    while (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(invocation.words[index]?.value ?? '')) {
      index += 1;
    }
  }
  return index;
};

const commandFlagValueIndex = (words: readonly ShellWord[], flag: string): number | null => {
  for (let index = 1; index < words.length - 1; index += 1) {
    const value = words[index]?.value;
    if (
      value !== undefined &&
      (value === `-${flag}` ||
        (value.startsWith('-') && !value.startsWith('--') && value.slice(1).includes(flag)))
    ) {
      return index + 1;
    }
  }
  return null;
};

const namedFlagValueIndex = (
  words: readonly ShellWord[],
  flags: ReadonlySet<string>,
  start = 1,
): number | null => {
  for (let index = start; index < words.length; index += 1) {
    const value = words[index]?.value;
    if (value !== undefined) {
      if (flags.has(value)) {
        return index + 1 < words.length ? index + 1 : null;
      }
      for (const flag of flags) {
        if (value.startsWith(`${flag}=`)) {
          return index;
        }
      }
    }
  }
  return null;
};

const FD_VALUE_FLAGS: ReadonlySet<string> = new Set([
  '-e',
  '--extension',
  '-t',
  '--type',
  '-E',
  '--exclude',
  '-d',
  '--max-depth',
  '--min-depth',
  '--exact-depth',
  '-c',
  '--color',
  '--changed-within',
  '--changed-before',
  '-S',
  '--size',
  '-o',
  '--owner',
  '-j',
  '--threads',
  '-g',
  '--glob',
  '--format',
  '--max-results',
  '--ignore-file',
  '--search-path',
  '--base-directory',
  '--path-separator',
  '--and',
]);

const pathLike = (value: string): boolean =>
  value === '/' ||
  value === '~' ||
  value === '.' ||
  value === '..' ||
  value.startsWith('/') ||
  value.startsWith('~/') ||
  value.startsWith('./') ||
  value.startsWith('../') ||
  /^\$\{?HOME\}?(?:\/|$)/u.test(value);

const pathDanger = (value: string): number => {
  if (value === '/') {
    return 100;
  }
  if (value === '~' || /^\$\{?HOME\}?(?:\/|$)/u.test(value)) {
    return 90;
  }
  if (/^\/(?:etc|usr|bin|sbin|System|Library|var|boot|root|home)(?:\/|$)/u.test(value)) {
    return 80;
  }
  if (value.startsWith('/Users/')) {
    return 70;
  }
  if (value.startsWith('/')) {
    return 60;
  }
  if (value.startsWith('../')) {
    return 40;
  }
  return 10;
};

const pickExecRoot = (
  words: readonly ShellWord[],
  execFlagIndex: number,
  kind: 'fd' | 'find',
): ShellWord => {
  const candidates: ShellWord[] = [];
  for (let index = 1; index < execFlagIndex; index += 1) {
    const word = words[index];
    if (word !== undefined && kind === 'fd' && FD_VALUE_FLAGS.has(word.value)) {
      index += 1;
    } else if (word?.value.startsWith('-') === true) {
      if (kind === 'find') {
        break;
      }
    } else if (word !== undefined && pathLike(word.value)) {
      candidates.push(word);
    }
  }
  candidates.sort((left, right) => pathDanger(right.value) - pathDanger(left.value));
  return (
    candidates[0] ?? {
      source: '.',
      value: '.',
      kind: 'literal',
      range: words[0]?.range ?? { start: 0, end: 0 },
      quoted: false,
    }
  );
};

const FD_EXEC_FLAGS: ReadonlySet<string> = new Set(['-x', '-X', '--exec', '--exec-batch']);
const FD_PLACEHOLDERS: ReadonlySet<string> = new Set(['{}', '{/}', '{//}', '{.}', '{/.}']);
const FIND_EXEC_FLAGS: ReadonlySet<string> = new Set(['-exec', '-execdir', '-ok', '-okdir']);
const FIND_PLACEHOLDERS: ReadonlySet<string> = new Set(['{}']);
const RTK_WRAPPER_SUBCOMMANDS: ReadonlySet<string> = new Set([
  'run',
  'proxy',
  'err',
  'test',
  'summary',
]);

interface PrefixWrapper {
  readonly valueFlags: ReadonlySet<string>;
  readonly skipPositionals: number;
  readonly shellFlag: boolean;
}

const PREFIX_WRAPPERS: Readonly<Record<string, PrefixWrapper>> = {
  timeout: {
    valueFlags: new Set(['-s', '--signal', '-k', '--kill-after']),
    skipPositionals: 1,
    shellFlag: false,
  },
  gtimeout: {
    valueFlags: new Set(['-s', '--signal', '-k', '--kill-after']),
    skipPositionals: 1,
    shellFlag: false,
  },
  chroot: { valueFlags: new Set(['--userspec', '--groups']), skipPositionals: 1, shellFlag: false },
  flock: {
    valueFlags: new Set(['-w', '--wait', '--timeout', '-E', '--conflict-exit-code']),
    skipPositionals: 1,
    shellFlag: true,
  },
  su: { valueFlags: new Set(), skipPositionals: 0, shellFlag: true },
};

export type { PrefixWrapper };
export {
  FD_EXEC_FLAGS,
  FD_PLACEHOLDERS,
  FIND_EXEC_FLAGS,
  FIND_PLACEHOLDERS,
  HEAD_RENAMING_HEADS,
  PREFIX_WRAPPERS,
  RTK_WRAPPER_SUBCOMMANDS,
  SHELL_WRAPPER_HEADS,
  commandFlagValueIndex,
  namedFlagValueIndex,
  pickExecRoot,
  skipHeadRenamingPrefix,
  skipOptions,
};
