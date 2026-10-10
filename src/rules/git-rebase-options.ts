interface RebaseArguments {
  readonly upstream: string | undefined;
  readonly onto: string | undefined;
  readonly branch: string | undefined;
  readonly interactive: boolean;
  readonly exec: boolean;
  readonly updateRefs: boolean | undefined;
  readonly operation: string | undefined;
}

// Git accepts unique long-option abbreviations and bundled short options.
// Optional values (-S/-r) must be attached; mandatory values consume a word.
const VALUE_OPTIONS = new Set([
  '--onto',
  '--exec',
  '--strategy',
  '--strategy-option',
  '--whitespace',
  '--empty',
  '--trailer',
]);
const LONG_OPTIONS = [
  ...VALUE_OPTIONS,
  '--keep-base',
  '--no-verify',
  '--verify',
  '--quiet',
  '--verbose',
  '--stat',
  '--signoff',
  '--committer-date-is-author-date',
  '--reset-author-date',
  '--ignore-date',
  '--ignore-whitespace',
  '--force-rebase',
  '--no-ff',
  '--ff',
  '--continue',
  '--skip',
  '--abort',
  '--quit',
  '--edit-todo',
  '--show-current-patch',
  '--apply',
  '--merge',
  '--interactive',
  '--rerere-autoupdate',
  '--autosquash',
  '--update-refs',
  '--gpg-sign',
  '--rebase-merges',
  '--autostash',
  '--fork-point',
  '--root',
  '--reschedule-failed-exec',
  '--reapply-cherry-picks',
] as const;
const OPERATIONS = new Set(['--abort', '--quit', '--continue', '--skip', '--edit-todo']);
const SHORT_VALUES: ReadonlyMap<string, string> = new Map([
  ['x', '--exec'],
  ['s', '--strategy'],
  ['X', '--strategy-option'],
  ['C', '-C'],
]);

const longOption = (argument: string): string => {
  if (LONG_OPTIONS.includes(argument)) {
    return argument;
  }
  if (argument.startsWith('--no-')) {
    return `--no-${longOption(`--${argument.slice('--no-'.length)}`).slice(2)}`;
  }
  const matches = LONG_OPTIONS.filter((option) => option.startsWith(argument));
  return matches.length === 1 ? (matches[0] ?? argument) : argument;
};

interface RebaseOption {
  readonly name: string;
  readonly value: string | undefined;
}

const shortOptions = (
  argument: string,
): { readonly options: readonly RebaseOption[]; readonly consumesNext: boolean } => {
  const options: RebaseOption[] = [];
  for (let offset = 1; offset < argument.length; offset += 1) {
    const short = argument[offset] ?? '';
    if (short === 'i') {
      options.push({ name: '--interactive', value: undefined });
    }
    const valueOption = SHORT_VALUES.get(short);
    if (valueOption !== undefined) {
      options.push({ name: valueOption, value: undefined });
      return { options, consumesNext: offset + 1 === argument.length };
    }
    if (short === 'S' || short === 'r') {
      break;
    }
  }
  return { options, consumesNext: false };
};

const parseRebaseArguments = (args: readonly string[]): RebaseArguments => {
  const positional: string[] = [];
  const options: RebaseOption[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] ?? '';
    if (argument === '--') {
      positional.push(...args.slice(index + 1));
      break;
    }
    if (argument.startsWith('--')) {
      const equals = argument.indexOf('=');
      const option = longOption(equals === -1 ? argument : argument.slice(0, equals));
      if (VALUE_OPTIONS.has(option) && equals === -1) {
        index += 1;
        options.push({ name: option, value: args[index] });
      } else {
        options.push({
          name: option,
          value: equals === -1 ? undefined : argument.slice(equals + 1),
        });
      }
    } else if (argument.startsWith('-') && argument !== '-') {
      const parsed = shortOptions(argument);
      options.push(...parsed.options);
      index += parsed.consumesNext ? 1 : 0;
    } else {
      positional.push(argument);
    }
  }
  const root =
    options.findLast((option) => ['--root', '--no-root'].includes(option.name))?.name === '--root';
  const updateRefs = options.findLast((option) =>
    ['--update-refs', '--no-update-refs'].includes(option.name),
  );
  return {
    upstream: root ? undefined : positional[0],
    onto: options.findLast((option) => ['--onto', '--no-onto'].includes(option.name))?.value,
    branch: root ? positional[0] : positional[1],
    interactive: options.some((option) => option.name === '--interactive'),
    exec: options.some((option) => option.name === '--exec'),
    updateRefs: updateRefs === undefined ? undefined : updateRefs.name === '--update-refs',
    operation: options.findLast((option) => OPERATIONS.has(option.name))?.name,
  };
};

export { parseRebaseArguments };
