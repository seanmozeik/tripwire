interface MergeArguments {
  /** The last `--edit` or `--no-edit`; undefined leaves Git's default in place. */
  readonly edit: boolean | undefined;
  /** `-m` or `-F` supplies the message, so Git does not open an editor by default. */
  readonly message: boolean;
  readonly strategies: readonly string[];
  readonly operation: string | undefined;
}

// Git accepts unique long-option abbreviations and bundled short options.
// Optional values (-S, --log, --gpg-sign) must be attached; mandatory values
// Consume the next word.
const VALUE_OPTIONS = new Set([
  '--strategy',
  '--strategy-option',
  '--message',
  '--file',
  '--into-name',
  '--cleanup',
]);
const LONG_OPTIONS = [
  ...VALUE_OPTIONS,
  '--stat',
  '--summary',
  '--compact-summary',
  '--log',
  '--squash',
  '--commit',
  '--edit',
  '--ff',
  '--ff-only',
  '--rerere-autoupdate',
  '--verify-signatures',
  '--verbose',
  '--quiet',
  '--abort',
  '--quit',
  '--continue',
  '--allow-unrelated-histories',
  '--progress',
  '--gpg-sign',
  '--autostash',
  '--overwrite-ignore',
  '--signoff',
  '--no-verify',
  '--verify',
] as const;
const OPERATIONS = new Set(['--abort', '--quit', '--continue']);
const SHORT_VALUES: ReadonlyMap<string, string> = new Map([
  ['s', '--strategy'],
  ['X', '--strategy-option'],
  ['m', '--message'],
  ['F', '--file'],
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

interface MergeOption {
  readonly name: string;
  readonly value: string | undefined;
}

const shortOptions = (
  argument: string,
  next: string | undefined,
): { readonly options: readonly MergeOption[]; readonly consumesNext: boolean } => {
  const options: MergeOption[] = [];
  for (let offset = 1; offset < argument.length; offset += 1) {
    const short = argument[offset] ?? '';
    if (short === 'e') {
      options.push({ name: '--edit', value: undefined });
    }
    const valueOption = SHORT_VALUES.get(short);
    if (valueOption !== undefined) {
      const attached = argument.slice(offset + 1);
      const consumesNext = attached === '';
      options.push({ name: valueOption, value: consumesNext ? next : attached });
      return { options, consumesNext };
    }
    if (short === 'S') {
      break;
    }
  }
  return { options, consumesNext: false };
};

const parseMergeArguments = (args: readonly string[]): MergeArguments => {
  const options: MergeOption[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index] ?? '';
    if (argument === '--') {
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
      const parsed = shortOptions(argument, args[index + 1]);
      options.push(...parsed.options);
      index += parsed.consumesNext ? 1 : 0;
    }
  }
  const edit = options.findLast((option) => ['--edit', '--no-edit'].includes(option.name));
  return {
    edit: edit === undefined ? undefined : edit.name === '--edit',
    message: options.some((option) => ['--message', '--file'].includes(option.name)),
    strategies: options
      .filter((option) => option.name === '--strategy')
      .map((option) => option.value ?? ''),
    operation: options.findLast((option) => OPERATIONS.has(option.name))?.name,
  };
};

export { parseMergeArguments };
