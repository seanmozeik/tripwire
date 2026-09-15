import type { ShellInvocation, ShellWord } from '../bash';

type UvInvocation =
  | {
      readonly kind: 'command';
      readonly words: readonly ShellWord[];
      readonly unsafeInlineContext: boolean;
    }
  | { readonly kind: 'blocked'; readonly reason: string }
  | { readonly kind: 'irrelevant' };

const FLAGS = new Set([
  '--all-extras',
  '--no-editable',
  '--no-build',
  '--no-sources',
  '--no-sync',
  '--no-dev',
  '--only-dev',
  '--all-groups',
  '--no-default-groups',
  '--active',
  '--locked',
  '--frozen',
  '--offline',
  '--no-project',
  '--no-config',
  '--no-python-downloads',
  '--quiet',
  '-q',
  '--verbose',
  '-v',
]);
const VALUE_OPTIONS = new Set([
  '--project',
  '--directory',
  '--package',
  '--group',
  '--no-group',
  '--only-group',
  '--extra',
  '--with',
  '--with-editable',
  '--with-requirements',
]);
const CONTEXT_OPTIONS = new Set([
  '--project',
  '--directory',
  '--with',
  '--with-editable',
  '--with-requirements',
]);
const scriptInvocation = (
  words: readonly ShellWord[],
  unsafeInlineContext: boolean,
): UvInvocation | null => {
  const option = words[0]?.value;
  if (option === undefined || !(option === '--script' || option.startsWith('--script='))) {
    return null;
  }
  const target = words[option === '--script' ? 1 : 0];
  if (target === undefined) {
    return { kind: 'irrelevant' };
  }
  return {
    kind: 'command',
    words: [
      { ...target, kind: 'literal', value: 'python', source: 'python' },
      option === '--script'
        ? target
        : {
            ...target,
            value: option.slice('--script='.length),
            source: `'${option.slice('--script='.length).replaceAll("'", String.raw`'\''`)}'`,
          },
      ...words.slice(option === '--script' ? 2 : 1),
    ],
    unsafeInlineContext,
  };
};

const UV_ENVIRONMENT_GUIDANCE =
  'Declare dependencies in pyproject.toml, run uv sync, then use uv run --no-sync python -c with inline source. If selecting Python, use --python with a literal version such as 3.12.';

const unsupportedOptions = (token: string, fallback: string): UvInvocation => ({
  kind: 'blocked',
  reason: /^--with(?:-editable|-requirements)?(?:=|$)/u.test(token)
    ? `uv dependency injection options are not inspected. ${UV_ENVIRONMENT_GUIDANCE}`
    : fallback,
});

// Option ownership stops at the launched command. A pytest .py argument is not
// interpreter source, and an option after that command belongs to the child.
const uvInvocation = (invocation: Pick<ShellInvocation, 'words' | 'tokens'>): UvInvocation => {
  const words = invocation.words.slice(1);
  let index = 0;
  let unsafeInlineContext = false;
  const flags = (): void => {
    while (index < words.length) {
      const token = words[index]?.value ?? '';
      if (words[index]?.kind !== 'literal') {
        break;
      }
      if (FLAGS.has(token)) {
        index += 1;
      } else if (token === '--python' || token === '-p' || token.startsWith('--python=')) {
        const attached = token.startsWith('--python=');
        const version = attached
          ? token.slice('--python='.length)
          : (words[index + 1]?.value ?? '');
        unsafeInlineContext ||= !/^[23](?:\.\d+){0,2}t?$/u.test(version);
        index += attached ? 1 : 2;
      } else if (VALUE_OPTIONS.has(token.split('=')[0] ?? '')) {
        unsafeInlineContext ||= CONTEXT_OPTIONS.has(token.split('=')[0] ?? '');
        index += token.includes('=') ? 1 : 2;
      } else {
        break;
      }
    }
  };
  flags();
  if (words[index]?.value !== 'run') {
    return invocation.tokens.includes('run')
      ? unsupportedOptions(words[index]?.value ?? '', 'The uv run options require review.')
      : { kind: 'irrelevant' };
  }
  index += 1;
  flags();
  if (words[index]?.value === '--') {
    index += 1;
  }
  const script = scriptInvocation(words.slice(index), unsafeInlineContext);
  if (script !== null) {
    return script;
  }
  const executable = words[index];
  const head = executable?.value;
  if (
    executable === undefined ||
    head === undefined ||
    ['--help', '-h', '--version', '-V'].includes(head)
  ) {
    return { kind: 'irrelevant' };
  }
  if (head.startsWith('-') && head !== '-') {
    return unsupportedOptions(head, 'The uv run command or options require review.');
  }
  return {
    kind: 'command',
    words:
      head === '-'
        ? [
            { ...executable, kind: 'literal', value: 'python', source: 'python' },
            ...words.slice(index),
          ]
        : words.slice(index),
    unsafeInlineContext,
  };
};

export { uvInvocation, UV_ENVIRONMENT_GUIDANCE };
