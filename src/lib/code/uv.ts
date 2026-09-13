import type { ShellInvocation } from '../bash';

type UvInvocation =
  | { readonly kind: 'command'; readonly argv: readonly string[]; readonly noSync: boolean }
  | { readonly kind: 'blocked'; readonly reason: string }
  | { readonly kind: 'irrelevant' };

const FLAGS = new Set([
  '--no-sync',
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
const uvInvocation = (invocation: ShellInvocation): UvInvocation => {
  const words = invocation.words.slice(1);
  if (words.some((word) => word.kind !== 'literal')) {
    return { kind: 'blocked', reason: 'The uv command contains unresolved arguments.' };
  }
  let index = 0;
  let noSync = false;
  const flags = (): boolean => {
    while (index < words.length) {
      const token = words[index]?.value ?? '';
      if (FLAGS.has(token)) {
        noSync ||= token === '--no-sync';
        index += 1;
      } else if (token === '--python' || token === '-p' || token.startsWith('--python=')) {
        const attached = token.startsWith('--python=');
        const version = attached
          ? token.slice('--python='.length)
          : (words[index + 1]?.value ?? '');
        if (!/^[23](?:\.\d+){0,2}t?$/u.test(version)) {
          return false;
        }
        index += attached ? 1 : 2;
      } else {
        break;
      }
    }
    return true;
  };
  if (!flags()) {
    return { kind: 'blocked', reason: 'The uv Python selector must be a literal version.' };
  }
  if (words[index]?.value !== 'run') {
    return invocation.tokens.includes('run')
      ? unsupportedOptions(words[index]?.value ?? '', 'The uv run options require review.')
      : { kind: 'irrelevant' };
  }
  index += 1;
  if (!flags()) {
    return { kind: 'blocked', reason: 'The uv Python selector must be a literal version.' };
  }
  if (words[index]?.value === '--') {
    index += 1;
  }
  const head = words[index]?.value;
  if (head === undefined || (head.startsWith('-') && head !== '-')) {
    return unsupportedOptions(head ?? '', 'The uv run command or options require review.');
  }
  return { kind: 'command', argv: words.slice(index).map((word) => word.value), noSync };
};

export { uvInvocation, UV_ENVIRONMENT_GUIDANCE };
