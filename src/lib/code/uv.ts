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
  '--quiet',
  '-q',
  '--verbose',
  '-v',
]);

// Option ownership stops at the launched command. A pytest .py argument is not
// interpreter source, and an option after that command belongs to the child.
const uvInvocation = (invocation: ShellInvocation): UvInvocation => {
  const words = invocation.words.slice(1);
  if (words.some((word) => word.kind !== 'literal')) {
    return { kind: 'blocked', reason: 'The uv command contains unresolved arguments.' };
  }
  let index = 0;
  let noSync = false;
  const flags = (): void => {
    while (FLAGS.has(words[index]?.value ?? '')) {
      noSync ||= words[index]?.value === '--no-sync';
      index += 1;
    }
  };
  flags();
  if (words[index]?.value !== 'run') {
    return invocation.tokens.includes('run')
      ? { kind: 'blocked', reason: 'The uv run options require review.' }
      : { kind: 'irrelevant' };
  }
  index += 1;
  flags();
  if (words[index]?.value === '--') {
    index += 1;
  }
  const head = words[index]?.value;
  if (head === undefined || (head.startsWith('-') && head !== '-')) {
    return { kind: 'blocked', reason: 'The uv run command or options require review.' };
  }
  return { kind: 'command', argv: words.slice(index).map((word) => word.value), noSync };
};

export { uvInvocation };
