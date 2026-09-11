import type { ShellInvocation } from './types';

const VALUE_FLAGS = new Set([
  '--method',
  '-X',
  '--field',
  '-F',
  '--raw-field',
  '-f',
  '--input',
  '--header',
  '-H',
  '--hostname',
  '--cache',
  '--jq',
  '-q',
  '--template',
  '-t',
  '--preview',
  '-p',
]);
const FLAGS = new Set([
  '--paginate',
  '--slurp',
  '--silent',
  '--verbose',
  '--include',
  '-i',
  '--help',
  '--allow-escape-sequences',
]);
const BODY_FLAGS = new Set(['--field', '-F', '--raw-field', '-f', '--input']);

const readOption = (
  invocation: ShellInvocation,
  index: number,
): { name: string; value: string; nextIndex: number } | null => {
  const token = invocation.words[index]?.value ?? '';
  const equals = token.indexOf('=');
  const attachedShort = !token.startsWith('--') && token.length > 2;
  let name = token;
  let start = equals + 1;
  if (attachedShort) {
    name = token.slice(0, 2);
    start = token[2] === '=' ? 3 : 2;
  } else if (equals !== -1) {
    name = token.slice(0, equals);
  }
  if (!VALUE_FLAGS.has(name)) {
    return null;
  }
  if (attachedShort || equals !== -1) {
    return { name, value: token.slice(start), nextIndex: index };
  }
  const next = invocation.words[index + 1];
  return next?.kind === 'literal' ? { name, value: next.value, nextIndex: index + 1 } : null;
};

// GH changes its default to POST for fields/body input. An explicit method
// overrides that default; fields on GET are query parameters, not mutations.
const ghApiMutates = (invocation: ShellInvocation): boolean => {
  if (invocation.head !== 'gh' || invocation.tokens[1] !== 'api') {
    return false;
  }
  let method: string | null = null;
  let body = false;
  let graphql = false;
  let unresolved = false;
  for (let index = 2; index < invocation.words.length; index += 1) {
    const word = invocation.words[index];
    if (word === undefined) {
      return true;
    }
    unresolved ||= word.kind !== 'literal';
    const token = word.value;
    if (!token.startsWith('-')) {
      graphql ||= token === 'graphql';
    } else if (!FLAGS.has(token)) {
      const option = readOption(invocation, index);
      if (option === null) {
        return true;
      }
      // Typed fields can read @file or stdin. Explicit GET must not turn an
      // uninspected local file into an allowed outbound query parameter.
      if (
        option.name === '--input' ||
        (['-F', '--field'].includes(option.name) &&
          option.value.slice(option.value.indexOf('=') + 1).startsWith('@'))
      ) {
        return true;
      }
      if (option.name === '--method' || option.name === '-X') {
        method = option.value;
      }
      body ||= BODY_FLAGS.has(option.name);
      index = option.nextIndex;
    }
  }
  // GraphQL operation semantics require a separate parser. Keep body-bearing
  // GraphQL requests under the existing review boundary, including forced GET.
  if (graphql && body) {
    return true;
  }
  // Preserve ordinary unparameterized endpoint lookups. The new explicit-GET
  // exception requires literal argument boundaries throughout the command.
  return method === null ? body : unresolved || !['GET', 'HEAD'].includes(method);
};

export { ghApiMutates };
