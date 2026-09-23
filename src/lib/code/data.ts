import { validateCodec } from './codecs';
import { failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';

// Inert data has no user-defined coercions or callables. Unknown bytes cannot
// authorize a path, a process argument, or a callable.
const data: Value = { kind: 'data' };
const text: Value = { kind: 'text' };
const isData = (value: Value): boolean => {
  const pending = [value];
  const seen = new Set<Value>();
  while (pending.length > 0) {
    const current = pending.pop();
    if (current !== undefined && !seen.has(current)) {
      seen.add(current);
      if (seen.size > 12_000) {
        return failInspection('Data exceeds the value inspection budget.');
      }
      if (current.kind === 'list') {
        pending.push(...current.items);
      } else if (current.kind === 'object') {
        pending.push(...current.entries.values());
      } else if (
        !new Set(['string', 'number', 'text', 'counter', 'data', 'builtin']).has(current.kind)
      ) {
        return false;
      }
    }
  }
  return true;
};
const requireData = (values: readonly Value[]): void => {
  if (!values.every((value) => isData(value))) {
    failInspection('Only inert data can be passed to a data operation.');
  }
};
const replaceText = (args: readonly Value[], language: CodeLanguage): Value => {
  const [before, after, count] = args;
  const validCount =
    language === 'python' &&
    args.length === 3 &&
    count?.kind === 'number' &&
    Number.isSafeInteger(count.value);
  if (
    (!validCount && args.length !== 2) ||
    before === undefined ||
    after === undefined ||
    !(
      before.kind === 'string' ||
      before.kind === 'text' ||
      (language !== 'python' && before.kind === 'builtin' && before.name === 'RegExp')
    ) ||
    !['string', 'text'].includes(after.kind)
  ) {
    return failInspection(
      'Text replacement needs two strings and an optional Python integer count.',
    );
  }
  return text;
};

const textMethod = (
  receiver: Value,
  name: string,
  args: readonly Value[],
  language: CodeLanguage,
): Value | null => {
  if (receiver.kind === 'string' || receiver.kind === 'text' || receiver.kind === 'data') {
    if (name === 'join' && args.length === 1) {
      return text;
    }
    if (name === 'decode' || name === 'encode') {
      if (args.length > 1) {
        return failInspection('Text conversion accepts only a standard encoding.');
      }
      if (args[0] !== undefined) {
        validateCodec(args[0]);
      }
      return text;
    }
    if (name === 'replace' || name === 'replaceAll') {
      return replaceText(args, language);
    }
    if (
      [
        'strip',
        'rstrip',
        'lstrip',
        'trim',
        'lower',
        'upper',
        'toLowerCase',
        'toUpperCase',
        'slice',
        'substring',
        'toFixed',
        'toPrecision',
        'toString',
      ].includes(name)
    ) {
      return text;
    }
    if (
      [
        'split',
        'splitlines',
        'startswith',
        'endswith',
        'startsWith',
        'endsWith',
        'includes',
        'find',
        'index',
        'indexOf',
        'match',
        'search',
        'test',
        'group',
        'groups',
        'groupdict',
      ].includes(name)
    ) {
      return data;
    }
  }
  return null;
};

const dataMethod = (
  receiver: Value,
  name: string,
  args: readonly Value[],
  language: CodeLanguage,
): Value => {
  requireData(args);
  if (language !== 'python' && name === 'join' && isData(receiver)) {
    return text;
  }
  if (language === 'python' && receiver.kind === 'counter' && name === 'most_common') {
    if (args.length > 1) {
      return failInspection('Counter.most_common accepts at most one data argument.');
    }
    return data;
  }
  const result = textMethod(receiver, name, args, language);
  if (result !== null) {
    return result;
  }
  if (
    language === 'python' &&
    ['get', 'keys', 'values', 'items', 'count', 'index'].includes(name) &&
    isData(receiver)
  ) {
    return data;
  }
  return failInspection(`Unsupported data method: ${name}.`);
};

const jsonLoad = (args: readonly Value[]): Value => {
  const [input] = args;
  const knownInput =
    input?.kind === 'file' || (input?.kind === 'symbol' && input.name === 'sys.stdin');
  if (args.length !== 1 || !knownInput) {
    return failInspection('JSON load requires a known file or stdin without callbacks.');
  }
  return data;
};

const regexSubstitution = (args: readonly Value[]): Value => {
  const [pattern, replacement, input] = args;
  if (
    args.length < 3 ||
    args.length > 5 ||
    pattern?.kind !== 'string' ||
    replacement?.kind !== 'string' ||
    input === undefined
  ) {
    return failInspection('Regex substitution needs literal pattern/replacement and one input.');
  }
  requireData([input, ...args.slice(3)]);
  return text;
};

const dataCall = (name: string, args: readonly Value[]): Value | null => {
  if (name === 're.sub') {
    return regexSubstitution(args);
  }
  if (name === 'json.load') {
    return jsonLoad(args);
  }
  if (['json.loads', 'JSON.parse', 'json.dumps', 'JSON.stringify', 'str'].includes(name)) {
    requireData(args);
    if (args.length < 1 || args.length > (name === 'JSON.stringify' ? 3 : 1)) {
      return failInspection('JSON callbacks and serialization options require review.');
    }
    return ['json.loads', 'JSON.parse'].includes(name) ? data : text;
  }
  if (
    [
      'len',
      'int',
      'float',
      'abs',
      'round',
      'sum',
      'sorted',
      'list',
      'bool',
      'min',
      'max',
      'any',
      'all',
    ].includes(name)
  ) {
    requireData(args);
    return data;
  }
  if (['print', 'console.log', 'console.info', 'console.warn', 'console.error'].includes(name)) {
    requireData(args);
    return data;
  }
  if (['sys.stdout.write', 'sys.stderr.write'].includes(name)) {
    requireData(args);
    return data;
  }
  if (name === 'sys.stdin.read') {
    requireData(args);
    return text;
  }
  return null;
};

export { data, dataCall, dataMethod, isData, requireData, text };
