import { validateCodec } from './codecs';
import { failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';
import { unknown } from './values';

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
      switch (current.kind) {
        case 'string':
        case 'number':
        case 'text':
        case 'data': {
          break;
        }
        case 'list': {
          pending.push(...current.items);
          break;
        }
        case 'object': {
          pending.push(...current.entries.values());
          break;
        }
        case 'file':
        case 'archive':
        case 'path':
        case 'method':
        case 'symbol':
        case 'unknown': {
          return false;
        }
        default: {
          return false;
        }
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
    !['string', 'text'].includes(before.kind) ||
    !['string', 'text'].includes(after.kind)
  ) {
    return failInspection(
      'Text replacement needs two strings and an optional Python integer count.',
    );
  }
  return text;
};

const dataMethod = (
  receiver: Value,
  name: string,
  args: readonly Value[],
  language: CodeLanguage,
): Value => {
  requireData(args);
  if (receiver.kind === 'string' || receiver.kind === 'text') {
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
        'trim',
        'lower',
        'upper',
        'toLowerCase',
        'toUpperCase',
        'slice',
        'substring',
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
      ].includes(name)
    ) {
      return data;
    }
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
    args.length !== 3 ||
    pattern?.kind !== 'string' ||
    replacement?.kind !== 'string' ||
    input === undefined
  ) {
    return failInspection('Regex substitution needs literal pattern/replacement and one input.');
  }
  requireData([input]);
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
    if (args.length !== 1) {
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
    return unknown;
  }
  if (name === 'sys.stdin.read') {
    requireData(args);
    return text;
  }
  return null;
};

export { data, dataCall, dataMethod, isData, requireData, text };
