import { failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';
import { unknown } from './values';

// Inert data has no user-defined coercions or callables. Unknown bytes cannot
// authorize a path, a process argument, or an overwrite that might empty a file.
const data: Value = { kind: 'data' };
const fileText = (path: string): Value => ({ kind: 'text', path, preservesNonempty: true });
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
const writeKind = (target: string, value: Value | undefined): 'write' | 'truncate' => {
  if (value?.kind === 'string' && value.value.length > 0) {
    return 'write';
  }
  if (value?.kind === 'text' && value.path === target && value.preservesNonempty) {
    return 'write';
  }
  return 'truncate';
};

const replaceText = (receiver: Value, args: readonly Value[], language: CodeLanguage): Value => {
  const [before, after] = args;
  if (args.length !== 2 || before?.kind !== 'string' || after?.kind !== 'string') {
    return failInspection('Text replacement needs two literal strings.');
  }
  // JS replacement tokens such as $` can produce an empty string even when
  // the submitted replacement is nonempty. Literal Python str.replace cannot.
  const preserves = after.value.length > 0 && (language === 'python' || !after.value.includes('$'));
  return receiver.kind === 'text'
    ? { ...receiver, preservesNonempty: receiver.preservesNonempty && preserves }
    : { kind: 'text', path: null, preservesNonempty: false };
};

const dataMethod = (
  receiver: Value,
  name: string,
  args: readonly Value[],
  language: CodeLanguage,
): Value => {
  requireData(args);
  if (receiver.kind === 'string' || receiver.kind === 'text') {
    if (name === 'replace' || name === 'replaceAll') {
      return replaceText(receiver, args, language);
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
      return { kind: 'text', path: null, preservesNonempty: false };
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
  // Backreferences may expand to empty text. They cannot prove preservation.
  const preserves = replacement.value.length > 0 && !replacement.value.includes('\\');
  return input.kind === 'text'
    ? { ...input, preservesNonempty: input.preservesNonempty && preserves }
    : { kind: 'text', path: null, preservesNonempty: false };
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
    return ['json.loads', 'JSON.parse'].includes(name)
      ? data
      : { kind: 'text', path: null, preservesNonempty: false };
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
    return { kind: 'text', path: null, preservesNonempty: false };
  }
  return null;
};

export { data, dataCall, dataMethod, fileText, isData, requireData, writeKind };
