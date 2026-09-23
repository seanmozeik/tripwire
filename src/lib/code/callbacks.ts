import type { CallArguments } from './arguments';
import { data, requireData, text } from './data';
import { failInspection } from './syntax';
import type { Value } from './types';

type Invoke = (fn: Value, args: readonly Value[]) => Value;

const methodCallback = (
  fn: Extract<Value, { kind: 'method' }>,
  input: CallArguments,
  invoke: Invoke,
): Value | null => {
  if (!['map', 'filter', 'forEach', 'reduce', 'sort'].includes(fn.name)) {
    return null;
  }
  requireData([fn.receiver]);
  const [positional, ...rest] = input.positional;
  const callback = input.keywords.get('key') ?? positional;
  for (const [name, value] of input.keywords) {
    if (name !== 'key' || fn.name !== 'sort') {
      requireData([value]);
    }
  }
  if (fn.name === 'sort' && (fn.receiver.kind === 'list' || fn.receiver.kind === 'object')) {
    fn.receiver.opaque = true;
  }
  if (callback === undefined && fn.name === 'sort') {
    return data;
  }
  if (callback === undefined) {
    return failInspection('Missing callback.');
  }
  requireData(rest);
  const result = invoke(
    callback,
    fn.name === 'reduce' || (fn.name === 'sort' && !input.keywords.has('key'))
      ? [data, data]
      : [data],
  );
  requireData([result]);
  return data;
};

const namedCallback = (name: string, input: CallArguments, invoke: Invoke): Value | null => {
  const args = input.positional;
  if (name === 'sorted' && input.keywords.has('key')) {
    const callback = input.keywords.get('key');
    requireData(args);
    for (const [key, value] of input.keywords) {
      if (key !== 'key') {
        requireData([value]);
      }
    }
    if (callback !== undefined) {
      requireData([invoke(callback, [data])]);
    }
    return data;
  }
  if (name === 'functools.reduce' || name === 'Array.from') {
    const index = name === 'Array.from' ? 1 : 0;
    const callback = args[index];
    requireData(args.filter((_, position) => position !== index));
    if (callback !== undefined) {
      requireData([invoke(callback, name === 'Array.from' ? [data] : [data, data])]);
    }
    return data;
  }
  const [, callback] = args;
  if (callback?.kind === 'closure' && ['JSON.stringify', 're.sub'].includes(name)) {
    requireData([args[0] ?? data, ...args.slice(2), ...input.keywords.values()]);
    requireData([invoke(callback, name === 'JSON.stringify' ? [text, data] : [data])]);
    return text;
  }
  return null;
};

const callbackCall = (fn: Value, input: CallArguments, invoke: Invoke): Value | null => {
  if (fn.kind === 'method') {
    return methodCallback(fn, input, invoke);
  }
  return fn.kind === 'symbol' ? namedCallback(fn.name, input, invoke) : null;
};

export { callbackCall };
