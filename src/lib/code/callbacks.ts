import type { CallArguments } from './arguments';
import { data, requireData, text } from './data';
import { failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';

const containerMutated = (value: Extract<Value, { kind: 'list' }>): boolean =>
  value.opaque === true;

type Invoke = (fn: Value, args: readonly Value[], repeated?: boolean) => Value;

// Precise receivers execute in source order. Mutation invalidates the shared
// container object, including through aliases, before another item is trusted.
const literalCallbacks = (
  receiver: Value,
  callback: Value,
  invoke: Invoke,
  reducer = false,
  initial?: Value,
): Value | null => {
  if (receiver.kind !== 'list' || receiver.opaque === true) {
    return null;
  }
  if (receiver.items.length > 128) {
    return failInspection('Callback exceeds the bounded iteration limit.');
  }
  let accumulator = initial ?? receiver.items[0] ?? data;
  const start = reducer && initial === undefined ? 1 : 0;
  const items = receiver.items.length === 0 ? [data] : receiver.items;
  for (let index = start; index < items.length; index += 1) {
    const item = items[index] ?? data;
    const position: Value = { kind: 'number', value: index };
    accumulator = invoke(
      callback,
      reducer ? [accumulator, item, position, receiver] : [item, position, receiver],
      false,
    );
    requireData([accumulator]);
    if (containerMutated(receiver)) {
      return failInspection('Mutation of a callback receiver changes the iteration bounds.');
    }
  }
  return reducer ? accumulator : data;
};

const replacementCallback = (
  fn: Extract<Value, { kind: 'method' }>,
  input: CallArguments,
  invoke: Invoke,
): Value | null => {
  if (
    ['replace', 'replaceAll', 'sub', 'subn'].includes(fn.name) &&
    input.positional.some((value) => value.kind === 'closure')
  ) {
    requireData([fn.receiver]);
    const index = ['sub', 'subn'].includes(fn.name) ? 0 : 1;
    const callback = input.positional[index];
    requireData(input.positional.filter((_, position) => position !== index));
    requireData([...input.keywords.values()]);
    if (callback?.kind !== 'closure') {
      return failInspection('Unresolved replacement callback.');
    }
    requireData([invoke(callback, [data])]);
    return fn.name === 'subn' ? data : text;
  }
  return null;
};

const methodCallback = (
  fn: Extract<Value, { kind: 'method' }>,
  input: CallArguments,
  invoke: Invoke,
  language: CodeLanguage,
): Value | null => {
  const replacement = replacementCallback(fn, input, invoke);
  if (replacement !== null) {
    return replacement;
  }
  if (
    !['map', 'filter', 'forEach', 'some', 'every', 'find', 'flatMap', 'reduce', 'sort'].includes(
      fn.name,
    )
  ) {
    return null;
  }
  if (fn.name === 'find' && language === 'python') {
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
  if (fn.name !== 'sort') {
    const literal = literalCallbacks(fn.receiver, callback, invoke, fn.name === 'reduce', rest[0]);
    if (literal !== null) {
      return literal;
    }
  }
  const result = invoke(
    callback,
    fn.name === 'reduce' || (fn.name === 'sort' && !input.keywords.has('key'))
      ? [data, data]
      : [data],
  );
  requireData([result]);
  return data;
};

const scheduledCallback = (name: string, input: CallArguments, invoke: Invoke): Value | null => {
  const args = input.positional;
  if (['process.once', 'process.on', 'setInterval', 'setTimeout', 'asyncio.run'].includes(name)) {
    const index = name.startsWith('process.') ? 1 : 0;
    const callback = args[index];
    requireData(args.filter((_, position) => position !== index));
    if (callback?.kind !== 'closure' || input.keywords.size > 0) {
      return failInspection('Scheduling requires an inspected closure.');
    }
    requireData([invoke(callback, [])]);
    return data;
  }
  return null;
};

const pythonLiteralCallback = (
  name: string,
  input: CallArguments,
  invoke: Invoke,
): Value | null => {
  const args = input.positional;
  if (name === 'map' || name === 'filter') {
    const [callback, receiver] = args;
    if (
      args.length !== 2 ||
      input.keywords.size !== 0 ||
      callback === undefined ||
      receiver === undefined
    ) {
      return failInspection('Mapping requires one inspected iterable and callback.');
    }
    requireData([receiver]);
    const literal = literalCallbacks(receiver, callback, (fn, values, repeated) =>
      invoke(fn, values.slice(0, 1), repeated),
    );
    if (literal === null) {
      requireData([invoke(callback, [data])]);
    }
    return data;
  }
  if (name === 'sorted' && input.keywords.has('key')) {
    const callback = input.keywords.get('key');
    requireData(args);
    for (const [key, value] of input.keywords) {
      if (key !== 'key') {
        requireData([value]);
      }
    }
    if (callback !== undefined) {
      const literal = literalCallbacks(args[0] ?? data, callback, (fn, values, repeated) =>
        invoke(fn, values.slice(0, 1), repeated),
      );
      if (literal === null) {
        requireData([invoke(callback, [data])]);
      }
    }
    return data;
  }
  return null;
};

const namedCallback = (name: string, input: CallArguments, invoke: Invoke): Value | null => {
  const args = input.positional;
  const scheduled = scheduledCallback(name, input, invoke);
  if (scheduled !== null) {
    return scheduled;
  }
  const literal = pythonLiteralCallback(name, input, invoke);
  if (literal !== null) {
    return literal;
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

const groupBy = (input: CallArguments, invoke: Invoke): Value => {
  const args = input.positional;
  const [items, callback] = args;
  if (
    args.length !== 2 ||
    input.keywords.size > 0 ||
    items === undefined ||
    callback === undefined
  ) {
    return failInspection('Grouping requires inspected data and a callback.');
  }
  requireData([items, invoke(callback, [data, data])]);
  return data;
};

const callbackCall = (
  fn: Value,
  input: CallArguments,
  invoke: Invoke,
  language: CodeLanguage,
): Value | null => {
  if (fn.kind === 'method') {
    return methodCallback(fn, input, invoke, language);
  }
  if (fn.kind === 'symbol' && fn.name === 'Map.groupBy') {
    return groupBy(input, invoke);
  }
  return fn.kind === 'symbol' ? namedCallback(fn.name, input, invoke) : null;
};

export { callbackCall };
