import type { SyntaxNode } from '@lezer/common';

import { failInspection } from './syntax';
import type { Value } from './types';

interface CallArguments {
  readonly positional: readonly Value[];
  readonly keywords: ReadonlyMap<string, Value>;
}
interface CallSignature {
  readonly parameters: readonly string[];
  readonly defaults?: Readonly<Record<string, Value>>;
  readonly options?: Readonly<Record<string, (value: Value) => void>>;
}
const addKeywords = (keywords: Map<string, Value>, entries: ReadonlyMap<string, Value>): void => {
  for (const [name, item] of entries) {
    if (keywords.has(name)) {
      return failInspection('Duplicate expanded keyword.');
    }
    keywords.set(name, item);
  }
};
const callArguments = (
  parts: readonly SyntaxNode[],
  evaluate: (node: SyntaxNode) => Value,
  source: string,
): CallArguments => {
  const positional: Value[] = [];
  const keywords = new Map<string, Value>();
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part === undefined) {
      return failInspection('Missing call argument.');
    }
    if (['*', 'Spread', '**'].includes(part.name)) {
      const next = parts[index + 1];
      if (next === undefined) {
        return failInspection('Missing expanded argument.');
      }
      const value = evaluate(next);
      if (part.name === '**' && value.kind === 'object' && value.opaque !== true) {
        addKeywords(keywords, value.entries);
      } else if (part.name !== '**' && value.kind === 'list' && value.opaque !== true) {
        positional.push(...value.items);
      } else {
        return failInspection('Expanded arguments must be statically bounded.');
      }
      index += 1;
    } else if (parts[index + 1]?.name === 'AssignOp') {
      const value = parts[index + 2];
      const name = source.slice(part.from, part.to);
      if (keywords.has(name) || value === undefined) {
        return failInspection('Duplicate or missing keyword argument.');
      }
      keywords.set(name, evaluate(value));
      index += 2;
    } else {
      if (keywords.size > 0) {
        return failInspection('A positional argument follows a keyword argument.');
      }
      positional.push(evaluate(part));
    }
  }
  return { positional, keywords };
};
const bindArguments = (input: CallArguments, signature?: CallSignature): readonly Value[] => {
  if (input.keywords.size === 0) {
    return input.positional;
  }
  if (signature === undefined) {
    return failInspection('Unsupported keyword argument.');
  }
  const values = new Map<number, Value>(input.positional.map((value, index) => [index, value]));
  for (const [name, value] of input.keywords) {
    const index = signature.parameters.indexOf(name);
    if (index === -1) {
      const validate = Object.hasOwn(signature.options ?? {}, name)
        ? signature.options?.[name]
        : undefined;
      if (validate === undefined) {
        return failInspection(`Unsupported keyword argument: ${name}.`);
      }
      validate(value);
    } else {
      if (values.has(index)) {
        return failInspection(`Duplicate argument: ${name}.`);
      }
      values.set(index, value);
    }
  }
  const args: Value[] = [];
  const end = Math.max(-1, ...values.keys());
  for (let index = 0; index <= end; index += 1) {
    const name = signature.parameters[index] ?? '';
    const fallback = Object.hasOwn(signature.defaults ?? {}, name)
      ? signature.defaults?.[name]
      : undefined;
    const value = values.get(index) ?? fallback;
    if (value === undefined) {
      return failInspection(`Missing argument: ${name}.`);
    }
    args.push(value);
  }
  return args;
};
export { bindArguments, callArguments };
export type { CallArguments, CallSignature };
