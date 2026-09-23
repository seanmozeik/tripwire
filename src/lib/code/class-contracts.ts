import type { SyntaxNode } from '@lezer/common';

import type { CallArguments } from './arguments';
import { data, requireData } from './data';
import { children, failInspection } from './syntax';
import type { Value } from './types';

interface BaseClassContract {
  readonly overrides: ReadonlySet<string>;
  readonly entries: ReadonlyMap<string, ReadonlySet<string>>;
}

const htmlHandlers = new Set([
  'handle_starttag',
  'handle_endtag',
  'handle_startendtag',
  'handle_data',
  'handle_entityref',
  'handle_charref',
  'handle_comment',
  'handle_decl',
  'handle_pi',
  'unknown_decl',
]);
const baseClasses: ReadonlyMap<string, BaseClassContract> = new Map([
  [
    'html.parser.HTMLParser',
    {
      overrides: htmlHandlers,
      entries: new Map([
        ['feed', htmlHandlers],
        ['close', htmlHandlers],
      ]),
    },
  ],
]);

const baseClassContract = (value: Value): BaseClassContract => {
  const contract = value.kind === 'symbol' ? baseClasses.get(value.name) : undefined;
  return contract ?? failInspection('Class inheritance can invoke uninspected hooks.');
};

interface ClassContext {
  readonly evaluate: (node: SyntaxNode) => Value;
  readonly closure: (node: SyntaxNode) => Value;
  readonly text: (node: SyntaxNode) => string;
}

const classContract = (
  parts: readonly SyntaxNode[],
  context: ClassContext,
): BaseClassContract | undefined => {
  const bases = parts.find((part) => part.name === 'ArgList');
  if (bases === undefined) {
    return undefined;
  }
  const values = children(bases).filter((part) => !['(', ')'].includes(part.name));
  const [base] = values;
  if (values.length !== 1 || base === undefined) {
    return failInspection('Class metaclasses and multiple inheritance require inspection.');
  }
  return baseClassContract(context.evaluate(base));
};

const defineClass = (
  parts: readonly SyntaxNode[],
  context: ClassContext,
): readonly [string, Value] => {
  const name = parts.find((part) => part.name === 'VariableName');
  const body = parts.find((part) => part.name === 'Body');
  if (name === undefined || body === undefined) {
    return failInspection('Class inheritance and metaclasses can invoke uninspected hooks.');
  }
  const contract = classContract(parts, context);
  const methods = new Map<string, Value>();
  for (const member of children(body).filter(
    (part) => ![':', 'PassStatement'].includes(part.name),
  )) {
    if (member.name !== 'FunctionDefinition') {
      return failInspection('Only plain class methods are inspected.');
    }
    const method = children(member).find((part) => part.name === 'VariableName');
    if (method === undefined) {
      return failInspection('Missing method name.');
    }
    const methodName = context.text(method);
    if (methodName.startsWith('__') && methodName !== '__init__') {
      return failInspection('Implicit class hooks require inspection at every implicit call site.');
    }
    if (contract !== undefined && !contract.overrides.has(methodName)) {
      return failInspection('Base-class subclasses may only override contracted handlers.');
    }
    methods.set(methodName, context.closure(member));
  }
  return [
    context.text(name),
    { kind: 'class', methods, ...(contract !== undefined && { contract }) },
  ];
};

const invokeContract = (
  receiver: Extract<Value, { kind: 'instance' }>,
  entry: string,
  args: CallArguments,
  callback: (fn: Value, args: readonly Value[]) => Value,
): Value => {
  requireData(args.positional);
  if (args.keywords.size > 0) {
    return failInspection('Uninspected base-class entry options.');
  }
  const handlers = receiver.contract?.entries.get(entry);
  if (handlers === undefined) {
    return failInspection('Unresolved base-class entry method.');
  }
  const forget = (): void => {
    for (const key of receiver.entries.keys()) {
      receiver.entries.set(key, data);
    }
  };
  forget();
  try {
    for (const [name, method] of receiver.methods) {
      if (handlers.has(name)) {
        if (method.kind !== 'closure') {
          return failInspection('Unresolved base-class handler.');
        }
        callback(method, [receiver, ...method.parameters.slice(1).map(() => data)]);
      }
    }
  } finally {
    forget();
  }
  return data;
};

export { defineClass, invokeContract };
export type { BaseClassContract };
