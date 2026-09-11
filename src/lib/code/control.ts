import type { SyntaxNode } from '@lezer/common';

import { data, requireData } from './data';
import { children, failInspection } from './syntax';
import type { Value } from './types';
import { unknown } from './values';

interface ControlContext {
  readonly bindings: Map<string, Value>;
  readonly text: (node: SyntaxNode) => string;
  readonly evaluate: (node: SyntaxNode) => Value;
  readonly statement: (node: SyntaxNode) => void;
}

const restore = (target: Map<string, Value>, source: ReadonlyMap<string, Value>): void => {
  target.clear();
  for (const [key, value] of source) {
    target.set(key, value);
  }
};

const join = (target: Map<string, Value>, states: readonly ReadonlyMap<string, Value>[]): void => {
  const names = new Set(states.flatMap((state) => [...state.keys()]));
  target.clear();
  for (const name of names) {
    const value = states[0]?.get(name);
    target.set(
      name,
      value !== undefined && states.every((state) => state.get(name) === value) ? value : unknown,
    );
  }
};

const inspectBranches = (node: SyntaxNode, context: ControlContext): void => {
  const before = new Map(context.bindings);
  const states: Map<string, Value>[] = [before];
  for (const part of children(node).filter(
    (child) => !['if', 'elif', 'else', '(', ')'].includes(child.name),
  )) {
    restore(context.bindings, before);
    if (part.name === 'Body' || part.name === 'Block') {
      context.statement(part);
      states.push(new Map(context.bindings));
    } else {
      requireData([context.evaluate(part)]);
    }
  }
  join(context.bindings, states);
};

// For unknown iteration counts, forget every binding written in the body before
// checking it. This prevents an alias changed late in one iteration being used
// as its old safe value in a later iteration.
const forgetLoopWrites = (node: SyntaxNode, context: ControlContext): void => {
  const parts = children(node);
  if (
    [
      'AssignStatement',
      'ImportStatement',
      'ForStatement',
      'VariableDeclaration',
      'WithStatement',
    ].includes(node.name)
  ) {
    const end = parts.findIndex((part) => ['AssignOp', 'Equals', 'in'].includes(part.name));
    for (const part of end === -1 ? parts : parts.slice(0, end)) {
      if (part.name === 'VariableName' || part.name === 'VariableDefinition') {
        context.bindings.set(context.text(part), unknown);
      }
    }
  }
  for (const part of parts) {
    forgetLoopWrites(part, context);
  }
};

const iterate = (
  target: SyntaxNode | undefined,
  input: SyntaxNode | undefined,
  context: ControlContext,
  visit: () => void,
  body?: SyntaxNode,
): void => {
  if (
    target === undefined ||
    !['VariableName', 'VariableDefinition'].includes(target.name) ||
    input === undefined
  ) {
    return failInspection('Only simple iteration bindings are inspected.');
  }
  const iterable = context.evaluate(input);
  let values: readonly Value[];
  if (iterable.kind === 'list') {
    values = iterable.items;
  } else if (iterable.kind === 'data') {
    values = [data];
  } else {
    return failInspection('Iteration needs bounded literals or inert JSON data.');
  }
  if (values.length > 128) {
    return failInspection('Iteration needs bounded literals or inert JSON data.');
  }
  const before = new Map(context.bindings);
  const states: Map<string, Value>[] = [before];
  if (iterable.kind === 'data' && body !== undefined) {
    forgetLoopWrites(body, context);
  }
  // Empty bodies are also checked; unreachable syntax cannot hide operations.
  for (const value of values.length === 0 ? [unknown] : values) {
    context.bindings.set(context.text(target), value);
    visit();
    states.push(new Map(context.bindings));
  }
  join(context.bindings, states);
};

const inspectLoop = (node: SyntaxNode, context: ControlContext): void => {
  const parts = children(node);
  const spec = parts.find((part) => part.name === 'ForOfSpec');
  if (spec !== undefined) {
    const fields = children(spec);
    const [, declaration, target, operator, input] = fields;
    const block = parts.at(2);
    if (
      fields.length !== 6 ||
      !['const', 'let'].includes(declaration?.name ?? '') ||
      operator?.name !== 'of' ||
      block?.name !== 'Block'
    ) {
      return failInspection('Unsupported JavaScript iteration form.');
    }
    iterate(
      target,
      input,
      context,
      () => {
        context.statement(block);
      },
      block,
    );
    return;
  }
  const index = parts.findIndex((part) => part.name === 'in');
  const body = parts[index + 2];
  if (index !== 2 || body?.name !== 'Body' || parts.length !== 5) {
    return failInspection('Unsupported loop shape.');
  }
  iterate(
    parts[index - 1],
    parts[index + 1],
    context,
    () => {
      context.statement(body);
    },
    body,
  );
};

const inspectComprehension = (parts: readonly SyntaxNode[], context: ControlContext): Value => {
  const index = parts.findIndex((part) => part.name === 'for');
  const expression = parts[index - 1];
  if (
    index !== 1 ||
    expression === undefined ||
    parts[index + 2]?.name !== 'in' ||
    ![5, 7].includes(parts.length)
  ) {
    return failInspection('Only single-generator comprehensions are inspected.');
  }
  const before = new Map(context.bindings);
  iterate(parts[index + 1], parts[index + 3], context, () => {
    if (parts.length === 7) {
      const [, candidate] = parts.slice(5);
      const condition = candidate ?? failInspection('Missing comprehension filter.');
      if (parts[5]?.name !== 'if') {
        failInspection('Unsupported comprehension filter.');
      }
      requireData([context.evaluate(condition)]);
    }
    requireData([context.evaluate(expression)]);
  });
  restore(context.bindings, before);
  return data;
};

export { inspectBranches, inspectComprehension, inspectLoop };
export type { ControlContext };
