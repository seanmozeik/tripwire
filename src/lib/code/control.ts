import type { SyntaxNode } from '@lezer/common';

import { data, isData, requireData } from './data';
import type { Scope, ScopeSnapshot } from './scope';
import { children, failInspection } from './syntax';
import type { Value } from './types';
import { unknown } from './values';

interface ControlContext {
  readonly bindings: Scope;
  readonly repeat: (visit: () => void) => void;
  readonly snapshot: () => ScopeSnapshot;
  readonly restore: (snapshot: ScopeSnapshot) => void;
  readonly join: (states: readonly ScopeSnapshot[]) => void;
  readonly text: (node: SyntaxNode) => string;
  readonly evaluate: (node: SyntaxNode) => Value;
  readonly statement: (node: SyntaxNode) => void;
}

const inspectBranches = (node: SyntaxNode, context: ControlContext): void => {
  let before = context.snapshot();
  const states: ScopeSnapshot[] = [before];
  for (const part of children(node).filter(
    (child) => !['if', 'elif', 'else', '(', ')'].includes(child.name),
  )) {
    context.restore(before);
    if (part.name === 'Body' || part.name === 'Block' || part.name.endsWith('Statement')) {
      context.statement(part);
      states.push(context.snapshot());
    } else {
      requireData([context.evaluate(part)]);
      before = context.snapshot();
      states.push(before);
    }
  }
  context.join(states);
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
      'UpdateStatement',
      'AssignmentExpression',
      'UpdateExpression',
    ].includes(node.name)
  ) {
    const end = parts.findIndex((part) => ['AssignOp', 'Equals', 'in'].includes(part.name));
    for (const part of end === -1 ? parts : parts.slice(0, end)) {
      if (part.name === 'VariableName' || part.name === 'VariableDefinition') {
        const previous = context.bindings.get(context.text(part));
        context.bindings.assign(
          context.text(part),
          previous !== undefined && isData(previous) ? data : unknown,
        );
      }
    }
  }
  if (node.name === 'CallExpression' || node.name === 'MemberExpression') {
    for (const part of parts) {
      if (part.name === 'VariableName') {
        const value = context.bindings.get(context.text(part));
        if (value?.kind === 'list' || value?.kind === 'object') {
          value.opaque = true;
        }
      }
    }
  }
  for (const part of parts) {
    forgetLoopWrites(part, context);
  }
};

const bindTarget = (target: SyntaxNode, value: Value, context: ControlContext): void => {
  if (target.name === 'ArrayPattern') {
    if (
      children(target).some((part) => !['[', ']', ',', 'VariableDefinition'].includes(part.name))
    ) {
      return failInspection('Destructuring defaults or nested patterns are not inspected.');
    }
    const names = children(target).filter((part) => part.name === 'VariableDefinition');
    for (const [index, name] of names.entries()) {
      context.bindings.set(
        context.text(name),
        value.kind === 'list' ? (value.items[index] ?? data) : data,
      );
    }
  } else {
    context.bindings.set(context.text(target), value);
  }
};

const containerMutated = (value: Extract<Value, { kind: 'list' }>): boolean =>
  value.opaque === true;

const iterate = (
  target: SyntaxNode | undefined,
  input: SyntaxNode | undefined,
  context: ControlContext,
  visit: () => void,
  body?: SyntaxNode,
): void => {
  if (
    target === undefined ||
    !['VariableName', 'VariableDefinition', 'ArrayPattern'].includes(target.name) ||
    input === undefined
  ) {
    return failInspection('Only simple iteration bindings are inspected.');
  }
  const iterable = context.evaluate(input);
  let values: readonly Value[];
  if (iterable.kind === 'list' && iterable.opaque !== true) {
    values = iterable.items;
  } else if (['data', 'text', 'list', 'object'].includes(iterable.kind)) {
    values = [data];
  } else {
    return failInspection('Iteration needs bounded literals or inert JSON data.');
  }
  if (values.length > 128) {
    return failInspection('Iteration needs bounded literals or inert JSON data.');
  }
  const before = context.snapshot();
  const states: ScopeSnapshot[] = [before];
  if ((iterable.kind !== 'list' || iterable.opaque === true) && body !== undefined) {
    forgetLoopWrites(body, context);
  }
  // Empty bodies are also checked; unreachable syntax cannot hide operations.
  for (const value of values.length === 0 ? [unknown] : values) {
    bindTarget(target, value, context);
    if (iterable.kind === 'list' && iterable.opaque !== true) {
      visit();
      if (containerMutated(iterable)) {
        failInspection('Mutation of an iterated container changes the iteration bounds.');
      }
    } else {
      context.repeat(visit);
    }
    states.push(context.snapshot());
  }
  context.join(states);
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
  if (index < 2 || body?.name !== 'Body') {
    return failInspection('Unsupported loop shape.');
  }
  iterate(
    parts[index - 1],
    parts[index + 1],
    context,
    () => {
      for (const target of parts.slice(1, index).filter((part) => part.name === 'VariableName')) {
        if (index > 2) {
          context.bindings.set(context.text(target), data);
        }
      }
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
  const before = context.snapshot();
  iterate(parts[index + 1], parts[index + 3], context, () => {
    if (parts.length === 7) {
      const [, candidate] = parts.slice(5);
      const condition = candidate ?? failInspection('Missing comprehension filter.');
      if (parts[5]?.name !== 'if') {
        failInspection('Unsupported comprehension filter.');
      }
      requireData([context.evaluate(condition)]);
      const [left, operator, right] = children(condition);
      const target = parts[index + 1];
      if (
        condition.name === 'BinaryExpression' &&
        left?.name === 'VariableName' &&
        operator !== undefined &&
        context.text(operator) === 'in' &&
        right !== undefined &&
        target !== undefined &&
        context.text(left) === context.text(target)
      ) {
        const allowed = context.evaluate(right);
        if (
          allowed.kind === 'list' &&
          allowed.items.length > 0 &&
          allowed.items.length <= 128 &&
          allowed.items.every((value) => value.kind === 'string')
        ) {
          const name = context.text(target);
          const previous = context.bindings.get(name) ?? unknown;
          for (const value of allowed.items) {
            context.bindings.set(name, value);
            requireData([context.evaluate(expression)]);
          }
          context.bindings.set(name, previous);
          return;
        }
      }
    }
    requireData([context.evaluate(expression)]);
  });
  context.restore(before);
  return data;
};

export { forgetLoopWrites, inspectBranches, inspectComprehension, inspectLoop };
export type { ControlContext };
