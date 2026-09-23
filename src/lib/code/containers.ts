import type { SyntaxNode } from '@lezer/common';

import { requireData } from './data';
import { children, failInspection, stringLiteral } from './syntax';
import type { Value } from './types';

interface ObjectContext {
  readonly evaluate: (node: SyntaxNode) => Value;
  readonly text: (node: SyntaxNode) => string;
  readonly entries: Map<string, Value>;
}
const computedProperty = (fields: readonly SyntaxNode[], context: ObjectContext): boolean => {
  const [, key, close, separator, value] = fields;
  if (
    key === undefined ||
    close?.name !== ']' ||
    separator?.name !== ':' ||
    value === undefined ||
    fields.length !== 5
  ) {
    return failInspection('Incomplete computed property.');
  }
  const computed = context.evaluate(key);
  requireData([computed]);
  const item = context.evaluate(value);
  if (computed.kind === 'string' || computed.kind === 'number') {
    context.entries.set(String(computed.value), item);
    return false;
  }
  requireData([item]);
  return true;
};
const objectProperty = (property: SyntaxNode, context: ObjectContext): boolean => {
  const fields = children(property);
  const [key, separator, value] = fields;
  if (key?.name === 'Spread' && separator !== undefined && fields.length === 2) {
    requireData([context.evaluate(separator)]);
    return true;
  }
  if (key?.name === '[') {
    return computedProperty(fields, context);
  }
  if (fields.length === 1 && key?.name === 'PropertyDefinition') {
    context.entries.set(context.text(key), context.evaluate(key));
    return false;
  }
  if (
    property.name !== 'Property' ||
    key === undefined ||
    !['PropertyDefinition', 'String', 'Number'].includes(key.name) ||
    separator?.name !== ':' ||
    value === undefined ||
    fields.length !== 3
  ) {
    return failInspection('Accessors and executable object properties require inspection.');
  }
  const name = key.name === 'String' ? stringLiteral(context.text(key)) : context.text(key);
  if (name === '__proto__') {
    return failInspection('Prototype mutation requires inspection.');
  }
  context.entries.set(name, context.evaluate(value));
  return false;
};
const objectValue = (
  node: SyntaxNode,
  evaluate: (node: SyntaxNode) => Value,
  text: (node: SyntaxNode) => string,
): Value => {
  const entries = new Map<string, Value>();
  let spread = false;
  for (const property of children(node).filter((part) => !['{', '}', ','].includes(part.name))) {
    const opaque = objectProperty(property, { evaluate, text, entries });
    spread ||= opaque;
  }
  if (spread) {
    requireData([...entries.values()]);
    return { kind: 'data' };
  }
  return { kind: 'object', entries };
};

const dictionaryValue = (node: SyntaxNode, evaluate: (node: SyntaxNode) => Value): Value => {
  const parts = children(node).filter((part) => !['{', '}', ','].includes(part.name));
  const entries = new Map<string, Value>();
  for (let index = 0; index < parts.length; index += 3) {
    const [keyNode, separator, valueNode] = parts.slice(index, index + 3);
    if (keyNode === undefined || separator?.name !== ':' || valueNode === undefined) {
      return failInspection('Unsupported dictionary entry.');
    }
    const key = evaluate(keyNode);
    if (key.kind !== 'string') {
      return failInspection('Dictionary keys must be literal strings.');
    }
    entries.set(key.value, evaluate(valueNode));
  }
  return { kind: 'object', entries };
};

const formatValue = (node: SyntaxNode, evaluate: (node: SyntaxNode) => Value): Value => {
  for (const replacement of children(node).filter((part) => part.name !== 'Escape')) {
    if (replacement.name !== 'FormatReplacement') {
      return failInspection('Unsupported formatted string component.');
    }
    const fields = children(replacement).filter((part) => !['{', '}'].includes(part.name));
    if (fields[0] === undefined) {
      return failInspection('Format conversions and specifications require review.');
    }
    requireData([evaluate(fields[0])]);
    for (const spec of fields.slice(1)) {
      if (spec.name !== 'FormatSpec' && spec.name !== 'FormatConversion') {
        return failInspection('Unsupported format specifier.');
      }
      for (const nested of children(spec).filter((part) => part.name === 'FormatReplacement')) {
        for (const expression of children(nested).filter(
          (part) => !['{', '}'].includes(part.name),
        )) {
          requireData([evaluate(expression)]);
        }
      }
    }
  }
  return { kind: 'text' };
};

export { objectValue, dictionaryValue, formatValue };
