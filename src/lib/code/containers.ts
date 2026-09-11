import type { SyntaxNode } from '@lezer/common';

import { requireData } from './data';
import { children, failInspection } from './syntax';
import type { Value } from './types';

const objectValue = (
  node: SyntaxNode,
  evaluate: (node: SyntaxNode) => Value,
  text: (node: SyntaxNode) => string,
): Value => {
  const entries = new Map<string, Value>();
  for (const property of children(node).filter((part) => !['{', '}', ','].includes(part.name))) {
    const fields = children(property);
    const [key, separator, value] = fields;
    if (
      property.name !== 'Property' ||
      key?.name !== 'PropertyDefinition' ||
      separator?.name !== ':' ||
      value === undefined ||
      fields.length !== 3
    ) {
      return failInspection('Computed properties, accessors, and object spread are not inspected.');
    }
    entries.set(text(key), evaluate(value));
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
  for (const replacement of children(node)) {
    if (replacement.name !== 'FormatReplacement') {
      return failInspection('Unsupported formatted string component.');
    }
    const fields = children(replacement).filter((part) => !['{', '}'].includes(part.name));
    if (fields.length !== 1 || fields[0] === undefined) {
      return failInspection('Format conversions and specifications require review.');
    }
    requireData([evaluate(fields[0])]);
  }
  return { kind: 'text' };
};

const containerValue = (
  node: SyntaxNode,
  evaluate: (node: SyntaxNode) => Value,
  text: (node: SyntaxNode) => string,
): Value | null => {
  switch (node.name) {
    case 'ObjectExpression': {
      return objectValue(node, evaluate, text);
    }
    case 'DictionaryExpression': {
      return dictionaryValue(node, evaluate);
    }
    case 'FormatString': {
      return formatValue(node, evaluate);
    }
    default: {
      return null;
    }
  }
};

export { containerValue };
