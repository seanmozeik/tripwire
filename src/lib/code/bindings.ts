import type { SyntaxNode } from '@lezer/common';

import { data, requireData } from './data';
import { indexedValue, namedMember } from './members';
import { children, failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';

interface BindingContext {
  readonly language: CodeLanguage;
  readonly text: (node: SyntaxNode) => string;
  readonly evaluate: (node: SyntaxNode) => Value;
  readonly set: (name: string, value: Value) => void;
}

const bindArrayPattern = (node: SyntaxNode, value: Value, context: BindingContext): void => {
  const parts = children(node).slice(1, -1);
  let position = 0;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part?.name === ',') {
      position += 1;
    } else if (part !== undefined) {
      if (part.name === 'Spread') {
        const target = parts[index + 1];
        if (target === undefined) {
          return failInspection('Missing rest binding.');
        }
        requireData([value]);
        bindPattern(
          target,
          value.kind === 'list' && value.opaque !== true
            ? { kind: 'list', items: value.items.slice(position) }
            : data,
          context,
        );
        return;
      }
      let item = indexedValue(value, { kind: 'number', value: position });
      if (parts[index + 1]?.name === 'Equals') {
        const fallback = parts[index + 2];
        if (fallback === undefined) {
          return failInspection('Missing binding default.');
        }
        const alternative = context.evaluate(fallback);
        requireData([item, alternative]);
        item = data;
        index += 2;
      }
      bindPattern(part, item, context);
    }
  }
};

const bindPattern = (node: SyntaxNode, value: Value, context: BindingContext): void => {
  if (['VariableName', 'VariableDefinition', 'PropertyName'].includes(node.name)) {
    context.set(context.text(node), value);
    return;
  }
  if (node.name === 'ArrayPattern') {
    bindArrayPattern(node, value, context);
    return;
  }
  if (node.name === 'ObjectPattern') {
    for (const property of children(node).filter((part) => !['{', '}', ','].includes(part.name))) {
      const [key, separator, target] = children(property);
      if (key?.name !== 'PropertyName') {
        return failInspection('Computed binding requires a literal key.');
      }
      const member = namedMember(value, context.text(key), context.language);
      if (separator === undefined) {
        bindPattern(key, member, context);
      } else if (separator.name === ':' && target !== undefined) {
        bindPattern(target, member, context);
      } else {
        return failInspection('Object binding defaults require inspection.');
      }
    }
    return;
  }
  return failInspection('Unsupported binding pattern.');
};

export { bindPattern };
