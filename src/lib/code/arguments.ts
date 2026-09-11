import type { SyntaxNode } from '@lezer/common';

import { failInspection } from './syntax';
import type { Value } from './types';
import { valueString } from './values';

const acceptsEncoding = (fn: Value): boolean =>
  (fn.kind === 'symbol' && fn.name === 'open') ||
  (fn.kind === 'method' &&
    fn.receiver.kind === 'path' &&
    ['read_text', 'write_text'].includes(fn.name));

const validateKeyword = (fn: Value, name: string, value: Value): void => {
  if (name === 'encoding' && acceptsEncoding(fn)) {
    const encoding = valueString(value).toLowerCase().replaceAll(/[-_]/gu, '');
    if (
      [
        'utf8',
        'utf16',
        'utf16le',
        'utf16be',
        'utf32',
        'utf32le',
        'utf32be',
        'ascii',
        'latin1',
      ].includes(encoding)
    ) {
      return;
    }
    return failInspection('Custom Python codecs require review.');
  }
  if (
    name === 'indent' &&
    fn.kind === 'symbol' &&
    ['json.dump', 'json.dumps'].includes(fn.name) &&
    ['number', 'string'].includes(value.kind)
  ) {
    return;
  }
  return failInspection('Unsupported keyword argument.');
};

// Only supported keywords are consumed. Python codecs can run user code, so
// a custom encoding cannot be treated as an inert string option.
const callArguments = (
  parts: readonly SyntaxNode[],
  fn: Value,
  evaluate: (node: SyntaxNode) => Value,
  source: string,
): readonly Value[] => {
  const args: Value[] = [];
  let keywordSeen = false;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (part === undefined) {
      return failInspection('Missing call argument.');
    }
    if (parts[index + 1]?.name === 'AssignOp') {
      const value = parts[index + 2];
      if (keywordSeen || value === undefined) {
        return failInspection('Unsupported keyword argument.');
      }
      validateKeyword(fn, source.slice(part.from, part.to), evaluate(value));
      keywordSeen = true;
      index += 2;
    } else {
      if (keywordSeen) {
        return failInspection('A positional argument follows a keyword argument.');
      }
      args.push(evaluate(part));
    }
  }
  return args;
};

export { callArguments };
