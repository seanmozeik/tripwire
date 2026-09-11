import type { SyntaxNode } from '@lezer/common';
import { parser as javascript } from '@lezer/javascript';
import { parser as python } from '@lezer/python';

import type { CodeLanguage } from './types';

const typescript = javascript.configure({ dialect: 'ts' });
const MAX_SOURCE = 65_536;
const MAX_NODES = 12_000;
const MAX_DEPTH = 80;

class CodeInspectionError extends Error {
  override name = 'CodeInspectionError';
}

const failInspection = (message: string): never => {
  throw new CodeInspectionError(message);
};

const children = (node: SyntaxNode): SyntaxNode[] => {
  const result: SyntaxNode[] = [];
  for (let child = node.firstChild; child !== null; child = child.nextSibling) {
    result.push(child);
  }
  return result;
};

const parseCode = (language: CodeLanguage, source: string): SyntaxNode => {
  if (source.length > MAX_SOURCE) {
    throw new CodeInspectionError('Code exceeds the source size limit.');
  }
  const parser = { python, javascript, typescript }[language];
  const pending = parser.startParse(source);
  const deadline = performance.now() + 40;
  let tree = pending.advance();
  while (tree === null) {
    if (performance.now() > deadline) {
      throw new CodeInspectionError('Code exceeds the parsing time budget.');
    }
    tree = pending.advance();
  }
  let count = 0;
  const stack = [{ node: tree.topNode, depth: 0 }];
  while (stack.length > 0) {
    const item = stack.pop();
    if (item === undefined) {
      break;
    }
    count += 1;
    if (count > MAX_NODES || item.depth > MAX_DEPTH || performance.now() > deadline) {
      throw new CodeInspectionError('Code exceeds the tree inspection budget.');
    }
    if (item.node.type.isError) {
      throw new CodeInspectionError('Code contains invalid or incomplete syntax.');
    }
    for (const node of children(item.node)) {
      stack.push({ node, depth: item.depth + 1 });
    }
  }
  return tree.topNode;
};

// Decode only unambiguous plain literals. No eval, interpreter, or dynamic imports.
const stringLiteral = (text: string): string => {
  const [quote] = text;
  if (
    (quote !== '"' && quote !== "'") ||
    text.at(-1) !== quote ||
    text.startsWith(quote.repeat(3))
  ) {
    throw new CodeInspectionError('Unsupported string literal.');
  }
  const body = text.slice(1, -1);
  if (body.includes('\\')) {
    throw new CodeInspectionError('Escaped strings need explicit review.');
  }
  return body;
};

export { CodeInspectionError, children, failInspection, parseCode, stringLiteral };
