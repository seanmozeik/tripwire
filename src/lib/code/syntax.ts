import { cpuUsage } from 'node:process';

import type { SyntaxNode } from '@lezer/common';
import { parser as javascript } from '@lezer/javascript';
import { parser as python } from '@lezer/python';

import type { CodeLanguage } from './types';

const parsers = { python, javascript, typescript: javascript.configure({ dialect: 'ts' }) };
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

const syntaxError = (language: CodeLanguage, source: string, offset: number): never => {
  const preceding = source.slice(0, offset);
  const line = preceding.split('\n').length;
  const column = offset - preceding.lastIndexOf('\n');
  const excerpt = source.slice(Math.max(0, offset - 16), offset + 32);
  const literalNewline = excerpt.includes(String.raw`\n`)
    ? String.raw` In single shell quotes, \n is two characters, not a newline; use a heredoc.`
    : '';
  return failInspection(
    `${language} syntax error at line ${line}, column ${column}: ${JSON.stringify(excerpt)}.${literalNewline}`,
  );
};

const parseCode = (language: CodeLanguage, source: string): SyntaxNode => {
  if (source.length > MAX_SOURCE) {
    throw new CodeInspectionError('Code exceeds the source size limit.');
  }
  const parser = parsers[language];
  const pending = parser.startParse(source);
  // Charge parser work, not time spent descheduled on a busy host.
  const started = cpuUsage();
  const overBudget = (): boolean => {
    const elapsed = cpuUsage(started);
    return elapsed.user + elapsed.system > 40_000;
  };
  let tree = pending.advance();
  while (tree === null) {
    if (overBudget()) {
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
    if (count > MAX_NODES || item.depth > MAX_DEPTH || overBudget()) {
      throw new CodeInspectionError('Code exceeds the tree inspection budget.');
    }
    if (item.node.type.isError) {
      syntaxError(language, source, item.node.from);
    }
    for (const node of children(item.node).toReversed()) {
      stack.push({ node, depth: item.depth + 1 });
    }
  }
  return tree.topNode;
};

// Decode only unambiguous plain literals. No eval, interpreter, or dynamic imports.
const stringLiteral = (text: string, language: CodeLanguage = 'javascript'): string => {
  const raw = language === 'python' && /^[rR]["']/u.test(text);
  const literal = raw ? text.slice(1) : text;
  const [quote] = literal;
  if (quote !== '"' && quote !== "'") {
    throw new CodeInspectionError('Unsupported string literal.');
  }
  const delimiter =
    language === 'python' && literal.startsWith(quote.repeat(3)) ? quote.repeat(3) : quote;
  if (!literal.endsWith(delimiter)) {
    return failInspection('Incomplete string literal.');
  }
  const body = literal.slice(delimiter.length, -delimiter.length);
  return raw ? body : decodeEscapes(body);
};

const decodeEscapes = (body: string): string => {
  const simple: Readonly<Record<string, string>> = {
    n: '\n',
    r: '\r',
    t: '\t',
    b: '\b',
    f: '\f',
    v: '\v',
    '\\': '\\',
    "'": "'",
    '"': '"',
  };
  let result = '';
  for (let index = 0; index < body.length; index += 1) {
    const char = body[index];
    if (char === '\\') {
      index += 1;
      const escaped = body[index];
      if (escaped === undefined) {
        return failInspection('Incomplete escape.');
      }
      if (simple[escaped] !== undefined) {
        result += simple[escaped];
      } else if (escaped === 'x' || escaped === 'u') {
        const count = escaped === 'x' ? 2 : 4;
        const digits = body.slice(index + 1, index + 1 + count);
        if (digits.length !== count || !/^[0-9a-f]+$/iu.test(digits)) {
          return failInspection('Unsupported Unicode escape.');
        }
        result += String.fromCodePoint(Number.parseInt(digits, 16));
        index += count;
      } else {
        return failInspection('Unsupported string escape.');
      }
    } else {
      result += char;
    }
  }
  return result;
};

export { CodeInspectionError, children, failInspection, parseCode, stringLiteral };
