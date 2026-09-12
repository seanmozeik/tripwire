import type { SyntaxNode } from '@lezer/common';

import { callArguments } from './arguments';
import { resolveCall } from './calls';
import { containerValue } from './containers';
import { inspectBranches, inspectComprehension, inspectLoop, type ControlContext } from './control';
import { data, isData, requireData } from './data';
import { javascriptImport, pythonImport } from './imports';
import { indexedValue, namedMember } from './members';
import { CodeInspectionError, children, failInspection, parseCode, stringLiteral } from './syntax';
import type { CodeLanguage, CodeOperation, CodeReport, Value } from './types';
import { initialBindings, pythonJoin, symbol, textValue, valueString } from './values';

const IGNORE = new Set(['Comment', 'LineComment', 'BlockComment', ';']);

class CodeAnalyzer {
  readonly operations: CodeOperation[] = [];
  readonly #bindings: Map<string, Value>;
  readonly #source: string;
  readonly #language: CodeLanguage;
  #evaluatedBytes = 0;
  #steps = 0;

  constructor(source: string, language: CodeLanguage) {
    this.#source = source;
    this.#language = language;
    this.#bindings = initialBindings(language);
  }

  #text(node: SyntaxNode): string {
    return this.#source.slice(node.from, node.to);
  }

  inspect(root: SyntaxNode): void {
    for (const node of children(root)) {
      this.#statement(node);
    }
  }

  #statement(node: SyntaxNode): void {
    this.#step();
    if (IGNORE.has(node.name)) {
      return;
    }
    const parts = children(node).filter((part) => !IGNORE.has(part.name));
    switch (node.name) {
      case 'Body':
      case 'Block':
      case 'StatementGroup': {
        for (const part of parts) {
          if (![':', '{', '}'].includes(part.name)) {
            this.#statement(part);
          }
        }
        return;
      }
      case 'ExpressionStatement': {
        for (const part of parts) {
          this.#eval(part);
        }
        return;
      }
      case 'AssignStatement':
      case 'VariableDeclaration': {
        this.#assign(parts);
        return;
      }
      case 'ImportStatement':
      case 'ImportDeclaration': {
        const text = (part: SyntaxNode): string => this.#text(part);
        const bindings =
          node.name === 'ImportStatement'
            ? pythonImport(parts, text)
            : javascriptImport(parts, text, this.#language);
        for (const [name, value] of bindings) {
          this.#bindings.set(name, value);
        }
        return;
      }
      case 'ForStatement': {
        inspectLoop(node, this.#control());
        return;
      }
      case 'IfStatement': {
        inspectBranches(node, this.#control());
        return;
      }
      case 'AssertStatement': {
        requireData(
          parts
            .filter((part) => !['assert', ','].includes(part.name))
            .map((part) => this.#eval(part)),
        );
        return;
      }
      case 'WithStatement': {
        this.#withFile(parts);
        return;
      }
      default: {
        failInspection(`Unsupported executable syntax: ${node.name}.`);
      }
    }
  }

  #assign(parts: readonly SyntaxNode[]): void {
    const equals = parts.findIndex((part) => part.name === 'AssignOp' || part.name === 'Equals');
    const target = parts.find((part) =>
      ['VariableName', 'VariableDefinition', 'ObjectPattern'].includes(part.name),
    );
    const operator = parts[equals];
    const expression = parts[equals + 1];
    if (
      operator === undefined ||
      target === undefined ||
      expression === undefined ||
      parts.length !== equals + 2
    ) {
      return failInspection('Unsupported binding or assignment.');
    }
    if (this.#text(operator) !== '=') {
      return failInspection('Compound assignment is not inspected.');
    }
    if (
      parts
        .slice(0, equals)
        .some((part) => ['MemberExpression', 'ArrayPattern'].includes(part.name))
    ) {
      return failInspection('Destructuring or object mutation is not inspected.');
    }
    const value = this.#eval(expression);
    if (target.name === 'ObjectPattern') {
      this.#destructure(target, value);
    } else {
      this.#bindings.set(this.#text(target), value);
    }
  }

  #withFile(parts: readonly SyntaxNode[]): void {
    const [, expression, alias, target, body] = parts;
    if (
      parts.length !== 5 ||
      expression === undefined ||
      alias?.name !== 'as' ||
      target?.name !== 'VariableName' ||
      body?.name !== 'Body'
    ) {
      return failInspection('Only a single known file context is inspected.');
    }
    const value = this.#eval(expression);
    if (value.kind !== 'file' && value.kind !== 'archive') {
      return failInspection('Context manager callbacks require review.');
    }
    this.#bindings.set(this.#text(target), value);
    this.#statement(body);
  }

  #destructure(pattern: SyntaxNode, value: Value): void {
    if (value.kind !== 'symbol') {
      return failInspection('Only named module members can be destructured.');
    }
    for (const property of children(pattern).filter(
      (part) => !['{', '}', ','].includes(part.name),
    )) {
      const fields = children(property);
      const [name, separator, alias] = fields;
      if (property.name !== 'PatternProperty' || name?.name !== 'PropertyName') {
        return failInspection('Computed or rest destructuring is not inspected.');
      }
      if (fields.length === 1) {
        this.#bindings.set(this.#text(name), symbol(`${value.name}.${this.#text(name)}`));
      } else if (
        fields.length === 3 &&
        separator?.name === ':' &&
        alias?.name === 'VariableDefinition'
      ) {
        this.#bindings.set(this.#text(alias), symbol(`${value.name}.${this.#text(name)}`));
      } else {
        return failInspection('Destructuring defaults are not inspected.');
      }
    }
  }

  #eval(node: SyntaxNode): Value {
    this.#step();
    const value = this.#expression(node);
    if (value.kind === 'string') {
      this.#evaluatedBytes += value.value.length;
    }
    if (value.kind === 'path' || value.kind === 'file') {
      this.#evaluatedBytes += value.path.length;
    }
    if (this.#evaluatedBytes > 1_048_576) {
      return failInspection('Code exceeds the resolved value budget.');
    }
    return value;
  }

  #step(): void {
    this.#steps += 1;
    if (this.#steps > 12_000) {
      failInspection('Code exceeds the evaluation step budget.');
    }
  }

  #control(): ControlContext {
    return {
      bindings: this.#bindings,
      text: (node) => this.#text(node),
      evaluate: (node) => this.#eval(node),
      statement: (node) => {
        this.#statement(node);
      },
    };
  }

  #expression(node: SyntaxNode): Value {
    const container = containerValue(
      node,
      (part) => this.#eval(part),
      (part) => this.#text(part),
    );
    if (container !== null) {
      return container;
    }
    switch (node.name) {
      case 'String': {
        return textValue(stringLiteral(this.#text(node), this.#language));
      }
      case 'Number': {
        return { kind: 'number', value: Number(this.#text(node)) };
      }
      case 'Boolean':
      case 'BooleanLiteral':
      case 'None':
      case 'Null': {
        return data;
      }
      case 'VariableName': {
        return (
          this.#bindings.get(this.#text(node)) ??
          failInspection('Unresolved variable or persistent runtime state.')
        );
      }
      case 'ParenthesizedExpression':
      case 'AwaitExpression': {
        const expression = children(node).find((part) => !['(', ')', 'await'].includes(part.name));
        return expression === undefined
          ? failInspection('Missing expression.')
          : this.#eval(expression);
      }
      case 'ArrayExpression':
      case 'Array':
      case 'TupleExpression': {
        return {
          kind: 'list',
          items: children(node)
            .filter((part) => !['[', ']', '(', ')', ','].includes(part.name))
            .map((part) => this.#eval(part)),
        };
      }
      case 'ArrayComprehensionExpression': {
        return inspectComprehension(
          children(node).filter((part) => !['[', ']'].includes(part.name)),
          this.#control(),
        );
      }
      case 'BinaryExpression': {
        return this.#binary(node);
      }
      case 'MemberExpression': {
        return this.#member(node);
      }
      case 'CallExpression': {
        return this.#call(node);
      }
      default: {
        return failInspection(`Unsupported expression: ${node.name}.`);
      }
    }
  }

  #binary(node: SyntaxNode): Value {
    const [left, op, right] = children(node);
    if (left === undefined || op === undefined || right === undefined) {
      return failInspection('Incomplete binary expression.');
    }
    const a = this.#eval(left);
    const b = this.#eval(right);
    const operator = this.#text(op);
    if (a.kind === 'string' && b.kind === 'string' && operator === '+') {
      return textValue(a.value + b.value);
    }
    if (a.kind === 'path' && operator === '/') {
      return { kind: 'path', path: pythonJoin([a.path, valueString(b)]) };
    }
    if (
      a.kind === 'number' &&
      b.kind === 'number' &&
      ['+', '-', '*', '/', '%', '**', '==', '===', '<', '>'].includes(operator)
    ) {
      return data;
    }
    if (isData(a) && isData(b)) {
      return data;
    }
    return failInspection('Dynamic operators are not inspected.');
  }

  #member(node: SyntaxNode): Value {
    const parts = children(node);
    const [receiver, separator, property] = parts;
    if (receiver === undefined || property === undefined || separator === undefined) {
      return failInspection('Computed property access is not inspected.');
    }
    const value = this.#eval(receiver);
    if (
      this.#language === 'python' &&
      this.#text(separator) === '[' &&
      parts.some((part) => part.name === ':')
    ) {
      const bounds = parts.slice(2, -1).filter((part) => part.name !== ':');
      requireData([value, ...bounds.map((part) => this.#eval(part))]);
      return data;
    }
    if (this.#text(separator) === '[' && parts.length === 4) {
      return indexedValue(value, this.#eval(property));
    }
    if (this.#text(separator) !== '.' || property.name !== 'PropertyName' || parts.length !== 3) {
      return failInspection('Unsupported property access.');
    }
    return namedMember(value, this.#text(property), this.#language);
  }

  #call(node: SyntaxNode): Value {
    const [callee, argsNode] = children(node);
    if (callee === undefined || argsNode?.name !== 'ArgList') {
      return failInspection('Unsupported call syntax.');
    }
    const fn = this.#eval(callee);
    const parts = children(argsNode).filter((part) => !['(', ')', ','].includes(part.name));
    const args = parts.some((part) => part.name === 'for')
      ? {
          positional: [inspectComprehension(parts, this.#control())],
          keywords: new Map<string, Value>(),
        }
      : callArguments(parts, (part) => this.#eval(part), this.#source);
    if (args.positional.length + args.keywords.size > 128) {
      return failInspection('Call exceeds the argument count limit.');
    }
    return resolveCall(fn, args, {
      language: this.#language,
      range: { start: node.from, end: node.to },
      operations: this.operations,
    });
  }
}

const analyzeCode = (language: CodeLanguage, source: string): CodeReport => {
  const analyzer = new CodeAnalyzer(source, language);
  try {
    analyzer.inspect(parseCode(language, source));
    return { operations: analyzer.operations, gap: null };
  } catch (cause) {
    return {
      operations: analyzer.operations,
      gap: cause instanceof CodeInspectionError ? cause.message : 'The code inspector failed.',
    };
  }
};

export { analyzeCode };
