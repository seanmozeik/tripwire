import type { SyntaxNode } from '@lezer/common';

import { resolveCall } from './calls';
import { javascriptImport, pythonImport } from './imports';
import { CodeInspectionError, children, failInspection, parseCode, stringLiteral } from './syntax';
import type { CodeLanguage, CodeOperation, CodeReport, Value } from './types';
import { initialBindings, pythonJoin, symbol, textValue, unknown, valueString } from './values';

const IGNORE = new Set(['Comment', 'LineComment', 'BlockComment', ';']);

class CodeAnalyzer {
  readonly operations: CodeOperation[] = [];
  readonly #bindings: Map<string, Value>;
  readonly #source: string;
  readonly #language: CodeLanguage;

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
    if (IGNORE.has(node.name)) {
      return;
    }
    const parts = children(node).filter((part) => !IGNORE.has(part.name));
    switch (node.name) {
      case 'StatementGroup': {
        for (const part of parts) {
          this.#statement(part);
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
      default: {
        failInspection(`Unsupported executable syntax: ${node.name}.`);
      }
    }
  }

  #assign(parts: readonly SyntaxNode[]): void {
    const equals = parts.findIndex((part) => part.name === 'AssignOp' || part.name === 'Equals');
    const target = parts.find(
      (part) => part.name === 'VariableName' || part.name === 'VariableDefinition',
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
      parts.some((part) =>
        ['MemberExpression', 'ObjectPattern', 'ArrayPattern'].includes(part.name),
      )
    ) {
      return failInspection('Destructuring or object mutation is not inspected.');
    }
    this.#bindings.set(this.#text(target), this.#eval(expression));
  }

  #eval(node: SyntaxNode): Value {
    switch (node.name) {
      case 'String': {
        return textValue(stringLiteral(this.#text(node)));
      }
      case 'Number': {
        return { kind: 'number', value: Number(this.#text(node)) };
      }
      case 'Boolean':
      case 'BooleanLiteral':
      case 'None':
      case 'Null': {
        return unknown;
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
      case 'ObjectExpression': {
        return this.#object(node);
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

  #object(node: SyntaxNode): Value {
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
        return failInspection(
          'Computed properties, accessors, and object spread are not inspected.',
        );
      }
      entries.set(this.#text(key), this.#eval(value));
    }
    return { kind: 'object', entries };
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
      return unknown;
    }
    return failInspection('Dynamic operators are not inspected.');
  }

  #member(node: SyntaxNode): Value {
    const [receiver, separator, property] = children(node);
    if (
      receiver === undefined ||
      property?.name !== 'PropertyName' ||
      separator === undefined ||
      this.#text(separator) !== '.'
    ) {
      return failInspection('Computed property access is not inspected.');
    }
    const value = this.#eval(receiver);
    const member = this.#text(property);
    if (member.startsWith('_') || member === 'constructor' || member === 'prototype') {
      return failInspection('Runtime reflection is not inspected.');
    }
    if (value.kind === 'symbol') {
      return symbol(`${value.name}.${member}`);
    }
    if (value.kind === 'path' || value.kind === 'file') {
      return { kind: 'method', receiver: value, name: member };
    }
    return failInspection('Unknown receiver may execute a property getter.');
  }

  #call(node: SyntaxNode): Value {
    const [callee, argsNode] = children(node);
    if (callee === undefined || argsNode?.name !== 'ArgList') {
      return failInspection('Unsupported call syntax.');
    }
    const fn = this.#eval(callee);
    const args = children(argsNode)
      .filter((part) => !['(', ')', ','].includes(part.name))
      .map((part) => this.#eval(part));
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
