import path from 'node:path';
import { cpuUsage } from 'node:process';

import type { SyntaxNode } from '@lezer/common';

import { callArguments, type CallArguments } from './arguments';
import { bindPattern } from './bindings';
import { builtinExceptions, isBuiltinException } from './builtins';
import { resolveCall } from './calls';
import { defineClass, invokeContract } from './class-contracts';
import { objectValue, dictionaryValue, formatValue } from './containers';
import {
  forgetLoopWrites,
  inspectBranches,
  inspectComprehension,
  inspectLoop,
  type ControlContext,
  type EvaluationSnapshot,
} from './control';
import { data, isData, requireData, text as unknownText } from './data';
import { javascriptImport, pythonImport } from './imports';
import { indexedValue, namedMember } from './members';
import { Scopes, Scope } from './scope';
import { CodeInspectionError, children, failInspection, parseCode, stringLiteral } from './syntax';
import { syntaxHandlers } from './syntax-handlers';
import type { ClosureParameter, CodeLanguage, CodeOperation, CodeReport, Value } from './types';
import { initialBindings, pythonJoin, textValue, unknown, valueString } from './values';

const IGNORE = new Set(['Comment', 'LineComment', 'BlockComment', ';']);
const TRY_PARTS = new Set([
  'try',
  'except',
  'as',
  'else',
  'finally',
  'Body',
  'Block',
  'CatchClause',
  'FinallyClause',
]);

const literalValue = (source: string, language: CodeLanguage): Value => {
  // Bytes remain inert, unknown contents. Do not reinterpret them as paths.
  return language === 'python' && /^(?:b|br|rb)["']/iu.test(source)
    ? unknownText
    : textValue(stringLiteral(source, language));
};

class CodeAnalyzer {
  readonly operations: CodeOperation[] = [];
  #bindings: Scope;
  readonly #scopes = new Scopes();
  #depth = 0;
  #iterations = 0;
  #returns: Value[] = [];
  #returnStates: EvaluationSnapshot[] = [];
  readonly #source: string;
  readonly #language: CodeLanguage;
  #evaluatedBytes = 0;
  #steps = 0;
  #nonlocals = new Set<string>();
  readonly #argv: Value;
  #cwd: string | null;
  #started: ReturnType<typeof cpuUsage> = cpuUsage();

  constructor(
    source: string,
    language: CodeLanguage,
    argv: readonly (string | null)[] = [],
    cwd: string | null = process.cwd(),
  ) {
    this.#argv = {
      kind: 'list',
      items: argv.map((value) => (value === null ? unknownText : textValue(value))),
    };
    this.#source = source;
    this.#language = language;
    this.#bindings = this.#scopes.create(undefined, initialBindings(language));
    if (language === 'python') {
      for (const name of builtinExceptions) {
        this.#bindings.set(name, { kind: 'symbol', name });
      }
    }
    this.#cwd = cwd === null ? null : path.resolve(cwd);
  }

  #text(node: SyntaxNode): string {
    return this.#source.slice(node.from, node.to);
  }

  inspect(root: SyntaxNode): void {
    this.#started = cpuUsage();
    for (const node of children(root)) {
      this.#statement(node);
    }
  }

  #statement(node: SyntaxNode): void {
    this.#step();
    if (IGNORE.has(node.name)) {
      return;
    }
    const handler = this.#statementHandlers.get(node.name);
    if (handler === undefined) {
      return failInspection(`Unsupported executable syntax: ${node.name}.`);
    }
    handler(
      node,
      children(node).filter((part) => !IGNORE.has(part.name)),
    );
  }

  readonly #statementHandlers = syntaxHandlers<undefined>([
    [
      ['Body', 'Block', 'StatementGroup'],
      (node, parts) => {
        this.#block(node, parts);
      },
    ],
    [
      ['ExpressionStatement'],
      (_node, parts) => {
        for (const part of parts) {
          this.#eval(part);
        }
      },
    ],
    [
      ['AssignStatement', 'VariableDeclaration'],
      (_node, parts) => {
        this.#assign(parts);
      },
    ],
    [
      ['ImportStatement', 'ImportDeclaration'],
      (node, parts) => {
        const text = (part: SyntaxNode): string => this.#text(part);
        const bindings =
          node.name === 'ImportStatement'
            ? pythonImport(parts, text)
            : javascriptImport(parts, text, this.#language);
        for (const [name, value] of bindings) {
          this.#bindings.set(name, value);
        }
      },
    ],
    [
      ['ForStatement'],
      (node) => {
        inspectLoop(node, this.#control());
      },
    ],
    [
      ['IfStatement'],
      (node) => {
        inspectBranches(node, this.#control());
      },
    ],
    [
      ['AssertStatement'],
      (_node, parts) => {
        requireData(
          parts
            .filter((part) => !['assert', ','].includes(part.name))
            .map((part) => this.#eval(part)),
        );
      },
    ],
    [
      ['WithStatement'],
      (_node, parts) => {
        this.#withFile(parts);
      },
    ],
    [
      ['ClassDefinition'],
      (_node, parts) => {
        const [name, value] = defineClass(parts, {
          evaluate: (node) => this.#eval(node),
          closure: (node) => this.#closure(node),
          text: (node) => this.#text(node),
        });
        this.#bindings.set(name, value);
      },
    ],
    [
      ['FunctionDeclaration', 'FunctionDefinition'],
      (node, parts) => {
        const name =
          parts.find((part) => ['VariableName', 'VariableDefinition'].includes(part.name)) ??
          failInspection('Missing function name.');
        this.#bindings.set(this.#text(name), this.#closure(node));
      },
    ],
    [
      ['ReturnStatement'],
      (_node, parts) => {
        const value = parts.find((part) => part.name !== 'return');
        this.#returns.push(value === undefined ? data : this.#eval(value));
        this.#returnStates.push(this.#snapshot());
      },
    ],
    [
      ['TryStatement'],
      (node) => {
        this.#tryStatement(node);
      },
    ],
    [
      ['ThrowStatement', 'RaiseStatement'],
      (_node, parts) => {
        for (const part of parts.filter(
          (candidate) => !['raise', 'throw'].includes(candidate.name),
        )) {
          const value = this.#eval(part);
          if (!isBuiltinException(value)) {
            requireData([value]);
          }
        }
      },
    ],
    [
      ['WhileStatement'],
      (node, parts) => {
        this.#repeat(node, () => {
          for (const part of parts.filter(
            (candidate) => !['while', '(', ')', 'else'].includes(candidate.name),
          )) {
            if (['Body', 'Block'].includes(part.name)) {
              this.#statement(part);
            } else {
              requireData([this.#eval(part)]);
            }
          }
        });
      },
    ],
    [
      ['ScopeStatement'],
      (_node, parts) => {
        this.#declareNonlocals(parts);
      },
    ],
    [
      ['PassStatement', 'BreakStatement', 'ContinueStatement'],
      () => {
        /* No expression or binding effects. */
      },
    ],
    [
      ['UpdateStatement'],
      (_node, parts) => {
        this.#update(parts);
      },
    ],
  ]);

  #block(node: SyntaxNode, parts: readonly SyntaxNode[]): void {
    const outer = this.#bindings;
    if (node.name === 'Block') {
      this.#bindings = this.#scopes.create(outer);
    }
    try {
      for (const part of parts) {
        if (![':', '{', '}'].includes(part.name)) {
          this.#statement(part);
        }
      }
    } finally {
      if (this.#bindings !== outer) {
        this.#scopes.release(this.#bindings);
      }
      this.#bindings = outer;
    }
  }

  #declareNonlocals(parts: readonly SyntaxNode[]): void {
    if (parts[0]?.name !== 'nonlocal') {
      return failInspection('Global rebinding requires inspection.');
    }
    for (const part of parts.filter((candidate) => candidate.name === 'VariableName')) {
      const name = this.#text(part);
      if (this.#bindings.parent?.get(name) === undefined) {
        return failInspection('Unbound nonlocal.');
      }
      this.#nonlocals.add(name);
    }
  }

  #update(parts: readonly SyntaxNode[]): void {
    const [target, , expression] = parts;
    if (target === undefined || expression === undefined) {
      return failInspection('Incomplete update.');
    }
    requireData([this.#eval(target), this.#eval(expression)]);
    this.#bindings.assign(this.#text(target), data);
  }

  #multipleDeclaration(parts: readonly SyntaxNode[]): boolean {
    if (!parts.some((part) => part.name === ',')) {
      return false;
    }
    {
      let start = 0;
      for (let index = 0; index <= parts.length; index += 1) {
        if (index === parts.length || parts[index]?.name === ',') {
          const [declaration] = parts;
          const prefix =
            start > 0 &&
            declaration !== undefined &&
            ['const', 'let', 'var'].includes(declaration.name)
              ? [declaration]
              : [];
          this.#assign([...prefix, ...parts.slice(start, index)]);
          start = index + 1;
        }
      }
      return true;
    }
  }

  #multipleAssignment(parts: readonly SyntaxNode[]): boolean {
    if (this.#language !== 'python') {
      return this.#multipleDeclaration(parts);
    }
    if (parts.some((part) => part.name === ',')) {
      const at = parts.findIndex((part) => part.name === 'AssignOp');
      const targets = parts.slice(0, at).filter((part) => part.name !== ',');
      const expressions = parts.slice(at + 1).filter((part) => part.name !== ',');
      if (at === -1 || targets.some((part) => part.name !== 'VariableName')) {
        return failInspection('Unsupported tuple assignment.');
      }
      const values = expressions.map((part) => this.#eval(part));
      const [first] = values;
      let items: readonly Value[] = values;
      if (values.length === 1) {
        if (first?.kind === 'list' && first.opaque !== true) {
          ({ items } = first);
        } else {
          requireData(values);
          items = targets.map(() => data);
        }
      }
      for (const [index, target] of targets.entries()) {
        const name = this.#text(target);
        if (this.#nonlocals.has(name)) {
          this.#bindings.parent?.assign(name, items[index] ?? data);
        } else {
          this.#bindings.set(name, items[index] ?? data);
        }
      }
      return true;
    }
    return false;
  }

  #mutate(target: SyntaxNode, expression: SyntaxNode): void {
    const [receiver, separator, key] = children(target);
    if (receiver === undefined || key === undefined) {
      return failInspection('Incomplete mutation.');
    }
    const container = this.#eval(receiver);
    if (container.kind === 'environment') {
      return failInspection('Runtime environment mutation can change interpreter startup.');
    }
    if (separator !== undefined && this.#text(separator) === '[') {
      requireData([this.#eval(key)]);
    }
    const value = this.#eval(expression);
    if (container.kind === 'instance' && separator?.name === '.') {
      if (this.#text(key).startsWith('_')) {
        return failInspection('Instance reflection is not inspected.');
      }
      requireData([value]);
      container.entries.set(this.#text(key), value);
      return;
    }
    requireData([container, value]);
    if (container.kind === 'list' || container.kind === 'object') {
      container.opaque = true;
    }
  }

  #assign(parts: readonly SyntaxNode[]): void {
    if (this.#multipleAssignment(parts)) {
      return;
    }
    const equals = parts.findIndex((part) =>
      ['AssignOp', 'Equals', 'UpdateOp'].includes(part.name),
    );
    const target = parts.find((part) =>
      [
        'VariableName',
        'VariableDefinition',
        'ObjectPattern',
        'ArrayPattern',
        'MemberExpression',
      ].includes(part.name),
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
    if (!['=', ':='].includes(this.#text(operator))) {
      if (target.name !== 'VariableName') {
        return failInspection('Unsupported compound assignment target.');
      }
      requireData([this.#eval(target), this.#eval(expression)]);
      this.#bindings.assign(this.#text(target), data);
      return;
    }
    if (target.name === 'MemberExpression') {
      this.#mutate(target, expression);
      return;
    }
    if (parts.slice(0, equals).some((part) => ['MemberExpression'].includes(part.name))) {
      return failInspection('Destructuring or object mutation is not inspected.');
    }
    const value = this.#eval(expression);
    if (['ObjectPattern', 'ArrayPattern'].includes(target.name)) {
      this.#destructure(
        target,
        value,
        this.#language === 'python' ||
          parts.some((part) => ['const', 'let', 'var'].includes(part.name)),
      );
    } else if (
      this.#language === 'python' ||
      parts.some((part) => ['const', 'let', 'var'].includes(part.name))
    ) {
      if (this.#nonlocals.has(this.#text(target))) {
        this.#bindings.parent?.assign(this.#text(target), value);
      } else {
        this.#bindings.set(this.#text(target), value);
      }
    } else {
      this.#bindings.assign(this.#text(target), value);
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

  #destructure(pattern: SyntaxNode, value: Value, local = true): void {
    bindPattern(pattern, value, {
      language: this.#language,
      text: (node) => this.#text(node),
      evaluate: (node) => this.#eval(node),
      set: (name, item) => {
        if (local) {
          this.#bindings.set(name, item);
        } else {
          this.#bindings.assign(name, item);
        }
      },
    });
  }

  #eval(node: SyntaxNode): Value {
    this.#step();
    const result = this.#expression(node);
    const value =
      (result.kind === 'list' || result.kind === 'object') && result.opaque === true
        ? data
        : result;
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
    if (this.#steps % 32 === 0) {
      const elapsed = cpuUsage(this.#started);
      if (elapsed.user + elapsed.system > 40_000) {
        failInspection('Code exceeds the evaluation CPU-time budget.');
      }
    }
    if (this.#steps > 12_000) {
      failInspection('Code exceeds the evaluation step budget.');
    }
  }

  #snapshot(): EvaluationSnapshot {
    return { scopes: this.#scopes.snapshot(), cwd: this.#cwd };
  }

  #restore(snapshot: EvaluationSnapshot): void {
    Scopes.restore(snapshot.scopes);
    this.#cwd = snapshot.cwd;
  }

  #join(states: readonly EvaluationSnapshot[]): void {
    this.#scopes.join(states.map((state) => state.scopes));
    this.#cwd = states.every((state) => state.cwd === states[0]?.cwd)
      ? (states[0]?.cwd ?? null)
      : null;
  }

  #repeat<Result>(body: SyntaxNode, visit: () => Result): Result {
    this.#iterations += 1;
    try {
      forgetLoopWrites(body, this.#control());
      return visit();
    } finally {
      this.#iterations -= 1;
      forgetLoopWrites(body, this.#control());
    }
  }

  #control(): ControlContext {
    return {
      bindings: this.#bindings,
      repeat: (body, visit) => {
        this.#repeat(body, visit);
      },
      snapshot: () => this.#snapshot(),
      restore: (snapshot) => {
        this.#restore(snapshot);
      },
      join: (states) => {
        this.#join(states);
      },
      text: (node) => this.#text(node),
      evaluate: (node) => this.#eval(node),
      statement: (node) => {
        this.#statement(node);
      },
    };
  }

  #array(node: SyntaxNode): Value {
    const parts = children(node).filter((part) => !['[', ']', '(', ')', ','].includes(part.name));
    const items: Value[] = [];
    let opaque = false;
    for (let index = 0; index < parts.length; index += 1) {
      const part = parts[index];
      if (part === undefined) {
        return failInspection('Missing array element.');
      }
      if (['Spread', '*'].includes(part.name)) {
        const next = parts[index + 1];
        if (next === undefined) {
          return failInspection('Missing spread operand.');
        }
        const value = this.#eval(next);
        if (value.kind === 'list' && value.opaque !== true) {
          items.push(...value.items);
        } else {
          requireData([value]);
          opaque = true;
        }
        index += 1;
      } else {
        items.push(this.#eval(part));
      }
    }
    if (opaque) {
      requireData(items);
      return data;
    }
    return { kind: 'list', items };
  }

  #expression(node: SyntaxNode): Value {
    const handler = this.#expressionHandlers.get(node.name);
    return handler === undefined
      ? failInspection(`Unsupported expression: ${node.name}.`)
      : handler(node, children(node));
  }

  readonly #expressionHandlers = syntaxHandlers<Value>([
    [
      ['ParenthesizedExpression', 'AwaitExpression'],
      (node) => {
        return this.#wrappedExpression(node);
      },
    ],
    [
      ['ArrayExpression', 'Array', 'TupleExpression'],
      (node) => {
        return this.#array(node);
      },
    ],
    [
      [
        'SetComprehensionExpression',
        'ComprehensionExpression',
        'DictionaryComprehensionExpression',
      ],
      (node) => {
        return this.#comprehension(node);
      },
    ],
    [
      ['ArrayComprehensionExpression'],
      (node) => {
        return inspectComprehension(
          children(node).filter((part) => !['[', ']'].includes(part.name)),
          this.#control(),
        );
      },
    ],
    [
      ['BinaryExpression'],
      (node) => {
        return this.#binary(node);
      },
    ],
    [
      ['ConditionalExpression'],
      (node) => {
        return this.#conditional(node);
      },
    ],
    [
      ['MemberExpression'],
      (node) => {
        return this.#member(node);
      },
    ],
    [
      ['NewExpression', 'CallExpression'],
      (node) => {
        return this.#call(node);
      },
    ],
    [
      ['String'],
      (node) => {
        return literalValue(this.#text(node), this.#language);
      },
    ],
    [
      ['Number'],
      (node) => {
        return { kind: 'number', value: Number(this.#text(node)) };
      },
    ],
    [
      ['Boolean', 'BooleanLiteral', 'None', 'null', 'Null'],
      () => {
        return data;
      },
    ],
    [
      ['PropertyDefinition', 'VariableName'],
      (node) => {
        return (
          this.#bindings.get(this.#text(node)) ??
          failInspection('Unresolved variable or persistent runtime state.')
        );
      },
    ],
    [
      ['ArrowFunction', 'FunctionExpression', 'LambdaExpression'],
      (node) => {
        return this.#closure(node);
      },
    ],
    [
      ['UnaryExpression'],
      (node) => {
        const parts = children(node).filter((part) => !IGNORE.has(part.name));
        const operator = parts.find((part) =>
          ['typeof', 'ArithOp', 'LogicOp', 'BitOp', 'UpdateOp', 'not', 'void', 'delete'].includes(
            part.name,
          ),
        );
        const operand = parts.find((part) => part !== operator);
        if (operand === undefined) {
          return failInspection('Missing unary operand.');
        }
        if (operator?.name === 'typeof') {
          if (
            operand.name !== 'VariableName' ||
            this.#bindings.get(this.#text(operand)) !== undefined
          ) {
            this.#eval(operand);
          }
          return unknownText;
        }
        requireData([this.#eval(operand)]);
        if (operator !== undefined && ['++', '--'].includes(this.#text(operator))) {
          if (operand.name !== 'VariableName') {
            return failInspection('Computed update target.');
          }
          this.#bindings.assign(this.#text(operand), data);
        }
        return data;
      },
    ],
    [
      ['RegExp'],
      () => {
        return { kind: 'builtin', name: 'RegExp' };
      },
    ],
    [
      ['TemplateString'],
      (node) => {
        for (const interpolation of children(node)) {
          for (const part of children(interpolation).filter(
            (candidate) => !['InterpolationStart', 'InterpolationEnd'].includes(candidate.name),
          )) {
            requireData([this.#eval(part)]);
          }
        }
        return unknownText;
      },
    ],
    [
      ['NamedExpression'],
      (node) => {
        CodeAnalyzer.#checkAssignmentScope(node);
        this.#assign(children(node));
        return data;
      },
    ],
    [
      ['AssignmentExpression'],
      (node) => {
        this.#assign(children(node));
        return data;
      },
    ],
    [
      ['ObjectExpression'],
      (node) => {
        return objectValue(
          node,
          (part) => this.#eval(part),
          (part) => this.#text(part),
        );
      },
    ],
    [
      ['DictionaryExpression'],
      (node) => {
        return dictionaryValue(node, (part) => this.#eval(part));
      },
    ],
    [
      ['FormatString'],
      (node) => {
        return formatValue(node, (part) => this.#eval(part));
      },
    ],
  ]);

  static #checkAssignmentScope(node: SyntaxNode): void {
    for (let ancestor = node.parent; ancestor !== null; ancestor = ancestor.parent) {
      if (
        ancestor.name.includes('Comprehension') ||
        (ancestor.name === 'ArgList' && children(ancestor).some((part) => part.name === 'for'))
      ) {
        return failInspection(
          'Comprehension assignment can rebind an outer scope. Use a separate inspected assignment.',
        );
      }
    }
  }

  #wrappedExpression(node: SyntaxNode): Value {
    const expression = children(node).find((part) => !['(', ')', 'await'].includes(part.name));
    return expression === undefined
      ? failInspection('Missing expression.')
      : this.#eval(expression);
  }

  #conditional(node: SyntaxNode): Value {
    const fields = children(node);
    const [yes, keyword, condition, otherwise, no] =
      this.#language === 'python'
        ? fields
        : [fields[2], fields[1], fields[0], fields[3], fields[4]];
    if (
      (this.#language === 'python' && (keyword?.name !== 'if' || otherwise?.name !== 'else')) ||
      yes === undefined ||
      condition === undefined ||
      no === undefined
    ) {
      return failInspection('Unsupported conditional expression.');
    }
    requireData([this.#eval(condition)]);
    const before = this.#snapshot();
    const a = this.#eval(yes);
    const yesState = this.#snapshot();
    this.#restore(before);
    const b = this.#eval(no);
    this.#join([yesState, this.#snapshot()]);
    if (['string', 'text'].includes(a.kind) && ['string', 'text'].includes(b.kind)) {
      return unknownText;
    }
    return isData(a) && isData(b) ? data : unknown;
  }

  #binary(node: SyntaxNode): Value {
    const fields = children(node);
    const [left, op] = fields;
    const right = fields.at(-1);
    if (left === undefined || op === undefined || right === undefined) {
      return failInspection('Incomplete binary expression.');
    }
    const a = this.#eval(left);
    const operator = this.#text(op);
    const before = ['&&', '||', '??', 'and', 'or'].includes(operator) ? this.#snapshot() : null;
    const b = this.#eval(right);
    if (before !== null) {
      this.#join([before, this.#snapshot()]);
    }
    if (a.kind === 'string' && b.kind === 'string' && operator === '+') {
      return textValue(a.value + b.value);
    }
    if (a.kind === 'opaque-path' && operator === '/') {
      requireData([b]);
      return a;
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
      return value.kind === 'string' || value.kind === 'text' ? unknownText : data;
    }
    if (this.#text(separator) === '[' && parts.length === 4) {
      return indexedValue(value, this.#eval(property));
    }
    if (
      !['.', '?.'].includes(this.#text(separator)) ||
      property.name !== 'PropertyName' ||
      parts.length !== 3
    ) {
      return failInspection('Unsupported property access.');
    }
    if (
      value.kind === 'symbol' &&
      ['sys', 'process'].includes(value.name) &&
      this.#text(property) === 'argv'
    ) {
      return this.#argv;
    }
    return namedMember(value, this.#text(property), this.#language);
  }

  #parameters(params: SyntaxNode): readonly ClosureParameter[] {
    const fields = children(params).filter((part) => !['(', ')', ','].includes(part.name));
    const parameters: ClosureParameter[] = [];
    let keywordOnly = false;
    for (let index = 0; index < fields.length; index += 1) {
      let field = fields[index];
      let rest: ClosureParameter['rest'];
      if (field !== undefined && ['*', '**', 'Spread'].includes(field.name)) {
        rest = field.name === '**' ? 'keywords' : 'positional';
        index += 1;
        field = fields[index];
      }
      if (
        field === undefined ||
        !['VariableName', 'VariableDefinition', 'ArrayPattern', 'ObjectPattern'].includes(
          field.name,
        )
      ) {
        return failInspection('Unsupported function parameter.');
      }
      const name = this.#text(field);
      if (fields[index + 1]?.name === 'TypeDef') {
        this.#annotation(fields[index + 1]);
        index += 1;
      }
      let fallback: Value | undefined;
      if (['AssignOp', 'Equals'].includes(fields[index + 1]?.name ?? '')) {
        const expression = fields[index + 2];
        if (expression === undefined) {
          return failInspection('Missing parameter default.');
        }
        fallback = this.#eval(expression);
        index += 2;
      }
      parameters.push({
        name,
        keywordOnly,
        ...(fallback !== undefined && { fallback }),
        ...(rest !== undefined && { rest }),
        ...(['ArrayPattern', 'ObjectPattern'].includes(field.name) && { pattern: field }),
      });
      keywordOnly ||= this.#language === 'python' && rest !== undefined;
    }
    return parameters;
  }

  #closure(node: SyntaxNode): Value {
    const parts = children(node);
    const params = parts.find((part) => part.name === 'ParamList');
    const body = parts.at(-1);
    if (params === undefined || body === undefined) {
      return failInspection('Unsupported function shape.');
    }
    const parameters = this.#parameters(params);
    for (const part of parts.filter((candidate) => candidate.name === 'TypeDef')) {
      this.#annotation(part);
    }
    return {
      kind: 'closure',
      scope: this.#bindings,
      parameters,
      body,
      expression: !['Body', 'Block'].includes(body.name),
    };
  }

  #annotation(node: SyntaxNode | undefined): void {
    if (node !== undefined) {
      for (const part of children(node)) {
        if (part.name === 'CallExpression') {
          this.#eval(part);
        } else {
          this.#annotation(part);
        }
      }
    }
  }

  #bindClosureArguments(fn: Extract<Value, { kind: 'closure' }>, args: CallArguments): void {
    for (const name of args.keywords.keys()) {
      if (!fn.parameters.some((param) => param.name === name || param.rest === 'keywords')) {
        return failInspection('Unknown closure keyword.');
      }
    }
    for (const [index, parameter] of fn.parameters.entries()) {
      if (
        parameter.keywordOnly !== true &&
        args.positional[index] !== undefined &&
        args.keywords.has(parameter.name)
      ) {
        return failInspection('Duplicate closure argument.');
      }
      let value: Value;
      if (parameter.rest === 'positional') {
        value = { kind: 'list', items: args.positional.slice(index) };
      } else if (parameter.rest === 'keywords') {
        value = {
          kind: 'object',
          entries: new Map(
            [...args.keywords].filter(
              ([name]) => !fn.parameters.some((param) => param.name === name),
            ),
          ),
        };
      } else {
        value =
          (parameter.keywordOnly === true ? undefined : args.positional[index]) ??
          args.keywords.get(parameter.name) ??
          parameter.fallback ??
          data;
      }
      if (parameter.pattern === undefined) {
        this.#bindings.set(parameter.name, value);
      } else {
        this.#destructure(parameter.pattern, value);
      }
    }
  }

  #invokeClosure(
    fn: Extract<Value, { kind: 'closure' }>,
    args: CallArguments,
    repeated = this.#iterations > 0,
  ): Value {
    this.#depth += 1;
    if (this.#depth > 16) {
      return failInspection('Function recursion exceeds the inspection depth.');
    }
    if (
      args.positional.length > fn.parameters.length &&
      !fn.parameters.some((parameter) => parameter.rest === 'positional')
    ) {
      return failInspection('Too many closure arguments.');
    }
    const outer = this.#bindings;
    const returns = this.#returns;
    const nonlocals = this.#nonlocals;
    this.#nonlocals = new Set();
    const returnStates = this.#returnStates;
    this.#bindings = this.#scopes.create(fn.scope);
    this.#returns = [];
    this.#returnStates = [];
    try {
      this.#bindClosureArguments(fn, args);
      if (fn.expression) {
        return repeated ? this.#repeat(fn.body, () => this.#eval(fn.body)) : this.#eval(fn.body);
      }
      if (repeated) {
        this.#repeat(fn.body, () => {
          this.#statement(fn.body);
        });
      } else {
        this.#statement(fn.body);
      }
      this.#join([...this.#returnStates, this.#snapshot()]);
      const [first] = this.#returns;
      if (first !== undefined && this.#returns.every((value) => value === first)) {
        return first;
      }
      return this.#returns.every((value) => isData(value)) ? data : unknown;
    } finally {
      if (this.#bindings !== outer) {
        this.#scopes.release(this.#bindings);
      }
      this.#bindings = outer;
      this.#returns = returns;
      this.#nonlocals = nonlocals;
      this.#returnStates = returnStates;
      this.#depth -= 1;
    }
  }

  #callback(fn: Value, args: readonly Value[]): Value {
    if (fn.kind === 'closure') {
      return this.#invokeClosure(
        fn,
        { positional: args.slice(0, fn.parameters.length), keywords: new Map() },
        true,
      );
    }
    return this.#resolve(fn, { positional: args, keywords: new Map() }, { start: 0, end: 0 });
  }

  #tryStatement(node: SyntaxNode): void {
    const before = this.#snapshot();
    const states = [before];
    // Exceptions can occur after any side effect; forget writes before handlers.
    forgetLoopWrites(node, this.#control());
    const parts = children(node);
    for (const [index, part] of parts.entries()) {
      if (part.name === 'Body' || part.name === 'Block') {
        forgetLoopWrites(node, this.#control());
        this.#statement(part);
        states.push(this.#snapshot());
      }
      if (part.name === 'CatchClause' || part.name === 'FinallyClause') {
        forgetLoopWrites(node, this.#control());
        for (const field of children(part)) {
          if (field.name === 'VariableDefinition') {
            this.#bindings.set(this.#text(field), data);
          }
          if (field.name === 'Block') {
            this.#statement(field);
          } else if (!['catch', 'finally', '(', ')', 'VariableDefinition'].includes(field.name)) {
            requireData([this.#eval(field)]);
          }
        }
        states.push(this.#snapshot());
      }
      if (part.name === 'VariableName' && parts[index - 1]?.name === 'as') {
        this.#bindings.set(this.#text(part), data);
      } else if (!TRY_PARTS.has(part.name)) {
        const value = this.#eval(part);
        const exceptionTypes = isBuiltinException(value);
        if (!exceptionTypes) {
          requireData([value]);
        }
      }
    }
    this.#join(states);
  }

  #comprehensionItem(
    parts: readonly SyntaxNode[],
    forIndex: number,
    inIndex: number,
    item: Value,
  ): void {
    const targets = parts.slice(forIndex + 1, inIndex).filter((part) => part.name !== ',');
    for (const [index, target] of targets.entries()) {
      if (target.name !== 'VariableName') {
        return failInspection('Unsupported comprehension binding.');
      }
      let value = item;
      if (targets.length !== 1) {
        value = item.kind === 'list' ? (item.items[index] ?? data) : data;
      }
      this.#bindings.set(this.#text(target), value);
    }
    for (const part of [...parts.slice(0, forIndex), ...parts.slice(inIndex + 2)].filter(
      (candidate) => ![':', 'if'].includes(candidate.name),
    )) {
      requireData([this.#eval(part)]);
    }
  }

  #comprehension(node: SyntaxNode): Value {
    const parts = children(node).filter(
      (part) => !['{', '}', '(', ')', '[', ']'].includes(part.name),
    );
    const forIndex = parts.findIndex((part) => part.name === 'for');
    const inIndex = parts.findIndex((part) => part.name === 'in');
    const input = parts[inIndex + 1];
    if (forIndex < 1 || inIndex < forIndex || input === undefined) {
      return failInspection('Unsupported comprehension.');
    }
    const iterable = this.#eval(input);
    requireData([iterable]);
    const values = iterable.kind === 'list' && iterable.opaque !== true ? iterable.items : [data];
    if (values.length > 128) {
      return failInspection('Comprehension exceeds the bounded iteration limit.');
    }
    const before = this.#bindings;
    this.#bindings = this.#scopes.create(before);
    try {
      return this.#repeat(node, () => {
        for (const item of values.length === 0 ? [data] : values) {
          this.#comprehensionItem(parts, forIndex, inIndex, item);
          if (iterable.kind === 'list' && iterable.opaque === true) {
            return failInspection('Mutation changes comprehension iteration bounds.');
          }
        }
        return data;
      });
    } finally {
      this.#scopes.release(this.#bindings);
      this.#bindings = before;
    }
  }

  #resolve(fn: Value, args: CallArguments, range: { start: number; end: number }): Value {
    return resolveCall(fn, args, {
      callback: (callback, values) => this.#callback(callback, values),
      language: this.#language,
      cwd: this.#cwd,
      changeCwd: (cwd) => {
        this.#cwd = cwd;
      },
      repeated: this.#iterations > 0,
      range,
      operations: this.operations,
    });
  }

  #call(node: SyntaxNode): Value {
    const [callee, argsNode] = children(node).filter((part) => part.name !== 'new');
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
    if (fn.kind === 'class') {
      const receiver: Value = {
        kind: 'instance',
        methods: fn.methods,
        ...(fn.contract !== undefined && { contract: fn.contract }),
        entries: new Scope(),
      };
      const init = fn.methods.get('__init__');
      if (init?.kind === 'closure') {
        this.#invokeClosure(init, { ...args, positional: [receiver, ...args.positional] });
      } else if (args.positional.length > 0 || args.keywords.size > 0) {
        return failInspection('Unexpected class constructor arguments.');
      }
      return receiver;
    }
    if (fn.kind === 'contract-method') {
      return invokeContract(fn.receiver, fn.name, args, (method, values) =>
        this.#callback(method, values),
      );
    }
    if (fn.kind === 'bound-method' && fn.fn.kind === 'closure') {
      return this.#invokeClosure(fn.fn, { ...args, positional: [fn.receiver, ...args.positional] });
    }
    if (fn.kind === 'closure') {
      return this.#invokeClosure(fn, args);
    }
    return this.#resolve(fn, args, { start: node.from, end: node.to });
  }
}

const analyzeCode = (
  language: CodeLanguage,
  source: string,
  argv?: readonly (string | null)[],
  cwd?: string | null,
): CodeReport => {
  const analyzer = new CodeAnalyzer(source, language, argv, cwd);
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
