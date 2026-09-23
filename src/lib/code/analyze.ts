import path from 'node:path';

import type { SyntaxNode } from '@lezer/common';

import { callArguments, type CallArguments } from './arguments';
import { bindPattern } from './bindings';
import { resolveCall } from './calls';
import { containerValue } from './containers';
import {
  forgetLoopWrites,
  inspectBranches,
  inspectComprehension,
  inspectLoop,
  type ControlContext,
} from './control';
import { data, isData, requireData, text as unknownText } from './data';
import { javascriptImport, pythonImport } from './imports';
import { indexedValue, namedMember } from './members';
import { Scopes, type Scope, type ScopeSnapshot } from './scope';
import { CodeInspectionError, children, failInspection, parseCode, stringLiteral } from './syntax';
import type { ClosureParameter, CodeLanguage, CodeOperation, CodeReport, Value } from './types';
import { initialBindings, pythonJoin, textValue, unknown, valueString } from './values';

const HTML_HANDLERS = new Set([
  'handle_starttag',
  'handle_endtag',
  'handle_startendtag',
  'handle_data',
  'handle_entityref',
  'handle_charref',
  'handle_comment',
  'handle_decl',
  'handle_pi',
  'unknown_decl',
]);

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
  #returnStates: ScopeSnapshot[] = [];
  readonly #source: string;
  readonly #language: CodeLanguage;
  #evaluatedBytes = 0;
  #steps = 0;
  #nonlocals = new Set<string>();
  readonly #argv: Value;
  readonly #runtime: Scope;

  constructor(
    source: string,
    language: CodeLanguage,
    argv: readonly (string | null)[] = [],
    cwd = '.',
  ) {
    this.#argv = {
      kind: 'list',
      items: argv.map((value) => (value === null ? unknownText : textValue(value))),
    };
    this.#source = source;
    this.#language = language;
    this.#bindings = this.#scopes.create(undefined, initialBindings(language));
    this.#runtime = this.#scopes.create(undefined, new Map([['cwd', textValue(cwd)]]));
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
    if (this.#extendedStatement(node, parts)) {
      return;
    }
    switch (node.name) {
      case 'Body':
      case 'Block':
      case 'StatementGroup': {
        this.#block(node, parts);
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
      this.#bindings = outer;
    }
  }

  #classBase(parts: readonly SyntaxNode[]): boolean {
    const bases = parts.find((part) => part.name === 'ArgList');
    if (bases === undefined) {
      return false;
    }
    const values = children(bases).filter((part) => !['(', ')'].includes(part.name));
    const [base] = values;
    if (values.length !== 1 || base === undefined) {
      return failInspection('Class metaclasses and multiple inheritance require inspection.');
    }
    const value = this.#eval(base);
    if (value.kind !== 'symbol' || value.name !== 'html.parser.HTMLParser') {
      return failInspection('Class inheritance can invoke uninspected hooks.');
    }
    return true;
  }

  #defineClass(parts: readonly SyntaxNode[]): void {
    const name = parts.find((part) => part.name === 'VariableName');
    const body = parts.find((part) => part.name === 'Body');
    if (name === undefined || body === undefined) {
      return failInspection('Class inheritance and metaclasses can invoke uninspected hooks.');
    }
    const htmlParser = this.#classBase(parts);
    const methods = new Map<string, Value>();
    for (const member of children(body).filter(
      (part) => ![':', 'PassStatement'].includes(part.name),
    )) {
      if (member.name !== 'FunctionDefinition') {
        return failInspection('Only plain class methods are inspected.');
      }
      const method = children(member).find((part) => part.name === 'VariableName');
      if (method === undefined) {
        return failInspection('Missing method name.');
      }
      const methodName = this.#text(method);
      if (methodName.startsWith('__') && methodName !== '__init__') {
        return failInspection(
          'Implicit class hooks require inspection at every implicit call site.',
        );
      }
      if (htmlParser && !HTML_HANDLERS.has(methodName)) {
        return failInspection('HTMLParser subclasses may only override inspected event handlers.');
      }
      methods.set(methodName, this.#closure(member));
    }
    this.#bindings.set(this.#text(name), { kind: 'class', methods, htmlParser });
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

  #extendedStatement(node: SyntaxNode, parts: readonly SyntaxNode[]): boolean {
    switch (node.name) {
      case 'ClassDefinition': {
        this.#defineClass(parts);
        return true;
      }
      case 'FunctionDeclaration':
      case 'FunctionDefinition': {
        const name = parts.find((part) =>
          ['VariableName', 'VariableDefinition'].includes(part.name),
        );
        if (name === undefined) {
          return failInspection('Missing function name.');
        }
        this.#bindings.set(this.#text(name), this.#closure(node));
        return true;
      }
      case 'ReturnStatement': {
        const value = parts.find((part) => part.name !== 'return');
        this.#returns.push(value === undefined ? data : this.#eval(value));
        this.#returnStates.push(this.#scopes.snapshot());
        return true;
      }
      case 'TryStatement': {
        this.#tryStatement(node);
        return true;
      }
      case 'ThrowStatement':
      case 'RaiseStatement': {
        for (const part of parts.filter(
          (candidate) => !['raise', 'throw'].includes(candidate.name),
        )) {
          requireData([this.#eval(part)]);
        }
        return true;
      }
      case 'WhileStatement': {
        this.#iterations += 1;
        forgetLoopWrites(node, this.#control());
        for (const part of parts.filter(
          (candidate) => !['while', '(', ')', 'else'].includes(candidate.name),
        )) {
          if (['Body', 'Block'].includes(part.name)) {
            this.#statement(part);
          } else {
            requireData([this.#eval(part)]);
          }
        }
        forgetLoopWrites(node, this.#control());
        this.#iterations -= 1;
        return true;
      }
      case 'ScopeStatement': {
        this.#declareNonlocals(parts);
        return true;
      }
      case 'PassStatement':
      case 'BreakStatement':
      case 'ContinueStatement': {
        return true;
      }
      case 'UpdateStatement': {
        this.#update(parts);
        return true;
      }
      default: {
        return false;
      }
    }
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
    if (this.#steps > 12_000) {
      failInspection('Code exceeds the evaluation step budget.');
    }
  }

  #control(): ControlContext {
    return {
      bindings: this.#bindings,
      repeat: (visit) => {
        this.#iterations += 1;
        try {
          visit();
        } finally {
          this.#iterations -= 1;
        }
      },
      snapshot: () => this.#scopes.snapshot(),
      restore: (snapshot) => {
        Scopes.restore(snapshot);
      },
      join: (states) => {
        this.#scopes.join(states);
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
    const extra = this.#atom(node) ?? this.#extendedExpression(node);
    if (extra !== null) {
      return extra;
    }
    const container = containerValue(
      node,
      (part) => this.#eval(part),
      (part) => this.#text(part),
    );
    if (container !== null) {
      return container;
    }
    switch (node.name) {
      case 'ParenthesizedExpression':
      case 'AwaitExpression': {
        return this.#wrappedExpression(node);
      }
      case 'ArrayExpression':
      case 'Array':
      case 'TupleExpression': {
        return this.#array(node);
      }
      case 'SetComprehensionExpression':
      case 'ComprehensionExpression':
      case 'DictionaryComprehensionExpression': {
        return this.#comprehension(node);
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
      case 'ConditionalExpression': {
        return this.#conditional(node);
      }
      case 'MemberExpression': {
        return this.#member(node);
      }
      case 'NewExpression':
      case 'CallExpression': {
        return this.#call(node);
      }
      default: {
        return failInspection(`Unsupported expression: ${node.name}.`);
      }
    }
  }

  #atom(node: SyntaxNode): Value | null {
    switch (node.name) {
      case 'String': {
        return literalValue(this.#text(node), this.#language);
      }
      case 'Number': {
        return { kind: 'number', value: Number(this.#text(node)) };
      }
      case 'Boolean':
      case 'BooleanLiteral':
      case 'None':
      case 'null':
      case 'Null': {
        return data;
      }
      case 'PropertyDefinition':
      case 'VariableName': {
        return (
          this.#bindings.get(this.#text(node)) ??
          failInspection('Unresolved variable or persistent runtime state.')
        );
      }
      default: {
        return null;
      }
    }
  }

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

  #extendedExpression(node: SyntaxNode): Value | null {
    switch (node.name) {
      case 'ArrowFunction':
      case 'FunctionExpression':
      case 'LambdaExpression': {
        return this.#closure(node);
      }
      case 'UnaryExpression': {
        const operand = children(node).at(-1);
        if (operand === undefined) {
          return failInspection('Missing unary operand.');
        }
        if (this.#text(node).startsWith('typeof ')) {
          if (
            operand.name !== 'VariableName' ||
            this.#bindings.get(this.#text(operand)) !== undefined
          ) {
            this.#eval(operand);
          }
          return unknownText;
        }
        requireData([this.#eval(operand)]);
        if (/^(?:\+\+|--)/u.test(this.#text(node)) || /(?:\+\+|--)$/u.test(this.#text(node))) {
          if (operand.name !== 'VariableName') {
            return failInspection('Computed update target.');
          }
          this.#bindings.assign(this.#text(operand), data);
        }
        return data;
      }
      case 'RegExp': {
        return { kind: 'builtin', name: 'RegExp' };
      }
      case 'TemplateString': {
        for (const interpolation of children(node)) {
          for (const part of children(interpolation).filter(
            (candidate) => !['InterpolationStart', 'InterpolationEnd'].includes(candidate.name),
          )) {
            requireData([this.#eval(part)]);
          }
        }
        return unknownText;
      }
      case 'NamedExpression': {
        CodeAnalyzer.#checkAssignmentScope(node);
        this.#assign(children(node));
        return data;
      }
      case 'AssignmentExpression': {
        this.#assign(children(node));
        return data;
      }
      default: {
        return null;
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
    const before = this.#scopes.snapshot();
    const a = this.#eval(yes);
    const yesState = this.#scopes.snapshot();
    Scopes.restore(before);
    const b = this.#eval(no);
    this.#scopes.join([yesState, this.#scopes.snapshot()]);
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
    const before = this.#scopes.snapshot();
    const b = this.#eval(right);
    const operator = this.#text(op);
    if (['&&', '||', '??', 'and', 'or'].includes(operator)) {
      this.#scopes.join([before, this.#scopes.snapshot()]);
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

  #invokeClosure(fn: Extract<Value, { kind: 'closure' }>, args: CallArguments): Value {
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
    if (this.#iterations > 0) {
      const previous = this.#bindings;
      this.#bindings = fn.scope;
      forgetLoopWrites(fn.body, this.#control());
      this.#bindings = previous;
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
        return this.#eval(fn.body);
      }
      this.#statement(fn.body);
      this.#scopes.join([...this.#returnStates, this.#scopes.snapshot()]);
      const [first] = this.#returns;
      if (first !== undefined && this.#returns.every((value) => value === first)) {
        return first;
      }
      return this.#returns.every((value) => isData(value)) ? data : unknown;
    } finally {
      this.#bindings = outer;
      this.#returns = returns;
      this.#nonlocals = nonlocals;
      this.#returnStates = returnStates;
      this.#depth -= 1;
    }
  }

  #callback(fn: Value, args: readonly Value[]): Value {
    if (fn.kind === 'closure') {
      const before = this.#bindings;
      this.#bindings = fn.scope;
      forgetLoopWrites(fn.body, this.#control());
      this.#bindings = before;
      this.#iterations += 1;
      const value = this.#invokeClosure(fn, {
        positional: args.slice(0, fn.parameters.length),
        keywords: new Map(),
      });
      this.#iterations -= 1;
      this.#bindings = fn.scope;
      forgetLoopWrites(fn.body, this.#control());
      this.#bindings = before;
      return value;
    }
    return this.#resolve(fn, { positional: args, keywords: new Map() }, { start: 0, end: 0 });
  }

  #tryStatement(node: SyntaxNode): void {
    const before = this.#scopes.snapshot();
    const states = [before];
    // Exceptions can occur after any side effect; forget writes before handlers.
    forgetLoopWrites(node, this.#control());
    for (const part of children(node)) {
      if (part.name === 'Body' || part.name === 'Block') {
        forgetLoopWrites(node, this.#control());
        this.#statement(part);
        states.push(this.#scopes.snapshot());
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
        states.push(this.#scopes.snapshot());
      }
      if (part.name === 'VariableName') {
        this.#bindings.set(this.#text(part), data);
      } else if (!TRY_PARTS.has(part.name)) {
        const value = this.#eval(part);
        const exceptionTypes =
          value.kind === 'list' &&
          value.items.every(
            (item) =>
              item.kind === 'symbol' &&
              ['Exception', 'ValueError', 'TypeError', 'SystemExit'].includes(item.name),
          );
        if (!exceptionTypes) {
          requireData([value]);
        }
      }
    }
    this.#scopes.join(states);
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
    this.#iterations += 1;
    try {
      for (const item of values.length === 0 ? [data] : values) {
        this.#comprehensionItem(parts, forIndex, inIndex, item);
        if (iterable.kind === 'list' && iterable.opaque === true) {
          return failInspection('Mutation changes comprehension iteration bounds.');
        }
      }
      return data;
    } finally {
      this.#iterations -= 1;
      this.#bindings = before;
    }
  }

  #resolve(fn: Value, args: CallArguments, range: { start: number; end: number }): Value {
    if (fn.kind === 'symbol' && ['process.chdir', 'os.chdir'].includes(fn.name)) {
      if (this.#iterations > 0 || args.positional.length !== 1 || args.keywords.size > 0) {
        return failInspection('Repeated or computed working-directory changes require inspection.');
      }
      const target = valueString(args.positional[0]);
      const previous = valueString(this.#runtime.get('cwd'));
      this.#runtime.set(
        'cwd',
        textValue(path.isAbsolute(target) ? target : path.join(previous, target)),
      );
      return data;
    }
    if (fn.kind === 'symbol' && ['process.cwd', 'os.getcwd'].includes(fn.name)) {
      if (args.positional.length > 0 || args.keywords.size > 0) {
        return failInspection('Unexpected working-directory arguments.');
      }
      return this.#runtime.get('cwd') ?? unknown;
    }
    const before = this.operations.length;
    const result = resolveCall(fn, args, {
      callback: (callback, values) => this.#callback(callback, values),
      language: this.#language,
      ...(this.#runtime.get('cwd')?.kind === 'string' && {
        cwd: valueString(this.#runtime.get('cwd')),
      }),
      range,
      operations: this.operations,
    });
    for (let index = before; index < this.operations.length; index += 1) {
      const operation = this.operations[index];
      if (operation !== undefined) {
        const cwd = valueString(this.#runtime.get('cwd'));
        this.operations[index] = {
          ...operation,
          cwd: operation.cwd === undefined ? cwd : path.resolve(cwd, operation.cwd),
        };
      }
    }
    return result;
  }

  #feedHtml(receiver: Extract<Value, { kind: 'instance' }>, args: CallArguments): Value {
    requireData(args.positional);
    if (args.keywords.size > 0) {
      return failInspection('Uninspected HTML parser options.');
    }
    for (const key of receiver.entries.keys()) {
      receiver.entries.set(key, data);
    }
    for (const method of receiver.methods.values()) {
      if (method.kind !== 'closure') {
        return failInspection('Unresolved HTML handler.');
      }
      this.#callback(method, [receiver, ...method.parameters.slice(1).map(() => data)]);
    }
    for (const key of receiver.entries.keys()) {
      receiver.entries.set(key, data);
    }
    return data;
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
        htmlParser: fn.htmlParser === true,
        entries: this.#scopes.create(),
      };
      const init = fn.methods.get('__init__');
      if (init?.kind === 'closure') {
        this.#invokeClosure(init, { ...args, positional: [receiver, ...args.positional] });
      } else if (args.positional.length > 0 || args.keywords.size > 0) {
        return failInspection('Unexpected class constructor arguments.');
      }
      return receiver;
    }
    if (
      fn.kind === 'bound-method' &&
      fn.receiver.kind === 'instance' &&
      fn.fn.kind === 'symbol' &&
      fn.fn.name === 'html-parser.feed'
    ) {
      return this.#feedHtml(fn.receiver, args);
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
  cwd?: string,
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
