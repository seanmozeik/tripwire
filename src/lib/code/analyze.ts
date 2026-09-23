import type { SyntaxNode } from '@lezer/common';

import { callArguments, type CallArguments } from './arguments';
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
import { initialBindings, pythonJoin, symbol, textValue, unknown, valueString } from './values';

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

  constructor(source: string, language: CodeLanguage) {
    this.#source = source;
    this.#language = language;
    this.#bindings = this.#scopes.create(undefined, initialBindings(language));
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

  #extendedStatement(node: SyntaxNode, parts: readonly SyntaxNode[]): boolean {
    switch (node.name) {
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
      case 'RaiseStatement': {
        for (const part of parts.filter((candidate) => candidate.name !== 'raise')) {
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
      case 'PassStatement':
      case 'BreakStatement':
      case 'ContinueStatement': {
        return true;
      }
      case 'UpdateStatement': {
        const [target, , expression] = parts;
        if (target === undefined || expression === undefined) {
          return failInspection('Incomplete update.');
        }
        requireData([this.#eval(target), this.#eval(expression)]);
        this.#bindings.assign(this.#text(target), data);
        return true;
      }
      default: {
        return false;
      }
    }
  }

  #assign(parts: readonly SyntaxNode[]): void {
    const equals = parts.findIndex((part) => part.name === 'AssignOp' || part.name === 'Equals');
    const target = parts.find((part) =>
      ['VariableName', 'VariableDefinition', 'ObjectPattern', 'MemberExpression'].includes(
        part.name,
      ),
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
      if (target.name !== 'VariableName') {
        return failInspection('Unsupported compound assignment target.');
      }
      requireData([this.#eval(target), this.#eval(expression)]);
      this.#bindings.assign(this.#text(target), data);
      return;
    }
    if (target.name === 'MemberExpression') {
      const [receiver, separator, key] = children(target);
      if (receiver === undefined || key === undefined) {
        return failInspection('Incomplete mutation.');
      }
      const container = this.#eval(receiver);
      if (separator !== undefined && this.#text(separator) === '[') {
        requireData([this.#eval(key)]);
      }
      requireData([container, this.#eval(expression)]);
      if (container.kind === 'list' || container.kind === 'object') {
        container.opaque = true;
      }
      return;
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
    } else if (
      this.#language === 'python' ||
      parts.some((part) => ['const', 'let', 'var'].includes(part.name))
    ) {
      this.#bindings.set(this.#text(target), value);
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
        const parts = children(node);
        if (parts.some((part) => part.name === 'Spread')) {
          requireData(
            parts
              .filter((part) => !['[', ']', ',', 'Spread'].includes(part.name))
              .map((part) => this.#eval(part)),
          );
          return data;
        }
        return {
          kind: 'list',
          items: children(node)
            .filter((part) => !['[', ']', '(', ')', ','].includes(part.name))
            .map((part) => this.#eval(part)),
        };
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
        requireData([this.#eval(operand)]);
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
    return namedMember(value, this.#text(property), this.#language);
  }

  #closure(node: SyntaxNode): Value {
    const parts = children(node);
    const params = parts.find((part) => part.name === 'ParamList');
    const body = parts.at(-1);
    if (params === undefined || body === undefined) {
      return failInspection('Unsupported function shape.');
    }
    const fields = children(params).filter((part) => !['(', ')', ','].includes(part.name));
    const parameters: ClosureParameter[] = [];
    for (let index = 0; index < fields.length; index += 1) {
      const field = fields[index];
      if (field === undefined || !['VariableName', 'VariableDefinition'].includes(field.name)) {
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
      parameters.push({ name, ...(fallback !== undefined && { fallback }) });
    }
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

  #invokeClosure(fn: Extract<Value, { kind: 'closure' }>, args: CallArguments): Value {
    this.#depth += 1;
    if (this.#depth > 16) {
      return failInspection('Function recursion exceeds the inspection depth.');
    }
    if (args.positional.length > fn.parameters.length) {
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
    const returnStates = this.#returnStates;
    this.#bindings = this.#scopes.create(fn.scope);
    this.#returns = [];
    this.#returnStates = [];
    try {
      for (const name of args.keywords.keys()) {
        if (!fn.parameters.some((param) => param.name === name)) {
          return failInspection('Unknown closure keyword.');
        }
      }
      for (const [index, parameter] of fn.parameters.entries()) {
        if (args.positional[index] !== undefined && args.keywords.has(parameter.name)) {
          return failInspection('Duplicate closure argument.');
        }
        this.#bindings.set(
          parameter.name,
          args.positional[index] ?? args.keywords.get(parameter.name) ?? parameter.fallback ?? data,
        );
      }
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
    return resolveCall(
      fn,
      { positional: args, keywords: new Map() },
      {
        language: this.#language,
        range: { start: 0, end: 0 },
        operations: this.operations,
        callback: (callback, values) => this.#callback(callback, values),
      },
    );
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
        requireData([this.#eval(part)]);
      }
    }
    this.#scopes.join(states);
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
    requireData([this.#eval(input)]);
    const before = this.#bindings;
    this.#bindings = this.#scopes.create(before);
    this.#iterations += 1;
    try {
      for (const target of parts.slice(forIndex + 1, inIndex)) {
        if (target.name === 'VariableName') {
          this.#bindings.set(this.#text(target), data);
        } else if (target.name !== ',') {
          return failInspection('Unsupported comprehension binding.');
        }
      }
      for (const part of [...parts.slice(0, forIndex), ...parts.slice(inIndex + 2)].filter(
        (candidate) => ![':', 'if'].includes(candidate.name),
      )) {
        requireData([this.#eval(part)]);
      }
      return data;
    } finally {
      this.#iterations -= 1;
      this.#bindings = before;
    }
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
    if (fn.kind === 'closure') {
      return this.#invokeClosure(fn, args);
    }
    return resolveCall(fn, args, {
      callback: (callback, values) => this.#callback(callback, values),
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
