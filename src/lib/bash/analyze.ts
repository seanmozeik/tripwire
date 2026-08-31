import {
  parse,
  type ArithmeticExpression,
  type AssignmentPrefix,
  type Command,
  type Node,
  type ParsedScript,
  type Redirect,
  type Statement,
  type TestExpression,
  type Word,
  type WordPart,
} from 'unbash';

import { ExecutionInspector } from './execution';
import type {
  BashAnalysisOptions,
  PipelinePosition,
  ShellDiagnostic,
  ShellDiagnosticKind,
  ShellInvocation,
  ShellProgram,
  ShellRedirect,
  ShellWord,
  SourceRange,
} from './types';
import {
  DYNAMIC_VALUE,
  backgroundPidWord,
  boundWord,
  cloneEnvironment,
  emptyEnvironment,
  type Environment,
  isQuotedPart,
  isTrustedMktemp,
  staticGeneratedValue,
  trustedTempWord,
  wordIsStatic,
} from './values';

interface VisitContext {
  readonly inspectedPipelineInput: boolean;
  readonly source: string;
  readonly pipeline: PipelinePosition | undefined;
}

interface AssignmentEffect {
  readonly binding: ShellWord | undefined;
  readonly name: string;
  readonly trustedTemp: boolean;
}

interface FunctionScope {
  readonly localNames: Set<string>;
}

type ParameterExpansionPart = Extract<WordPart, { readonly type: 'ParameterExpansion' }>;

const rangeOf = (node: { readonly pos: number; readonly end: number }): SourceRange => ({
  start: node.pos,
  end: node.end,
});

const basename = (value: string): string => {
  const index = value.lastIndexOf('/');
  return index === -1 ? value : value.slice(index + 1);
};

const mapsAgree = <Value>(maps: readonly ReadonlyMap<string, Value>[]): Map<string, Value> => {
  const [first, ...rest] = maps;
  const joined = new Map<string, Value>();
  if (first === undefined) {
    return joined;
  }
  for (const [name, value] of first) {
    if (rest.every((map) => map.get(name) === value)) {
      joined.set(name, value);
    }
  }
  return joined;
};

const environmentsAgree = (environments: readonly Environment[]): Environment => {
  const [first, ...rest] = environments;
  if (first === undefined) {
    return emptyEnvironment();
  }
  return {
    aliases: mapsAgree([first.aliases, ...rest.map((environment) => environment.aliases)]),
    backgroundPidAvailable: [first, ...rest].every(
      (environment) => environment.backgroundPidAvailable,
    ),
    bindings: mapsAgree([first.bindings, ...rest.map((environment) => environment.bindings)]),
    functions: mapsAgree([first.functions, ...rest.map((environment) => environment.functions)]),
    temps: mapsAgree([first.temps, ...rest.map((environment) => environment.temps)]),
  };
};

const replaceEnvironment = (target: Environment, source: Environment): void => {
  target.backgroundPidAvailable = source.backgroundPidAvailable;
  target.aliases.clear();
  for (const [name, value] of source.aliases) {
    target.aliases.set(name, value);
  }
  target.bindings.clear();
  for (const [name, value] of source.bindings) {
    target.bindings.set(name, value);
  }
  target.functions.clear();
  for (const [name, value] of source.functions) {
    target.functions.set(name, value);
  }
  target.temps.clear();
  for (const [name, value] of source.temps) {
    target.temps.set(name, value);
  }
};

const propagateMap = <Value>(
  target: Map<string, Value>,
  source: ReadonlyMap<string, Value>,
  excluded: ReadonlySet<string>,
): void => {
  for (const name of target.keys()) {
    if (!excluded.has(name) && !source.has(name)) {
      target.delete(name);
    }
  }
  for (const [name, value] of source) {
    if (!excluded.has(name)) {
      target.set(name, value);
    }
  }
};

const propagateFunctionEffects = (
  target: Environment,
  source: Environment,
  excludedVariables: ReadonlySet<string>,
): void => {
  propagateMap(target.aliases, source.aliases, new Set());
  propagateMap(target.functions, source.functions, new Set());
  propagateMap(target.bindings, source.bindings, excludedVariables);
  propagateMap(target.temps, source.temps, excludedVariables);
  target.backgroundPidAvailable = source.backgroundPidAvailable;
};

const applyAssignment = (effect: AssignmentEffect, environment: Environment): void => {
  environment.temps.delete(effect.name);
  environment.bindings.delete(effect.name);
  if (effect.trustedTemp) {
    environment.temps.set(effect.name, { variable: effect.name });
  } else if (effect.binding !== undefined) {
    environment.bindings.set(effect.name, effect.binding);
  }
};

const isExactAssignmentBinding = (
  assignment: AssignmentPrefix,
  normalizedValue: ShellWord | undefined,
  environment: Environment,
): boolean => {
  if (
    assignment.append === true ||
    assignment.index !== undefined ||
    assignment.array !== undefined ||
    assignment.value === undefined
  ) {
    return false;
  }
  if (normalizedValue?.kind === 'literal') {
    return (
      wordIsStatic(assignment.value) ||
      staticGeneratedValue(assignment.value, environment) !== null ||
      boundWord(assignment.value, environment) !== null
    );
  }
  return (
    normalizedValue?.kind === 'background-pid' &&
    backgroundPidWord(assignment.value, environment) !== null
  );
};

class BashAnalyzer {
  readonly #source: string;
  readonly #invocations: ShellInvocation[] = [];
  readonly #redirects: ShellRedirect[] = [];
  readonly #diagnostics: ShellDiagnostic[] = [];
  readonly #heredocRanges: SourceRange[] = [];
  readonly #seenScripts = new WeakSet<object>();
  readonly #activeAliases = new Set<string>();
  readonly #activeFunctions = new Set<string>();
  readonly #functionScopes: FunctionScope[] = [];
  readonly #execution: ExecutionInspector;
  readonly #options: BashAnalysisOptions;
  #nextInvocationId = 1;
  #nextPipelineId = 1;

  constructor(source: string, options: BashAnalysisOptions) {
    this.#source = source;
    this.#options = options;
    this.#execution = new ExecutionInspector(
      {
        addDiagnostic: (kind, message, range) => {
          this.#addDiagnostic(kind, message, range);
        },
        emitSynthetic: (words, parent, environment, context) => {
          this.#emitSynthetic(words, parent, environment, context);
        },
        inspectShellSource: (word, environment, context) => {
          this.#inspectShellSource(word, environment, context);
        },
      },
      options.executionCarrierAliases ?? [],
    );
  }

  analyze(script: ParsedScript): ShellProgram {
    const environment = emptyEnvironment();
    const bindLiteral = (name: string, value: string): void => {
      environment.bindings.set(name, {
        source: value,
        value,
        kind: 'literal',
        range: { start: 0, end: 0 },
        quoted: true,
        variable: name,
      });
    };
    if (this.#options.cwd !== undefined) {
      bindLiteral('PWD', this.#options.cwd);
    }
    for (const [index, value] of (this.#options.positionalArguments ?? []).entries()) {
      bindLiteral((index + 1).toString(), value);
    }
    this.#visitScript(script, environment, {
      inspectedPipelineInput: false,
      source: this.#source,
      pipeline: undefined,
    });
    return {
      source: this.#source,
      invocations: this.#invocations,
      redirects: this.#redirects,
      diagnostics: this.#diagnostics,
      hasBypass: this.#findBypass(),
    };
  }

  #addDiagnostic(kind: ShellDiagnosticKind, message: string, range: SourceRange): void {
    this.#diagnostics.push({ kind, message, range });
  }

  #visitScript(script: ParsedScript, environment: Environment, context: VisitContext): void {
    if (this.#seenScripts.has(script)) {
      return;
    }
    this.#seenScripts.add(script);
    const source = script.source ?? context.source;
    for (const error of script.errors ?? []) {
      this.#addDiagnostic('parse-error', error.message, { start: error.pos, end: error.pos });
    }
    this.#visitStatements(script.commands, environment, { ...context, source });
  }

  #visitStatements(
    statements: readonly Statement[],
    environment: Environment,
    context: VisitContext,
  ): void {
    for (const statement of statements) {
      this.#visitStatement(statement, environment, context);
    }
  }

  #visitStatement(statement: Statement, environment: Environment, context: VisitContext): void {
    this.#visitRedirects(statement.redirects, environment, context);
    this.#visitNode(statement.command, environment, context);
    if (statement.background === true) {
      environment.backgroundPidAvailable = true;
    }
  }

  #visitNode(node: Node, environment: Environment, context: VisitContext): void {
    if (
      this.#visitCommandStructure(node, environment, context) ||
      this.#visitControlFlow(node, environment, context) ||
      this.#visitCompoundStructure(node, environment, context)
    ) {
      return;
    }
    this.#addDiagnostic('parse-error', `Unknown Bash AST node: ${node.type}`, rangeOf(node));
  }

  #visitCommandStructure(node: Node, environment: Environment, context: VisitContext): boolean {
    if (node.type === 'Statement') {
      this.#visitStatement(node, environment, context);
      return true;
    }
    if (node.type === 'Command') {
      this.#visitCommand(node, environment, context);
      return true;
    }
    if (node.type === 'CompoundList') {
      this.#visitStatements(node.commands, environment, context);
      return true;
    }
    if (node.type === 'Pipeline') {
      const pipelineId = this.#nextPipelineId;
      this.#nextPipelineId += 1;
      const inspectedInputs = this.#execution.inspectPipelineInputs(
        node.commands,
        environment,
        context,
      );
      for (const [index, command] of node.commands.entries()) {
        this.#visitNode(command, cloneEnvironment(environment), {
          ...context,
          inspectedPipelineInput: inspectedInputs.has(index),
          pipeline: { id: pipelineId, index },
        });
      }
      return true;
    }
    if (node.type === 'AndOr') {
      const working = cloneEnvironment(environment);
      for (const command of node.commands) {
        this.#visitNode(command, working, context);
      }
      replaceEnvironment(environment, environmentsAgree([environment, working]));
      return true;
    }
    return false;
  }

  #visitControlFlow(node: Node, environment: Environment, context: VisitContext): boolean {
    if (node.type === 'If') {
      const clauseEnvironment = cloneEnvironment(environment);
      this.#visitNode(node.clause, clauseEnvironment, context);
      const thenEnvironment = cloneEnvironment(clauseEnvironment);
      this.#visitNode(node.then, thenEnvironment, context);
      const elseEnvironment = cloneEnvironment(clauseEnvironment);
      if (node.else !== undefined) {
        this.#visitNode(node.else, elseEnvironment, context);
      }
      replaceEnvironment(environment, environmentsAgree([thenEnvironment, elseEnvironment]));
      return true;
    }
    if (node.type === 'For' || node.type === 'Select') {
      const name = this.#normalizeWord(node.name, environment, context);
      const values = node.wordlist.map((word) => this.#normalizeWord(word, environment, context));
      if (
        name.kind === 'literal' &&
        /^[A-Za-z_][A-Za-z0-9_]*$/u.test(name.value) &&
        values.length > 0 &&
        values.length <= 32 &&
        values.every((value) => value.kind === 'literal')
      ) {
        for (const value of values) {
          const iteration = cloneEnvironment(environment);
          iteration.temps.delete(name.value);
          iteration.bindings.set(name.value, value);
          this.#visitNode(node.body, iteration, context);
        }
      } else {
        const iteration = cloneEnvironment(environment);
        iteration.temps.delete(name.value);
        iteration.bindings.delete(name.value);
        this.#visitNode(node.body, iteration, context);
      }
      return true;
    }
    if (node.type === 'ArithmeticFor') {
      this.#visitArithmetic(node.initialize, environment, context);
      this.#visitArithmetic(node.test, environment, context);
      this.#visitArithmetic(node.update, environment, context);
      this.#visitNode(node.body, cloneEnvironment(environment), context);
      return true;
    }
    if (node.type === 'While') {
      const loopEnvironment = cloneEnvironment(environment);
      this.#visitNode(node.clause, loopEnvironment, context);
      this.#visitNode(node.body, loopEnvironment, context);
      return true;
    }
    if (node.type === 'Function') {
      const name = this.#normalizeWord(node.name, environment, context);
      if (name.kind !== 'literal' || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name.value)) {
        this.#addDiagnostic('function', 'The function name is not static.', rangeOf(node));
      } else {
        environment.functions.set(name.value, node);
      }
      return true;
    }
    return false;
  }

  #visitCompoundStructure(node: Node, environment: Environment, context: VisitContext): boolean {
    if (node.type === 'Subshell') {
      this.#visitNode(node.body, cloneEnvironment(environment), context);
      return true;
    }
    if (node.type === 'BraceGroup') {
      this.#visitNode(node.body, environment, context);
      return true;
    }
    if (node.type === 'Case') {
      this.#normalizeWord(node.word, environment, context);
      const branches: Environment[] = [cloneEnvironment(environment)];
      for (const item of node.items) {
        for (const pattern of item.pattern) {
          this.#normalizeWord(pattern, environment, context);
        }
        const branch = cloneEnvironment(environment);
        this.#visitNode(item.body, branch, context);
        branches.push(branch);
      }
      replaceEnvironment(environment, environmentsAgree(branches));
      return true;
    }
    if (node.type === 'Coproc') {
      if (node.name !== undefined) {
        this.#normalizeWord(node.name, environment, context);
      }
      this.#visitRedirects(node.redirects, environment, context);
      this.#visitNode(node.body, cloneEnvironment(environment), context);
      return true;
    }
    if (node.type === 'TestCommand') {
      this.#visitTest(node.expression, environment, context);
      return true;
    }
    if (node.type === 'ArithmeticCommand') {
      this.#visitArithmetic(node.expression, environment, context);
      return true;
    }
    return false;
  }

  #visitCommand(command: Command, environment: Environment, context: VisitContext): void {
    const assignmentEffects = command.prefix.flatMap((assignment) => {
      const effect = this.#inspectAssignment(assignment, environment, context);
      return effect === null ? [] : [effect];
    });
    if (command.name === undefined) {
      for (const effect of assignmentEffects) {
        applyAssignment(effect, environment);
      }
    }
    const redirects = this.#visitRedirects(command.redirects, environment, context);
    if (command.name === undefined) {
      return;
    }
    const name = this.#normalizeWord(command.name, environment, context);
    const suffix = command.suffix.flatMap((word) =>
      this.#normalizeWordMany(word, environment, context),
    );
    if (name.kind === 'literal' && environment.functions.has(name.value)) {
      this.#invokeFunction(name.value, suffix, assignmentEffects, environment, context);
      return;
    }
    if (name.kind === 'literal' && environment.aliases.has(name.value)) {
      this.#invokeAlias(name.value, suffix, environment, context, rangeOf(command));
      return;
    }
    const invocation = this.#emitInvocation(
      [name, ...suffix],
      redirects,
      rangeOf(command),
      context,
      false,
    );
    if (invocation === null) {
      return;
    }
    if (invocation.head === 'alias') {
      this.#defineAliases(invocation, environment);
      return;
    }
    if (invocation.head === 'unalias') {
      this.#removeAliases(invocation, environment);
      return;
    }
    const inlineShellSource = this.#execution.inspectShellInput(
      invocation,
      command.redirects,
      environment,
      context,
    );
    this.#execution.inspectWrapper(invocation, environment, context, inlineShellSource);
    this.#applyVariableBuiltin(invocation, environment);
  }

  #inspectAssignment(
    assignment: AssignmentPrefix,
    environment: Environment,
    context: VisitContext,
  ): AssignmentEffect | null {
    for (const part of assignment.indexParts ?? []) {
      this.#visitWordPart(part, environment, context);
    }
    for (const word of assignment.array ?? []) {
      this.#normalizeWord(word, environment, context);
    }
    const normalizedValue =
      assignment.value === undefined
        ? undefined
        : this.#normalizeWord(assignment.value, environment, context);
    if (assignment.name === undefined) {
      return null;
    }
    const trustedTemp =
      assignment.append !== true &&
      assignment.index === undefined &&
      assignment.array === undefined &&
      assignment.value !== undefined &&
      isTrustedMktemp(assignment.value, environment);
    const exactBinding = isExactAssignmentBinding(assignment, normalizedValue, environment);
    return {
      binding: exactBinding ? normalizedValue : undefined,
      name: assignment.name,
      trustedTemp,
    };
  }

  #normalizeWordMany(word: Word, environment: Environment, context: VisitContext): ShellWord[] {
    const normalized = this.#normalizeWord(word, environment, context);
    if (normalized.kind !== 'literal' || normalized.quoted || !/[*?[]/u.test(normalized.value)) {
      return [normalized];
    }
    try {
      const matches = [...new Bun.Glob(normalized.value).scanSync({ onlyFiles: false, dot: true })];
      if (matches.length === 0) {
        return [normalized];
      }
      const expanded: ShellWord[] = [];
      for (const value of matches) {
        expanded.push({
          source: normalized.source,
          value,
          kind: normalized.kind,
          range: normalized.range,
          quoted: normalized.quoted,
        });
      }
      return expanded;
    } catch {
      return [normalized];
    }
  }

  #normalizeWord(word: Word, environment: Environment, context: VisitContext): ShellWord {
    for (const part of word.parts ?? []) {
      this.#visitWordPart(part, environment, context);
    }
    const trusted = trustedTempWord(word, environment);
    if (trusted !== null) {
      return trusted;
    }
    const backgroundPid = backgroundPidWord(word, environment);
    if (backgroundPid !== null) {
      return backgroundPid;
    }
    const bound = boundWord(word, environment);
    if (bound !== null) {
      return bound;
    }
    if (wordIsStatic(word)) {
      return {
        source: word.text,
        value: word.value,
        kind: 'literal',
        range: rangeOf(word),
        quoted: (word.parts ?? []).some((part) => isQuotedPart(part)),
      };
    }
    const generated = staticGeneratedValue(word, environment);
    if (generated !== null) {
      return {
        source: word.text,
        value: generated,
        kind: 'literal',
        range: rangeOf(word),
        quoted: true,
      };
    }
    return {
      source: word.text,
      value: word.value,
      kind: 'dynamic',
      range: rangeOf(word),
      quoted: (word.parts ?? []).some((part) => isQuotedPart(part)),
    };
  }

  #visitWordPart(part: WordPart, environment: Environment, context: VisitContext): void {
    switch (part.type) {
      case 'Literal':
      case 'SingleQuoted':
      case 'AnsiCQuoted':
      case 'SimpleExpansion': {
        return;
      }
      case 'DoubleQuoted':
      case 'LocaleString': {
        for (const child of part.parts) {
          this.#visitWordPart(child, environment, context);
        }
        return;
      }
      case 'ParameterExpansion': {
        this.#visitParameterExpansion(part, environment, context);
        return;
      }
      case 'CommandExpansion':
      case 'ProcessSubstitution': {
        if (part.script !== undefined) {
          this.#visitScript(part.script, cloneEnvironment(environment), context);
        }
        return;
      }
      case 'ArithmeticExpansion': {
        this.#visitArithmetic(part.expression, environment, context);
        return;
      }
      case 'ExtendedGlob':
      case 'BraceExpansion': {
        for (const child of part.parts ?? []) {
          this.#visitWordPart(child, environment, context);
        }
        break;
      }
      default: {
        break;
      }
    }
  }

  #visitParameterExpansion(
    part: ParameterExpansionPart,
    environment: Environment,
    context: VisitContext,
  ): void {
    for (const child of part.indexParts ?? []) {
      this.#visitWordPart(child, environment, context);
    }
    if (part.operand !== undefined) {
      this.#normalizeWord(part.operand, environment, context);
    }
    if (part.slice !== undefined) {
      this.#normalizeWord(part.slice.offset, environment, context);
      if (part.slice.length !== undefined) {
        this.#normalizeWord(part.slice.length, environment, context);
      }
    }
    if (part.replace !== undefined) {
      this.#normalizeWord(part.replace.pattern, environment, context);
      this.#normalizeWord(part.replace.replacement, environment, context);
    }
  }

  #visitArithmetic(
    expression: ArithmeticExpression | undefined,
    environment: Environment,
    context: VisitContext,
  ): void {
    if (expression === undefined) {
      return;
    }
    switch (expression.type) {
      case 'ArithmeticBinary': {
        this.#visitArithmetic(expression.left, environment, context);
        this.#visitArithmetic(expression.right, environment, context);
        return;
      }
      case 'ArithmeticUnary': {
        this.#visitArithmetic(expression.operand, environment, context);
        return;
      }
      case 'ArithmeticTernary': {
        this.#visitArithmetic(expression.test, environment, context);
        this.#visitArithmetic(expression.consequent, environment, context);
        this.#visitArithmetic(expression.alternate, environment, context);
        return;
      }
      case 'ArithmeticGroup': {
        this.#visitArithmetic(expression.expression, environment, context);
        return;
      }
      case 'ArithmeticWord': {
        for (const part of expression.parts ?? []) {
          this.#visitWordPart(part, environment, context);
        }
        return;
      }
      case 'ArithmeticCommandExpansion': {
        if (expression.script !== undefined) {
          this.#visitScript(expression.script, cloneEnvironment(environment), context);
        }
        break;
      }
      default: {
        break;
      }
    }
  }

  #visitTest(expression: TestExpression, environment: Environment, context: VisitContext): void {
    switch (expression.type) {
      case 'TestUnary': {
        this.#normalizeWord(expression.operand, environment, context);
        return;
      }
      case 'TestBinary': {
        this.#normalizeWord(expression.left, environment, context);
        this.#normalizeWord(expression.right, environment, context);
        return;
      }
      case 'TestLogical': {
        this.#visitTest(expression.left, environment, context);
        this.#visitTest(expression.right, environment, context);
        return;
      }
      case 'TestNot': {
        this.#visitTest(expression.operand, environment, context);
        return;
      }
      case 'TestGroup': {
        this.#visitTest(expression.expression, environment, context);
        break;
      }
      default: {
        break;
      }
    }
  }

  #visitRedirects(
    redirects: readonly Redirect[],
    environment: Environment,
    context: VisitContext,
  ): ShellRedirect[] {
    const normalized: ShellRedirect[] = [];
    for (const redirect of redirects) {
      if (redirect.body !== undefined) {
        this.#heredocRanges.push(rangeOf(redirect.body));
        this.#normalizeWord(redirect.body, environment, context);
      } else if (redirect.content !== undefined) {
        const contentStart = context.source.indexOf(redirect.content, redirect.end);
        if (contentStart !== -1) {
          this.#heredocRanges.push({
            start: contentStart,
            end: contentStart + redirect.content.length,
          });
        }
      }
      const target =
        redirect.target === undefined
          ? {
              source: '',
              value: DYNAMIC_VALUE,
              kind: 'dynamic' as const,
              range: rangeOf(redirect),
              quoted: false,
            }
          : this.#normalizeWord(redirect.target, environment, context);
      let op: ShellRedirect['op'];
      if (redirect.operator === '<<-') {
        op = '<<';
      } else if (redirect.operator === '>|') {
        op = '>';
      } else {
        op = redirect.operator;
      }
      const shellRedirect: ShellRedirect = { op, target, range: rangeOf(redirect) };
      normalized.push(shellRedirect);
      this.#redirects.push(shellRedirect);
    }
    return normalized;
  }

  #emitInvocation(
    words: readonly ShellWord[],
    redirects: readonly ShellRedirect[],
    range: SourceRange,
    context: VisitContext,
    synthetic: boolean,
  ): ShellInvocation | null {
    const [executable] = words;
    if (executable === undefined) {
      return null;
    }
    if (executable.kind !== 'literal') {
      this.#addDiagnostic(
        'dynamic-executable',
        'The executable name is computed at runtime.',
        executable.range,
      );
      return null;
    }
    const tokens = words.map((word) => word.value);
    const flags = tokens.slice(1).filter((token) => token.startsWith('-') && token !== '-');
    const args = tokens.slice(1).filter((token) => !token.startsWith('-') || token === '-');
    const invocation: ShellInvocation = {
      id: this.#nextInvocationId,
      head: basename(executable.value),
      words,
      tokens,
      args,
      flags,
      redirects,
      raw: synthetic
        ? words.map((word) => word.source).join(' ')
        : context.source.slice(range.start, range.end),
      range,
      pipeline: context.pipeline,
      synthetic,
    };
    this.#nextInvocationId += 1;
    this.#invocations.push(invocation);
    if (invocation.head === 'eval') {
      this.#addDiagnostic('eval', '`eval` can turn computed data into shell syntax.', range);
    }
    return invocation;
  }

  #invokeFunction(
    name: string,
    arguments_: readonly ShellWord[],
    assignments: readonly AssignmentEffect[],
    environment: Environment,
    context: VisitContext,
  ): void {
    const definition = environment.functions.get(name);
    if (definition === undefined) {
      return;
    }
    if (this.#activeFunctions.has(name)) {
      this.#addDiagnostic('function', `Recursive function call: ${name}`, rangeOf(definition));
      return;
    }
    this.#activeFunctions.add(name);
    const callEnvironment = cloneEnvironment(environment);
    const prefixNames = new Set(assignments.map((assignment) => assignment.name));
    for (const assignment of assignments) {
      applyAssignment(assignment, callEnvironment);
    }
    for (const bindingName of callEnvironment.bindings.keys()) {
      if (/^[0-9]+$/u.test(bindingName)) {
        callEnvironment.bindings.delete(bindingName);
      }
    }
    for (const [index, word] of arguments_.entries()) {
      callEnvironment.bindings.set(String(index + 1), word);
    }
    const scope: FunctionScope = { localNames: new Set() };
    this.#functionScopes.push(scope);
    try {
      this.#visitRedirects(definition.redirects, callEnvironment, context);
      this.#visitNode(definition.body, callEnvironment, context);
      const excludedVariables = new Set([...prefixNames, ...scope.localNames]);
      for (const bindingName of callEnvironment.bindings.keys()) {
        if (/^[0-9]+$/u.test(bindingName)) {
          excludedVariables.add(bindingName);
        }
      }
      propagateFunctionEffects(environment, callEnvironment, excludedVariables);
    } finally {
      this.#functionScopes.pop();
      this.#activeFunctions.delete(name);
    }
  }

  #invokeAlias(
    name: string,
    arguments_: readonly ShellWord[],
    environment: Environment,
    context: VisitContext,
    range: SourceRange,
  ): void {
    const replacement = environment.aliases.get(name);
    if (replacement === undefined) {
      return;
    }
    if (this.#activeAliases.has(name)) {
      this.#addDiagnostic('alias', `Recursive alias expansion: ${name}`, range);
      return;
    }
    this.#activeAliases.add(name);
    try {
      const script = parse(replacement);
      const [statement] = script.commands;
      const command = statement?.command;
      if (
        (script.errors?.length ?? 0) > 0 ||
        script.commands.length !== 1 ||
        statement?.background === true ||
        statement?.redirects.length !== 0 ||
        command?.type !== 'Command' ||
        command.name === undefined ||
        command.prefix.length > 0 ||
        command.redirects.length > 0
      ) {
        this.#visitScript(script, cloneEnvironment(environment), {
          ...context,
          source: replacement,
          pipeline: undefined,
        });
        this.#addDiagnostic(
          'alias',
          `Alias ${name} has compound expansion whose call arguments cannot be bound safely.`,
          range,
        );
        return;
      }
      const aliasContext = { ...context, source: replacement };
      const words = [
        this.#normalizeWord(command.name, environment, aliasContext),
        ...command.suffix.flatMap((word) =>
          this.#normalizeWordMany(word, environment, aliasContext),
        ),
        ...arguments_,
      ];
      const parent: ShellInvocation = {
        id: 0,
        head: name,
        words: [],
        tokens: [],
        args: [],
        flags: [],
        redirects: [],
        raw: name,
        range,
        pipeline: context.pipeline,
        synthetic: true,
      };
      this.#emitSynthetic(words, parent, environment, context);
    } finally {
      this.#activeAliases.delete(name);
    }
  }

  #defineAliases(invocation: ShellInvocation, environment: Environment): void {
    for (const word of invocation.words.slice(1)) {
      if (word.kind === 'literal') {
        const equalsIndex = word.value.indexOf('=');
        if (equalsIndex !== -1) {
          const name = word.value.slice(0, equalsIndex);
          if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) {
            environment.aliases.set(name, word.value.slice(equalsIndex + 1));
          } else {
            this.#addDiagnostic('alias', `Invalid alias name: ${name}`, word.range);
          }
        }
      } else {
        this.#addDiagnostic('alias', 'An alias definition is computed at runtime.', word.range);
      }
    }
  }

  #removeAliases(invocation: ShellInvocation, environment: Environment): void {
    if (invocation.tokens.includes('-a')) {
      environment.aliases.clear();
      return;
    }
    for (const word of invocation.words.slice(1)) {
      if (word.kind === 'literal') {
        environment.aliases.delete(word.value);
        this.#activeAliases.delete(word.value);
      }
    }
  }

  #emitSynthetic(
    words: readonly ShellWord[],
    parent: ShellInvocation,
    environment: Environment,
    context: VisitContext,
  ): void {
    const invocation = this.#emitInvocation(
      words,
      [],
      parent.range,
      { ...context, pipeline: parent.pipeline },
      true,
    );
    if (invocation !== null) {
      this.#execution.inspectWrapper(
        invocation,
        environment,
        context,
        context.inspectedPipelineInput,
      );
    }
  }

  #inspectShellSource(
    word: ShellWord | undefined,
    environment: Environment,
    context: VisitContext,
  ): void {
    if (word?.kind !== 'literal') {
      this.#addDiagnostic(
        'dynamic-shell-source',
        'A shell wrapper receives source that is computed at runtime.',
        word?.range ?? { start: 0, end: 0 },
      );
      return;
    }
    try {
      this.#visitScript(parse(word.value), cloneEnvironment(environment), {
        ...context,
        inspectedPipelineInput: false,
        source: word.value,
        pipeline: undefined,
      });
    } catch (cause) {
      this.#addDiagnostic(
        'parse-error',
        cause instanceof Error ? cause.message : 'The nested shell source could not be parsed.',
        word.range,
      );
    }
  }

  #applyVariableBuiltin(invocation: ShellInvocation, environment: Environment): void {
    if (
      invocation.head === 'export' &&
      invocation.flags.some((flag) => flag === '-f' || /^-[^-]*f/u.test(flag))
    ) {
      this.#addDiagnostic(
        'function',
        'Exported functions can execute in a nested shell outside the local call binding.',
        invocation.range,
      );
    }
    if (invocation.head === 'unset') {
      for (const word of invocation.words.slice(1)) {
        if (/^[A-Za-z_][A-Za-z0-9_]*$/u.test(word.value)) {
          environment.temps.delete(word.value);
          environment.bindings.delete(word.value);
        }
      }
      return;
    }
    if (!['export', 'readonly', 'declare', 'typeset', 'local'].includes(invocation.head)) {
      return;
    }
    const functionScope = this.#functionScopes.at(-1);
    for (const word of invocation.words.slice(1)) {
      const name = /^(?<name>[A-Za-z_][A-Za-z0-9_]*)/u.exec(word.source)?.groups?.['name'];
      if (name !== undefined) {
        if (invocation.head === 'local') {
          functionScope?.localNames.add(name);
        }
        environment.temps.delete(name);
        environment.bindings.delete(name);
      }
    }
  }

  #findBypass(): boolean {
    const masked = this.#source.split('');
    for (const range of this.#heredocRanges) {
      for (let index = range.start; index < range.end && index < masked.length; index += 1) {
        if (masked[index] !== '\n' && masked[index] !== '\r') {
          masked[index] = ' ';
        }
      }
    }
    return /(?<prefix>^|\s)#\s*tripwire-allow:[ \t]*\S[^\r\n]*/u.test(masked.join(''));
  }
}

const analyzeBash = (source: string, options: BashAnalysisOptions = {}): ShellProgram => {
  try {
    return new BashAnalyzer(source, options).analyze(parse(source));
  } catch (cause) {
    return {
      source,
      invocations: [],
      redirects: [],
      diagnostics: [
        {
          kind: 'parse-error',
          message: cause instanceof Error ? cause.message : 'The Bash parser failed.',
          range: { start: 0, end: source.length },
        },
      ],
      hasBypass: false,
    };
  }
};

export { analyzeBash };
