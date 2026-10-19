import { homedir } from 'node:os';
import path from 'node:path';

import {
  parse,
  type ArithmeticExpression,
  type AssignmentPrefix,
  type Command,
  type CommandArgument,
  type SyntaxNode,
  type ParsedScript,
  type Redirection,
  type Statement,
  type TestExpression,
  type Word,
  type WordPart,
} from 'unbash';

import {
  assignedNameOf,
  dynamicBinding,
  invalidateArithmeticBinding,
  joinBindings,
  restoreDeclaredBinding,
  variableWriteTargets,
  visitRepeatedBindings,
} from './bindings';
import { changeDirectory, recordCreatedDirectories } from './cwd';
import {
  environmentsAgree,
  propagateFunctionEffects,
  propagateMap,
  replaceEnvironment,
} from './environment-merge';
import { ExecutionInspector } from './execution';
import { joinStartup } from './startup';
import {
  isDirectoryChange,
  mayChangeDirectory,
  mayChangeHome,
  mayMutateHomeIndirectly,
} from './state-effects';
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
import { skipHeadRenamingPrefix } from './wrappers';

interface VisitContext {
  readonly inspectedPipelineInput: boolean;
  readonly source: string;
  readonly pipeline: PipelinePosition | undefined;
}

interface AssignmentEffect {
  readonly binding: ShellWord;
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

const applyAssignment = (effect: AssignmentEffect, environment: Environment): void => {
  environment.temps.delete(effect.name);
  environment.bindings.delete(effect.name);

  if (effect.trustedTemp) {
    environment.temps.set(effect.name, { variable: effect.name });
  } else {
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
    assignment.value.type !== 'Word'
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
  readonly #environmentAssignments = new Set<string>();
  readonly #heredocRanges: SourceRange[] = [];
  readonly #activeScripts = new WeakSet<object>();
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
    environment.cwd = this.#options.cwd;

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

    bindLiteral('HOME', this.#options.home ?? homedir());

    if (environment.cwd !== null) {
      bindLiteral('PWD', environment.cwd);
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
      environmentAssignments: [...this.#environmentAssignments],
      hasBypass: this.#findBypass(),
    };
  }

  #addDiagnostic(kind: ShellDiagnosticKind, message: string, range: SourceRange): void {
    this.#diagnostics.push({ kind, message, range });
  }

  #visitScript(script: ParsedScript, environment: Environment, context: VisitContext): void {
    if (this.#activeScripts.has(script)) {
      return;
    }

    this.#activeScripts.add(script);

    try {
      const source = script.source ?? context.source;

      for (const error of script.errors ?? []) {
        this.#addDiagnostic('parse-error', error.message, { start: error.pos, end: error.pos });
      }

      this.#visitStatements(script.commands, environment, { ...context, source });
    } finally {
      this.#activeScripts.delete(script);
    }
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
    // Bash runs a background statement in a subshell, so its directory and
    // variable changes never reach the commands after it.
    const scope = statement.background === true ? cloneEnvironment(environment) : environment;
    this.#visitNode(statement.command, scope, context);

    if (statement.background === true) {
      environment.backgroundPidAvailable = true;
    }
  }

  #visitNode(node: SyntaxNode, environment: Environment, context: VisitContext): void {
    if (
      this.#visitCommandStructure(node, environment, context) ||
      this.#visitControlFlow(node, environment, context) ||
      this.#visitCompoundStructure(node, environment, context)
    ) {
      return;
    }

    this.#addDiagnostic('parse-error', `Unknown Bash AST node: ${node.type}`, rangeOf(node));
  }

  #visitCommandStructure(
    node: SyntaxNode,
    environment: Environment,
    context: VisitContext,
  ): boolean {
    if (node.type === 'Statement') {
      this.#visitStatement(node, environment, context);

      return true;
    }

    if (node.type === 'Command') {
      this.#visitCommand(node, environment, context);

      return true;
    }

    if (node.type === 'Redirected') {
      this.#visitRedirects(node.redirects, environment, context);
      this.#visitNode(node.command, environment, context);

      return true;
    }

    if (node.type === 'CompoundList') {
      this.#visitStatements(node.commands, environment, context);

      return true;
    }

    if (node.type === 'Pipeline') {
      if (node.commands.length === 1) {
        const [command] = node.commands;

        if (command !== undefined) {
          this.#visitNode(command, environment, context);
        }

        return true;
      }

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
      this.#visitAndOr(node, environment, context);

      return true;
    }

    return false;
  }

  #visitAndOr(
    node: Extract<SyntaxNode, { type: 'AndOr' }>,
    environment: Environment,
    context: VisitContext,
  ): void {
    const working = cloneEnvironment(environment);
    // Every state where the list can stop, and every state where it has succeeded so far.
    let outgoing: Environment | undefined;
    let succeeded: Environment | undefined;

    for (const [index, command] of node.commands.entries()) {
      const operator = node.operators[index - 1];
      let branch = working;

      if (operator === '||') {
        branch = environmentsAgree([environment, working]);
      } else if (operator === '&&' && succeeded !== undefined) {
        // A command after && runs only when the list before it succeeded.
        branch = cloneEnvironment(succeeded);
      }

      const directoryChange = isDirectoryChange(command, branch);
      this.#visitNode(command, branch, context);

      const exits =
        command.type === 'Command' && ['exit', 'return'].includes(command.name?.value ?? '');

      if (exits) {
        succeeded = operator === '||' ? succeeded : undefined;
      } else {
        succeeded =
          operator === '||' && succeeded !== undefined
            ? environmentsAgree([succeeded, branch])
            : cloneEnvironment(branch);
        // The analysis already assumes that a resolved directory change
        // succeeds, so a following && command always runs after it.
        const continues = directoryChange && branch.cwd !== null && node.operators[index] === '&&';

        if (!continues) {
          outgoing =
            outgoing === undefined
              ? cloneEnvironment(branch)
              : environmentsAgree([outgoing, branch]);
        }
      }

      replaceEnvironment(working, outgoing ?? branch);
    }

    replaceEnvironment(environment, outgoing ?? working);
  }

  #visitControlFlow(node: SyntaxNode, environment: Environment, context: VisitContext): boolean {
    if (node.type === 'If') {
      const remaining = cloneEnvironment(environment);
      const branches: Environment[] = [];

      for (const branch of [node, ...node.elif]) {
        this.#visitNode(branch.clause, remaining, context);
        const taken = cloneEnvironment(remaining);
        this.#visitNode(branch.then, taken, context);
        branches.push(taken);
      }

      if (node.else !== undefined) {
        this.#visitNode(node.else, remaining, context);
      }

      branches.push(remaining);
      replaceEnvironment(environment, environmentsAgree(branches));

      return true;
    }

    if (
      ['ArithmeticFor', 'While', 'For', 'Select'].includes(node.type) &&
      mayChangeHome(node, environment)
    ) {
      environment.bindings.delete('HOME');
    }

    if (node.type === 'For' || node.type === 'Select') {
      this.#visitFor(node, environment, context);

      return true;
    }

    if (node.type === 'ArithmeticFor') {
      if (mayChangeDirectory(node.body, environment)) {
        environment.cwd = null;
        environment.directoryStack = [];
      }

      this.#visitArithmetic(node.initialize, environment, context);
      this.#visitArithmetic(node.test, environment, context);
      const loopEnvironment = cloneEnvironment(environment);
      visitRepeatedBindings(loopEnvironment, (iteration) => {
        this.#visitNode(node.body, iteration, context);
        this.#visitArithmetic(node.update, iteration, context);
        this.#visitArithmetic(node.test, iteration, context);
      });
      propagateMap(environment.bindings, joinBindings([environment, loopEnvironment]), new Set());

      return true;
    }

    if (node.type === 'While') {
      const loopEnvironment = cloneEnvironment(environment);

      if (mayChangeDirectory(node, environment)) {
        loopEnvironment.cwd = null;
        loopEnvironment.directoryStack = [];
      }

      visitRepeatedBindings(loopEnvironment, (iteration) => {
        this.#visitNode(node.clause, iteration, context);
        this.#visitNode(node.body, iteration, context);
      });
      environment.cwd = environmentsAgree([environment, loopEnvironment]).cwd;
      propagateMap(environment.bindings, joinBindings([environment, loopEnvironment]), new Set());

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

  #visitFor(
    node: Extract<SyntaxNode, { type: 'For' | 'Select' }>,
    environment: Environment,
    context: VisitContext,
  ): void {
    const changesDirectory = mayChangeDirectory(node.body, environment);

    if (changesDirectory) {
      environment.cwd = null;
      environment.directoryStack = [];
    }

    const name = this.#normalizeWord(node.name, environment, context);

    const values = (node.wordlist ?? []).flatMap((word) =>
      this.#normalizeWordMany(word, environment, context),
    );

    if (
      node.type === 'For' &&
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
        propagateMap(environment.bindings, joinBindings([environment, iteration]), new Set());
      }
    } else {
      const iteration = cloneEnvironment(environment);
      iteration.temps.delete(name.value);
      iteration.bindings.delete(name.value);
      visitRepeatedBindings(iteration, (repeated) => {
        this.#visitNode(node.body, repeated, context);
      });
      propagateMap(environment.bindings, joinBindings([environment, iteration]), new Set());
    }
  }

  #visitCompoundStructure(
    node: SyntaxNode,
    environment: Environment,
    context: VisitContext,
  ): boolean {
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
    const executionEnvironment =
      command.prefix.length === 0 ? environment : cloneEnvironment(environment);

    const assignmentEffects = command.prefix.flatMap((assignment) => {
      if (assignment.type !== 'Assignment') {
        return [];
      }

      const effect = this.#inspectAssignment(assignment, executionEnvironment, context);
      applyAssignment(effect, executionEnvironment);

      return [effect];
    });

    if (command.name === undefined) {
      for (const effect of assignmentEffects) {
        applyAssignment(effect, environment);
      }
    }

    const operandEnvironment = assignmentEffects.some((effect) => effect.name === 'HOME')
      ? cloneEnvironment(environment)
      : environment;

    for (const effect of assignmentEffects) {
      if (effect.name === 'HOME') {
        applyAssignment(effect, operandEnvironment);
      }
    }

    const redirects = this.#visitRedirects(command.redirects, operandEnvironment, context);

    if (command.name === undefined) {
      return;
    }

    const name = this.#normalizeWord(command.name, environment, context);

    const suffix = command.args.flatMap((word) =>
      this.#normalizeArgument(word, operandEnvironment, context),
    );

    if (name.kind === 'literal' && environment.functions.has(name.value)) {
      this.#invokeFunction(name.value, suffix, assignmentEffects, environment, context);

      return;
    }

    if (name.kind === 'literal' && environment.aliases.has(name.value)) {
      this.#invokeAlias(name.value, suffix, executionEnvironment, context, rangeOf(command));
      propagateFunctionEffects(
        environment,
        executionEnvironment,
        new Set(assignmentEffects.map((effect) => effect.name)),
      );

      return;
    }

    const invocation = this.#emitInvocation(
      [name, ...suffix],
      redirects,
      rangeOf(command),
      context,
      false,
      executionEnvironment,
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
      executionEnvironment,
      context,
    );

    this.#execution.inspectWrapper(invocation, executionEnvironment, context, inlineShellSource);
    this.#applyVariableBuiltin(invocation, environment);

    if (
      assignmentEffects.some((effect) => effect.name === 'CDPATH') &&
      ['cd', 'pushd', 'command', 'builtin'].includes(invocation.head)
    ) {
      environment.cwd = null;
    }

    changeDirectory(invocation, environment);
    recordCreatedDirectories(invocation, environment);
  }

  #inspectAssignment(
    assignment: AssignmentPrefix,
    environment: Environment,
    context: VisitContext,
  ): AssignmentEffect {
    if (assignment.index !== undefined) {
      this.#normalizeWord(assignment.index, environment, context);
    }

    if (assignment.value.type === 'ArrayValue') {
      for (const word of assignment.value.elements) {
        this.#normalizeWord(word, environment, context);
      }
    }

    const normalizedValue =
      assignment.value.type === 'Word'
        ? this.#normalizeWord(assignment.value, environment, context)
        : undefined;

    this.#environmentAssignments.add(assignment.name);

    const trustedTemp =
      assignment.append !== true &&
      assignment.index === undefined &&
      assignment.value.type === 'Word' &&
      isTrustedMktemp(assignment.value, environment);

    const exactBinding = isExactAssignmentBinding(assignment, normalizedValue, environment);

    return {
      binding:
        normalizedValue !== undefined && (exactBinding || assignment.name === 'CDPATH')
          ? normalizedValue
          : dynamicBinding({
              source: assignment.text,
              value: DYNAMIC_VALUE,
              kind: 'dynamic',
              range: rangeOf(assignment),
              quoted: false,
            }),
      name: assignment.name,
      trustedTemp,
    };
  }

  #normalizeArgument(
    argument: CommandArgument,
    environment: Environment,
    context: VisitContext,
  ): ShellWord[] {
    if (argument.type === 'Word') {
      return this.#normalizeWordMany(argument, environment, context);
    }

    const effect = this.#inspectAssignment(argument, environment, context);
    const value = effect.binding;

    const exact =
      argument.index === undefined && argument.append !== true && value.kind === 'literal';

    return [
      {
        source: argument.text,
        value: exact ? `${argument.name}=${value.value}` : DYNAMIC_VALUE,
        kind: exact ? 'literal' : 'dynamic',
        range: rangeOf(argument),
        quoted: value.quoted,
      },
    ];
  }

  #normalizeWordMany(word: Word, environment: Environment, context: VisitContext): ShellWord[] {
    const normalized = this.#normalizeWord(word, environment, context);

    if (normalized.kind !== 'literal' || normalized.quoted || !/[*?[]/u.test(normalized.value)) {
      return [normalized];
    }

    const cwd = path.isAbsolute(normalized.value)
      ? path.parse(normalized.value).root
      : environment.cwd;

    if (normalized.value.includes('**') || cwd === null) {
      return [{ ...normalized, kind: 'dynamic' }];
    }

    try {
      const matches: string[] = [];

      for (const match of new Bun.Glob(normalized.value).scanSync({
        cwd,
        onlyFiles: false,
        dot: true,
      })) {
        if (matches.length === 128) {
          return [{ ...normalized, kind: 'dynamic' }];
        }

        matches.push(match);
      }

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
      return [{ ...normalized, kind: 'dynamic' }];
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
      if (word.text.startsWith('~')) {
        const home = environment.bindings.get('HOME');

        const known =
          /^(?:~$|~\/)/u.test(word.value) && home?.kind === 'literal' && home.value.startsWith('/');

        return {
          source: word.text,
          value: known ? home.value + word.value.slice(1) : DYNAMIC_VALUE,
          kind: known ? 'literal' : 'dynamic',
          range: rangeOf(word),
          quoted: (word.parts ?? []).some((part) => isQuotedPart(part)),
        };
      }

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
        if (part.script === undefined) {
          this.#addDiagnostic(
            'dynamic-shell-source',
            'The nested shell source could not be parsed.',
            rangeOf(part),
          );
        } else {
          this.#visitScript(part.script, cloneEnvironment(environment), context);
        }

        return;
      }

      case 'ArithmeticExpansion': {
        this.#visitArithmetic(part.expression, environment, context);

        return;
      }

      case 'ExtendedGlob':
      case 'BraceExpansion':
      case 'Glob': {
        for (const child of part.parts ?? []) {
          this.#visitWordPart(child, environment, context);
        }

        break;
      }

      default: {
        this.#addDiagnostic('parse-error', 'Unsupported Bash word part.', rangeOf(part));
        break;
      }
    }
  }

  #visitParameterExpansion(
    part: ParameterExpansionPart,
    environment: Environment,
    context: VisitContext,
  ): void {
    const { operation } = part;

    if (
      operation?.type === 'Default' &&
      ['=', ':='].includes(operation.operator) &&
      /^[A-Za-z_][A-Za-z0-9_]*$/u.test(part.parameter)
    ) {
      const binding = environment.bindings.get(part.parameter);

      if (part.parameter === 'HOME') {
        environment.bindings.delete('HOME');
      } else if (
        binding?.kind !== 'literal' ||
        (operation.operator === ':=' && binding.value === '')
      ) {
        environment.bindings.set(part.parameter, {
          source: part.parameter,
          value: DYNAMIC_VALUE,
          kind: 'dynamic',
          range: rangeOf(operation.operand),
          quoted: false,
        });
      }
    }

    if (part.index !== undefined) {
      this.#normalizeWord(part.index, environment, context);
    }

    if (operation === undefined) {
      return;
    }

    if ('operand' in operation && operation.operand !== undefined) {
      this.#normalizeWord(operation.operand, environment, context);
    } else if (operation.type === 'Slice') {
      this.#normalizeWord(operation.offset, environment, context);

      if (operation.length !== undefined) {
        this.#normalizeWord(operation.length, environment, context);
      }
    } else if (operation.type === 'Replace') {
      this.#normalizeWord(operation.pattern, environment, context);
      this.#normalizeWord(operation.replacement, environment, context);
    } else if (operation.type === 'Unknown') {
      this.#addDiagnostic('parse-error', 'Unresolved parameter operation.', rangeOf(operation));
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

    if (JSON.stringify(expression).includes('HOME')) {
      environment.bindings.delete('HOME');
    }

    switch (expression.type) {
      case 'ArithmeticBinary': {
        if (/^(?:=|\+=|-=|\*=|\/=|%=|<<=|>>=|&=|\^=|\|=)$/u.test(expression.operator)) {
          this.#invalidateArithmeticTarget(expression.left, environment);
        }

        this.#visitArithmetic(expression.left, environment, context);
        this.#visitArithmetic(expression.right, environment, context);

        return;
      }

      case 'ArithmeticUnary': {
        if (expression.operator === '++' || expression.operator === '--') {
          this.#invalidateArithmeticTarget(expression.operand, environment);
        }

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
        const { parts } = expression;

        if (parts === undefined && /[^A-Za-z0-9_#@[\]]/u.test(expression.value)) {
          this.#addDiagnostic(
            'parse-error',
            'The arithmetic source could not be fully inspected.',
            rangeOf(expression),
          );

          return;
        }

        for (const part of parts ?? []) {
          this.#visitWordPart(part, environment, context);
        }

        return;
      }

      case 'ArithmeticCommandExpansion': {
        if (expression.script === undefined) {
          this.#addDiagnostic(
            'dynamic-shell-source',
            'The nested arithmetic command could not be parsed.',
            rangeOf(expression),
          );
        } else {
          this.#visitScript(expression.script, cloneEnvironment(environment), context);
        }

        break;
      }

      default: {
        this.#addDiagnostic(
          'parse-error',
          'Unsupported arithmetic expression.',
          rangeOf(expression),
        );
        break;
      }
    }
  }

  #invalidateArithmeticTarget(expression: ArithmeticExpression, environment: Environment): void {
    if (!invalidateArithmeticBinding(expression, environment)) {
      this.#addDiagnostic(
        'dynamic-shell-source',
        'A computed environment variable name can change how later commands execute.',
        rangeOf(expression),
      );
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
        for (const operand of expression.operands) {
          this.#visitTest(operand, environment, context);
        }

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
    redirects: readonly Redirection[],
    environment: Environment,
    context: VisitContext,
  ): ShellRedirect[] {
    const normalized: ShellRedirect[] = [];

    for (const redirect of redirects) {
      if (redirect.type === 'HereDoc') {
        this.#heredocRanges.push(rangeOf(redirect.body));

        for (const part of redirect.body.parts ?? []) {
          this.#visitWordPart(part, environment, context);
        }
      }

      const word = redirect.type === 'HereDoc' ? redirect.delimiter : redirect.target;

      let target: ShellWord;

      if (word === undefined) {
        target = {
          source: '',
          value: DYNAMIC_VALUE,
          kind: 'dynamic',
          range: rangeOf(redirect),
          quoted: false,
        };
      } else if (word.type === 'HereDocDelimiter') {
        target = {
          source: word.text,
          value: word.value,
          kind: 'literal',
          range: rangeOf(word),
          quoted: word.quoted,
        };
      } else {
        target = this.#normalizeWord(word, environment, context);
      }

      let op: ShellRedirect['op'];

      if (redirect.operator === '<<-') {
        op = '<<';
      } else if (redirect.operator === '>|') {
        op = '>';
      } else {
        op = redirect.operator;
      }

      const shellRedirect: ShellRedirect = {
        op,
        target,
        cwd: environment.cwd,
        range: rangeOf(redirect),
        ...(redirect.type === 'HereDoc' && {
          heredoc: { content: redirect.body.text, quoted: redirect.delimiter?.quoted === true },
        }),
      };

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
    environment: Environment,
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
    const home = environment.bindings.get('HOME');

    const invocation: ShellInvocation = {
      bindings: new Map(environment.bindings),
      ...(home?.kind === 'literal' && { home: home.value }),
      cwd: environment.cwd,
      startup: joinStartup(environment.startup),
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
        ...command.args.flatMap((word) => this.#normalizeArgument(word, environment, aliasContext)),
        ...arguments_,
      ];

      const parent: ShellInvocation = {
        bindings: new Map(environment.bindings),
        startup: joinStartup(environment.startup),
        cwd: environment.cwd,
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
      const [head] = words;

      if (head?.kind === 'literal') {
        changeDirectory({ ...parent, head: head.value, words }, environment);
      }
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
      parent.redirects,
      parent.range,
      { ...context, pipeline: parent.pipeline },
      true,
      environment,
    );

    if (invocation !== null) {
      this.#applyVariableBuiltin(invocation, environment);
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

    if (['command', 'builtin'].includes(invocation.head)) {
      const words = invocation.words.slice(skipHeadRenamingPrefix(invocation));
      const [head] = words;

      if (head?.kind === 'literal') {
        this.#applyVariableBuiltin({ ...invocation, head: head.value, words }, environment);
      }

      return;
    }

    if (mayMutateHomeIndirectly(invocation)) {
      environment.bindings.delete('HOME');
    }

    if (invocation.head === 'let') {
      // The let builtin receives arithmetic source as data; the AST does not expose its destinations.
      for (const [name, word] of environment.bindings) {
        environment.bindings.set(name, dynamicBinding(word));
      }

      environment.temps.clear();

      return;
    }

    if (this.#applyVariableWrite(invocation, environment)) {
      return;
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
      const name = assignedNameOf(word);

      if (name === undefined && word.kind === 'dynamic') {
        this.#addDiagnostic(
          'dynamic-shell-source',
          'A computed environment variable name can change how later commands execute.',
          word.range,
        );
      }

      if (name !== undefined) {
        this.#environmentAssignments.add(name);

        if (invocation.head === 'local') {
          functionScope?.localNames.add(name);
        }

        const previous = environment.bindings.get(name);
        environment.temps.delete(name);
        environment.bindings.delete(name);
        restoreDeclaredBinding(invocation, word, previous, environment);
      }
    }
  }

  #applyVariableWrite(invocation: ShellInvocation, environment: Environment): boolean {
    const targets = variableWriteTargets(invocation);

    if (targets === null) {
      return false;
    }

    for (const target of targets) {
      const name = assignedNameOf(target);

      if (target.kind !== 'literal' || name !== target.value) {
        this.#addDiagnostic(
          'dynamic-shell-source',
          'A computed environment variable name can change how later commands execute.',
          target.range,
        );
      } else {
        environment.temps.delete(name);
        environment.bindings.set(name, dynamicBinding(target));
        this.#environmentAssignments.add(name);
      }
    }

    return true;
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

const analyzeBash = (source: string, options: BashAnalysisOptions): ShellProgram => {
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
