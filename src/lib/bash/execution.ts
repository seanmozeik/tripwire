import type { Node, Redirect } from 'unbash';

import { ExecutionCarriers } from './carriers';
import type { ExecutionContext, ExecutionHost } from './execution-types';
import { PipelineInputInspector } from './pipeline-inputs';
import { rangeOf } from './static-command';
import type { ExecutionCarrierAlias, ShellInvocation, ShellWord } from './types';
import { DYNAMIC_VALUE, type Environment } from './values';
import {
  FD_EXEC_FLAGS,
  FD_PLACEHOLDERS,
  FIND_EXEC_FLAGS,
  FIND_PLACEHOLDERS,
  HEAD_RENAMING_HEADS,
  PREFIX_WRAPPERS,
  RTK_WRAPPER_SUBCOMMANDS,
  SHELL_WRAPPER_HEADS,
  commandFlagValueIndex,
  namedFlagValueIndex,
  pickExecRoot,
  skipHeadRenamingPrefix,
  skipOptions,
  type PrefixWrapper,
} from './wrappers';

class ExecutionInspector {
  readonly #carriers: ExecutionCarriers;
  readonly #host: ExecutionHost;
  readonly #pipelineInputs: PipelineInputInspector;

  constructor(host: ExecutionHost, carrierAliases: readonly ExecutionCarrierAlias[]) {
    this.#host = host;
    this.#carriers = new ExecutionCarriers(host, carrierAliases);
    this.#pipelineInputs = new PipelineInputInspector(host, this.#carriers);
  }

  inspectShellInput(
    invocation: ShellInvocation,
    redirects: readonly Redirect[],
    environment: Environment,
    context: ExecutionContext,
  ): boolean {
    if (!SHELL_WRAPPER_HEADS.has(invocation.head)) {
      return false;
    }
    let inspected = context.inspectedPipelineInput;
    for (const [index, redirect] of redirects.entries()) {
      if (
        (redirect.operator === '<<' || redirect.operator === '<<-') &&
        redirect.content !== undefined
      ) {
        const word: ShellWord = {
          source: redirect.content,
          value: redirect.content,
          kind: 'literal',
          range: rangeOf(redirect),
          quoted: redirect.heredocQuoted === true,
        };
        this.#host.inspectShellSource(word, environment, context);
        inspected = true;
      } else if (redirect.operator === '<<<') {
        this.#host.inspectShellSource(invocation.redirects[index]?.target, environment, context);
        inspected = true;
      } else if (redirect.operator === '<') {
        this.#host.addDiagnostic(
          'dynamic-shell-source',
          'A shell wrapper reads program source from a file that Tripwire has not inspected.',
          rangeOf(redirect),
        );
      }
    }
    return inspected;
  }

  inspectWrapper(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
    inlineShellSource = false,
  ): void {
    if (
      invocation.head === 'eval' ||
      this.#carriers.inspect(invocation, environment, context) ||
      this.#inspectShellWrapper(invocation, environment, context, inlineShellSource) ||
      this.#inspectCommandTextWrapper(invocation, environment, context)
    ) {
      return;
    }
    this.#inspectExecutableWrapper(invocation, environment, context);
  }

  inspectPipelineInputs(
    commands: readonly Node[],
    environment: Environment,
    context: ExecutionContext,
  ): ReadonlySet<number> {
    return this.#pipelineInputs.inspect(commands, environment, context);
  }

  #inspectShellWrapper(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
    inlineShellSource: boolean,
  ): boolean {
    if (!SHELL_WRAPPER_HEADS.has(invocation.head)) {
      return false;
    }
    const scriptIndex = commandFlagValueIndex(invocation.words, 'c');
    if (scriptIndex !== null) {
      this.#host.inspectShellSource(invocation.words[scriptIndex], environment, context);
      return true;
    }
    const hasInspectionOnlyFlag =
      inlineShellSource ||
      invocation.tokens.includes('-n') ||
      invocation.tokens.includes('--noexec') ||
      invocation.tokens.includes('--help') ||
      invocation.tokens.includes('--version');
    if (!hasInspectionOnlyFlag) {
      this.#host.addDiagnostic(
        'dynamic-shell-source',
        'A shell wrapper has no inline program source that Tripwire can inspect.',
        invocation.range,
      );
    }
    return true;
  }

  #inspectCommandTextWrapper(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ): boolean {
    switch (invocation.head) {
      case 'trap': {
        this.#inspectTrap(invocation, environment, context);
        return true;
      }
      case 'script': {
        const index = namedFlagValueIndex(invocation.words, new Set(['-c', '--command']));
        if (index !== null) {
          this.#host.inspectShellSource(invocation.words[index], environment, context);
        }
        return true;
      }
      case 'watch': {
        this.#inspectWatch(invocation, environment, context);
        return true;
      }
      case 'xargs': {
        this.#inspectXargs(invocation, environment, context);
        return true;
      }
      default: {
        return false;
      }
    }
  }

  #inspectWatch(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ): void {
    const start = skipHeadRenamingPrefix(invocation);
    const commandWords = invocation.words.slice(start);
    if (invocation.tokens.includes('-x') || invocation.tokens.includes('--exec')) {
      this.#host.emitSynthetic(commandWords, invocation, environment, context);
      return;
    }
    const [first] = commandWords;
    const last = commandWords.at(-1);
    const dynamic = commandWords.find((word) => word.kind === 'dynamic');
    if (dynamic !== undefined) {
      this.#host.addDiagnostic(
        'dynamic-shell-source',
        'watch receives command text that is computed at runtime.',
        dynamic.range,
      );
      return;
    }
    if (first !== undefined && last !== undefined) {
      const value = commandWords.map((word) => word.value).join(' ');
      this.#host.inspectShellSource(
        {
          source: value,
          value,
          kind: 'literal',
          range: { start: first.range.start, end: last.range.end },
          quoted: true,
        },
        environment,
        context,
      );
    }
  }

  #inspectExecutableWrapper(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ): void {
    if (HEAD_RENAMING_HEADS.has(invocation.head)) {
      const start = skipHeadRenamingPrefix(invocation);
      this.#host.emitSynthetic(invocation.words.slice(start), invocation, environment, context);
    } else if (invocation.head === 'fd' || invocation.head === 'fdfind') {
      this.#inspectExecFlag(invocation, FD_EXEC_FLAGS, FD_PLACEHOLDERS, environment, context);
    } else if (invocation.head === 'find' || invocation.head === 'gfind') {
      this.#inspectExecFlag(invocation, FIND_EXEC_FLAGS, FIND_PLACEHOLDERS, environment, context);
    } else if (invocation.head === 'rtk') {
      this.#inspectRtk(invocation, environment, context);
    } else {
      const prefix = Object.hasOwn(PREFIX_WRAPPERS, invocation.head)
        ? PREFIX_WRAPPERS[invocation.head]
        : undefined;
      if (prefix !== undefined) {
        this.#inspectPrefixWrapper(invocation, prefix, environment, context);
      }
    }
  }

  #inspectTrap(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ): void {
    const [, firstArgument, secondArgument] = invocation.words;
    const action = firstArgument?.value === '--' ? secondArgument : firstArgument;
    if (
      action === undefined ||
      action.value === '' ||
      action.value === '-' ||
      action.value === '-p' ||
      action.value === '-l'
    ) {
      return;
    }
    this.#host.inspectShellSource(action, environment, context);
  }

  #inspectXargs(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ): void {
    const start = skipHeadRenamingPrefix(invocation);
    const commandWords = invocation.words.slice(start);
    const executable =
      commandWords[0] ??
      ({
        kind: 'literal',
        quoted: false,
        range: invocation.range,
        source: 'echo',
        value: 'echo',
      } satisfies ShellWord);
    const generatedArgument: ShellWord = {
      kind: 'dynamic',
      quoted: false,
      range: invocation.range,
      source: '<xargs-input>',
      value: DYNAMIC_VALUE,
    };
    this.#host.emitSynthetic(
      [executable, ...commandWords.slice(1), generatedArgument],
      invocation,
      environment,
      context,
    );
  }

  #inspectExecFlag(
    invocation: ShellInvocation,
    flags: ReadonlySet<string>,
    placeholders: ReadonlySet<string>,
    environment: Environment,
    context: ExecutionContext,
  ): void {
    for (let index = 1; index < invocation.words.length; index += 1) {
      const current = invocation.words[index];
      if (current !== undefined && flags.has(current.value)) {
        const inner: ShellWord[] = [];
        const root = pickExecRoot(invocation.words, index, flags === FD_EXEC_FLAGS ? 'fd' : 'find');
        for (let cursor = index + 1; cursor < invocation.words.length; cursor += 1) {
          const word = invocation.words[cursor];
          if (word === undefined || word.value === ';' || word.value === '+') {
            break;
          }
          inner.push(placeholders.has(word.value) ? root : word);
        }
        this.#host.emitSynthetic(inner, invocation, environment, context);
      }
    }
  }

  #inspectRtk(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ): void {
    let index = 1;
    while (invocation.words[index]?.value.startsWith('-') === true) {
      index += 1;
    }
    const subcommand = invocation.words[index]?.value;
    if (subcommand === undefined) {
      return;
    }
    if (RTK_WRAPPER_SUBCOMMANDS.has(subcommand)) {
      const commandIndex = namedFlagValueIndex(
        invocation.words,
        new Set(['-c', '--command']),
        index + 1,
      );
      if (commandIndex !== null) {
        this.#host.inspectShellSource(invocation.words[commandIndex], environment, context);
        return;
      }
      this.#host.emitSynthetic(invocation.words.slice(index + 1), invocation, environment, context);
      return;
    }
    this.#host.emitSynthetic(invocation.words.slice(index), invocation, environment, context);
  }

  #inspectPrefixWrapper(
    invocation: ShellInvocation,
    spec: PrefixWrapper,
    environment: Environment,
    context: ExecutionContext,
  ): void {
    if (spec.shellFlag) {
      const commandIndex = namedFlagValueIndex(invocation.words, new Set(['-c', '--command']));
      if (commandIndex !== null) {
        this.#host.inspectShellSource(invocation.words[commandIndex], environment, context);
        return;
      }
    }
    let index = skipOptions(invocation.words, 1, spec.valueFlags);
    index += spec.skipPositionals;
    this.#host.emitSynthetic(invocation.words.slice(index), invocation, environment, context);
  }
}

export { ExecutionInspector };
export type { ExecutionContext } from './execution-types';
