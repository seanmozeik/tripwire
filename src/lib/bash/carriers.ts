import type { Command } from 'unbash';

import type { ExecutionContext, ExecutionHost } from './execution-types';
import { basename, staticCommandWords } from './static-command';
import type { ExecutionCarrierAlias, ShellInvocation, ShellWord } from './types';
import type { Environment } from './values';
import { SHELL_WRAPPER_HEADS, commandFlagValueIndex } from './wrappers';

interface CarrierMatch {
  readonly kind: 'ssh';
  readonly words: readonly ShellWord[];
}

interface SshOptionInspection {
  readonly nextIndex: number;
  readonly opaqueConfig: ShellWord | undefined;
  readonly source: ShellWord | undefined;
}

const SSH_VALUE_FLAGS: ReadonlySet<string> = new Set([
  '-B',
  '-b',
  '-c',
  '-D',
  '-E',
  '-e',
  '-F',
  '-I',
  '-i',
  '-J',
  '-L',
  '-l',
  '-m',
  '-O',
  '-o',
  '-p',
  '-Q',
  '-R',
  '-S',
  '-W',
  '-w',
]);

const inspectableSshOption = (words: readonly ShellWord[], index: number): SshOptionInspection => {
  const word = words[index];
  if (word === undefined) {
    return { nextIndex: index, opaqueConfig: undefined, source: undefined };
  }
  if (word.value === '-F' || word.value.startsWith('-F')) {
    return {
      nextIndex: word.value === '-F' ? index + 1 : index,
      opaqueConfig: word,
      source: undefined,
    };
  }
  let nextIndex = index;
  let option: ShellWord | undefined;
  if (word.value === '-o') {
    nextIndex += 1;
    option = words[nextIndex];
  } else if (word.value.startsWith('-o')) {
    option = { ...word, source: word.source.slice(2), value: word.value.slice(2) };
  }
  const parsed =
    option === undefined
      ? null
      : /^(?<key>[A-Za-z]+)(?:=|\s+)(?<source>[\s\S]+)$/u.exec(option.value);
  const key = parsed?.groups?.['key']?.toLowerCase();
  const source = parsed?.groups?.['source'];
  const executableSource =
    option !== undefined &&
    source !== undefined &&
    source !== 'none' &&
    key !== undefined &&
    ['localcommand', 'proxycommand', 'remotecommand'].includes(key)
      ? { ...option, source, value: source }
      : undefined;
  return { nextIndex, opaqueConfig: undefined, source: executableSource };
};

const sshCommandStart = (words: readonly ShellWord[]): number | null => {
  let index = 1;
  while (index < words.length) {
    const word = words[index];
    if (word?.kind !== 'literal') {
      return null;
    }
    if (word.value === '--') {
      index += 1;
      break;
    }
    if (SSH_VALUE_FLAGS.has(word.value)) {
      if (words[index + 1]?.kind !== 'literal') {
        return null;
      }
      index += 2;
    } else if (word.value.startsWith('-') && word.value !== '-') {
      index += 1;
    } else {
      break;
    }
  }
  const destination = words[index];
  return destination?.kind === 'literal' ? index + 1 : null;
};

class ExecutionCarriers {
  readonly #aliases: readonly ExecutionCarrierAlias[];
  readonly #host: ExecutionHost;

  constructor(host: ExecutionHost, aliases: readonly ExecutionCarrierAlias[]) {
    this.#host = host;
    this.#aliases = [...aliases].toSorted(
      (left, right) => right.command.length - left.command.length,
    );
  }

  isCarrierCommand(command: Command): boolean {
    const words = staticCommandWords(command);
    return words !== null && this.#match(words) !== null;
  }

  inspect(
    invocation: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ): boolean {
    const carrier = this.#match(invocation.words);
    if (carrier === null) {
      return false;
    }
    this.#inspectOptionSources(carrier.words, environment, context);
    const commandStart = sshCommandStart(carrier.words);
    if (commandStart === null) {
      if (carrier.words.some((word) => word.value === '-Q' || word.value === '-V')) {
        return true;
      }
      this.#host.addDiagnostic(
        'dynamic-shell-source',
        'Tripwire cannot identify the SSH destination and remote command safely.',
        invocation.range,
      );
      return true;
    }
    const remoteWords = carrier.words.slice(commandStart);
    if (remoteWords.length === 0) {
      const noRemoteCommand = carrier.words.some(
        (word) =>
          word.value === '-N' ||
          word.value === '-G' ||
          word.value === '-Q' ||
          word.value === '-V' ||
          word.value === '-W' ||
          word.value.startsWith('-W'),
      );
      if (!context.inspectedPipelineInput && !noRemoteCommand) {
        this.#host.addDiagnostic(
          'dynamic-shell-source',
          'An interactive remote shell has no command source that Tripwire can inspect.',
          invocation.range,
        );
      }
      return true;
    }
    const dynamic = remoteWords.find((word) => word.kind !== 'literal');
    if (dynamic !== undefined) {
      this.#host.addDiagnostic(
        'dynamic-shell-source',
        'The remote shell command is computed at runtime.',
        dynamic.range,
      );
      return true;
    }
    if (
      context.inspectedPipelineInput &&
      SHELL_WRAPPER_HEADS.has(basename(remoteWords[0]?.value ?? '')) &&
      commandFlagValueIndex(remoteWords, 'c') === null
    ) {
      this.#host.emitSynthetic(remoteWords, invocation, environment, {
        ...context,
        inspectedPipelineInput: true,
      });
      return true;
    }
    const [first] = remoteWords;
    const last = remoteWords.at(-1);
    if (first !== undefined && last !== undefined) {
      const source = remoteWords.map((word) => word.value).join(' ');
      this.#host.inspectShellSource(
        {
          source,
          value: source,
          kind: 'literal',
          range: { start: first.range.start, end: last.range.end },
          quoted: true,
        },
        environment,
        { ...context, inspectedPipelineInput: false },
      );
    }
    return true;
  }

  #match(words: readonly ShellWord[]): CarrierMatch | null {
    const [first] = words;
    if (first !== undefined && basename(first.value) === 'ssh') {
      return { kind: 'ssh', words };
    }
    for (const alias of this.#aliases) {
      if (
        alias.command.every((token, index) => words[index]?.value === token) &&
        alias.command.length <= words.length
      ) {
        const [executable] = words;
        if (executable === undefined) {
          return null;
        }
        return {
          kind: alias.equivalentTo,
          words: [
            { ...executable, source: alias.equivalentTo, value: alias.equivalentTo },
            ...words.slice(alias.command.length),
          ],
        };
      }
    }
    return null;
  }

  #inspectOptionSources(
    words: readonly ShellWord[],
    environment: Environment,
    context: ExecutionContext,
  ): void {
    for (let index = 1; index < words.length; index += 1) {
      const inspection = inspectableSshOption(words, index);
      index = inspection.nextIndex;
      if (inspection.opaqueConfig !== undefined) {
        this.#host.addDiagnostic(
          'dynamic-shell-source',
          'An explicit SSH configuration file may contain executable commands that Tripwire has not inspected.',
          inspection.opaqueConfig.range,
        );
      } else if (inspection.source !== undefined) {
        this.#host.inspectShellSource(inspection.source, environment, {
          ...context,
          inspectedPipelineInput: false,
        });
      }
    }
  }
}

export { ExecutionCarriers };
