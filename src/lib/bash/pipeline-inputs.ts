import type { Command, Node } from 'unbash';

import type { ExecutionCarriers } from './carriers';
import type { ExecutionContext, ExecutionHost } from './execution-types';
import { basename, rangeOf, staticCommandWords } from './static-command';
import type { Environment } from './values';
import { SHELL_WRAPPER_HEADS, commandFlagValueIndex } from './wrappers';

const literalBase64Input = (producer: Command, decoder: Command): string | null => {
  const producerWords = staticCommandWords(producer);
  const decoderWords = staticCommandWords(decoder);
  if (
    producerWords === null ||
    decoderWords === null ||
    basename(decoderWords[0]?.value ?? '') !== 'base64' ||
    decoderWords.length !== 2 ||
    !['-d', '-D', '--decode'].includes(decoderWords[1]?.value ?? '')
  ) {
    return null;
  }
  const producerHead = basename(producerWords[0]?.value ?? '');
  const producerArgs = producerWords.slice(1).map((word) => word.value);
  if (producerHead === 'printf' && producerArgs.length === 2) {
    const [format, value] = producerArgs;
    return format === '%s' || format === String.raw`%s\n` ? (value ?? null) : null;
  }
  if (producerHead === 'echo') {
    const values = producerArgs.filter((value) => value !== '-n');
    return values.length === 1 ? (values[0] ?? null) : null;
  }
  return null;
};

const decodeBase64 = (encoded: string): string | null => {
  if (
    encoded.length === 0 ||
    encoded.length > 1_048_576 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(encoded)
  ) {
    return null;
  }
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.toString('base64') !== encoded || bytes.includes(0)) {
    return null;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
};

class PipelineInputInspector {
  readonly #carriers: ExecutionCarriers;
  readonly #host: ExecutionHost;

  constructor(host: ExecutionHost, carriers: ExecutionCarriers) {
    this.#host = host;
    this.#carriers = carriers;
  }

  inspect(
    commands: readonly Node[],
    environment: Environment,
    context: ExecutionContext,
  ): ReadonlySet<number> {
    const inspected = new Set<number>();
    this.#inspectHeredocs(commands, environment, context, inspected);
    this.#inspectBase64(commands, environment, context, inspected);
    return inspected;
  }

  #inspectHeredocs(
    commands: readonly Node[],
    environment: Environment,
    context: ExecutionContext,
    inspected: Set<number>,
  ): void {
    for (let index = 0; index < commands.length - 1; index += 1) {
      const left = commands[index];
      const right = commands[index + 1];
      if (
        left?.type === 'Command' &&
        right?.type === 'Command' &&
        right.name !== undefined &&
        SHELL_WRAPPER_HEADS.has(basename(right.name.value))
      ) {
        for (const redirect of left.redirects) {
          if (
            (redirect.operator === '<<' || redirect.operator === '<<-') &&
            redirect.content !== undefined
          ) {
            this.#host.inspectShellSource(
              {
                source: redirect.content,
                value: redirect.content,
                kind: 'literal',
                range: rangeOf(redirect),
                quoted: redirect.heredocQuoted === true,
              },
              environment,
              context,
            );
            inspected.add(index + 1);
          }
        }
      }
    }
  }

  #inspectBase64(
    commands: readonly Node[],
    environment: Environment,
    context: ExecutionContext,
    inspected: Set<number>,
  ): void {
    for (let index = 0; index < commands.length - 2; index += 1) {
      const producer = commands[index];
      const decoder = commands[index + 1];
      const sink = commands[index + 2];
      if (
        producer?.type === 'Command' &&
        decoder?.type === 'Command' &&
        sink?.type === 'Command' &&
        this.#isShellInputSink(sink)
      ) {
        const encoded = literalBase64Input(producer, decoder);
        const decoded = encoded === null ? null : decodeBase64(encoded);
        if (decoded !== null) {
          this.#host.inspectShellSource(
            {
              source: decoded,
              value: decoded,
              kind: 'literal',
              range: rangeOf(producer),
              quoted: true,
            },
            environment,
            context,
          );
          inspected.add(index + 2);
        }
      }
    }
  }

  #isShellInputSink(command: Command): boolean {
    const words = staticCommandWords(command);
    if (words === null) {
      return false;
    }
    if (SHELL_WRAPPER_HEADS.has(basename(words[0]?.value ?? ''))) {
      return commandFlagValueIndex(words, 'c') === null;
    }
    return this.#carriers.isCarrierCommand(command);
  }
}

export { PipelineInputInspector };
