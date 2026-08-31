import { readFile } from 'node:fs/promises';

import { Data, Effect } from 'effect';

import { decideBash } from '../dispatch';
import { loadConfigResult, type ResolvedConfig } from '../lib/config';
import { currentEnvironment } from '../lib/environment';

class CheckedScriptError extends Data.TaggedError('CheckedScriptError')<{
  readonly message: string;
}> {}

const decodeScript = (bytes: Uint8Array): Effect.Effect<string, CheckedScriptError> =>
  Effect.try({
    try: () => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
    catch: () =>
      new CheckedScriptError({
        message: 'The checked script is not valid UTF-8, so Tripwire cannot parse it.',
      }),
  });

const readScript = (path: string): Effect.Effect<Uint8Array, CheckedScriptError> =>
  Effect.tryPromise({
    try: () => readFile(path),
    catch: (cause) =>
      new CheckedScriptError({
        message: `Tripwire could not read the checked script: ${String(cause)}`,
      }),
  });

const loadCheckedScriptConfig = (): Effect.Effect<ResolvedConfig, CheckedScriptError> =>
  loadConfigResult().pipe(
    Effect.flatMap((result) =>
      result.ok
        ? Effect.succeed(result.config)
        : Effect.fail(
            new CheckedScriptError({
              message: `Tripwire configuration failed to load: ${result.error}`,
            }),
          ),
    ),
  );

const executeBytes = (
  bytes: Uint8Array,
  arguments_: readonly string[],
): Effect.Effect<number, CheckedScriptError> =>
  Effect.tryPromise({
    try: async () => {
      const child = Bun.spawn(['/bin/bash', '-s', '--', ...arguments_], {
        cwd: process.cwd(),
        env: currentEnvironment(),
        stderr: 'inherit',
        stdin: 'pipe',
        stdout: 'inherit',
      });
      await child.stdin.write(bytes);
      await child.stdin.end();
      return child.exited;
    },
    catch: (cause) =>
      new CheckedScriptError({
        message: `Tripwire could not start the checked script: ${String(cause)}`,
      }),
  });

const runCheckedScript = (
  path: string,
  arguments_: readonly string[],
): Effect.Effect<void, CheckedScriptError> =>
  Effect.gen(function* runCheckedScriptEffect() {
    const bytes = yield* readScript(path);
    const source = yield* decodeScript(bytes);
    const config = yield* loadCheckedScriptConfig();
    const decision = decideBash(source, config, {
      cwd: process.cwd(),
      positionalArguments: arguments_,
    });
    if (decision.kind === 'deny' || decision.kind === 'ask') {
      yield* new CheckedScriptError({ message: `[tripwire:${decision.rule}] ${decision.message}` });
    }
    if (decision.kind === 'warn') {
      process.stderr.write(`[tripwire:${decision.rule}] ${decision.message}\n`);
    }
    process.exitCode = yield* executeBytes(bytes, arguments_);
  });

export { CheckedScriptError, runCheckedScript };
