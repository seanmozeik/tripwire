import { accessSync, constants, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { readRuntimeEnvironment } from './environment';

const NATIVE_PACKAGE = ['@seanmozeik', 'tripwire-darwin-arm64'].join('/');

interface RuntimeCommand {
  readonly arguments: readonly string[];
  readonly executable: string;
  readonly kind: 'native' | 'portable';
}

interface RuntimeCommandOptions {
  readonly architecture?: string;
  readonly bunExecutable?: string;
  readonly moduleUrl?: string | URL;
  readonly nativeResolver?: () => string;
  readonly platform?: NodeJS.Platform;
  readonly portableExecutable?: string;
}

const executableFile = (candidate: string): string | undefined => {
  try {
    accessSync(candidate, constants.X_OK);
    return realpathSync(candidate);
  } catch {
    return undefined;
  }
};

const resolveNativeExecutable = (
  moduleUrl: string | URL,
  resolver: (() => string) | undefined,
): string | undefined => {
  try {
    const candidate = resolver?.() ?? createRequire(moduleUrl).resolve(NATIVE_PACKAGE);
    return executableFile(candidate);
  } catch {
    return undefined;
  }
};

const portableExecutableFor = (moduleUrl: string | URL): string => {
  const modulePath = fileURLToPath(moduleUrl);
  let resolvedModulePath = modulePath;
  try {
    resolvedModulePath = realpathSync(modulePath);
  } catch {
    // Build-time imports do not have an output file yet. The sibling path is still deterministic.
  }
  return path.join(path.dirname(resolvedModulePath), 'tripwire.js');
};

const resolveTripwireCommand = (options: RuntimeCommandOptions = {}): RuntimeCommand => {
  const moduleUrl = options.moduleUrl ?? import.meta.url;
  const platform = options.platform ?? process.platform;
  const architecture = options.architecture ?? process.arch;
  const environment = readRuntimeEnvironment();
  if (!environment.forcePortable && platform === 'darwin' && architecture === 'arm64') {
    const executable = resolveNativeExecutable(moduleUrl, options.nativeResolver);
    if (executable !== undefined) {
      return { arguments: [], executable, kind: 'native' };
    }
  }

  return {
    arguments: [options.portableExecutable ?? portableExecutableFor(moduleUrl)],
    executable: options.bunExecutable ?? environment.bunExecutable ?? 'bun',
    kind: 'portable',
  };
};

export { NATIVE_PACKAGE, resolveTripwireCommand, type RuntimeCommand, type RuntimeCommandOptions };
