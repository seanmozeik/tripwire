import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import path from 'node:path';

interface ProjectCommand {
  readonly kind: 'project';
  readonly directory: string | null;
  readonly script: string | null;
}

// Project tests share the existing bun test trust boundary. This recognizes
// command grammar; it does not claim to inspect test bodies or dependencies.
const NODE_FLAGS = new Set([
  '--test',
  '--test-only',
  '--test-force-exit',
  '--no-warnings',
  '--experimental-strip-types',
]);
const NODE_VALUES = new Set([
  '--test-name-pattern',
  '--test-skip-pattern',
  '--test-concurrency',
  '--test-timeout',
]);
const DENO_FLAGS = new Set([
  '--allow-env',
  '--allow-sys',
  '--allow-read',
  '--allow-write',
  '--allow-net',
  '--allow-run',
  '--allow-ffi',
  '--allow-all',
  '-A',
  '--no-config',
  '--no-check',
  '--no-prompt',
  '--quiet',
  '-q',
  '--check',
  '--watch',
  '--parallel',
  '--fail-fast',
]);
const DENO_VALUES = new Set(['--config', '-c', '--filter', '--ignore', '--seed']);
const DENO_ATTACHED = new Set([
  '--allow-env',
  '--allow-sys',
  '--allow-read',
  '--allow-write',
  '--allow-net',
  '--allow-run',
  '--allow-ffi',
  '--no-check',
  '--fail-fast',
]);

const nodeTests = (args: readonly string[]): boolean => {
  let test = false;
  for (let index = 0; index < args.length; index += 1) {
    const token = args[index] ?? '';
    if (token === '--') {
      return (
        test &&
        args.slice(index + 1).every((value) => !value.startsWith('-') && !/^\w+:/u.test(value))
      );
    }
    if (!token.startsWith('-')) {
      // Node stops parsing runtime flags at the first file operand.
      return (
        test && args.slice(index).every((value) => !value.startsWith('-') && !/^\w+:/u.test(value))
      );
    }
    if (NODE_FLAGS.has(token)) {
      test ||= token === '--test';
    } else {
      const equals = token.indexOf('=');
      const name = equals === -1 ? token : token.slice(0, equals);
      const value = equals === -1 ? args[index + 1] : token.slice(equals + 1);
      if (value === undefined || value === '' || value.startsWith('-')) {
        return false;
      }
      if (
        !NODE_VALUES.has(name) &&
        !(name === '--import' && value === 'tsx') &&
        !(name === '--test-reporter' && ['spec', 'tap', 'dot', 'junit', 'lcov'].includes(value))
      ) {
        return false;
      }
      index += equals === -1 ? 1 : 0;
    }
  }
  return test;
};

const denoCheck = (args: readonly string[]): boolean => {
  if (!['test', 'fmt', 'lint', 'check'].includes(args[0] ?? '')) {
    return false;
  }
  for (let index = 1; index < args.length; index += 1) {
    const token = args[index] ?? '';
    if (token === '--') {
      // Deno can pass arguments to test modules after this separator.
      return args.slice(index + 1).every((value) => !/^\w+:/u.test(value));
    }
    if (!token.startsWith('-')) {
      if (/^\w+:/u.test(token)) {
        return false;
      }
    } else if (!DENO_FLAGS.has(token)) {
      const equals = token.indexOf('=');
      const name = equals === -1 ? token : token.slice(0, equals);
      const value = equals === -1 ? args[index + 1] : token.slice(equals + 1);
      if (
        (!DENO_VALUES.has(name) && !(equals !== -1 && DENO_ATTACHED.has(name))) ||
        value === undefined ||
        value === '' ||
        value.startsWith('-') ||
        /^\w+:/u.test(value)
      ) {
        return false;
      }
      index += equals === -1 ? 1 : 0;
    }
  }
  return true;
};

const bunScript = (args: readonly string[]): ProjectCommand | null => {
  let directory: string | null = null;
  let run = false;
  let index = 0;
  for (; index < args.length; index += 1) {
    const token = args[index] ?? '';
    if (token === 'run' && !run) {
      run = true;
    } else if ((token === '--cwd' || token.startsWith('--cwd=')) && directory === null) {
      if (token === '--cwd') {
        index += 1;
        directory = args[index] ?? '';
      } else {
        directory = token.slice('--cwd='.length);
      }
      if (directory === '' || directory.startsWith('-')) {
        return null;
      }
    } else {
      break;
    }
  }
  const script = args[index];
  if (!run || script === undefined || !/^[\w][\w:-]*$/u.test(script)) {
    return null;
  }
  return { kind: 'project', directory, script };
};

const projectCommand = (
  name: string,
  args: readonly string[],
): ProjectCommand | { readonly kind: 'irrelevant' } | null => {
  if (name === 'bun') {
    // Preserve the established conventional-gate policy. Other names and cwd
    // forms require an actual script in the selected manifest.
    if (
      args[0] === 'run' &&
      /^(?:check|test|typecheck|lint|format|build|verify)(?::[\w-]+)*$/u.test(args[1] ?? '')
    ) {
      return { kind: 'irrelevant' };
    }
    return bunScript(args);
  }
  if (
    (['node', 'nodejs', 'tsx'].includes(name) && nodeTests(args)) ||
    (name === 'deno' && denoCheck(args))
  ) {
    return { kind: 'project', directory: null, script: null };
  }
  return null;
};

const readManifest = (directory: string): string | null => {
  const fd = openSync(
    path.join(directory, 'package.json'),
    constants.O_RDONLY | constants.O_NONBLOCK,
  );
  try {
    if (!fstatSync(fd).isFile()) {
      return null;
    }
    const bytes = Buffer.alloc(1_048_577);
    const size = readSync(fd, bytes, 0, bytes.length, 0);
    return size < bytes.length
      ? new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size))
      : null;
  } finally {
    closeSync(fd);
  }
};

const hasPackageScript = (directory: string, name: string): boolean => {
  // Read data only, never import a manifest. Require the selected directory's
  // manifest so script lookup cannot silently fall through to an executable.
  try {
    const source = readManifest(directory);
    const value: unknown = source === null ? null : JSON.parse(source);
    if (value === null || typeof value !== 'object' || !('scripts' in value)) {
      return false;
    }
    const { scripts } = value;
    return (
      scripts !== null &&
      typeof scripts === 'object' &&
      !Array.isArray(scripts) &&
      Object.entries(scripts).some(
        ([key, script]) => key === name && typeof script === 'string' && script.trim().length > 0,
      )
    );
  } catch {
    return false;
  }
};

export { hasPackageScript, projectCommand };
export type { ProjectCommand };
