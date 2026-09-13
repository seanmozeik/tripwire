interface ProjectCommand {
  readonly kind: 'project';
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
  '--frozen',
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

const bunOptionValue = (args: readonly string[], index: number): number => {
  const token = args[index] ?? '';
  const equals = token.indexOf('=');
  const value = equals === -1 ? args[index + 1] : token.slice(equals + 1);
  return value === undefined || value === '' || value.startsWith('-')
    ? -1
    : index + (equals === -1 ? 1 : 0);
};

const BUN_COMMANDS = new Set([
  'run',
  'test',
  'install',
  'add',
  'remove',
  'update',
  'outdated',
  'pm',
  'build',
  'exec',
  'x',
  'repl',
  'init',
  'create',
  'link',
  'unlink',
  'publish',
  'upgrade',
]);

const BUN_SCRIPT_FLAGS = new Set([
  '--silent',
  '--if-present',
  '--bun',
  '-b',
  '--watch',
  '--hot',
  '--smol',
  '--workspaces',
  '--parallel',
  '--sequential',
  '--no-exit-on-error',
]);
const BUN_SCRIPT_VALUES = new Set(['--filter', '-F', '--cwd', '--elide-lines', '--shell']);

const bunScript = (args: readonly string[]): { readonly kind: 'irrelevant' } | null => {
  let directory = false;
  let run = false;
  let index = 0;
  for (; index < args.length; index += 1) {
    const token = args[index] ?? '';
    if (token === 'run' && !run) {
      run = true;
    } else if (BUN_SCRIPT_VALUES.has(token.split('=')[0] ?? '')) {
      if (token.startsWith('--cwd')) {
        if (directory) {
          return null;
        }
        directory = true;
      }
      index = bunOptionValue(args, index);
      if (index === -1) {
        return null;
      }
    } else if (!BUN_SCRIPT_FLAGS.has(token)) {
      break;
    }
  }
  const script = args[index];
  if (run && ['--help', '-h'].includes(script ?? '') && index === args.length - 1) {
    return { kind: 'irrelevant' };
  }
  if (
    script === undefined ||
    script === '' ||
    script.startsWith('-') ||
    (!run && BUN_COMMANDS.has(script))
  ) {
    return null;
  }
  // Named scripts are a trusted execution boundary. Bun owns script lookup;
  // options after the script name belong to that script, not the interpreter.
  return { kind: 'irrelevant' };
};

const projectCommand = (
  name: string,
  args: readonly string[],
): ProjectCommand | { readonly kind: 'irrelevant' } | null => {
  if (name === 'bun') {
    return bunScript(args);
  }
  if (
    (['node', 'nodejs', 'tsx'].includes(name) && nodeTests(args)) ||
    (name === 'deno' && denoCheck(args))
  ) {
    return { kind: 'project' };
  }
  return null;
};

export { projectCommand };
export type { ProjectCommand };
