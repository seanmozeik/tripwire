import { resolveDirectory } from './cwd';
import type { ExecutionContext, ExecutionHost } from './execution-types';
import type { ShellInvocation } from './types';
import { cloneEnvironment, type Environment } from './values';

interface WrapperSpec {
  readonly extraDelimiters?: readonly string[];
  readonly flagBundle?: RegExp;
  readonly cwdOptions?: readonly string[];
  readonly cwdOperand?: number;
  readonly subcommands: readonly string[];
  readonly values?: readonly string[];
  readonly flags?: readonly string[];
  readonly operands?: number;
  readonly delimiter?: boolean;
  readonly startup?: boolean;
  readonly shell?: boolean;
}

const specs: Readonly<Record<string, WrapperSpec>> = {
  corepack: { subcommands: [] },
  busybox: { subcommands: [] },
  toybox: { subcommands: [] },
  uvx: {
    subcommands: [],
    values: ['--from', '--python', '--with'],
    flags: ['--offline', '--no-cache'],
    startup: true,
  },
  mise: {
    subcommands: ['exec', 'x'],
    values: ['-C', '--cd', '-j', '--jobs'],
    cwdOptions: ['-C', '--cd'],
    delimiter: true,
    startup: true,
  },
  direnv: { subcommands: ['exec'], operands: 1, cwdOperand: 0, startup: true },
  dotenv: {
    subcommands: [],
    values: ['-e', '--env', '-v', '--variable'],
    flags: ['-o', '--override'],
    startup: true,
  },
  op: { subcommands: ['run'], values: ['--env-file'], flags: ['--no-masking'], startup: true },
  doppler: { subcommands: ['run'], values: ['--project', '--config', '--token'], startup: true },
  infisical: { subcommands: ['run'], values: ['--env', '--path', '--projectId'], startup: true },
  'aws-vault': {
    subcommands: ['exec'],
    operands: 1,
    values: ['--duration'],
    flags: ['--no-session'],
    startup: true,
  },
  nix: {
    extraDelimiters: ['-c', '--command'],
    subcommands: ['develop'],
    delimiter: true,
    startup: true,
  },
  'nix-shell': {
    extraDelimiters: ['--run', '--command'],
    subcommands: [],
    delimiter: true,
    startup: true,
    shell: true,
  },
  devbox: { subcommands: ['run'], startup: true },
  pixi: { subcommands: ['run'], values: ['-e', '--environment', '--manifest-path'], startup: true },
  pdm: { subcommands: ['run'], startup: true },
  hatch: { subcommands: ['run'], startup: true },
  conda: {
    subcommands: ['run'],
    values: ['-n', '--name', '-p', '--prefix', '--cwd'],
    cwdOptions: ['--cwd'],
    flags: ['--no-capture-output', '--live-stream'],
    startup: true,
  },
  fnm: { subcommands: ['exec'], values: ['--using'], startup: true },
  asdf: { subcommands: ['exec'] },
  rbenv: { subcommands: ['exec'] },
  pyenv: { subcommands: ['exec'] },
  volta: { subcommands: ['run'], values: ['--node', '--npm', '--yarn', '--pnpm'] },
  caffeinate: {
    flagBundle: /^-[dimsu]+$/u,
    subcommands: [],
    flags: ['-i', '-d', '-m', '-s', '-u'],
    values: ['-t', '-w'],
  },
};

interface WrapperCursor {
  index: number;
  subcommand: boolean;
  operands: number;
  readonly environment: Environment;
}

const optionValue = (
  invocation: ShellInvocation,
  cursor: WrapperCursor,
  spec: WrapperSpec,
): boolean => {
  const word = invocation.words[cursor.index];
  if (word === undefined) {
    return false;
  }
  const [flag] = word.value.split('=');
  const target = word.value.includes('=')
    ? { ...word, value: word.value.slice(word.value.indexOf('=') + 1) }
    : invocation.words[cursor.index + 1];
  if (target?.kind !== 'literal') {
    return false;
  }
  if (spec.cwdOptions?.includes(flag ?? '') === true) {
    cursor.environment.cwd = resolveDirectory(target, cursor.environment.cwd);
  }
  if (!word.value.includes('=')) {
    cursor.index += 1;
  }
  return true;
};

const wrapperCommand = (
  invocation: ShellInvocation,
  spec: WrapperSpec,
  environment: Environment,
): number | null => {
  const cursor: WrapperCursor = {
    index: 1,
    subcommand: spec.subcommands.length === 0,
    operands: spec.operands ?? 0,
    environment,
  };
  const subcommands = new Set(spec.subcommands);
  const values = new Set(spec.values);
  const flags = new Set(spec.flags);
  const delimiters = new Set(['--', ...(spec.extraDelimiters ?? [])]);
  for (; cursor.index < invocation.words.length; cursor.index += 1) {
    const word = invocation.words[cursor.index];
    if (word?.kind !== 'literal') {
      return null;
    }
    const { value } = word;
    if (!cursor.subcommand && subcommands.has(value)) {
      cursor.subcommand = true;
    } else if (cursor.subcommand && delimiters.has(value)) {
      return cursor.operands === 0 ? cursor.index + 1 : null;
    } else if (values.has(value.split('=')[0] ?? '')) {
      if (!optionValue(invocation, cursor, spec)) {
        return null;
      }
    } else if (flags.has(value) || spec.flagBundle?.test(value) === true) {
      // Known flags have no argument.
    } else {
      const result = wrapperOperand(spec, cursor, word);
      if (result !== undefined) {
        return result;
      }
    }
  }
  return null;
};

const wrapperOperand = (
  spec: WrapperSpec,
  cursor: WrapperCursor,
  word: ShellInvocation['words'][number],
): number | null | undefined => {
  if (word.value.startsWith('-') || !cursor.subcommand) {
    return null;
  }
  if (cursor.operands > 0) {
    if (spec.cwdOperand === (spec.operands ?? 0) - cursor.operands) {
      cursor.environment.cwd = resolveDirectory(word, cursor.environment.cwd);
    }
    cursor.operands -= 1;
    return undefined;
  }
  return spec.delimiter === true ? undefined : cursor.index;
};

const inspectToolWrapper = (
  invocation: ShellInvocation,
  environment: Environment,
  context: ExecutionContext,
  host: ExecutionHost,
): boolean => {
  const spec = Object.hasOwn(specs, invocation.head) ? specs[invocation.head] : undefined;
  if (spec === undefined) {
    return false;
  }
  const child = cloneEnvironment(environment);
  child.unverifiedStartup ||= spec.startup === true;
  if (spec.startup === true) {
    child.bindings.delete('HOME');
  }
  const index = wrapperCommand(invocation, spec, child);
  if (index === null || invocation.words[index] === undefined) {
    host.addDiagnostic(
      'dynamic-shell-source',
      `Cannot resolve ${invocation.head} wrapper options and command. Use a supported explicit command form.`,
      invocation.range,
    );
  } else if (spec.shell === true && invocation.words.length !== index + 1) {
    host.addDiagnostic(
      'dynamic-shell-source',
      'Shell wrapper has uninspected trailing options. Use one literal shell program.',
      invocation.range,
    );
  } else if (spec.shell === true) {
    host.inspectShellSource(invocation.words[index], child, context);
  } else {
    host.emitSynthetic(invocation.words.slice(index), invocation, child, context);
  }
  return true;
};

export { inspectToolWrapper };
