import { realpathSync, statSync } from 'node:fs';
import path from 'node:path';

import type { StartupResult, WrapperArguments } from '../bash/tool-wrappers';
import type { ShellInvocation } from '../bash/types';
import type { Environment } from '../bash/values';
import { currentEnvironment } from '../environment';
import { checkBackends } from './backends';
import { assertConfig, coreTool, literal, version } from './config';
import {
  ancestors,
  configRoot,
  configDirectory,
  localNames,
  readOptional,
  record,
  parseToml,
} from './files';
import { assertIdiomaticFiles } from './idiomatic';
import { assertSafe, MiseInspectionError } from './inspection-error';

// Activation state is inert for exec additions; see docs/mise-startup.md for
// the source audit. Unknown private variables still fail closed.
const ENVIRONMENT_KEYS = new Set([
  'MISE_SHELL',
  '__MISE_DIFF',
  '__MISE_ORIG_PATH',
  '__MISE_SESSION',
  '__MISE_LAST_UNTRUSTED_CONFIG_WARNING_KEY',
  '__MISE_ZSH_ACTIVATE_ENV',
  '__MISE_ZSH_ACTIVATE_PATH',
  '__MISE_ZSH_CHPWD_RAN',
  '__MISE_ZSH_PRECMD_RUN',
  '__MISE_BASH_CHPWD_RAN',
  '__MISE_BASH_SKIP_FIRST_PROMPT',
  '__MISE_EXE',
  '__MISE_FLAGS',
  '__MISE_HOOK_ENABLED',
  'MISE_OVERRIDE_CONFIG_FILENAMES',
  'MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES',
  'MISE_DEFAULT_CONFIG_FILENAME',
  'MISE_DEFAULT_TOOL_VERSIONS_FILENAME',
  'MISE_ENV',
  'MISE_ENVIRONMENT',
  'MISE_CEILING_PATHS',
  'MISE_CONFIG_FILE',
  'MISE_GLOBAL_CONFIG_FILE',
  'MISE_SYSTEM_CONFIG_FILE',
  'MISE_CONFIG_DIR',
  'MISE_SYSTEM_CONFIG_DIR',
  'MISE_SYSTEM_DIR',
  'MISE_DATA_DIR',
  'MISE_INSTALLS_DIR',
  'MISE_PLUGINS_DIR',
]);

const profilesFrom = (value: string | undefined, origin: string): string[] => {
  const profiles = value?.split(',') ?? [];
  if (profiles.length > 16 || profiles.some((name) => !/^[\w-]+$/u.test(name))) {
    throw new MiseInspectionError(`Uninspectable mise profile from ${origin}.`);
  }
  return profiles;
};

const assertCommandTools = (
  args: WrapperArguments,
  profiles: string[],
  tools: Set<string>,
): void => {
  for (const { name, value } of args.options) {
    if (name === '-E' || name === '--env') {
      profiles.push(...profilesFrom(value, `command option ${name}`));
    }
  }
  for (const operand of args.operands) {
    const [tool, requested, ...rest] = operand.split('@');
    if (tool === undefined || !coreTool(tool) || !version(requested) || rest.length > 0) {
      throw new MiseInspectionError(
        `Unverified mise command tool ${tool ?? '(missing)'} or its version.`,
      );
    }
    tools.add(tool.replace(/^core:/u, ''));
  }
};

const misercProfiles = (filename: string, profiles: string[]): void => {
  const source = readOptional(filename);
  if (source === null) {
    return;
  }
  const config: unknown = parseToml(filename, source);
  for (const [name, setting] of Object.entries(record(config))) {
    if (name !== 'env') {
      throw new MiseInspectionError(`${filename}: unverified early config key ${name}.`);
    }
    for (const profile of Array.isArray(setting) ? setting : [setting]) {
      if (typeof profile !== 'string') {
        throw new MiseInspectionError(`${filename}: uninspectable early config key env.`);
      }
      profiles.push(...profilesFrom(profile, `${filename}: env`));
      if (profiles.length > 16) {
        throw new MiseInspectionError(`${filename}: env profile count exceeds inspection limit.`);
      }
    }
  }
};

const startupEnvironment = (environment: Environment): Record<string, string | undefined> => {
  if (environment.bindings.get('HOME')?.kind !== 'literal') {
    throw new MiseInspectionError('Unknown mise home.');
  }
  const env = currentEnvironment();
  for (const [name, word] of environment.bindings) {
    if (
      name === 'HOME' ||
      name.startsWith('MISE_') ||
      name.startsWith('XDG_') ||
      name.startsWith('__MISE')
    ) {
      if (word.kind !== 'literal') {
        throw new MiseInspectionError(`Unknown mise environment variable ${name}.`);
      }
      env[name] = word.value;
    }
  }
  for (const name of Object.keys(env)) {
    if ((name.startsWith('MISE_') || name.startsWith('__MISE')) && !ENVIRONMENT_KEYS.has(name)) {
      throw new MiseInspectionError(`Unsupported mise environment variable ${name}.`);
    }
  }
  return env;
};

const filenameList = (value: string | undefined, variable: string): string[] => {
  const names = value?.split(path.delimiter) ?? [];
  if (
    names.length > 32 ||
    names.some(
      (name) =>
        !literal(name) ||
        name === '' ||
        /[?*[\]]/u.test(name) ||
        path.isAbsolute(name) ||
        name.split('/').includes('..'),
    )
  ) {
    throw new MiseInspectionError(`Uninspectable mise filenames from ${variable}.`);
  }
  return names;
};

const localFiles = (
  env: Record<string, string | undefined>,
  profiles: readonly string[],
): { readonly toml: string[]; readonly versions: string[]; readonly fragments: boolean } => {
  for (const name of ['MISE_DEFAULT_CONFIG_FILENAME', 'MISE_DEFAULT_TOOL_VERSIONS_FILENAME']) {
    if (env[name]?.includes(path.delimiter) === true) {
      throw new MiseInspectionError(`${name} must be one literal path.`);
    }
  }
  const defaults = new Set(localNames([]));
  const override = env['MISE_OVERRIDE_CONFIG_FILENAMES'];
  const versionsOverride = env['MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES'];
  const toml =
    override === undefined
      ? localNames(profiles).filter((name) => name !== '.tool-versions')
      : filenameList(override, 'MISE_OVERRIDE_CONFIG_FILENAMES').concat(
          localNames(profiles).filter((name) => !defaults.has(name)),
        );
  if (env['MISE_DEFAULT_CONFIG_FILENAME'] !== undefined) {
    toml.push(...filenameList(env['MISE_DEFAULT_CONFIG_FILENAME'], 'MISE_DEFAULT_CONFIG_FILENAME'));
  }
  if (toml.some((name) => !name.endsWith('.toml'))) {
    throw new MiseInspectionError(
      'MISE_OVERRIDE_CONFIG_FILENAMES or MISE_DEFAULT_CONFIG_FILENAME contains a non-TOML filename.',
    );
  }
  let versions = ['.tool-versions'];
  if (versionsOverride !== undefined) {
    versions =
      versionsOverride === 'none'
        ? []
        : filenameList(versionsOverride, 'MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES');
  }
  versions.push(
    ...filenameList(
      env['MISE_DEFAULT_TOOL_VERSIONS_FILENAME'],
      'MISE_DEFAULT_TOOL_VERSIONS_FILENAME',
    ),
  );
  return { toml, versions, fragments: override === undefined };
};

const discover = (
  cwd: string,
  invocationCwd: string,
  env: Record<string, string | undefined>,
  profiles: string[],
  roots: { readonly global: string; readonly system: string; readonly home: string },
): {
  readonly files: Map<string, string>;
  readonly versions: Set<string>;
  readonly parents: ReadonlySet<string>;
} => {
  const { global, system, home } = roots;
  const ceilings = env['MISE_CEILING_PATHS']?.split(path.delimiter) ?? [];
  if (ceilings.some((ceiling) => !path.isAbsolute(ceiling) || !literal(ceiling))) {
    throw new MiseInspectionError('Uninspectable mise directory variable MISE_CEILING_PATHS.');
  }
  const limits = new Set(ceilings.flatMap((ceiling) => [ceiling, realpathSync(ceiling)]));
  const parents = new Set([...ancestors(cwd, limits), ...ancestors(realpathSync(cwd), limits)]);
  const earlyParents = new Set([
    ...parents,
    ...ancestors(invocationCwd, limits),
    ...ancestors(realpathSync(invocationCwd), limits),
  ]);
  for (const parent of earlyParents) {
    misercProfiles(path.join(parent, '.miserc.toml'), profiles);
    misercProfiles(path.join(parent, '.config/miserc.toml'), profiles);
  }
  misercProfiles(path.join(global, 'miserc.toml'), profiles);
  misercProfiles(path.join(system, 'miserc.toml'), profiles);
  const files = new Map<string, string>();
  const versions = new Set<string>();
  const local = localFiles(env, profiles);
  for (const parent of parents) {
    const names = local.toml.map((name) => path.join(parent, name));
    if (local.fragments) {
      names.push(
        ...['.config/mise', '.mise', 'mise'].flatMap((name) =>
          configDirectory(path.join(parent, name), profiles),
        ),
      );
    }
    for (const name of local.versions) {
      const filename = path.join(parent, name);
      versions.add(filename);
      names.push(filename);
    }
    for (const filename of names) {
      files.set(filename, configRoot(filename));
    }
  }
  for (const [directoryName, override, root] of [
    [global, env['MISE_GLOBAL_CONFIG_FILE'] ?? env['MISE_CONFIG_FILE'], home],
    [system, env['MISE_SYSTEM_CONFIG_FILE'], undefined],
  ] as const) {
    const names = override === undefined ? configDirectory(directoryName, profiles) : [override];
    for (const filename of names) {
      if (!literal(filename) || !path.isAbsolute(filename)) {
        throw new MiseInspectionError(
          'Uninspectable mise config override: MISE_CONFIG_FILE, MISE_GLOBAL_CONFIG_FILE, or MISE_SYSTEM_CONFIG_FILE must be an absolute literal filename.',
        );
      }
      files.set(filename, root ?? configRoot(filename));
    }
  }
  const homeVersions = path.join(
    home,
    env['MISE_DEFAULT_TOOL_VERSIONS_FILENAME'] ?? local.versions[0] ?? '.tool-versions',
  );
  files.set(homeVersions, home);
  versions.add(homeVersions);
  return { files, versions, parents };
};

// No subprocesses, template rendering, plugins, or mise caches are consulted.
// Unknown discovery/settings inputs fail closed rather than silently omitting files.
const miseStartupSafe = (
  invocation: ShellInvocation,
  environment: Environment,
  args: WrapperArguments,
): StartupResult => {
  try {
    const { cwd } = environment;
    if (cwd === null || invocation.cwd === null || !statSync(cwd).isDirectory()) {
      throw new MiseInspectionError('Unverified mise working directory.');
    }
    const env = startupEnvironment(environment);
    const home = env['HOME'];
    if (home === undefined || !path.isAbsolute(home)) {
      throw new MiseInspectionError('Unverified mise HOME: expected an absolute path.');
    }
    const directory = (name: string, fallback: string): string => {
      const value = env[name] ?? fallback;
      if (!path.isAbsolute(value) || !literal(value)) {
        throw new MiseInspectionError(`Uninspectable mise directory variable ${name}.`);
      }
      return value;
    };
    const global = directory(
      'MISE_CONFIG_DIR',
      path.join(directory('XDG_CONFIG_HOME', path.join(home, '.config')), 'mise'),
    );
    const system = directory('MISE_SYSTEM_CONFIG_DIR', directory('MISE_SYSTEM_DIR', '/etc/mise'));
    const data = directory(
      'MISE_DATA_DIR',
      path.join(directory('XDG_DATA_HOME', path.join(home, '.local/share')), 'mise'),
    );
    const profiles = profilesFrom(
      env['MISE_ENV'] ?? env['MISE_ENVIRONMENT'],
      env['MISE_ENV'] === undefined ? 'MISE_ENVIRONMENT' : 'MISE_ENV',
    );
    const tools = new Set<string>();
    assertCommandTools(args, profiles, tools);
    const idiomaticTools = new Set<string>();
    const { files, versions, parents } = discover(cwd, invocation.cwd, env, profiles, {
      global,
      system,
      home,
    });
    assertSafe(files.size <= 2048, 'Mise config discovery exceeds 2048 files.');
    for (const [filename, root] of files) {
      try {
        assertConfig(filename, tools, root, versions.has(filename), idiomaticTools);
      } catch (cause) {
        if (!(cause instanceof MiseInspectionError)) {
          throw cause;
        }
        throw new MiseInspectionError(`${filename}: ${cause.message}`, { cause });
      }
    }
    assertIdiomaticFiles(
      parents,
      idiomaticTools,
      directory('MISE_PLUGINS_DIR', path.join(data, 'plugins')),
    );
    checkBackends(
      directory('MISE_INSTALLS_DIR', path.join(data, 'installs')),
      directory('MISE_PLUGINS_DIR', path.join(data, 'plugins')),
      new Set([...tools, ...idiomaticTools]),
    );
    return { safe: true };
  } catch (cause) {
    return {
      safe: false,
      reason:
        cause instanceof MiseInspectionError ? cause.message : 'Internal mise inspector error.',
    };
  }
};

export { miseStartupSafe };
