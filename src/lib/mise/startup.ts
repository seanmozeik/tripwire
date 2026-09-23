import { realpathSync, statSync } from 'node:fs';
import path from 'node:path';

import type { ShellInvocation } from '../bash/types';
import type { Environment } from '../bash/values';
import { currentEnvironment } from '../environment';
import { configSafe, coreTool, literal, version } from './config';
import {
  ancestors,
  configRoot,
  configDirectory,
  entries,
  localNames,
  readOptional,
  record,
} from './files';

const ENVIRONMENT_KEYS = new Set([
  'MISE_SHELL',
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

const profilesFrom = (value: string | undefined): string[] => {
  const profiles = value?.split(',') ?? [];
  if (profiles.length > 16 || profiles.some((name) => !/^[\w-]+$/u.test(name))) {
    throw new Error('Uninspectable mise profile.');
  }
  return profiles;
};

const commandTools = (
  invocation: ShellInvocation,
  profiles: string[],
  tools: Set<string>,
): boolean => {
  for (let index = 1; index < invocation.words.length; index += 1) {
    const word = invocation.words[index];
    if (word?.kind !== 'literal') {
      return false;
    }
    if (word.value === '--') {
      return true;
    }
    const [flag, inline] = word.value.split('=');
    if (['-C', '--cd', '-j', '--jobs', '-E', '--env'].includes(flag ?? '')) {
      if (inline === undefined) {
        index += 1;
      }
      const value = inline ?? invocation.words[index]?.value;
      if (flag === '-E' || flag === '--env') {
        profiles.push(...profilesFrom(value));
      }
    } else if (!['exec', 'x'].includes(word.value)) {
      const [tool, requested, ...rest] = word.value.split('@');
      if (tool === undefined || !coreTool(tool) || !version(requested) || rest.length > 0) {
        return false;
      }
      tools.add(tool.replace(/^core:/u, ''));
    }
  }
  return false;
};

const misercProfiles = (filename: string, profiles: string[]): void => {
  const source = readOptional(filename);
  if (source === null) {
    return;
  }
  const config: unknown = Bun.TOML.parse(source);
  for (const [name, setting] of Object.entries(record(config))) {
    if (name !== 'env') {
      throw new Error('Uninspectable mise early setting.');
    }
    for (const profile of Array.isArray(setting) ? setting : [setting]) {
      if (typeof profile !== 'string') {
        throw new TypeError('Uninspectable mise environment.');
      }
      profiles.push(...profilesFrom(profile));
      if (profiles.length > 16) {
        throw new Error('Mise profile count exceeds inspection limit.');
      }
    }
  }
};

const backendSafe = (installs: string, plugins: string, tools: ReadonlySet<string>): boolean => {
  const source = readOptional(path.join(installs, '.mise-installs.toml'));
  const manifest = source === null ? {} : record(Bun.TOML.parse(source));
  const installedPlugins = new Set(entries(plugins));
  for (const tool of tools) {
    if (installedPlugins.has(tool)) {
      return false;
    }
    // Older metadata formats can select a plugin instead of the core backend.
    for (const filename of ['.mise.backend', '.mise.backend.json', '.mise.backend.toml']) {
      if (readOptional(path.join(installs, tool, filename)) !== null) {
        return false;
      }
    }
    const value = manifest[tool];
    if (value !== undefined) {
      const entry = record(value);
      if (
        entry['full'] !== `core:${tool}` ||
        (entry['opts'] !== undefined && Object.keys(record(entry['opts'])).length > 0)
      ) {
        return false;
      }
    }
  }
  return true;
};

const startupEnvironment = (environment: Environment): Record<string, string | undefined> => {
  if (environment.bindings.get('HOME')?.kind !== 'literal') {
    throw new Error('Unknown mise home.');
  }
  const env = currentEnvironment();
  for (const [name, word] of environment.bindings) {
    if (name === 'HOME' || name.startsWith('MISE_') || name.startsWith('XDG_')) {
      if (word.kind !== 'literal') {
        throw new Error('Unknown mise environment.');
      }
      env[name] = word.value;
    }
  }
  if (
    Object.keys(env).some(
      (name) =>
        (name.startsWith('MISE_') && !ENVIRONMENT_KEYS.has(name)) || name.startsWith('__MISE'),
    )
  ) {
    throw new Error('Unsupported mise environment setting.');
  }
  return env;
};

const filenameList = (value: string | undefined): string[] => {
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
    throw new Error('Uninspectable mise filenames.');
  }
  return names;
};

const localFiles = (
  env: Record<string, string | undefined>,
  profiles: readonly string[],
): { readonly toml: string[]; readonly versions: string[]; readonly fragments: boolean } => {
  for (const name of ['MISE_DEFAULT_CONFIG_FILENAME', 'MISE_DEFAULT_TOOL_VERSIONS_FILENAME']) {
    if (env[name]?.includes(path.delimiter) === true) {
      throw new Error('A default mise filename must be one literal path.');
    }
  }
  const defaults = new Set(localNames([]));
  const override = env['MISE_OVERRIDE_CONFIG_FILENAMES'];
  const versionsOverride = env['MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES'];
  const toml =
    override === undefined
      ? localNames(profiles).filter((name) => name !== '.tool-versions')
      : filenameList(override).concat(localNames(profiles).filter((name) => !defaults.has(name)));
  if (env['MISE_DEFAULT_CONFIG_FILENAME'] !== undefined) {
    toml.push(...filenameList(env['MISE_DEFAULT_CONFIG_FILENAME']));
  }
  if (toml.some((name) => !name.endsWith('.toml'))) {
    throw new Error('Mise TOML filename is unverified.');
  }
  let versions = ['.tool-versions'];
  if (versionsOverride !== undefined) {
    versions = versionsOverride === 'none' ? [] : filenameList(versionsOverride);
  }
  versions.push(...filenameList(env['MISE_DEFAULT_TOOL_VERSIONS_FILENAME']));
  return { toml, versions, fragments: override === undefined };
};

const discover = (
  cwd: string,
  invocationCwd: string,
  env: Record<string, string | undefined>,
  profiles: string[],
  roots: { readonly global: string; readonly system: string; readonly home: string },
): { readonly files: Map<string, string>; readonly versions: Set<string> } => {
  const { global, system, home } = roots;
  const ceilings = env['MISE_CEILING_PATHS']?.split(path.delimiter) ?? [];
  if (ceilings.some((ceiling) => !path.isAbsolute(ceiling) || !literal(ceiling))) {
    throw new Error('Uninspectable mise ceiling.');
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
        throw new Error('Uninspectable mise override.');
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
  return { files, versions };
};

// No subprocesses, template rendering, plugins, or mise caches are consulted.
// Unknown discovery/settings inputs fail closed rather than silently omitting files.
const miseStartupSafe = (invocation: ShellInvocation, environment: Environment): boolean => {
  try {
    const { cwd } = environment;
    if (cwd === null || invocation.cwd === null || !statSync(cwd).isDirectory()) {
      return false;
    }
    const env = startupEnvironment(environment);
    const home = env['HOME'];
    if (home === undefined || !path.isAbsolute(home)) {
      return false;
    }
    const directory = (name: string, fallback: string): string => {
      const value = env[name] ?? fallback;
      if (!path.isAbsolute(value) || !literal(value)) {
        throw new Error('Uninspectable mise directory.');
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
    const profiles = profilesFrom(env['MISE_ENV'] ?? env['MISE_ENVIRONMENT']);
    const tools = new Set<string>();
    if (!commandTools(invocation, profiles, tools)) {
      return false;
    }
    const { files, versions } = discover(cwd, invocation.cwd, env, profiles, {
      global,
      system,
      home,
    });
    if (
      files.size > 2048 ||
      ![...files].every(([filename, root]) =>
        configSafe(filename, tools, root, versions.has(filename)),
      )
    ) {
      return false;
    }
    return backendSafe(
      directory('MISE_INSTALLS_DIR', path.join(data, 'installs')),
      directory('MISE_PLUGINS_DIR', path.join(data, 'plugins')),
      tools,
    );
  } catch {
    return false;
  }
};

export { miseStartupSafe };
