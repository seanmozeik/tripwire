import path from 'node:path';

import { STARTUP_VARIABLES } from '../interpreter-startup';
import { readOptional, record, parseToml } from './files';
import { MiseInspectionError, assertSafe } from './inspection-error';

const CORE_TOOLS = new Set([
  'bun',
  'deno',
  'dotnet',
  'elixir',
  'erlang',
  'go',
  'java',
  'node',
  'python',
  'ruby',
  'rust',
  'swift',
  'zig',
]);
const startupName = (name: string): boolean =>
  STARTUP_VARIABLES.has(name) ||
  ['PATH', 'HOME', 'SHELL', 'ENV', 'BASH_ENV', 'ZDOTDIR'].includes(name) ||
  name.startsWith('MISE_') ||
  name.startsWith('XDG_') ||
  name.startsWith('__MISE');

const literal = (value: unknown): boolean =>
  typeof value === 'string' && !/\{[{%#]|\$|`/u.test(value);
const version = (value: unknown): boolean =>
  typeof value === 'string' && /^(?:latest|system|[0-9][\w.+-]*)$/u.test(value);
const coreTool = (name: string): boolean => CORE_TOOLS.has(name.replace(/^core:/u, ''));

const assertDotenv = (filename: string): void => {
  const source = readOptional(filename);
  if (source === null) {
    throw new MiseInspectionError(`Missing dotenv file ${filename}.`);
  }
  for (const line of source
    .split(/\r?\n/u)
    .filter((item) => item.trim() !== '' && !item.trimStart().startsWith('#'))) {
    const match = /^(?:export\s+)?(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>[^\r\n]*)$/u.exec(
      line.trim(),
    );
    const name = match?.groups?.['name'];
    const value = match?.groups?.['value'];
    assertSafe(
      name !== undefined &&
        !startupName(name) &&
        literal(value) &&
        typeof value === 'string' &&
        (/^[^'"\\]*$/u.test(value) || /^"[^"\\]*"$/u.test(value) || /^'[^'\\]*'$/u.test(value)),
      `${filename}: unverified dotenv variable ${name ?? '(invalid assignment)'}.`,
    );
  }
};

const assertEnvFiles = (setting: unknown, directory: string): void => {
  for (const [directive, files] of Object.entries(record(setting, 'env._'))) {
    assertSafe(directive === 'file', `Unverified config key env._.${directive}.`);
    for (const file of Array.isArray(files) ? files : [files]) {
      if (typeof file !== 'string' || !literal(file) || /[?*[\]]/u.test(file)) {
        throw new MiseInspectionError('Unverified config key env._.file.');
      }
      assertDotenv(path.resolve(directory, file));
    }
  }
};

const assertEnvTable = (value: unknown, directory: string): void => {
  if (Array.isArray(value)) {
    for (const item of value) {
      assertEnvTable(item, directory);
    }
    return;
  }
  for (const [name, setting] of Object.entries(record(value, 'env'))) {
    if (name === '_') {
      assertEnvFiles(setting, directory);
    } else {
      assertSafe(
        !startupName(name) &&
          (literal(setting) || typeof setting === 'number' || typeof setting === 'boolean'),
        `Unverified config key env.${name}.`,
      );
    }
  }
};

const assertToolsTable = (value: unknown, tools: Set<string>): void => {
  for (const [name, setting] of Object.entries(record(value, 'tools'))) {
    const versions = Array.isArray(setting) ? setting : [setting];
    assertSafe(
      coreTool(name) && versions.length > 0 && versions.every((item: unknown) => version(item)),
      `Unverified config key tools.${name} (backend or version).`,
    );
    tools.add(name.replace(/^core:/u, ''));
  }
};

const templateFree = (value: unknown, depth = 0): boolean => {
  if (depth > 64) {
    return false;
  }
  if (typeof value === 'string') {
    return !/\{[{%#]/u.test(value);
  }
  if (Array.isArray(value)) {
    return value.every((item: unknown) => templateFree(item, depth + 1));
  }
  if (typeof value === 'object' && value !== null) {
    return Object.entries(value).every(
      ([name, item]: [string, unknown]) =>
        templateFree(name, depth + 1) && templateFree(item, depth + 1),
    );
  }
  return true;
};

const assertSettingsTable = (value: unknown, idiomaticTools: Set<string>): void => {
  for (const [name, setting] of Object.entries(record(value, 'settings'))) {
    if (name === 'idiomatic_version_file_enable_tools' && Array.isArray(setting)) {
      for (const tool of setting) {
        if (typeof tool !== 'string' || !/^[a-z][a-z0-9-]*$/u.test(tool)) {
          throw new MiseInspectionError(`Unverified config key settings.${name}.`);
        }
        idiomaticTools.add(tool);
      }
    } else if (name === 'ruby') {
      for (const [key, item] of Object.entries(record(setting, 'settings.ruby'))) {
        assertSafe(
          key === 'compile' && typeof item === 'boolean',
          `Unverified config key settings.ruby.${key}.`,
        );
      }
    } else {
      assertSafe(
        ['verbose', 'quiet', 'yes', 'color'].includes(name) && typeof setting === 'boolean',
        `Unverified config key settings.${name}.`,
      );
    }
  }
};

const assertConfig = (
  filename: string,
  tools: Set<string>,
  root: string,
  toolVersions: boolean,
  idiomaticTools: Set<string>,
): void => {
  const source = readOptional(filename);
  if (source === null) {
    return;
  }
  if (toolVersions || path.basename(filename) === '.tool-versions') {
    for (const line of source.split(/\r?\n/u)) {
      const [name, ...versions] = line.split('#')[0]?.trim().split(/\s+/u) ?? [];
      if (name !== undefined && name !== '') {
        assertToolsTable({ [name]: versions }, tools);
      }
    }
    return;
  }
  const config: unknown = parseToml(filename, source);
  for (const [name, setting] of Object.entries(record(config))) {
    assertSafe(templateFree({ [name]: setting }), `Unverified template in config key ${name}.`);
    switch (name) {
      case 'env': {
        assertEnvTable(setting, root);
        break;
      }
      case 'tools': {
        assertToolsTable(setting, tools);
        break;
      }
      case 'settings': {
        assertSettingsTable(setting, idiomaticTools);
        break;
      }
      case 'min_version': {
        assertSafe(version(setting), 'Unverified config key min_version.');
        break;
      }
      case 'tasks': {
        break;
      }
      default: {
        throw new MiseInspectionError(`Unverified config key ${name}.`);
      }
    }
  }
};

export { assertConfig, coreTool, literal, version };
