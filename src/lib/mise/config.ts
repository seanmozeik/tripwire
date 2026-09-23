import path from 'node:path';

import { STARTUP_VARIABLES } from '../interpreter-startup';
import { readOptional, record, parseToml } from './files';
import { requireSafe } from './result';

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

const dotenv = (filename: string): boolean => {
  const source = readOptional(filename);
  if (source === null) {
    throw new Error(`Missing dotenv file ${filename}.`);
  }
  return source.split(/\r?\n/u).every((line) => {
    if (line.trim() === '' || line.trimStart().startsWith('#')) {
      return true;
    }
    const match = /^(?:export\s+)?(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?<value>[^\r\n]*)$/u.exec(
      line.trim(),
    );
    const name = match?.groups?.['name'];
    const value = match?.groups?.['value'];
    return requireSafe(
      name !== undefined &&
        !startupName(name) &&
        literal(value) &&
        typeof value === 'string' &&
        (/^[^'"\\]*$/u.test(value) || /^"[^"\\]*"$/u.test(value) || /^'[^'\\]*'$/u.test(value)),
      `${filename}: unverified dotenv variable ${name ?? '(invalid assignment)'}.`,
    );
  });
};

const envTable = (value: unknown, directory: string): boolean => {
  if (Array.isArray(value)) {
    return value.every((item) => envTable(item, directory));
  }
  return Object.entries(record(value, 'env')).every(([name, setting]) => {
    if (name === '_') {
      return Object.entries(record(setting, 'env._')).every(([directive, files]) => {
        if (directive !== 'file') {
          throw new Error(`Unverified config key env._.${directive}.`);
        }
        return requireSafe(
          (Array.isArray(files) ? files : [files]).every(
            (file: unknown) =>
              typeof file === 'string' &&
              literal(file) &&
              !/[?*[\]]/u.test(file) &&
              dotenv(path.resolve(directory, file)),
          ),
          'Unverified config key env._.file.',
        );
      });
    }
    return requireSafe(
      !startupName(name) &&
        (literal(setting) || typeof setting === 'number' || typeof setting === 'boolean'),
      `Unverified config key env.${name}.`,
    );
  });
};

const toolsTable = (value: unknown, tools: Set<string>): boolean => {
  for (const [name, setting] of Object.entries(record(value, 'tools'))) {
    const versions = Array.isArray(setting) ? setting : [setting];
    requireSafe(
      coreTool(name) && versions.length > 0 && versions.every((item: unknown) => version(item)),
      `Unverified config key tools.${name} (backend or version).`,
    );
    tools.add(name.replace(/^core:/u, ''));
  }
  return true;
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

const settingsTable = (value: unknown, tools: Set<string>): boolean =>
  Object.entries(record(value, 'settings')).every(([name, setting]) => {
    if (name === 'idiomatic_version_file_enable_tools' && Array.isArray(setting)) {
      for (const tool of setting) {
        if (typeof tool !== 'string' || !/^[a-z][a-z0-9-]*$/u.test(tool)) {
          throw new Error(`Unverified config key settings.${name}.`);
        }
        tools.add(tool);
      }
      return true;
    }
    if (name === 'ruby') {
      return Object.entries(record(setting, 'settings.ruby')).every(([key, item]) =>
        requireSafe(
          key === 'compile' && typeof item === 'boolean',
          `Unverified config key settings.ruby.${key}.`,
        ),
      );
    }
    return requireSafe(
      ['verbose', 'quiet', 'yes', 'color'].includes(name) && typeof setting === 'boolean',
      `Unverified config key settings.${name}.`,
    );
  });

const configSafe = (
  filename: string,
  tools: Set<string>,
  root: string,
  toolVersions = false,
): boolean => {
  const source = readOptional(filename);
  if (source === null) {
    return true;
  }
  if (toolVersions || path.basename(filename) === '.tool-versions') {
    return source.split(/\r?\n/u).every((line) => {
      const fields = line.split('#')[0]?.trim().split(/\s+/u) ?? [];
      const [name, ...versions] = fields;
      if (name === undefined || name === '') {
        return true;
      }
      return requireSafe(
        toolsTable({ [name]: versions }, tools) && versions.length > 0,
        `Unverified tool-version entry ${name}.`,
      );
    });
  }
  const config: unknown = parseToml(filename, source);

  return Object.entries(record(config)).every(([name, setting]) => {
    requireSafe(templateFree({ [name]: setting }), `Unverified template in config key ${name}.`);
    switch (name) {
      case 'env': {
        return envTable(setting, root);
      }
      case 'tools': {
        return toolsTable(setting, tools);
      }
      case 'settings': {
        return settingsTable(setting, tools);
      }
      case 'min_version': {
        return requireSafe(version(setting), 'Unverified config key min_version.');
      }
      // Plain tasks are inert; templates were rejected throughout the decoded tree.
      case 'tasks': {
        return true;
      }
      default: {
        throw new Error(`Unverified config key ${name}.`);
      }
    }
  });
};

export { configSafe, coreTool, literal, version };
