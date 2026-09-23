import path from 'node:path';

import { STARTUP_VARIABLES } from '../interpreter-startup';
import { readOptional, record } from './files';

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
  name.startsWith('XDG_');

const literal = (value: unknown): boolean =>
  typeof value === 'string' && !/\{[{%#]|\$|`/u.test(value);
const version = (value: unknown): boolean =>
  typeof value === 'string' && /^(?:latest|system|[0-9][\w.+-]*)$/u.test(value);
const coreTool = (name: string): boolean => CORE_TOOLS.has(name.replace(/^core:/u, ''));

const dotenv = (filename: string): boolean => {
  const source = readOptional(filename);
  if (source === null) {
    return false;
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
    return (
      name !== undefined &&
      !startupName(name) &&
      literal(value) &&
      typeof value === 'string' &&
      (/^[^'"\\]*$/u.test(value) || /^"[^"\\]*"$/u.test(value) || /^'[^'\\]*'$/u.test(value))
    );
  });
};

const envTable = (value: unknown, directory: string): boolean => {
  if (Array.isArray(value)) {
    return value.every((item) => envTable(item, directory));
  }
  return Object.entries(record(value)).every(([name, setting]) => {
    if (name === '_') {
      return Object.entries(record(setting)).every(([directive, files]) => {
        if (directive !== 'file') {
          return false;
        }
        return (Array.isArray(files) ? files : [files]).every(
          (file: unknown) =>
            typeof file === 'string' &&
            literal(file) &&
            !/[?*[\]]/u.test(file) &&
            dotenv(path.resolve(directory, file)),
        );
      });
    }
    return (
      !startupName(name) &&
      (literal(setting) || typeof setting === 'number' || typeof setting === 'boolean')
    );
  });
};

const toolsTable = (value: unknown, tools: Set<string>): boolean =>
  Object.entries(record(value)).every(([name, setting]) => {
    if (
      !coreTool(name) ||
      !(Array.isArray(setting) ? setting : [setting]).every((item: unknown) => version(item))
    ) {
      return false;
    }
    tools.add(name.replace(/^core:/u, ''));
    return true;
  });

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
      return toolsTable({ [name]: versions }, tools) && versions.length > 0;
    });
  }
  const config: unknown = Bun.TOML.parse(source);
  if (!templateFree(config)) {
    return false;
  }
  return Object.entries(record(config)).every(([name, setting]) => {
    switch (name) {
      case 'env': {
        return envTable(setting, root);
      }
      case 'tools': {
        return toolsTable(setting, tools);
      }
      case 'min_version': {
        return version(setting);
      }
      // Plain tasks are inert; templates were rejected throughout the decoded tree.
      case 'tasks': {
        return true;
      }
      default: {
        return false;
      }
    }
  });
};

export { configSafe, coreTool, literal, version };
