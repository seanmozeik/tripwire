import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

import { MiseInspectionError } from './inspection-error';

const absent = (cause: unknown): boolean =>
  cause instanceof Error && 'code' in cause && cause.code === 'ENOENT';

const readOptional = (filename: string): string | null => {
  try {
    const stat = statSync(filename);
    if (!stat.isFile() || stat.size > 131_072) {
      throw new MiseInspectionError(
        `Uninspectable mise file ${filename}: expected a regular file of at most 131072 bytes.`,
      );
    }
    return readFileSync(filename, 'utf8');
  } catch (cause) {
    if (absent(cause)) {
      return null;
    }
    if (cause instanceof Error && 'code' in cause) {
      throw new MiseInspectionError(`Cannot read mise file ${filename}.`, { cause });
    }
    throw cause;
  }
};

const entries = (directory: string): string[] => {
  try {
    const names = readdirSync(directory);
    if (names.length > 256) {
      throw new MiseInspectionError(`Mise directory ${directory} exceeds inspection limit.`);
    }
    return names;
  } catch (cause) {
    if (absent(cause)) {
      return [];
    }
    if (cause instanceof Error && 'code' in cause) {
      throw new MiseInspectionError(`Cannot read mise directory ${directory}.`, { cause });
    }
    throw cause;
  }
};

const ancestors = (cwd: string, ceilings: ReadonlySet<string> = new Set()): string[] => {
  const result: string[] = [];
  for (let current = cwd; result.length < 128; current = path.dirname(current)) {
    result.push(current);
    if (current === path.dirname(current) || ceilings.has(current)) {
      return result;
    }
  }
  throw new MiseInspectionError('Mise ancestor limit.');
};

// Mise v2026.9.12 src/config/mod.rs: LOCAL_CONFIG_FILENAMES and env_config_patterns.
const variants = (base: string, profiles: readonly string[]): string[] =>
  [`${base}.toml`, `${base}.local.toml`].concat(
    profiles.flatMap((profile) => [`${base}.${profile}.toml`, `${base}.${profile}.local.toml`]),
  );

const localNames = (profiles: readonly string[]): string[] =>
  ['.tool-versions'].concat(
    [
      '.config/mise/config',
      '.config/mise/mise',
      '.config/mise',
      '.mise/config',
      'mise/config',
      'mise',
      '.mise',
    ].flatMap((base) => variants(base, profiles)),
  );

const configDirectory = (directory: string, profiles: readonly string[]): string[] =>
  ['config', 'mise']
    .flatMap((base) => variants(path.join(directory, base), profiles))
    .concat(
      // Inspect every conf.d TOML, conservatively including inactive profile files.
      entries(path.join(directory, 'conf.d'))
        .filter((name) => !name.startsWith('.') && name.endsWith('.toml'))
        .map((name) => path.join(directory, 'conf.d', name)),
    );

// Mise config_root.rs deliberately uses the path reached, without desymlinking.
const configRoot = (filename: string): string => {
  let directory = path.dirname(filename);
  if (path.basename(directory) === 'conf.d') {
    directory = path.dirname(directory);
  } else if (!/^config(?:\..+)?\.toml$/u.test(path.basename(filename))) {
    return path.basename(directory) === '.config' ? path.dirname(directory) : directory;
  }
  if (['mise', '.mise'].includes(path.basename(directory))) {
    directory = path.dirname(directory);
  }
  return path.basename(directory) === '.config' ? path.dirname(directory) : directory;
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const record = (value: unknown, context = 'mise config'): Record<string, unknown> => {
  if (!isRecord(value)) {
    throw new MiseInspectionError(`${context}: expected a table.`);
  }
  return value;
};

const parseToml = (filename: string, source: string): unknown => {
  try {
    return Bun.TOML.parse(source);
  } catch (cause) {
    if (!(cause instanceof SyntaxError)) {
      throw cause;
    }
    // Parser messages can contain config values; identify the file without leaking them.
    throw new MiseInspectionError(`TOML parse error in ${filename}.`);
  }
};

export {
  parseToml,
  configRoot,
  ancestors,
  configDirectory,
  entries,
  localNames,
  readOptional,
  record,
};
