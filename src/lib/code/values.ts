import path from 'node:path';

import { failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';

const unknown: Value = { kind: 'unknown' };
const symbol = (name: string): Value => ({ kind: 'symbol', name });
const textValue = (value: string): Value => {
  if (value.length > 65_536) {
    return failInspection('A resolved string exceeds its size limit.');
  }
  return { kind: 'string', value };
};
const valueString = (value: Value | undefined): string => {
  if (value?.kind === 'string') {
    return value.value;
  }
  if (value?.kind === 'path') {
    return value.path;
  }
  return failInspection('An operation has an unresolved path or argument.');
};
const PYTHON_MODULES = new Set([
  'collections',
  'os',
  'os.path',
  'shutil',
  'pathlib',
  'subprocess',
  'json',
  'math',
  'sys',
  're',
  'zipfile',
  'difflib',
  'glob',
]);
const JS_MODULES = new Set(['fs', 'fs/promises', 'path', 'child_process']);
const PYTHON_GLOBALS = [
  'print',
  'len',
  'str',
  'int',
  'float',
  'abs',
  'round',
  'open',
  'sum',
  'sorted',
  'list',
  'bool',
  'min',
  'max',
  'any',
  'all',
];
const JS_GLOBALS = ['console', 'require', 'JSON', 'Deno'];

const initialBindings = (language: CodeLanguage): Map<string, Value> =>
  new Map(
    (language === 'python' ? PYTHON_GLOBALS : JS_GLOBALS).map((name) => [name, symbol(name)]),
  );

const moduleName = (name: string, language: CodeLanguage): string => {
  const normalized = language !== 'python' && name.startsWith('node:') ? name.slice(5) : name;
  const modules = language === 'python' ? PYTHON_MODULES : JS_MODULES;
  if (!modules.has(normalized)) {
    return failInspection(
      `Module ${JSON.stringify(name)} can execute code that was not inspected.`,
    );
  }
  return normalized === 'fs/promises' ? 'fs' : normalized;
};

// Python resets the prefix at an absolute component. Node path.join does not.
const pythonJoin = (parts: readonly string[]): string => {
  let result = '';
  for (const part of parts) {
    result = part.startsWith('/') ? part : path.posix.join(result, part);
  }
  return result;
};

export { initialBindings, moduleName, pythonJoin, symbol, textValue, unknown, valueString };
