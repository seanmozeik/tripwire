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
  'plistlib',
  'asyncio',
  'inspect',
  'collections',
  'datetime',
  'time',
  'platform',
  'statistics',
  'textwrap',
  'shlex',
  'base64',
  'urllib',
  'urllib.parse',
  'html',
  'html.parser',
  'random',
  'string',
  'itertools',
  'functools',
  'uuid',
  'importlib',
  'importlib.util',
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
  'hashlib',
]);
const JS_MODULES = new Set(['fs', 'fs/promises', 'path', 'child_process', 'crypto', 'util', 'os']);
const PYTHON_GLOBALS = [
  'isinstance',
  'iter',
  'next',
  'reversed',
  'oct',
  'hex',
  'Exception',
  'ValueError',
  'TypeError',
  'print',
  'dict',
  'set',
  'tuple',
  'enumerate',
  'zip',
  'range',
  'repr',
  'type',
  'SystemExit',
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
const JS_GLOBALS = [
  'Error',
  'TypeError',
  'setInterval',
  'setTimeout',
  'console',
  'require',
  'JSON',
  'Deno',
  'Bun',
  'Math',
  'Number',
  'String',
  'Boolean',
  'Object',
  'Array',
  'Date',
  'Set',
  'Map',
  'RegExp',
  'URL',
  'URLSearchParams',
  'Buffer',
  'process',
  'parseInt',
  'parseFloat',
  'isNaN',
  'isFinite',
];

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
