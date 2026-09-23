import path from 'node:path';

import { builtinProperty, dataProperties } from './builtins';
import { data, isData, text } from './data';
import { failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';
import { symbol } from './values';

const indexedValue = (value: Value, key: Value): Value => {
  if (
    key.kind === 'string' &&
    (key.value.startsWith('_') || ['constructor', 'prototype'].includes(key.value))
  ) {
    return failInspection('Runtime reflection is not inspected.');
  }
  if (!isData(key)) {
    return failInspection('Index has uninspected effects.');
  }
  if (value.kind === 'text' || value.kind === 'string') {
    return text;
  }
  if (value.kind === 'data' || value.kind === 'counter' || value.kind === 'environment') {
    return data;
  }
  if (value.kind === 'list' && key.kind === 'number') {
    const result = value.items[key.value] ?? data;
    return isData(result) ? result : failInspection('Computed access cannot select a callable.');
  }
  if (value.kind === 'object' && key.kind === 'string') {
    const result = value.entries.get(key.value) ?? data;
    return isData(result) ? result : failInspection('Computed access cannot select a callable.');
  }
  return failInspection('Computed property access is not inspected.');
};

const instanceMember = (value: Value, member: string): Value | null => {
  if (value.kind === 'opaque-path') {
    return { kind: 'method', receiver: value, name: member };
  }
  if (value.kind === 'instance') {
    if (value.htmlParser === true && ['feed', 'close'].includes(member)) {
      return {
        kind: 'bound-method',
        fn: { kind: 'symbol', name: 'html-parser.feed' },
        receiver: value,
      };
    }
    const method = value.methods.get(member);
    return (
      value.entries.get(member) ??
      (method === undefined ? data : { kind: 'bound-method', fn: method, receiver: value })
    );
  }
  if (value.kind === 'path' && member === 'parent') {
    return { kind: 'path', path: path.posix.dirname(value.path) };
  }
  if (value.kind === 'path' && ['name', 'suffix', 'stem'].includes(member)) {
    const parsed = path.posix.parse(value.path);
    return {
      kind: 'string',
      value: { name: parsed.base, suffix: parsed.ext, stem: parsed.name }[member] ?? parsed.name,
    };
  }
  return null;
};

const namedMember = (value: Value, member: string, language: CodeLanguage): Value => {
  if (value.kind === 'builtin' && value.name === 'python-type' && member === '__name__') {
    return text;
  }
  if (member.startsWith('_') || member === 'constructor' || member === 'prototype') {
    return failInspection('Runtime reflection is not inspected.');
  }
  const special = instanceMember(value, member);
  if (special !== null) {
    return special;
  }
  if (value.kind === 'symbol') {
    const name = `${value.name}.${member}`;
    if (['os.environ', 'process.env'].includes(name)) {
      return { kind: 'environment' };
    }
    return dataProperties.has(name) ? data : symbol(name);
  }
  if (value.kind === 'builtin') {
    return builtinProperty(value.name, member) ?? { kind: 'method', receiver: value, name: member };
  }
  if (
    value.kind === 'path' ||
    value.kind === 'file' ||
    value.kind === 'archive' ||
    value.kind === 'hash' ||
    value.kind === 'bun-file' ||
    value.kind === 'image'
  ) {
    return { kind: 'method', receiver: value, name: member };
  }
  return dataMember(value, member, language);
};

const dataMember = (value: Value, member: string, language: CodeLanguage): Value => {
  if (value.kind === 'environment') {
    return data;
  }
  if (member === 'length' && isData(value)) {
    return data;
  }
  if (value.kind === 'object' && language !== 'python') {
    return value.entries.get(member) ?? data;
  }
  if (
    isData(value) &&
    ['st_size', 'st_mtime', 'st_mode', 'year', 'month', 'day', 'size'].includes(member)
  ) {
    return data;
  }
  if (isData(value)) {
    if (
      value.kind === 'data' &&
      language !== 'python' &&
      ![
        'map',
        'filter',
        'forEach',
        'reduce',
        'sort',
        'toUpperCase',
        'toLowerCase',
        'slice',
        'includes',
        'startsWith',
        'endsWith',
        'join',
        'split',
        'trim',
        'replace',
        'replaceAll',
        'toString',
        'toFixed',
        'toPrecision',
        'match',
        'search',
        'push',
        'pop',
        'splice',
      ].includes(member)
    ) {
      return data;
    }
    return { kind: 'method', receiver: value, name: member };
  }
  return failInspection('Unknown receiver may execute a property getter.');
};

export { indexedValue, namedMember };
