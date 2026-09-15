import { data, isData, text } from './data';
import { failInspection } from './syntax';
import type { CodeLanguage, Value } from './types';
import { symbol } from './values';

const indexedValue = (value: Value, key: Value): Value => {
  if (!isData(key)) {
    return failInspection('Index has uninspected effects.');
  }
  if (value.kind === 'text' || value.kind === 'string') {
    return text;
  }
  if (value.kind === 'data' || value.kind === 'counter') {
    return data;
  }
  if (value.kind === 'list' && key.kind === 'number') {
    return value.items[key.value] ?? data;
  }
  if (value.kind === 'object' && key.kind === 'string') {
    return value.entries.get(key.value) ?? data;
  }
  return failInspection('Computed property access is not inspected.');
};

const namedMember = (value: Value, member: string, language: CodeLanguage): Value => {
  if (member.startsWith('_') || member === 'constructor' || member === 'prototype') {
    return failInspection('Runtime reflection is not inspected.');
  }
  if (value.kind === 'symbol') {
    return symbol(`${value.name}.${member}`);
  }
  if (
    value.kind === 'path' ||
    value.kind === 'file' ||
    value.kind === 'archive' ||
    value.kind === 'hash' ||
    value.kind === 'bun-file'
  ) {
    return { kind: 'method', receiver: value, name: member };
  }
  if (value.kind === 'object' && language !== 'python') {
    return value.entries.get(member) ?? data;
  }
  if (isData(value)) {
    if (value.kind === 'data' && language !== 'python') {
      return data;
    }
    return { kind: 'method', receiver: value, name: member };
  }
  return failInspection('Unknown receiver may execute a property getter.');
};

export { indexedValue, namedMember };
