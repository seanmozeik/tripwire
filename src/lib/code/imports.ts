import type { SyntaxNode } from '@lezer/common';

import { children, failInspection, stringLiteral } from './syntax';
import type { CodeLanguage, Value } from './types';
import { moduleName, symbol } from './values';

const pythonImport = (
  parts: readonly SyntaxNode[],
  text: (node: SyntaxNode) => string,
): ReadonlyMap<string, Value> => {
  const [first, moduleNode] = parts;
  if (moduleNode === undefined) {
    return failInspection('Missing Python import.');
  }
  const module = moduleName(text(moduleNode), 'python');
  if (first?.name === 'from') {
    const importIndex = parts.findIndex((part) => part.name === 'import');
    const imported = parts[importIndex + 1];
    if (imported?.name !== 'VariableName') {
      return failInspection('Unsupported Python import.');
    }
    const alias = parts[importIndex + 2]?.name === 'as' ? parts[importIndex + 3] : imported;
    if (alias === undefined || parts.length !== importIndex + (alias === imported ? 2 : 4)) {
      return failInspection('Unsupported Python import list.');
    }
    return new Map([[text(alias), symbol(`${module}.${text(imported)}`)]]);
  }
  const alias = parts[2]?.name === 'as' ? parts[3] : moduleNode;
  if (alias === undefined || parts.length !== (alias === moduleNode ? 2 : 4)) {
    return failInspection('Unsupported Python import list.');
  }
  return new Map([[text(alias), symbol(module)]]);
};

const javascriptImport = (
  parts: readonly SyntaxNode[],
  text: (node: SyntaxNode) => string,
  language: CodeLanguage,
): ReadonlyMap<string, Value> => {
  const source = parts.find((part) => part.name === 'String');
  if (source === undefined) {
    return failInspection('Import source is unresolved.');
  }
  const module = moduleName(stringLiteral(text(source)), language);
  const group = parts.find((part) => part.name === 'ImportGroup');
  if (group === undefined) {
    const binding = parts.find((part) => part.name === 'VariableDefinition');
    if (binding === undefined) {
      return failInspection('Unsupported JavaScript import.');
    }
    return new Map([[text(binding), symbol(module)]]);
  }
  if (parts.some((part) => part.name === 'VariableDefinition')) {
    return failInspection('Combined default and named import requires review.');
  }
  const names = children(group).filter((part) => !['{', '}', ','].includes(part.name));
  const bindings = new Map<string, Value>();
  for (let index = 0; index < names.length; index += 1) {
    const imported = names[index];
    if (imported === undefined) {
      break;
    }
    const alias = names[index + 1]?.name === 'as' ? names[index + 2] : imported;
    if (alias === undefined) {
      return failInspection('Import alias is unresolved.');
    }
    bindings.set(text(alias), symbol(`${module}.${text(imported)}`));
    if (alias !== imported) {
      index += 2;
    }
  }
  return bindings;
};

export { javascriptImport, pythonImport };
