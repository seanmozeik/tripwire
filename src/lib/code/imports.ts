import type { SyntaxNode } from '@lezer/common';

import { children, failInspection, stringLiteral } from './syntax';
import type { CodeLanguage, Value } from './types';
import { moduleName, symbol } from './values';

const pythonModuleBinding = (
  name: string,
  from: string | null,
): { qualified: string; bound: string } => {
  const qualified = from === null ? moduleName(name, 'python') : `${from}.${name}`;
  // An unaliased "import os.path" binds os, while "from os import path" binds os.path.
  return { qualified, bound: from === null ? (qualified.split('.')[0] ?? qualified) : qualified };
};

const dottedImport = (
  parts: readonly SyntaxNode[],
  start: number,
  initial: string,
  text: (node: SyntaxNode) => string,
): { name: string; index: number } => {
  let name = initial;
  let index = start;
  while (parts[index]?.name === '.') {
    const next = parts[index + 1];
    if (next?.name !== 'VariableName') {
      return failInspection('Missing dotted module member.');
    }
    name += `.${text(next)}`;
    index += 2;
  }
  return { name, index };
};

const pythonImport = (
  input: readonly SyntaxNode[],
  text: (node: SyntaxNode) => string,
): ReadonlyMap<string, Value> => {
  const parts = input.filter((part) => !['(', ')'].includes(part.name));
  const [first, moduleNode] = parts;
  if (moduleNode === undefined) {
    return failInspection('Missing Python import.');
  }
  const from =
    first?.name === 'from'
      ? moduleName(
          parts
            .slice(
              1,
              parts.findIndex((part) => part.name === 'import'),
            )
            .map((part) => text(part))
            .join(''),
          'python',
        )
      : null;
  const bindings = new Map<string, Value>();
  let index = from === null ? 1 : parts.findIndex((part) => part.name === 'import') + 1;
  while (index < parts.length) {
    const imported = parts[index];
    if (imported?.name !== 'VariableName' && imported?.name !== 'MemberExpression') {
      return failInspection('Unsupported Python import list.');
    }
    let importedName = text(imported);
    index += 1;
    const dotted = dottedImport(parts, index, importedName, text);
    importedName = dotted.name;
    ({ index } = dotted);
    const binding = pythonModuleBinding(importedName, from);
    let alias = importedName.split('.')[0] ?? '';
    let { bound } = binding;
    if (parts[index]?.name === 'as') {
      const name = parts[index + 1];
      if (name?.name !== 'VariableName') {
        return failInspection('Invalid import alias.');
      }
      alias = text(name);
      bound = binding.qualified;
      index += 2;
    }
    bindings.set(alias, symbol(bound));
    if (index < parts.length && parts[index]?.name !== ',') {
      return failInspection('Unsupported import separator.');
    }
    index += 1;
  }
  return bindings;
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
