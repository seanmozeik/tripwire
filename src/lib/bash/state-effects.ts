import { forEachChild, type SyntaxNode } from 'unbash';

import { variableWriteTargets } from './bindings';
import type { ShellInvocation } from './types';
import { wordIsStatic, type Environment } from './values';

const mayChangeDirectory = (node: SyntaxNode, environment: Environment): boolean => {
  const pending: SyntaxNode[] = [node];
  const seen = new Set<SyntaxNode>();

  while (pending.length > 0) {
    const value = pending.pop();

    if (value !== undefined && !seen.has(value)) {
      seen.add(value);

      if (value.type === 'Command') {
        const { name } = value;

        if (
          name !== undefined &&
          (['cd', 'pushd', 'popd'].includes(name.value) ||
            environment.functions.has(name.value) ||
            environment.aliases.has(name.value))
        ) {
          return true;
        }
      }

      forEachChild(value, (child) => {
        pending.push(child);
      });
    }
  }

  return false;
};

// A plain cd, pushd, or popd that no function or alias shadows.
const isDirectoryChange = (node: SyntaxNode, environment: Environment): boolean => {
  if (node.type === 'Pipeline' && node.commands.length === 1) {
    const [command] = node.commands;

    return command !== undefined && isDirectoryChange(command, environment);
  }

  return (
    node.type === 'Command' &&
    node.name !== undefined &&
    wordIsStatic(node.name) &&
    ['cd', 'pushd', 'popd'].includes(node.name.value) &&
    !environment.functions.has(node.name.value) &&
    !environment.aliases.has(node.name.value)
  );
};

const mayMutateHomeIndirectly = (invocation: ShellInvocation): boolean => {
  if (['source', '.', 'eval', 'read', 'getopts', 'let'].includes(invocation.head)) {
    return true;
  }

  if (invocation.head === 'printf' && variableWriteTargets(invocation) !== null) {
    return true;
  }

  if (['export', 'readonly', 'declare', 'typeset', 'local', 'unset'].includes(invocation.head)) {
    return (
      invocation.words.slice(1).some((word) => word.kind !== 'literal') ||
      invocation.flags.some((flag) => /^-[^-]*n/u.test(flag))
    );
  }

  return false;
};

const HOME_MUTATION_WORDS = new Set([
  'HOME',
  'source',
  '.',
  'eval',
  'read',
  'getopts',
  'let',
  'printf',
  'export',
  'declare',
  'typeset',
  'unset',
]);

// Loops may revisit an operand after a later mutation. Invalidate before the
// first visit unless the body cannot change the home binding.
const mayChangeHome = (node: SyntaxNode, environment: Environment): boolean => {
  const pending: SyntaxNode[] = [node];

  while (pending.length > 0) {
    const value = pending.pop();

    if (value !== undefined) {
      if ('name' in value && value.name === 'HOME') {
        return true;
      }

      if (
        'value' in value &&
        typeof value.value === 'string' &&
        (HOME_MUTATION_WORDS.has(value.value) ||
          value.value.startsWith('HOME=') ||
          environment.functions.has(value.value) ||
          environment.aliases.has(value.value))
      ) {
        return true;
      }

      forEachChild(value, (child) => {
        pending.push(child);
      });
    }
  }

  return false;
};

export { mayChangeDirectory, isDirectoryChange, mayMutateHomeIndirectly, mayChangeHome };
