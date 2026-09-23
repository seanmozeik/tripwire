import { statSync } from 'node:fs';
import path from 'node:path';

import type { ShellInvocation, ShellWord } from './types';
import type { Environment } from './values';
import { skipHeadRenamingPrefix } from './wrappers';

const resolveDirectory = (target: ShellWord | undefined, cwd: string | null): string | null => {
  if (target?.kind !== 'literal' || target.value === '-' || target.value === '') {
    return null;
  }
  const expanded = target.value;
  if (!path.isAbsolute(expanded) && cwd === null) {
    return null;
  }
  try {
    const resolved = path.resolve(cwd ?? '/', expanded);
    return statSync(resolved).isDirectory() ? resolved : null;
  } catch {
    return null;
  }
};

const usesCdpath = (target: ShellWord, environment: Environment): boolean => {
  const cdpath = environment.bindings.get('CDPATH');
  return (
    cdpath !== undefined &&
    cdpath.value !== '' &&
    !path.isAbsolute(target.value) &&
    !['.', '..'].includes(target.value) &&
    !target.value.startsWith('./') &&
    !target.value.startsWith('../') &&
    !target.value.startsWith('~')
  );
};

const changeDirectory = (invocation: ShellInvocation, environment: Environment): void => {
  if (['command', 'builtin'].includes(invocation.head)) {
    const words = invocation.words.slice(skipHeadRenamingPrefix(invocation));
    const [head] = words;
    if (head?.kind === 'literal' && ['cd', 'pushd', 'popd'].includes(head.value)) {
      changeDirectory({ ...invocation, head: head.value, words }, environment);
    }
    return;
  }
  if (!['cd', 'pushd', 'popd'].includes(invocation.head)) {
    return;
  }
  const args = invocation.words.slice(1).filter((word) => word.value !== '--');
  if (invocation.head === 'popd') {
    environment.cwd = args.length === 0 ? (environment.directoryStack.pop() ?? null) : null;
  } else if (invocation.head === 'pushd' && args.length === 0) {
    const previous = environment.directoryStack.pop() ?? null;
    environment.directoryStack.push(environment.cwd);
    environment.cwd = previous;
  } else {
    if (invocation.head === 'pushd') {
      environment.directoryStack.push(environment.cwd);
    }
    const target = args[0] ?? environment.bindings.get('HOME');
    const searched = target !== undefined && usesCdpath(target, environment);
    environment.cwd =
      args.length <= 1 && !searched ? resolveDirectory(target, environment.cwd) : null;
  }
  if (environment.cwd === null) {
    environment.directoryStack = [];
  }
  environment.bindings.delete('PWD');
};

export { changeDirectory, resolveDirectory };
