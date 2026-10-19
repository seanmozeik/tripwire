import { lstatSync, statSync } from 'node:fs';
import path from 'node:path';

import type { ShellInvocation, ShellWord } from './types';
import type { Environment } from './values';
import { skipHeadRenamingPrefix } from './wrappers';

const resolveShellPath = (target: string, cwd: string | null): string | null => {
  if (path.isAbsolute(target)) {
    return path.resolve(target);
  }

  return cwd === null ? null : path.resolve(cwd, target);
};

const isCreatedDirectory = (target: string, created: ReadonlySet<string>): boolean =>
  [...created].some((directory) => directory === target || directory.startsWith(`${target}/`));

// A directory that exists, or that an earlier `mkdir -p` in the same program
// made, is a known destination. An existing non-directory is never one.
const resolveDirectory = (
  target: ShellWord | undefined,
  cwd: string | null,
  created: ReadonlySet<string>,
): string | null => {
  if (target?.kind !== 'literal' || target.value === '-' || target.value === '') {
    return null;
  }

  const expanded = target.value;

  if (!path.isAbsolute(expanded) && cwd === null) {
    return null;
  }

  const resolved = resolveShellPath(expanded, cwd);

  if (resolved === null) {
    return null;
  }

  try {
    return statSync(resolved).isDirectory() ? resolved : null;
  } catch {
    return isCreatedDirectory(resolved, created) ? resolved : null;
  }
};

// `mkdir -p` fails when an existing component is a file or a dangling link.
const canCreateDirectory = (target: string): boolean => {
  let current = target;

  for (;;) {
    try {
      return statSync(current).isDirectory();
    } catch (error) {
      if (!(error instanceof Error) || !('code' in error) || error.code !== 'ENOENT') {
        return false;
      }
    }

    try {
      lstatSync(current);

      return false;
    } catch {
      // The component is missing. Check its parent.
    }

    const parent = path.dirname(current);

    if (parent === current) {
      return false;
    }

    current = parent;
  }
};

// Returns the operands of `mkdir -p`, or null for any other or unrecognized form.
const mkdirParentOperands = (invocation: ShellInvocation): readonly ShellWord[] | null => {
  let parents = false;
  const operands: ShellWord[] = [];
  const words = invocation.words.slice(1);

  for (let index = 0; index < words.length; index += 1) {
    const word = words[index];

    if (word?.kind !== 'literal') {
      return null;
    }

    const { value } = word;

    if (value === '--') {
      operands.push(...words.slice(index + 1));
      break;
    }

    if (value === '-m' || value === '--mode') {
      index += 1;
    } else if (value === '--parents' || /^-[pv]+$/u.test(value)) {
      parents ||= value === '--parents' || value.includes('p');
    } else if (value !== '--verbose' && !value.startsWith('--mode=')) {
      if (value.startsWith('-')) {
        return null;
      }

      operands.push(word);
    }
  }

  return parents ? operands : null;
};

// Record literal `mkdir -p` targets so a later `cd` into one resolves. The
// policy rules still classify every path under the resulting working directory.
const recordCreatedDirectories = (invocation: ShellInvocation, environment: Environment): void => {
  if (invocation.head !== 'mkdir' || invocation.synthetic) {
    return;
  }

  for (const operand of mkdirParentOperands(invocation) ?? []) {
    if (operand.kind === 'literal' && !operand.value.split('/').includes('..')) {
      const target = resolveShellPath(operand.value, invocation.cwd);

      if (target !== null && canCreateDirectory(target)) {
        environment.createdDirectories.add(target);
      }
    }
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
      args.length <= 1 && !searched
        ? resolveDirectory(target, environment.cwd, environment.createdDirectories)
        : null;
  }

  if (environment.cwd === null) {
    environment.directoryStack = [];
  }

  environment.bindings.delete('PWD');
};

export { changeDirectory, recordCreatedDirectories, resolveDirectory, resolveShellPath };
