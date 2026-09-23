import { readlinkSync } from 'node:fs';
import path from 'node:path';

import { resolveWritePath } from '../path-resolution';
import { failInspection } from './syntax';
import type { CodeOperation, CodeRange, Value } from './types';

const overlaps = (first: string, second: string): boolean =>
  first === second || first.startsWith(`${second}/`) || second.startsWith(`${first}/`);

const changedPaths = (operation: CodeOperation): readonly string[] | null => {
  if (operation.kind !== 'process') {
    return operation.kind === 'read' || operation.kind === 'json-module' ? [] : [operation.path];
  }
  const [command] = operation.argv;
  if (command === undefined || !['mv', 'cp', 'ln'].includes(command)) {
    return null;
  }
  return command === 'mv'
    ? operation.argv.slice(operation.argv.indexOf('--') + 1)
    : operation.argv.slice(-1);
};

const resolvePathCall = (
  submitted: string,
  method: string,
  args: readonly Value[],
  context: {
    readonly operations: CodeOperation[];
    readonly range: CodeRange;
    readonly cwd?: string;
  },
): Value => {
  if (args.length > 0 || context.cwd === undefined) {
    return failInspection('Path resolution needs a known working directory and checked options.');
  }
  const target = path.resolve(context.cwd, submitted);
  const actual = resolveWritePath(target);
  for (const operation of context.operations) {
    const affected = changedPaths(operation);
    if (
      affected === null ||
      affected.some((value) => {
        const mutation = path.resolve(operation.cwd ?? context.cwd ?? '.', value);
        return overlaps(target, mutation) || overlaps(actual, resolveWritePath(mutation));
      })
    ) {
      return failInspection(
        'Earlier filesystem effects can change this resolved path. Use a literal destination that can be checked directly.',
      );
    }
  }
  context.operations.push({ kind: 'read', path: target, range: context.range });
  if (method === 'resolve') {
    return { kind: 'path', path: actual };
  }
  try {
    return { kind: 'path', path: readlinkSync(target) };
  } catch {
    return { kind: 'opaque-path' };
  }
};

export { resolvePathCall };
