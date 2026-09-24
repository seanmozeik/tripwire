import { readlinkSync } from 'node:fs';
import path from 'node:path';

import { resolveWritePath } from '../path-resolution';
import { recordOperation, type OperationContext } from './operations';
import { failInspection } from './syntax';
import type { CodeOperation, Value } from './types';

const overlaps = (first: string, second: string): boolean =>
  first === second || first.startsWith(`${second}/`) || second.startsWith(`${first}/`);

const changedPaths = (operation: CodeOperation): readonly string[] | null => {
  if (operation.kind === 'process') {
    return operation.mutations;
  }
  if (operation.kind === 'transfer') {
    return operation.command === 'mv'
      ? [...operation.sources, operation.destination]
      : [operation.destination];
  }
  return operation.kind === 'read' || operation.kind === 'json-module' ? [] : [operation.path];
};

const resolvePathCall = (
  submitted: string,
  method: string,
  args: readonly Value[],
  context: OperationContext,
): Value => {
  if (args.length > 0 || context.cwd === null) {
    return failInspection('Path resolution needs a known working directory and checked options.');
  }
  const target = path.resolve(context.cwd, submitted);
  const actual = resolveWritePath(target);
  for (const operation of context.operations) {
    const affected = changedPaths(operation);
    if (
      affected === null ||
      affected.some((value) => {
        if (!path.isAbsolute(value) && operation.cwd === null) {
          return true;
        }
        const mutation =
          operation.cwd === null ? path.resolve(value) : path.resolve(operation.cwd, value);
        return overlaps(target, mutation) || overlaps(actual, resolveWritePath(mutation));
      })
    ) {
      return failInspection(
        'Earlier filesystem effects can change this resolved path. Use a literal destination that can be checked directly.',
      );
    }
  }
  recordOperation(context, { kind: 'read', path: target, range: context.range });
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
