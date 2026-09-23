import path from 'node:path';

import { failInspection } from './syntax';
import type { CodeEffect, CodeOperation, CodeRange } from './types';

interface OperationContext {
  readonly cwd: string | null;
  readonly range: CodeRange;
  readonly operations: CodeOperation[];
}

const recordOperation = (context: OperationContext, ...operations: readonly CodeEffect[]): void => {
  for (const operation of operations) {
    let { cwd } = context;
    if (cwd === null) {
      let paths: readonly string[] = [];
      if (operation.kind === 'transfer') {
        paths = [...operation.sources, operation.destination];
      } else if (operation.kind !== 'process') {
        paths = [operation.path];
      }
      if (paths.length === 0 || paths.some((target) => !path.isAbsolute(target))) {
        return failInspection('An operation depends on an unresolved working directory.');
      }
      // Absolute file operands do not depend on the interpreter's directory.
      cwd = '/';
    }
    context.operations.push({ ...operation, cwd });
  }
};

// Explicit process calls retain their conservative mutation footprint. Unlike
// inline file APIs, these still go through full command policy evaluation.
const recordProcess = (context: OperationContext, argv: readonly string[]): void => {
  const [command] = argv;
  let mutations: readonly string[] | null = null;
  if (command === 'mv') {
    mutations = argv.slice(argv.indexOf('--') + 1);
  } else if (command === 'cp' || command === 'ln') {
    mutations = argv.slice(-1);
  }
  recordOperation(context, { kind: 'process', argv, mutations, range: context.range });
};

export { recordOperation, recordProcess };
export type { OperationContext };
