import { data, requireData, text } from './data';
import { children, failInspection, parseCode } from './syntax';
import type { Value } from './types';

const transpiler = (args: readonly Value[]): Value => {
  if (args.length > 1) {
    return failInspection('Unexpected transpiler arguments.');
  }
  const [options] = args;
  if (options !== undefined) {
    if (options.kind !== 'object' || options.opaque === true) {
      return failInspection('Transpiler options must be known.');
    }
    for (const [key, value] of options.entries) {
      if (!['loader', 'target'].includes(key)) {
        return failInspection('Transpiler macros and custom configuration require review.');
      }
      requireData([value]);
    }
  }
  return { kind: 'builtin', name: 'transpiler' };
};
const transpile = (method: string, args: readonly Value[]): Value => {
  requireData(args);
  if (
    !['transformSync', 'transform', 'scan', 'scanImports'].includes(method) ||
    args.length < 1 ||
    args.length > 2
  ) {
    return failInspection('Uninspected transpiler method.');
  }
  const [source] = args;
  if (source?.kind !== 'string') {
    return failInspection(
      'Runtime transpiler source may execute uninspected macros. Submit literal source for inspection.',
    );
  }
  const pending = [parseCode('typescript', source.value)];
  while (pending.length > 0) {
    const node = pending.pop();
    if (node !== undefined) {
      if (['ImportDeclaration', 'DynamicImport'].includes(node.name)) {
        return failInspection('Transpiler imports may execute macros.');
      }
      pending.push(...children(node));
    }
  }
  return method.startsWith('scan') ? data : text;
};

export { transpiler, transpile };
