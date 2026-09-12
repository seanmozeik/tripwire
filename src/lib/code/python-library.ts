import path from 'node:path';

import type { CallSignature } from './arguments';
import { data, requireData } from './data';
import { failInspection } from './syntax';
import type { CodeOperation, CodeRange, Value } from './types';
import { valueString } from './values';
import { openArchive } from './zipfile';

const inert = (value: Value): void => {
  requireData([value]);
};
const diffSignature: CallSignature = {
  parameters: ['a', 'b', 'fromfile', 'tofile', 'fromfiledate', 'tofiledate', 'n', 'lineterm'],
  defaults: {
    fromfile: { kind: 'string', value: '' },
    tofile: { kind: 'string', value: '' },
    fromfiledate: { kind: 'string', value: '' },
    tofiledate: { kind: 'string', value: '' },
    n: { kind: 'number', value: 3 },
    lineterm: { kind: 'string', value: '\n' },
  },
};
const pythonSignatures: Readonly<Record<string, CallSignature>> = {
  'glob.glob': { parameters: ['pathname'], options: { recursive: inert } },
  'glob.iglob': { parameters: ['pathname'], options: { recursive: inert } },
  'difflib.unified_diff': diffSignature,
  'difflib.context_diff': diffSignature,
};

const pythonLibraryCall = (
  name: string,
  args: readonly Value[],
  context: { readonly operations: CodeOperation[]; readonly range: CodeRange },
): Value | null => {
  if (['glob.glob', 'glob.iglob'].includes(name)) {
    if (args.length !== 1) {
      return failInspection('Globbing needs a literal pattern.');
    }
    const pattern = valueString(args[0]);
    const prefix = pattern.split(/[?*[]/u)[0] ?? '';
    context.operations.push({
      kind: 'read',
      path: path.posix.dirname(prefix),
      range: context.range,
    });
    return data;
  }
  if (name === 'zipfile.ZipFile') {
    return openArchive(args, context);
  }
  if (name === 'zipfile.is_zipfile') {
    if (args.length !== 1) {
      return failInspection('ZIP inspection needs one file path.');
    }
    context.operations.push({ kind: 'read', path: valueString(args[0]), range: context.range });
    return data;
  }
  if (
    [
      'difflib.unified_diff',
      'difflib.context_diff',
      'difflib.ndiff',
      'difflib.get_close_matches',
    ].includes(name)
  ) {
    requireData(args);
    return data;
  }
  return null;
};

export { pythonLibraryCall, pythonSignatures };
