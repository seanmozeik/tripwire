import type { CallSignature } from './arguments';
import { data, requireData, text } from './data';
import { failInspection } from './syntax';
import type { CodeOperation, CodeRange, Value } from './types';
import { valueString } from './values';

interface ArchiveContext {
  readonly operations: CodeOperation[];
  readonly range: CodeRange;
}

const zipSignatures: Readonly<Record<string, CallSignature>> = {
  'zipfile.ZipFile': {
    parameters: ['file', 'mode', 'compression'],
    defaults: { mode: { kind: 'string', value: 'r' } },
  },
  'zipfile.is_zipfile': { parameters: ['filename'] },
};
const archiveSignatures: Readonly<Record<string, CallSignature>> = {
  read: { parameters: ['name'] },
  write: { parameters: ['filename', 'arcname'] },
  writestr: { parameters: ['zinfo_or_arcname', 'data'] },
};

const openArchive = (args: readonly Value[], context: ArchiveContext): Value => {
  if (args.length < 1 || args.length > 3) {
    return failInspection('ZIP constructor options are not inspected.');
  }
  const [file, modeValue, compression] = args;
  const target = valueString(file);
  const mode = modeValue === undefined ? 'r' : valueString(modeValue);
  if (!['r', 'w', 'x', 'a'].includes(mode)) {
    return failInspection('ZIP open mode must be r, w, x, or a.');
  }
  if (
    compression !== undefined &&
    compression.kind !== 'number' &&
    !(
      compression.kind === 'symbol' &&
      /^zipfile\.ZIP_(?:STORED|DEFLATED|BZIP2|LZMA|ZSTANDARD)$/u.test(compression.name)
    )
  ) {
    return failInspection('ZIP compression must be a standard constant.');
  }
  context.operations.push({
    kind: mode === 'r' ? 'read' : 'write',
    path: target,
    range: context.range,
  });
  return { kind: 'archive', path: target };
};

const archiveCall = (
  archive: Extract<Value, { kind: 'archive' }>,
  member: string,
  args: readonly Value[],
  context: ArchiveContext,
): Value => {
  requireData(args);
  if (['close', 'namelist', 'testzip', 'printdir'].includes(member) && args.length === 0) {
    return data;
  }
  if (member === 'read' && args.length === 1) {
    return text;
  }
  if (member === 'write' && args.length >= 1 && args.length <= 2) {
    context.operations.push(
      { kind: 'read', path: valueString(args[0]), range: context.range },
      { kind: 'write', path: archive.path, range: context.range },
    );
    return data;
  }
  if (member === 'writestr' && args.length === 2) {
    context.operations.push({ kind: 'write', path: archive.path, range: context.range });
    return data;
  }
  if (member === 'extract' || member === 'extractall') {
    return failInspection(
      'ZIP extraction needs verified member destinations. Read named members and write them to explicit paths.',
    );
  }
  return failInspection(`Unsupported ZIP method: ${member}.`);
};

export { archiveCall, openArchive, zipSignatures, archiveSignatures };
