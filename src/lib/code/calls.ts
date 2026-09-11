import path from 'node:path';

import { data, dataCall, dataMethod, fileText, writeKind } from './data';
import { failInspection } from './syntax';
import type { CodeLanguage, CodeOperation, CodeRange, Value } from './types';
import { moduleName, pythonJoin, symbol, textValue, unknown, valueString } from './values';

const FILE_OPERATIONS = new Map<string, 'delete' | 'read' | 'write' | 'truncate'>([
  ...[
    'os.remove',
    'os.unlink',
    'os.rmdir',
    'shutil.rmtree',
    'fs.rm',
    'fs.rmSync',
    'fs.unlink',
    'fs.unlinkSync',
    'fs.rmdir',
    'fs.rmdirSync',
    'Deno.remove',
    'Deno.removeSync',
  ].map((name): [string, 'delete'] => [name, 'delete']),
  ...['fs.readFile', 'fs.readFileSync', 'Deno.readTextFile', 'Deno.readTextFileSync'].map(
    (name): [string, 'read'] => [name, 'read'],
  ),
  ...[
    'fs.writeFile',
    'fs.writeFileSync',
    'fs.appendFile',
    'fs.appendFileSync',
    'Deno.writeTextFile',
    'Deno.writeTextFileSync',
  ].map((name): [string, 'write'] => [name, 'write']),
  ...['os.truncate', 'fs.truncate', 'fs.truncateSync'].map((name): [string, 'truncate'] => [
    name,
    'truncate',
  ]),
]);
const PROCESS = new Set([
  'subprocess.run',
  'subprocess.call',
  'subprocess.check_call',
  'subprocess.check_output',
  'subprocess.Popen',
  'child_process.execFile',
  'child_process.execFileSync',
  'child_process.spawn',
  'child_process.spawnSync',
]);

interface CallContext {
  readonly language: CodeLanguage;
  readonly range: CodeRange;
  readonly operations: CodeOperation[];
}

const validateReadOptions = (name: string, args: readonly Value[]): void => {
  if (!name.startsWith('fs.')) {
    return;
  }
  if (args.length > 2) {
    return failInspection('Read callbacks are not inspected.');
  }
  const [, options] = args;
  if (options === undefined || options.kind === 'string') {
    return;
  }
  if (options.kind !== 'object') {
    return failInspection('Read options are unresolved.');
  }
  for (const [key, value] of options.entries) {
    if (key === 'flag' && valueString(value) !== 'r') {
      return failInspection('A file read flag can truncate or write the file.');
    }
    if (key !== 'flag' && key !== 'encoding') {
      return failInspection('Unsupported read option.');
    }
    valueString(value);
  }
};

const validateWriteOptions = (name: string, args: readonly Value[]): void => {
  if (!name.startsWith('fs.')) {
    return;
  }
  const options = args.at(2);
  if (options === undefined && args.length <= 2) {
    return;
  }
  // Encodings such as hex/base64 can turn a nonempty string into an empty write.
  if (
    args.length === 3 &&
    options?.kind === 'string' &&
    options.value.replace('-', '') === 'utf8'
  ) {
    return;
  }
  return failInspection('Write encodings, flags, and callbacks require explicit review.');
};

const processArguments = (name: string, args: readonly Value[]): readonly string[] => {
  const [first, second] = args;
  if (name.startsWith('subprocess.')) {
    if (args.length !== 1 || first?.kind !== 'list') {
      return failInspection('Subprocess options or shell execution require review.');
    }
    if (first.items.length === 0) {
      return failInspection('Empty subprocess argument list.');
    }
    return first.items.map((value) => valueString(value));
  }
  if (args.length > 2 || (second !== undefined && second.kind !== 'list')) {
    return failInspection('Subprocess options require review.');
  }
  return [
    valueString(first),
    ...(second?.kind === 'list' ? second.items.map((value) => valueString(value)) : []),
  ];
};

const pathCall = (
  receiver: Extract<Value, { kind: 'path' | 'file' }>,
  member: string,
  args: readonly Value[],
  context: CallContext,
): Value => {
  const kinds: Readonly<Record<string, 'delete' | 'read' | 'write'>> =
    receiver.kind === 'path'
      ? {
          unlink: 'delete',
          rmdir: 'delete',
          read_text: 'read',
          read_bytes: 'read',
          write_text: 'write',
          write_bytes: 'write',
        }
      : { read: 'read', write: 'write' };
  const kind = kinds[member];
  if (kind === undefined) {
    return failInspection(`Unsupported ${receiver.kind} method: ${member}.`);
  }
  if (kind === 'read' && args.length > 0) {
    return failInspection('File read encoding and offset options require review.');
  }
  if (kind === 'write' && args.length !== 1) {
    return failInspection('File write encoding and callback options require review.');
  }
  const effect = kind === 'write' ? writeKind(receiver.path, args[0]) : kind;
  context.operations.push({ kind: effect, path: receiver.path, range: context.range });
  return kind === 'read' ? fileText(receiver.path) : unknown;
};

const openFile = (args: readonly Value[], context: CallContext): Value => {
  if (args.length > 2) {
    return failInspection('File opener options are not inspected.');
  }
  const mode = args[1] === undefined ? 'r' : valueString(args[1]);
  const access: Readonly<Record<string, 'read' | 'truncate' | 'write'>> = {
    r: 'read',
    rb: 'read',
    rt: 'read',
    w: 'truncate',
    wb: 'truncate',
    wt: 'truncate',
    a: 'write',
    ab: 'write',
    at: 'write',
  };
  const kind = access[mode];
  if (kind === undefined) {
    return failInspection('Unsupported file open mode.');
  }
  const target = valueString(args[0]);
  context.operations.push({ kind, path: target, range: context.range });
  return { kind: 'file', path: target };
};

const resolveCall = (fn: Value, args: readonly Value[], context: CallContext): Value => {
  if (fn.kind === 'method') {
    return fn.receiver.kind === 'path' || fn.receiver.kind === 'file'
      ? pathCall(fn.receiver, fn.name, args, context)
      : dataMethod(fn.receiver, fn.name, args, context.language);
  }
  if (fn.kind !== 'symbol') {
    return failInspection('Dynamic call target.');
  }
  const { name } = fn;
  const pure = dataCall(name, args);
  if (pure !== null) {
    return pure;
  }
  if (name === 'require') {
    return symbol(moduleName(valueString(args[0]), context.language));
  }
  if (name === 'pathlib.Path' || name === 'pathlib.PosixPath') {
    return { kind: 'path', path: pythonJoin(args.map((value) => valueString(value))) };
  }
  if (name === 'os.path.join') {
    return textValue(pythonJoin(args.map((value) => valueString(value))));
  }
  if (name === 'path.join') {
    return textValue(path.posix.join(...args.map((value) => valueString(value))));
  }
  if (name === 'open') {
    return openFile(args, context);
  }
  const kind = FILE_OPERATIONS.get(name);
  if (kind !== undefined) {
    return fileOperation(name, kind, args, context);
  } else if (PROCESS.has(name)) {
    context.operations.push({
      kind: 'process',
      argv: processArguments(name, args),
      range: context.range,
    });
  } else {
    return failInspection(`Call ${JSON.stringify(name)} has uninspected effects.`);
  }
  return unknown;
};

const fileOperation = (
  name: string,
  kind: 'read' | 'write' | 'delete' | 'truncate',
  args: readonly Value[],
  context: CallContext,
): Value => {
  if (kind === 'read') {
    validateReadOptions(name, args);
  }
  if (kind === 'write') {
    validateWriteOptions(name, args);
  }
  const target = valueString(args[0]);
  const effect = kind === 'write' ? writeKind(target, args[1]) : kind;
  context.operations.push({ kind: effect, path: target, range: context.range });
  if (kind === 'read') {
    // Only UTF-8 preserves nonempty bytes as nonempty text. For example, a
    // one-byte file decoded as UTF-16LE can produce an empty string.
    const [, encoding] = args;
    return name.startsWith('Deno.') ||
      (encoding?.kind === 'string' && encoding.value.toLowerCase().replace('-', '') === 'utf8')
      ? fileText(target)
      : data;
  }
  return unknown;
};

export { resolveCall };
