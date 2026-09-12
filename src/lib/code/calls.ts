import path from 'node:path';

import type { CallArguments } from './arguments';
import { normalizeCallArguments } from './call-signatures';
import { data, dataCall, dataMethod, requireData, text } from './data';
import { validateReadOptions, validateWriteOptions } from './file-options';
import { pythonLibraryCall } from './python-library';
import { failInspection } from './syntax';
import type { CodeLanguage, CodeOperation, CodeRange, Value } from './types';
import { moduleName, pythonJoin, symbol, textValue, unknown, valueString } from './values';
import { archiveCall } from './zipfile';

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
  if (receiver.kind === 'path' && ['glob', 'rglob', 'iterdir'].includes(member)) {
    if (args.length !== (member === 'iterdir' ? 0 : 1)) {
      return failInspection('Directory listing options are not inspected.');
    }
    if (args[0] !== undefined) {
      valueString(args[0]);
    }
    context.operations.push({ kind: 'read', path: receiver.path, range: context.range });
    return data;
  }
  if (receiver.kind === 'file' && member === 'close' && args.length === 0) {
    return unknown;
  }
  const kinds: Readonly<Record<string, 'delete' | 'read' | 'write'>> =
    receiver.kind === 'path'
      ? {
          unlink: 'delete',
          rmdir: 'delete',
          read_text: 'read',
          read_bytes: 'read',
          write_text: 'write',
          write_bytes: 'write',
          mkdir: 'write',
        }
      : { read: 'read', write: 'write' };
  const kind = kinds[member];
  if (kind === undefined) {
    return failInspection(`Unsupported ${receiver.kind} method: ${member}.`);
  }
  if (kind === 'read' && args.length > 0) {
    return failInspection('File read encoding and offset options require review.');
  }
  if (kind === 'write' && args.length !== (member === 'mkdir' ? 0 : 1)) {
    return failInspection('File write encoding and callback options require review.');
  }
  if (kind === 'write') {
    requireData(args);
  }
  context.operations.push({ kind, path: receiver.path, range: context.range });
  return kind === 'read' ? text : data;
};

const openFile = (args: readonly Value[], context: CallContext): Value => {
  if (args.length > 2) {
    return failInspection('File opener options are not inspected.');
  }
  const mode = args[1] === undefined ? 'r' : valueString(args[1]);
  const access: Readonly<Record<string, 'read' | 'write'>> = {
    r: 'read',
    rb: 'read',
    rt: 'read',
    w: 'write',
    wb: 'write',
    wt: 'write',
    x: 'write',
    xb: 'write',
    xt: 'write',
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

const methodCall = (
  fn: Extract<Value, { kind: 'method' }>,
  args: readonly Value[],
  context: CallContext,
): Value => {
  if (fn.receiver.kind === 'archive') {
    return archiveCall(fn.receiver, fn.name, args, context);
  }
  return fn.receiver.kind === 'path' || fn.receiver.kind === 'file'
    ? pathCall(fn.receiver, fn.name, args, context)
    : dataMethod(fn.receiver, fn.name, args, context.language);
};

const resolveCall = (fn: Value, input: CallArguments, context: CallContext): Value => {
  const args = normalizeCallArguments(fn, input);
  if (fn.kind === 'method') {
    return methodCall(fn, args, context);
  }
  if (fn.kind !== 'symbol') {
    return failInspection('Dynamic call target.');
  }
  const { name } = fn;
  const library = pythonLibraryCall(name, args, context);
  if (library !== null) {
    return library;
  }
  if (name === 'json.dump') {
    const [value, file] = args;
    if (args.length !== 2 || value === undefined || file?.kind !== 'file') {
      return failInspection('JSON output needs inert data and a known file handle.');
    }
    requireData([value]);
    context.operations.push({ kind: 'write', path: file.path, range: context.range });
    return unknown;
  }
  const pure = dataCall(name, args);
  if (pure !== null) {
    return pure;
  }
  if (name === 'require') {
    const target = valueString(args[0]);
    if (args.length === 1 && /^(?:\.{1,2}\/|\/).*\.json$/u.test(target)) {
      context.operations.push({ kind: 'json-module', path: target, range: context.range });
      return data;
    }
    return symbol(moduleName(target, context.language));
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
  if (kind === 'write') {
    requireData(args.slice(1, 2));
  }
  context.operations.push({ kind, path: target, range: context.range });
  if (kind === 'read') {
    const [, encoding] = args;
    return name.startsWith('Deno.') || encoding?.kind === 'string' || encoding?.kind === 'object'
      ? text
      : data;
  }
  return unknown;
};

export { resolveCall };
