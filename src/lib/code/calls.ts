import path from 'node:path';

import type { CallArguments } from './arguments';
import { builtinCall, builtinMethod } from './builtins';
import { normalizeCallArguments } from './call-signatures';
import { callbackCall } from './callbacks';
import { data, dataCall, dataMethod, isData, requireData, text } from './data';
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
  readonly callback: (fn: Value, args: readonly Value[]) => Value;
  readonly language: CodeLanguage;
  readonly range: CodeRange;
  readonly operations: CodeOperation[];
}

const processArguments = (name: string, args: readonly Value[]): readonly string[] => {
  const [first, second] = args;
  if (name.startsWith('subprocess.')) {
    if (args.length !== 1 || first?.kind !== 'list' || first.opaque === true) {
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

const pathEffect = (
  receiver: Extract<Value, { kind: 'path' | 'file' }>,
  member: string,
  args: readonly Value[],
  context: CallContext,
): Value | null => {
  if (receiver.kind === 'path' && ['rename', 'replace', 'symlink_to'].includes(member)) {
    const target = valueString(args[0]);
    context.operations.push(
      {
        kind: member === 'symlink_to' ? 'read' : 'delete',
        path: receiver.path,
        range: context.range,
      },
      {
        kind: 'write',
        path: member === 'symlink_to' ? receiver.path : target,
        range: context.range,
      },
    );
    if (member !== 'symlink_to') {
      context.operations.push({ kind: 'delete', path: target, range: context.range });
    }
    if (member === 'symlink_to') {
      context.operations.push({ kind: 'read', path: target, range: context.range });
    }
    return { kind: 'path', path: target };
  }
  if (receiver.kind === 'path' && member === 'with_name') {
    return {
      kind: 'path',
      path: path.posix.join(path.posix.dirname(receiver.path), valueString(args[0])),
    };
  }
  if (
    receiver.kind === 'path' &&
    ['stat', 'is_symlink', 'exists', 'is_file', 'is_dir'].includes(member)
  ) {
    requireData(args);
    context.operations.push({ kind: 'read', path: receiver.path, range: context.range });
    return data;
  }
  return null;
};

const pathCall = (
  receiver: Extract<Value, { kind: 'path' | 'file' }>,
  member: string,
  args: readonly Value[],
  context: CallContext,
): Value => {
  const extra = pathEffect(receiver, member, args, context);
  if (extra !== null) {
    return extra;
  }
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
      : { read: 'read', readlines: 'read', readline: 'read', write: 'write' };
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
  return kind === 'read' && member !== 'readlines' ? text : data;
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

const collectionMethod = (
  fn: Extract<Value, { kind: 'method' }>,
  args: readonly Value[],
): Value | null => {
  if (fn.receiver.kind === 'builtin') {
    return (
      builtinMethod(fn.receiver.name, fn.name, args) ??
      failInspection('Unsupported builtin method.')
    );
  }
  if (
    isData(fn.receiver) &&
    [
      'append',
      'extend',
      'insert',
      'push',
      'pop',
      'splice',
      'update',
      'clear',
      'add',
      'set',
      'sort',
      'reverse',
    ].includes(fn.name)
  ) {
    requireData([fn.receiver, ...args]);
    if (fn.receiver.kind === 'list' || fn.receiver.kind === 'object') {
      fn.receiver.opaque = true;
    }
    return data;
  }
  return null;
};

const methodCall = (
  fn: Extract<Value, { kind: 'method' }>,
  args: readonly Value[],
  context: CallContext,
): Value => {
  const extra = collectionMethod(fn, args);
  if (extra !== null) {
    return extra;
  }
  if (fn.receiver.kind === 'bun-file') {
    if (!['json', 'text', 'arrayBuffer', 'bytes'].includes(fn.name) || args.length !== 0) {
      return failInspection('Unsupported Bun file read.');
    }
    context.operations.push({ kind: 'read', path: fn.receiver.path, range: context.range });
    return fn.name === 'text' ? text : data;
  }
  if (fn.receiver.kind === 'hash') {
    requireData(args);
    if (fn.name === 'update' && args.length === 1) {
      return { kind: 'hash' };
    }
    if (fn.name === 'copy' && args.length === 0) {
      return { kind: 'hash' };
    }
    if (['digest', 'hexdigest'].includes(fn.name) && args.length <= 1) {
      return text;
    }
    return failInspection('Unsupported hash operation.');
  }
  if (fn.receiver.kind === 'archive') {
    return archiveCall(fn.receiver, fn.name, args, context);
  }
  return fn.receiver.kind === 'path' || fn.receiver.kind === 'file'
    ? pathCall(fn.receiver, fn.name, args, context)
    : dataMethod(fn.receiver, fn.name, args, context.language);
};

const printCall = (fn: Value, input: CallArguments): Value | null => {
  if (fn.kind === 'symbol' && fn.name === 'print') {
    for (const [key, value] of input.keywords) {
      if (
        key === 'file' &&
        value.kind === 'symbol' &&
        ['sys.stderr', 'sys.stdout'].includes(value.name)
      ) {
        requireData(input.positional);
      } else if (['sep', 'end', 'flush'].includes(key)) {
        requireData([value]);
      } else {
        return failInspection('Unsupported print destination or option.');
      }
    }
    requireData(input.positional);
    return data;
  }
  return null;
};

const resolveCall = (fn: Value, input: CallArguments, context: CallContext): Value => {
  const callback = callbackCall(fn, input, context.callback);
  if (callback !== null) {
    return callback;
  }
  const printed = printCall(fn, input);
  if (printed !== null) {
    return printed;
  }
  const args = normalizeCallArguments(fn, input);
  if (fn.kind === 'method') {
    return methodCall(fn, args, context);
  }
  if (fn.kind !== 'symbol') {
    return failInspection('Dynamic call target.');
  }
  const { name } = fn;
  const builtin = builtinCall(name, args);
  if (builtin !== null) {
    return builtin;
  }
  const library = pythonLibraryCall(name, args, context);
  if (library !== null) {
    return library;
  }
  const fileEffect = transferCall(name, args, context);
  if (fileEffect !== null) {
    return fileEffect;
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
  return effectCall(name, args, context);
};

const effectCall = (name: string, args: readonly Value[], context: CallContext): Value => {
  if (name === 'require') {
    const target = valueString(args[0]);
    if (args.length === 1 && /^(?:\.{1,2}\/|\/).*\.json$/u.test(target)) {
      context.operations.push({ kind: 'json-module', path: target, range: context.range });
      return data;
    }
    return symbol(moduleName(target, context.language));
  }
  if (['pathlib.Path', 'pathlib.PosixPath'].includes(name)) {
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
  if (name === 'Bun.file') {
    return bunFile(args);
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
    return name === 'subprocess.check_output' ? text : data;
  }
  return failInspection(`Call ${JSON.stringify(name)} has uninspected effects.`);
};

const bunFile = (args: readonly Value[]): Value => {
  if (args.length !== 1) {
    return failInspection('Bun.file requires one literal path.');
  }
  return { kind: 'bun-file', path: valueString(args[0]) };
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
  return data;
};

const transferCall = (name: string, args: readonly Value[], context: CallContext): Value | null => {
  if (['fs.readdirSync', 'fs.statSync', 'fs.lstatSync', 'os.listdir'].includes(name)) {
    requireData(args.slice(1));
    context.operations.push({ kind: 'read', path: valueString(args[0]), range: context.range });
    return data;
  }
  if (name === 'fs.mkdirSync') {
    requireData(args.slice(1));
    context.operations.push({ kind: 'write', path: valueString(args[0]), range: context.range });
    return data;
  }
  const copy = [
    'fs.copyFileSync',
    'shutil.copy',
    'shutil.copy2',
    'shutil.copyfile',
    'fs.symlinkSync',
    'os.symlink',
  ].includes(name);
  const move = ['fs.renameSync', 'os.rename', 'os.replace', 'shutil.move'].includes(name);
  if (!copy && !move) {
    return null;
  }
  if (args.length !== 2) {
    return failInspection('File transfer options require inspection.');
  }
  context.operations.push(
    { kind: 'read', path: valueString(args[0]), range: context.range },
    { kind: 'write', path: valueString(args[1]), range: context.range },
  );
  if (move) {
    context.operations.push(
      { kind: 'delete', path: valueString(args[0]), range: context.range },
      { kind: 'delete', path: valueString(args[1]), range: context.range },
    );
  }
  return data;
};

export { resolveCall };
