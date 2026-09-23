import { bindArguments, type CallArguments, type CallSignature } from './arguments';
import { validateCodec } from './codecs';
import { requireData } from './data';
import { pythonSignatures } from './python-library';
import type { Value } from './types';
import { archiveSignatures, zipSignatures } from './zipfile';

const inert = (value: Value): void => {
  requireData([value]);
};
const signatures: Readonly<Record<string, CallSignature>> = {
  ...pythonSignatures,
  ...zipSignatures,
  open: { parameters: ['file', 'mode'], options: { encoding: validateCodec } },
  'json.dump': { parameters: ['obj', 'fp'], options: { indent: inert } },
  'json.dumps': {
    parameters: ['obj'],
    options: { indent: inert, sort_keys: inert, ensure_ascii: inert, separators: inert },
  },
  're.sub': {
    parameters: ['pattern', 'repl', 'string', 'count', 'flags'],
    defaults: { count: { kind: 'number', value: 0 } },
  },
  'subprocess.check_output': {
    parameters: ['args'],
    options: { text: inert, encoding: validateCodec, timeout: inert },
  },
  'subprocess.run': {
    parameters: ['args'],
    options: {
      text: inert,
      encoding: validateCodec,
      capture_output: inert,
      check: inert,
      timeout: inert,
    },
  },
  sorted: { parameters: ['iterable'], options: { reverse: inert } },
};
const pathSignatures: Readonly<Record<string, CallSignature>> = {
  unlink: { parameters: [], options: { missing_ok: inert } },
  symlink_to: { parameters: ['target'], options: { target_is_directory: inert } },
  read_text: { parameters: [], options: { encoding: validateCodec } },
  write_text: { parameters: ['data'], options: { encoding: validateCodec } },
  mkdir: { parameters: [], options: { parents: inert, exist_ok: inert } },
};

const signatureFor = (fn: Value): CallSignature | undefined => {
  if (fn.kind === 'symbol') {
    return Object.hasOwn(signatures, fn.name) ? signatures[fn.name] : undefined;
  }
  if (fn.kind !== 'method') {
    return undefined;
  }
  if (
    fn.receiver.kind === 'builtin' &&
    fn.receiver.name === 'datetime' &&
    fn.name === 'isoformat'
  ) {
    return { parameters: [], options: { timespec: inert, sep: inert } };
  }
  if (fn.receiver.kind === 'archive') {
    return Object.hasOwn(archiveSignatures, fn.name) ? archiveSignatures[fn.name] : undefined;
  }
  if (fn.receiver.kind === 'path') {
    return Object.hasOwn(pathSignatures, fn.name) ? pathSignatures[fn.name] : undefined;
  }
  if (['string', 'text', 'data'].includes(fn.receiver.kind) && fn.name === 'splitlines') {
    return { parameters: ['keepends'] };
  }
  if (['string', 'text'].includes(fn.receiver.kind) && ['decode', 'encode'].includes(fn.name)) {
    return { parameters: ['encoding'] };
  }
  return undefined;
};

const normalizeCallArguments = (fn: Value, input: CallArguments): readonly Value[] =>
  bindArguments(input, signatureFor(fn));

export { normalizeCallArguments };
