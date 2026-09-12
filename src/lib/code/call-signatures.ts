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
  'json.dumps': { parameters: ['obj'], options: { indent: inert } },
};
const pathSignatures: Readonly<Record<string, CallSignature>> = {
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
  if (fn.receiver.kind === 'archive') {
    return Object.hasOwn(archiveSignatures, fn.name) ? archiveSignatures[fn.name] : undefined;
  }
  if (fn.receiver.kind === 'path') {
    return Object.hasOwn(pathSignatures, fn.name) ? pathSignatures[fn.name] : undefined;
  }
  if (['string', 'text'].includes(fn.receiver.kind) && ['decode', 'encode'].includes(fn.name)) {
    return { parameters: ['encoding'] };
  }
  return undefined;
};

const normalizeCallArguments = (fn: Value, input: CallArguments): readonly Value[] =>
  bindArguments(input, signatureFor(fn));

export { normalizeCallArguments };
