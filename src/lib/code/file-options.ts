import { requireData } from './data';
import { failInspection } from './syntax';
import type { Value } from './types';
import { valueString } from './values';

const WRITE_FLAGS = new Set(['w', 'wx', 'a', 'ax', 'r+', 'w+', 'wx+', 'a+', 'ax+']);
const NODE_DATA_OPTIONS = new Set(['mode', 'flush']);
const DENO_DATA_OPTIONS = new Set(['mode', 'append', 'create']);

const validateReadOptions = (name: string, args: readonly Value[]): void => {
  if (!name.startsWith('fs.')) {
    if (args.length !== 1) {
      failInspection('File read options require review.');
    }
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
  if (args.length < 2 || args.length > 3) {
    return failInspection('A file write needs data and no uninspected callbacks.');
  }
  const options = args.at(2);
  if (options === undefined) {
    return;
  }
  const node = name.startsWith('fs.');
  if (node && options.kind === 'string' && Buffer.isEncoding(options.value)) {
    return;
  }
  if (options.kind !== 'object') {
    return failInspection('Write options are unresolved.');
  }
  const dataOptions = node ? NODE_DATA_OPTIONS : DENO_DATA_OPTIONS;
  for (const [key, value] of options.entries) {
    requireData([value]);
    // These options can change output bytes or open mode, but not the target.
    const accepted =
      dataOptions.has(key) ||
      (node && key === 'encoding' && value.kind === 'string' && Buffer.isEncoding(value.value)) ||
      (node && key === 'flag' && WRITE_FLAGS.has(valueString(value)));
    if (!accepted) {
      return failInspection('Unsupported file write option.');
    }
  }
};

export { validateReadOptions, validateWriteOptions };
