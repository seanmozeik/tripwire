import { failInspection } from './syntax';
import type { Value } from './types';
import { valueString } from './values';

const STANDARD_CODECS = new Set([
  'utf8',
  'utf16',
  'utf16le',
  'utf16be',
  'utf32',
  'utf32le',
  'utf32be',
  'ascii',
  'latin1',
]);

const validateCodec = (value: Value): void => {
  const encoding = valueString(value).toLowerCase().replaceAll(/[-_]/gu, '');
  if (!STANDARD_CODECS.has(encoding)) {
    failInspection('Custom Python codecs require review.');
  }
};

export { validateCodec };
