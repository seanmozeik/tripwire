import type { ShellInvocation, ShellProgram } from '../lib/bash';
import { type Decision, allow, deny } from '../lib/decision';

// Block tar/zip/unzip extractions that would write into / or $HOME
// (`tar -xf foo.tar.gz -C /` style explosions).

const isExtractFlag = (flag: string): boolean =>
  flag === '--extract' ||
  (flag.startsWith('-') && !flag.startsWith('--') && flag.slice(1).includes('x'));

const findChangeDir = (seg: ShellInvocation): string | null => {
  for (let i = 0; i < seg.tokens.length; i += 1) {
    const t = seg.tokens[i];
    if (t !== undefined) {
      if (t === '-C' || t === '--directory') {
        return seg.tokens[i + 1] ?? null;
      }
      if (t.startsWith('--directory=')) {
        return t.slice('--directory='.length);
      }
    }
  }
  return null;
};

const isUnsafeExtractDest = (dest: string): boolean => {
  return dest === '/' || /^(?<home>~|\$HOME|\$\{HOME\})$/u.test(dest);
};

const unzipDestination = (seg: ShellInvocation): string | undefined => {
  const destinationFlag = seg.tokens.indexOf('-d');
  return destinationFlag === -1 ? undefined : seg.tokens[destinationFlag + 1];
};

const bashTarExplosion = (program: ShellProgram): Decision => {
  for (const seg of program.invocations) {
    if (seg.head === 'tar') {
      const [, legacyOptionWord] = seg.tokens;
      const extracting =
        seg.flags.some(isExtractFlag) ||
        seg.tokens.includes('--extract') ||
        (legacyOptionWord !== undefined &&
          /^[a-zA-Z]+$/u.test(legacyOptionWord) &&
          legacyOptionWord.includes('x'));
      const dest = extracting ? findChangeDir(seg) : null;
      if (dest !== null && isUnsafeExtractDest(dest)) {
        return deny(
          'tar-extract-to-root',
          `tar -x with -C ${dest} can overwrite arbitrary system files. Refuse — extract to a contained directory (e.g. ./tmp/extract) and inspect before moving anything elsewhere.`,
        );
      }
    }
  }
  // Unzip with -d destination
  for (const seg of program.invocations) {
    if (seg.head === 'unzip') {
      const dest = unzipDestination(seg);
      if (dest !== undefined && isUnsafeExtractDest(dest)) {
        return deny(
          'unzip-to-root',
          `unzip -d ${dest} can overwrite arbitrary system files. Refuse — extract to a contained directory.`,
        );
      }
    }
  }
  return allow('bash-tar-explosion');
};

export { bashTarExplosion };
