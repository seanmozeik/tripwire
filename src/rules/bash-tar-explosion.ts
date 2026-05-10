import { type Segment, hasBypass } from '../lib/bash';
import { type Decision, allow, deny } from '../lib/decision';

// Block tar/zip/unzip extractions that would write into / or $HOME
// (`tar -xf foo.tar.gz -C /` style explosions).

const isExtractFlag = (f: string): boolean =>
  f === '-x' ||
  f === '-xf' ||
  f === '-xzf' ||
  f === '-xjf' ||
  f === '-xJf' ||
  f === '-xvf' ||
  f === '-xvzf' ||
  f === '-xvjf' ||
  f === '--extract' ||
  /^-[xvzjJtf]+$/.test(f);

const findChangeDir = (seg: Segment): string | null => {
  for (let i = 0; i < seg.tokens.length; i++) {
    const t = seg.tokens[i]!;
    if (t === '-C' || t === '--directory') {
      return seg.tokens[i + 1] ?? null;
    }
    if (t.startsWith('--directory=')) {
      return t.slice('--directory='.length);
    }
  }
  return null;
};

const isUnsafeExtractDest = (dest: string): boolean => {
  return dest === '/' || /^(~|\$HOME|\$\{HOME\})$/.test(dest);
};

const bashTarExplosion = (segments: readonly Segment[], cmd: string): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-tar-explosion');
  }
  for (const seg of segments) {
    if (seg.head !== 'tar') {
      continue;
    }
    const extracting = seg.flags.some(isExtractFlag) || seg.tokens.includes('--extract');
    if (!extracting) {
      continue;
    }
    const dest = findChangeDir(seg);
    if (dest !== null && isUnsafeExtractDest(dest)) {
      return deny(
        'tar-extract-to-root',
        `tar -x with -C ${dest} can overwrite arbitrary system files. Refuse — extract to a contained directory (e.g. ./tmp/extract) and inspect before moving anything elsewhere.`,
      );
    }
  }
  // Unzip with -d destination
  for (const seg of segments) {
    if (seg.head !== 'unzip') {
      continue;
    }
    for (let i = 0; i < seg.tokens.length; i++) {
      if (seg.tokens[i] === '-d') {
        const dest = seg.tokens[i + 1];
        if (dest !== undefined && isUnsafeExtractDest(dest)) {
          return deny(
            'unzip-to-root',
            `unzip -d ${dest} can overwrite arbitrary system files. Refuse — extract to a contained directory.`,
          );
        }
      }
    }
  }
  return allow('bash-tar-explosion');
};

export { bashTarExplosion };
