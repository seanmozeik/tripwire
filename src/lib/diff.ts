import { readFileSync } from 'node:fs';

// Lines present in `next` but not in `prev`, compared trimmed.
// Whitespace-only differences are ignored — we want semantic additions.
const addedLines = (prev: string, next: string): string[] => {
  const prevSet = new Set(
    prev
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0),
  );
  return next
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .filter((l) => !prevSet.has(l.trim()));
};

const readFileOrEmpty = (path: string): string => {
  try {
    return readFileSync(path, 'utf8');
  } catch {
    return '';
  }
};

export { addedLines, readFileOrEmpty };
