interface Token {
  readonly raw: string;
  readonly value: string;
  readonly start: number;
  readonly end: number;
}

interface SegmentPart {
  readonly kind: 'segment';
  readonly text: string;
}

interface SeparatorPart {
  readonly kind: 'separator';
  readonly text: string;
}

type Part = SegmentPart | SeparatorPart;

const GREP_HEADS: ReadonlySet<string> = new Set(['grep', 'rg', 'egrep', 'fgrep']);
const COLLISION_SHORT: ReadonlySet<string> = new Set(['r', 'R', 'E']);
const COLLISION_LONG: ReadonlySet<string> = new Set([
  '--recursive',
  '--dereference-recursive',
  '--extended-regexp',
]);
const VALUE_SHORT: ReadonlySet<string> = new Set(['A', 'B', 'C', 'm', 'd', 'D', 'e', 'f']);

const basename = (head: string): string => {
  const slashIdx = head.lastIndexOf('/');
  return slashIdx === -1 ? head : head.slice(slashIdx + 1);
};

const splitShellSegments = (command: string): Part[] => {
  const parts: Part[] = [];
  let quote: "'" | '"' | null = null;
  let segmentStart = 0;
  let i = 0;

  while (i < command.length) {
    const ch = command[i]!;
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (quote === "'") {
      if (ch === "'") {
        quote = null;
      }
      i++;
      continue;
    }
    if (quote === '"') {
      if (ch === '"') {
        quote = null;
      }
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      i++;
      continue;
    }

    const two = command.slice(i, i + 2);
    const op = two === '&&' || two === '||' || two === '|&' ? two : ch;
    if (op === ';' || op === '&' || op === '|' || op === '&&' || op === '||' || op === '|&') {
      if (i > segmentStart) {
        parts.push({ kind: 'segment', text: command.slice(segmentStart, i) });
      }
      parts.push({ kind: 'separator', text: op });
      i += op.length;
      segmentStart = i;
      continue;
    }
    i++;
  }

  if (segmentStart < command.length) {
    parts.push({ kind: 'segment', text: command.slice(segmentStart) });
  }
  return parts;
};

const tokenizeSegment = (segment: string): Token[] => {
  const tokens: Token[] = [];
  let quote: "'" | '"' | null = null;
  let raw = '';
  let value = '';
  let start = 0;

  const flush = (end: number): void => {
    if (raw.length === 0) {
      return;
    }
    tokens.push({ raw, value, start, end });
    raw = '';
    value = '';
  };

  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i]!;
    if (raw.length === 0 && !/\s/u.test(ch)) {
      start = i;
    }
    if (ch === '\\') {
      raw += ch;
      const next = segment[i + 1];
      if (next !== undefined) {
        raw += next;
        value += next;
        i++;
      }
      continue;
    }
    if (quote === "'") {
      raw += ch;
      if (ch === "'") {
        quote = null;
      } else {
        value += ch;
      }
      continue;
    }
    if (quote === '"') {
      raw += ch;
      if (ch === '"') {
        quote = null;
      } else {
        value += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      raw += ch;
      quote = ch;
      continue;
    }
    if (/\s/u.test(ch)) {
      flush(i);
      continue;
    }
    raw += ch;
    value += ch;
  }
  flush(segment.length);
  return tokens;
};

const sanitizeShortFlag = (flag: string): string | null => {
  let out = '-';
  for (let i = 1; i < flag.length; i++) {
    const letter = flag[i]!;
    if (VALUE_SHORT.has(letter)) {
      out += flag.slice(i);
      return out.length === 1 ? null : out;
    }
    if (!COLLISION_SHORT.has(letter)) {
      out += letter;
    }
  }
  return out.length === 1 ? null : out;
};

const sanitizedTokenValues = (tokens: readonly Token[]): ReadonlyMap<Token, string | null> => {
  const changed = new Map<Token, string | null>();
  let optionsEnded = false;
  let skipValueFor: string | null = null;

  for (const token of tokens) {
    if (skipValueFor !== null) {
      skipValueFor = null;
      continue;
    }
    if (optionsEnded) {
      continue;
    }
    if (token.value === '--') {
      optionsEnded = true;
      continue;
    }
    if (COLLISION_LONG.has(token.value)) {
      changed.set(token, null);
      continue;
    }
    if (token.value.startsWith('--')) {
      continue;
    }
    if (token.value.startsWith('-') && token.value !== '-') {
      const clean = sanitizeShortFlag(token.value);
      if (clean !== token.value) {
        changed.set(token, clean);
      }
      if (clean?.length === 2 && VALUE_SHORT.has(clean.at(-1)!)) {
        skipValueFor = clean.at(-1)!;
      }
    }
  }
  return changed;
};

const applyTokenChanges = (
  body: string,
  tokens: readonly Token[],
  changes: ReadonlyMap<Token, string | null>,
): string => {
  let out = '';
  let cursor = 0;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!;
    if (!changes.has(token)) {
      out += body.slice(cursor, token.end);
      cursor = token.end;
      continue;
    }
    const replacement = changes.get(token) ?? null;
    out += body.slice(cursor, token.start);
    if (replacement === null) {
      cursor = token.end;
      const next = tokens[i + 1];
      if (next === undefined) {
        out = out.trimEnd();
      } else if (/\s$/u.test(out)) {
        cursor = next.start;
      }
      continue;
    }
    out += replacement;
    cursor = token.end;
  }

  return out + body.slice(cursor);
};

const sanitizeSegment = (segment: string): string => {
  const leading = /^\s*/u.exec(segment)?.[0] ?? '';
  const trailing = /\s*$/u.exec(segment)?.[0] ?? '';
  const body = segment.slice(leading.length, segment.length - trailing.length);
  const tokens = tokenizeSegment(body);
  const head = tokens[0];
  if (head === undefined || !GREP_HEADS.has(basename(head.value))) {
    return segment;
  }
  return `${leading}${applyTokenChanges(body, tokens, sanitizedTokenValues(tokens))}${trailing}`;
};

const sanitizeGrepFlags = (command: string): string =>
  splitShellSegments(command)
    .map((part) => (part.kind === 'segment' ? sanitizeSegment(part.text) : part.text))
    .join('');

export { sanitizeGrepFlags };
