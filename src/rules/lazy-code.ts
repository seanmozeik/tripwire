import { type Decision, allow, warn } from '../lib/decision';
import { addedLines, readFileOrEmpty } from '../lib/diff';
import type { EditInput, WriteInput } from '../lib/event';

// Phrases that frequently signal incomplete or deferred work. Some — like
// "fallback" or "placeholder" — are also legitimate product terms (an auth
// Fallback flow, an HTML input placeholder). Rather than try to disambiguate
// Statically, we accept the false-positive rate and keep this as a non-
// Blocking warn. The advisory is written to make the intent unmistakable
// So the agent treats real-product uses as no-action and treats actual
// Stub work as a prompt to finish the job before returning to the user.
const STUB_RE: readonly RegExp[] = [
  /\bTODO\s*:/i,
  /\bFIXME\s*:/i,
  /\bXXX\s*:/i,
  /\bHACK\s*:/i,
  /\bfor now\b/i,
  /\bnot implemented\b/i,
  /\bNotImplementedError\b/,
  /\btemp fix\b/i,
  /\bfallback\b/i,
  /\bplaceholder\b/i,
  /\bbackwards?[ -]?compat(?<ibility>ibility)?\b/i,
  /\bfor later\b/i,
  /\blater on\b/i,
  /\bget back to\b/i,
  /\bI'?ll fix\b/i,
  /\bto be implemented\b/i,
  /\bnot yet (?<state>implemented|done)\b/i,
  /\bstubbed\b/i,
];

const CODE_EXT_RE =
  /\.(?<ext>ts|tsx|js|jsx|mjs|cjs|py|rs|go|rb|java|kt|swift|c|cc|cpp|h|hpp|cs|php|sh|zsh|bash|lua|ex|exs|clj|scala|dart)$/i;

const TEST_PATH_RE =
  /(?<prefix>^|\/)(?<dir>__tests__|tests?|spec|fixtures?|mocks?|__mocks__|stories)(?<suffix>\/|$)|\.(?<ext>test|spec|fixture|mock|stories)\.[^/]+$/i;

// Comment-syntax-agnostic. Works in `//`, `#`, `--`, `/* */`, `<!-- -->`,
// `;`, `%`, etc.
const BYPASS_RE = /tripwire-allow\b/;

const matches = (line: string): boolean => {
  if (BYPASS_RE.test(line)) {
    return false;
  }
  for (const re of STUB_RE) {
    if (re.test(line)) {
      return true;
    }
  }
  return false;
};

const lazyCode = (input: EditInput | WriteInput): Decision => {
  const path = input.file_path;
  if (!CODE_EXT_RE.test(path) || TEST_PATH_RE.test(path)) {
    return allow('lazy-code');
  }

  const next = 'content' in input ? input.content : input.new_string;
  const prev = 'content' in input ? readFileOrEmpty(path) : input.old_string;

  const offenders: string[] = [];
  for (const line of addedLines(prev, next)) {
    if (matches(line)) {
      offenders.push(line.slice(0, 200));
    }
  }
  if (offenders.length === 0) {
    return allow('lazy-code');
  }

  const sample = offenders
    .slice(0, 3)
    .map((l) => `  • ${l}`)
    .join('\n');
  const more = offenders.length > 3 ? `\n  …and ${offenders.length - 3} more` : '';

  return warn(
    'lazy-code-marker',
    [
      `Heads up: line(s) you just added contain words that often signal incomplete or deferred work. The write went through — this is a flag, not a block.`,
      ``,
      `Why this exists: AI coding agents have a strong pull toward stubbing things, deferring "for now," and shipping half-built fallbacks instead of finishing the work in the same turn. The point of this warning is to push back on that pull on every iteration. If you stubbed something out for time, finish it this turn rather than leaving deferred work for later.`,
      ``,
      `If the marker is genuinely permanent — a real product term ("auth fallback flow", "retry fallback chain", an HTML input placeholder, a public API field literally named "placeholder"), a logging tag, or a comment intentionally left for a human reader — no action needed. To silence the flag on subsequent edits of that line, append \`tripwire-allow: <one-line reason>\` (any comment syntax: \`//\`, \`#\`, \`--\`, etc.).`,
      ``,
      `Flagged additions:`,
      sample + more,
    ].join('\n'),
  );
};

export { lazyCode };
