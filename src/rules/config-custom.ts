// Config-based custom blocking/allowing rules.
// Uses shell parsing utilities to match command patterns from config.

import { hasBypass, parseCommand, type Segment } from '../lib/bash';
import type { BlockRule } from '../lib/config';
import { type Decision, allow, deny, ask } from '../lib/decision';

const BYPASS_HELP = 'If this is intentional, append ` # tripwire-allow: <reason>` to the command.';

const ALIASES: ReadonlyMap<string, string> = new Map([
  ['add', 'create'],
  ['new', 'create'],
  ['edit', 'update'],
  ['set', 'update'],
  ['rm', 'delete'],
  ['del', 'delete'],
  ['remove', 'delete'],
]);

const canonical = (token: string): string => ALIASES.get(token) ?? token;

// Strip directory prefix so an absolute or homebrew-style path matches its
// Basename — `/opt/homebrew/bin/gog` and `gog` are the same command for
// Policy purposes. shim's typed dispatcher resolves CLIs to absolute paths,
// So matchers that compare `seg.head` literally would otherwise miss every
// Rule for those invocations.
const basename = (token: string): string => {
  const idx = token.lastIndexOf('/');
  return idx === -1 ? token : token.slice(idx + 1);
};

const flagPresent = (tokens: readonly string[], flag: string): boolean =>
  tokens.some((t) => t === flag || t.startsWith(`${flag}=`));

const flagValue = (tokens: readonly string[], flag: string): string | null => {
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t === flag) {
      return tokens[i + 1] ?? '';
    }
    if (t.startsWith(`${flag}=`)) {
      return t.slice(flag.length + 1);
    }
  }
  return null;
};

const subcommandTokens = (seg: Segment): string[] => {
  const out: string[] = [];
  const tokens = seg.tokens.slice(1);
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (t.startsWith('-')) {
      // Without per-CLI flag metadata, we conservatively treat
      // `--flag value` / `-f value` as one option pair and `--flag=value`
      // As one token. This keeps global selectors like `--account X`
      // Out of the subcommand path, at the cost of not distinguishing
      // Boolean flags that precede positional args.
      if (!t.includes('=') && tokens[i + 1] !== undefined && !tokens[i + 1]!.startsWith('-')) {
        i++;
      }
      continue;
    }
    out.push(t);
  }
  return out;
};

// Match a pattern against parsed segments using shell parsing.
// This is more powerful than simple regex because it uses the same
// Parsing logic as the rest of tripwire.
const matchPattern = (segments: readonly Segment[], rule: BlockRule): boolean => {
  const pattern = rule.pattern;
  const patternSegs = parseCommand(pattern);
  if (patternSegs.length === 0) {
    return false;
  }

  const patternTokens = patternSegs[0]!.tokens;
  const patternHead = patternTokens[0];
  if (patternHead === undefined) {
    return false;
  }
  const patternSubcommands = patternTokens.slice(1);

  for (const seg of segments) {
    if (basename(seg.head) !== basename(patternHead)) {
      continue;
    }

    if (patternSubcommands.length > 0) {
      const actualSubcommands = subcommandTokens(seg);
      const pathMatches = patternSubcommands.every(
        (p, i) =>
          actualSubcommands[i] !== undefined && canonical(actualSubcommands[i]) === canonical(p),
      );
      if (!pathMatches) {
        continue;
      }
    }

    if ((rule.requiresFlags ?? []).some((flag) => !flagPresent(seg.tokens, flag))) {
      continue;
    }

    const valueChecks = rule.forbidsFlagValues ?? [];
    const valuesMatch = valueChecks.every((check) => {
      const value = flagValue(seg.tokens, check.flag);
      return value !== null && check.values.includes(value);
    });
    if (!valuesMatch) {
      continue;
    }

    if (
      patternSubcommands.length === 0 &&
      rule.requiresFlags === undefined &&
      rule.forbidsFlagValues === undefined
    ) {
      return true;
    }

    return true;
  }
  return false;
};

export const configCustom = (
  segments: readonly Segment[],
  cmd: string,
  blockedCommands: readonly BlockRule[],
  allowedCommands: readonly BlockRule[],
): Decision => {
  if (hasBypass(cmd)) {
    return allow('config-custom');
  }

  // Check allowed first (overrides blocks)
  for (const allowRule of allowedCommands) {
    if (matchPattern(segments, allowRule)) {
      return allow('config-custom');
    }
  }

  // Then check blocked
  for (const blockRule of blockedCommands) {
    if (matchPattern(segments, blockRule)) {
      const message = blockRule.message.includes('tripwire-allow')
        ? blockRule.message
        : `${blockRule.message} ${BYPASS_HELP}`;
      return blockRule.action === 'ask'
        ? ask('config-custom', message)
        : deny('config-custom', message);
    }
  }

  return allow('config-custom');
};

export { matchPattern };
