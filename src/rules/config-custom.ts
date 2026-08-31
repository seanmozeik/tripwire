// Config-based custom blocking/allowing rules.
// Uses shell parsing utilities to match command patterns from config.

import { analyzeBash, type ShellInvocation, type ShellProgram } from '../lib/bash';
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

// Match command policy by executable basename so an absolute path cannot
// bypass a configured rule.
const basename = (token: string): string => {
  const idx = token.lastIndexOf('/');
  return idx === -1 ? token : token.slice(idx + 1);
};

const flagPresent = (tokens: readonly string[], flag: string): boolean =>
  tokens.some((t) => t === flag || t.startsWith(`${flag}=`));

const flagValue = (tokens: readonly string[], flag: string): string | null => {
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t !== undefined) {
      if (t === flag) {
        return tokens[i + 1] ?? '';
      }
      if (t.startsWith(`${flag}=`)) {
        return t.slice(flag.length + 1);
      }
    }
  }
  return null;
};

const subcommandTokens = (seg: ShellInvocation): string[] => {
  const out: string[] = [];
  const tokens = seg.tokens.slice(1);
  for (let i = 0; i < tokens.length; i += 1) {
    const t = tokens[i];
    if (t?.startsWith('-') === true) {
      // Without per-CLI flag metadata, we conservatively treat
      // `--flag value` / `-f value` as one option pair and `--flag=value`
      // As one token. This keeps global selectors like `--account X`
      // Out of the subcommand path, at the cost of not distinguishing
      // Boolean flags that precede positional args.
      const nextToken = tokens[i + 1];
      if (!t.includes('=') && nextToken !== undefined && !nextToken.startsWith('-')) {
        i += 1;
      }
    } else if (t !== undefined) {
      out.push(t);
    }
  }
  return out;
};

// Match a pattern against parsed segments using shell parsing.
// This is more powerful than simple regex because it uses the same
// Parsing logic as the rest of tripwire.
const matchPattern = (program: ShellProgram, rule: BlockRule): boolean => {
  const { pattern } = rule;
  const patternProgram = analyzeBash(pattern);
  if (patternProgram.diagnostics.length > 0 || patternProgram.invocations.length === 0) {
    return false;
  }

  const [patternSegment] = patternProgram.invocations;
  if (patternSegment === undefined) {
    return false;
  }
  const [patternHead, ...patternSubcommands] = patternSegment.tokens;
  if (patternHead === undefined) {
    return false;
  }

  return program.invocations.some((segment) => {
    if (basename(segment.head) !== basename(patternHead)) {
      return false;
    }
    const actualSubcommands = subcommandTokens(segment);
    const subcommandsMatch = patternSubcommands.every(
      (part, index) =>
        actualSubcommands[index] !== undefined &&
        canonical(actualSubcommands[index]) === canonical(part),
    );
    const requiredFlagsMatch = (rule.requiresFlags ?? []).every((flag) =>
      flagPresent(segment.tokens, flag),
    );
    const forbiddenValuesMatch = (rule.forbidsFlagValues ?? []).every((check) => {
      const value = flagValue(segment.tokens, check.flag);
      return value !== null && check.values.includes(value);
    });
    return subcommandsMatch && requiredFlagsMatch && forbiddenValuesMatch;
  });
};

export const configCustom = (
  program: ShellProgram,
  blockedCommands: readonly BlockRule[],
  allowedCommands: readonly BlockRule[],
): Decision => {
  // Check allowed first (overrides blocks)
  for (const allowRule of allowedCommands) {
    if (matchPattern(program, allowRule)) {
      return allow('config-custom');
    }
  }

  // Then check blocked
  for (const blockRule of blockedCommands) {
    if (matchPattern(program, blockRule)) {
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
