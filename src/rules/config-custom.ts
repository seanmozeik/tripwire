// Config-based custom blocking/allowing rules.
// Uses shell parsing utilities to match command patterns from config.

import { parseCommand, type Segment } from '../lib/bash';
import type { BlockRule } from '../lib/config';
import { type Decision, allow, deny, ask } from '../lib/decision';

// Match a pattern against parsed segments using shell parsing.
// This is more powerful than simple regex because it uses the same
// Parsing logic as the rest of tripwire.
const matchPattern = (segments: readonly Segment[], pattern: string): boolean => {
  const patternSegs = parseCommand(pattern);
  if (patternSegs.length === 0) {
    return false;
  }

  const patternHead = patternSegs[0]!.head;

  // Simple head match for now - can be extended to match flags, args, etc.
  for (const seg of segments) {
    if (seg.head === patternHead) {
      return true;
    }
  }
  return false;
};

export const configCustom = (
  segments: readonly Segment[],
  _cmd: string,
  blockedCommands: readonly BlockRule[],
  allowedCommands: readonly BlockRule[],
): Decision => {
  // Check allowed first (overrides blocks)
  for (const allowRule of allowedCommands) {
    if (matchPattern(segments, allowRule.pattern)) {
      return allow('config-custom');
    }
  }

  // Then check blocked
  for (const blockRule of blockedCommands) {
    if (matchPattern(segments, blockRule.pattern)) {
      return blockRule.action === 'deny'
        ? deny('config-custom', blockRule.message)
        : ask('config-custom', blockRule.message);
    }
  }

  return allow('config-custom');
};
