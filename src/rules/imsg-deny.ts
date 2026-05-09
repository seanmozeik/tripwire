import { type Segment, hasBypass } from '../lib/bash.ts';
import { type Decision, allow, deny } from '../lib/decision.ts';

// Reproduce Sean's existing imsg-block hook inside tripwire so the
// Disabled standalone hook doesn't need to come back. `imsg` is the raw
// MacOS iMessage CLI; Sean uses `send` (which wraps it and is locked to
// His number) for messaging.

const imsgDeny = (segments: readonly Segment[], cmd: string): Decision => {
  if (hasBypass(cmd)) {
    return allow('imsg-deny');
  }
  for (const seg of segments) {
    if (seg.head === 'imsg') {
      return deny(
        'imsg-blocked',
        'The `imsg` CLI is blocked. Use `send` to message Sean — `send` is hard-locked to his number and is the right channel for any iMessage delivery.',
      );
    }
  }
  return allow('imsg-deny');
};

export { imsgDeny };
