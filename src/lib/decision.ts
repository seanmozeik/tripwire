// Decisions are ordered by restrictiveness:
//   Allow — let the tool call proceed silently
//   Warn  — let the tool call proceed but inject a system message so the
//           Agent sees the advisory in its next turn
//   Ask   — Claude Code prompts the user before letting the call proceed
//   Deny  — block the tool call (PreToolUse) or refuse to surface its
//           Output to the model (PostToolUse)
//
type DecisionKind = 'allow' | 'warn' | 'ask' | 'deny';

interface Decision {
  readonly kind: DecisionKind;
  readonly rule: string;
  readonly message: string;
}

const order: Record<DecisionKind, number> = { allow: 0, warn: 1, ask: 2, deny: 3 };

const allow = (rule: string): Decision => ({ kind: 'allow', rule, message: '' });
const warn = (rule: string, message: string): Decision => ({ kind: 'warn', rule, message });
const ask = (rule: string, message: string): Decision => ({ kind: 'ask', rule, message });
const deny = (rule: string, message: string): Decision => ({ kind: 'deny', rule, message });

// Merge picks the most restrictive kind.
const merge = (decisions: readonly Decision[]): Decision => {
  let best: Decision = allow('none');
  for (const d of decisions) {
    if (order[d.kind] > order[best.kind]) {
      best = d;
    }
  }
  return best;
};

export type { Decision, DecisionKind };
export { allow, ask, deny, merge, warn };
