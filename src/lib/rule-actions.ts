import { Schema } from 'effect';

import { type Decision, allow, ask, deny, warn } from './decision';

const RuleActionSchema = Schema.Literals(['allow', 'warn', 'ask', 'deny']);

// These rules express workflow policy. Catastrophic operations, destructive
// Git actions, secret access, and uninspectable shell structures stay outside
// This schema so personal config cannot weaken product safety invariants.
const RuleActionsSchema = Schema.Struct({
  'brew-mutation': Schema.optional(RuleActionSchema),
  'chmod-777-recursive': Schema.optional(RuleActionSchema),
  'defaults-write': Schema.optional(RuleActionSchema),
  'dscl-mutate': Schema.optional(RuleActionSchema),
  'launchctl-mutation': Schema.optional(RuleActionSchema),
  'mas-mutation': Schema.optional(RuleActionSchema),
  'no-gpg-sign': Schema.optional(RuleActionSchema),
  'no-verify': Schema.optional(RuleActionSchema),
  osascript: Schema.optional(RuleActionSchema),
  'pmset-write': Schema.optional(RuleActionSchema),
  'rsync-delete': Schema.optional(RuleActionSchema),
  'scutil-set': Schema.optional(RuleActionSchema),
  'security-keychain-add-write': Schema.optional(RuleActionSchema),
  'softwareupdate-install': Schema.optional(RuleActionSchema),
  sudo: Schema.optional(RuleActionSchema),
  systemsetup: Schema.optional(RuleActionSchema),
  topgrade: Schema.optional(RuleActionSchema),
});

type RuleAction = typeof RuleActionSchema.Type;
type RuleActions = typeof RuleActionsSchema.Type;

const isRuleActionId = (rule: string): rule is keyof RuleActions =>
  Object.hasOwn(RuleActionsSchema.fields, rule);

const applyRuleAction = (decision: Decision, actions: RuleActions): Decision => {
  const configured = isRuleActionId(decision.rule) ? actions[decision.rule] : undefined;
  if (configured === undefined || configured === decision.kind) {
    return decision;
  }
  if (configured === 'allow') {
    return allow(decision.rule);
  }
  if (configured === 'warn') {
    return warn(decision.rule, decision.message);
  }
  if (configured === 'ask') {
    return ask(decision.rule, decision.message);
  }
  return deny(decision.rule, decision.message);
};

export type { RuleAction, RuleActions };
export { applyRuleAction, RuleActionSchema, RuleActionsSchema };
