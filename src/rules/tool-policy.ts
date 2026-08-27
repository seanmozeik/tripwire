import { type Segment, hasBypass } from '../lib/bash';
import type { ToolPolicy } from '../lib/config';
import { type Decision, allow, deny, warn } from '../lib/decision';

const hasShortFlag = (flags: readonly string[], expected: string): boolean =>
  flags.some(
    (flag) => flag.startsWith('-') && !flag.startsWith('--') && flag.slice(1).includes(expected),
  );

const matches = (segment: Segment, policy: ToolPolicy): boolean => {
  if (!policy.executables.includes(segment.head)) {
    return false;
  }

  const commandArguments = segment.tokens.slice(1);
  if (
    !(policy.match?.argumentsIncludeAll ?? []).every((argument) =>
      commandArguments.includes(argument),
    )
  ) {
    return false;
  }
  if (
    !(policy.match?.argumentsStartWith ?? []).every(
      (argument, index) => commandArguments[index] === argument,
    )
  ) {
    return false;
  }
  return (policy.match?.shortFlagsIncludeAll ?? []).every((flag) =>
    hasShortFlag(segment.flags, flag),
  );
};

const toolPolicy = (
  segments: readonly Segment[],
  command: string,
  policies: readonly ToolPolicy[],
): Decision => {
  if (hasBypass(command)) {
    return allow('tool-policy');
  }
  for (const segment of segments) {
    for (const policy of policies) {
      if (matches(segment, policy)) {
        return policy.action === 'deny'
          ? deny(policy.rule, policy.message)
          : warn(policy.rule, policy.message);
      }
    }
  }
  return allow('tool-policy');
};

export { toolPolicy };
