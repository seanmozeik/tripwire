import type { ShellInvocation, ShellProgram } from '../lib/bash';
import type { ToolPolicy } from '../lib/config';
import { type Decision, allow, deny, warn } from '../lib/decision';

const hasShortFlag = (flags: readonly string[], expected: string): boolean =>
  flags.some(
    (flag) => flag.startsWith('-') && !flag.startsWith('--') && flag.slice(1).includes(expected),
  );

const matches = (segment: ShellInvocation, policy: ToolPolicy): boolean => {
  if (!policy.executables.includes(segment.head)) {
    return false;
  }

  const commandArguments = segment.tokens.slice(1);
  const commandArgumentSet = new Set(commandArguments);
  if (
    !(policy.match?.argumentsIncludeAll ?? []).every((argument) => commandArgumentSet.has(argument))
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

const toolPolicy = (program: ShellProgram, policies: readonly ToolPolicy[]): Decision => {
  for (const segment of program.invocations) {
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
