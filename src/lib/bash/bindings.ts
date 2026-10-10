import type { ArithmeticExpression } from 'unbash';

import type { ShellInvocation, ShellWord } from './types';
import { cloneEnvironment, DYNAMIC_VALUE, type Environment } from './values';
import { skipOptions } from './wrappers';

const dynamicBinding = (word: ShellWord): ShellWord => ({
  ...word,
  kind: 'dynamic',
  value: DYNAMIC_VALUE,
});

const assignedNameOf = (word: ShellWord): string | undefined =>
  /^(?<name>[A-Za-z_][A-Za-z0-9_]*)/u.exec(
    word.kind === 'literal' ? word.value : word.source.replace(/^['"]/u, ''),
  )?.groups?.['name'];

const sameBinding = (left: ShellWord | undefined, right: ShellWord): boolean =>
  left === right ||
  (left?.kind === 'literal' && right.kind === 'literal' && left.value === right.value);

const joinBindings = (environments: readonly Environment[]): Map<string, ShellWord> => {
  const bindings = new Map<string, ShellWord>();
  for (const environment of environments) {
    for (const [name, word] of environment.bindings) {
      bindings.set(
        name,
        environments.every((candidate) => sameBinding(candidate.bindings.get(name), word))
          ? word
          : dynamicBinding(word),
      );
    }
  }
  return bindings;
};

const bindingsChanged = (
  left: ReadonlyMap<string, ShellWord>,
  right: ReadonlyMap<string, ShellWord>,
): boolean =>
  left.size !== right.size || [...right].some(([name, word]) => !sameBinding(left.get(name), word));

const widenBindings = (environments: readonly Environment[]): Map<string, ShellWord> => {
  const bindings = joinBindings(environments);
  for (const [name, word] of bindings) {
    if (name !== 'HOME' && name !== 'PWD') {
      bindings.set(name, dynamicBinding(word));
    }
  }
  return bindings;
};

const replaceBindings = (
  environment: Environment,
  bindings: ReadonlyMap<string, ShellWord>,
): void => {
  environment.bindings.clear();
  for (const [name, word] of bindings) {
    environment.bindings.set(name, word);
  }
};

// One widened replay represents later iterations without an unbounded fixpoint.
const visitRepeatedBindings = (
  environment: Environment,
  visit: (iteration: Environment) => void,
): void => {
  const incoming = cloneEnvironment(environment);
  const outgoing = cloneEnvironment(environment);
  visit(outgoing);
  const branches = [incoming, outgoing];
  if (bindingsChanged(incoming.bindings, outgoing.bindings)) {
    const replay = cloneEnvironment(outgoing);
    replaceBindings(replay, widenBindings(branches));
    replay.temps.clear();
    visit(replay);
    branches.push(replay);
  }
  replaceBindings(environment, joinBindings(branches));
};

const invalidateArithmeticBinding = (
  expression: ArithmeticExpression,
  environment: Environment,
): boolean => {
  if (expression.type === 'ArithmeticGroup') {
    return invalidateArithmeticBinding(expression.expression, environment);
  }
  const name =
    expression.type === 'ArithmeticWord'
      ? /^(?<name>[A-Za-z_][A-Za-z0-9_]*)/u.exec(expression.value)?.groups?.['name']
      : undefined;
  if (name === undefined) {
    return false;
  }
  environment.temps.delete(name);
  environment.bindings.set(name, {
    source: name,
    value: DYNAMIC_VALUE,
    kind: 'dynamic',
    range: { start: expression.pos, end: expression.end },
    quoted: false,
  });
  return true;
};

const restoreDeclaredBinding = (
  invocation: ShellInvocation,
  word: ShellWord,
  previous: ShellWord | undefined,
  environment: Environment,
): void => {
  const name = assignedNameOf(word);
  if (name === undefined) {
    return;
  }
  const scalar = !invocation.flags.some((flag) => /^-[^-]*[aAin]/u.test(flag));
  if (!scalar || word.kind !== 'literal' || word.value.startsWith(`${name}+=`)) {
    environment.bindings.set(name, dynamicBinding(word));
  } else if (word.value.startsWith(`${name}=`)) {
    environment.bindings.set(name, { ...word, value: word.value.slice(name.length + 1) });
  } else if (word.value === name && previous !== undefined) {
    environment.bindings.set(name, previous);
  }
};

const variableWriteTargets = (invocation: ShellInvocation): readonly ShellWord[] | null => {
  if (invocation.head === 'getopts') {
    const index = invocation.tokens[1] === '--' ? 3 : 2;
    return invocation.words.slice(index, index + 1);
  }
  if (invocation.head === 'read') {
    const start = skipOptions(
      invocation.words,
      1,
      new Set(['-a', '-d', '-i', '-n', '-N', '-p', '-t', '-u']),
    );
    return invocation.words.slice(start);
  }
  if (invocation.head !== 'printf') {
    return null;
  }
  const targets: ShellWord[] = [];
  for (let index = 1; index < invocation.words.length; index += 1) {
    const flag = invocation.words[index];
    if (flag === undefined || !flag.value.startsWith('-v')) {
      break;
    }
    if (flag.value === '-v') {
      index += 1;
      const target = invocation.words[index];
      if (target !== undefined) {
        targets.push(target);
      }
    } else {
      targets.push({ ...flag, value: flag.value.slice(2) });
    }
  }
  return targets.length === 0 ? null : targets;
};

export {
  assignedNameOf,
  dynamicBinding,
  invalidateArithmeticBinding,
  joinBindings,
  restoreDeclaredBinding,
  variableWriteTargets,
  visitRepeatedBindings,
};
