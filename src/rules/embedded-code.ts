import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { isSafePathTarget, type ShellProgram } from '../lib/bash';
import { skipHeadRenamingPrefix } from '../lib/bash/wrappers';
import { analyzeCode } from '../lib/code/analyze';
import { interpreterInput } from '../lib/code/carriers';
import type { CodeLanguage, CodeOperation } from '../lib/code/types';
import type { SafePathsConfig } from '../lib/config';
import { allow, deny, merge, type Decision } from '../lib/decision';
import { applyShellBypass } from './bash-bypass';
import { pathProtect } from './path-protect';
import { readProtect } from './read-protect';

interface CodePolicy {
  readonly safePaths: SafePathsConfig;
  readonly cwd: string;
  readonly inspectCommand: (command: string) => Decision;
  readonly remoteHeads: ReadonlySet<string>;
}

const STARTUP_VARIABLES = new Set([
  'NODE_OPTIONS',
  'NODE_PATH',
  'PYTHONPATH',
  'PYTHONHOME',
  'PYTHONSTARTUP',
  'LD_PRELOAD',
  'DYLD_INSERT_LIBRARIES',
  'BUN_OPTIONS',
]);

const uncertainContext = (program: ShellProgram, policy: CodePolicy): boolean => {
  if (program.environmentAssignments?.some((name) => STARTUP_VARIABLES.has(name)) === true) {
    return true;
  }
  return program.invocations.some((command) => {
    if (
      ['cd', 'pushd', 'popd', 'chroot'].includes(command.head) ||
      policy.remoteHeads.has(command.head)
    ) {
      return true;
    }
    if (
      ['env', 'sudo'].includes(command.head) &&
      command.tokens
        .slice(1, skipHeadRenamingPrefix(command))
        .some((token) => /^(?:-C|-D|-R|--chdir(?:=|$)|--chroot(?:=|$))/u.test(token))
    ) {
      return true;
    }
    return (
      command.head === 'env' &&
      command.tokens.some((word) => STARTUP_VARIABLES.has(word.split('=')[0] ?? ''))
    );
  });
};

const codeDeny = (message: string): Decision =>
  deny(
    'embedded-code',
    `${message} Use a dedicated file tool, a recoverable deletion tool, or a command Tripwire can fully inspect.`,
  );

const canonicalPath = (target: string): string | null => {
  let current = target;
  const suffix: string[] = [];
  for (let depth = 0; depth < 256; depth += 1) {
    try {
      return path.join(realpathSync(current), ...suffix.toReversed());
    } catch (cause) {
      if (!(cause instanceof Error) || !('code' in cause) || cause.code !== 'ENOENT') {
        return null;
      }
    }
    try {
      if (lstatSync(current).isSymbolicLink()) {
        return null;
      }
    } catch (cause) {
      if (!(cause instanceof Error) || !('code' in cause) || cause.code !== 'ENOENT') {
        return null;
      }
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return null;
    }
    suffix.push(path.basename(current));
    current = parent;
  }
  return null;
};

const safeDeletion = (target: string, policy: CodePolicy): boolean => {
  if (target === '' || target.includes('\0')) {
    return false;
  }
  if (!isSafePathTarget(target, policy.safePaths.relative, policy.safePaths.absolute)) {
    return false;
  }
  const resolved = canonicalPath(path.resolve(policy.cwd, target));
  const base = canonicalPath(policy.cwd);
  if (
    resolved === null ||
    base === null ||
    resolved === path.parse(resolved).root ||
    resolved === base
  ) {
    return false;
  }
  // Classify the real target in the same absolute/relative scope as the submitted path.
  const actual = path.isAbsolute(target) ? resolved : path.relative(base, resolved);
  return isSafePathTarget(actual, policy.safePaths.relative, policy.safePaths.absolute);
};

const quoteArgument = (argument: string): string =>
  `'${argument.replaceAll("'", String.raw`'\''`)}'`;

const operationDecision = (operation: CodeOperation, policy: CodePolicy): Decision => {
  if (operation.kind === 'process') {
    return policy.inspectCommand(operation.argv.map(quoteArgument).join(' '));
  }
  const target = path.resolve(policy.cwd, operation.path);
  if (operation.kind === 'json-module') {
    try {
      const resolved = realpathSync(target);
      if (path.extname(resolved) !== '.json' || !lstatSync(resolved).isFile()) {
        return codeDeny('JSON imports must resolve to a regular .json file.');
      }
      return merge([readProtect({ file_path: target }), readProtect({ file_path: resolved })]);
    } catch {
      return codeDeny('JSON import target could not be verified.');
    }
  }
  if (
    (operation.kind === 'delete' || operation.kind === 'truncate') &&
    !safeDeletion(operation.path, policy)
  ) {
    return codeDeny(
      `${operation.kind} outside a verified safe scope: ${JSON.stringify(operation.path)}.`,
    );
  }
  return operation.kind === 'read'
    ? readProtect({ file_path: target })
    : pathProtect({ file_path: target, content: '' });
};

const inspectCode = (language: CodeLanguage, source: string, policy: CodePolicy): Decision => {
  const report = analyzeCode(language, source);
  if (report.gap !== null) {
    return codeDeny(report.gap);
  }
  return merge(report.operations.map((operation) => operationDecision(operation, policy)));
};

const embeddedCode = (program: ShellProgram, policy: CodePolicy): Decision => {
  const decisions: Decision[] = [];
  for (const invocation of program.invocations) {
    const input = interpreterInput(invocation);
    if (input.kind === 'blocked') {
      decisions.push(applyShellBypass(program, codeDeny(input.reason)));
    }
    if (input.kind === 'project' && uncertainContext(program, policy)) {
      return codeDeny('The project command has an unverified execution context.');
    }
    if (input.kind === 'command') {
      if (uncertainContext(program, policy)) {
        return codeDeny('The forwarded command has an unverified execution context.');
      }
      decisions.push(policy.inspectCommand(input.argv.map(quoteArgument).join(' ')));
    }
    if (input.kind === 'source') {
      if (uncertainContext(program, policy)) {
        return codeDeny(
          'Interpreter startup, working directory, or remote filesystem state is not verified.',
        );
      }
      decisions.push(inspectCode(input.language, input.source, policy));
    }
  }
  return decisions.length === 0 ? allow('embedded-code') : merge(decisions);
};

export { codeDeny, embeddedCode, inspectCode };
export type { CodePolicy };
