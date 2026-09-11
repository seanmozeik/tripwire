import { lstatSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { isSafePathTarget, type ShellProgram } from '../lib/bash';
import { analyzeCode } from '../lib/code/analyze';
import { interpreterInput } from '../lib/code/carriers';
import type { CodeLanguage, CodeOperation } from '../lib/code/types';
import type { SafePathsConfig } from '../lib/config';
import { allow, deny, merge, type Decision } from '../lib/decision';
import { pathProtect } from './path-protect';
import { readProtect } from './read-protect';

interface CodePolicy {
  readonly safePaths: SafePathsConfig;
  readonly cwd: string;
  readonly inspectCommand: (command: string) => Decision;
}

const codeDeny = (message: string): Decision =>
  deny(
    'embedded-code',
    `${message} Use a dedicated file tool, a recoverable deletion tool, or a command Tripwire can fully inspect.`,
  );

const safeDeletion = (target: string, policy: CodePolicy): boolean => {
  if (target === '' || target.includes('\0')) {
    return false;
  }
  const resolved = path.resolve(policy.cwd, target);
  if (resolved === path.parse(resolved).root || resolved === policy.cwd) {
    return false;
  }
  if (!isSafePathTarget(target, policy.safePaths.relative, policy.safePaths.absolute)) {
    return false;
  }
  // An existing symlink inside a safe scope must not redirect deletion to protected data.
  let current = resolved;
  for (let depth = 0; depth < 256; depth += 1) {
    try {
      if (lstatSync(current).isSymbolicLink()) {
        return false;
      }
      realpathSync(current);
    } catch (cause) {
      if (!(cause instanceof Error) || !('code' in cause) || cause.code !== 'ENOENT') {
        return false;
      }
    }
    const parent = path.dirname(current);
    if (parent === current) {
      return true;
    }
    current = parent;
  }
  return false;
};

const quoteArgument = (argument: string): string =>
  `'${argument.replaceAll("'", String.raw`'\''`)}'`;

const operationDecision = (operation: CodeOperation, policy: CodePolicy): Decision => {
  if (operation.kind === 'process') {
    return policy.inspectCommand(operation.argv.map(quoteArgument).join(' '));
  }
  const target = path.resolve(policy.cwd, operation.path);
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
      return codeDeny(input.reason);
    }
    if (input.kind === 'source') {
      if (program.invocations.some((command) => ['cd', 'pushd', 'popd'].includes(command.head))) {
        return codeDeny('A directory change makes the interpreter working directory uncertain.');
      }
      decisions.push(inspectCode(input.language, input.source, policy));
    }
  }
  return decisions.length === 0 ? allow('embedded-code') : merge(decisions);
};

export { codeDeny, embeddedCode, inspectCode };
export type { CodePolicy };
