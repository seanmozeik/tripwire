import { statSync } from 'node:fs';
import path from 'node:path';

import type { ShellInvocation } from '../lib/bash';
import { resolveShellPath } from '../lib/bash/cwd';
import { deny, merge, type Decision } from '../lib/decision';
import { pathProtect } from './path-protect';
import { readProtect } from './read-protect';
import { checkShellWritePath } from './shell-write';

const transferOperands = (command: ShellInvocation): string[] | null => {
  let options = true;
  let optionValue = false;
  const operands: string[] = [];
  for (const word of command.words.slice(1)) {
    if (word.kind !== 'literal' && !(word.kind === 'trusted-temp-path' && word.quoted)) {
      return null;
    }
    if (optionValue) {
      optionValue = false;
    } else if (options && word.value === '--') {
      options = false;
    } else if (options && word.value.startsWith('-')) {
      if (command.head === 'install' && ['-m', '-o', '-g'].includes(word.value)) {
        optionValue = true;
      } else {
        const flags = command.head === 'rsync' ? /^-[avzRrptlHn]+$/u : /^-[RrpfinsvLHP]+$/u;
        if (!flags.test(word.value)) {
          return null;
        }
      }
    } else {
      operands.push(word.value);
    }
  }
  return optionValue ? null : operands;
};

const fileTransfer = (command: ShellInvocation): Decision => {
  const operands = transferOperands(command);
  if (
    operands === null ||
    (command.head === 'rsync' && operands.some((operand) => operand.includes(':')))
  ) {
    return deny(
      'redirect-dynamic-target',
      'File transfer operands or options are not inspected. Use literal local source and destination paths with simple options.',
    );
  }
  return transferDecision(command.head, operands.slice(0, -1), operands.at(-1), command.cwd);
};

const transferDecision = (
  command: string,
  sources: readonly string[],
  destination: string | undefined,
  cwd: string | null,
): Decision => {
  const operands = destination === undefined ? sources : [...sources, destination];
  if (cwd === null && operands.some((operand) => !path.isAbsolute(operand))) {
    return deny(
      'redirect-dynamic-target',
      'File transfer working directory is unresolved. Use absolute paths.',
    );
  }
  if (destination === undefined) {
    return merge([]);
  }
  const target = resolveShellPath(destination, cwd);
  if (target === null) {
    return deny(
      'redirect-dynamic-target',
      'File transfer destination is unresolved. Use an absolute path.',
    );
  }
  let directory = destination.endsWith('/');
  try {
    directory ||= statSync(target).isDirectory();
  } catch {
    /* New destination. */
  }
  const decisions: Decision[] = [pathProtect({ file_path: target, content: '' })];
  for (const source of sources) {
    const input = resolveShellPath(source, cwd);
    if (input === null) {
      return deny(
        'redirect-dynamic-target',
        'File transfer source is unresolved. Use an absolute path.',
      );
    }
    decisions.push(readProtect({ file_path: input }));
    if (command === 'mv') {
      decisions.push(pathProtect({ file_path: input, content: '' }));
    }
    if (directory) {
      decisions.push(
        pathProtect({ file_path: path.join(target, path.basename(source)), content: '' }),
      );
    }
  }
  const protectedTarget = checkShellWritePath(target);
  return merge(protectedTarget === null ? decisions : [...decisions, protectedTarget]);
};

export { fileTransfer, transferDecision };
