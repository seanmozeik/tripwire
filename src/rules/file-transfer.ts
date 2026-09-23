import { statSync } from 'node:fs';
import path from 'node:path';

import type { ShellInvocation } from '../lib/bash';
import { deny, merge, type Decision } from '../lib/decision';
import { pathProtect } from './path-protect';
import { readProtect } from './read-protect';

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
      if (word.source.startsWith('~')) {
        return null;
      }
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
  if (command.cwd === null && operands.some((operand) => !path.isAbsolute(operand))) {
    return deny(
      'redirect-dynamic-target',
      'File transfer working directory is unresolved. Use absolute paths.',
    );
  }
  const destination = operands.at(-1);
  if (destination === undefined) {
    return merge([]);
  }
  const cwd = command.cwd ?? process.cwd();
  const target = path.resolve(cwd, destination);
  let directory = destination.endsWith('/');
  try {
    directory ||= statSync(target).isDirectory();
  } catch {
    /* New destination. */
  }
  const decisions: Decision[] = [pathProtect({ file_path: target, content: '' })];
  for (const source of operands.slice(0, -1)) {
    const input = path.resolve(cwd, source);
    decisions.push(readProtect({ file_path: input }));
    if (command.head === 'mv') {
      decisions.push(pathProtect({ file_path: input, content: '' }));
    }
    if (directory) {
      decisions.push(
        pathProtect({ file_path: path.join(target, path.basename(source)), content: '' }),
      );
    }
  }
  return merge(decisions);
};

export { fileTransfer };
