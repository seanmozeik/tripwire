import { statSync } from 'node:fs';
import path from 'node:path';

import type { ShellInvocation } from '../lib/bash';
import { deny, merge, type Decision } from '../lib/decision';
import { pathProtect } from './path-protect';
import { readProtect } from './read-protect';

const fileTransfer = (command: ShellInvocation): Decision => {
  const words = command.words.slice(1);
  let options = true;
  const operands: string[] = [];
  for (const word of words) {
    if (word.kind !== 'literal') {
      return deny(
        'redirect-dynamic-target',
        'File transfer operands are unresolved. Use literal source and destination paths.',
      );
    }
    if (options && word.value === '--') {
      options = false;
    } else if (options && word.value.startsWith('-')) {
      if (!/^-[RrpfinsvLHP]+$/u.test(word.value)) {
        return deny(
          'redirect-dynamic-target',
          'File transfer options are not inspected. Use simple source and destination operands.',
        );
      }
    } else {
      operands.push(word.value);
    }
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
  let directory = false;
  try {
    directory = statSync(target).isDirectory();
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
