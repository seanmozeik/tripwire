import type { ShellProgram, ShellWord } from '../lib/bash';
import { resolveShellPath } from '../lib/bash/cwd';
import { type Decision, allow, deny } from '../lib/decision';
import { fileTransfer } from './file-transfer';
import { checkShellWritePath } from './shell-write';

// Block writes (via shell redirect, tee, cp, mv) that target sensitive
// Files. Catches the exfil-via-redirect gap that path-protect can't see
// Because it only watches Edit/Write tool calls.

const checkWord = (word: ShellWord, cwd: string | null): Decision | null => {
  const target = resolveShellPath(word.value, cwd);
  return word.kind === 'dynamic' || word.kind === 'background-pid' || target === null
    ? deny(
        'redirect-dynamic-target',
        'Redirect or write target is unresolved. Use a literal absolute path or a known working directory.',
      )
    : checkShellWritePath(target);
};

const bashRedirect = (program: ShellProgram): Decision => {
  for (const redirect of program.redirects) {
    if (
      redirect.op === '>' ||
      redirect.op === '>>' ||
      redirect.op === '&>' ||
      redirect.op === '&>>'
    ) {
      const decision = checkWord(redirect.target, redirect.cwd);
      if (decision !== null) {
        return decision;
      }
    }
  }
  for (const seg of program.invocations) {
    const argumentWords = seg.words.slice(1).filter((word) => !word.value.startsWith('-'));
    if (seg.head === 'tee') {
      for (const word of argumentWords) {
        const decision = checkWord(word, seg.cwd);
        if (decision !== null) {
          return decision;
        }
      }
    }
    if (['cp', 'mv', 'ln', 'rsync', 'install'].includes(seg.head)) {
      const decision = fileTransfer(seg);
      if (decision.kind !== 'allow') {
        return decision;
      }
    }
  }
  return allow('bash-redirect');
};

export { bashRedirect };
