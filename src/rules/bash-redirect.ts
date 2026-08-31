import type { ShellProgram, ShellWord } from '../lib/bash';
import { type Decision, allow, deny } from '../lib/decision';
import { classifyProtectedPath, type ProtectedPathSpec } from './path-protect';

// Block writes (via shell redirect, tee, cp, mv) that target sensitive
// Files. Catches the exfil-via-redirect gap that path-protect can't see
// Because it only watches Edit/Write tool calls.

const PROTECTED_TARGET_RE: readonly ProtectedPathSpec[] = [
  {
    rule: 'redirect-env',
    pattern: /(?<prefix>^|\/)\.env(?<ext>\.[^/]+)?$/u,
    message:
      'Refusing to write into a .env file via shell redirect / tee / cp / mv. .env files hold secrets — never overwrite from a tool call.',
  },
  {
    rule: 'redirect-dev-vars',
    pattern: /(?<prefix>^|\/)\.dev\.vars(?<ext>\.[^/]+)?$/u,
    message: 'Refusing to write into .dev.vars (Cloudflare/Wrangler secrets).',
  },
  {
    rule: 'redirect-ssh',
    pattern: /(?<prefix>^|\/)\.ssh\//u,
    message: 'Refusing to write into ~/.ssh/ via shell.',
  },
  {
    rule: 'redirect-key',
    pattern: /\.(?<ext>pem|key|p12|pfx)$/iu,
    message: 'Refusing to overwrite a private-key-shaped file via shell.',
  },
  {
    rule: 'redirect-aws-credentials',
    pattern: /(?<prefix>^|\/)\.aws\/credentials$/u,
    message: 'Refusing to write into ~/.aws/credentials via shell.',
  },
  {
    rule: 'redirect-netrc',
    pattern: /(?<prefix>^|\/)\.netrc$/u,
    message: 'Refusing to write into ~/.netrc via shell.',
  },
  {
    rule: 'redirect-block-device',
    pattern: /^\/dev\/(?<type>sd|disk|nvme|rdisk)/iu,
    message: 'Redirecting into a raw block device wipes the disk. Refuse.',
  },
];

const checkPath = (path: string): Decision | null => {
  const protection = classifyProtectedPath(path, 'write', PROTECTED_TARGET_RE);
  if (protection !== null) {
    return deny(protection.rule, protection.message);
  }
  return null;
};

const checkWord = (word: ShellWord): Decision | null =>
  word.kind === 'dynamic' || word.kind === 'background-pid'
    ? deny(
        'redirect-dynamic-target',
        'Tripwire cannot prove that this computed write target avoids protected files.',
      )
    : checkPath(word.value);

const bashRedirect = (program: ShellProgram): Decision => {
  for (const redirect of program.redirects) {
    if (
      redirect.op === '>' ||
      redirect.op === '>>' ||
      redirect.op === '&>' ||
      redirect.op === '&>>'
    ) {
      const decision = checkWord(redirect.target);
      if (decision !== null) {
        return decision;
      }
    }
  }
  for (const seg of program.invocations) {
    const argumentWords = seg.words.slice(1).filter((word) => !word.value.startsWith('-'));
    if (seg.head === 'tee') {
      for (const word of argumentWords) {
        const decision = checkWord(word);
        if (decision !== null) {
          return decision;
        }
      }
    }
    if (seg.head === 'cp' || seg.head === 'mv') {
      // The destination is the last positional arg.
      const destination = argumentWords.at(-1);
      if (destination !== undefined) {
        const decision = checkWord(destination);
        if (decision !== null) {
          return decision;
        }
      }
    }
  }
  return allow('bash-redirect');
};

export { bashRedirect };
