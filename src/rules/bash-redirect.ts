import { type Segment, hasBypass } from '../lib/bash';
import { type Decision, allow, deny } from '../lib/decision';

// Block writes (via shell redirect, tee, cp, mv) that target sensitive
// Files. Catches the exfil-via-redirect gap that path-protect can't see
// Because it only watches Edit/Write tool calls.

const PROTECTED_TARGET_RE: readonly { rule: string; pattern: RegExp; message: string }[] = [
  {
    rule: 'redirect-env',
    pattern: /(?<prefix>^|\/)\.env(?<ext>\.[^/]+)?$/,
    message:
      'Refusing to write into a .env file via shell redirect / tee / cp / mv. .env files hold secrets — never overwrite from a tool call.',
  },
  {
    rule: 'redirect-dev-vars',
    pattern: /(?<prefix>^|\/)\.dev\.vars(?<ext>\.[^/]+)?$/,
    message: 'Refusing to write into .dev.vars (Cloudflare/Wrangler secrets).',
  },
  {
    rule: 'redirect-ssh',
    pattern: /(?<prefix>^|\/)\.ssh\//,
    message: 'Refusing to write into ~/.ssh/ via shell.',
  },
  {
    rule: 'redirect-key',
    pattern: /\.(?<ext>pem|key|p12|pfx)$/i,
    message: 'Refusing to overwrite a private-key-shaped file via shell.',
  },
  {
    rule: 'redirect-aws-credentials',
    pattern: /(?<prefix>^|\/)\.aws\/credentials$/,
    message: 'Refusing to write into ~/.aws/credentials via shell.',
  },
  {
    rule: 'redirect-netrc',
    pattern: /(?<prefix>^|\/)\.netrc$/,
    message: 'Refusing to write into ~/.netrc via shell.',
  },
  {
    rule: 'redirect-block-device',
    pattern: /^\/dev\/(?<type>sd|disk|nvme|rdisk)/i,
    message: 'Redirecting into a raw block device wipes the disk. Refuse.',
  },
];

const checkPath = (path: string): Decision | null => {
  for (const p of PROTECTED_TARGET_RE) {
    if (p.pattern.test(path)) {
      return deny(p.rule, p.message);
    }
  }
  return null;
};

const bashRedirect = (segments: readonly Segment[], cmd: string): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-redirect');
  }
  for (const seg of segments) {
    for (const r of seg.redirects) {
      if (r.op === '>' || r.op === '>>') {
        const d = checkPath(r.target);
        if (d !== null) {
          return d;
        }
      }
    }
    if (seg.head === 'tee') {
      for (const t of seg.args) {
        const d = checkPath(t);
        if (d !== null) {
          return d;
        }
      }
    }
    if (seg.head === 'cp' || seg.head === 'mv') {
      // The destination is the last positional arg.
      const dst = seg.args.at(-1);
      if (dst !== undefined) {
        const d = checkPath(dst);
        if (d !== null) {
          return d;
        }
      }
    }
  }
  return allow('bash-redirect');
};

export { bashRedirect };
