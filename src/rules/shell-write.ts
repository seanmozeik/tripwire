import { deny, type Decision } from '../lib/decision';
import { classifyProtectedPath, type ProtectedPathSpec } from './path-protect';

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
    pattern: /(?<prefix>^|\/)\.ssh(?:\/|$)/u,
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

const checkShellWritePath = (target: string): Decision | null => {
  const protection = classifyProtectedPath(target, 'write', PROTECTED_TARGET_RE);
  if (protection !== null) {
    return deny(protection.rule, protection.message);
  }
  return null;
};

export { checkShellWritePath };
