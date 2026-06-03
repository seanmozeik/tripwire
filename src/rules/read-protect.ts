// oxlint-disable-next-line unicorn/import-style
import { resolve } from 'node:path';

import { type Decision, allow, deny } from '../lib/decision';
import type { ReadInput } from '../lib/event';

interface Spec {
  readonly rule: string;
  readonly pattern: RegExp;
  readonly message: string;
}

const PROTECTIONS: readonly Spec[] = [
  {
    rule: 'read-env',
    pattern: /(?<prefix>^|\/)\.env(?<ext>\.[^/]+)?$/,
    message:
      '.env files hold secrets that should never enter the model context. Refuse to read. If the goal is documenting required env vars, look at .env.example or describe the schema from memory.',
  },
  {
    rule: 'read-dev-vars',
    pattern: /(?<prefix>^|\/)\.dev\.vars(?<ext>\.[^/]+)?$/,
    message: 'Refuse to read .dev.vars (Cloudflare/Wrangler secrets).',
  },
  {
    rule: 'read-ssh',
    pattern: /(?<prefix>^|\/)\.ssh\//,
    message: 'Refuse to read files inside ~/.ssh/.',
  },
  {
    rule: 'read-ssh-key',
    pattern: /(?<prefix>^|\/)(?<key>id_rsa|id_ed25519|id_ecdsa|id_dsa)$/,
    message: 'Refuse to read SSH private key files.',
  },
  {
    rule: 'read-private-key',
    pattern: /\.(?<ext>pem|key|p12|pfx)$/i,
    message: 'Refuse to read private-key-shaped files.',
  },
  {
    rule: 'read-aws-credentials',
    pattern: /(?<prefix>^|\/)\.aws\/credentials$/,
    message: 'Refuse to read ~/.aws/credentials.',
  },
  {
    rule: 'read-netrc',
    pattern: /(?<prefix>^|\/)\.netrc$/,
    message: 'Refuse to read ~/.netrc (host credentials).',
  },
  {
    rule: 'read-secrets-file',
    pattern: /(?<prefix>^|\/)secrets?\.(?<ext>json|ya?ml|toml|env)$/i,
    message: 'Refuse to read a file named secrets.{json,yaml,toml,env}.',
  },
];

const readProtect = (input: ReadInput): Decision => {
  const path = resolve(input.file_path);
  for (const p of PROTECTIONS) {
    if (p.pattern.test(path)) {
      return deny(p.rule, p.message);
    }
  }
  return allow('read-protect');
};

export { readProtect };
