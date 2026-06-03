import { resolve } from 'node:path';

import { type Decision, allow, deny } from '../lib/decision';
import type { EditInput, WriteInput } from '../lib/event';

interface Spec {
  readonly pattern: RegExp;
  readonly rule: string;
  readonly message: string;
}

const protections: readonly Spec[] = [
  {
    pattern: /(^|\/)\.env(\.[^/]+)?$/,
    rule: 'env-file',
    message:
      '.env files hold secrets that should never be sent to the model. Refuse to write or edit. If an example is needed, create .env.example with redacted placeholders.',
  },
  {
    pattern: /(^|\/)\.dev\.vars(\.[^/]+)?$/,
    rule: 'dev-vars',
    message: '.dev.vars holds Cloudflare/Wrangler secrets. Do not modify.',
  },
  { pattern: /(^|\/)\.ssh\//, rule: 'ssh-dir', message: 'Never write into ~/.ssh/. Refuse.' },
  {
    pattern: /(^|\/)(id_rsa|id_ed25519|id_ecdsa|id_dsa)(\.pub)?$/,
    rule: 'ssh-key',
    message: 'SSH key file. Refuse.',
  },
  {
    pattern: /\.(pem|key|p12|pfx)$/i,
    rule: 'private-key',
    message:
      'Private key file. Refuse to overwrite. If generating a new key, use a different filename and let the user review.',
  },
  {
    pattern: /(^|\/)secrets?\.(json|ya?ml|toml|env)$/i,
    rule: 'secrets-file',
    message: 'Secrets file. Refuse.',
  },
  {
    pattern: /(^|\/)\.aws\/credentials$/,
    rule: 'aws-credentials',
    message: 'AWS credentials file. Refuse.',
  },
  { pattern: /(^|\/)\.netrc$/, rule: 'netrc', message: '.netrc holds host credentials. Refuse.' },
];

const pathProtect = (input: EditInput | WriteInput): Decision => {
  const path = resolve(input.file_path);
  for (const p of protections) {
    if (p.pattern.test(path)) {
      return deny(p.rule, p.message);
    }
  }
  return allow('path-protect');
};

export { pathProtect };
