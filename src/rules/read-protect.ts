import { type Decision, allow, deny } from '../lib/decision';
import type { ReadInput } from '../lib/event';
import { classifyProtectedPath, type ProtectedPathSpec } from './path-protect';

const PROTECTIONS: readonly ProtectedPathSpec[] = [
  {
    rule: 'read-env',
    pattern: /(?<prefix>^|\/)\.env(?<ext>\.[^/]+)?$/u,
    message:
      '.env files hold secrets that should never enter the model context. Refuse to read. If the goal is documenting required env vars, look at .env.example or describe the schema from memory.',
  },
  {
    rule: 'read-dev-vars',
    pattern: /(?<prefix>^|\/)\.dev\.vars(?<ext>\.[^/]+)?$/u,
    message: 'Refuse to read .dev.vars (Cloudflare/Wrangler secrets).',
  },
  {
    rule: 'read-ssh',
    pattern: /(?<prefix>^|\/)\.ssh\//u,
    message: 'Refuse to read files inside ~/.ssh/.',
  },
  {
    rule: 'read-ssh-key',
    pattern: /(?<prefix>^|\/)(?<key>id_rsa|id_ed25519|id_ecdsa|id_dsa)$/u,
    message: 'Refuse to read SSH private key files.',
  },
  {
    rule: 'read-private-key',
    pattern: /\.(?<ext>pem|key|p12|pfx)$/iu,
    message: 'Refuse to read private-key-shaped files.',
  },
  {
    rule: 'read-aws-credentials',
    pattern: /(?<prefix>^|\/)\.aws\/credentials$/u,
    message: 'Refuse to read ~/.aws/credentials.',
  },
  {
    rule: 'read-netrc',
    pattern: /(?<prefix>^|\/)\.netrc$/u,
    message: 'Refuse to read ~/.netrc (host credentials).',
  },
  {
    rule: 'read-secrets-file',
    pattern: /(?<prefix>^|\/)secrets?\.(?<ext>json|ya?ml|toml|env)$/iu,
    message: 'Refuse to read a file named secrets.{json,yaml,toml,env}.',
  },
];

const readProtect = (input: ReadInput): Decision => {
  const protection = classifyProtectedPath(input.file_path, 'read', PROTECTIONS);
  if (protection !== null) {
    return deny(protection.rule, protection.message);
  }
  return allow('read-protect');
};

export { readProtect };
