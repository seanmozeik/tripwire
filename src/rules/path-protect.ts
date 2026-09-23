import path from 'node:path';

import { type Decision, allow, deny } from '../lib/decision';
import type { EditInput, WriteInput } from '../lib/event';
import { resolveExistingPath, resolveWritePath } from '../lib/path-resolution';

interface ProtectedPathSpec {
  readonly pattern: RegExp;
  readonly rule: string;
  readonly message: string;
}

type PathAccess = 'read' | 'write';

const protections: readonly ProtectedPathSpec[] = [
  {
    pattern: /(?<prefix>^|\/)\.env(?<ext>\.[^/]+)?$/u,
    rule: 'env-file',
    message:
      '.env files hold secrets that should never be sent to the model. Refuse to write or edit. If an example is needed, create .env.example with redacted placeholders.',
  },
  {
    pattern: /(?<prefix>^|\/)\.dev\.vars(?<ext>\.[^/]+)?$/u,
    rule: 'dev-vars',
    message: '.dev.vars holds Cloudflare/Wrangler secrets. Do not modify.',
  },
  {
    pattern: /(?<prefix>^|\/)\.ssh(?:\/|$)/u,
    rule: 'ssh-dir',
    message: 'Never write into ~/.ssh/. Refuse.',
  },
  {
    pattern: /(?<prefix>^|\/)(?<key>id_rsa|id_ed25519|id_ecdsa|id_dsa)(?<pub>\.pub)?$/u,
    rule: 'ssh-key',
    message: 'SSH key file. Refuse.',
  },
  {
    pattern: /\.(?<ext>pem|key|p12|pfx)$/iu,
    rule: 'private-key',
    message:
      'Private key file. Refuse to overwrite. If generating a new key, use a different filename and let the user review.',
  },
  {
    pattern: /(?<prefix>^|\/)secrets?\.(?<ext>json|ya?ml|toml|env)$/iu,
    rule: 'secrets-file',
    message: 'Secrets file. Refuse.',
  },
  {
    pattern: /(?<prefix>^|\/)\.aws\/credentials$/u,
    rule: 'aws-credentials',
    message: 'AWS credentials file. Refuse.',
  },
  {
    pattern: /(?<prefix>^|\/)\.netrc$/u,
    rule: 'netrc',
    message: '.netrc holds host credentials. Refuse.',
  },
];

const classifyProtectedPath = (
  submittedPath: string,
  access: PathAccess,
  specs: readonly ProtectedPathSpec[],
): ProtectedPathSpec | null => {
  const absolutePath = path.resolve(submittedPath);
  const resolvedPath =
    access === 'write' ? resolveWritePath(absolutePath) : resolveExistingPath(absolutePath);
  const candidates = [submittedPath, absolutePath];
  if (resolvedPath !== null && !candidates.includes(resolvedPath)) {
    candidates.push(resolvedPath);
  }

  for (const candidate of candidates) {
    for (const spec of specs) {
      if (spec.pattern.test(candidate)) {
        return spec;
      }
    }
  }
  return null;
};

const pathProtect = (input: EditInput | WriteInput): Decision => {
  const protection = classifyProtectedPath(input.file_path, 'write', protections);
  if (protection !== null) {
    return deny(protection.rule, protection.message);
  }
  return allow('path-protect');
};

export type { PathAccess, ProtectedPathSpec };
export { classifyProtectedPath, pathProtect };

export { resolveWritePath } from '../lib/path-resolution';
