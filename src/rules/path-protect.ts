import { lstatSync, readlinkSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { type Decision, allow, deny } from '../lib/decision';
import type { EditInput, WriteInput } from '../lib/event';

interface ProtectedPathSpec {
  readonly pattern: RegExp;
  readonly rule: string;
  readonly message: string;
}

type PathAccess = 'read' | 'write';

const protections: readonly ProtectedPathSpec[] = [
  {
    pattern: /(?<prefix>^|\/)\.env(?<ext>\.[^/]+)?$/,
    rule: 'env-file',
    message:
      '.env files hold secrets that should never be sent to the model. Refuse to write or edit. If an example is needed, create .env.example with redacted placeholders.',
  },
  {
    pattern: /(?<prefix>^|\/)\.dev\.vars(?<ext>\.[^/]+)?$/,
    rule: 'dev-vars',
    message: '.dev.vars holds Cloudflare/Wrangler secrets. Do not modify.',
  },
  {
    pattern: /(?<prefix>^|\/)\.ssh\//,
    rule: 'ssh-dir',
    message: 'Never write into ~/.ssh/. Refuse.',
  },
  {
    pattern: /(?<prefix>^|\/)(?<key>id_rsa|id_ed25519|id_ecdsa|id_dsa)(?<pub>\.pub)?$/,
    rule: 'ssh-key',
    message: 'SSH key file. Refuse.',
  },
  {
    pattern: /\.(?<ext>pem|key|p12|pfx)$/i,
    rule: 'private-key',
    message:
      'Private key file. Refuse to overwrite. If generating a new key, use a different filename and let the user review.',
  },
  {
    pattern: /(?<prefix>^|\/)secrets?\.(?<ext>json|ya?ml|toml|env)$/i,
    rule: 'secrets-file',
    message: 'Secrets file. Refuse.',
  },
  {
    pattern: /(?<prefix>^|\/)\.aws\/credentials$/,
    rule: 'aws-credentials',
    message: 'AWS credentials file. Refuse.',
  },
  {
    pattern: /(?<prefix>^|\/)\.netrc$/,
    rule: 'netrc',
    message: '.netrc holds host credentials. Refuse.',
  },
];

const resolveExistingPath = (absolutePath: string): string | null => {
  try {
    return realpathSync(absolutePath);
  } catch {
    return null;
  }
};

// A write target may not exist yet. Resolve the deepest existing parent and
// append the missing suffix. If an existing component is a dangling symlink,
// follow its link text before continuing so `alias -> .env` cannot hide a new
// protected target.
const resolveWritePath = (absolutePath: string, seen: Set<string> = new Set<string>()): string => {
  if (seen.has(absolutePath)) {
    return absolutePath;
  }
  seen.add(absolutePath);

  const existing = resolveExistingPath(absolutePath);
  if (existing !== null) {
    return existing;
  }

  try {
    if (lstatSync(absolutePath).isSymbolicLink()) {
      const target = readlinkSync(absolutePath);
      return resolveWritePath(path.resolve(path.dirname(absolutePath), target), seen);
    }
  } catch {
    // The target does not exist. Resolve its parent below.
  }

  const parent = path.dirname(absolutePath);
  if (parent === absolutePath) {
    return absolutePath;
  }
  return path.join(resolveWritePath(parent, seen), path.basename(absolutePath));
};

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
