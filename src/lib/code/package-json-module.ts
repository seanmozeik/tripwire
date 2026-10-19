import { lstatSync, readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';

// Node CommonJS loads a resolved `.json` file as data. This module resolves a
// bare package specifier such as `example/package.json` the way `node -e` and
// `node -p` do, and returns null for every form it does not model exactly.

interface PackageSpecifier {
  readonly name: string;
  readonly subpath: string;
}

const parsePackageSpecifier = (specifier: string): PackageSpecifier | null => {
  if (/[\\%:]/u.test(specifier) || /^[./#]/u.test(specifier)) {
    return null;
  }

  const segments = specifier.split('/');

  if (segments.some((segment) => ['', '.', '..'].includes(segment))) {
    return null;
  }

  const nameLength = segments[0]?.startsWith('@') === true ? 2 : 1;
  const packageName = segments[nameLength - 1];

  if (
    segments.length <= nameLength ||
    segments[0] === '@' ||
    packageName === undefined ||
    packageName.startsWith('.')
  ) {
    return null;
  }

  const subpath = segments.slice(nameLength).join('/');

  return subpath.endsWith('.json')
    ? { name: segments.slice(0, nameLength).join('/'), subpath }
    : null;
};

const isPackageJsonSpecifier = (specifier: string): boolean =>
  parsePackageSpecifier(specifier) !== null;

type Manifest =
  | { readonly kind: 'missing' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'present'; readonly fields: Readonly<Record<string, unknown>> };

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const readManifest = (file: string): Manifest => {
  let source: string;

  try {
    source = readFileSync(file, 'utf8');
  } catch (cause) {
    const missing =
      cause instanceof Error &&
      'code' in cause &&
      ['ENOENT', 'ENOTDIR'].includes(String(cause.code));

    return { kind: missing ? 'missing' : 'invalid' };
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(source);
  } catch {
    return { kind: 'invalid' };
  }

  return isRecord(parsed) ? { kind: 'present', fields: parsed } : { kind: 'invalid' };
};

const hasExports = (manifest: Manifest): boolean =>
  manifest.kind === 'present' &&
  manifest.fields['exports'] !== undefined &&
  manifest.fields['exports'] !== null;

// Package exports can map a JSON subpath to code under any condition. Only an
// exact self-mapping such as "./package.json": "./package.json" is accepted.
const exportedFile = (manifest: Manifest, directory: string, subpath: string): string | null => {
  if (manifest.kind !== 'present') {
    return null;
  }

  const { exports: exportsField } = manifest.fields;
  const key = `./${subpath}`;

  return isRecord(exportsField) && Object.hasOwn(exportsField, key) && exportsField[key] === key
    ? path.join(directory, subpath)
    : null;
};

const nearestManifest = (directory: string): { directory: string; manifest: Manifest } | null => {
  let current = directory;

  for (;;) {
    if (path.basename(current) === 'node_modules') {
      return null;
    }

    const manifest = readManifest(path.join(current, 'package.json'));

    if (manifest.kind !== 'missing') {
      return { directory: current, manifest };
    }

    const parent = path.dirname(current);

    if (parent === current) {
      return null;
    }

    current = parent;
  }
};

type Lookup = { readonly kind: 'file'; readonly file: string } | { readonly kind: 'next' } | null;

// Node tries the exact file, then extension suffixes, then a directory entry.
// Anything other than one regular file here could load code instead of data.
const packageFile = (packageDirectory: string, subpath: string): Lookup => {
  const candidate = path.join(packageDirectory, subpath);

  try {
    if (statSync(candidate).isFile()) {
      return { kind: 'file', file: candidate };
    }

    return null;
  } catch {
    // Missing. Check below that Node has no other candidate here.
  }

  for (const alternative of [
    candidate,
    `${candidate}.js`,
    `${candidate}.json`,
    `${candidate}.node`,
  ]) {
    try {
      lstatSync(alternative);

      return null;
    } catch {
      // Missing.
    }
  }

  return { kind: 'next' };
};

// Node first resolves a request that names the enclosing package through its
// own exports. Inline source is evaluated as a module in the startup cwd.
const selfReference = (
  specifier: string,
  start: string,
): { readonly resolved: string | null } | null => {
  const scope = nearestManifest(start);

  if (scope === null || scope.manifest.kind === 'missing') {
    return null;
  }

  if (scope.manifest.kind === 'invalid') {
    return { resolved: null };
  }

  const { name } = scope.manifest.fields;

  if (name === undefined || !hasExports(scope.manifest)) {
    return null;
  }

  if (typeof name !== 'string') {
    return { resolved: null };
  }

  if (specifier !== name && !specifier.startsWith(`${name}/`)) {
    return null;
  }

  const subpath = specifier.slice(name.length + 1);

  return {
    resolved: subpath === '' ? null : exportedFile(scope.manifest, scope.directory, subpath),
  };
};

const resolvePackageJsonModule = (specifier: string, cwd: string): string | null => {
  const parsed = parsePackageSpecifier(specifier);

  if (parsed === null) {
    return null;
  }

  let start: string;

  try {
    start = realpathSync(cwd);
  } catch {
    return null;
  }

  const self = selfReference(specifier, start);

  if (self !== null) {
    return self.resolved;
  }

  let current = start;

  for (;;) {
    if (path.basename(current) !== 'node_modules') {
      const packageDirectory = path.join(current, 'node_modules', parsed.name);
      const manifest = readManifest(path.join(packageDirectory, 'package.json'));

      if (manifest.kind === 'invalid') {
        return null;
      }

      if (hasExports(manifest)) {
        return exportedFile(manifest, packageDirectory, parsed.subpath);
      }

      const lookup = packageFile(packageDirectory, parsed.subpath);

      if (lookup?.kind !== 'next') {
        return lookup?.file ?? null;
      }
    }

    const parent = path.dirname(current);

    if (parent === current) {
      // NODE_PATH and global folders are not modeled.
      return null;
    }

    current = parent;
  }
};

export { isPackageJsonSpecifier, resolvePackageJsonModule };
