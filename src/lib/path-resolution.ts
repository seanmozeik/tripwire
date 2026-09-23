import { lstatSync, readlinkSync, realpathSync } from 'node:fs';
import path from 'node:path';

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

export { resolveExistingPath, resolveWritePath };
