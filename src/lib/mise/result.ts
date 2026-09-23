type StartupResult = { readonly safe: true } | { readonly safe: false; readonly reason: string };

const requireSafe = (safe: boolean, reason: string): boolean => {
  if (!safe) {
    throw new Error(reason);
  }
  return true;
};

export { requireSafe };
export type { StartupResult };
