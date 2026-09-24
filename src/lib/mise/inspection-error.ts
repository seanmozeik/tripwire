class MiseInspectionError extends Error {
  override name = 'MiseInspectionError';
}

const assertSafe = (condition: boolean, reason: string): void => {
  if (!condition) {
    throw new MiseInspectionError(reason);
  }
};

export { MiseInspectionError, assertSafe };
