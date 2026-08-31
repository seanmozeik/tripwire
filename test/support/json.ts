const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const parseJsonRecord = (text: string): Record<string, unknown> => {
  const value = JSON.parse(text) as unknown;
  if (!isRecord(value)) {
    throw new Error('Expected a JSON object');
  }
  return value;
};

const recordField = (
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> | undefined => {
  const field = value[key];
  return isRecord(field) ? field : undefined;
};

const recordArrayField = (
  value: Record<string, unknown>,
  key: string,
): readonly Record<string, unknown>[] => {
  const field = value[key];
  return Array.isArray(field) ? field.filter((item) => isRecord(item)) : [];
};

export { isRecord, parseJsonRecord, recordArrayField, recordField };
