import { record } from './files';
import { assertVersionSelector, stripBom } from './idiomatic-version';
import { MiseInspectionError, assertSafe } from './inspection-error';

type Engine = { name: string | undefined; version: string | undefined; field: string };

const optionalString = (value: unknown, field: string): string | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new MiseInspectionError(`${field}: expected a string.`);
  }
  return value;
};

// Package_json.rs deserializes every array entry, but selects only the first.
const engine = (value: unknown, field: string): Engine | undefined => {
  if (value === undefined || value === null) {
    return undefined;
  }
  return (Array.isArray(value) ? value : [value]).map((item: unknown, index) => {
    const context = Array.isArray(value) ? `${field}[${index}]` : field;
    const data = record(item, context);
    return {
      name: optionalString(data['name'], `${context}.name`),
      version: optionalString(data['version'], `${context}.version`),
      field: `${context}.version`,
    };
  })[0];
};

const assertPackageManagerVersion = (value: string, field: string): void => {
  const [version, ...checksum] = value.split('+');
  assertVersionSelector(version?.trim(), field);
  // Mise passes the suffix through as a checksum installation option.
  assertSafe(
    checksum.length === 0 ||
      (checksum.length === 1 && /^sha(?:224|256|384|512)\.[0-9a-fA-F]+$/u.test(checksum[0] ?? '')),
    `${field}: unverified package manager checksum.`,
  );
};

const parsePackageJson = (source: string, filename: string): Record<string, unknown> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripBom(source));
  } catch {
    throw new MiseInspectionError(`${filename}: invalid package.json JSON.`);
  }
  return record(parsed, filename);
};

const assertMatchingChecksums = (runtime: string, managers: readonly Engine[]): void => {
  for (const manager of managers) {
    if (
      manager.version?.includes('+') === true &&
      manager.version.split('+')[0]?.trim() === runtime
    ) {
      assertPackageManagerVersion(manager.version, manager.field);
      return;
    }
  }
};

const assertPackageJson = (source: string, filename: string, tool: string): void => {
  const pkg = parsePackageJson(source, filename);
  const dev = pkg['devEngines'];
  const engines = dev === undefined || dev === null ? {} : record(dev, `${filename}: devEngines`);
  const runtime = engine(engines['runtime'], `${filename}: devEngines.runtime`);
  const manager = engine(engines['packageManager'], `${filename}: devEngines.packageManager`);
  const top = optionalString(pkg['packageManager'], `${filename}: packageManager`);
  const separator = top?.indexOf('@') ?? -1;
  const topManager: Engine = {
    name: top?.slice(0, separator),
    version: separator < 0 ? undefined : top?.slice(separator + 1),
    field: `${filename}: packageManager`,
  };
  const managers = [manager, topManager].filter((item): item is Engine => item?.name === tool);

  // Node/deno only read devEngines.runtime; bun prefers it over packageManager.
  // Engines, scripts, dependencies, and other names are not version sources.
  if (
    ['node', 'deno', 'bun'].includes(tool) &&
    runtime?.name === tool &&
    runtime.version !== undefined &&
    runtime.version !== ''
  ) {
    assertVersionSelector(runtime.version, runtime.field);
    if (tool !== 'bun') {
      return;
    }
    assertMatchingChecksums(runtime.version, managers);
  } else if (['bun', 'npm', 'pnpm', 'yarn'].includes(tool)) {
    const selected = managers.find((item) => item.version !== undefined && item.version !== '');
    if (selected?.version !== undefined) {
      assertPackageManagerVersion(selected.version, selected.field);
    }
  }
};

export { assertPackageJson };
