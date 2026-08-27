interface RuntimeEnvironment {
  readonly bunExecutable: string | undefined;
  readonly forcePortable: boolean;
  readonly packageDist: string | undefined;
}

const nonEmptyEnvironmentValue = (value: string | undefined): string | undefined => {
  const normalized = value?.trim();
  return normalized === undefined || normalized.length === 0 ? undefined : normalized;
};

const readRuntimeEnvironment = (): RuntimeEnvironment => ({
  bunExecutable: nonEmptyEnvironmentValue(process.env['TRIPWIRE_BUN']),
  forcePortable: process.env['TRIPWIRE_FORCE_PORTABLE'] === '1',
  packageDist: nonEmptyEnvironmentValue(process.env['TRIPWIRE_PACKAGE_DIST']),
});

const environmentWithPackageDist = (packageDist: string): Record<string, string | undefined> => ({
  ...process.env,
  TRIPWIRE_PACKAGE_DIST: packageDist,
});

export { environmentWithPackageDist, readRuntimeEnvironment, type RuntimeEnvironment };
