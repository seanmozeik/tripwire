import {
  composeDeClankConfig,
  coreBaseConfig,
  effectConfig,
  loadPersonalData,
} from '@seanmozeik/de-clank/config';
import { defineConfig } from 'oxlint';

const projectConfig = defineConfig({
  env: { es2024: true, node: true },
  globals: { Bun: 'readonly' },
  ignorePatterns: ['node_modules', 'dist', 'coverage'],
  rules: {
    'de-clank/no-environment-access-outside-boundary': [
      'error',
      { allowedFilePatterns: [String.raw`/src/lib/environment\.ts$`] },
    ],
    'de-clank/no-personal-test-data': ['error', loadPersonalData()],
    'de-clank/no-test-only-production-code': [
      'error',
      {
        productionEntrypoints: [
          'scripts/build.ts',
          'src/index.ts',
          'src/main.ts',
          'src/pi-extension.ts',
        ],
      },
    ],
    'de-clank/no-unowned-source-root-files': [
      'error',
      { allowed: ['dispatch.ts', 'index.ts', 'main.ts', 'pi-extension.ts'] },
    ],
  },
});

export default composeDeClankConfig(coreBaseConfig, effectConfig, projectConfig);
