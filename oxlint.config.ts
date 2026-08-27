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
    'no-continue': 'off',
    'require-unicode-regexp': 'off',
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
      { allowed: ['cli.ts', 'dispatch.ts', 'index.ts', 'main.ts', 'pi-extension.ts'] },
    ],
  },
  overrides: [
    {
      files: ['test/**/*.ts'],
      rules: {
        'max-statements': 'off',
        'typescript/no-unsafe-type-assertion': 'off',
        'vitest/prefer-importing-vitest-globals': 'off',
      },
    },
    {
      files: ['src/lib/bash.ts'],
      rules: {
        'de-clank/no-chained-type-assertions': 'off',
        'de-clank/no-overlong-comments': 'off',
        'de-clank/require-safety-comment-for-type-assertion': 'off',
        'no-inline-comments': 'off',
        'no-shadow': 'off',
        'typescript/no-non-null-assertion': 'off',
        'typescript/no-unsafe-type-assertion': 'off',
      },
    },
    {
      files: ['src/lib/cursor.ts', 'src/pi-extension.ts'],
      rules: {
        // These adapters normalize typed host unions before Schema decodes HookEvent.
        'de-clank-effect/prefer-effect-schema-boundary-decoding': 'off',
      },
    },
    {
      files: ['src/cli.ts', 'scripts/**/*.ts'],
      rules: {
        'no-console': 'off',
        // Src/main.ts imports this module only after it selects CLI mode.
        'de-clank/no-heavy-cli-entrypoint-imports': 'off',
      },
    },
  ],
});

export default composeDeClankConfig(coreBaseConfig, effectConfig, projectConfig);
