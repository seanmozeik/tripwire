// Config system using Effect Schema for validation and Effect for safe loading.
// Config file: ~/.config/tripwire/config.json
// Falls back to defaults if file doesn't exist or is invalid.

import { accessSync, constants, readFileSync } from 'node:fs';
import { homedir } from 'node:os';

import { Effect, Schema } from 'effect';

const BlockRuleSchema = Schema.Struct({
  pattern: Schema.String,
  message: Schema.String,
  action: Schema.optional(Schema.Union([Schema.Literal('deny'), Schema.Literal('ask')])),
});

const RtkConfigSchema = Schema.Struct({
  enabled: Schema.optional(Schema.Boolean),
  path: Schema.optional(Schema.String),
});

const GitConfigSchema = Schema.Struct({
  protectedBranches: Schema.optional(Schema.Array(Schema.String)),
  enforceConventionalCommits: Schema.optional(Schema.Boolean),
});

const SafePathsConfigSchema = Schema.Struct({
  relative: Schema.optional(Schema.Array(Schema.String)),
  absolute: Schema.optional(Schema.Array(Schema.String)),
});

const ConfigSchema = Schema.Struct({
  rtk: Schema.optional(RtkConfigSchema),
  git: Schema.optional(GitConfigSchema),
  safePaths: Schema.optional(SafePathsConfigSchema),
  blockedCommands: Schema.optional(Schema.Array(BlockRuleSchema)),
  allowedCommands: Schema.optional(Schema.Array(BlockRuleSchema)),
});

const CONFIG_PATH = `${homedir()}/.config/tripwire/config.json`;

const configExists = (): Effect.Effect<boolean> =>
  Effect.sync(() => {
    try {
      accessSync(CONFIG_PATH, constants.R_OK);
      return true;
    } catch {
      return false;
    }
  });

const readConfigFile = (): Effect.Effect<string, Error> =>
  Effect.try({ try: () => readFileSync(CONFIG_PATH, 'utf8'), catch: (error) => error as Error });

const parseConfigJson = (raw: string): Effect.Effect<unknown, Error> =>
  Effect.try({ try: () => JSON.parse(raw) as unknown, catch: (error) => error as Error });

const decodeConfig = (unknown: unknown): Effect.Effect<Config, Error> =>
  Schema.decodeUnknownEffect(ConfigSchema)(unknown);

const getDefaultConfig = (): Config => ({
  rtk: { enabled: false },
  git: {
    protectedBranches: ['main', 'master', 'develop', 'production', 'release'],
    enforceConventionalCommits: true,
  },
  safePaths: {},
  blockedCommands: [],
  allowedCommands: [],
});

const mergeWithDefaults = (partial: Config): Config => ({
  rtk: partial.rtk ?? getDefaultConfig().rtk,
  git: partial.git ?? getDefaultConfig().git,
  safePaths: partial.safePaths ?? getDefaultConfig().safePaths,
  blockedCommands: partial.blockedCommands ?? getDefaultConfig().blockedCommands,
  allowedCommands: partial.allowedCommands ?? getDefaultConfig().allowedCommands,
});

export const loadConfig = (): Effect.Effect<Config> =>
  Effect.gen(function* () {
    const exists = yield* configExists();
    if (!exists) {
      return getDefaultConfig();
    }

    const raw = yield* readConfigFile();
    const parsed = yield* parseConfigJson(raw);
    const config = yield* decodeConfig(parsed);
    return mergeWithDefaults(config);
  }).pipe(
    Effect.timeout(1000),
    // oxlint-disable-next-line promise/prefer-await-to-then
    Effect.catch(() => {
      // Log error but return defaults to never block the agent
      console.error('[tripwire] Config loading failed, using defaults');
      return Effect.succeed(getDefaultConfig());
    }),
  );

export type BlockRule = typeof BlockRuleSchema.Type;
export type RtkConfig = typeof RtkConfigSchema.Type;
export type GitConfig = typeof GitConfigSchema.Type;
export type SafePathsConfig = typeof SafePathsConfigSchema.Type;
export type Config = typeof ConfigSchema.Type;

export { CONFIG_PATH, ConfigSchema };
