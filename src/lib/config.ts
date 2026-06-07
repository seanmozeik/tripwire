// Config system using Effect Schema for validation and Effect for safe loading.
// Config file: ~/.config/tripwire/config.json
// Falls back to defaults if file doesn't exist or is invalid.

import { accessSync, constants, readFileSync } from 'node:fs';
import { homedir } from 'node:os';

import { Cause, Effect, Schema } from 'effect';

const BlockRuleSchema = Schema.Struct({
  pattern: Schema.String,
  message: Schema.String,
  action: Schema.optional(Schema.Union([Schema.Literal('deny'), Schema.Literal('ask')])),
  requiresFlags: Schema.optional(Schema.Array(Schema.String)),
  forbidsFlagValues: Schema.optional(
    Schema.Array(Schema.Struct({ flag: Schema.String, values: Schema.Array(Schema.String) })),
  ),
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
  git: Schema.optional(GitConfigSchema),
  safePaths: Schema.optional(SafePathsConfigSchema),
  blockedCommands: Schema.optional(Schema.Array(BlockRuleSchema)),
  allowedCommands: Schema.optional(Schema.Array(BlockRuleSchema)),
});

const CONFIG_PATH = `${homedir()}/.config/tripwire/config.json`;

const configExists = (path: string): Effect.Effect<boolean> =>
  Effect.sync(() => {
    try {
      accessSync(path, constants.R_OK);
      return true;
    } catch {
      return false;
    }
  });

const readConfigFile = (path: string): Effect.Effect<string, Error> =>
  Effect.try({ try: () => readFileSync(path, 'utf8'), catch: (error) => error as Error });

const parseConfigJson = (raw: string): Effect.Effect<unknown, Error> =>
  Effect.try({ try: () => JSON.parse(raw) as unknown, catch: (error) => error as Error });

// `onExcessProperty: 'error'` rejects unknown keys (the default 'ignore' would
// Silently strip them — a typo'd `blockedComands` would vanish unnoticed, the
// Same silent-policy-drop class this whole change exists to kill). A stray key
// Now fails loud, e.g. the `rtk` block that triggered MTA-137.
const decodeConfig = (unknown: unknown): Effect.Effect<Config, Error> =>
  Schema.decodeUnknownEffect(ConfigSchema)(unknown, { onExcessProperty: 'error' });

const getDefaultConfig = (): Config => ({
  git: {
    protectedBranches: ['main', 'master', 'develop', 'production', 'release'],
    enforceConventionalCommits: true,
  },
  safePaths: {},
  blockedCommands: [],
  allowedCommands: [],
});

const mergeWithDefaults = (partial: Config): Config => ({
  git: partial.git ?? getDefaultConfig().git,
  safePaths: partial.safePaths ?? getDefaultConfig().safePaths,
  blockedCommands: partial.blockedCommands ?? getDefaultConfig().blockedCommands,
  allowedCommands: partial.allowedCommands ?? getDefaultConfig().allowedCommands,
});

// A present-but-broken config (bad JSON, schema decode failure, timeout) must
// Never be papered over with defaults — that silently drops all custom safety
// Policy. `loadConfigResult` reports the failure as data so callers can fail
// Closed loudly (see `loadConfig` and the dispatcher). A *missing* file is the
// One legitimate defaults case.
type ConfigLoad =
  | { readonly ok: true; readonly config: Config }
  | { readonly ok: false; readonly error: string };

export const loadConfigResult = (path: string = CONFIG_PATH): Effect.Effect<ConfigLoad> =>
  Effect.gen(function* () {
    const exists = yield* configExists(path);
    if (!exists) {
      const result: ConfigLoad = { ok: true, config: getDefaultConfig() };
      return result;
    }

    const raw = yield* readConfigFile(path);
    const parsed = yield* parseConfigJson(raw);
    const config = yield* decodeConfig(parsed);
    const result: ConfigLoad = { ok: true, config: mergeWithDefaults(config) };
    return result;
  }).pipe(
    Effect.timeout(1000),
    Effect.catchCause((cause) => {
      const result: ConfigLoad = { ok: false, error: Cause.pretty(cause) };
      return Effect.succeed(result);
    }),
  );

// Loud loader for library consumers (e.g. the shim daemon) that expect a
// `Config`. A broken config dies rather than silently defaulting, so the
// Consumer fails closed visibly until the file is fixed.
export const loadConfig = (path: string = CONFIG_PATH): Effect.Effect<Config> =>
  loadConfigResult(path).pipe(
    Effect.flatMap((result) =>
      result.ok
        ? Effect.succeed(result.config)
        : Effect.die(new Error(`[tripwire] config load failed (${path}): ${result.error}`)),
    ),
  );

export type BlockRule = typeof BlockRuleSchema.Type;
export type GitConfig = typeof GitConfigSchema.Type;
export type SafePathsConfig = typeof SafePathsConfigSchema.Type;
export type Config = typeof ConfigSchema.Type;

export type { ConfigLoad };
export { CONFIG_PATH, ConfigSchema, getDefaultConfig, mergeWithDefaults };
