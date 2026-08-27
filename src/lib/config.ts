// Config system using Effect Schema for validation and Effect for safe loading.
// Config file: ~/.config/tripwire/config.json
// Falls back to defaults only if the file does not exist.

import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';

import { Cause, Data, Effect, Schema } from 'effect';

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

const ToolPolicyMatchSchema = Schema.Struct({
  argumentsIncludeAll: Schema.optional(Schema.Array(Schema.String)),
  argumentsStartWith: Schema.optional(Schema.Array(Schema.String)),
  shortFlagsIncludeAll: Schema.optional(Schema.Array(Schema.String)),
});

const ToolPolicySchema = Schema.Struct({
  rule: Schema.String,
  executables: Schema.Array(Schema.String),
  action: Schema.Union([Schema.Literal('deny'), Schema.Literal('warn')]),
  message: Schema.String,
  match: Schema.optional(ToolPolicyMatchSchema),
});

const SecretScannerConfigSchema = Schema.Struct({
  executable: Schema.String,
  timeoutMs: Schema.Finite.check(Schema.isGreaterThan(0)),
});

const ConfigSchema = Schema.Struct({
  git: Schema.optional(GitConfigSchema),
  safePaths: Schema.optional(SafePathsConfigSchema),
  toolPolicies: Schema.optional(Schema.Array(ToolPolicySchema)),
  blockedCommands: Schema.optional(Schema.Array(BlockRuleSchema)),
  allowedCommands: Schema.optional(Schema.Array(BlockRuleSchema)),
  secretScanner: Schema.optional(SecretScannerConfigSchema),
});

const CONFIG_PATH = `${homedir()}/.config/tripwire/config.json`;

class ConfigReadError extends Data.TaggedError('ConfigReadError')<{ readonly cause: unknown }> {}

class ConfigParseError extends Data.TaggedError('ConfigParseError')<{ readonly cause: unknown }> {}

const isMissingFile = (cause: unknown): boolean =>
  cause instanceof Error && 'code' in cause && cause.code === 'ENOENT';

const readConfigFile = (path: string): Effect.Effect<string | null, ConfigReadError> =>
  Effect.try({
    try: () => readFileSync(path, 'utf8'),
    catch: (cause) => new ConfigReadError({ cause }),
  }).pipe(
    Effect.catchTag('ConfigReadError', (error) =>
      isMissingFile(error.cause) ? Effect.succeed(null) : Effect.fail(error),
    ),
  );

const parseConfigJson = (raw: string): Effect.Effect<unknown, Error> =>
  Effect.try({
    try: () => JSON.parse(raw) as unknown,
    catch: (cause) => new ConfigParseError({ cause }),
  });

// Reject unknown keys so a misspelled policy cannot disappear silently.
const decodeConfig = (unknown: unknown): Effect.Effect<Config, Error> =>
  Schema.decodeUnknownEffect(ConfigSchema)(unknown, { onExcessProperty: 'error' });

const getDefaultConfig = (): ResolvedConfig => ({
  git: { protectedBranches: [], enforceConventionalCommits: false },
  safePaths: {},
  toolPolicies: [],
  blockedCommands: [],
  allowedCommands: [],
  secretScanner: { executable: 'betterleaks', timeoutMs: 5000 },
});

const mergeWithDefaults = (partial: Config): ResolvedConfig => {
  const defaults = getDefaultConfig();
  return {
    git: {
      protectedBranches: partial.git?.protectedBranches ?? defaults.git.protectedBranches,
      enforceConventionalCommits:
        partial.git?.enforceConventionalCommits ?? defaults.git.enforceConventionalCommits,
    },
    safePaths: { ...defaults.safePaths, ...partial.safePaths },
    toolPolicies: partial.toolPolicies ?? defaults.toolPolicies,
    blockedCommands: partial.blockedCommands ?? defaults.blockedCommands,
    allowedCommands: partial.allowedCommands ?? defaults.allowedCommands,
    secretScanner: partial.secretScanner ?? defaults.secretScanner,
  };
};

// A present but invalid config must not fall back to defaults because that
// would drop custom safety policy. Only a missing file selects defaults.
type ConfigLoad =
  | { readonly ok: true; readonly config: ResolvedConfig }
  | { readonly ok: false; readonly error: string };

export const loadConfigResult = (path: string = CONFIG_PATH): Effect.Effect<ConfigLoad> =>
  Effect.gen(function* loadConfigResultEffect() {
    const raw = yield* readConfigFile(path);
    if (raw === null) {
      const result: ConfigLoad = { ok: true, config: getDefaultConfig() };
      return result;
    }

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

// Library consumers get a loud failure instead of an unconfigured fallback.
export const loadConfig = (path: string = CONFIG_PATH): Effect.Effect<ResolvedConfig> =>
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
export type ToolPolicy = typeof ToolPolicySchema.Type;
export type SecretScannerConfig = typeof SecretScannerConfigSchema.Type;
export type Config = typeof ConfigSchema.Type;

export interface ResolvedConfig {
  readonly git: {
    readonly protectedBranches: readonly string[];
    readonly enforceConventionalCommits: boolean;
  };
  readonly safePaths: SafePathsConfig;
  readonly toolPolicies: readonly ToolPolicy[];
  readonly blockedCommands: readonly BlockRule[];
  readonly allowedCommands: readonly BlockRule[];
  readonly secretScanner: SecretScannerConfig;
}

export type { ConfigLoad };
export {
  CONFIG_PATH,
  ConfigSchema,
  SecretScannerConfigSchema,
  getDefaultConfig,
  mergeWithDefaults,
};
