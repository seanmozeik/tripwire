export type { Decision } from './lib/decision';
export type { HookEvent } from './lib/event';
export type { Config, ConfigLoad, ResolvedConfig } from './lib/config';
export { allow, deny, ask, warn } from './lib/decision';
export { decide, decideBash } from './dispatch';
export { getDefaultConfig, loadConfig, loadConfigResult, mergeWithDefaults } from './lib/config';
