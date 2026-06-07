export type { Decision } from './lib/decision.ts';
export type { HookEvent } from './lib/event.ts';
export type { Config, ConfigLoad } from './lib/config.ts';
export { allow, deny, ask, warn } from './lib/decision.ts';
export { decide } from './dispatch.ts';
export { getDefaultConfig, loadConfig, loadConfigResult, mergeWithDefaults } from './lib/config.ts';
