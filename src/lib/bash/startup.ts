type StartupState =
  | { readonly kind: 'direct' }
  | { readonly kind: 'checked' }
  | { readonly kind: 'unverified'; readonly reason: string };

const joinStartup = (...states: readonly StartupState[]): StartupState =>
  states.find((state) => state.kind === 'unverified') ??
  states.find((state) => state.kind === 'checked') ?? { kind: 'direct' };

const UNKNOWN_STARTUP =
  'Interpreter startup, working directory, or remote filesystem state is not verified.';

export { joinStartup, UNKNOWN_STARTUP };
export type { StartupState };
