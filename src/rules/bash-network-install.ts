import type { ShellProgram } from '../lib/bash';
import { type Decision, allow, ask, deny } from '../lib/decision';

// Block `curl|wget ... | bash|sh|zsh` (the canonical supply-chain footgun).
// Ask before global installs that pull arbitrary code from a registry.

const FETCH_HEADS: ReadonlySet<string> = new Set(['curl', 'wget', 'wget2', 'aria2c', 'xh']);
const SHELL_HEADS: ReadonlySet<string> = new Set(['bash', 'sh', 'zsh', 'fish']);

const isFetchPipedToShell = (program: ShellProgram): boolean => {
  for (const fetch of program.invocations) {
    const { pipeline } = fetch;
    if (FETCH_HEADS.has(fetch.head) && pipeline !== undefined) {
      const shell = program.invocations.find(
        (candidate) =>
          candidate.pipeline?.id === pipeline.id &&
          candidate.pipeline.index === pipeline.index + 1 &&
          SHELL_HEADS.has(candidate.head),
      );
      if (shell !== undefined) {
        return true;
      }
    }
  }
  return false;
};

interface InstallSpec {
  readonly head: string;
  readonly subcommand: string;
  readonly rule: string;
  readonly message: string;
}

const INSTALL_SPECS: readonly InstallSpec[] = [
  {
    head: 'cargo',
    subcommand: 'install',
    rule: 'cargo-install',
    message:
      'Confirm before `cargo install <crate>`: this builds and installs arbitrary code from crates.io into ~/.cargo/bin globally.',
  },
  {
    head: 'go',
    subcommand: 'install',
    rule: 'go-install',
    message: 'Confirm before `go install`: this fetches and installs arbitrary Go code globally.',
  },
  {
    head: 'gem',
    subcommand: 'install',
    rule: 'gem-install',
    message: 'Confirm before `gem install`: pulls arbitrary code from rubygems.org.',
  },
];

const bashNetworkInstall = (program: ShellProgram): Decision => {
  if (isFetchPipedToShell(program)) {
    return deny(
      'curl-pipe-shell',
      "Piping `curl` / `wget` directly into a shell runs whatever the remote URL serves. Refuse — download to a file, inspect, then run if appropriate. If you genuinely need this, append ` # tripwire-allow: <reason>` (and explain to the user what you're running).",
    );
  }
  for (const seg of program.invocations) {
    for (const s of INSTALL_SPECS) {
      if (seg.head === s.head && seg.tokens[1] === s.subcommand) {
        return ask(s.rule, s.message);
      }
    }
  }
  return allow('bash-network-install');
};

export { bashNetworkInstall };
