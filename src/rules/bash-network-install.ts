import { type Segment, hasBypass } from '../lib/bash';
import { type Decision, allow, ask, deny } from '../lib/decision';

// Block `curl|wget ... | bash|sh|zsh` (the canonical supply-chain footgun).
// Ask before global installs that pull arbitrary code from a registry.

const FETCH_HEADS: ReadonlySet<string> = new Set(['curl', 'wget', 'wget2', 'aria2c', 'xh']);
const SHELL_HEADS: ReadonlySet<string> = new Set(['bash', 'sh', 'zsh', 'fish']);

const isFetchPipedToShell = (segments: readonly Segment[]): boolean => {
  // Shell-quote splits a pipeline `curl X | bash` into two segments. We
  // Detect the pattern by looking for adjacent fetch-then-shell heads.
  for (let i = 0; i < segments.length - 1; i++) {
    const a = segments[i]!;
    const b = segments[i + 1]!;
    if (FETCH_HEADS.has(a.head) && SHELL_HEADS.has(b.head)) {
      return true;
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

const bashNetworkInstall = (segments: readonly Segment[], cmd: string): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-network-install');
  }
  if (isFetchPipedToShell(segments)) {
    return deny(
      'curl-pipe-shell',
      "Piping `curl` / `wget` directly into a shell runs whatever the remote URL serves. Refuse — download to a file, inspect, then run if appropriate. If you genuinely need this, append ` # tripwire-allow: <reason>` (and explain to Sean what you're running).",
    );
  }
  for (const seg of segments) {
    for (const s of INSTALL_SPECS) {
      if (seg.head === s.head && seg.tokens[1] === s.subcommand) {
        return ask(s.rule, s.message);
      }
    }
  }
  return allow('bash-network-install');
};

export { bashNetworkInstall };
