import { type Segment, hasBypass } from '../lib/bash.ts';
import { type Decision, allow, ask, deny } from '../lib/decision.ts';

interface Spec {
  readonly rule: string;
  readonly action: 'deny' | 'ask';
  readonly message: string;
  // Match function evaluated against the parsed segment. Returns true when
  // The rule fires.
  readonly match: (seg: Segment, raw: string) => boolean;
}

const argsJoined = (seg: Segment): string => seg.tokens.slice(1).join(' ');

const flagPresent = (seg: Segment, ...flags: readonly string[]): boolean =>
  seg.flags.some((f) => flags.includes(f));

const SPECS: readonly Spec[] = [
  // ── catastrophic deletions ────────────────────────────────────────────
  {
    rule: 'rm-rf-root',
    action: 'deny',
    message:
      'rm -rf / is catastrophic. If the goal is cleaning a subdirectory, scope the path inside the project (e.g. ./dist).',
    match: (seg) =>
      seg.head === 'rm' && flagPresent(seg, '-rf', '-fr', '-Rf', '-fR') && seg.tokens.includes('/'),
  },
  {
    rule: 'rm-rf-home',
    action: 'deny',
    message: 'rm -rf on $HOME / ~ would erase the home directory. Refuse.',
    match: (seg) =>
      seg.head === 'rm' &&
      flagPresent(seg, '-rf', '-fr', '-Rf', '-fR') &&
      seg.tokens.some((t) => /^(~|\$HOME|\$\{HOME\})$/.test(t)),
  },
  {
    rule: 'fork-bomb',
    action: 'deny',
    message: 'Fork bomb pattern detected. Refuse.',
    match: (_seg, raw) => /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/.test(raw),
  },
  {
    rule: 'dd-raw-device',
    action: 'deny',
    message: 'dd writing to a raw block device wipes the disk. Refuse.',
    match: (seg) => seg.head === 'dd' && /\bof=\/dev\/(disk|sd|nvme|rdisk)/i.test(argsJoined(seg)),
  },
  {
    rule: 'mkfs',
    action: 'deny',
    message: 'mkfs formats a filesystem. Refuse.',
    match: (seg) => /^mkfs(\.[a-z0-9]+)?$/i.test(seg.head),
  },
  {
    rule: 'kill-all',
    action: 'deny',
    message: 'kill -9 -1 kills every process you own. Refuse.',
    match: (seg) => seg.head === 'kill' && seg.tokens.includes('-9') && seg.tokens.includes('-1'),
  },
  {
    rule: 'chmod-777-recursive',
    action: 'deny',
    message:
      'Recursive chmod 777 makes everything world-writable. Use 755 for directories, 644 for files, scoped narrowly.',
    match: (seg) =>
      seg.head === 'chmod' && seg.flags.some((f) => f.includes('R')) && seg.tokens.includes('777'),
  },

  // ── git: detailed policy lives in bash-git.ts (smarter, supports
  // ── `git -C <dir>`, conventional-commit enforcement, etc.) ──────────

  // ── verify-skipping & signing-bypass ──────────────────────────────────
  {
    rule: 'no-verify',
    action: 'deny',
    message:
      "--no-verify skips git hooks. Per Sean's rules: never skip hooks. Fix the underlying issue.",
    match: (seg) => seg.tokens.includes('--no-verify'),
  },
  {
    rule: 'no-gpg-sign',
    action: 'deny',
    message: 'Bypassing GPG signing is off-limits unless Sean explicitly asks for it.',
    match: (_seg, raw) => /--no-gpg-sign\b|-c\s+commit\.gpgsign=false/.test(raw),
  },

  // ── sudo: ask ─────────────────────────────────────────────────────────
  {
    rule: 'sudo',
    action: 'ask',
    message:
      'sudo escalates privileges and is almost never needed in a coding session. If genuinely required, explain why; otherwise find a non-sudo path.',
    match: (seg) => seg.head === 'sudo',
  },

  // ── macOS / system destructive ────────────────────────────────────────
  {
    rule: 'shutdown',
    action: 'deny',
    message: 'shutdown / reboot / halt control the machine. Refuse — Sean drives that himself.',
    match: (seg) => ['shutdown', 'reboot', 'halt', 'poweroff'].includes(seg.head),
  },
  {
    rule: 'launchctl-mutation',
    action: 'deny',
    message:
      'launchctl load/unload/bootstrap/bootout/kickstart mutates system services. Refuse — surface the intent to Sean instead.',
    match: (seg) =>
      seg.head === 'launchctl' &&
      typeof seg.tokens[1] === 'string' &&
      ['load', 'unload', 'bootstrap', 'bootout', 'kickstart', 'enable', 'disable'].includes(
        seg.tokens[1],
      ),
  },
  {
    rule: 'defaults-write',
    action: 'deny',
    message: '`defaults write` mutates macOS preferences. Refuse — surface the intent to Sean.',
    match: (seg) => seg.head === 'defaults' && seg.tokens[1] === 'write',
  },
  {
    rule: 'csrutil',
    action: 'deny',
    message: 'csrutil controls System Integrity Protection. Refuse.',
    match: (seg) => seg.head === 'csrutil',
  },
  {
    rule: 'nvram',
    action: 'deny',
    message: 'nvram modifies firmware variables. Refuse.',
    match: (seg) => seg.head === 'nvram',
  },
  {
    rule: 'diskutil-destructive',
    action: 'deny',
    message: 'diskutil eraseDisk / reformat / partitionDisk wipes disks. Refuse.',
    match: (seg) =>
      seg.head === 'diskutil' &&
      typeof seg.tokens[1] === 'string' &&
      ['eraseDisk', 'reformat', 'partitionDisk', 'eraseVolume', 'secureErase'].includes(
        seg.tokens[1],
      ),
  },
  {
    rule: 'tmutil-destructive',
    action: 'deny',
    message: 'tmutil delete / disablelocal touches Time Machine. Refuse.',
    match: (seg) =>
      seg.head === 'tmutil' &&
      typeof seg.tokens[1] === 'string' &&
      ['delete', 'disablelocal'].includes(seg.tokens[1]),
  },
  {
    rule: 'osascript',
    action: 'ask',
    message:
      'osascript runs arbitrary AppleScript and can do almost anything (move files, send emails, drive apps). Confirm with Sean what you want done before running it.',
    match: (seg) => seg.head === 'osascript',
  },
  {
    rule: 'topgrade',
    action: 'deny',
    message:
      'topgrade upgrades everything (brew, mas, npm globals, rust, mise). Sean controls that himself.',
    match: (seg) => seg.head === 'topgrade',
  },
  {
    rule: 'mackup',
    action: 'deny',
    message: "Mackup is off-limits per Sean's rules. Never modify mackup config or sync flow.",
    match: (seg) => seg.head === 'mackup',
  },
  {
    rule: 'rsync-delete',
    action: 'deny',
    message:
      'rsync --delete removes files at the destination. High blast radius — surface intent to Sean instead.',
    match: (seg) => seg.head === 'rsync' && seg.flags.includes('--delete'),
  },
  {
    rule: 'softwareupdate-install',
    action: 'deny',
    message:
      '`softwareupdate --install / -i / -d` triggers macOS system updates. Refuse — Sean drives system updates himself.',
    match: (seg) =>
      seg.head === 'softwareupdate' &&
      seg.flags.some(
        (f) => f === '--install' || f === '-i' || f === '-d' || f.startsWith('--download'),
      ),
  },
  {
    rule: 'pmset-write',
    action: 'deny',
    message:
      '`pmset` (with arguments) writes power-management settings. Read-only `pmset -g` is fine; mutations need Sean.',
    match: (seg) =>
      seg.head === 'pmset' &&
      seg.tokens.length > 1 &&
      !seg.tokens.includes('-g') &&
      !seg.tokens.includes('-G'),
  },
  {
    rule: 'dscl-mutate',
    action: 'deny',
    message:
      '`dscl . -create / -delete / -append / -change / -merge` modifies the local directory service (your user account, groups, etc.). Refuse.',
    match: (seg) =>
      seg.head === 'dscl' &&
      seg.tokens.some((t) =>
        ['-create', '-delete', '-append', '-change', '-merge', '-passwd'].includes(t),
      ),
  },
  {
    rule: 'xattr-quarantine-bypass',
    action: 'deny',
    message:
      "`xattr -d com.apple.quarantine` removes Gatekeeper's quarantine bit — the macOS protection against running untrusted binaries. Refuse.",
    match: (seg) =>
      seg.head === 'xattr' &&
      seg.tokens.includes('-d') &&
      seg.tokens.some((t) => t.includes('com.apple.quarantine')),
  },
  {
    rule: 'spctl-disable',
    action: 'deny',
    message:
      '`spctl --master-disable` / `--global-disable` disables Gatekeeper system-wide. Refuse.',
    match: (seg) =>
      seg.head === 'spctl' &&
      seg.flags.some(
        (f) => f === '--master-disable' || f === '--global-disable' || f === '--disable',
      ),
  },
  {
    rule: 'kextload',
    action: 'deny',
    message:
      'Loading a kernel extension (`kextload`, `kmutil load`) is a system-level mutation. Refuse — Sean handles this manually.',
    match: (seg) =>
      seg.head === 'kextload' ||
      seg.head === 'kextunload' ||
      (seg.head === 'kmutil' && (seg.tokens[1] === 'load' || seg.tokens[1] === 'unload')),
  },
  {
    rule: 'security-keychain-destructive',
    action: 'deny',
    message:
      '`security delete-keychain / delete-generic-password / delete-internet-password / set-keychain-settings` mutates your Keychain (where every CLI Sean wrote stores its secrets). Refuse — Sean owns Keychain.',
    match: (seg) =>
      seg.head === 'security' &&
      typeof seg.tokens[1] === 'string' &&
      [
        'delete-keychain',
        'delete-generic-password',
        'delete-internet-password',
        'delete-certificate',
        'delete-identity',
        'set-keychain-settings',
        'unlock-keychain',
        'lock-keychain',
        'create-keychain',
      ].includes(seg.tokens[1]),
  },
  {
    rule: 'security-keychain-add-write',
    action: 'ask',
    message:
      "`security add-generic-password / add-internet-password / add-certificate` writes to your Keychain. Sean's tools (`Bun.secrets`, agent-browser-profiles) manage their own entries — confirm this is the right path before adding anything else manually.",
    match: (seg) =>
      seg.head === 'security' &&
      typeof seg.tokens[1] === 'string' &&
      ['add-generic-password', 'add-internet-password', 'add-certificate'].includes(seg.tokens[1]),
  },
  {
    rule: 'systemsetup',
    action: 'deny',
    message:
      '`systemsetup -set...` writes machine-wide settings (timezone, sleep, network time, restart-on-power-failure). Refuse.',
    match: (seg) => seg.head === 'systemsetup' && seg.tokens.some((t) => t.startsWith('-set')),
  },
  {
    rule: 'scutil-set',
    action: 'deny',
    message:
      '`scutil --set` writes system configuration (computer name, hostname, LocalHostName). Refuse — read-only `scutil --get` is fine.',
    match: (seg) => seg.head === 'scutil' && seg.tokens.includes('--set'),
  },

  // ── package mutation: ask before installing/removing ──────────────────
  {
    rule: 'brew-mutation',
    action: 'ask',
    message:
      "`brew install/uninstall/upgrade/untap` modifies Sean's machine globally. Confirm before running.",
    match: (seg) =>
      seg.head === 'brew' &&
      typeof seg.tokens[1] === 'string' &&
      ['install', 'uninstall', 'upgrade', 'reinstall', 'untap', 'tap'].includes(seg.tokens[1]),
  },
  {
    rule: 'mas-mutation',
    action: 'ask',
    message: '`mas install/uninstall` changes installed Mac App Store apps. Confirm.',
    match: (seg) =>
      seg.head === 'mas' &&
      typeof seg.tokens[1] === 'string' &&
      ['install', 'uninstall', 'purchase'].includes(seg.tokens[1]),
  },

  // ── cloud destructive ────────────────────────────────────────────────
  {
    rule: 'gh-destructive',
    action: 'deny',
    message: 'gh repo/release/issue delete is destructive on shared state. Refuse.',
    match: (seg) =>
      seg.head === 'gh' &&
      typeof seg.tokens[1] === 'string' &&
      typeof seg.tokens[2] === 'string' &&
      ['repo', 'release', 'issue', 'pr'].includes(seg.tokens[1]) &&
      ['delete', 'destroy', 'remove'].includes(seg.tokens[2]),
  },
  {
    rule: 'flyctl-destroy',
    action: 'deny',
    message: 'flyctl apps destroy / volumes destroy nukes deployed infra. Refuse.',
    match: (seg) =>
      seg.head === 'flyctl' && seg.tokens.some((t) => t === 'destroy' || t === 'delete'),
  },
  {
    rule: 'gcloud-delete',
    action: 'deny',
    message: '`gcloud ... delete` affects cloud resources. Refuse.',
    match: (seg) => seg.head === 'gcloud' && seg.tokens.includes('delete'),
  },
];

const bashDeny = (segments: readonly Segment[], cmd: string): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-deny');
  }
  for (const seg of segments) {
    for (const s of SPECS) {
      if (s.match(seg, cmd)) {
        return s.action === 'deny' ? deny(s.rule, s.message) : ask(s.rule, s.message);
      }
    }
  }
  return allow('bash-deny');
};

export { bashDeny };
