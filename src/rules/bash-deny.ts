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

  // ── git: Sean handles it himself ──────────────────────────────────────
  {
    rule: 'git-force-push',
    action: 'deny',
    message: 'Sean handles git himself. tripwire never force-pushes. Stop and explain in chat.',
    match: (seg) =>
      seg.head === 'git' &&
      seg.tokens[1] === 'push' &&
      seg.flags.some((f) => f === '--force' || f === '-f' || f.startsWith('--force-with-lease')),
  },
  {
    rule: 'git-reset-hard',
    action: 'deny',
    message:
      'git reset --hard discards uncommitted work. Sean handles git; describe intent in chat.',
    match: (seg) =>
      seg.head === 'git' && seg.tokens[1] === 'reset' && seg.tokens.includes('--hard'),
  },
  {
    rule: 'git-clean',
    action: 'deny',
    message: "git clean -fd deletes untracked files (often Sean's in-progress work). Refuse.",
    match: (seg) =>
      seg.head === 'git' && seg.tokens[1] === 'clean' && seg.flags.some((f) => /[df]/.test(f)),
  },
  {
    rule: 'git-config-global',
    action: 'deny',
    message:
      "Modifying global / system git config is off-limits — that is Sean's personal identity. Read-only `git config --get` is fine.",
    match: (seg) =>
      seg.head === 'git' &&
      seg.tokens[1] === 'config' &&
      seg.tokens.some((t) => t === '--global' || t === '--system') &&
      !seg.tokens.includes('--get') &&
      !seg.tokens.includes('-l') &&
      !seg.tokens.includes('--list'),
  },
  {
    rule: 'git-mutation',
    action: 'deny',
    message:
      'Sean handles all git mutations himself (per CLAUDE.md). Read-only git is fine: status, diff, log, show, blame.',
    match: (seg) =>
      seg.head === 'git' &&
      typeof seg.tokens[1] === 'string' &&
      [
        'commit',
        'push',
        'stash',
        'checkout',
        'reset',
        'rebase',
        'merge',
        'cherry-pick',
        'rm',
        'mv',
        'tag',
        'branch',
        'am',
        'pull',
        'restore',
        'switch',
        'worktree',
      ].includes(seg.tokens[1]),
  },

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
