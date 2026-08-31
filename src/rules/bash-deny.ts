import type { ShellInvocation, ShellProgram } from '../lib/bash';
import { type Decision, allow, ask, deny, merge } from '../lib/decision';
import { applyRuleAction, type RuleActions } from '../lib/rule-actions';
import { applyShellBypass } from './bash-bypass';

interface Spec {
  readonly rule: string;
  readonly action: 'deny' | 'ask';
  readonly message: string;
  // Match function evaluated against the parsed segment. Returns true when
  // The rule fires.
  readonly match: (seg: ShellInvocation, raw: string) => boolean;
}

const argsJoined = (seg: ShellInvocation): string => seg.tokens.slice(1).join(' ');

const flagPresent = (seg: ShellInvocation, ...flags: readonly string[]): boolean => {
  const segmentFlags = new Set(seg.flags);
  return flags.some((flag) => segmentFlags.has(flag));
};

const STATIC_SUBCOMMAND_DEPTH: ReadonlyMap<string, number> = new Map([
  ['launchctl', 1],
  ['defaults', 1],
  ['diskutil', 1],
  ['tmutil', 1],
  ['security', 1],
  ['brew', 1],
  ['mas', 1],
  ['kmutil', 1],
  ['gh', 2],
]);

const STATIC_POLICY_ARGUMENTS: ReadonlySet<string> = new Set([
  'dd',
  'kill',
  'chmod',
  'softwareupdate',
  'pmset',
  'dscl',
  'xattr',
  'spctl',
  'systemsetup',
  'scutil',
  'flyctl',
  'gcloud',
]);

const hasComputedPolicyDiscriminator = (seg: ShellInvocation): boolean => {
  if (seg.head === 'dd') {
    return seg.words
      .slice(1)
      .some((word) => word.kind === 'dynamic' && !word.source.startsWith('if='));
  }
  if (seg.head === 'rsync') {
    const separator = seg.words.findIndex((word) => word.value === '--');
    const optionEnd = separator === -1 ? seg.words.length : separator;
    return seg.words.slice(1, optionEnd).some((word) => word.kind === 'dynamic');
  }
  if (seg.head === 'gh' && seg.tokens[1] === 'api') {
    for (let index = 2; index < seg.words.length; index += 1) {
      const previous = seg.words[index - 1]?.value;
      const word = seg.words[index];
      if (
        word?.kind === 'dynamic' &&
        (previous === '--method' ||
          previous === '-X' ||
          word.source.startsWith('-X') ||
          word.source.startsWith('--method='))
      ) {
        return true;
      }
    }
    return false;
  }
  const depth = STATIC_SUBCOMMAND_DEPTH.get(seg.head);
  if (depth !== undefined) {
    return seg.words.slice(1, depth + 1).some((word) => word.kind === 'dynamic');
  }
  return (
    STATIC_POLICY_ARGUMENTS.has(seg.head) &&
    seg.words.slice(1).some((word) => word.kind === 'dynamic')
  );
};

const ghApiMethod = (seg: ShellInvocation): string | null => {
  if (seg.head !== 'gh' || seg.tokens[1] !== 'api') {
    return null;
  }
  for (let index = 2; index < seg.tokens.length; index += 1) {
    const token = seg.tokens[index];
    if (token === '--method' || token === '-X') {
      return seg.tokens[index + 1]?.toUpperCase() ?? '';
    }
    if (token?.startsWith('--method=') === true) {
      return token.slice('--method='.length).toUpperCase();
    }
    if (token?.startsWith('-X') === true && token.length > 2) {
      return token.slice(2).toUpperCase();
    }
  }
  return null;
};

const ghApiMutates = (seg: ShellInvocation): boolean => {
  if (seg.head !== 'gh' || seg.tokens[1] !== 'api') {
    return false;
  }
  const method = ghApiMethod(seg);
  if (method !== null && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return true;
  }
  return seg.flags.some(
    (flag) =>
      flag === '--input' ||
      flag.startsWith('--input=') ||
      flag === '-f' ||
      flag === '-F' ||
      flag === '--field' ||
      flag.startsWith('--field=') ||
      flag === '--raw-field' ||
      flag.startsWith('--raw-field='),
  );
};

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
      seg.tokens.some((t) => /^(?<home>~|\$HOME|\$\{HOME\})$/u.test(t)),
  },
  {
    rule: 'fork-bomb',
    action: 'deny',
    message: 'Fork bomb pattern detected. Refuse.',
    match: (_seg, raw) => /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;/u.test(raw),
  },
  {
    rule: 'source-script',
    action: 'deny',
    message:
      '`source` / `.` executes a file in the current shell. Refuse arbitrary sourced scripts.',
    match: (seg) => (seg.head === 'source' || seg.head === '.') && seg.tokens.length > 1,
  },
  {
    rule: 'dd-raw-device',
    action: 'deny',
    message: 'dd writing to a raw block device wipes the disk. Refuse.',
    match: (seg) =>
      seg.head === 'dd' && /\bof=\/dev\/(?<type>disk|sd|nvme|rdisk)/iu.test(argsJoined(seg)),
  },
  {
    rule: 'mkfs',
    action: 'deny',
    message: 'mkfs formats a filesystem. Refuse.',
    match: (seg) => /^mkfs(?<ext>\.[a-z0-9]+)?$/iu.test(seg.head),
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
    message: '--no-verify skips git hooks. Per policy: never skip hooks. Fix the underlying issue.',
    match: (seg) => seg.tokens.includes('--no-verify'),
  },
  {
    rule: 'no-gpg-sign',
    action: 'deny',
    message: 'Bypassing GPG signing is off-limits unless explicitly requested.',
    match: (_seg, raw) => /--no-gpg-sign\b|-c\s+commit\.gpgsign=false/u.test(raw),
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
    message:
      'shutdown / reboot / halt control the machine. Refuse — system control should be done manually.',
    match: (seg) => ['shutdown', 'reboot', 'halt', 'poweroff'].includes(seg.head),
  },
  {
    rule: 'launchctl-mutation',
    action: 'deny',
    message:
      'launchctl load/unload/bootstrap/bootout/kickstart mutates system services. Refuse — surface the intent instead.',
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
    message: '`defaults write` mutates macOS preferences. Refuse — surface the intent.',
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
      'osascript runs arbitrary AppleScript and can do almost anything (move files, send emails, drive apps). Confirm with the user what you want done before running it.',
    match: (seg) => seg.head === 'osascript',
  },
  {
    rule: 'topgrade',
    action: 'deny',
    message:
      'topgrade upgrades everything (brew, mas, npm globals, rust, mise). System upgrades should be done manually.',
    match: (seg) => seg.head === 'topgrade',
  },
  {
    rule: 'rsync-delete',
    action: 'deny',
    message:
      'rsync --delete removes files at the destination. High blast radius — surface the intent instead.',
    match: (seg) => seg.head === 'rsync' && seg.flags.includes('--delete'),
  },
  {
    rule: 'softwareupdate-install',
    action: 'deny',
    message:
      '`softwareupdate --install / -i / -d` triggers macOS system updates. Refuse — system updates should be done manually.',
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
      '`pmset` (with arguments) writes power-management settings. Read-only `pmset -g` is fine; mutations need the user.',
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
      'Loading a kernel extension (`kextload`, `kmutil load`) is a system-level mutation. Refuse — the user handles this manually.',
    match: (seg) =>
      seg.head === 'kextload' ||
      seg.head === 'kextunload' ||
      (seg.head === 'kmutil' && (seg.tokens[1] === 'load' || seg.tokens[1] === 'unload')),
  },
  {
    rule: 'security-keychain-destructive',
    action: 'deny',
    message:
      '`security delete-keychain / delete-generic-password / delete-internet-password / set-keychain-settings` mutates your Keychain (where CLIs store their secrets). Refuse — Keychain should be managed manually.',
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
      '`security add-generic-password / add-internet-password / add-certificate` writes to your Keychain. Other tools manage their own entries — confirm this is the right path before adding anything else manually.',
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
      '`brew install/uninstall/upgrade/untap` modifies the machine globally. Confirm before running.',
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
    rule: 'gh-api-mutation',
    action: 'deny',
    message:
      '`gh api` with a mutating HTTP method can change shared GitHub state and bypass Git workflow protections. Refuse the inline mutation.',
    match: ghApiMutates,
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

const bashDeny = (program: ShellProgram, ruleActions: RuleActions = {}): Decision => {
  // Collect the first matching spec per segment, then return the most
  // Restrictive across all of them. Returning the first match outright lets
  // A weaker `ask` on an early segment (e.g. the outer `sudo`) shadow a
  // `deny` on a later unwrapped segment (e.g. the interior `shutdown`).
  const hits: Decision[] = [];
  if (program.diagnostics.length > 0) {
    const reasons = [...new Set(program.diagnostics.map((diagnostic) => diagnostic.message))];
    const decision = deny(
      'unsupported-shell-structure',
      `Tripwire cannot inspect this shell program safely: ${reasons.join(' ')}`,
    );
    hits.push(applyShellBypass(program, decision));
  }
  for (const seg of program.invocations) {
    if (hasComputedPolicyDiscriminator(seg)) {
      const decision = deny(
        'unsupported-shell-structure',
        `Tripwire cannot classify computed policy arguments to \`${seg.head}\` safely.`,
      );
      hits.push(applyShellBypass(program, decision));
    } else {
      const spec = SPECS.find((candidate) => candidate.match(seg, program.source));
      if (spec !== undefined) {
        const decision =
          spec.action === 'deny' ? deny(spec.rule, spec.message) : ask(spec.rule, spec.message);
        hits.push(applyShellBypass(program, applyRuleAction(decision, ruleActions)));
      }
    }
  }
  return hits.length === 0 ? allow('bash-deny') : merge(hits);
};

export { bashDeny };
