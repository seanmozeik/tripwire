import type { ShellProgram } from '../lib/bash';
import { type Decision, allow } from '../lib/decision';

const NON_BYPASSABLE_RULES: ReadonlySet<string> = new Set([
  'unsupported-shell-structure',
  'source-script',
  'rm-rf-root',
  'rm-rf-home',
  'fork-bomb',
  'dd-raw-device',
  'mkfs',
  'kill-all',
  'diskutil-destructive',
  'tmutil-destructive',
  'shutdown',
  'csrutil',
  'nvram',
  'kextload',
  'spctl-disable',
  'xattr-quarantine-bypass',
  'topgrade',
  'softwareupdate-install',
  'systemsetup',
  'scutil-set',
  'security-keychain-destructive',
  'no-verify',
  'no-gpg-sign',
  'curl-pipe-shell',
  'gh-api-mutation',
  'gh-destructive',
  'flyctl-destroy',
  'gcloud-delete',
  'git-dynamic-subcommand',
  'git-dynamic-mutation',
  'git-restore-discard',
  'git-checkout-force',
  'git-checkout-discard',
  'git-checkout-discard-all',
  'git-switch-force',
  'git-reset-hard',
  'git-force-push',
  'git-filter',
  'git-update-ref',
  'git-reflog-expire',
  'git-symbolic-ref-write',
]);

const applyShellBypass = (program: ShellProgram, decision: Decision): Decision => {
  if (!program.hasBypass || decision.kind === 'allow' || NON_BYPASSABLE_RULES.has(decision.rule)) {
    return decision;
  }
  return allow(decision.rule);
};

export { applyShellBypass, NON_BYPASSABLE_RULES };
