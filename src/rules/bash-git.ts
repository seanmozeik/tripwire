import { type Segment, hasBypass, unwrapStaticString } from '../lib/bash';
import type { GitConfig } from '../lib/config';
import { type Decision, allow, ask, deny, warn } from '../lib/decision';

// Smart git policy. Replaces blanket git handling with intent-based decisions:
//
//   - Read-only ops (status, log, diff, show, blame, fetch, etc.) — silent allow.
//   - Working-tree-destroying ops (reset --hard, clean -fd, checkout .,
//     Restore <path>) — deny with concrete safer alternative.
//   - History-rewriting ops (rebase -i, filter-branch, filter-repo,
//     Commit --amend, gc --prune=now, reflog expire, update-ref) — deny.
//   - Branch destruction (branch -D, branch -d on protected, push --delete,
//     Push :branch) — deny.
//   - Direct push to protected branches (main / master / develop /
//     Production / release) — deny, route to PR.
//   - Force push (--force / -f / --force-with-lease) — deny everywhere.
//   - Commits — allow ONLY with Conventional Commits format on the first
//     `-m` value. Auto-stage (-a / --all / -am) — ask. Editor mode (no -m
//     And no -F) — deny (would hang the agent).
//   - Rebase / cherry-pick / merge — ask (creates conflicts).
//   - Config — allow read; deny write to --global / --system; deny local
//     Write (Sean's identity / workflow).
//
// `git -C <dir>`, `git --git-dir=<path>`, `git --work-tree=<path>`,
// `git -c key=value` are stripped before subcommand dispatch — `git -C ../foo
// Reset --hard` is handled the same as `git reset --hard`.

const DEFAULT_PROTECTED_BRANCHES: readonly string[] = [
  'main',
  'master',
  'develop',
  'production',
  'release',
];

const getProtectedBranches = (config: GitConfig): readonly string[] =>
  config.protectedBranches ?? DEFAULT_PROTECTED_BRANCHES;

// Conventional Commits 1.0.0 — type(scope)?(!)?: description
const CONVENTIONAL_RE =
  /^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([\w./\- ]+\))?!?:\s+\S/;

const PRE_SUB_FLAG_TAKES_VALUE: ReadonlySet<string> = new Set([
  '-C',
  '-c',
  '--git-dir',
  '--work-tree',
  '--namespace',
  '--super-prefix',
]);

const PRE_SUB_FLAG_NO_VALUE: ReadonlySet<string> = new Set([
  '--bare',
  '--paginate',
  '-p',
  '--no-pager',
  '--no-replace-objects',
  '--literal-pathspecs',
  '--glob-pathspecs',
  '--noglob-pathspecs',
  '--icase-pathspecs',
  '--no-optional-locks',
  '--exec-path',
  '--html-path',
  '--man-path',
  '--info-path',
]);

interface GitInvocation {
  readonly subcommand: string;
  readonly subArgs: readonly string[];
}

const parseGit = (seg: Segment): GitInvocation | null => {
  if (seg.head !== 'git') {
    return null;
  }
  const toks = seg.tokens.slice(1);
  let i = 0;
  while (i < toks.length) {
    const t = toks[i]!;
    if (PRE_SUB_FLAG_TAKES_VALUE.has(t)) {
      i += 2;
      continue;
    }
    if (PRE_SUB_FLAG_NO_VALUE.has(t)) {
      i++;
      continue;
    }
    if (
      t.startsWith('--git-dir=') ||
      t.startsWith('--work-tree=') ||
      t.startsWith('--namespace=') ||
      t.startsWith('--super-prefix=') ||
      t.startsWith('--exec-path=')
    ) {
      i++;
      continue;
    }
    if (t.startsWith('-')) {
      // Unknown pre-subcommand flag; assume no value, advance.
      i++;
      continue;
    }
    return { subcommand: t, subArgs: toks.slice(i + 1) };
  }
  return null;
};

const messageOf = (subArgs: readonly string[]): string | null => {
  for (let i = 0; i < subArgs.length; i++) {
    const t = subArgs[i]!;
    if (t === '-m' || t === '--message') {
      const raw = subArgs[i + 1];
      return raw === undefined ? null : unwrapStaticString(raw);
    }
    if (t.startsWith('--message=')) {
      return unwrapStaticString(t.slice('--message='.length));
    }
    // Combined short flags like `-am`, `-ma`, `-amS` carry the message
    // In the next positional arg — same as `-m` alone.
    if (/^-[a-zA-Z]*m[a-zA-Z]*$/.test(t)) {
      const raw = subArgs[i + 1];
      return raw === undefined ? null : unwrapStaticString(raw);
    }
  }
  return null;
};

const protectedBranchHit = (positional: readonly string[], config: GitConfig): string | null => {
  const branches = getProtectedBranches(config);
  for (const arg of positional) {
    for (const p of branches) {
      if (arg === p || arg.endsWith(`:${p}`) || arg.endsWith(`/${p}`)) {
        return p;
      }
    }
  }
  return null;
};

const positionalOf = (subArgs: readonly string[]): string[] =>
  subArgs.filter((a) => !a.startsWith('-'));

const flagsOf = (subArgs: readonly string[]): string[] => subArgs.filter((a) => a.startsWith('-'));

const has = (subArgs: readonly string[], ...needles: readonly string[]): boolean =>
  needles.some((n) => subArgs.includes(n));

interface HandlerCtx {
  readonly subcommand: string;
  readonly subArgs: readonly string[];
  readonly flags: readonly string[];
  readonly positional: readonly string[];
  readonly config: GitConfig;
}

type Handler = (ctx: HandlerCtx) => Decision;

const handleConfig: Handler = ({ subArgs, positional }) => {
  if (has(subArgs, '--global', '--system')) {
    return deny(
      'git-config-global',
      'Modifying global / system git config is off-limits — that is your personal identity. Read-only `git config --get` is fine.',
    );
  }
  const isRead = has(subArgs, '--get', '-l', '--list', '--get-all', '--get-regexp');
  if (!isRead && positional.length >= 2) {
    return deny(
      'git-config-write',
      'Local git config writes should be done explicitly. To read a value, use `git config --get <key>`.',
    );
  }
  return allow('bash-git');
};

const handleRm: Handler = ({ subArgs }) => {
  if (has(subArgs, '--cached')) {
    return allow('bash-git');
  }
  return ask(
    'git-rm',
    '`git rm <path>` removes from the index AND the working tree. To untrack-only, use `git rm --cached <path>`. To delete the file separately, use `trash` / `rip`. Confirm intent.',
  );
};

const handleRestore: Handler = ({ subArgs, positional }) => {
  const stagedOnly = has(subArgs, '--staged', '-S') && !has(subArgs, '--worktree', '-W');
  if (stagedOnly) {
    return allow('bash-git');
  }
  if (positional.length > 0) {
    return deny(
      'git-restore-discard',
      '`git restore <path>` discards uncommitted changes in the working tree. Refuse — `git diff <path>` to inspect first, or `git stash push <path>` to preserve.',
    );
  }
  return allow('bash-git');
};

const handleCheckout: Handler = ({ subArgs, positional }) => {
  if (has(subArgs, '-b', '-B')) {
    return allow('bash-git');
  }
  if (has(subArgs, '-f', '--force')) {
    return deny(
      'git-checkout-force',
      '`git checkout -f` overwrites the working tree without preserving uncommitted changes. Refuse.',
    );
  }
  if (subArgs.includes('--')) {
    return deny(
      'git-checkout-discard',
      '`git checkout -- <path>` discards uncommitted working-tree changes. Refuse — use `git stash push <path>` to preserve, or `git diff <path>` to inspect first.',
    );
  }
  if (positional.length === 1 && (positional[0] === '.' || positional[0]!.startsWith('./'))) {
    return deny(
      'git-checkout-discard-all',
      '`git checkout .` discards ALL uncommitted working-tree changes. Refuse — `git stash` to preserve, or `git diff` to inspect first.',
    );
  }
  return allow('bash-git');
};

const handleSwitch: Handler = ({ subArgs }) => {
  if (has(subArgs, '-f', '--force', '--discard-changes')) {
    return deny(
      'git-switch-force',
      '`git switch -f / --discard-changes` throws away uncommitted working-tree changes. Refuse.',
    );
  }
  return allow('bash-git');
};

const handleReset: Handler = ({ subArgs, flags, positional }) => {
  if (has(subArgs, '--hard')) {
    return deny(
      'git-reset-hard',
      '`git reset --hard` discards all uncommitted changes AND moves HEAD. Refuse — describe the intent in chat. If undoing a published commit, `git revert <sha>` is safer.',
    );
  }
  if (has(subArgs, '--keep')) {
    return ask(
      'git-reset-keep',
      '`git reset --keep` resets HEAD but preserves uncommitted local changes. Confirm intent.',
    );
  }
  if (positional.length === 0 && flags.length === 0) {
    return allow('bash-git');
  }
  return ask(
    'git-reset-mixed',
    '`git reset` moves HEAD. Confirm intent — if undoing a commit, `git revert` is usually safer.',
  );
};

const handleClean: Handler = ({ flags }) => {
  if (flags.some((f) => /^-[a-zA-Z]*[df]/.test(f) || f === '--force')) {
    return deny(
      'git-clean-fd',
      '`git clean -fd` deletes untracked files (often your in-progress work). Refuse — inspect with `git clean -dn` (dry run) first. If genuinely needed, append ` # tripwire-allow: <reason>`.',
    );
  }
  return allow('bash-git');
};

const handleRebase: Handler = ({ subArgs, positional, config }) => {
  if (has(subArgs, '--abort', '--quit', '--continue', '--skip', '--edit-todo')) {
    return allow('bash-git');
  }
  if (has(subArgs, '-i', '--interactive')) {
    return deny(
      'git-rebase-interactive',
      '`git rebase -i` rewrites history interactively. Refuse — too easy to lose commits in the agent loop. If this is genuinely required, do it manually outside the agent.',
    );
  }
  const onto = positional[0];
  const branches = getProtectedBranches(config);
  if (onto !== undefined && branches.includes(onto)) {
    return ask(
      'git-rebase-onto-protected',
      `Rebasing onto \`${onto}\` rewrites history of the current branch. \`git merge ${onto}\` is usually safer. Confirm intent.`,
    );
  }
  return ask(
    'git-rebase',
    '`git rebase` rewrites commit history. `git merge` is usually safer. Confirm intent.',
  );
};

const handleCherryPick: Handler = ({ subArgs }) => {
  if (has(subArgs, '--abort', '--quit', '--continue', '--skip')) {
    return allow('bash-git');
  }
  return ask(
    'git-cherry-pick',
    '`git cherry-pick` applies commits onto the current branch and can create conflicts. Confirm intent.',
  );
};

const handleMerge: Handler = ({ subArgs }) => {
  if (has(subArgs, '--abort', '--continue', '--quit')) {
    return allow('bash-git');
  }
  return ask('git-merge', '`git merge <branch>` may create merge conflicts. Confirm intent.');
};

const handleCommit: Handler = ({ subArgs, config }) => {
  if (has(subArgs, '--amend')) {
    return deny(
      'git-commit-amend',
      '`git commit --amend` rewrites the last commit. If it has been pushed, this causes upstream divergence. Refuse — surface the intent.',
    );
  }
  const msg = messageOf(subArgs);
  const hasFile = has(subArgs, '-F', '--file', '-c', '-C', '--reuse-message', '--reedit-message');
  const hasNoEdit = has(subArgs, '--no-edit');
  if (msg === null && !hasFile && !hasNoEdit) {
    return deny(
      'git-commit-no-message',
      '`git commit` without `-m "..."` opens an editor and hangs the agent. Use `git commit -m "<conventional message>"`.',
    );
  }
  if (msg !== null && config.enforceConventionalCommits !== false && !CONVENTIONAL_RE.test(msg)) {
    return deny(
      'git-commit-non-conventional',
      [
        'Commit message must follow Conventional Commits format:',
        '  `<type>(<scope>)?(!)?: <description>`',
        'Allowed types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert.',
        'Examples:',
        '  `fix(auth): handle expired token refresh`',
        '  `feat: add bash-git rule`',
        '  `chore: bump deps`',
        `Got: ${JSON.stringify(msg)}`,
      ].join('\n'),
    );
  }
  if (has(subArgs, '-a', '--all') || subArgs.some((t) => /^-[a-zA-Z]*a[a-zA-Z]*$/.test(t))) {
    return ask(
      'git-commit-auto-stage',
      '`git commit -a / --all` auto-stages every tracked change. Explicit `git add <files>` first is usually clearer about what is being committed. Confirm.',
    );
  }
  return allow('bash-git');
};

const handlePush: Handler = ({ subArgs, flags, positional, config }) => {
  if (flags.some((f) => f === '--force' || f === '-f' || f.startsWith('--force-with-lease'))) {
    return deny(
      'git-force-push',
      'Force push is forbidden. If a branch needs to be reset upstream, surface the intent — there is almost always a non-force path.',
    );
  }
  if (has(subArgs, '--delete', '--mirror') || subArgs.some((a) => a.startsWith(':'))) {
    return deny(
      'git-push-delete',
      'Refusing to delete a remote branch via push. If genuinely needed, surface the intent.',
    );
  }
  const hit = protectedBranchHit(positional, config);
  if (hit !== null) {
    return deny(
      'git-push-protected',
      `Refusing to push directly to protected branch \`${hit}\`. Open a PR instead: \`gh pr create\`.`,
    );
  }
  return allow('bash-git');
};

const handleBranch: Handler = ({ subArgs, flags, positional, config }) => {
  const deleteFlag = flags.find(
    (f) =>
      f === '-D' ||
      f === '-d' ||
      f === '--delete' ||
      /^-[a-zA-Z]*D/.test(f) ||
      /^-[a-zA-Z]*d/.test(f),
  );
  if (deleteFlag !== undefined) {
    const targets = positional;
    const branches = getProtectedBranches(config);
    const hit = targets.find((t) => branches.includes(t));
    if (hit !== undefined) {
      return deny('git-branch-delete-protected', `Refusing to delete protected branch \`${hit}\`.`);
    }
    if (deleteFlag === '-D' || deleteFlag.includes('D')) {
      return deny(
        'git-branch-force-delete',
        `\`git branch -D ${targets.join(' ')}\` force-deletes branches even if unmerged (potential data loss). To delete a merged branch, use \`-d\`. To force, append \` # tripwire-allow: <reason>\`.`,
      );
    }
    return ask(
      'git-branch-delete',
      `\`git branch -d ${targets.join(' ')}\` deletes a branch (merged-only check). Confirm intent.`,
    );
  }
  if (has(subArgs, '-m', '-M', '--move')) {
    return ask('git-branch-move', 'Renaming a branch can confuse pushed remotes. Confirm intent.');
  }
  return allow('bash-git');
};

const handleTag: Handler = ({ subArgs }) => {
  if (has(subArgs, '-d', '--delete')) {
    return deny('git-tag-delete', '`git tag -d` deletes a tag. Refuse — surface intent.');
  }
  return allow('bash-git');
};

const handleStash: Handler = ({ subArgs }) => {
  const sub = subArgs[0] ?? 'push';
  if (sub === 'drop' || sub === 'clear') {
    return deny(
      'git-stash-drop',
      `\`git stash ${sub}\` discards stashed work. Refuse — \`git stash list\` and \`git stash show\` to inspect first.`,
    );
  }
  return allow('bash-git');
};

const handleGc: Handler = ({ flags }) => {
  if (flags.some((f) => f.startsWith('--prune=') || f === '--aggressive')) {
    return deny(
      'git-gc-prune',
      '`git gc --prune=now` / `--aggressive` destroys reflog recovery options. Refuse.',
    );
  }
  return allow('bash-git');
};

const handleRemote: Handler = ({ subArgs }) => {
  const sub = subArgs[0];
  if (sub === 'add' || sub === 'remove' || sub === 'rm' || sub === 'set-url' || sub === 'rename') {
    return ask(
      'git-remote-mutate',
      `\`git remote ${sub}\` changes which remote you're pushing to. Confirm — accidentally pointing at the wrong remote is high blast-radius.`,
    );
  }
  return allow('bash-git');
};

const handleSubmoduleOrWorktree: Handler = ({ subcommand, subArgs }) => {
  const sub = subArgs[0] ?? '';
  const mutating = ['add', 'remove', 'rm', 'deinit', 'sync', 'set-url'].includes(sub);
  if (mutating) {
    return ask(
      'git-submodule-worktree-mutate',
      `\`git ${subcommand} ${sub}\` modifies repo structure. Confirm intent.`,
    );
  }
  return allow('bash-git');
};

const HANDLERS: ReadonlyMap<string, Handler> = new Map<string, Handler>([
  ['config', handleConfig],
  ['add', () => allow('bash-git')],
  ['mv', () => allow('bash-git')],
  ['rm', handleRm],
  ['restore', handleRestore],
  ['checkout', handleCheckout],
  ['switch', handleSwitch],
  ['reset', handleReset],
  ['clean', handleClean],
  ['rebase', handleRebase],
  ['cherry-pick', handleCherryPick],
  ['merge', handleMerge],
  ['commit', handleCommit],
  ['push', handlePush],
  ['branch', handleBranch],
  ['tag', handleTag],
  ['stash', handleStash],
  [
    'filter-branch',
    ({ subcommand }) =>
      deny('git-filter', `\`git ${subcommand}\` rewrites entire repo history. Refuse.`),
  ],
  [
    'filter-repo',
    ({ subcommand }) =>
      deny('git-filter', `\`git ${subcommand}\` rewrites entire repo history. Refuse.`),
  ],
  ['gc', handleGc],
  [
    'update-ref',
    () =>
      deny(
        'git-update-ref',
        '`git update-ref` directly mutates refs and bypasses normal git operations. Refuse.',
      ),
  ],
  ['remote', handleRemote],
  ['submodule', handleSubmoduleOrWorktree],
  ['worktree', handleSubmoduleOrWorktree],
  [
    'init',
    ({ subcommand }) =>
      warn(
        `git-${subcommand}`,
        `\`git ${subcommand}\` is allowed but unusual mid-session. Make sure this is what Sean asked for.`,
      ),
  ],
  [
    'clone',
    ({ subcommand }) =>
      warn(
        `git-${subcommand}`,
        `\`git ${subcommand}\` is allowed but unusual mid-session. Make sure this is what Sean asked for.`,
      ),
  ],
]);

const evalGit = (inv: GitInvocation, config: GitConfig): Decision | null => {
  const { subcommand, subArgs } = inv;
  const flags = flagsOf(subArgs);
  const positional = positionalOf(subArgs);

  // ── read-only / inspection ───────────────────────────────────────────
  const READ_ONLY: ReadonlySet<string> = new Set([
    'status',
    'diff',
    'log',
    'show',
    'blame',
    'rev-parse',
    'rev-list',
    'ls-files',
    'ls-tree',
    'cat-file',
    'reflog',
    'describe',
    'shortlog',
    'whatchanged',
    'archive',
    'bundle',
    'fsck',
    'fetch',
    'ls-remote',
    'help',
    'version',
    'grep',
    'name-rev',
    'merge-base',
    'symbolic-ref',
    'check-ignore',
    'count-objects',
    'verify-commit',
    'verify-tag',
  ]);
  if (READ_ONLY.has(subcommand)) {
    if (subcommand === 'reflog' && (subArgs[0] === 'expire' || has(subArgs, '--expire'))) {
      return deny(
        'git-reflog-expire',
        "`git reflog expire` destroys git's recovery history. Refuse — surface the intent.",
      );
    }
    if (subcommand === 'symbolic-ref' && positional.length >= 2) {
      return deny(
        'git-symbolic-ref-write',
        '`git symbolic-ref <name> <ref>` rewrites a symbolic ref. Refuse.',
      );
    }
    return allow('bash-git');
  }

  const handler = HANDLERS.get(subcommand);
  if (handler !== undefined) {
    return handler({ subcommand, subArgs, flags, positional, config });
  }
  return warn(
    'git-unknown-subcommand',
    `\`git ${subcommand}\` is not classified by tripwire. Allowing — flag if this looks like history-rewriting or data-loss territory.`,
  );
};

const bashGit = (segments: readonly Segment[], cmd: string, config: GitConfig): Decision => {
  if (hasBypass(cmd)) {
    return allow('bash-git');
  }
  for (const seg of segments) {
    const inv = parseGit(seg);
    if (inv === null) {
      continue;
    }
    const d = evalGit(inv, config);
    if (d !== null && d.kind !== 'allow') {
      return d;
    }
  }
  return allow('bash-git');
};

export { bashGit };
