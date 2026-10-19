import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { analyzeBash } from '../src/lib/bash';
import type { DecisionKind } from '../src/lib/decision';
import { bashGit } from '../src/rules/bash-git';

const gitDecision = (command: string) =>
  bashGit(analyzeBash(command, { cwd: '/work/example.git.feature' }), {
    protectedBranches: ['main', 'release'],
  });

const expectRule = (commands: readonly string[], kind: DecisionKind, rule: string): void => {
  for (const command of commands) {
    bunTest.expect(gitDecision(command).kind, command).toBe(kind);
    bunTest.expect(gitDecision(command).rule, command).toBe(rule);
  }
};

bunTest.describe('Git history safety invariants', () => {
  bunTest.test('keeps ordinary history work as workflow asks', () => {
    expectRule(['git cherry-pick a..b'], 'ask', 'git-cherry-pick');
    expectRule(
      [
        'git rebase --autosquash 1111111',
        'git rebase --strategy main 1111111',
        'git rebase -smain 1111111',
        'git rebase --strategy-option main 1111111',
        'git rebase -Xmain 1111111',
        'git rebase -C main 1111111',
        'git rebase -Cmain 1111111',
        'git rebase --whitespace main 1111111',
        'git rebase --empty main 1111111',
        'git rebase --trailer main 1111111',
        'git rebase --strategy-option -i 1111111',
        'git rebase -Skeyix 1111111',
        'git rebase -sstrategyix 1111111',
        'git -c rebase.interactive=true rebase 1111111',
      ],
      'ask',
      'git-rebase',
    );
  });

  bunTest.test(
    'asks for every accepted exec option spelling and instruction format override',
    () => {
      expectRule(
        [
          'git rebase --exec ./check.sh 1111111',
          'git rebase --exec=./check.sh 1111111',
          'git rebase -x ./check.sh 1111111',
          'git rebase -x./check.sh 1111111',
          'git rebase -qx./check.sh 1111111',
          'git rebase --ex=./check.sh 1111111',
          'git rebase --exe ./check.sh 1111111',
          "git rebase --exec 'rm -rf ~' 1111111",
          'git rebase -x-i 1111111',
          'git rebase --continue --exec ./check.sh',
          "git -c 'rebase.instructionFormat=%s%nexec echo fixture-marker' rebase 1111111",
          'FORMAT=%s; git --config-env=rebase.instructionFormat=FORMAT rebase 1111111',
        ],
        'ask',
        'git-rebase-exec',
      );
    },
  );

  bunTest.test('denies interactive flags including bundles and abbreviations', () => {
    expectRule(
      [
        'git rebase -i HEAD~3',
        'git rebase --interactive HEAD~3',
        'git rebase -qi HEAD~3',
        'git rebase --inter HEAD~3',
        'git rebase --continue -i',
        'GIT_EDITOR=vim git rebase -i HEAD~3',
      ],
      'deny',
      'git-rebase-interactive',
    );
  });

  bunTest.test('protects upstream, onto, and explicit branch operands after option values', () => {
    expectRule(
      [
        'git rebase main',
        'git rebase origin/main',
        'git rebase refs/heads/main',
        'git rebase --onto main a b',
        'git rebase --onto=origin/main a b',
        'git rebase --ont main a b',
        'git rebase --root --onto main',
        'git rebase --strategy recursive main',
        'git rebase --strategy=recursive origin/main',
        'git rebase -s recursive main',
        'git rebase -srecursive main',
        'git rebase -X ours main',
        'git rebase -Xours main',
        'git rebase -C 3 main',
        'git rebase -C3 main',
        'git rebase --whitespace fix main',
        'git rebase --empty drop main',
        'git rebase --trailer Signed-off-by=Example main',
        'git rebase -S main',
        'git rebase --gpg-sign main',
        'git rebase -r main',
        'git rebase --rebase-merges main',
        'git rebase 1111111 main',
        'git rebase --root main',
        'git rebase --root --no-ro 1111111 main',
        'git rebase -- main',
      ],
      'ask',
      'git-rebase-onto-protected',
    );
  });

  bunTest.test('asks for submitted editor, hook, and runtime configuration overrides', () => {
    expectRule(
      [
        'GIT_EDITOR=vim git rebase --continue',
        'GIT_SEQUENCE_EDITOR=./edit.sh git rebase 1111111',
        'env GIT_EDITOR=vim git rebase --continue',
        'GIT_EDITOR=vim command git rebase --continue',
        "GIT_EDITOR=vim bash -c 'git rebase --continue'",
        'export GIT_EDITOR=vim; git rebase --continue',
        'export GIT_EDITOR=$UNKNOWN; git rebase --continue',
        'declare -x GIT_EDITOR=vim; git rebase --continue',
        'typeset -x GIT_EDITOR=vim; git rebase --continue',
        'readonly GIT_EDITOR=vim; git rebase --continue',
        'declare -x -n GIT_EDITOR=EDITOR; git rebase --continue',
        'declare -x -i GIT_EDITOR=true; git rebase --continue',
        'f(){ local GIT_EDITOR=vim; git rebase --continue; }; f',
        "export 'GIT_EDITOR=vim'; git rebase --continue",
        'key=GIT_EDITOR; export "$key=vim"; git rebase --continue',
        'GIT_EDITOR=$UNKNOWN git rebase --continue',
        'GIT_EDITOR=vim; GIT_EDITOR+=true; git rebase --continue',
        'export GIT_EDITOR+=vim; git rebase --continue',
        'TASK_OVERRIDE=true; TASK_OVERRIDE=vim GIT_EDITOR=$TASK_OVERRIDE git rebase --continue',
        'export GIT_EDITOR=true; read GIT_EDITOR; git rebase --continue',
        'export GIT_EDITOR=true; read -r -p "editor prompt" GIT_EDITOR; git rebase --continue',
        'export GIT_EDITOR=true; printf -v GIT_EDITOR %s vim; git rebase --continue',
        'export GIT_EDITOR=true; printf -vGIT_EDITOR %s vim; git rebase --continue',
        'for item in 1; do export GIT_EDITOR=vim; done; git rebase --continue',
        'while condition; do export GIT_EDITOR=vim; done; git rebase --continue',
        'for ((item=0; item<1; item++)); do export GIT_EDITOR=vim; done; git rebase --continue',
        `export GIT_EDITOR=; : "\${GIT_EDITOR:=vim}"; git rebase --continue`,
        'export GIT_EDITOR=true; ((GIT_EDITOR=123)); git rebase --continue',
        'export GIT_EDITOR=true; let GIT_EDITOR=123; git rebase --continue',
        'export GIT_EDITOR=true; getopts a GIT_EDITOR -a; git rebase --continue',
        'export GIT_EDITOR=true; while condition; do git rebase --continue; export GIT_EDITOR=vim; done',
        'export GIT_EDITOR=true; FIRST=true; SECOND=true; THIRD=vim; while condition; do GIT_EDITOR=$FIRST git rebase --continue; FIRST=$SECOND; SECOND=$THIRD; done',
        'export GIT_EDITOR=true; while condition; do value=$(git rebase --continue); export GIT_EDITOR=vim; done',
        'if condition; then export GIT_EDITOR=vim; fi; git rebase --continue',
        'git -c core.editor=./edit.sh cherry-pick -e a',
        'git -ccore.editor=./edit.sh cherry-pick -e a',
        'git -c CORE.EDITOR=./edit.sh rebase --continue',
        'git -c sequence.editor=./edit.sh rebase 1111111',
        'git -c core.hooksPath=./hooks rebase 1111111',
        'OVERRIDE=vim git --config-env=core.editor=OVERRIDE rebase --continue',
        'OVERRIDE=vim git --config-env core.editor=OVERRIDE rebase --continue',
        'git --config-env=core.editor=UNKNOWN rebase --continue',
        'GIT_CONFIG_PARAMETERS="\'core.editor=vim\'" git rebase --continue',
        'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.editor GIT_CONFIG_VALUE_0=vim git rebase --continue',
        'VISUAL=vim git cherry-pick --edit a',
        'EDITOR=vim git cherry-pick --continue',
      ],
      'ask',
      'git-editor-override',
    );
  });

  bunTest.test(
    'allows safe no-op overrides and scopes command prefixes to their invocation',
    () => {
      expectRule(
        [
          'GIT_EDITOR=true git rebase --continue',
          'GIT_SEQUENCE_EDITOR=: GIT_EDITOR=true git rebase --continue',
          "GIT_EDITOR='' git rebase --continue",
          'GIT_EDITOR= GIT_SEQUENCE_EDITOR= git rebase --continue',
          'env GIT_EDITOR=true git rebase --continue',
          'export GIT_EDITOR=true; git rebase --continue',
          'declare -x GIT_EDITOR=true; git rebase --continue',
          'git -c core.editor=: -c sequence.editor=true rebase --continue',
          'OVERRIDE=true git --config-env=core.editor=OVERRIDE rebase --continue',
          'GIT_EDITOR=vim git status; git rebase --continue',
          'export GIT_EDITOR=vim; env -u GIT_EDITOR git rebase --continue',
          'export GIT_EDITOR=vim; env --unset=GIT_EDITOR git rebase --continue',
          'export GIT_EDITOR=vim; env -i git rebase --continue',
          'GIT_EDITOR=vim; unset GIT_EDITOR; git rebase --continue',
          'TASK_OVERRIDE=vim; TASK_OVERRIDE=true GIT_EDITOR=$TASK_OVERRIDE git rebase --continue',
          'if condition; then export GIT_EDITOR=true; else export GIT_EDITOR=true; fi; git rebase --continue',
          'export GIT_EDITOR=true; printf "%s" "-vGIT_EDITOR"; git rebase --continue',
          `export GIT_EDITOR=true; : "\${GIT_EDITOR:=vim}"; git rebase --continue`,
          `export GIT_EDITOR=; : "\${GIT_EDITOR=vim}"; git rebase --continue`,
          'while condition; do GIT_EDITOR=true git rebase --continue; export GIT_EDITOR=vim; done',
          'export GIT_EDITOR=true; let GIT_EDITOR=123; GIT_EDITOR=true git rebase --continue',
          'export GIT_EDITOR=true; let GIT_EDITOR=123; export GIT_EDITOR=:; git rebase --continue',
        ],
        'allow',
        'bash-git',
      );
    },
  );

  bunTest.test('snapshots bindings independently for direct and synthetic invocations', () => {
    const program = analyzeBash(
      'GIT_EDITOR=vim command git status; env GIT_EDITOR=true git status; git status',
      { cwd: '/work/example.git.feature' },
    );

    const invocations = program.invocations.filter((invocation) => invocation.head === 'git');
    bunTest
      .expect(invocations.map((invocation) => invocation.bindings.get('GIT_EDITOR')?.value))
      .toEqual(['vim', 'true', undefined]);
  });

  bunTest.test('fails closed on computed environment variable names', () => {
    for (const command of [
      'export "$UNKNOWN"; git rebase --continue',
      'read "$UNKNOWN"; git rebase --continue',
      'printf -v "$UNKNOWN" %s vim; git rebase --continue',
    ]) {
      const program = analyzeBash(command, { cwd: '/work/example.git.feature' });
      bunTest
        .expect(program.diagnostics, command)
        .toEqual([bunTest.expect.objectContaining({ kind: 'dynamic-shell-source' })]);
    }
  });

  bunTest.test('transient bindings do not swallow alias directory changes', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'example-git-history-'));

    try {
      mkdirSync(path.join(root, 'other'));

      const program = analyzeBash("alias enter='cd other'; GIT_EDITOR=true enter; git status", {
        cwd: root,
      });

      const invocation = program.invocations.find((value) => value.head === 'git');
      bunTest.expect(invocation?.cwd).toBe(path.join(root, 'other'));
      bunTest.expect(invocation?.bindings.has('GIT_EDITOR')).toBeFalse();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
