import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash, type Config } from '../src';
import type { RuleAction } from '../src/lib/rule-actions';
import { parseJsonRecord, recordField } from './support/json';

const git = { protectedBranches: ['main'] };
const configured: Config = {
  git,
  ruleActions: { 'git-cherry-pick': 'allow', 'git-rebase': 'allow' },
};
const policies: readonly Config[] = [{ git }, configured];
const options = { cwd: '/work/example.git.feature' };

bunTest.describe('configurable Git history workflow', () => {
  bunTest.test.each([
    ['git cherry-pick a..b', 'git-cherry-pick'],
    ['git rebase --autosquash 1111111', 'git-rebase'],
  ])('%s defaults to ask', (command, rule) => {
    bunTest.expect(decideBash(command, { git }, options)).toMatchObject({ kind: 'ask', rule });
  });

  bunTest.test.each([
    'git cherry-pick a..b',
    'git rebase --autosquash 1111111',
    'git -C /work/example.git.feature cherry-pick a..b',
    'git -C /work/example.git.feature rebase --autosquash 1111111',
    'GIT_EDITOR=true git cherry-pick -e a',
    'GIT_SEQUENCE_EDITOR=true git -C /work/example.git.feature rebase --autosquash 1111111',
    'GIT_EDITOR=: GIT_SEQUENCE_EDITOR= git rebase --autosquash 1111111',
    'git -c core.editor=true -c sequence.editor=: -c core.hooksPath= cherry-pick --edit a',
  ])('allows configured workflow: %s', (command) => {
    bunTest.expect(decideBash(command, configured, options).kind).toBe('allow');
  });

  bunTest.test.each<RuleAction>(['allow', 'warn', 'ask', 'deny'])(
    'applies the %s action to ordinary history operations',
    (action) => {
      for (const command of ['git cherry-pick a..b', 'git rebase --autosquash 1111111']) {
        const config: Config = { ruleActions: { 'git-cherry-pick': action, 'git-rebase': action } };
        bunTest.expect(decideBash(command, config, options).kind).toBe(action);
      }
    },
  );

  for (const policy of policies) {
    bunTest.describe(
      policy.ruleActions === undefined ? 'default policy' : 'configured allows',
      () => {
        bunTest.test.each([
          'git rebase main',
          'git rebase origin/main',
          'git rebase --onto main a b',
          'git rebase --onto=origin/main a b',
          'git rebase --root --onto main',
          'git rebase --strategy recursive --strategy-option ours origin/main',
          'git rebase ordinary-base main',
          'git rebase --root main',
        ])('preserves protected targets: %s', (command) => {
          bunTest
            .expect(decideBash(command, policy, options))
            .toMatchObject({ kind: 'ask', rule: 'git-rebase-onto-protected' });
        });

        bunTest.test.each(['git rebase -i HEAD~3', 'git rebase --interactive HEAD~3'])(
          'denies interactive history: %s',
          (command) => {
            bunTest
              .expect(decideBash(command, policy, options))
              .toMatchObject({ kind: 'deny', rule: 'git-rebase-interactive' });
          },
        );

        bunTest.test.each([
          'git rebase --exec ./check.sh 1111111',
          'git rebase -x ./check.sh 1111111',
          'git rebase --exec=./check.sh 1111111',
          "git rebase --exec 'rm -rf ~' 1111111",
          "git -c 'rebase.instructionFormat=%s%nexec ./check.sh' rebase --autosquash 1111111",
        ])('requires approval for uninspected exec: %s', (command) => {
          bunTest
            .expect(decideBash(command, policy, options))
            .toMatchObject({ kind: 'ask', rule: 'git-rebase-exec' });
        });

        bunTest.test.each([
          'GIT_EDITOR=vim git rebase --continue',
          'GIT_SEQUENCE_EDITOR=./x.sh git rebase --autosquash 1111111',
          'git -c core.editor=./x.sh cherry-pick -e a',
          'git -c sequence.editor=./x.sh rebase --continue',
          'git -c core.hooksPath=./hooks cherry-pick a',
          'GIT_EDITOR=./x.sh git cherry-pick --continue',
          'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.editor GIT_CONFIG_VALUE_0=./x.sh git rebase --continue',
        ])('requires approval for execution overrides: %s', (command) => {
          bunTest
            .expect(decideBash(command, policy, options))
            .toMatchObject({ kind: 'ask', rule: 'git-editor-override' });
        });

        bunTest.test.each([
          'git rebase --update-refs --onto ordinary-base 1111111',
          'git rebase --upd --onto ordinary-base 1111111',
          'git rebase --no-update-refs --update-refs 1111111',
          'git -c rebase.updateRefs=true rebase 1111111',
          'git -c rebase.updateRefs=YES rebase 1111111',
          'git -c rebase.updateRefs=1 rebase 1111111',
          'git -c rebase.updateRefs rebase 1111111',
          'UPDATE_REFS=true git --config-env=rebase.updateRefs=UPDATE_REFS rebase 1111111',
          'UPDATE_REFS=true git --config-env rebase.updateRefs=UPDATE_REFS rebase 1111111',
          'git --config-env=rebase.updateRefs=UNRESOLVED_REFS rebase 1111111',
        ])('requires approval for additional branch updates: %s', (command) => {
          bunTest
            .expect(decideBash(command, policy, options))
            .toMatchObject({ kind: 'ask', rule: 'git-rebase-update-refs' });
        });

        bunTest.test.each([
          'git rebase --update-refs --no-update-refs 1111111',
          'git rebase --update-refs --no-upd 1111111',
          'git -c rebase.updateRefs=true rebase --no-update-refs 1111111',
          'git -c rebase.updateRefs=false rebase 1111111',
          'git -c rebase.updateRefs=NO rebase 1111111',
          'git -c rebase.updateRefs=0 rebase 1111111',
          'git -c rebase.updateRefs=off rebase 1111111',
          'git -c rebase.updateRefs=true -c rebase.updateRefs=false rebase 1111111',
          'UPDATE_REFS=false git --config-env=rebase.updateRefs=UPDATE_REFS rebase 1111111',
        ])('uses workflow policy when additional branch updates are disabled: %s', (command) => {
          const decision = decideBash(command, policy, options);
          bunTest.expect(decision.kind).toBe(policy.ruleActions === undefined ? 'ask' : 'allow');
          if (policy.ruleActions === undefined) {
            bunTest.expect(decision.rule).toBe('git-rebase');
          }
        });
      },
    );
  }

  bunTest.test('an allowed cherry-pick does not skip a later protected push', () => {
    bunTest
      .expect(decideBash('git cherry-pick a..b; git push origin main', configured, options))
      .toMatchObject({ kind: 'deny', rule: 'git-push-protected' });
  });

  bunTest.test.each([
    ['git push origin main', 'deny', 'git-push-protected'],
    ['git rebase --exec ./check.sh 1111111', 'ask', 'git-rebase-exec'],
    ['git rebase -i HEAD~3', 'deny', 'git-rebase-interactive'],
    ['git rebase --update-refs 1111111', 'ask', 'git-rebase-update-refs'],
  ])('a configured warning does not hide later safety checks: %s', (later, kind, rule) => {
    const policy: Config = { git, ruleActions: { 'git-cherry-pick': 'warn' } };
    bunTest
      .expect(decideBash(`git cherry-pick a..b; ${later}`, policy, options))
      .toMatchObject({ kind, rule });
  });

  bunTest.test('retains a configured warning after later allowed invocations', () => {
    bunTest
      .expect(
        decideBash(
          'git cherry-pick a..b; git status',
          { ruleActions: { 'git-cherry-pick': 'warn' } },
          options,
        ),
      )
      .toMatchObject({ kind: 'warn', rule: 'git-cherry-pick' });
  });

  bunTest.test('a nested execution carrier receives the same workflow configuration', () => {
    bunTest
      .expect(decideBash("ssh example-host 'git cherry-pick a..b'", configured, options).kind)
      .toBe('allow');
    bunTest
      .expect(decideBash("ssh example-host 'git rebase origin/main'", configured, options))
      .toMatchObject({ kind: 'ask', rule: 'git-rebase-onto-protected' });
  });
});

bunTest.test(
  'source tripwire test matches unit decisions without running submitted commands',
  () => {
    const home = mkdtempSync(path.join(tmpdir(), 'tripwire-history-cli-'));
    try {
      const configDirectory = path.join(home, '.config', 'tripwire');
      mkdirSync(configDirectory, { recursive: true });
      for (const policy of policies) {
        writeFileSync(path.join(configDirectory, 'config.json'), JSON.stringify(policy));
        for (const command of [
          'git -C /work/example.git.feature cherry-pick 1111111..2222222',
          'GIT_SEQUENCE_EDITOR=true git -C /work/example.git.feature rebase --autosquash 1111111',
          'git rebase origin/main',
          'git rebase -i HEAD~3',
          'git rebase --exec ./scripts/check.sh 1111111',
          'git rebase --update-refs --onto ordinary-base 1111111',
        ]) {
          const decision = decideBash(command, policy, options);
          const result = Bun.spawnSync(
            [
              process.execPath,
              new URL('../src/main.ts', import.meta.url).pathname,
              'test',
              command,
            ],
            {
              env: { ...process.env, HOME: home },
              cwd: home,
              stderr: 'pipe',
              stdout: 'pipe',
              timeout: 10_000,
            },
          );
          bunTest.expect(result.exitCode).toBe(0);
          bunTest.expect(result.stderr.toString()).toBe('');
          const output = parseJsonRecord(result.stdout.toString());
          if (decision.kind === 'allow') {
            bunTest.expect(output).toEqual({ continue: true });
          } else {
            const hook = recordField(output, 'hookSpecificOutput');
            bunTest.expect(hook?.['permissionDecision']).toBe(decision.kind);
            bunTest
              .expect(hook?.['permissionDecisionReason'])
              .toContain(`[tripwire:${decision.rule}]`);
          }
        }
      }
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  },
  30_000,
);
