import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decide, decideBash } from '../src/dispatch';
import { analyzeBash } from '../src/lib/bash';

bunTest.test('tracked cwd reaches inline code, redirects, copies, and deletion', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'example-cwd-'));
  const safe = path.join(root, 'ordinary');
  const protectedDirectory = path.join(root, 'protected');
  try {
    mkdirSync(safe);
    mkdirSync(path.join(root, '~'));
    const home = path.join(root, 'fictional-home');
    mkdirSync(home);
    mkdirSync(protectedDirectory);
    writeFileSync(path.join(protectedDirectory, '.env'), 'example');
    symlinkSync('.env', path.join(protectedDirectory, 'output'));
    symlinkSync('/', path.join(protectedDirectory, 'dist'));
    const inspect = (command: string): string =>
      decide({
        hook_event_name: 'PreToolUse',
        tool_name: 'Bash',
        cwd: root,
        tool_input: { command },
      }).kind;
    for (const command of [
      'python3 -c \'open("output","w").write("example")\'',
      'echo example > output',
      'cp example output',
      'tee output',
    ]) {
      bunTest.expect(inspect(`cd ordinary && ${command}`)).toBe('allow');
      bunTest.expect(inspect(`cd protected && ${command}`)).toBe('deny');
      bunTest.expect(inspect(`(cd protected); cd ordinary; ${command}`)).toBe('allow');
      bunTest.expect(inspect(`cd "$DIR"; ${command}`)).toBe('deny');
    }
    bunTest.expect(inspect('cd protected; rm -rf dist')).toBe('allow');
    bunTest.expect(inspect('cd protected; rm -rf dist/')).toBe('deny');
    bunTest.expect(inspect('cd protected; rm -rf dist/etc')).toBe('deny');
    bunTest.expect(inspect('command cd protected; echo example > output')).toBe('deny');
    bunTest.expect(inspect('builtin cd protected; echo example > output')).toBe('deny');
    bunTest
      .expect(inspect("alias enter='cd protected'; enter; echo example > output"))
      .toBe('deny');
    bunTest.expect(inspect('CDPATH=protected cd ordinary; echo example > output')).toBe('deny');
    bunTest.expect(inspect('cd protected || cd ordinary; echo example > output')).toBe('deny');
    bunTest
      .expect(inspect('for x in 1 2; do cd protected; done; echo example > output'))
      .toBe('deny');
    bunTest.expect(inspect('cd /; tar -xf example.tar -C .')).toBe('deny');
    bunTest.expect(inspect('cd /; unzip example.zip -d .')).toBe('deny');
    bunTest.expect(inspect('cd ordinary; rm -rf dist')).toBe('allow');
    bunTest.expect(inspect('cd ordinary || exit; python3 -c \'open("output","w")\'')).toBe('allow');
    bunTest
      .expect(inspect('if test -f example; then cd protected; fi; echo example > output'))
      .toBe('deny');
    bunTest.expect(inspect('cd missing; python3 -c \'open("output","w")\'')).toBe('deny');
    bunTest.expect(inspect('pushd protected; popd; echo example > output')).toBe('allow');
    bunTest.expect(inspect('direnv exec protected tee output')).toBe('deny');
    bunTest.expect(inspect('mise -C protected exec -- tee output')).toBe('deny');
    const directories = analyzeBash(
      "cd '~'; printf literal; cd ~; printf home; cd ~/..; printf parent",
      { cwd: root, home },
    );
    bunTest
      .expect(
        directories.invocations
          .filter((invocation) => invocation.head === 'printf')
          .map((invocation) => invocation.cwd),
      )
      .toEqual([path.join(root, '~'), home, path.dirname(home)]);
    bunTest
      .expect(inspect('pushd ordinary; pushd ../protected; pushd; echo example > output'))
      .toBe('allow');
    bunTest
      .expect(
        inspect('pushd ordinary; pushd ../protected; pushd missing; popd; echo example > output'),
      )
      .toBe('deny');
    const program = analyzeBash('cd ordinary; (cd ..; printf inside); printf outside', {
      cwd: root,
    });
    bunTest
      .expect(
        program.invocations
          .filter((invocation) => invocation.head === 'printf')
          .map((invocation) => invocation.cwd),
      )
      .toEqual([root, safe]);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

const inspect = (command: string, cwd: string): string =>
  decide({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd, tool_input: { command } }).kind;

bunTest.test('relative deletion follows the resolved cwd and symlink target', () => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'example-delete-'));
  try {
    symlinkSync('/', path.join(cwd, 'escape'));
    for (const command of [
      'rm x.log',
      'python3 -c \'import os; os.remove("x.log")\'',
      'node -e \'require("fs").unlinkSync("x.log")\'',
    ]) {
      bunTest.expect(inspect(`cd /tmp && ${command}`, cwd)).toBe('allow');
      bunTest.expect(inspect(`cd / && ${command}`, cwd)).toBe('deny');
      bunTest.expect(inspect(`cd missing && ${command}`, cwd)).toBe('deny');
      bunTest.expect(inspect(`cd "$UNKNOWN" && ${command}`, cwd)).toBe('deny');
      bunTest.expect(inspect(command.replaceAll('x.log', 'escape/x.log'), cwd)).toBe('deny');
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});

bunTest.test('a safe cwd cannot authorize an unresolved shell operand', () => {
  bunTest.expect(inspect('cd /tmp; rm "$TARGET"', '/')).toBe('deny');
  bunTest.expect(inspect('cd /tmp; find "$TARGET" -delete', '/')).toBe('deny');
});

const fixtureRoot = realpathSync(mkdtempSync(path.join(tmpdir(), 'example-resolution-')));
const project = path.join(fixtureRoot, 'work/project');
const scratch = path.join(fixtureRoot, 'scratch/run-1');
const session = path.join(fixtureRoot, 'session');
mkdirSync(path.join(project, 'app'), { recursive: true });
mkdirSync(scratch, { recursive: true });
mkdirSync(session);
writeFileSync(path.join(project, 'package.json'), '{"name":"example-project"}');
writeFileSync(path.join(fixtureRoot, 'blocker'), 'example');

bunTest.afterAll(() => {
  rmSync(fixtureRoot, { recursive: true, force: true });
});

const decideIn = (
  command: string,
  cwd = session,
): { readonly kind: string; readonly rule: string } => {
  const { kind, rule } = decideBash(command, {}, { cwd });
  return { kind, rule };
};

// Default policy warns about some Git subcommands; a warning does not block the call.
const expectPermitted = (command: string): void => {
  bunTest.expect(['allow', 'warn']).toContain(decideIn(command).kind);
};

const invocationCwd = (command: string, head: string): (string | null)[] =>
  analyzeBash(command, { cwd: session })
    .invocations.filter((invocation) => invocation.head === head)
    .map((invocation) => invocation.cwd);

const unresolvedRedirect = { kind: 'deny', rule: 'redirect-dynamic-target' };

bunTest.describe('static assignments in && lists', () => {
  bunTest.test('keep their value after cd, as they do without it', () => {
    for (const command of [
      `S=${scratch}; git status > $S/a.txt`,
      `cd ${project} && S=${scratch} && git status > $S/a.txt`,
      `T=${scratch}/tool.mjs; node $T app/package.json`,
      `cd ${project} && T=${scratch}/tool.mjs; node $T app/package.json`,
      `S=${scratch}; git apply --numstat $S/fix.patch`,
      `cd ${project} && S=${scratch}; git apply --numstat $S/fix.patch`,
      `S=${scratch} && T=${scratch}/nested && echo example > $T/a.txt`,
      `cd ${project} && S=${scratch} && mkdir -p "$S" && git diff > "$S/index.diff"`,
    ]) {
      expectPermitted(command);
    }
    const [redirect] = analyzeBash(`cd ${project} && S=${scratch} && git status > $S/a.txt`, {
      cwd: session,
    }).redirects;
    bunTest.expect(redirect?.target.kind).toBe('literal');
    bunTest.expect(redirect?.target.value).toBe(`${scratch}/a.txt`);
    bunTest.expect(redirect?.cwd).toBe(project);
  });

  bunTest.test('stay unresolved when the list can stop before the assignment', () => {
    for (const command of [
      `false && S=${scratch}; echo example > $S/a.txt`,
      `cd ${project} || S=${scratch}; echo example > $S/a.txt`,
      `cd ${fixtureRoot}/missing && S=${scratch}; echo example > $S/a.txt`,
    ]) {
      bunTest.expect(decideIn(command)).toEqual(unresolvedRedirect);
    }
  });

  bunTest.test('keep command substitution values unresolved after cd', () => {
    for (const command of [
      'cd /work && S=$(pwd) && echo x > $S/a',
      `cd ${project} && S=$(git rev-parse --show-toplevel) && echo x > $S/a`,
    ]) {
      bunTest.expect(decideIn(command)).toEqual(unresolvedRedirect);
    }
  });

  bunTest.test('still apply the protected-path rule to the resolved value', () => {
    bunTest
      .expect(decideIn(`cd ${project} && S=${fixtureRoot}/profile/.ssh && echo x > $S/config`))
      .toEqual({ kind: 'deny', rule: 'redirect-ssh' });
    bunTest
      .expect(decideIn(`cd ${project} && S=${scratch}; echo x > $S/.env`))
      .toEqual({ kind: 'deny', rule: 'redirect-env' });
  });

  bunTest.test('pass a resolved cd only when && follows it', () => {
    bunTest
      .expect(invocationCwd(`cd ${project} && printf one; printf two`, 'printf'))
      .toEqual([project, project]);
    bunTest
      .expect(invocationCwd(`cd ${project} || printf one; printf two`, 'printf'))
      .toEqual([null, null]);
    bunTest.expect(invocationCwd(`true && cd ${project}; printf two`, 'printf')).toEqual([null]);
  });
});

bunTest.describe('directories made by mkdir -p in the same program', () => {
  bunTest.test('are known to a later cd and to paths under it', () => {
    for (const command of [
      `mkdir -p ${scratch}/newdir && cd ${scratch}/newdir && printf x > a.txt`,
      `mkdir -p ${scratch}/m && cd ${project} && cp package.json ${scratch}/m/p.json`,
      `cd ${project} && cp package.json ${scratch}/nonexist/p.json`,
      `mkdir -p -m 700 ${scratch}/a/b; cd ${scratch}/a && printf x > b/c.txt`,
      `cd ${scratch} && mkdir -pv relative/child && cd relative && printf x > a.txt`,
    ]) {
      expectPermitted(command);
    }
    bunTest
      .expect(
        invocationCwd(`mkdir -p ${scratch}/newdir && cd ${scratch}/newdir && printf x`, 'printf'),
      )
      .toEqual([`${scratch}/newdir`]);
  });

  bunTest.test('do not make other directories known', () => {
    for (const command of [
      `cd ${fixtureRoot}/missing && printf x > a.txt`,
      `mkdir -p ${scratch}/other && cd ${scratch}/missing && printf x > a.txt`,
      `mkdir ${scratch}/plain && cd ${scratch}/plain && printf x > a.txt`,
      `mkdir -p ${fixtureRoot}/blocker/sub && cd ${fixtureRoot}/blocker/sub && printf x > a.txt`,
      `mkdir -p "$UNKNOWN" ${scratch}/listed && cd ${scratch}/listed && printf x > a.txt`,
      `mkdir -p ${scratch}/up/../side && cd ${scratch}/side && printf x > a.txt`,
      `if test -f example; then mkdir -p ${scratch}/maybe; fi; cd ${scratch}/maybe && printf x > a.txt`,
      `(mkdir -p ${scratch}/inner); cd ${scratch}/inner && printf x > a.txt`,
    ]) {
      bunTest.expect(decideIn(command)).toEqual(unresolvedRedirect);
    }
  });

  bunTest.test('keep destructive and protected-path checks on the resolved target', () => {
    const fresh = 'mkdir -p /work/project/fresh && cd /work/project/fresh';
    bunTest
      .expect(decideIn(`${fresh} && rm -rf ../../shared`))
      .toEqual({ kind: 'deny', rule: 'destructive-outside-safe-paths' });
    bunTest
      .expect(decideIn(`${fresh} && rm -rf src`))
      .toEqual({ kind: 'deny', rule: 'destructive-outside-safe-paths' });
    bunTest.expect(decideIn(`${fresh} && rm -rf build`)).toEqual({ kind: 'allow', rule: 'none' });
    bunTest
      .expect(decideIn(`mkdir -p ${scratch}/keys && cd ${scratch}/keys && printf x > .env`))
      .toEqual({ kind: 'deny', rule: 'redirect-env' });
  });
});

bunTest.test('background statements keep their directory and variable changes', () => {
  bunTest
    .expect(decideIn('cd /tmp & rm -rf src', '/work/project'))
    .toEqual({ kind: 'deny', rule: 'destructive-outside-safe-paths' });
  for (const command of [
    `S=${scratch} & printf x > $S/a.txt`,
    `mkdir -p ${scratch}/bg & cd ${scratch}/bg && printf x > a.txt`,
  ]) {
    bunTest.expect(decideIn(command)).toEqual(unresolvedRedirect);
  }
  bunTest
    .expect(invocationCwd(`cd ${project} && printf one & printf two`, 'printf'))
    .toEqual([project, session]);
});
