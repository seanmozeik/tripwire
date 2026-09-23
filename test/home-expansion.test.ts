import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { analyzeBash } from '../src/lib/bash';
import { bashDeny } from '../src/rules/bash-deny';
import { bashRedirect } from '../src/rules/bash-redirect';
import { bashScopedRm } from '../src/rules/bash-scoped-rm';
import { bashTarExplosion } from '../src/rules/bash-tar-explosion';

const home = '/tripwire-home-fixture';
const inspect = (command: string): string =>
  bashRedirect(analyzeBash(command, { home, cwd: '/tmp' })).kind;

bunTest.test.each([
  'cp /tmp/x ~/Downloads/x',
  'mv /tmp/a.txt ~/dev/example/',
  'cp -r dist ~/backup/',
  'ln -s /tmp/x ~/example-link',
  'rsync -a dist/ ~/backup/',
  'HOME=/tmp/example; cp x ~/y',
  'export HOME=/tmp/example; cp x ~/y',
  'export HOME; cp x ~/y',
  'cp x "~/literal"',
  'HOME=/tmp/example cp x ~/y',
])('allows a resolved home operand: %s', (command) => {
  bunTest.expect(inspect(command)).toBe('allow');
});

bunTest.test.each([
  'mv /tmp/source ~/.ssh',
  'cp /tmp/x ~/.ssh/',
  'cp /tmp/x ~/.aws/credentials',
  'HOME=/tmp/example/.ssh cp x ~/y',
  'HOME=$X cp x ~/.ssh/',
  'export HOME=$X; mv a ~/b',
  'unset HOME; cp x ~/y',
  'export "$X"; cp x ~/y',
  'printf -v HOME %s "$X"; cp x ~/y',
  'declare -n ref=HOME; ref=$X; cp x ~/y',
  'env "HOME=/tmp/.ssh" sh -c \'cp x ~/y\'',
  'command unset HOME; cp x ~/y',
  "alias clearhome='unset HOME'; clearhome; cp x ~/y",
  'env HOME="$X" sh -c \'cp x ~/y\'',
  'source settings.sh; cp x ~/y',
  '. settings.sh; cp x ~/y',
  'eval "$code"; cp x ~/y',
  'f() { HOME=$X; }; f; cp x ~/y',
  "alias transfer='cp x ~/y'; HOME=$X transfer",
  'if test -f x; then HOME=$X; fi; cp x ~/y',
  'for x in a b; do cp x ~/y; HOME=$X; done',
  'while test -f x; do cp x ~/y; HOME=$X; done',
  "env HOME=/tmp/example/.ssh sh -c 'cp x ~/y'",
  "env -u HOME sh -c 'cp x ~/y'",
  "env -i sh -c 'cp x ~/y'",
  "dotenv sh -c 'cp x ~/y'",
  'cp x ~another/y',
  'echo x > ~/.ssh/key',
  'HOME=$X; echo x > ~/y',
])('denies protected or unknown home operands: %s', (command) => {
  bunTest.expect(inspect(command)).toBe('deny');
});

bunTest.test('home expansion is shared by transfer, rm, redirect and cd operands', () => {
  const program = analyzeBash('cp x ~/backup/; rm ~/backup/x; echo x > ~/out; cd ~', { home });
  bunTest.expect(program.invocations[0]?.words.at(-1)?.value).toBe(`${home}/backup/`);
  bunTest.expect(program.invocations[1]?.words.at(-1)?.value).toBe(`${home}/backup/x`);
  bunTest.expect(program.redirects[0]?.target.value).toBe(`${home}/out`);
  bunTest.expect(program.invocations.at(-1)?.words.at(-1)?.value).toBe(home);
  bunTest.expect(bashScopedRm(analyzeBash('HOME=$X; rm ~/x', { home }), {}).kind).toBe('deny');
});

bunTest.test('resolved home retains catastrophic deletion and extraction protection', () => {
  bunTest
    .expect(bashDeny(analyzeBash('rm -rf ~ # tripwire-allow: fixture', { home })).kind)
    .toBe('deny');
  bunTest.expect(bashTarExplosion(analyzeBash('tar -xf a.tar -C ~', { home })).kind).toBe('deny');
});

bunTest.test('assigned home resolves symlink destinations and cd uses the same home', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'tripwire-home-fixture-'));
  try {
    mkdirSync(path.join(directory, '.ssh'));
    symlinkSync('.ssh', path.join(directory, 'alias'));
    bunTest.expect(inspect(`HOME=${directory}/alias cp x ~/y`)).toBe('deny');
    const program = analyzeBash('cd ~; cp x y', { home: directory, cwd: '/' });
    bunTest.expect(program.invocations.at(-1)?.cwd).toBe(directory);
    const unknown = analyzeBash('unset HOME; cd; cp x y', { home: directory, cwd: '/' });
    bunTest.expect(unknown.invocations.at(-1)?.cwd).toBeNull();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
