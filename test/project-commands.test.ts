import * as bunTest from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash } from '../src/dispatch';
import { analyzeBash } from '../src/lib/bash';
import { projectCommandFixtures } from './fixtures/project-commands';

bunTest.describe('project command classification (commands are never executed)', () => {
  for (const fixture of projectCommandFixtures) {
    bunTest.test(fixture.name, () => {
      const result = decideBash(fixture.command, {}, { cwd: '/tripwire-policy-fixture' });
      bunTest.expect(result.kind, result.message).toBe(fixture.allowed ? 'allow' : 'deny');
    });
  }
  bunTest.test('command lookup emits no executable operand', () => {
    const result = analyzeBash('command -v node python3 pnpm', { cwd: '/tripwire-policy-fixture' });
    bunTest.expect(result.invocations.map((invocation) => invocation.head)).toEqual(['command']);
  });
  bunTest.test('Bun scripts do not depend on the selected package manifest', () => {
    const cwd = mkdtempSync(path.join(tmpdir(), 'tripwire-project-command-'));
    try {
      mkdirSync(path.join(cwd, 'server'));
      writeFileSync(
        path.join(cwd, 'server/package.json'),
        JSON.stringify({
          scripts: { 'generate:database-types': 'inert fixture', 'qa:release': 'inert fixture' },
        }),
      );
      for (const command of [
        'bun --cwd server --cwd missing run qa:release',
        'bun run --cwd server --preload ./payload.js qa:release',
        'bun -F server --preload ./payload.js run qa:release',
        'bun run --shell',
        'bun --cwd server run generate:database-types',
        'bun run --cwd server generate:database-types',
        'bun --cwd=server run qa:release',
        'bun run --cwd=server qa:release -- --filter data',
        'bun run generate:database-types',
        'bun observe',
        'bun --cwd missing observe --eval "argument data"',
        'bun --cwd server run verify-source-file-line-budget',
        'bun --cwd missing run generate:database-types',
        'cd server && bun run qa:release',
        'NODE_OPTIONS="--import ./payload.js" bun --cwd server run qa:release',
        'env -C /unverified bun --cwd server run qa:release',
        'env --chdir=/unverified bun --cwd server run qa:release',
        'bun run qa:release --eval "argument data"',
        'bun run qa:release -p "argument data"',
        'bun run --silent qa:release',
        'bun --filter server run qa:release',
        'bun -F server run qa:release',
        'bun -b run qa:release',
        'bun run --workspaces qa:release',
        'bun run --parallel --no-exit-on-error qa:release qa:other',
        'bun run --sequential qa:release qa:other',
        'bun --filter server --elide-lines 20 run qa:release',
        'bun run --shell=bun qa:release',
      ]) {
        const result = decideBash(command, {}, { cwd });
        bunTest.expect(result.kind, `${command}: ${result.message}`).toBe('allow');
      }
      for (const command of [
        'bun --cwd server run qa:release; rm -rf /protected',
        'bun -e \'require("fs").unlinkSync("/protected")\'',
        'bun -p \'require("fs").unlinkSync("/protected")\'',
        'bun run -e \'require("fs").unlinkSync("/protected")\'',
        'bun exec "rm -rf /protected"',
        'bun run --parallel -e \'require("fs").unlinkSync("/protected")\'',
      ]) {
        bunTest.expect(decideBash(command, {}, { cwd }).kind, command).toBe('deny');
      }
      bunTest
        .expect(
          decideBash('bun run generate:database-types', {}, { cwd: path.join(cwd, 'server') }).kind,
        )
        .toBe('allow');
      writeFileSync(path.join(cwd, 'server/package.json'), '{invalid');
      bunTest.expect(decideBash('bun --cwd server run qa:release', {}, { cwd }).kind).toBe('allow');
      for (const manifest of [
        { scripts: ['inert fixture'] },
        { scripts: { 'qa:release': null } },
        { scripts: { 'qa:release': '' } },
        { scripts: { 'qa:release': '   ' } },
      ]) {
        writeFileSync(path.join(cwd, 'server/package.json'), JSON.stringify(manifest));
        bunTest
          .expect(decideBash('bun --cwd server run qa:release', {}, { cwd }).kind)
          .toBe('allow');
      }
      writeFileSync(path.join(cwd, 'server/package.json'), ' '.repeat(1_048_577));
      bunTest.expect(decideBash('bun --cwd server run qa:release', {}, { cwd }).kind).toBe('allow');
      writeFileSync(path.join(cwd, 'server/package.json'), new Uint8Array([255]));
      bunTest.expect(decideBash('bun --cwd server run qa:release', {}, { cwd }).kind).toBe('allow');
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
});
