import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decide, decideBash } from '../src/dispatch';
import { analyzeCode } from '../src/lib/code/analyze';

const python = (source: string): string => `python3 - <<'PY'\n${source}\nPY`;
const javascript = (source: string): string => `node - <<'JS'\n${source}\nJS`;

bunTest.describe('adversarial review regressions (policy-only)', () => {
  bunTest.test.each([
    python('import os\nos.unlink(os.path.join("/tmp", "/protected"))'),
    python('from pathlib import Path\n(Path("/tmp") / "/protected").unlink()'),
    python('import fs'),
    javascript('require("os")'),
    javascript('require("fs").readFileSync("/protected", {flag:"w"})'),
    javascript('require("fs").readFileSync("/protected", {flag:512})'),
    javascript('const {rmSync: del} = require("fs"); del("/protected")'),
    javascript('const {rmSync: del = unknown()} = require("fs"); del("/protected")'),
    javascript('require("fs").writeFileSync(1, "x")'),
    javascript('require("fs").writeFileSync(".ssh/id_rsa", "x")'),
    python('open("README.md", "r", 1, 2, 3, unknown_opener)'),
    python('import os\nos.removedirs("dist/a")'),
    python('import os\nos.chdir("/protected")\nos.unlink("dist/a")'),
    `cd /protected; ${python('import os\nos.unlink("dist/a")')}`,
    `cd /protected; ${javascript('require("fs").rmSync("dist/a")')}`,
    'python3 -c "print(1)" extra-argument',
    'node -e "console.log(1)" --require ./uninspected.js',
    'python3 - <<< "$CODE"',
    'node - < source.js',
    'python3 - <<PY\nprint("$(uninspected)")\nPY',
    'node - <<JS\nconsole.log(`uninspected`)\nJS',
    `python3 -c '${'('.repeat(100)}1${')'.repeat(100)}'`,
    python(`s="x"\n${'s=s+s\n'.repeat(100)}`),
    javascript(`let s="x"; ${'s=s+s;'.repeat(100)}`),
    javascript('require("fs").writeFileSync("/protected", "x", "hex")'),
    javascript('require("fs").writeFileSync("/protected", "x", {encoding:"base64"})'),
    'NODE_OPTIONS="--require ./payload.js" node -e "console.log(1)"',
    'env NODE_OPTIONS="--require ./payload.js" node -e "console.log(1)"',
    'export PYTHONPATH=/untrusted; python3 -c "print(1)"',
    "ssh host node -e 'console.log(1)'",
    'uv run python3 -c \'import os; os.unlink("/protected")\'',
    'uv run --script cleanup.py',
    'poetry run python3 -c \'import os; os.unlink("/protected")\'',
    'pipenv run python3 -c \'import os; os.unlink("/protected")\'',
    'npx tsx -e \'require("fs").rmSync("/protected")\'',
    'timeout 5 node -e \'require("fs").rmSync("/protected")\'',
    'sudo python3 -c \'import os; os.unlink("/protected")\'',
    'nice node -e \'require("fs").rmSync("/protected")\'',
    'command /usr/bin/python3 -c \'import os; os.unlink("/protected")\'',
    'python3.14t -c \'import os; os.unlink("/protected")\'',
  ])('blocks %s', (command) => {
    bunTest.expect(decideBash(command).kind).toBe('deny');
  });

  bunTest.test.each([
    python('import os\nos.unlink("/tmp/tripwire-review-fixture")'),
    javascript('require("fs").rmSync("/tmp/tripwire-review-fixture")'),
    javascript('const {rmSync: del} = require("fs"); del("dist/fixture")'),
    javascript('require("fs").readFileSync("README.md", {flag:"r", encoding:"utf8"})'),
    python('print(open("README.md").read())'),
    'python3 - <<< \'print("safe")\'',
    'node --eval=\'console.log("safe")\'',
    'python3 -c\'print("safe")\'',
  ])('allows %s', (command) => {
    bunTest.expect(decideBash(command).kind).toBe('allow');
  });

  bunTest.test('resolved JS aliases retain the deletion and source range', () => {
    const source = 'const {rmSync: del} = require("fs"); del("/protected")';
    const report = analyzeCode('javascript', source);
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(report.operations)
      .toEqual([{ kind: 'delete', path: '/protected', range: { start: 37, end: source.length } }]);
  });

  bunTest.test('symlink escape blocks and leaves the sentinel unchanged', () => {
    const root = mkdtempSync(path.join(tmpdir(), 'tripwire-symlink-review-'));
    try {
      mkdirSync(path.join(root, 'kept'));
      const sentinel = path.join(root, 'kept', 'sentinel');
      writeFileSync(sentinel, 'unchanged');
      symlinkSync(path.join(root, 'kept'), path.join(root, 'dist'));
      const decision = decideBash(
        javascript('require("fs").rmSync("dist/sentinel")'),
        {},
        { cwd: root },
      );
      bunTest.expect(decision.kind).toBe('deny');
      bunTest.expect(readFileSync(sentinel, 'utf8')).toBe('unchanged');
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  bunTest.test.each(['js_repl', 'python_repl', 'functions.js_repl'])(
    'blocks unverified persistent state in %s',
    (tool_name) => {
      bunTest
        .expect(
          decide({ hook_event_name: 'PreToolUse', tool_name, tool_input: { code: 'print(1)' } })
            .kind,
        )
        .toBe('deny');
    },
  );
});
