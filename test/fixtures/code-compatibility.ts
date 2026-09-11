interface CompatibilityPair {
  readonly name: string;
  readonly source: string;
  readonly allow: string;
  readonly block: string;
}

const python = (code: string): string => `python3 - <<'PY'\n${code}\nPY`;
const js = (code: string): string => `node - <<'JS'\n${code}\nJS`;

// Rollout references identify the source pattern. Paths and data are synthetic.
// Neither side of a pair is executable test code: the policy receives strings only.
const compatibilityPairs: readonly CompatibilityPair[] = [
  {
    name: 'read-modify-write preserves a nonempty file',
    source: 'astra 2026-09-11 01a08c81-2e34-7052-8dcd-339f145401b1:3493',
    allow: python(
      'from pathlib import Path\np=Path("README.md")\ns=p.read_text().replace("6,093 tests", "6,136 tests")\np.write_text(s)',
    ),
    block: python(
      'from pathlib import Path\np=Path("README.md")\ns=p.read_text().replace(p.read_text(), "")\np.write_text(s)',
    ),
  },
  {
    name: 'JSON stdin is inert data, not an executable path',
    source: 'fable 2026-09-08 c2b34c7d-56ef-4267-aff9-cc74086d2d06:255',
    allow: `cat package.json | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("dependencies"))'`,
    block: `cat package.json | python3 -c 'import sys,json,os; d=json.load(sys.stdin); os.unlink(d["target"])'`,
  },
  {
    name: 'JSON file access and nested indexing',
    source: 'astra 2026-09-09 01a071df-8e7e-7691-a3e3-24396d213683:54315',
    allow: python(
      'import json\nfrom pathlib import Path\nd=json.loads(Path("results.json").read_text())\nprint(d["metrics"]["pass"])',
    ),
    block: python(
      'import json\nfrom pathlib import Path\nd=json.loads(Path("results.json").read_text())\nPath(d["target"]).unlink()',
    ),
  },
  {
    name: 'loop over known file paths',
    source: 'astra 2026-09-08 01a071df-8e7e-7691-a3e3-24396d213683:48618 (reduced)',
    allow: python(
      'import json\nfrom pathlib import Path\nfor name in ["first.json", "last.json"]:\n print(json.loads(Path(name).read_text())["pass"])',
    ),
    block: python(
      'from pathlib import Path\nfor name in ["dist/first", "/protected"]:\n Path(name).unlink()',
    ),
  },
  {
    name: 'loop over JSON records',
    source: 'astra 2026-09-08 01a071df-8e7e-7691-a3e3-24396d213683:48618 (reduced)',
    allow: python(
      'import json\nrows=json.load(open("results.json"))\nfor row in rows:\n print(row["pass"])',
    ),
    block: python(
      'import json,os\nrows=json.load(open("results.json"))\nfor row in rows:\n os.unlink(row["path"])',
    ),
  },
  {
    name: 'both branches are checked',
    source: 'astra JSON summary pattern, adversarial branch pair',
    allow: python(
      'import json\nd=json.load(open("results.json"))\nif d.get("pass"):\n print("pass")\nelse:\n print("fail")',
    ),
    block: python(
      'import json,os\nd=json.load(open("results.json"))\nif d.get("pass"):\n print("pass")\nelse:\n os.unlink("/protected")',
    ),
  },
  {
    name: 'JSON comprehension and aggregate',
    source: 'astra 2026-09-09 01a071df-8e7e-7691-a3e3-24396d213683:54323 (reduced)',
    allow: python(
      'import json\nrows=json.load(open("results.json"))\nprint(sum(row["pass"] for row in rows))',
    ),
    block: python(
      'import json,os\nrows=json.load(open("results.json"))\nprint([os.unlink("/protected") for row in rows])',
    ),
  },
  {
    name: 'JS reads preserve string operations',
    source: 'Astra file inspection/edit pattern, JavaScript equivalent',
    allow: js(
      'const fs = require("node:fs"); const p="README.md"; const s=fs.readFileSync(p,"utf8").replace("old", "new"); fs.writeFileSync(p,s);',
    ),
    block: js(
      'const fs = require("node:fs"); const p="README.md"; fs.writeFileSync(p,fs.readFileSync(p,"utf8").replace("old", ""));',
    ),
  },
  {
    name: 'JS JSON member access',
    source: 'astra 2026-09-10 01a08bd4-109e-7d20-a7d2-a0014cc3f7ff:447 (explicit read)',
    allow: js(
      'const fs=require("fs"); const d=JSON.parse(fs.readFileSync("package.json","utf8")); console.log(d.scripts);',
    ),
    block: js(
      'const fs=require("fs"); const d=JSON.parse(fs.readFileSync("package.json","utf8")); fs.rmSync(d.target);',
    ),
  },
  {
    name: 'JS JSON data cannot become a callable',
    source: 'Adversarial counterpart to plain JSON property access',
    allow: js('const d=JSON.parse("{}"); console.log(d["name"]);'),
    block: js('const d=JSON.parse("{}"); d["constructor"]("return process")();'),
  },
  {
    name: 'escaped text and triple-quoted replacement',
    source: 'fable 2026-09-08 c2b34c7d-56ef-4267-aff9-cc74086d2d06:4563 (reduced)',
    allow: python(
      'from pathlib import Path\np=Path("README.md")\np.write_text(p.read_text().replace("old\\n", """new\ntext"""))',
    ),
    block: python('import os\nos.unlink("/protec\\x74ed")'),
  },
  {
    name: 'import aliases retain destructive meaning',
    source: 'Common multi-import form from Astra and Fable rollouts',
    allow: python('import json as j, math as m\nprint(j.loads("{}"))'),
    block: python('from os import unlink as discard, path as paths\ndiscard("/protected")'),
  },
  {
    name: 'project checks versus inline eval',
    source: 'astra 2026-09-10 01a08bd4-109e-7d20-a7d2-a0014cc3f7ff:287',
    allow: 'bun run typecheck; bun run lint',
    block: 'bun run --eval \'require("fs").rmSync("/protected")\'',
  },
  {
    name: 'uv pytest owns its test file argument',
    source: 'fable 2026-09-09 d23299e2-9ff1-42f0-a5ee-3c0fba0cdabe:1256',
    allow: 'uv run --locked pytest -q tests/test_example.py -k caught_once',
    block: 'uv run --locked python -c \'import os; os.unlink("/protected")\'',
  },
  {
    name: 'uv explicit Python without environment synchronization',
    source: 'Astra uv heredoc pattern, constrained to an existing environment',
    allow: 'uv run --no-sync python3 -c \'print("hello")\'',
    block: 'uv run --no-sync python3 -c \'import os; os.unlink("/protected")\'',
  },
  {
    name: 'uv stdin without an explicit interpreter',
    source: 'Regression for 523156b; stdin is always source',
    allow: 'uv run --no-sync - <<\'PY\'\nprint("hello")\nPY',
    block: 'uv run --no-sync - <<\'PY\'\nimport os; os.unlink("/protected")\nPY',
  },
  {
    name: 'uv command must still obey shell deletion policy',
    source: 'Adversarial wrapper counterpart',
    allow: 'uv run --no-sync printf hello',
    block: 'uv run --no-sync rm -rf /protected',
  },
];

export { compatibilityPairs };
