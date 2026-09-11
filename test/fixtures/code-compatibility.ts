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
  ...[
    'python',
    'python3',
    'python3.13',
    'uv run --no-sync python',
    'uv run --no-sync python3',
    'uv run --locked --no-sync --python 3.13 python3',
    'uv run --no-sync --python=3.13 -- python3',
    'uv --offline run --no-sync -p 3.13 python',
    'env uv run --no-sync --no-python-downloads python3',
  ].map((command) => ({
    name: `Python launch form: ${command}`,
    source: 'Cross-product of observed Python/uv forms and interpreter selection boundary',
    allow: `${command} -c 'import json; print(json.loads("{}"))'`,
    block: `${command} -c 'import os; os.unlink("/protected")'`,
  })),
  {
    name: 'Python dictionary summary with an assertion and formatted output',
    source: 'Astra JSON summary pattern, reduced to inert fields and formatting',
    allow: python(
      'import json\nd=json.load(open("results.json"))\nassert "pass" in d\nsummary={"pass": d["pass"], "count": len(d)}\nprint(json.dumps(summary))\nprint(f"count: {len(d)}")',
    ),
    block: python('import os\nsummary={"pass": os.unlink("/protected")}\nprint(summary)'),
  },
  {
    name: 'file context managers read JSON without executing callbacks',
    source: 'Python JSON inspection pattern with a standard file context manager',
    allow: python('import json\nwith open("results.json") as f:\n print(json.load(f))'),
    block: python('with open(".env", "w") as f:\n f.write("")'),
  },
  {
    name: 'JavaScript iteration over JSON records',
    source: 'astra 2026-09-10 01a08c81-2e34-7052-8dcd-339f145401b1:561 (explicit JSON read)',
    allow: js(
      'const fs=require("fs"); const rows=JSON.parse(fs.readFileSync("results.json","utf8")); for (const row of rows) { console.log(row.message); }',
    ),
    block: js(
      'const fs=require("fs"); const rows=JSON.parse(fs.readFileSync("results.json","utf8")); for (const row of rows) { fs.rmSync(row.path); }',
    ),
  },
  {
    name: 'Python slice bounds are inspected for effects',
    source: 'astra 2026-09-08 01a07dc3-4685-7893-b3a3-a422b51a06bf:454 (preview boundary)',
    allow: python('from pathlib import Path\ns=Path("run.log").read_text()\nprint(s[0:2500])'),
    block: python(
      'from pathlib import Path\nimport os\ns=Path("run.log").read_text()\nprint(s[os.unlink("/protected"):2500])',
    ),
  },
  {
    name: 'regex redaction of a log followed by a bounded preview',
    source: 'astra 2026-09-08 01a07dc3-4685-7893-b3a3-a422b51a06bf:454',
    allow: python(
      'from pathlib import Path\nimport re\ns=Path("run.log").read_text()\ns=re.sub(r"(?:sk-|wk-|ws-)[A-Za-z0-9_-]+", "[redacted]", s)\nprint(s[:2500])',
    ),
    block: python(
      'from pathlib import Path\nimport re\np=Path(".env")\np.write_text(re.sub(r"[\\s\\S]*", "", p.read_text()))',
    ),
  },
  {
    name: 'regex replacement follows the destination policy',
    source: 'Astra regex-edit pattern, bounded to literal replacement text',
    allow: python(
      'from pathlib import Path\nimport re\np=Path("README.md")\np.write_text(re.sub(r"version: [0-9]+", "version: 2", p.read_text()))',
    ),
    block: python(
      'from pathlib import Path\nimport re\np=Path(".env")\np.write_text(re.sub(r"()[\\s\\S]*", r"\\1", p.read_text()))',
    ),
  },
  {
    name: 'TypeScript annotations do not hide effects',
    source: 'Astra JavaScript edit pattern expressed in the TypeScript REPL dialect',
    allow: `bun -e 'const fs = require("fs"); const p: string = "README.md"; fs.writeFileSync(p, fs.readFileSync(p,"utf8").replace("old","new"));'`,
    block: `bun -e 'const fs = require("fs"); const p: string = "/protected"; fs.rmSync(p);'`,
  },
  {
    name: 'read-modify-write follows the destination policy',
    source: 'astra 2026-09-11 01a08c81-2e34-7052-8dcd-339f145401b1:3493',
    allow: python(
      'from pathlib import Path\np=Path("README.md")\ns=p.read_text().replace("6,093 tests", "6,136 tests")\np.write_text(s)',
    ),
    block: python(
      'from pathlib import Path\np=Path(".env")\ns=p.read_text().replace(p.read_text(), "")\np.write_text(s)',
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
      'const fs = require("node:fs"); const p=".env"; fs.writeFileSync(p,fs.readFileSync(p,"utf8").replace("old", ""));',
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
