import * as bunTest from 'bun:test';

import { analyzeCode } from '../../src/lib/code/analyze';
import type { CodeLanguage } from '../../src/lib/code/types';

const javascript = [
  'console.log(new Set([1,2]).size,new Map().set("x",1).get("x"),new URL("https://example.com").hostname,Math.PI,Buffer.from("example").toString("utf8"))',

  'console.log(["example"].filter(x=>/example/.test(x)).join(","))',
  'console.log("example".replace(/example/g,"other"))',
  'const fs=require("fs"); [1].forEach(x=>fs.writeFileSync("example","data"))',
  'let x=1; {let x=2; console.log(x)} console.log(x)',

  'console.log(JSON.stringify({x:1}, null, 2))',
  'console.log(new Date(1).toISOString(), Date.now())',
  'console.log([1,2].map(x => x*2).filter(Boolean))',
  'console.log([1,2].reduce((a,x)=>a+x,0))',
  'const r=JSON.parse("{}"); console.log(r.diagnostics?.map(x=>x))',
  'const fs=require("fs"); const d=JSON.parse(fs.readFileSync("package.json","utf8")); console.log(Object.keys(d).map(k=>k.toUpperCase()))',
  'const fs=require("fs"); console.log(fs.readdirSync("src").length)',
  'const p=JSON.parse("{}"); for(const [k,v] of Object.entries(p.scripts)) { console.log(k,v) }',
  'try { console.log(1) } catch(e) { console.log(e) }',
  'console.log(Object.keys(process.env))',
  'console.log(require("crypto").createHash("sha256").update("example").digest("hex"))',
  `const x=1; console.log(\`example \${x}\`, x ? 1 : 2, !x, -x, typeof x, /x/g)`,
  'const x=[1]; console.log([...x]); const y={a:1}; console.log({...y})',
  'function outer(x) { return y => x+y; } const f=outer(1); console.log(f(2))',
  'console.log(Array.from([1,2], x=>x*2))',
  'console.log(JSON.stringify({x:1}, (k,v)=>v))',
];
const python = [
  'xs=[1,2]\nxs.sort(key=lambda x:-x)\nprint(xs)',

  'import datetime\nprint(datetime.datetime.fromtimestamp(1,datetime.timezone.utc).isoformat(timespec="milliseconds"))',
  'import re\nprint(re.sub("a",lambda m:m.group(0),"aaa"))',
  'import sys\nsys.stdout.write("example")',
  's="example"\nif True:\n s=s.replace("example","other")\nopen("example","w").write(s)',

  'import datetime, time, platform, math, re, os, sys\nprint(datetime.datetime.now().isoformat(), time.time(), platform.system(), math.sqrt(4), os.getcwd(), sys.version)',
  'import json\ns=json.loads("{}")\nprint(s.replace("a","b"),s.startswith("a"),s.endswith("b"),s.strip(),s.rstrip())',
  'import json\nd=json.loads("{}")\nprint({k:v for k,v in d.items()})\nprint({x for x in d})\nprint(sum(x for x in d))\nfor k,v in d.items():\n print(k,v)',
  'print(1 in [1], 2 not in [1])',
  'def f(x=2):\n return x\nprint(f(), (lambda x: -x)(2))',
  'try:\n print(1)\nexcept Exception as e:\n print(e)\nfinally:\n print(2)',
  'raise SystemExit(1)',
  'x=0\nwhile x<3:\n x+=1\nprint(x)',
  'd={}\nd["k"]=2\nxs=[]\nxs.append(2)\nprint(d,xs)',
  'from pathlib import Path\nprint(Path("example").stat().st_size, Path("example").is_symlink())\nprint(Path("example").with_name("other").read_text())',
  'import sys\nprint("example", file=sys.stderr)',
  'x=1\nprint(f"{x:.2f}")',
  'import re\nprint(re.sub("a","b","aaa",flags=re.S))',
  'print(sorted([1,2],key=lambda x: -x))',
  'import json\nprint(json.dumps({"x":1},indent=2,sort_keys=True))',
  'with open("example") as f:\n print(f.readlines())',
];
for (const [language, sources] of [
  ['javascript', javascript],
  ['python', python],
] satisfies readonly [CodeLanguage, readonly string[]][]) {
  bunTest.test.each(sources)(`${language} ordinary code: %s`, (source) => {
    bunTest.expect(analyzeCode(language, source, [], '/tripwire-policy-fixture').gap).toBeNull();
  });
}
const attacks: readonly [CodeLanguage, string][] = [
  ['javascript', 'console.log(()=>require("fs").rmSync("/"))'],
  ['javascript', 'console.log(JSON.stringify({x:()=>1}))'],
  ['javascript', 'const d=JSON.parse("{}"); d["x"]("example")'],
  ['javascript', 'const x={}; x["constructor"]'],
  [
    'javascript',
    'const fs=require("fs"); let p="/tmp/example"; JSON.parse("[]").forEach(x=>{fs.rmSync(p); p="/"})',
  ],
  [
    'javascript',
    'const fs=require("fs"); const x=["/tmp/example"]; const y=x; y.push("/"); x.forEach(p=>fs.rmSync(p))',
  ],
  ['javascript', 'function f(){return f()} f()'],
  [
    'javascript',
    'console.log(JSON.stringify({x:1}, (k,v)=>require("fs").rmSync(process.env.TARGET)))',
  ],
  ['python', 'print(lambda: 1)'],
  ['python', 'import platform\nplatform.architecture()'],
  ['python', 'import uuid\nuuid.uuid1()'],
  ['python', 'import importlib.util\nimportlib.util.find_spec("a.b")'],
  ['python', 'import os\nos.system("example")'],
  ['python', 'import subprocess\ncmd=["echo"]\nother=cmd\nother.append("x")\nsubprocess.run(cmd)'],
  ['python', 'import os\nfor p in os.listdir("."):\n os.remove(p)'],
  ['python', 'def f(x=eval("example")):\n return x'],
  ['python', 'def f(x: eval("example")):\n return x'],
];
bunTest.test.each(attacks)('keeps dangerous %s opaque: %s', (language, source) => {
  bunTest.expect(analyzeCode(language, source, [], '/tripwire-policy-fixture').gap).not.toBeNull();
});
bunTest.test('closure calls extract actual file effects', () => {
  const report = analyzeCode(
    'python',
    'from pathlib import Path\ndef remove(p):\n Path(p).unlink()\nremove("/")',
    [],
    '/tripwire-policy-fixture',
  );
  bunTest.expect(report.gap).toBeNull();
  bunTest.expect(report.operations.map((operation) => operation.kind)).toEqual(['delete']);
});
