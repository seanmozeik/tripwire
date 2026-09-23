import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';
import { analyzeCode } from '../src/lib/code/analyze';
import type { CodeLanguage, CodeOperation } from '../src/lib/code/types';

const quote = (value: string): string => `'${value.replaceAll("'", String.raw`'\''`)}'`;
const denied: readonly [CodeLanguage, string][] = [
  [
    'python',
    'from pathlib import Path\np="/tmp/example"\nfor x in [1,2]:\n Path(p).unlink()\n p="/"\n continue\n p="/tmp/example"',
  ],

  [
    'javascript',
    'const cmd=["z","rm"]; const alias=cmd; alias.sort(); require("child_process").execFileSync(cmd[0],["-rf","/"])',
  ],
  [
    'python',
    'import subprocess\ncmd=["z","rm"]\nother=cmd\nother.sort()\nsubprocess.run([cmd[0],"-rf","/"])',
  ],
  ['python', 'from pathlib import Path\nxs=[1,2]\nxs.sort(key=lambda x: Path("/").unlink())'],

  ['javascript', 'try {console.log(1)} finally {require("fs").rmSync("/")}'],
  [
    'javascript',
    'const fs=require("fs"); for(const [x=fs.rmSync("/")] of JSON.parse("[]")){console.log(x)}',
  ],
  ['python', 'from pathlib import Path\ntry:\n print(1)\nexcept Path("/").unlink():\n print(2)'],

  [
    'javascript',
    'const fs=require("fs"); let p="/tmp/example"; function f(){p="/";return true} if(f()){fs.rmSync(p)}',
  ],
  [
    'javascript',
    'const fs=require("fs"); let p="/"; const flag=JSON.parse("true"); flag ? (p="/") : (p="/tmp/example"); fs.rmSync(p)',
  ],
  [
    'javascript',
    'const fs=require("fs"); let p="/"; function f(){return 1; p="/tmp/example"} f(); fs.rmSync(p)',
  ],
  [
    'javascript',
    'const fs=require("fs"); let p="/"; const flag=JSON.parse("true"); flag || (p="/tmp/example"); fs.rmSync(p)',
  ],

  [
    'javascript',
    'const fs=require("fs"); let p="/tmp/example"; function change(){fs.rmSync(p); p="/"} [1,2].forEach(x=>change())',
  ],
  [
    'javascript',
    'const fs=require("fs"); let p="/tmp/example"; const d=JSON.parse("{}"); function change(){fs.rmSync(p);p="/"} for(const x of d){change()}',
  ],
  [
    'javascript',
    'const fs=require("fs"); let p="/tmp/example"; try { p="/"; JSON.parse("{}"); p="/tmp/example" } catch(e) {fs.rmSync(p)}',
  ],
  ['javascript', 'const fs=require("fs"); const d={}; console.log({...d, x:fs.rmSync("/")})'],
  ['javascript', 'const fs=require("fs"); let p="/"; { let p="/tmp/example"; } fs.rmSync(p)'],
  [
    'javascript',
    'const fs=require("fs"); const p=["/tmp/example"]; for(const x of p){fs.rmSync(x);p.push("/")}',
  ],
  [
    'javascript',
    'const fs=require("fs"); let p="/tmp/example"; [1].sort((a,b)=>{fs.rmSync(p);p="/";return 0})',
  ],
  [
    'javascript',
    'const fs=require("fs"); let p="/tmp/example"; JSON.stringify({},(k,v)=>{fs.rmSync(p);p="/";return v})',
  ],
  ['javascript', 'const fs=require("fs"); function f(x=fs.rmSync("/")){return x}'],
  ['javascript', 'const d={f:x=>x}; d["f"]("example")'],
  ['javascript', 'const f=()=>1; console.log(!f)'],
  [
    'python',
    'from pathlib import Path\ndef outer(p):\n return lambda: Path(p).unlink()\nf=outer("/")\nf()',
  ],
  ['python', 'from pathlib import Path\ndef f(x=Path("/").unlink()):\n return x'],
  ['python', 'from pathlib import Path\ndef f(x: Path("/").unlink()):\n return x'],
  [
    'python',
    'from pathlib import Path\nimport json\nxs=["/tmp/example"]\nys=xs\nfor x in json.loads("[]"):\n Path(xs[0]).unlink()\n ys.append("/")',
  ],
  [
    'python',
    'from pathlib import Path\nxs=["/tmp/example"]\nfor p in xs:\n Path(p).unlink()\n xs.append("/")',
  ],
  ['python', 'import re\nfrom pathlib import Path\nre.sub("a",lambda m: Path("/").unlink(),"aaa")'],
  [
    'python',
    'import json\nfrom pathlib import Path\ndef f(x):\n if x:\n  return "/tmp/example"\n return "/"\nPath(f(json.loads("true"))).unlink()',
  ],
  ['python', 'import os\nimport subprocess\nsubprocess.run(os.listdir("."))'],
];
bunTest.test.each(denied)('denies effects through %s state: %s', (language, source) => {
  bunTest
    .expect(decideBash(`${language === 'python' ? 'python3 -c' : 'node -e'} ${quote(source)}`).kind)
    .toBe('deny');
});
const transfers: readonly [CodeLanguage, string, readonly CodeOperation['kind'][]][] = [
  [
    'python',
    'from pathlib import Path\nPath("/tmp/example-a").rename("/tmp/example-b")',
    ['process'],
  ],
  [
    'python',
    'from pathlib import Path\nPath("/tmp/example-a").replace("/tmp/example-b")',
    ['process'],
  ],
  ['python', 'from pathlib import Path\nPath("example-a").symlink_to("example-b")', ['process']],
  ['python', 'import os\nos.rename("/tmp/example-a","/tmp/example-b")', ['process']],
  ['python', 'import shutil\nshutil.copy("example-a","example-b")', ['process']],
  ['python', 'import shutil\nshutil.move("/tmp/example-a","/tmp/example-b")', ['process']],
  ['javascript', 'require("fs").renameSync("/tmp/example-a","/tmp/example-b")', ['process']],
  ['javascript', 'require("fs").copyFileSync("example-a","example-b")', ['process']],
  ['javascript', 'require("fs").mkdirSync("example")', ['write']],
  ['javascript', 'require("fs").symlinkSync("example-a","example-b")', ['process']],
];
bunTest.test.each(transfers)('extracts %s file effects: %s', (language, source, kinds) => {
  const report = analyzeCode(language, source);
  bunTest.expect(report.gap).toBeNull();
  bunTest.expect(report.operations.map((operation) => operation.kind)).toEqual([...kinds]);
  const runner = language === 'python' ? 'python3 -c' : 'node -e';
  bunTest.expect(decideBash(`${runner} ${quote(source)}`).kind).toBe('allow');
  const dangerous = source
    .replaceAll('example-b', '.env')
    .replaceAll('mkdirSync("example")', 'mkdirSync(".ssh/example")');
  bunTest.expect(decideBash(`${runner} ${quote(dangerous)}`).kind).toBe('deny');
});
