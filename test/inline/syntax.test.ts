import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';
import { analyzeCode } from '../../src/lib/code/analyze';

const pythonCases = [
  ['type inspection', 'import json\nx=json.loads("{}")\nprint(isinstance(x,dict))'],
  ['iterator bindings', 'print(next(iter([1,2])))'],
  ['tuple binding', 'a,b=("alpha","beta")\nprint(a,b)'],
  ['parallel expressions', 'a,b="alpha","beta"\nprint(a,b)'],
  ['rest parameters', 'def f(*items):\n print(items)\nf(1,2)'],
  ['keyword rest', 'def f(**items):\n print(items)\nf(value=1)'],
  ['star array', 'a=[1,2]\nprint([*a,3])'],
  ['star call', 'a=[1,2]\nprint(*a)'],
  ['stdin iteration', 'import sys\nfor line in sys.stdin:\n print(line.partition(": "))'],
  ['file iteration', 'for line in open("report.txt"):\n print(line)'],
  ['walrus', 'text="example"\nwhile (i:=text.find("x"))>=0:\n print(i)\n break'],
  ['import separator', 'import importlib.util\nprint(1)'],
  ['dictionary defaults', 'd={}\nd.setdefault("example",set()).update([1])\nprint(d)'],
  [
    'compiled regex',
    'import re\nr=re.compile("x")\nfor m in r.finditer("example"):\n print(m.start(),m.end())',
  ],
  ['regex callback', 'import re\nprint(re.compile("x").subn(lambda m:m.group(0),"example"))'],
  ['replace runtime string', 's=open("report.txt").read()\nprint(s.replace("x",s+"y",1))'],
  ['decoder options', 'print(open("report.txt","rb").read().decode("utf-8",errors="replace"))'],
  [
    'sequence matcher',
    'import difflib\nprint(difflib.SequenceMatcher(None,[1],[2],autojunk=False).get_opcodes())',
  ],
  ['plist serialization', 'import plistlib\nprint(plistlib.dumps({"example":1}))'],
  ['inspection library', 'import inspect\nprint(inspect.cleandoc(" example "))'],
  [
    'path resolution comparison',
    'from pathlib import Path\nprint(Path("report.txt").resolve()==Path("other.txt").resolve())',
  ],
  [
    'readlink comparison',
    'from pathlib import Path\nprint(Path("report.txt").readlink()==Path("other.txt"))',
  ],
  [
    'plain class',
    'class Record:\n def __init__(self,value): self.value=value\n def show(self): print(self.value)\nRecord("example").show()',
  ],
  [
    'nonlocal',
    'def outer():\n n=0\n def f():\n  nonlocal n\n  n+=1\n  return n\n print(f())\nouter()',
  ],
];
const javascriptCases = [
  ['typeof', 'console.log(typeof MissingFeature, typeof Bun.file("report.txt").image)'],
  ['destructured callback', 'console.log([[1,2]].map(([,v])=>v))'],
  ['object parameter', 'const f=({value})=>value; console.log(f({value:1}))'],
  ['rest parameters', 'const f=(...items)=>console.log(items); f(1,2)'],
  ['multiple bindings', 'const a=1,b=2; console.log(a,b)'],
  ['single statement loop', 'for(const x of [1,2]) console.log(x)'],
  ['computed object', 'const k="value"; console.log({[k]:1,...{other:2},"label":3})'],
  ['replacement callback', 'let n=0; console.log("example".replace(/x/g,s=>++n?s:"y"))'],
  ['throw', 'if (true) throw Error("example")'],
  ['Bun image', 'await Bun.file("image.png").image().avif({quality:60}).write("image.avif")'],
  ['Bun write', 'await Bun.write("report.txt",JSON.stringify({value:1}))'],
  ['Bun file write', 'await Bun.file("report.txt").write("example")'],
  ['module resolution', 'console.log(require.resolve("example/package.json",{paths:["app"]}))'],
  [
    'utility library',
    'const {isDeepStrictEqual}=require("node:util"); console.log(isDeepStrictEqual({},{}))',
  ],
  ['OS library', 'console.log(require("node:os").platform())'],
  [
    'timer callback',
    'process.once("SIGINT",()=>process.exit(0)); setInterval(()=>console.log("example"),1000)',
  ],
];
const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

bunTest.test.each(pythonCases)('Python %s and dangerous twin', (_, source) => {
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(`${source}\nimport os; os.remove("/srv/example/record.txt")`)}`,
      ).kind,
    )
    .toBe('deny');
});
bunTest.test.each(javascriptCases)('JS %s and dangerous twin', (_, source) => {
  bunTest.expect(decideBash(`bun -e ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(
      decideBash(
        `bun -e ${quote(`${source}; require("fs").unlinkSync("/srv/example/record.txt")`)}`,
      ).kind,
    )
    .toBe('deny');
});

bunTest.test('invalid code stays closed without rejecting complete objects', () => {
  bunTest
    .expect(analyzeCode('javascript', 'const x={"value": "example"}; console.log(x)').gap)
    .toBeNull();
  bunTest.expect(analyzeCode('javascript', 'const x={"value": "example').gap).not.toBeNull();
});

bunTest.test('tuple iteration binds each static operand', () => {
  const source =
    'from pathlib import Path\nfor source,target in [("a.txt","b.txt")]:\n Path(source).rename(target)';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(decideBash(`python3 -c ${quote(source.replace('b.txt', '.env'))}`).kind)
    .toBe('deny');
});

bunTest.test('exception tuples and builtin type names remain inert', () => {
  const source =
    'try:\n print(1)\nexcept (ValueError,TypeError) as error:\n print(type(error).__name__)';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(source.replace('print(type(error).__name__)', 'open(".env","w").write("example")'))}`,
      ).kind,
    )
    .toBe('deny');
});

bunTest.test('bounded dictionary comprehensions preserve inspected module names', () => {
  const source =
    'import importlib.util; print({name:importlib.util.find_spec(name) is not None for name in ["example","other"]})';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(decideBash(`python3 -c ${quote(source.replace('"other"', '"example.child"'))}`).kind)
    .toBe('deny');
});
bunTest.test('walrus in a comprehension cannot conceal outer rebinding', () => {
  const source =
    'import os\np="/tmp/example"\n[(p:="/srv/example/record.txt") for x in [1]]\nos.remove(p)';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('deny');
});

bunTest.test('grouping inspects callbacks over inert directory names', () => {
  const source =
    'const fs=require("node:fs"); const groups=Map.groupBy(fs.readdirSync(".").filter(name=>name.endsWith(".sql")),name=>name.split("_")[0]); console.log([...groups].filter(([,values])=>values.length>1))';
  bunTest.expect(decideBash(`node -e ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(
      decideBash(
        `node -e ${quote(source.replace('name.split("_")[0]', 'fs.writeFileSync(".env","example")'))}`,
      ).kind,
    )
    .toBe('deny');
});

bunTest.test('formatted string escapes preserve expression inspection', () => {
  const source = 'import re\nprint(re.sub("x",lambda m:f"example {m[0]}\\n", "x"))';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(
      decideBash(`python3 -c ${quote(source.replace('m[0]', "open('.env','w').write('example')"))}`)
        .kind,
    )
    .toBe('deny');
});
