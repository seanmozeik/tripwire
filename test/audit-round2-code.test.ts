import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';
import { analyzeCode } from '../src/lib/code/analyze';

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

bunTest.test.each([
  'python3 -c \'import sys; open(sys.argv[1],"w").write("example")\' report.txt',
  'node -e \'require("fs").writeFileSync(process.argv[1],"example")\' -- report.txt',
  'bun -e \'await Bun.write(process.argv[1],"example")\' report.txt',
])('binds interpreter argv: %s', (command) => {
  bunTest.expect(decideBash(command).kind).toBe('allow');
  bunTest.expect(decideBash(command.replace('report.txt', '.env')).kind).toBe('deny');
});

bunTest.test.each([
  '__getattr__',
  '__del__',
  '__eq__',
  '__hash__',
  '__str__',
  '__format__',
  '__iter__',
  '__getattribute__',
  '__new__',
])('blocks implicit class hook %s', (hook) => {
  bunTest
    .expect(analyzeCode('python', `class Record:\n def ${hook}(self): return 1\nRecord()`).gap)
    .not.toBeNull();
});

bunTest.test.each([
  [
    'python',
    'class Record:\n def show(self):\n  import os\n  os.remove("/srv/example/record.txt")\nRecord().show()',
  ],
  [
    'python',
    'import re,os\nre.compile("x").sub(lambda m:os.remove("/srv/example/record.txt"),"x")',
  ],
  [
    'javascript',
    'const f=([value])=>require("fs").unlinkSync(value); f(["/srv/example/record.txt"])',
  ],
  ['javascript', 'setInterval(()=>require("fs").unlinkSync("/srv/example/record.txt"),1000)'],
  [
    'javascript',
    'const x={get value(){require("fs").unlinkSync("/srv/example/record.txt")}}; console.log({...x})',
  ],
])('inspects nested effects in %s', (language, source) => {
  bunTest
    .expect(decideBash(`${language === 'python' ? 'python3 -c' : 'node -e'} ${quote(source)}`).kind)
    .toBe('deny');
});

bunTest.test('transpiler literal source cannot hide macros', () => {
  bunTest
    .expect(
      decideBash(
        `bun -e ${quote('console.log(new Bun.Transpiler({loader:"ts"}).transformSync("const n: number = 1"))')}`,
      ).kind,
    )
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        `bun -e ${quote('new Bun.Transpiler().transformSync(await Bun.file("input.ts").text())')}`,
      ).kind,
    )
    .toBe('deny');
  bunTest
    .expect(
      decideBash(
        `bun -e ${quote('new Bun.Transpiler({macro:{example:{run:"./macro.ts"}}}).transformSync("run()")')}`,
      ).kind,
    )
    .toBe('deny');
});
bunTest.test('module discovery excludes parent-package execution', () => {
  bunTest
    .expect(
      decideBash('python3 -c \'import importlib.util; print(importlib.util.find_spec("example"))\'')
        .kind,
    )
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        'python3 -c \'import importlib.util; print(importlib.util.find_spec("example.child"))\'',
      ).kind,
    )
    .toBe('deny');
});
bunTest.test('keyword-only defaults cannot bind positional rest values', () => {
  const source =
    'import os\ndef f(*args, target="/srv/example/record.txt"):\n os.remove(target)\nf("/tmp/a", "/tmp/b")';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('deny');
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(source.replace('/srv/example/record.txt', '/tmp/example-record.txt'))}`,
      ).kind,
    )
    .toBe('allow');
});
bunTest.test('stdin argument binding preserves policy targets', () => {
  bunTest
    .expect(
      decideBash(
        'python3 - report.txt <<\'PY\'\nimport sys\nopen(sys.argv[1],"w").write("example")\nPY',
      ).kind,
    )
    .toBe('allow');
  bunTest
    .expect(
      decideBash('python3 - .env <<\'PY\'\nimport sys\nopen(sys.argv[1],"w").write("example")\nPY')
        .kind,
    )
    .toBe('deny');
});
bunTest.test('subprocess cwd reaches deletion policy', () => {
  const source = 'import subprocess; subprocess.run(["rm","example.txt"],cwd="/tmp",check=True)';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest.expect(decideBash(`python3 -c ${quote(source.replace('/tmp', '/'))}`).kind).toBe('deny');
});
bunTest.test('invalid code stays closed without rejecting complete objects', () => {
  bunTest
    .expect(analyzeCode('javascript', 'const x={"value": "example"}; console.log(x)').gap)
    .toBeNull();
  bunTest.expect(analyzeCode('javascript', 'const x={"value": "example').gap).not.toBeNull();
});

bunTest.test('multiple declarations keep block scope', () => {
  const source =
    'let target="/srv/example/record.txt"; {const n=1,target="/tmp/example"; console.log(n,target)} require("fs").unlinkSync(target)';
  bunTest.expect(decideBash(`node -e ${quote(source)}`).kind).toBe('deny');
});
bunTest.test('nonlocal tuple assignment invalidates the parent binding', () => {
  const source =
    'import os\ndef outer():\n target="/tmp/example"\n other=0\n def update():\n  nonlocal target,other\n  target,other="/srv/example/record.txt",1\n update()\n os.remove(target)\nouter()';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('deny');
});

bunTest.test.each([
  ['python3 -c', 'import os; os.chdir("/tmp"); os.remove("example.txt")'],
  ['node -e', 'process.chdir("/tmp"); require("fs").unlinkSync("example.txt")'],
])('inline cwd changes preserve deletion policy for %s', (runner, source) => {
  bunTest.expect(decideBash(`${runner} ${quote(source)}`).kind).toBe('allow');
  bunTest.expect(decideBash(`${runner} ${quote(source.replace('/tmp', '/'))}`).kind).toBe('deny');
  bunTest
    .expect(decideBash(`${runner} ${quote(source.replace('/tmp', '/missing-example-cwd'))}`).kind)
    .toBe('deny');
});
bunTest.test('branching cwd cannot authorize a later relative delete', () => {
  const source =
    'import os,json\nos.chdir("/tmp")\nif json.loads("true"): os.chdir("/")\nos.remove("example.txt")';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('deny');
});

bunTest.test('HTML parser subclasses inspect their event handlers', () => {
  const source =
    'from html.parser import HTMLParser\nclass Parser(HTMLParser):\n def handle_data(self,text): print(text)\nParser().feed("<p>example</p>")';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(source.replace('print(text)', 'open(".env","w").write(text)'))}`,
      ).kind,
    )
    .toBe('deny');
  bunTest
    .expect(decideBash(`python3 -c ${quote(source.replace('handle_data', '__getattr__'))}`).kind)
    .toBe('deny');
});

bunTest.test('tuple iteration binds each static operand', () => {
  const source =
    'from pathlib import Path\nfor source,target in [("a.txt","b.txt")]:\n Path(source).rename(target)';
  bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('allow');
  bunTest
    .expect(decideBash(`python3 -c ${quote(source.replace('b.txt', '.env'))}`).kind)
    .toBe('deny');
});

bunTest.test.each([
  [
    'python3 -c',
    'import os,subprocess\nenv=os.environ\nenv["PYTHONPATH"]="/srv/example"\nsubprocess.run(["python3","-c","print(1)"])',
  ],
  [
    'node -e',
    'const env=process.env; env.NODE_OPTIONS="--require /srv/example/payload.js"; require("child_process").execFileSync("node",["-e","console.log(1)"])',
  ],
])('environment aliases cannot change interpreter startup in %s', (runner, source) => {
  bunTest.expect(decideBash(`${runner} ${quote(source)}`).kind).toBe('deny');
});

bunTest.test.each(['$VALUES', '"$@"', `"\${values[@]}"`])(
  'variable-width argv %s cannot shift a checked operand',
  (expansion) => {
    const source = 'import sys,os; os.remove(sys.argv[2])';
    bunTest
      .expect(decideBash(`python3 -c ${quote(source)} ${expansion} /tmp/example`).kind)
      .toBe('deny');
  },
);
bunTest.test('quoted scalar argv can be printed without authorizing a path', () => {
  bunTest
    .expect(decideBash('python3 -c \'import sys; print(sys.argv[1])\' "$VALUE"').kind)
    .toBe('allow');
  bunTest
    .expect(decideBash('python3 -c \'import sys,os; os.remove(sys.argv[1])\' "$VALUE"').kind)
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

bunTest.test('unknown JavaScript argv cannot supply interpreter startup flags', () => {
  bunTest.expect(decideBash('node -e \'console.log(1)\' "$OPTION" ./payload.js').kind).toBe('deny');
  bunTest
    .expect(decideBash("bun -e 'console.log(1)' example --preload ./payload.js").kind)
    .toBe('deny');
  bunTest
    .expect(decideBash('node -e \'console.log(process.argv[1])\' -- "$VALUE"').kind)
    .toBe('allow');
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
