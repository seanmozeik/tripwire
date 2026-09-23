import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

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
