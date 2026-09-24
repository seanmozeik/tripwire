import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';
import { analyzeCode } from '../../src/lib/code/analyze';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

bunTest.test.each(['map', 'filter', 'forEach', 'some', 'every', 'find', 'flatMap', 'reduce'])(
  'literal %s checks each item and dangerous twin',
  (method) => {
    const callback =
      method === 'reduce' ? '(a,p)=>{fs.unlinkSync(p);return a},0' : 'p=>fs.unlinkSync(p)';
    const source = `const fs=require("fs"); ["dist/a.txt","dist/b.txt"].${method}(${callback})`;
    bunTest
      .expect(decideBash(`node -e ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe('allow');
    bunTest
      .expect(
        decideBash(
          `node -e ${quote(source.replace('dist/b.txt', '/srv/fictional/b.txt'))}`,
          {},
          { cwd: '/tripwire-policy-fixture' },
        ).kind,
      )
      .toBe('deny');
    const report = analyzeCode('javascript', source, [], '/tripwire-policy-fixture');
    bunTest.expect(report.gap).toBeNull();
    bunTest
      .expect(report.operations.map((operation) => ('path' in operation ? operation.path : null)))
      .toEqual(['dist/a.txt', 'dist/b.txt']);
  },
);

bunTest.test.each([
  'list(map(lambda p: os.unlink(p), ["dist/a.txt","dist/b.txt"]))',
  'list(filter(lambda p: os.unlink(p), ["dist/a.txt","dist/b.txt"]))',
  'sorted(["dist/a.txt","dist/b.txt"], key=lambda p: os.unlink(p))',
  '[os.unlink(p) for p in ["dist/a.txt","dist/b.txt"]]',
  '{p: os.unlink(p) for p in ["dist/a.txt","dist/b.txt"]}',
  'list(os.unlink(p) for p in ["dist/a.txt","dist/b.txt"])',
])('Python literal callback or comprehension: %s', (expression) => {
  const source = `import os\n${expression}`;
  bunTest
    .expect(decideBash(`python3 -c ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(source.replace('dist/b.txt', '/srv/fictional/b.txt'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});

bunTest.test.each([
  'const fs=require("fs"); let p="dist/a"; [1,2].forEach(x=>{fs.unlinkSync(p);p="/"})',
  'const fs=require("fs"); const xs=["dist/a","dist/b"]; xs.map(p=>{xs[1]="/";fs.unlinkSync(p)})',
  'const fs=require("fs"); const xs=["dist/a","dist/b"]; const ys=xs; xs.map(p=>{ys.push("/");fs.unlinkSync(p)})',
  'const fs=require("fs"); const xs=["dist/a"]; [1,2].map(x=>{fs.unlinkSync(xs[0]);xs[0]="/"})',
  'const fs=require("fs"); ["dist/a","/"].reduce((a,p)=>{fs.unlinkSync(a);return p}, "dist/initial"); fs.unlinkSync("/")',
])('literal callbacks retain mutation safety: %s', (source) => {
  bunTest
    .expect(decideBash(`node -e ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('deny');
});

bunTest.test('reduce carries the accumulator between calls', () => {
  const source =
    'const fs=require("fs"); ["dist/a","dist/b"].reduce((a,p)=>{fs.unlinkSync(a);return p},"dist/initial")';
  bunTest
    .expect(decideBash(`node -e ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        `node -e ${quote(source.replace('dist/a', '/'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});

bunTest.test('literal callback budget is bounded', () => {
  for (const length of [128, 129]) {
    const items = Array.from({ length }, () => '"dist/example"').join(',');
    const source = `[${items}].forEach(p=>require("fs").unlinkSync(p))`;
    bunTest
      .expect(decideBash(`node -e ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe(length === 128 ? 'allow' : 'deny');
  }
});

bunTest.test('known inner receiver retains unknown outer repetition', () => {
  const source =
    'const fs=require("fs"); let p="dist/a"; function f(){fs.unlinkSync(p);p="/"} for (const x of JSON.parse("[]")) [1].forEach(f)';
  bunTest
    .expect(decideBash(`node -e ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('deny');
  bunTest
    .expect(
      decideBash(
        `node -e ${quote(source.replace('p="/"', 'console.log(p)'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('allow');
});

bunTest.test('Python data string find remains an ordinary string operation', () => {
  const source = 'import json\ns=json.loads("{}")\nprint(s.find("example"))';
  bunTest
    .expect(decideBash(`python3 -c ${quote(source)}`, {}, { cwd: '/tripwire-policy-fixture' }).kind)
    .toBe('allow');
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(`${source}\nopen(".env","w")`)}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});
