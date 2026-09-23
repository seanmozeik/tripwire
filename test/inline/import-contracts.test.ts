import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

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
