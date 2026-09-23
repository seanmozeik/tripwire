import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';
import { analyzeCode } from '../../src/lib/code/analyze';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

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

bunTest.test.each(['feed("example")', 'close()'])(
  'base-class entry %s invokes all supported overrides',
  (entry) => {
    const source = `from html.parser import HTMLParser\nclass Parser(HTMLParser):\n def handle_data(self,text): print(text)\n def handle_comment(self,text): open(".env","w").write(text)\nParser().${entry}`;
    bunTest.expect(decideBash(`python3 -c ${quote(source)}`).kind).toBe('deny');
    bunTest
      .expect(
        decideBash(
          `python3 -c ${quote(source.replace('open(".env","w").write(text)', 'print(text)'))}`,
        ).kind,
      )
      .toBe('allow');
  },
);

bunTest.test.each(['feed', 'reset', '__init__'])(
  'base-class implementation method %s cannot be overridden',
  (method) => {
    const source = `from html.parser import HTMLParser\nclass Parser(HTMLParser):\n def ${method}(self): print(1)\nParser()`;
    bunTest.expect(analyzeCode('python', source).gap).not.toBeNull();
  },
);
