import * as bunTest from 'bun:test';

import { decideBash } from '../../src/dispatch';
import { analyzeCode } from '../../src/lib/code/analyze';
import { builtinMethod, builtinProperty } from '../../src/lib/code/builtins';

const quote = (source: string): string => `'${source.replaceAll("'", String.raw`'\''`)}'`;

bunTest.test.each([
  'KeyError',
  'OSError',
  '(KeyError, OSError)',
  'FileNotFoundError',
  'RuntimeError',
])('builtin exception %s is recognized in handlers and raises', (exception) => {
  const source = `try:\n print(1)\nexcept ${exception} as error:\n print(type(error).__name__)`;
  bunTest.expect(analyzeCode('python', source, [], '/tripwire-policy-fixture').gap).toBeNull();
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(source.replace('print(type(error).__name__)', 'open(".env","w").write("example")'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
  if (!exception.startsWith('(')) {
    bunTest
      .expect(analyzeCode('python', `raise ${exception}`, [], '/tripwire-policy-fixture').gap)
      .toBeNull();
    bunTest
      .expect(
        analyzeCode('python', `raise ${exception}("example")`, [], '/tripwire-policy-fixture').gap,
      )
      .toBeNull();
  }
});

bunTest.test(
  'an exception clause still inspects shadowed classes and constructor arguments',
  () => {
    bunTest
      .expect(
        decideBash(
          `python3 -c ${quote('import os\ndef KeyError():\n os.remove("/")\ntry:\n print(1)\nexcept KeyError():\n print(2)')}`,
          {},
          { cwd: '/tripwire-policy-fixture' },
        ).kind,
      )
      .toBe('deny');
    bunTest
      .expect(
        decideBash(
          `python3 -c ${quote('raise OSError(open(".env","w").write("example"))')}`,
          {},
          { cwd: '/tripwire-policy-fixture' },
        ).kind,
      )
      .toBe('deny');
    bunTest
      .expect(
        analyzeCode(
          'python',
          'try:\n print(1)\nexcept UnknownException:\n print(2)',
          [],
          '/tripwire-policy-fixture',
        ).gap,
      )
      .not.toBeNull();
  },
);

bunTest.test.each([
  ['Map', 'get'],
  ['Map', 'has'],
  ['Set', 'has'],
  ['Set', 'entries'],
  ['python-regex', 'finditer'],
  ['python-regex', 'findall'],
  ['python-regex', 'search'],
  ['sequence-matcher', 'get_opcodes'],
  ['sequence-matcher', 'ratio'],
  ['RegExp', 'test'],
  ['json-decoder', 'decode'],
  ['Date', 'getTime'],
  ['Date', 'toJSON'],
])('%s.%s returns inert data without string authority', (receiver, method) => {
  bunTest.expect(builtinMethod(receiver, method, [])?.kind).toBe('data');
});

bunTest.test.each([
  ['Date', 'toISOString'],
  ['URL', 'toString'],
  ['python-regex', 'sub'],
  ['datetime', 'isoformat'],
])('%s.%s retains string results', (receiver, method) => {
  bunTest.expect(builtinMethod(receiver, method, [])?.kind).toBe('text');
});

bunTest.test('builtin properties use typed results and reject inherited table properties', () => {
  bunTest
    .expect(builtinProperty('URL', 'searchParams'))
    .toEqual({ kind: 'builtin', name: 'URLSearchParams' });
  bunTest.expect(builtinProperty('Map', 'size')?.kind).toBe('data');
  bunTest.expect(builtinProperty('process-result', 'stdout')?.kind).toBe('text');
  bunTest.expect(builtinProperty('process-result', 'returncode')?.kind).toBe('data');
  bunTest.expect(builtinProperty('URL', 'constructor')).toBeNull();
  bunTest.expect(builtinMethod('Map', 'constructor', [])).toBeNull();
});

bunTest.test.each([
  'import re\nfor match in re.compile("x").finditer("example"):\n print(match.start())',
  'import difflib\nfor tag,i,j,k,l in difflib.SequenceMatcher(None,[1],[2]).get_opcodes():\n print(tag,i,j,k,l)',
])('iterates non-string builtin results: %s', (source) => {
  bunTest.expect(analyzeCode('python', source, [], '/tripwire-policy-fixture').gap).toBeNull();
  bunTest
    .expect(
      decideBash(
        `python3 -c ${quote(source.replace(/print\([^\n]+\)/u, 'open(".env","w").write("example")'))}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
});

bunTest.test.each([
  'typeof MissingFeature',
  'typeof/*comment*/MissingFeature',
  'typeof\nMissingFeature',
  'let n=0; ++/*comment*/n; --n; console.log(n)',
])('unary operators use parsed tokens: %s', (source) => {
  bunTest.expect(analyzeCode('javascript', source, [], '/tripwire-policy-fixture').gap).toBeNull();
});

bunTest.test('typeof inspects computed operands and update invalidates a literal target', () => {
  bunTest
    .expect(
      decideBash(
        `node -e ${quote('typeof(require("fs").unlinkSync("/"))')}`,
        {},
        { cwd: '/tripwire-policy-fixture' },
      ).kind,
    )
    .toBe('deny');
  bunTest
    .expect(
      analyzeCode(
        'javascript',
        'let target="/tmp/example"; ++target; require("fs").unlinkSync(target)',
        [],
        '/tripwire-policy-fixture',
      ).gap,
    )
    .not.toBeNull();
});
