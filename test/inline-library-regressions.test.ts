import * as bunTest from 'bun:test';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash } from '../src/dispatch';
import { analyzeCode } from '../src/lib/code/analyze';

const python = (source: string): string => `python3 - <<'PY'\n${source}\nPY`;

bunTest.test('JSON imports verify the resolved regular file', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'tripwire-json-import-'));
  try {
    mkdirSync(path.join(root, 'directory.json'));
    writeFileSync(path.join(root, 'directory.json', 'index.js'), 'module.exports = 1;');
    writeFileSync(path.join(root, 'payload.js'), 'module.exports = 1;');
    writeFileSync(path.join(root, 'data.json'), '{}');
    writeFileSync(path.join(root, 'secrets.json'), '{}');
    symlinkSync('payload.js', path.join(root, 'script-link.json'));
    symlinkSync('data.json', path.join(root, 'data-link.json'));
    symlinkSync('secrets.json', path.join(root, 'secret-link.json'));
    for (const name of ['data.json', 'data-link.json']) {
      bunTest
        .expect(decideBash(`node -e 'console.log(require("./${name}"))'`, {}, { cwd: root }).kind)
        .toBe('allow');
    }
    for (const name of ['directory.json', 'script-link.json', 'secret-link.json', 'missing.json']) {
      bunTest
        .expect(decideBash(`node -e 'require("./${name}")'`, {}, { cwd: root }).kind)
        .toBe('deny');
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

bunTest.test.each([
  'import zipfile; zipfile.ZipFile(file="input.zip", mode="r")',
  'from zipfile import ZipFile as Z, ZIP_DEFLATED as C; z=Z(mode="w", file="output.zip", compression=C)',
  'import zipfile; z=zipfile.ZipFile("output.zip", mode="w"); z.write(filename="README.md", arcname="doc.md")',
  'import zipfile; z=zipfile.ZipFile("output.zip", "w"); z.writestr(data="hello", zinfo_or_arcname="doc.md")',
  'import zipfile; zipfile.ZipFile("input.zip", compression=zipfile.ZIP_STORED).read(name="doc.md")',
])('normalizes ZIP keyword arguments: %s', (source) => {
  bunTest.expect(decideBash(python(source)).kind).toBe('allow');
});

bunTest.test.each([
  'import zipfile; zipfile.ZipFile("input.zip", file="other.zip")',
  'import zipfile; zipfile.ZipFile(mode="w")',
  'import zipfile; zipfile.ZipFile(file=".env", mode="w")',
  'import zipfile; z=zipfile.ZipFile("out.zip", "w"); z.write(filename=".env", arcname="safe")',
  'import zipfile; zipfile.ZipFile(file="input.zip", unknown=True)',
  'import zipfile,os; zipfile.ZipFile(file="input.zip", mode=os.unlink("/protected"))',
])('retains checks after keyword binding: %s', (source) => {
  bunTest.expect(decideBash(python(source)).kind).toBe('deny');
});

bunTest.test.each(['utf_8', 'utf8', 'utf-32', 'utf_32_le', 'latin_1'])(
  'uses the same codec policy for files and text: %s',
  (encoding) => {
    for (const source of [
      `open("README.md", encoding="${encoding}").read()`,
      `"hello".encode("${encoding}")`,
      `"hello".encode(encoding="${encoding}")`,
      `import zipfile; zipfile.ZipFile("input.zip").read("doc").decode("${encoding}")`,
    ]) {
      bunTest.expect(decideBash(python(source)).kind).toBe('allow');
    }
  },
);

bunTest.test('custom codecs remain blocked in both call forms', () => {
  for (const source of [
    'open("README.md", encoding="custom").read()',
    '"hello".encode("custom")',
    '"hello".encode(encoding="custom")',
  ]) {
    bunTest.expect(decideBash(python(source)).kind).toBe('deny');
  }
});

bunTest.test('ZIP argument forms produce the same file operations', () => {
  const positional = analyzeCode('python', 'import zipfile; zipfile.ZipFile("output.zip", "w")');
  const keyword = analyzeCode(
    'python',
    'import zipfile; zipfile.ZipFile(mode="w", file="output.zip")',
  );
  bunTest.expect(positional.gap).toBeNull();
  bunTest.expect(keyword.gap).toBeNull();
  for (const report of [keyword, positional]) {
    bunTest.expect(report.operations).toHaveLength(1);
    bunTest.expect(report.operations[0]).toMatchObject({ kind: 'write', path: 'output.zip' });
  }
});
