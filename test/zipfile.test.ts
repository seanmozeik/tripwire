import * as bunTest from 'bun:test';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash } from '../src/dispatch';

const python = (code: string): string => `python3 - <<'PY'\n${code}\nPY`;

bunTest.describe('Python archive and text operations', () => {
  bunTest.test.each([
    'import zipfile; z=zipfile.ZipFile("input.zip"); print(z.namelist()); z.close()',
    'from zipfile import ZipFile as Z; print(Z("input.zip").read("doc.md").decode("utf-8"))',
    'import zipfile\nwith zipfile.ZipFile("input.zip") as z:\n print(z.read("doc.md"))',
    'import zipfile; z=zipfile.ZipFile("output.zip", "w", zipfile.ZIP_DEFLATED); z.writestr("doc.md", "hello"); z.close()',
    'import zipfile; z=zipfile.ZipFile("output.zip", "w"); z.write("README.md", "doc.md")',
    'import difflib; print("".join(difflib.unified_diff(["old"], ["new"])))',
    'import difflib; print("".join(difflib.unified_diff(["old"], ["new"], fromfile="before", tofile="after", lineterm="")))',
    'import glob; print(sorted(glob.glob("src/**/*.py", recursive=True)))',
    'from pathlib import Path; print(list(Path("src").glob("*.ts")))',
    // Reduced from 01a095c0-2eb8-7443-b1d2-67f9147d0b03, 2026-09-12.
    'import zipfile,pathlib; z=zipfile.ZipFile("input.zip"); p=pathlib.Path("/tmp/tripwire-zip-output"); p.mkdir(exist_ok=True); [(p / n).write_bytes(z.read(n)) for n in z.namelist() if n in ("guide.md", "transcript.md", "record.json")]',
  ])('allows %s', (source) => {
    bunTest
      .expect(decideBash(python(source), {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe('allow');
  });

  bunTest.test.each([
    'import zipfile; zipfile.ZipFile(".env", "w")',
    'import zipfile; zipfile.ZipFile(".env")',
    'import zipfile; z=zipfile.ZipFile("output.zip", "w"); z.write(".env")',
    'import zipfile; zipfile.ZipFile("input.zip").extractall("/")',
    'import zipfile,pathlib; z=zipfile.ZipFile("input.zip"); [(pathlib.Path("/tmp") / n).write_bytes(z.read(n)) for n in z.namelist()]',
    'import zipfile,pathlib; z=zipfile.ZipFile("input.zip"); [(pathlib.Path("/tmp") / n).write_bytes(z.read(n)) for n in z.namelist() if n in ("/Users/example/.ssh/id_rsa",)]',
    'import zipfile; zipfile.ZipFile("input.zip").read("doc").decode("custom_codec")',
    'import zipfile,os; z=zipfile.ZipFile("input.zip"); os.unlink("/protected")',
    'import glob,os; [os.unlink(n) for n in glob.glob("*")]',
    'import difflib,os; print("".join(difflib.unified_diff(["old"], ["new"], fromfile=os.unlink("/protected"))))',
  ])('blocks %s', (source) => {
    bunTest
      .expect(decideBash(python(source), {}, { cwd: '/tripwire-policy-fixture' }).kind)
      .toBe('deny');
  });

  bunTest.test('reads local JSON as data and retains protected-path checks', () => {
    const cwd = mkdtempSync(path.join(tmpdir(), 'fictional-json-'));
    try {
      writeFileSync(path.join(cwd, 'package.json'), '{"version":"0.0.0-fictional"}');
      for (const [source, expected] of [
        ['console.log(require("./package.json").version)', 'allow'],
        ['require("./secrets.json")', 'deny'],
        ['require("./uninspected.js")', 'deny'],
      ] as const) {
        bunTest.expect(decideBash(`node -e '${source}'`, {}, { cwd }).kind).toBe(expected);
      }
    } finally {
      rmSync(cwd, { recursive: true, force: true });
    }
  });
});
