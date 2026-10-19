import * as bunTest from 'bun:test';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash } from '../src/dispatch';

const inspect = (command: string) => decideBash(command, {}, { cwd: '/tripwire-policy-fixture' });
const quote = (value: string): string => `'${value.replaceAll("'", String.raw`'\''`)}'`;

bunTest.test('policy denials distinguish unsafe effects from unsupported inspection', () => {
  const deletion = inspect(`python3 -c ${quote('import os; os.unlink("/protected")')}`);
  bunTest.expect(deletion.kind).toBe('deny');
  bunTest.expect(deletion.message).toContain('outside a verified safe scope');
  bunTest.expect(deletion.message).not.toContain('could not complete');
  bunTest.expect(deletion.message).not.toContain('Named script');
  const unsupported = inspect(`node -e ${quote('require("./uninspected.js")')}`);
  bunTest.expect(unsupported.kind).toBe('deny');
  bunTest.expect(unsupported.message).toContain('could not complete inline-code inspection');
});

bunTest.test.each([
  'pnpm install --offline',
  'pnpm install --force --frozen-lockfile --prefer-offline',
  'pnpm --dir server install --ignore-scripts',
  'npm ci',
  'yarn install --immutable',
  'pnpm run install',
  'npm run install',
  'npm rm example',
  'pnpm rm example',
  'npm unlink example',
  'pnpm --dir server rm example',
  'pnpm dlx -c "printf safe"',
  'pnpm --shell-mode dlx printf safe',
  'node -v',
  'node --version',
  'mise which node',
  'mise where node',
  'mise --quiet which node',
  'mise -C /tmp --quiet which node',
  'rsync -an --exclude=node_modules /tmp/a/ /tmp/b/',
  'rsync --archive --dry-run --exclude node_modules --include "*.ts" /tmp/a/ /tmp/b/',
])('permits a supported command without executing it: %s', (command) => {
  const result = inspect(command);
  bunTest.expect(result.kind, result.message).toBe('allow');
});

bunTest.test.each([
  'pnpm exec install /tmp/example /example/.env',
  'pnpm exec rm -rf /protected',
  'npm exec -- rm -rf /protected',
  'pnpm dlx node -e \'require("fs").unlinkSync("/protected")\'',
  'yarn dlx node -e \'require("fs").unlinkSync("/protected")\'',
  'pnpm --package=node dlx node -e \'require("fs").unlinkSync("/protected")\'',
  'yarn dlx --package=node node -e \'require("fs").unlinkSync("/protected")\'',
  'pnpm dlx sh -c "rm -rf /protected"',
  'pnpm dlx -c rm -rf /protected',
  'pnpm --shell-mode dlx "printf safe; rm -rf /protected"',
  'pnpm dlx --allow-build example node -e \'require("fs").unlinkSync("/protected")\'',
  'pnpm install --offline; rm -rf /protected',
  'node -v -e \'require("fs").unlinkSync("/protected")\'',
  'python3 -v -c \'import os; os.unlink("/protected")\'',
  'mise which node; rm -rf /protected',
  'mise exec -- rm -rf /protected',
  'mise --quiet exec -- rm -rf /protected',
  'rsync -an --exclude=node_modules /tmp/a/ /example/.ssh/',
  'rsync -an --exclude node_modules /example/.env /tmp/b/',
  'rsync -an --exclude=node_modules host:/example /tmp/b/',
  'rsync -an --exclude-from /example/.env /tmp/a/ /tmp/b/',
  'rsync -an --exclude',
])('keeps executable and protected-path checks: %s', (command) => {
  bunTest.expect(inspect(command).kind).toBe('deny');
});

bunTest.test.each([
  'print(isinstance({}, (list, dict)))',
  'from collections import defaultdict; d=defaultdict(int); d["x"]+=1; print(d)',
  'print("prefix-text".removeprefix("prefix-").removesuffix("text"))',
  'print("abcabc".rindex("a"))',
  'import zipfile; z=zipfile.ZipFile("/tmp/example.zip"); print(z.infolist())',
  'import zipfile; print(zipfile.ZipFile("/tmp/example.zip").infolist()[0].filename)',
  'import zipfile; print(zipfile.ZipFile("/tmp/example.zip").infolist()[-1].is_dir())',
  'import zipfile\nfor i in zipfile.ZipFile("/tmp/example.zip").infolist():\n print(i.filename, i.file_size, i.is_dir())',
])('permits inert Python data: %s', (source) => {
  const result = inspect(`python3 -c ${quote(source)}`);
  bunTest.expect(result.kind, result.message).toBe('allow');
});

bunTest.test.each([
  'console.log([1,2].at(-1))',
  String.raw`const fs=require("fs"); const lines=fs.readFileSync("/tmp/example.log","utf8").trim().split("\n"); console.log(JSON.parse(lines.at(-1)))`,
])('permits inert JavaScript data: %s', (source) => {
  const result = inspect(`node -e ${quote(source)}`);
  bunTest.expect(result.kind, result.message).toBe('allow');
});

bunTest.test.each([
  'from collections import defaultdict; import os; d=defaultdict(os.getpid); print(d["x"])',
  'import os; print(isinstance({}, (dict, os.system)))',
  'import zipfile; z=zipfile.ZipFile("/example/.env"); print(z.infolist())',
  'import zipfile; open(zipfile.ZipFile("/tmp/example.zip").infolist()[0].filename,"w").write("x")',
  'import zipfile\nfor i in zipfile.ZipFile("/tmp/example.zip").infolist():\n open(i.filename,"w").write("x")',
  'import zipfile; zipfile.ZipFile("/tmp/example.zip").extractall("/tmp/output")',
])('does not authorize effects through Python data: %s', (source) => {
  bunTest.expect(inspect(`python3 -c ${quote(source)}`).kind).toBe('deny');
});

bunTest.test.each([
  'const fs=require("fs"); [fs.unlinkSync].at(0)("/protected")',
  'const fs=require("fs"); fs.unlinkSync(["/protected"].at(0))',
  'const fs=require("fs"); console.log([1].at(fs.unlinkSync("/protected")))',
])('does not authorize effects through JavaScript data: %s', (source) => {
  bunTest.expect(inspect(`node -e ${quote(source)}`).kind).toBe('deny');
});

bunTest.test('rm unlinks a final temporary link but still checks traversal', () => {
  const cwd = mkdtempSync(path.join(tmpdir(), 'tripwire-unlink-'));

  try {
    const link = path.join(cwd, 'link');
    symlinkSync('/protected', link);

    for (const command of [`rm ${quote(link)}`, `rm -rf ${quote(link)}`]) {
      bunTest.expect(decideBash(command, {}, { cwd }).kind).toBe('allow');
    }

    for (const target of [`${link}/`, `${link}/child`, `${link}/.`]) {
      bunTest.expect(decideBash(`rm -rf ${quote(target)}`, {}, { cwd }).kind).toBe('deny');
    }
  } finally {
    rmSync(cwd, { recursive: true, force: true });
  }
});
