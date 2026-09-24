import * as bunTest from 'bun:test';
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

const entry = new URL('../src/main.ts', import.meta.url).pathname;

bunTest.test('mise startup in a real process with an activated shell and global settings', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'mise-process-'));
  const home = path.join(root, 'home');
  const project = path.join(root, 'project');
  const cwd = path.join(project, 'child');
  const config = path.join(home, '.config/mise/config.toml');
  mkdirSync(path.dirname(config), { recursive: true });
  cpSync(new URL('fixtures/mise-idiomatic', import.meta.url), project, { recursive: true });
  const searchPath = [
    path.join(home, '.local/share/mise/installs/python/3.13/bin'),
    path.join(home, '.local/share/mise/shims'),
    path.join(home, '.local/bin'),
    '/opt/homebrew/bin',
    '/usr/local/bin',
    '/usr/bin',
    '/bin',
  ].join(path.delimiter);
  const env = {
    HOME: home,
    PATH: searchPath,
    MISE_SYSTEM_CONFIG_DIR: path.join(root, 'system'),
    MISE_CEILING_PATHS: root,
    MISE_SHELL: 'zsh',
    // Mise's zlib/base64 MessagePack EnvDiff: old={}, new={PYTHONPATH: 'inherited'}, path=[].
    __MISE_DIFF: 'eJxrXpyfk9KwOC+1vHFVQGSIh79fgGOIx8rMvIzUosyS1JQlBYklGRMAQoYQUw',
    __MISE_ORIG_PATH: '/usr/bin:/bin',
    __MISE_SESSION: '',
    __MISE_ZSH_ACTIVATE_ENV: '',
    __MISE_ZSH_ACTIVATE_PATH: searchPath,
    __MISE_ZSH_CHPWD_RAN: '1',
    __MISE_ZSH_PRECMD_RUN: '1',
    // Inherited startup state is also inherited by a plain interpreter.
    PYTHONPATH: 'inherited',
  };
  const run = (code: string): string => {
    const child = Bun.spawnSync([process.execPath, entry, '--tripwire-hook'], {
      cwd,
      env,
      stdin: new TextEncoder().encode(
        JSON.stringify({
          hook_event_name: 'PreToolUse',
          tool_name: 'Bash',
          cwd,
          tool_input: { command: `mise exec -- python3 -c '${code}'` },
        }),
      ),
      stdout: 'pipe',
      stderr: 'pipe',
    });
    bunTest.expect(child.exitCode).toBe(0);
    return child.stdout.toString();
  };
  try {
    const backend = path.join(home, '.local/share/mise/installs/python/.mise.backend.toml');
    mkdirSync(path.dirname(backend), { recursive: true });
    writeFileSync(backend, 'short="python"\nfull="core:python"\nexplicit_backend=true');
    writeFileSync(
      config,
      '[tools]\npython="3.13"\n[settings]\nidiomatic_version_file_enable_tools=["python","node","bun","deno","npm","pnpm","yarn"]\n[settings.ruby]\ncompile=false\n',
    );
    bunTest.expect(run('print(1)').trim()).toBe('{"continue": true}');
    bunTest.expect(run('import os; os.remove("/")')).toContain('"deny"');
    for (const value of [
      'path:./payload',
      'https://example.invalid/node',
      'asdf:fictional',
      '$(echo fictional)',
    ]) {
      writeFileSync(path.join(cwd, '.nvmrc'), value);
      const deniedVersion = run('print(1)');
      bunTest.expect(deniedVersion).toContain('"deny"');
      bunTest.expect(deniedVersion).toContain('.nvmrc');
    }
    writeFileSync(path.join(cwd, '.nvmrc'), 'lts/*');
    writeFileSync(path.join(cwd, 'package.json'), '{"packageManager":"pnpm@file:./payload"}');
    const deniedPackage = run('print(1)');
    bunTest.expect(deniedPackage).toContain('"deny"');
    bunTest.expect(deniedPackage).toContain('package.json');
    bunTest.expect(deniedPackage).toContain('packageManager');
    writeFileSync(path.join(cwd, 'package.json'), '{}');
    writeFileSync(path.join(cwd, '.python-version'), '$(echo fictional)');
    const idiomaticDenied = run('print(1)');
    bunTest.expect(idiomaticDenied).toContain('"deny"');
    bunTest.expect(idiomaticDenied).toContain('.python-version');
    writeFileSync(path.join(cwd, '.python-version'), '3.13.1');
    writeFileSync(config, '[tools]\npython="3.13"\n[env]\nPYTHONPATH="payload"\n');
    const denied = run('print(1)');
    bunTest.expect(denied).toContain('"deny"');
    bunTest.expect(denied).toContain(config);
    bunTest.expect(denied).toContain('env.PYTHONPATH');
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
