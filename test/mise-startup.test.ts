import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decideBash } from '../src/dispatch';

let root = '';
let previous: Record<string, string | undefined> = {};
const write = (name: string, source: string): void => {
  const filename = path.join(root, name);
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, source);
};
const inspect = (wrapper = 'mise exec --', code = 'print(1)'): string =>
  decideBash(`${wrapper} python3 -c '${code}'`, {}, { cwd: path.join(root, 'project/child') }).kind;

bunTest.beforeEach(() => {
  previous = { ...process.env };
  root = mkdtempSync(path.join(tmpdir(), 'mise-fixture-'));
  mkdirSync(path.join(root, 'project/child'), { recursive: true });
  process.env['HOME'] = path.join(root, 'home');
  process.env['MISE_CONFIG_DIR'] = path.join(root, 'global');
  process.env['MISE_SYSTEM_CONFIG_DIR'] = path.join(root, 'system');
  process.env['MISE_DATA_DIR'] = path.join(root, 'data');
  process.env['MISE_CEILING_PATHS'] = root;
});
bunTest.afterEach(() => {
  for (const name of Object.keys(process.env)) {
    if (!(name in previous)) {
      Reflect.deleteProperty(process.env, name);
    }
  }
  Object.assign(process.env, previous);
  rmSync(root, { recursive: true, force: true });
});

bunTest.test.each([
  'mise exec --',
  'mise x --',
  'mise exec python@3.13 --',
  'mise exec core:python@3.13 --',
  'mise exec -C .. --',
  'mise -C .. exec --',
  'mise exec --cd=.. --',
])('safe version and env with dangerous twin: %s', (wrapper) => {
  write('project/mise.toml', '[tools]\npython="3.13"\n[env]\nEXAMPLE_LABEL="fictional"');
  bunTest.expect(inspect(wrapper)).toBe('allow');
  bunTest.expect(inspect(wrapper, 'import os; os.remove("/")')).toBe('deny');
  write('project/mise.toml', '[env]\nPYTHONSTARTUP="payload.py"');
  bunTest.expect(inspect(wrapper)).toBe('deny');
});

bunTest.test.each([
  'project/mise.toml',
  'project/.mise.toml',
  'project/mise.local.toml',
  'project/.mise.local.toml',
  'project/.config/mise/config.toml',
  'project/.config/mise/mise.toml',
  'project/.config/mise.toml',
  'project/.mise/config.toml',
  'project/mise/config.toml',
  'project/.config/mise/config.local.toml',
  'project/.config/mise/mise.local.toml',
  'project/.config/mise.local.toml',
  'project/.mise/config.local.toml',
  'project/mise/config.local.toml',
  'project/.config/mise/conf.d/example.toml',
  'project/.mise/conf.d/example.toml',
  'project/mise/conf.d/example.toml',
  'global/config.toml',
  'global/mise.local.toml',
  'global/conf.d/example.toml',
  'system/config.toml',
  'system/conf.d/example.toml',
])('discovers %s without executing configuration', (filename) => {
  write(filename, '[env]\nEXAMPLE="fictional"');
  bunTest.expect(inspect()).toBe('allow');
  write(filename, '[env]\nNODE_OPTIONS="--require ./fictional.cjs"');
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test.each(['MISE_ENV', 'MISE_ENVIRONMENT'])(
  'loads comma separated profiles from %s',
  (variable) => {
    process.env[variable] = 'example,other';
    write('project/mise.other.local.toml', '[tools]\nnode="22"');
    bunTest.expect(inspect()).toBe('allow');
    write('project/mise.other.local.toml', '[env]\nPYTHONPATH="fictional"');
    bunTest.expect(inspect()).toBe('deny');
  },
);

bunTest.test.each(['MISE_CONFIG_FILE', 'MISE_GLOBAL_CONFIG_FILE', 'MISE_SYSTEM_CONFIG_FILE'])(
  'loads explicit %s',
  (variable) => {
    process.env[variable] = path.join(root, 'override.toml');
    write('override.toml', '[tools]\npython="3.13"');
    bunTest.expect(inspect()).toBe('allow');
    write('override.toml', '[hooks]\nenter="echo fictional"');
    bunTest.expect(inspect()).toBe('deny');
  },
);

bunTest.test('early config and command line select profiles', () => {
  write('project/.miserc.toml', 'env=["example"]');
  write('project/.mise.example.toml', '[env]\nEXAMPLE="fictional"');
  bunTest.expect(inspect()).toBe('allow');
  bunTest.expect(inspect('mise -E example exec --')).toBe('allow');
  write('project/.mise.example.toml', '[env]\nBUN_OPTIONS="--preload ./fictional.js"');
  bunTest.expect(inspect()).toBe('deny');
  bunTest.expect(inspect('mise -E example exec --')).toBe('deny');
});

bunTest.test('dotenv is read statically and checked', () => {
  write('project/mise.toml', '[env._]\nfile="fictional.env"');
  write('project/fictional.env', 'EXAMPLE="fictional"');
  bunTest.expect(inspect()).toBe('allow');
  write('project/fictional.env', 'NODE_OPTIONS=--require ./fictional.js');
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test('tool versions and backend metadata retain core-only startup', () => {
  write('project/.tool-versions', 'python 3.13\nnode 22 # fictional');
  write('data/installs/.mise-installs.toml', '[python]\nshort="python"\nfull="core:python"');
  bunTest.expect(inspect()).toBe('allow');
  write('data/installs/.mise-installs.toml', '[python]\nshort="python"\nfull="asdf:python"');
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test.each([
  '[env',
  '[env]\nEXAMPLE="{{ exec(command=\'echo fictional\') }}"',
  '[env._]\nsource="fictional.sh"',
  '[env._]\npath="bin"',
  '[env._]\nfile="missing.env"',
  '[hooks]\nenter="echo fictional"',
  '[tools]\n"asdf:python"="3.13"',
  '[tools]\n"vfox:python"="3.13"',
  '[plugins]\npython="https://example.invalid/plugin"',
  '[tools]\npython={version="3.13",postinstall="echo fictional"}',
  '[env]\nPATH="./bin"',
  '[settings]\nexperimental=true',
  'dotenv="missing.env"',
])('unsafe config has an allow control: %s', (config) => {
  write('project/mise.toml', '[tools]\npython="3.13"');
  bunTest.expect(inspect()).toBe('allow');
  write('project/mise.toml', config);
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test.each([
  'MISE_OVERRIDE_UNKNOWN_FILENAMES',
  'MISE_NODE_VERSION',
  'MISE_ENV_FILE',
  'MISE_UNKNOWN_SETTING',
])('unknown override %s fails closed', (variable) => {
  bunTest.expect(inspect()).toBe('allow');
  process.env[variable] = 'fictional';
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test('unknown cwd, plugins, and modified shell discovery cannot authorize startup', () => {
  bunTest.expect(inspect()).toBe('allow');
  bunTest
    .expect(decideBash("mise exec -- python3 -c 'print(1)'", {}, { cwd: null }).kind)
    .toBe('deny');
  bunTest.expect(inspect('mise exec -C "$UNKNOWN" --')).toBe('deny');
  bunTest.expect(inspect('MISE_CONFIG_FILE="$UNKNOWN" mise exec --')).toBe('deny');
  write('data/plugins/python/bin/exec-env', 'echo fictional');
  write('project/mise.toml', '[tools]\npython="3.13"');
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test.each([
  'project/.config/mise/config.toml',
  'project/.mise/conf.d/example.toml',
  'global/config.toml',
])('dotenv uses mise config root for %s', (filename) => {
  const directory = filename.startsWith('global') ? 'home' : 'project';
  write(filename, '[env._]\nfile="fictional.env"');
  write(`${directory}/fictional.env`, 'EXAMPLE=fictional');
  bunTest.expect(inspect()).toBe('allow');
  write(`${directory}/fictional.env`, 'PYTHONSTARTUP=fictional.py');
  write(path.join(path.dirname(filename), 'fictional.env'), 'EXAMPLE=decoy');
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test('earlier commands cannot alter checked configuration', () => {
  write('project/mise.toml', '[tools]\npython="3.13"');
  bunTest.expect(inspect()).toBe('allow');
  bunTest.expect(inspect('cp fictional.toml ../mise.toml; mise exec --')).toBe('deny');
  bunTest.expect(inspect('printf fictional > ../mise.toml; mise exec --')).toBe('deny');
  bunTest.expect(inspect('env MISE_ENV=unknown mise exec --')).toBe('deny');
});

bunTest.test.each(['MISE_OVERRIDE_CONFIG_FILENAMES', 'MISE_DEFAULT_CONFIG_FILENAME'])(
  'static config filenames from %s',
  (variable) => {
    process.env[variable] = 'fictional.toml';
    write('project/fictional.toml', '[tools]\npython="3.13"');
    bunTest.expect(inspect()).toBe('allow');
    write('project/fictional.toml', '[env]\nPYTHONHOME="fictional"');
    bunTest.expect(inspect()).toBe('deny');
  },
);

bunTest.test.each(['MISE_OVERRIDE_TOOL_VERSIONS_FILENAMES', 'MISE_DEFAULT_TOOL_VERSIONS_FILENAME'])(
  'static tool-version filenames from %s',
  (variable) => {
    process.env[variable] = '.fictional-versions';
    write('project/.fictional-versions', 'python 3.13');
    bunTest.expect(inspect()).toBe('allow');
    write('project/.fictional-versions', 'asdf:python 3.13');
    bunTest.expect(inspect()).toBe('deny');
  },
);

bunTest.test('separate mise commands do not change a bare interpreter context', () => {
  const command =
    "python3 -c 'print(1)'; mise exec -- printf fictional > example.txt; python3 -c 'print(2)'";
  bunTest.expect(decideBash(command, {}, { cwd: root }).kind).toBe('allow');
  bunTest
    .expect(
      decideBash(command.replace('print(2)', 'import os; os.remove("/")'), {}, { cwd: root }).kind,
    )
    .toBe('deny');
});

bunTest.test.each([
  '[tasks.example]\nrun="{{ exec(command=\'echo fictional\') }}"',
  String.raw`[tasks.example]
run="\u007b\u007b exec(command='echo fictional') }}"`,
])('task templates cannot execute while config loads: %s', (config) => {
  write('project/mise.toml', '[tasks.example]\nrun="echo fictional"');
  bunTest.expect(inspect()).toBe('allow');
  write('project/mise.toml', config);
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test('early profile lists are bounded', () => {
  write('project/.miserc.toml', 'env=["example"]');
  bunTest.expect(inspect()).toBe('allow');
  write(
    'project/.miserc.toml',
    `env=${JSON.stringify(Array.from({ length: 17 }, (_, index) => `example${index}`))}`,
  );
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test('default filenames cannot be mistaken for override filename lists', () => {
  process.env['MISE_DEFAULT_CONFIG_FILENAME'] = 'fictional.toml';
  write('project/fictional.toml', '[tools]\npython="3.13"');
  bunTest.expect(inspect()).toBe('allow');
  process.env['MISE_DEFAULT_CONFIG_FILENAME'] = 'fictional.toml:other.toml';
  write('project/fictional.toml:other.toml', '[env]\nNODE_OPTIONS="--require fictional"');
  bunTest.expect(inspect()).toBe('deny');
});

bunTest.test.each([
  ['.mise.backend', 'python\ncore:python\n', 'python\nasdf:python\n'],
  [
    '.mise.backend.json',
    '{"short":"python","id":"core:python"}',
    '{"short":"python","id":"asdf:python"}',
  ],
  [
    '.mise.backend.toml',
    'short="python"\nfull="core:python"',
    'short="python"\nfull="asdf:python"',
  ],
])('core metadata is inspected rather than rejected: %s', (name, safe, unsafe) => {
  write('project/mise.toml', '[tools]\npython="3.13"');
  const filename = `data/installs/python/${name}`;
  write(filename, safe);
  bunTest.expect(inspect()).toBe('allow');
  write(filename, unsafe);
  const decision = decideBash(
    "mise exec -- python3 -c 'print(1)'",
    {},
    { cwd: path.join(root, 'project') },
  );
  bunTest.expect(decision.kind).toBe('deny');
  bunTest.expect(decision.message).toContain(filename);
  bunTest.expect(decision.message).toContain('python');
});

bunTest.test.each([
  ['[env]\nPYTHONPATH="payload"', 'env.PYTHONPATH'],
  ['[env._]\nsource="payload.sh"', 'env._.source'],
  ['[env._]\nfile="*.env"', 'env._.file'],
  ['[tools]\n"asdf:python"="3.13"', 'tools.asdf:python'],
  ['[settings]\nenv_cache=true', 'settings.env_cache'],
  ['[settings.ruby]\ncompile="unknown"', 'settings.ruby.compile'],
  ['[hooks]\nenter="echo example"', 'hooks'],
  ['[env', 'TOML parse error'],
])('mise denial identifies config and key or parser: %s', (config, reason) => {
  write('project/mise.toml', config);
  const decision = decideBash(
    "mise exec -- python3 -c 'print(1)'",
    {},
    { cwd: path.join(root, 'project') },
  );
  bunTest.expect(decision.kind).toBe('deny');
  bunTest.expect(decision.message).toContain(path.join(root, 'project/mise.toml'));
  bunTest.expect(decision.message).toContain(reason);
});

bunTest.test.each(['zsh', 'bash', 'fish', 'nu', 'elvish', 'pwsh', 'xonsh'])(
  'inherited %s activation bookkeeping does not add startup effects',
  (shell) => {
    process.env['MISE_SHELL'] = shell;
    for (const name of [
      '__MISE_DIFF',
      '__MISE_ORIG_PATH',
      '__MISE_SESSION',
      '__MISE_LAST_UNTRUSTED_CONFIG_WARNING_KEY',
      '__MISE_ZSH_ACTIVATE_ENV',
      '__MISE_ZSH_ACTIVATE_PATH',
      '__MISE_ZSH_CHPWD_RAN',
      '__MISE_ZSH_PRECMD_RUN',
      '__MISE_BASH_CHPWD_RAN',
      '__MISE_BASH_SKIP_FIRST_PROMPT',
      '__MISE_EXE',
      '__MISE_FLAGS',
      '__MISE_HOOK_ENABLED',
    ]) {
      process.env[name] = 'fictional';
    }
    process.env['PYTHONPATH'] = 'inherited';
    write('project/mise.toml', '[tools]\npython="3.13"');
    bunTest.expect(inspect()).toBe('allow');
    write('project/mise.toml', '[env]\nPYTHONPATH="added-by-mise"');
    bunTest.expect(inspect()).toBe('deny');
  },
);

bunTest.test.each([
  '__MISE_SCRIPT',
  '__MISE_SHIM',
  '__MISE_ENV_CACHE_KEY',
  '__MISE_UNKNOWN',
  'MISE_UNKNOWN_SETTING',
])('unsupported environment names are reported: %s', (name) => {
  process.env[name] = 'fictional';
  const decision = decideBash("mise exec -- python3 -c 'print(1)'", {}, { cwd: root });
  bunTest.expect(decision.kind).toBe('deny');
  bunTest.expect(decision.message).toContain(name);
});

bunTest.test('settings retain plugin and startup boundaries', () => {
  write(
    'global/config.toml',
    '[tools]\npython="3.13"\n[settings]\nidiomatic_version_file_enable_tools=["ruby"]\n[settings.ruby]\ncompile=false',
  );
  bunTest.expect(inspect()).toBe('allow');
  write('data/plugins/ruby/bin/list-idiomatic-filenames', 'echo fictional');
  const decision = decideBash("mise exec -- python3 -c 'print(1)'", {}, { cwd: root });
  bunTest.expect(decision.kind).toBe('deny');
  bunTest.expect(decision.message).toContain('data/plugins/ruby');
});

bunTest.test('submitted activation mutations cannot reuse inherited bookkeeping approval', () => {
  bunTest.expect(inspect('__MISE_DIFF=fictional mise exec --')).toBe('deny');
  write('project/mise.toml', '[env]\n__MISE_DIFF="fictional"');
  bunTest.expect(inspect()).toBe('deny');
});
