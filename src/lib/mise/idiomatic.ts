import path from 'node:path';

import { coreTool } from './config';
import { entries, readOptional } from './files';
import { assertPackageJson } from './idiomatic-package';
import { assertVersionSelector, stripBom, versionLines } from './idiomatic-version';
import { assertSafe } from './inspection-error';

// Mise v2026.9.12 registry/*.toml; backend/mod.rs adds these to backend filenames.
const IDIOMATIC_FILES: Readonly<Record<string, readonly string[]>> = {
  atmos: ['.atmos-version'],
  bazel: ['.bazelversion'],
  bun: ['.bun-version', 'package.json'],
  chezmoi: ['.chezmoiversion'],
  cmake: ['CMakeLists.txt'],
  crystal: ['.crystal-version'],
  dagger: ['dagger.json'],
  deno: ['.deno-version', 'package.json'],
  dotnet: ['global.json'],
  earthly: ['Earthfile'],
  elixir: ['.exenv-version'],
  go: ['.go-version', 'go.mod', 'go.work'],
  'golangci-lint': ['.golangci.yml', '.golangci.yaml', '.golangci.toml', '.golangci.json'],
  goreleaser: [
    '.config/goreleaser.yml',
    '.config/goreleaser.yaml',
    '.goreleaser.yml',
    '.goreleaser.yaml',
    'goreleaser.yml',
    'goreleaser.yaml',
  ],
  java: ['.java-version', '.sdkmanrc'],
  lefthook: [
    'lefthook.yml',
    'lefthook.yaml',
    '.lefthook.yml',
    '.lefthook.yaml',
    'lefthook.toml',
    '.lefthook.toml',
    'lefthook.json',
    '.lefthook.json',
    'lefthook.jsonc',
    '.lefthook.jsonc',
    '.config/lefthook.yml',
    '.config/lefthook.yaml',
    '.config/lefthook.toml',
    '.config/lefthook.json',
    '.config/lefthook.jsonc',
  ],
  node: ['.nvmrc', '.node-version', 'package.json'],
  npm: ['package.json'],
  opentofu: ['.opentofu-version'],
  packer: ['.packer-version'],
  perl: ['.perl-version'],
  pixi: ['pixi.toml', 'pyproject.toml'],
  pnpm: ['package.json'],
  'pre-commit': ['.pre-commit-config.yaml'],
  python: ['.python-version', '.python-versions'],
  ruby: ['.ruby-version', 'Gemfile'],
  ruff: ['ruff.toml', '.ruff.toml'],
  rust: ['rust-toolchain.toml'],
  swift: ['.swift-version'],
  task: ['Taskfile.yml', 'Taskfile.yaml', 'taskfile.yml', 'taskfile.yaml'],
  terraform: ['.terraform-version'],
  terragrunt: ['.terragrunt-version'],
  terramate: ['.terramate-version'],
  yarn: ['.yvmrc', 'package.json'],
  zig: ['.zig-version'],
};

// The remaining structured readers require their own parsers. Never mistake a
// scalar-looking body for a successfully parsed Gemfile, TOML, JSON, or Go file.
const PLAIN_FILES = new Set([
  '.atmos-version',
  '.bun-version',
  '.chezmoiversion',
  '.crystal-version',
  '.deno-version',
  '.exenv-version',
  '.go-version',
  '.java-version',
  '.nvmrc',
  '.node-version',
  '.opentofu-version',
  '.packer-version',
  '.perl-version',
  '.python-version',
  '.python-versions',
  '.ruby-version',
  '.swift-version',
  '.terraform-version',
  '.terragrunt-version',
  '.terramate-version',
  '.yvmrc',
  '.zig-version',
]);

const assertIdiomaticSource = (source: string, filename: string, tool: string): void => {
  const name = path.basename(filename);
  if (name === 'package.json') {
    assertPackageJson(source, filename, tool);
    return;
  }
  if (name === '.bazelversion') {
    // Registry/bazel.toml anchors its numeric capture to the first line.
    const version =
      /^[\t ]*v?(?<version>[0-9]+\.[0-9]+(?:\.[0-9]+)?[0-9A-Za-z.-]*)[\t ]*\r?$/u.exec(
        stripBom(source).split('\n')[0] ?? '',
      )?.groups?.['version'];
    assertVersionSelector(version, `${filename}: version for ${tool}`);
    return;
  }
  assertSafe(PLAIN_FILES.has(name), `${filename}: unsupported idiomatic file format for ${tool}.`);
  const lines = versionLines(source);
  // Core node/java consume lines; ruby/go consume the whole normalized body.
  // All other plain readers inherit backend/mod.rs's whitespace tokenization.
  let values: string[];
  if (tool === 'ruby' || tool === 'go') {
    const body = lines.join('\n');
    values =
      lines.length === 0
        ? []
        : [(tool === 'ruby' ? body.replace(/^(?:ruby-)*/u, '') : body).replace(/^v*/u, '')];
  } else if (tool === 'node' || tool === 'java') {
    values = lines;
  } else {
    values = lines.flatMap((line) => line.split(/\p{White_Space}+/u));
  }
  for (const value of values) {
    assertVersionSelector(value, `${filename}: version for ${tool}`);
  }
};

const assertIdiomaticFiles = (
  parents: ReadonlySet<string>,
  tools: ReadonlySet<string>,
  plugins: string,
): void => {
  const installed = new Set(entries(plugins));
  for (const tool of tools) {
    assertSafe(
      coreTool(tool) || !installed.has(tool),
      `Unverified mise plugin ${path.join(plugins, tool)} for idiomatic version files.`,
    );
    const filenames = Object.hasOwn(IDIOMATIC_FILES, tool) ? (IDIOMATIC_FILES[tool] ?? []) : [];
    for (const parent of parents) {
      for (const name of filenames) {
        const filename = path.join(parent, name);
        const source = readOptional(filename);
        if (source !== null) {
          assertIdiomaticSource(source, filename, tool);
        }
      }
    }
  }
};

export { assertIdiomaticFiles };
