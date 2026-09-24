import path from 'node:path';

import { coreTool, version } from './config';
import { entries, readOptional } from './files';
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
        assertSafe(
          source === null || version(source.trim()),
          `${filename}: unverified idiomatic version for ${tool}.`,
        );
      }
    }
  }
};

export { assertIdiomaticFiles };
