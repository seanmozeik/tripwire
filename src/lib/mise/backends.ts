import path from 'node:path';

import { coreTool } from './config';
import { entries, parseToml, readOptional, record } from './files';
import { MiseInspectionError, assertSafe } from './inspection-error';

const checkEntry = (filename: string, tool: string, value: unknown): void => {
  if (value !== undefined) {
    const entry = record(value, `${filename}: backend ${tool}`);
    assertSafe(
      coreTool(tool) &&
        entry['full'] === `core:${tool}` &&
        (entry['short'] === undefined || entry['short'] === tool) &&
        (entry['opts'] === undefined ||
          Object.keys(record(entry['opts'], `${filename}: ${tool}.opts`)).length === 0),
      `${filename}: unverified backend for ${tool}.`,
    );
  }
};

const legacyEntry = (filename: string, source: string): Record<string, unknown> => {
  if (filename.endsWith('.json')) {
    try {
      const entry = record(JSON.parse(source));
      return { ...entry, full: entry['id'] };
    } catch (cause) {
      if (!(cause instanceof SyntaxError)) {
        throw cause;
      }
      throw new MiseInspectionError(`JSON parse error in ${filename}.`);
    }
  }
  const [short, full] = source.split(/\r?\n/u).filter((line) => line !== '');
  return { short, full };
};

// Mise v2026.9.12 toolset/install_state.rs: check all metadata formats,
// conservatively including shadowed entries. Mere file presence is not a plugin.
const checkBackends = (installs: string, plugins: string, tools: ReadonlySet<string>): void => {
  const manifestFile = path.join(installs, '.mise-installs.toml');
  const source = readOptional(manifestFile);
  const manifest = source === null ? {} : record(parseToml(manifestFile, source), manifestFile);
  const installedPlugins = new Set(entries(plugins));
  for (const tool of tools) {
    assertSafe(!installedPlugins.has(tool), `Unverified mise plugin ${path.join(plugins, tool)}.`);
    checkEntry(manifestFile, tool, manifest[tool]);
    for (const name of ['.mise.backend', '.mise.backend.json', '.mise.backend.toml']) {
      const filename = path.join(installs, tool, name);
      const metadata = readOptional(filename);
      if (metadata !== null) {
        checkEntry(
          filename,
          tool,
          name.endsWith('.toml') ? parseToml(filename, metadata) : legacyEntry(filename, metadata),
        );
      }
    }
  }
};

export { checkBackends };
