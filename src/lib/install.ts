// Agent installation module for Tripwire hooks and the native Pi extension.

import { lstat, mkdir, readlink, rename, rm, symlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import pathModule from 'node:path';
import { fileURLToPath } from 'node:url';

import { file } from 'bun';

interface AgentHooksConfig {
  hooks?: {
    PreToolUse?: { hooks: { type: string; command: string; timeout?: number }[] }[];
    PostToolUse?: { hooks: { type: string; command: string; timeout?: number }[] }[];
  };
}

const piExtensionSourceCandidates = [
  pathModule.join(pathModule.dirname(process.execPath), 'tripwire-pi.js'),
  fileURLToPath(new URL('../../dist/tripwire-pi.js', import.meta.url)),
  fileURLToPath(new URL('tripwire-pi.js', import.meta.url)),
];

interface PiInstallOptions {
  readonly extensionSource?: string;
  readonly homeDirectory?: string;
}

interface ExtensionLinkResult {
  readonly action: 'already' | 'installed' | 'updated';
  readonly success: boolean;
}

interface CursorHook {
  command: string;
  type?: string;
  timeout?: number;
  failClosed?: boolean;
}

interface CursorConfig {
  version?: number;
  hooks?: Record<string, CursorHook[]>;
}

const isJsonRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isCommandHook = (
  value: unknown,
): value is { type: string; command: string; timeout?: number } =>
  isJsonRecord(value) &&
  typeof value['type'] === 'string' &&
  typeof value['command'] === 'string' &&
  (value['timeout'] === undefined || typeof value['timeout'] === 'number');

const isHookGroups = (
  value: unknown,
): value is { hooks: { type: string; command: string; timeout?: number }[] }[] =>
  Array.isArray(value) &&
  value.every(
    (group) =>
      isJsonRecord(group) && Array.isArray(group['hooks']) && group['hooks'].every(isCommandHook),
  );

const isAgentHooksConfig = (value: unknown): value is AgentHooksConfig => {
  if (!isJsonRecord(value)) {
    return false;
  }
  const { hooks } = value;
  if (hooks === undefined) {
    return true;
  }
  return (
    isJsonRecord(hooks) &&
    (hooks['PreToolUse'] === undefined || isHookGroups(hooks['PreToolUse'])) &&
    (hooks['PostToolUse'] === undefined || isHookGroups(hooks['PostToolUse']))
  );
};

const parseAgentHooksConfig = (raw: string, label: string): AgentHooksConfig => {
  const value: unknown = JSON.parse(raw);
  if (!isAgentHooksConfig(value)) {
    throw new Error(`${label} hook config has an unsupported shape`);
  }
  return value;
};

const parseCursorConfig = (raw: string): CursorConfig => {
  const value: unknown = JSON.parse(raw);
  if (!isJsonRecord(value)) {
    throw new Error('Cursor hooks.json must contain a JSON object');
  }
  const { hooks } = value;
  if (hooks === undefined) {
    return value;
  }
  if (!isJsonRecord(hooks)) {
    throw new Error('Cursor hooks.json `hooks` must be an object');
  }
  for (const [eventName, eventHooks] of Object.entries(hooks)) {
    if (
      !Array.isArray(eventHooks) ||
      eventHooks.some((hook) => !isJsonRecord(hook) || typeof hook['command'] !== 'string')
    ) {
      throw new Error(`Cursor hooks.json event ${eventName} must contain command hooks`);
    }
  }
  return value;
};

const TRIPWIRE_HOOK = 'tripwire-hook';

const installExtensionLink = async (
  source: string,
  extensionPath: string,
): Promise<ExtensionLinkResult> => {
  await mkdir(pathModule.dirname(extensionPath), { recursive: true });
  try {
    const status = await lstat(extensionPath);
    if (!status.isSymbolicLink()) {
      return { action: 'already', success: false };
    }
    const currentTarget = await readlink(extensionPath);
    if (currentTarget === source) {
      return { action: 'already', success: true };
    }
    const resolvedTarget = pathModule.resolve(pathModule.dirname(extensionPath), currentTarget);
    if (pathModule.basename(resolvedTarget) !== 'tripwire-pi.js') {
      return { action: 'already', success: false };
    }

    const pendingPath = `${extensionPath}.${process.pid}.next`;
    await rm(pendingPath, { force: true });
    try {
      await symlink(source, pendingPath);
      await rename(pendingPath, extensionPath);
    } finally {
      await rm(pendingPath, { force: true });
    }
    return { action: 'updated', success: true };
  } catch (error) {
    if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) {
      throw error;
    }
    await symlink(source, extensionPath);
    return { action: 'installed', success: true };
  }
};

const CURSOR_HOOK_EVENTS = [
  'preToolUse',
  'postToolUse',
  'beforeShellExecution',
  'afterShellExecution',
  'beforeReadFile',
  'afterFileEdit',
] as const;

const CURSOR_FAIL_CLOSED_EVENTS = new Set(['preToolUse', 'beforeShellExecution', 'beforeReadFile']);

const isTripwireCommand = (command: string): boolean =>
  command === TRIPWIRE_HOOK ||
  command.startsWith(`${TRIPWIRE_HOOK} `) ||
  command.includes('/tripwire-hook') ||
  command.includes('/tripwire.js') ||
  command.includes('/dist/tripwire');

const addCursorHook = (
  hooks: CursorHook[] | undefined,
  eventName: string,
): [CursorHook[], boolean] => {
  const failClosed = CURSOR_FAIL_CLOSED_EVENTS.has(eventName);
  const newHook = {
    command: `${TRIPWIRE_HOOK} --cursor-event ${eventName}`,
    ...(failClosed && { failClosed: true }),
  };
  if (hooks === undefined) {
    return [[newHook], true];
  }

  let changed = false;
  const hasTripwire = hooks.some((hook) => isTripwireCommand(hook.command));
  const desiredCommand = `${TRIPWIRE_HOOK} --cursor-event ${eventName}`;
  const normalized = hooks.map((hook) => {
    if (!isTripwireCommand(hook.command)) {
      return hook;
    }
    if (hook.command === desiredCommand && (!failClosed || hook.failClosed === true)) {
      return hook;
    }
    changed = true;
    return { ...hook, command: desiredCommand, ...(failClosed && { failClosed: true }) };
  });

  if (hasTripwire) {
    return [normalized, changed];
  }
  return [[...normalized, newHook], true];
};

const addHookIfMissing = (
  hooks: { hooks: { type: string; command: string; timeout?: number }[] }[] | undefined,
): [{ hooks: { type: string; command: string; timeout?: number }[] }[], boolean] => {
  if (!hooks) {
    const newHooks: { hooks: { type: string; command: string; timeout?: number }[] }[] = [
      { hooks: [{ type: 'command', command: TRIPWIRE_HOOK }] },
    ];
    return [newHooks, false];
  }

  let needsNormalization = false;

  const normalizedHooks = hooks.map((h) => ({
    hooks: h.hooks.map((hook) => {
      if (hook.command === TRIPWIRE_HOOK || hook.command.endsWith('/tripwire-hook')) {
        if (hook.command !== TRIPWIRE_HOOK) {
          needsNormalization = true;
          return { ...hook, command: TRIPWIRE_HOOK };
        }
        return hook;
      }
      return hook;
    }),
  }));

  const hasTripwire = normalizedHooks.some((h) =>
    h.hooks.some((hook) => hook.command === TRIPWIRE_HOOK),
  );

  if (hasTripwire) {
    return [normalizedHooks, !needsNormalization];
  }

  const newHooks: { hooks: { type: string; command: string; timeout?: number }[] }[] = [
    ...normalizedHooks,
    { hooks: [{ type: 'command', command: TRIPWIRE_HOOK }] },
  ];
  return [newHooks, false];
};

export const installClaude = async (): Promise<{ success: boolean; message: string }> => {
  const configPath = `${homedir()}/.claude/settings.json`;
  const configFile = file(configPath);

  try {
    const raw = await configFile.text();
    const config = parseAgentHooksConfig(raw, 'Claude');

    config.hooks ??= {};
    const [preToolUse, preSkipped] = addHookIfMissing(config.hooks.PreToolUse);
    const [postToolUse, postSkipped] = addHookIfMissing(config.hooks.PostToolUse);

    config.hooks.PreToolUse = preToolUse;
    config.hooks.PostToolUse = postToolUse;

    if (preSkipped && postSkipped) {
      return { success: true, message: `Already configured: ${configPath}` };
    }

    await configFile.write(`${JSON.stringify(config, null, 2)}\n`);

    return { success: true, message: `Updated ${configPath}` };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('No such file')) {
      return { success: false, message: `Config file not found: ${configPath}` };
    }
    return { success: false, message: `Failed to update Claude config: ${message}` };
  }
};

export const installPi = async (
  options: PiInstallOptions = {},
): Promise<{ success: boolean; message: string }> => {
  const homeDirectory = options.homeDirectory ?? homedir();
  const configPath = `${homeDirectory}/.pi/agent/settings.json`;
  const configFile = file(configPath);
  const extensionPath = `${homeDirectory}/.pi/agent/extensions/tripwire.js`;

  try {
    const source =
      options.extensionSource ??
      piExtensionSourceCandidates.find((candidate) => Bun.file(candidate).size > 0);
    if (source === undefined) {
      return { success: false, message: 'Built Pi extension not found; run `bun run build` first' };
    }
    const raw = await configFile.text();
    let config = parseAgentHooksConfig(raw, 'Pi');
    if (config.hooks !== undefined) {
      const { PreToolUse, PostToolUse, ...otherHooks } = config.hooks;
      const cleanGroups = (
        groups: { hooks: { type: string; command: string; timeout?: number }[] }[] | undefined,
      ) =>
        groups
          ?.map((group) => ({
            ...group,
            hooks: group.hooks.filter((hook) => !isTripwireCommand(hook.command)),
          }))
          .filter((group) => group.hooks.length > 0) ?? [];
      const cleanPreToolUse = cleanGroups(PreToolUse);
      const cleanPostToolUse = cleanGroups(PostToolUse);
      const nextHooks = {
        ...otherHooks,
        ...(cleanPreToolUse.length > 0 && { PreToolUse: cleanPreToolUse }),
        ...(cleanPostToolUse.length > 0 && { PostToolUse: cleanPostToolUse }),
      };
      if (Object.keys(nextHooks).length === 0) {
        const { hooks: _removedHooks, ...configWithoutHooks } = config;
        config = configWithoutHooks;
      } else {
        config.hooks = nextHooks;
      }
    }
    const link = await installExtensionLink(source, extensionPath);
    if (!link.success) {
      return {
        success: false,
        message: `Refusing to replace existing Pi extension: ${extensionPath}`,
      };
    }
    await configFile.write(`${JSON.stringify(config, null, 2)}\n`);
    const verb = link.action === 'updated' ? 'Updated' : 'Installed';
    return { success: true, message: `${verb} ${extensionPath}` };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('No such file')) {
      return { success: false, message: `Config file not found: ${configPath}` };
    }
    return { success: false, message: `Failed to update pi config: ${message}` };
  }
};

export const installOhMyPi = async (
  options: PiInstallOptions = {},
): Promise<{ success: boolean; message: string }> => {
  const homeDirectory = options.homeDirectory ?? homedir();
  const extensionPath = `${homeDirectory}/.omp/agent/extensions/tripwire.js`;
  try {
    const source =
      options.extensionSource ??
      piExtensionSourceCandidates.find((candidate) => Bun.file(candidate).size > 0);
    if (source === undefined) {
      return { success: false, message: 'Built Pi extension not found; run `bun run build` first' };
    }
    const link = await installExtensionLink(source, extensionPath);
    if (!link.success) {
      return {
        success: false,
        message: `Refusing to replace existing oh-my-pi extension: ${extensionPath}`,
      };
    }
    if (link.action === 'already') {
      return { success: true, message: `Already configured: ${extensionPath}` };
    }
    const verb = link.action === 'updated' ? 'Updated' : 'Installed';
    return { success: true, message: `${verb} ${extensionPath}` };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, message: `Failed to install oh-my-pi extension: ${message}` };
  }
};

export const installCodex = async (): Promise<{ success: boolean; message: string }> => {
  const configTomlPath = `${homedir()}/.codex/config.toml`;
  const hooksJsonPath = `${homedir()}/.codex/hooks.json`;
  const hooksJsonFile = file(hooksJsonPath);
  const configTomlFile = file(configTomlPath);

  let hooksUpdated = false;
  let tomlUpdated = false;

  // First, update hooks.json
  try {
    const raw = await hooksJsonFile.text();
    const config = parseAgentHooksConfig(raw, 'Codex');

    config.hooks ??= {};
    const [preToolUse, preSkipped] = addHookIfMissing(config.hooks.PreToolUse);
    const [postToolUse, postSkipped] = addHookIfMissing(config.hooks.PostToolUse);

    config.hooks.PreToolUse = preToolUse;
    config.hooks.PostToolUse = postToolUse;

    if (!preSkipped || !postSkipped) {
      hooksUpdated = true;
    }

    // Add timeout to tripwire-hook if not present
    let timeoutAdded = false;
    const addTimeout = (
      hooks: { hooks: { type: string; command: string; timeout?: number }[] }[] | undefined,
    ): { hooks: { type: string; command: string; timeout?: number }[] }[] => {
      return (
        hooks?.map((h) => ({
          hooks: h.hooks.map((hook) => {
            if (hook.command === TRIPWIRE_HOOK && hook.timeout === undefined) {
              timeoutAdded = true;
              return { ...hook, timeout: 10 };
            }
            return hook;
          }),
        })) ?? []
      );
    };

    config.hooks.PreToolUse = addTimeout(config.hooks.PreToolUse);
    config.hooks.PostToolUse = addTimeout(config.hooks.PostToolUse);
    hooksUpdated ||= timeoutAdded;

    if (hooksUpdated) {
      await hooksJsonFile.write(`${JSON.stringify(config, null, 2)}\n`);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('No such file')) {
      return { success: false, message: `Config file not found: ${hooksJsonPath}` };
    }
    return { success: false, message: `Failed to update Codex hooks.json: ${message}` };
  }

  // Then, update config.toml to enable hooks
  try {
    const raw = await configTomlFile.text();
    let toml = raw;

    // Enable hooks in [features] section
    if (toml.includes('hooks = true')) {
      // Already enabled, nothing to do
    } else {
      tomlUpdated = true;
      if (toml.includes('[features]')) {
        // Find [features] section and add hooks = true
        const featuresIndex = toml.indexOf('[features]');
        const nextSectionIndex = toml.indexOf('\n[', featuresIndex + 1);
        if (nextSectionIndex === -1) {
          toml += '\nhooks = true';
        } else {
          toml = `${toml.slice(0, nextSectionIndex)}\nhooks = true${toml.slice(nextSectionIndex)}`;
        }
      } else {
        toml += '\n[features]\nhooks = true';
      }
    }

    if (tomlUpdated) {
      await configTomlFile.write(toml);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('No such file')) {
      return { success: false, message: `Config file not found: ${configTomlPath}` };
    }
    return { success: false, message: `Failed to update Codex config.toml: ${message}` };
  }

  if (!hooksUpdated && !tomlUpdated) {
    return { success: true, message: `Already configured: ${configTomlPath} and ${hooksJsonPath}` };
  }

  return { success: true, message: `Updated ${configTomlPath} and ${hooksJsonPath}` };
};

export const installCursor = async (): Promise<{ success: boolean; message: string }> => {
  const configPath = `${homedir()}/.cursor/hooks.json`;
  const configFile = file(configPath);

  try {
    const raw = await configFile.text();
    const config = parseCursorConfig(raw);
    config.version ??= 1;
    config.hooks ??= {};

    let updated = false;
    for (const eventName of CURSOR_HOOK_EVENTS) {
      const [hooks, changed] = addCursorHook(config.hooks[eventName], eventName);
      config.hooks[eventName] = hooks;
      updated ||= changed;
    }

    if (!updated) {
      return { success: true, message: `Already configured: ${configPath}` };
    }
    await configFile.write(`${JSON.stringify(config, null, 2)}\n`);
    return { success: true, message: `Updated ${configPath}` };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('No such file')) {
      return { success: false, message: `Config file not found: ${configPath}` };
    }
    return { success: false, message: `Failed to update Cursor hooks.json: ${message}` };
  }
};

export const installAll = async (): Promise<
  { target: string; success: boolean; message: string }[]
> => {
  return [
    { target: 'claude', ...(await installClaude()) },
    { target: 'codex', ...(await installCodex()) },
    { target: 'cursor', ...(await installCursor()) },
    { target: 'pi', ...(await installPi()) },
    { target: 'oh-my-pi', ...(await installOhMyPi()) },
  ];
};

export { addCursorHook, parseCursorConfig, type CursorHook };
