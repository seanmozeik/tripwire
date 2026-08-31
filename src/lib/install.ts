// Agent installation module for Tripwire hooks and the native Pi extension.

import {
  lstat,
  mkdir,
  open,
  readFile,
  readlink,
  realpath,
  rename,
  rm,
  stat,
  symlink,
  type FileHandle,
} from 'node:fs/promises';
import { homedir } from 'node:os';
import pathModule from 'node:path';
import { fileURLToPath } from 'node:url';

import { readRuntimeEnvironment } from './environment';

interface CommandHook extends Record<string, unknown> {
  type: string;
  command: string;
  timeout?: number;
}

interface HookGroup extends Record<string, unknown> {
  hooks: CommandHook[];
}

interface AgentHooks extends Record<string, unknown> {
  PreToolUse?: HookGroup[];
  PostToolUse?: HookGroup[];
}

interface AgentHooksConfig extends Record<string, unknown> {
  hooks?: AgentHooks;
}

const { packageDist } = readRuntimeEnvironment();
const piExtensionSourceCandidates = [
  ...(packageDist === undefined ? [] : [pathModule.join(packageDist, 'tripwire-pi.js')]),
  pathModule.join(pathModule.dirname(process.execPath), 'tripwire-pi.js'),
  fileURLToPath(new URL('../../dist/tripwire-pi.js', import.meta.url)),
  fileURLToPath(new URL('tripwire-pi.js', import.meta.url)),
];

export interface InstallOptions {
  readonly extensionSource?: string;
  readonly homeDirectory?: string;
  readonly hookCommand?: string;
}

interface AtomicTextReplaceOptions {
  readonly beforeRename?: (pendingPath: string, targetPath: string) => Promise<void> | void;
}

interface ExtensionLinkResult {
  readonly action: 'already' | 'installed' | 'updated';
  readonly success: boolean;
}

interface CursorHook extends Record<string, unknown> {
  command: string;
  type?: string;
  timeout?: number;
  failClosed?: boolean;
}

interface CursorConfig extends Record<string, unknown> {
  version?: number;
  hooks?: Record<string, CursorHook[]>;
}

const isJsonRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const isErrno = (error: unknown, code: string): boolean =>
  error instanceof Error && 'code' in error && error.code === code;

export const replaceTextAtomically = async (
  targetPath: string,
  text: string,
  options: AtomicTextReplaceOptions = {},
): Promise<void> => {
  let publicationPath = targetPath;
  let targetIsSymlink = false;
  try {
    const targetStatus = await lstat(targetPath);
    targetIsSymlink = targetStatus.isSymbolicLink();
  } catch (error) {
    if (!isErrno(error, 'ENOENT')) {
      throw error;
    }
  }
  if (targetIsSymlink) {
    // A dangling link fails here instead of being replaced.
    publicationPath = await realpath(targetPath);
  }

  const pendingPath = `${publicationPath}.${process.pid}.next`;
  let handle: FileHandle | undefined;
  let mode = 0o600;

  try {
    const targetStatus = await stat(publicationPath);
    mode = targetStatus.mode & 0o7777;
  } catch (error) {
    if (!isErrno(error, 'ENOENT')) {
      throw error;
    }
  }

  await rm(pendingPath, { force: true });
  try {
    handle = await open(pendingPath, 'wx', mode);
    await handle.writeFile(text, 'utf8');
    // Chmod is explicit after writing because open applies the umask and writes can clear mode bits.
    await handle.chmod(mode);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await options.beforeRename?.(pendingPath, publicationPath);
    await rename(pendingPath, publicationPath);
  } finally {
    try {
      if (handle !== undefined) {
        await handle.close();
      }
    } finally {
      await rm(pendingPath, { force: true });
    }
  }
};

const isCommandHook = (value: unknown): value is CommandHook =>
  isJsonRecord(value) &&
  typeof value['type'] === 'string' &&
  typeof value['command'] === 'string' &&
  (value['timeout'] === undefined || typeof value['timeout'] === 'number');

const isHookGroups = (value: unknown): value is HookGroup[] =>
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
  command.includes('/tripwire-darwin-arm64/') ||
  command.includes('/tripwire-hook') ||
  command.includes('/tripwire.js') ||
  command.includes('/dist/tripwire');

const addCursorHook = (
  hooks: CursorHook[] | undefined,
  eventName: string,
  hookCommand = TRIPWIRE_HOOK,
): [CursorHook[], boolean] => {
  const failClosed = CURSOR_FAIL_CLOSED_EVENTS.has(eventName);
  const newHook = {
    command: `${hookCommand} --cursor-event ${eventName}`,
    ...(failClosed && { failClosed: true }),
  };
  if (hooks === undefined) {
    return [[newHook], true];
  }

  let changed = false;
  const hasTripwire = hooks.some((hook) => isTripwireCommand(hook.command));
  const desiredCommand = `${hookCommand} --cursor-event ${eventName}`;
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
  hooks: HookGroup[] | undefined,
  hookCommand = TRIPWIRE_HOOK,
): [HookGroup[], boolean] => {
  if (!hooks) {
    const newHooks: HookGroup[] = [{ hooks: [{ type: 'command', command: hookCommand }] }];
    return [newHooks, false];
  }

  let needsNormalization = false;

  const normalizedHooks = hooks.map((h) => ({
    ...h,
    hooks: h.hooks.map((hook) => {
      if (isTripwireCommand(hook.command)) {
        if (hook.command !== hookCommand) {
          needsNormalization = true;
          return { ...hook, command: hookCommand };
        }
        return hook;
      }
      return hook;
    }),
  }));

  const hasTripwire = normalizedHooks.some((h) =>
    h.hooks.some((hook) => hook.command === hookCommand),
  );

  if (hasTripwire) {
    return [normalizedHooks, !needsNormalization];
  }

  const newHooks: HookGroup[] = [
    ...normalizedHooks,
    { hooks: [{ type: 'command', command: hookCommand }] },
  ];
  return [newHooks, false];
};

export const installClaude = async (
  options: InstallOptions = {},
): Promise<{ success: boolean; message: string }> => {
  const homeDirectory = options.homeDirectory ?? homedir();
  const hookCommand = options.hookCommand ?? TRIPWIRE_HOOK;
  const configPath = `${homeDirectory}/.claude/settings.json`;
  try {
    const raw = await readFile(configPath, 'utf8');
    const config = parseAgentHooksConfig(raw, 'Claude');

    config.hooks ??= {};
    const [preToolUse, preSkipped] = addHookIfMissing(config.hooks.PreToolUse, hookCommand);
    const [postToolUse, postSkipped] = addHookIfMissing(config.hooks.PostToolUse, hookCommand);

    config.hooks.PreToolUse = preToolUse;
    config.hooks.PostToolUse = postToolUse;

    if (preSkipped && postSkipped) {
      return { success: true, message: `Already configured: ${configPath}` };
    }

    await replaceTextAtomically(configPath, `${JSON.stringify(config, null, 2)}\n`);

    return { success: true, message: `Updated ${configPath}` };
  } catch (error) {
    if (isErrno(error, 'ENOENT')) {
      return { success: false, message: `Config file not found: ${configPath}` };
    }
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, message: `Failed to update Claude config: ${message}` };
  }
};

export const installPi = async (
  options: InstallOptions = {},
): Promise<{ success: boolean; message: string }> => {
  const homeDirectory = options.homeDirectory ?? homedir();
  const configPath = `${homeDirectory}/.pi/agent/settings.json`;
  const extensionPath = `${homeDirectory}/.pi/agent/extensions/tripwire.js`;

  try {
    const source =
      options.extensionSource ??
      piExtensionSourceCandidates.find((candidate) => Bun.file(candidate).size > 0);
    if (source === undefined) {
      return { success: false, message: 'Built Pi extension not found; run `bun run build` first' };
    }
    const raw = await readFile(configPath, 'utf8');
    let config = parseAgentHooksConfig(raw, 'Pi');
    if (config.hooks !== undefined) {
      const { PreToolUse, PostToolUse, ...otherHooks } = config.hooks;
      const cleanGroups = (groups: HookGroup[] | undefined) =>
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
    const nextRaw = `${JSON.stringify(config, null, 2)}\n`;
    const settingsChanged = nextRaw !== raw;

    // The extension must be available before old hook settings are removed.
    const link = await installExtensionLink(source, extensionPath);
    if (!link.success) {
      return {
        success: false,
        message: `Refusing to replace existing Pi extension: ${extensionPath}`,
      };
    }
    if (settingsChanged) {
      await replaceTextAtomically(configPath, nextRaw);
    }
    if (link.action === 'already' && !settingsChanged) {
      return { success: true, message: `Already configured: ${extensionPath}` };
    }
    const verb = link.action === 'updated' ? 'Updated' : 'Installed';
    return { success: true, message: `${verb} ${extensionPath}` };
  } catch (error) {
    if (isErrno(error, 'ENOENT')) {
      return { success: false, message: `Config file not found: ${configPath}` };
    }
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, message: `Failed to update pi config: ${message}` };
  }
};

export const installOhMyPi = async (
  options: InstallOptions = {},
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

const parseCodexFeatures = (raw: string): Record<string, unknown> | undefined => {
  const parsed: unknown = Bun.TOML.parse(raw);
  const features = isJsonRecord(parsed) ? parsed['features'] : undefined;
  if (features !== undefined && !isJsonRecord(features)) {
    throw new Error('Codex config.toml `features` must be a table');
  }
  return features;
};

const enableCodexHooks = (raw: string): string => {
  if (parseCodexFeatures(raw)?.['hooks'] === true) {
    return raw;
  }

  const newline = raw.includes('\r\n') ? '\r\n' : '\n';
  const featuresHeader = /^[\t ]*\[features\][\t ]*(?:#.*)?(?:\r?\n|$)/mu.exec(raw);
  let next: string;
  if (featuresHeader === null) {
    const separator = raw.length === 0 || raw.endsWith('\n') ? '' : newline;
    const finalNewline = raw.length === 0 || raw.endsWith('\n') ? newline : '';
    next = `${raw}${separator}[features]${newline}hooks = true${finalNewline}`;
  } else {
    const sectionStart = featuresHeader.index + featuresHeader[0].length;
    const nextHeaderPattern = /^[\t ]*\[/gmu;
    nextHeaderPattern.lastIndex = sectionStart;
    const nextHeader = nextHeaderPattern.exec(raw);
    const sectionEnd = nextHeader?.index ?? raw.length;
    const section = raw.slice(sectionStart, sectionEnd);
    const assignment =
      /^(?<prefix>[\t ]*hooks[\t ]*=[\t ]*)(?<value>[^#\r\n]*?)(?<suffix>[\t ]*(?:#.*)?)$/mu.exec(
        section,
      );

    if (assignment === null) {
      const headerHasNewline = featuresHeader[0].endsWith('\n');
      const insertion = headerHasNewline ? `hooks = true${newline}` : `${newline}hooks = true`;
      next = `${raw.slice(0, sectionStart)}${insertion}${raw.slice(sectionStart)}`;
    } else {
      const prefix = assignment.groups?.['prefix'];
      const value = assignment.groups?.['value'];
      if (prefix === undefined || value === undefined) {
        throw new Error('Could not locate Codex hooks value in config.toml');
      }
      const valueStart = sectionStart + assignment.index + prefix.length;
      const valueEnd = valueStart + value.length;
      next = `${raw.slice(0, valueStart)}true${raw.slice(valueEnd)}`;
    }
  }

  if (parseCodexFeatures(next)?.['hooks'] !== true) {
    throw new Error('Could not enable Codex hooks in config.toml');
  }
  return next;
};

export const installCodex = async (
  options: InstallOptions = {},
): Promise<{ success: boolean; message: string }> => {
  const homeDirectory = options.homeDirectory ?? homedir();
  const hookCommand = options.hookCommand ?? TRIPWIRE_HOOK;
  const configTomlPath = `${homeDirectory}/.codex/config.toml`;
  const hooksJsonPath = `${homeDirectory}/.codex/hooks.json`;

  try {
    // Read and validate both files before the first write.
    const [hooksRaw, tomlRaw] = await Promise.all([
      readFile(hooksJsonPath, 'utf8'),
      readFile(configTomlPath, 'utf8'),
    ]);
    const config = parseAgentHooksConfig(hooksRaw, 'Codex');
    config.hooks ??= {};
    const [preToolUse] = addHookIfMissing(config.hooks.PreToolUse, hookCommand);
    const [postToolUse] = addHookIfMissing(config.hooks.PostToolUse, hookCommand);

    const addTimeout = (hooks: HookGroup[]): HookGroup[] =>
      hooks.map((group) => ({
        ...group,
        hooks: group.hooks.map((hook) =>
          hook.command === hookCommand && hook.timeout === undefined
            ? { ...hook, timeout: 10 }
            : hook,
        ),
      }));

    config.hooks.PreToolUse = addTimeout(preToolUse);
    config.hooks.PostToolUse = addTimeout(postToolUse);
    const nextHooksRaw = `${JSON.stringify(config, null, 2)}\n`;
    const nextTomlRaw = enableCodexHooks(tomlRaw);
    const hooksUpdated = nextHooksRaw !== hooksRaw;
    const tomlUpdated = nextTomlRaw !== tomlRaw;

    // Publish hooks.json first. It is inert while the feature is disabled, and a retry repairs
    // a first-file-only partial update without changing the already published bytes.
    if (hooksUpdated) {
      await replaceTextAtomically(hooksJsonPath, nextHooksRaw);
    }
    if (tomlUpdated) {
      await replaceTextAtomically(configTomlPath, nextTomlRaw);
    }

    if (!hooksUpdated && !tomlUpdated) {
      return {
        success: true,
        message: `Already configured: ${configTomlPath} and ${hooksJsonPath}`,
      };
    }
    return { success: true, message: `Updated ${configTomlPath} and ${hooksJsonPath}` };
  } catch (error) {
    if (isErrno(error, 'ENOENT')) {
      const missingPath =
        isJsonRecord(error) && typeof error['path'] === 'string'
          ? error['path']
          : `${configTomlPath} or ${hooksJsonPath}`;
      return { success: false, message: `Config file not found: ${missingPath}` };
    }
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, message: `Failed to update Codex config: ${message}` };
  }
};

export const installCursor = async (
  options: InstallOptions = {},
): Promise<{ success: boolean; message: string }> => {
  const homeDirectory = options.homeDirectory ?? homedir();
  const hookCommand = options.hookCommand ?? TRIPWIRE_HOOK;
  const configPath = `${homeDirectory}/.cursor/hooks.json`;
  try {
    const raw = await readFile(configPath, 'utf8');
    const config = parseCursorConfig(raw);
    config.version ??= 1;
    config.hooks ??= {};

    let updated = false;
    for (const eventName of CURSOR_HOOK_EVENTS) {
      const [hooks, changed] = addCursorHook(config.hooks[eventName], eventName, hookCommand);
      config.hooks[eventName] = hooks;
      updated ||= changed;
    }

    if (!updated) {
      return { success: true, message: `Already configured: ${configPath}` };
    }
    await replaceTextAtomically(configPath, `${JSON.stringify(config, null, 2)}\n`);
    return { success: true, message: `Updated ${configPath}` };
  } catch (error) {
    if (isErrno(error, 'ENOENT')) {
      return { success: false, message: `Config file not found: ${configPath}` };
    }
    const message = error instanceof Error ? error.message : String(error);
    return { success: false, message: `Failed to update Cursor hooks.json: ${message}` };
  }
};

export const installAll = async (
  options: InstallOptions = {},
): Promise<{ target: string; success: boolean; message: string }[]> => {
  return [
    { target: 'claude', ...(await installClaude(options)) },
    { target: 'codex', ...(await installCodex(options)) },
    { target: 'cursor', ...(await installCursor(options)) },
    { target: 'pi', ...(await installPi(options)) },
    { target: 'oh-my-pi', ...(await installOhMyPi(options)) },
  ];
};

export { addCursorHook, parseCursorConfig, type CursorHook };
