// Config installation module for tripwire hooks.
// Parses and upserts hook configurations for Claude Code, Codex, Cursor, and pi-guardrails.

import { homedir } from 'node:os';

import { file } from 'bun';

interface ClaudeConfig {
  hooks?: {
    PreToolUse?: { hooks: { type: string; command: string }[] }[];
    PostToolUse?: { hooks: { type: string; command: string }[] }[];
  };
}

interface PiConfig {
  hooks?: {
    PreToolUse?: { hooks: { type: string; command: string }[] }[];
    PostToolUse?: { hooks: { type: string; command: string }[] }[];
  };
}

interface CodexHooksConfig {
  hooks?: {
    PreToolUse?: { hooks: { type: string; command: string; timeout?: number }[] }[];
    PostToolUse?: { hooks: { type: string; command: string; timeout?: number }[] }[];
  };
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

const parseCursorConfig = (raw: string): CursorConfig => {
  const value: unknown = JSON.parse(raw);
  if (!isJsonRecord(value)) {
    throw new Error('Cursor hooks.json must contain a JSON object');
  }
  const hooks = value['hooks'];
  if (hooks === undefined) {
    return value as CursorConfig;
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
  return value as CursorConfig;
};

const TRIPWIRE_HOOK = 'tripwire-hook';

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
  command.includes('/tripwire.js');

const cursorEventFromCommand = (command: string): string | undefined =>
  /(?:^|\s)--cursor-event(?:=|\s+)(?<event>[^\s]+)/.exec(command)?.groups?.['event'];

const withCursorEvent = (command: string, eventName: string): string => {
  const cursorEvent = /(?<prefix>^|\s)--cursor-event(?:=|\s+)(?<event>[^\s]+)/;
  const match = cursorEvent.exec(command);
  if (match !== null) {
    return command.replace(
      cursorEvent,
      `${match.groups?.['prefix'] ?? ''}--cursor-event ${eventName}`,
    );
  }
  return `${command} --cursor-event ${eventName}`;
};

const addCursorHook = (
  hooks: CursorHook[] | undefined,
  eventName: string,
): [CursorHook[], boolean] => {
  const failClosed = CURSOR_FAIL_CLOSED_EVENTS.has(eventName);
  const newHook = {
    command: `${TRIPWIRE_HOOK} --cursor-event ${eventName}`,
    ...(failClosed ? { failClosed: true } : {}),
  };
  if (hooks === undefined) {
    return [[newHook], true];
  }

  let changed = false;
  const hasTripwire = hooks.some((hook) => isTripwireCommand(hook.command));
  const normalized = hooks.map((hook) => {
    if (!isTripwireCommand(hook.command)) {
      return hook;
    }
    if (
      cursorEventFromCommand(hook.command) === eventName &&
      (!failClosed || hook.failClosed === true)
    ) {
      return hook;
    }
    changed = true;
    return {
      ...hook,
      command: withCursorEvent(hook.command, eventName),
      ...(failClosed ? { failClosed: true } : {}),
    };
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
    const config = JSON.parse(raw) as ClaudeConfig;

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

export const installPi = async (): Promise<{ success: boolean; message: string }> => {
  const configPath = `${homedir()}/.pi/agent/settings.json`;
  const configFile = file(configPath);

  try {
    const raw = await configFile.text();
    const config = JSON.parse(raw) as PiConfig;

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
    return { success: false, message: `Failed to update pi config: ${message}` };
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
    const config = JSON.parse(raw) as CodexHooksConfig;

    config.hooks ??= {};
    const [preToolUse, preSkipped] = addHookIfMissing(config.hooks.PreToolUse);
    const [postToolUse, postSkipped] = addHookIfMissing(config.hooks.PostToolUse);

    config.hooks.PreToolUse = preToolUse;
    config.hooks.PostToolUse = postToolUse;

    if (!preSkipped || !postSkipped) {
      hooksUpdated = true;
    }

    // Add timeout to tripwire-hook if not present
    const addTimeout = (
      hooks: { hooks: { type: string; command: string; timeout?: number }[] }[] | undefined,
    ): { hooks: { type: string; command: string; timeout?: number }[] }[] => {
      return (
        hooks?.map((h) => ({
          hooks: h.hooks.map((hook) => {
            if (hook.command === TRIPWIRE_HOOK && hook.timeout === undefined) {
              return { ...hook, timeout: 10 };
            }
            return hook;
          }),
        })) ?? []
      );
    };

    config.hooks.PreToolUse = addTimeout(config.hooks.PreToolUse);
    config.hooks.PostToolUse = addTimeout(config.hooks.PostToolUse);

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
  ];
};

export { addCursorHook, parseCursorConfig, type CursorHook };
