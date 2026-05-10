// Config installation module for tripwire hooks.
// Parses and upserts hook configurations for Claude Code, Codex, and pi-guardrails.

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

const TRIPWIRE_HOOK = 'tripwire-hook';

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

export const installAll = async (): Promise<
  { target: string; success: boolean; message: string }[]
> => {
  return [
    { target: 'claude', ...(await installClaude()) },
    { target: 'codex', ...(await installCodex()) },
    { target: 'pi', ...(await installPi()) },
  ];
};
