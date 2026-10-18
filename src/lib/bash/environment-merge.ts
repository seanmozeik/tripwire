import { joinBindings } from './bindings';
import { joinStartup } from './startup';
import { emptyEnvironment, type Environment } from './values';

// Control-flow merges keep only the facts that hold on every incoming path.

const mapsAgree = <Value>(maps: readonly ReadonlyMap<string, Value>[]): Map<string, Value> => {
  const [first, ...rest] = maps;
  const joined = new Map<string, Value>();
  if (first === undefined) {
    return joined;
  }
  for (const [name, value] of first) {
    if (rest.every((map) => map.get(name) === value)) {
      joined.set(name, value);
    }
  }
  return joined;
};

const environmentsAgree = (environments: readonly Environment[]): Environment => {
  const [first, ...rest] = environments;
  if (first === undefined) {
    return emptyEnvironment();
  }
  return {
    startup: joinStartup(...environments.map((environment) => environment.startup)),
    cwd: rest.every((environment) => environment.cwd === first.cwd) ? first.cwd : null,
    directoryStack: rest.every(
      (environment) =>
        JSON.stringify(environment.directoryStack) === JSON.stringify(first.directoryStack),
    )
      ? [...first.directoryStack]
      : [],
    createdDirectories: new Set(
      [...first.createdDirectories].filter((directory) =>
        rest.every((environment) => environment.createdDirectories.has(directory)),
      ),
    ),
    aliases: mapsAgree([first.aliases, ...rest.map((environment) => environment.aliases)]),
    backgroundPidAvailable: [first, ...rest].every(
      (environment) => environment.backgroundPidAvailable,
    ),
    bindings: joinBindings(environments),
    functions: mapsAgree([first.functions, ...rest.map((environment) => environment.functions)]),
    temps: mapsAgree([first.temps, ...rest.map((environment) => environment.temps)]),
  };
};

const replaceSet = (target: Set<string>, source: ReadonlySet<string>): void => {
  target.clear();
  for (const value of source) {
    target.add(value);
  }
};

const replaceEnvironment = (target: Environment, source: Environment): void => {
  if (target === source) {
    return;
  }
  target.startup = joinStartup(source.startup);
  target.cwd = source.cwd;
  target.directoryStack = [...source.directoryStack];
  replaceSet(target.createdDirectories, source.createdDirectories);
  target.backgroundPidAvailable = source.backgroundPidAvailable;
  target.aliases.clear();
  for (const [name, value] of source.aliases) {
    target.aliases.set(name, value);
  }
  target.bindings.clear();
  for (const [name, value] of source.bindings) {
    target.bindings.set(name, value);
  }
  target.functions.clear();
  for (const [name, value] of source.functions) {
    target.functions.set(name, value);
  }
  target.temps.clear();
  for (const [name, value] of source.temps) {
    target.temps.set(name, value);
  }
};

const propagateMap = <Value>(
  target: Map<string, Value>,
  source: ReadonlyMap<string, Value>,
  excluded: ReadonlySet<string>,
): void => {
  for (const name of target.keys()) {
    if (!excluded.has(name) && !source.has(name)) {
      target.delete(name);
    }
  }
  for (const [name, value] of source) {
    if (!excluded.has(name)) {
      target.set(name, value);
    }
  }
};

const propagateFunctionEffects = (
  target: Environment,
  source: Environment,
  excludedVariables: ReadonlySet<string>,
): void => {
  propagateMap(target.aliases, source.aliases, new Set());
  propagateMap(target.functions, source.functions, new Set());
  propagateMap(target.bindings, source.bindings, excludedVariables);
  propagateMap(target.temps, source.temps, excludedVariables);
  target.startup = joinStartup(source.startup);
  target.cwd = source.cwd;
  target.directoryStack = [...source.directoryStack];
  replaceSet(target.createdDirectories, source.createdDirectories);
  target.backgroundPidAvailable = source.backgroundPidAvailable;
};

export { environmentsAgree, propagateFunctionEffects, propagateMap, replaceEnvironment };
