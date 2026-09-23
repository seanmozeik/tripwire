import { data, isData, text } from './data';
import type { Value } from './types';
import { unknown } from './values';

class Scope extends Map<string, Value> {
  readonly parent: Scope | undefined;

  constructor(parent?: Scope, values?: ReadonlyMap<string, Value>) {
    super(values);
    this.parent = parent;
  }

  override get(name: string): Value | undefined {
    return super.get(name) ?? this.parent?.get(name);
  }

  assign(name: string, value: Value): void {
    if (super.has(name) || this.parent?.get(name) === undefined) {
      this.set(name, value);
    } else {
      this.parent.assign(name, value);
    }
  }
}

const joinValues = (values: readonly Value[]): Value => {
  const [first] = values;
  if (first !== undefined && values.every((value) => value === first)) {
    return first;
  }
  if (values.every((value) => value.kind === 'text' || value.kind === 'string')) {
    return text;
  }
  return values.every((value) => isData(value)) ? data : unknown;
};

type ScopeSnapshot = ReadonlyMap<Scope, ReadonlyMap<string, Value>>;
class Scopes {
  readonly #scopes = new Set<Scope>();

  create(parent?: Scope, values?: ReadonlyMap<string, Value>): Scope {
    const scope = new Scope(parent, values);
    this.#scopes.add(scope);
    return scope;
  }

  snapshot(): ScopeSnapshot {
    return new Map([...this.#scopes].map((scope) => [scope, new Map(scope)]));
  }

  static restore(snapshot: ScopeSnapshot): void {
    for (const [scope, values] of snapshot) {
      scope.clear();
      for (const [name, value] of values) {
        scope.set(name, value);
      }
    }
  }

  join(states: readonly ScopeSnapshot[]): void {
    for (const scope of this.#scopes) {
      const maps = states.map((state) => state.get(scope) ?? new Map<string, Value>());
      const names = new Set(maps.flatMap((map) => [...map.keys()]));
      scope.clear();
      for (const name of names) {
        scope.set(name, joinValues(maps.map((map) => map.get(name) ?? unknown)));
      }
    }
  }
}

export { Scope, Scopes };
export type { ScopeSnapshot };
