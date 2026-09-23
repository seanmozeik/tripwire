import type { SyntaxNode } from '@lezer/common';

type SyntaxHandler<Result> = (node: SyntaxNode, parts: readonly SyntaxNode[]) => Result;

const syntaxHandlers = <Result>(
  groups: readonly (readonly [readonly string[], SyntaxHandler<Result>])[],
): ReadonlyMap<string, SyntaxHandler<Result>> =>
  new Map(groups.flatMap(([names, handler]) => names.map((name) => [name, handler] as const)));

export { syntaxHandlers };
