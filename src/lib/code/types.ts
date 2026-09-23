import type { SyntaxNode } from '@lezer/common';

import type { Scope } from './scope';

type CodeLanguage = 'python' | 'javascript' | 'typescript';

interface CodeRange {
  readonly start: number;
  readonly end: number;
}

type CodeOperation = (
  | {
      readonly kind: 'read' | 'write' | 'delete' | 'truncate' | 'json-module';
      readonly path: string;
      readonly range: CodeRange;
    }
  | { readonly kind: 'process'; readonly argv: readonly string[]; readonly range: CodeRange }
) & { readonly cwd?: string };

interface CodeReport {
  readonly operations: readonly CodeOperation[];
  /** Any gap blocks authorization, including parser recovery and budget exhaustion. */
  readonly gap: string | null;
}

interface ClosureParameter {
  readonly name: string;
  readonly fallback?: Value;
  readonly pattern?: SyntaxNode;
  readonly keywordOnly?: boolean;
  readonly rest?: 'positional' | 'keywords';
}

type Value =
  | {
      readonly kind: 'class';
      readonly htmlParser?: boolean;
      readonly methods: ReadonlyMap<string, Value>;
    }
  | {
      readonly kind: 'instance';
      readonly htmlParser?: boolean;
      readonly methods: ReadonlyMap<string, Value>;
      readonly entries: Map<string, Value>;
    }
  | { readonly kind: 'bound-method'; readonly fn: Value; readonly receiver: Value }
  | { readonly kind: 'builtin'; readonly name: string }
  | {
      readonly kind: 'closure';
      readonly scope: Scope;
      readonly parameters: readonly ClosureParameter[];
      readonly body: SyntaxNode;
      readonly expression: boolean;
    }
  | { readonly kind: 'environment' }
  | { readonly kind: 'opaque-path' }
  | { readonly kind: 'image'; readonly path: string }
  | { readonly kind: 'counter' }
  | { readonly kind: 'hash' }
  | { readonly kind: 'bun-file'; readonly path: string }
  | { readonly kind: 'data' }
  | { readonly kind: 'text' }
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'number'; readonly value: number }
  | { readonly kind: 'symbol'; readonly name: string }
  | { readonly kind: 'path' | 'file'; readonly path: string }
  | { readonly kind: 'archive'; readonly path: string }
  | { readonly kind: 'method'; readonly receiver: Value; readonly name: string }
  | { readonly kind: 'list'; opaque?: boolean; readonly items: readonly Value[] }
  | { readonly kind: 'object'; opaque?: boolean; readonly entries: ReadonlyMap<string, Value> }
  | { readonly kind: 'unknown' };

export type { ClosureParameter, CodeLanguage, CodeOperation, CodeRange, CodeReport, Value };
