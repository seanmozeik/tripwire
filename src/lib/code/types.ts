type CodeLanguage = 'python' | 'javascript' | 'typescript';

interface CodeRange {
  readonly start: number;
  readonly end: number;
}

type CodeOperation =
  | {
      readonly kind: 'read' | 'write' | 'delete' | 'truncate';
      readonly path: string;
      readonly range: CodeRange;
    }
  | { readonly kind: 'process'; readonly argv: readonly string[]; readonly range: CodeRange };

interface CodeReport {
  readonly operations: readonly CodeOperation[];
  /** Any gap blocks authorization, including parser recovery and budget exhaustion. */
  readonly gap: string | null;
}

type Value =
  | { readonly kind: 'data' }
  | { readonly kind: 'text'; readonly path: string | null; readonly preservesNonempty: boolean }
  | { readonly kind: 'string'; readonly value: string }
  | { readonly kind: 'number'; readonly value: number }
  | { readonly kind: 'symbol'; readonly name: string }
  | { readonly kind: 'path' | 'file'; readonly path: string }
  | { readonly kind: 'method'; readonly receiver: Value; readonly name: string }
  | { readonly kind: 'list'; readonly items: readonly Value[] }
  | { readonly kind: 'object'; readonly entries: ReadonlyMap<string, Value> }
  | { readonly kind: 'unknown' };

export type { CodeLanguage, CodeOperation, CodeRange, CodeReport, Value };
