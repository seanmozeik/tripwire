import type { ExecutionCarrierAlias } from './config';

interface SourceRange {
  readonly start: number;
  readonly end: number;
}

type ShellWordKind = 'literal' | 'dynamic' | 'trusted-temp-path' | 'background-pid';

interface BashAnalysisOptions {
  readonly cwd?: string;
  readonly executionCarrierAliases?: readonly ExecutionCarrierAlias[];
  readonly positionalArguments?: readonly string[];
}

interface ShellWord {
  /** Raw shell source for this word. */
  readonly source: string;
  /** Dequoted policy value. Dynamic values use a fail-closed sentinel. */
  readonly value: string;
  readonly kind: ShellWordKind;
  readonly range: SourceRange;
  readonly quoted: boolean;
  readonly variable?: string;
}

interface ShellRedirect {
  readonly op: '>' | '>>' | '<' | '<<' | '<<<' | '<>' | '>&' | '<&' | '&>' | '&>>';
  readonly target: ShellWord;
  readonly range: SourceRange;
}

interface PipelinePosition {
  readonly id: number;
  readonly index: number;
}

interface ShellInvocation {
  readonly id: number;
  readonly head: string;
  readonly words: readonly ShellWord[];
  readonly tokens: readonly string[];
  readonly args: readonly string[];
  readonly flags: readonly string[];
  readonly redirects: readonly ShellRedirect[];
  readonly raw: string;
  readonly range: SourceRange;
  readonly pipeline: PipelinePosition | undefined;
  readonly synthetic: boolean;
}

type ShellDiagnosticKind =
  | 'parse-error'
  | 'dynamic-executable'
  | 'dynamic-shell-source'
  | 'eval'
  | 'function'
  | 'alias';

interface ShellDiagnostic {
  readonly kind: ShellDiagnosticKind;
  readonly message: string;
  readonly range: SourceRange;
}

interface ShellProgram {
  readonly source: string;
  readonly invocations: readonly ShellInvocation[];
  readonly redirects: readonly ShellRedirect[];
  readonly diagnostics: readonly ShellDiagnostic[];
  readonly hasBypass: boolean;
}

export type {
  BashAnalysisOptions,
  PipelinePosition,
  ShellDiagnostic,
  ShellDiagnosticKind,
  ShellInvocation,
  ShellProgram,
  ShellRedirect,
  ShellWord,
  ShellWordKind,
  SourceRange,
};
export type { ExecutionCarrierAlias, ExecutionCarrierKind } from './config';
