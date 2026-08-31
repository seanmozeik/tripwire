import type { ShellDiagnosticKind, ShellInvocation, ShellWord, SourceRange } from './types';
import type { Environment } from './values';

interface ExecutionContext {
  readonly inspectedPipelineInput: boolean;
  readonly source: string;
  readonly pipeline: ShellInvocation['pipeline'];
}

interface ExecutionHost {
  readonly addDiagnostic: (kind: ShellDiagnosticKind, message: string, range: SourceRange) => void;
  readonly emitSynthetic: (
    words: readonly ShellWord[],
    parent: ShellInvocation,
    environment: Environment,
    context: ExecutionContext,
  ) => void;
  readonly inspectShellSource: (
    word: ShellWord | undefined,
    environment: Environment,
    context: ExecutionContext,
  ) => void;
}

export type { ExecutionContext, ExecutionHost };
