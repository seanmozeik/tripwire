import { Schema } from 'effect';

const ExecutionCarrierKindSchema = Schema.Literal('ssh');

const ExecutionCarrierAliasSchema = Schema.Struct({
  command: Schema.Array(Schema.NonEmptyString).check(Schema.isMinLength(1), Schema.isMaxLength(16)),
  equivalentTo: ExecutionCarrierKindSchema,
});

const ShellConfigSchema = Schema.Struct({
  executionCarrierAliases: Schema.optional(
    Schema.Array(ExecutionCarrierAliasSchema).check(Schema.isMaxLength(64)),
  ),
});

type ExecutionCarrierAlias = typeof ExecutionCarrierAliasSchema.Type;
type ExecutionCarrierKind = typeof ExecutionCarrierKindSchema.Type;
type ShellConfig = typeof ShellConfigSchema.Type;

export type { ExecutionCarrierAlias, ExecutionCarrierKind, ShellConfig };
export { ExecutionCarrierAliasSchema, ExecutionCarrierKindSchema, ShellConfigSchema };
