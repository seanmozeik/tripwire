import type { Command, Function as BashFunction, ParsedScript, Word, WordPart } from 'unbash';

import type { ShellWord, SourceRange } from './types';

const DYNAMIC_VALUE = '__tripwire_dynamic_shell_value__';
const TRUSTED_TEMP_ROOT = '/private/tmp/tripwire-provenance';
const BACKGROUND_PID_VALUE = '__tripwire_background_pid__';

interface TrustedTempValue {
  readonly variable: string;
}

interface Environment {
  readonly aliases: Map<string, string>;
  backgroundPidAvailable: boolean;
  readonly bindings: Map<string, ShellWord>;
  readonly functions: Map<string, BashFunction>;
  readonly temps: Map<string, TrustedTempValue>;
}

interface StaticCommand {
  readonly command: Command;
  readonly head: string;
  readonly args: readonly string[];
}

const rangeOf = (node: { readonly pos: number; readonly end: number }): SourceRange => ({
  start: node.pos,
  end: node.end,
});

const basename = (value: string): string => {
  const index = value.lastIndexOf('/');
  return index === -1 ? value : value.slice(index + 1);
};

const emptyEnvironment = (): Environment => ({
  aliases: new Map(),
  backgroundPidAvailable: false,
  bindings: new Map(),
  functions: new Map(),
  temps: new Map(),
});

const cloneEnvironment = (environment: Environment): Environment => ({
  aliases: new Map(environment.aliases),
  backgroundPidAvailable: environment.backgroundPidAvailable,
  bindings: new Map(environment.bindings),
  functions: new Map(environment.functions),
  temps: new Map(environment.temps),
});

const isQuotedPart = (part: WordPart): boolean =>
  part.type === 'SingleQuoted' ||
  part.type === 'DoubleQuoted' ||
  part.type === 'AnsiCQuoted' ||
  part.type === 'LocaleString';

const partsAreStatic = (parts: readonly WordPart[]): boolean =>
  parts.every((part) => {
    switch (part.type) {
      case 'Literal':
      case 'SingleQuoted':
      case 'AnsiCQuoted': {
        return true;
      }
      case 'DoubleQuoted':
      case 'LocaleString': {
        return partsAreStatic(part.parts);
      }
      case 'SimpleExpansion':
      case 'ParameterExpansion':
      case 'CommandExpansion':
      case 'ArithmeticExpansion':
      case 'ProcessSubstitution':
      case 'ExtendedGlob':
      case 'BraceExpansion': {
        return false;
      }
      default: {
        return false;
      }
    }
  });

const wordIsStatic = (word: Word): boolean => partsAreStatic(word.parts ?? []);

const staticCommandOf = (script: ParsedScript | undefined): StaticCommand | null => {
  if (script === undefined || (script.errors?.length ?? 0) > 0 || script.commands.length !== 1) {
    return null;
  }
  const [statement] = script.commands;
  if (statement === undefined || statement.background === true || statement.redirects.length > 0) {
    return null;
  }
  const { command } = statement;
  if (command.type !== 'Command' || command.name === undefined || !wordIsStatic(command.name)) {
    return null;
  }
  if (command.prefix.length > 0 || command.suffix.some((word) => !wordIsStatic(word))) {
    return null;
  }
  return {
    command,
    head: basename(command.name.value),
    args: command.suffix.map((word) => word.value),
  };
};

const soleCommandExpansion = (word: Word): ParsedScript | undefined => {
  const parts = word.parts ?? [];
  if (parts.length !== 1) {
    return undefined;
  }
  const [part] = parts;
  if (part?.type === 'CommandExpansion') {
    return part.script;
  }
  if (part?.type !== 'DoubleQuoted' || part.parts.length !== 1) {
    return undefined;
  }
  const [child] = part.parts;
  return child?.type === 'CommandExpansion' ? child.script : undefined;
};

const commandIsShadowed = (command: StaticCommand, environment: Environment): boolean =>
  command.command.name?.value.includes('/') === false &&
  (environment.aliases.has(command.head) || environment.functions.has(command.head));

const staticGeneratedValue = (word: Word, environment: Environment): string | null => {
  const parsed = staticCommandOf(soleCommandExpansion(word));
  if (parsed === null || commandIsShadowed(parsed, environment)) {
    return null;
  }
  if (parsed.head === 'cat' && parsed.args.length === 0 && parsed.command.redirects.length === 1) {
    const [redirect] = parsed.command.redirects;
    if (redirect?.operator !== '<<' && redirect?.operator !== '<<-') {
      return null;
    }
    if (
      redirect.heredocQuoted === true ||
      redirect.body === undefined ||
      wordIsStatic(redirect.body)
    ) {
      return (redirect.content ?? '').replace(/\n+$/u, '');
    }
    return null;
  }
  if (parsed.head === 'printf' && parsed.args.length === 2) {
    const [format, value] = parsed.args;
    if (format === '%s' || format === String.raw`%s\n`) {
      return value ?? '';
    }
  }
  return null;
};

const isSafeTemporaryTemplate = (value: string): boolean =>
  [
    '/tmp',
    '/private/tmp',
    '/var/tmp',
    '/private/var/tmp',
    '/var/folders',
    '/private/var/folders',
  ].some((root) => value === root || value.startsWith(`${root}/`));

const mktempArguments = (
  args: readonly string[],
): {
  readonly explicitDirectory: string | null;
  readonly positionals: readonly string[];
  readonly systemTempTemplate: boolean;
} => {
  let systemTempTemplate = false;
  let explicitDirectory: string | null = null;
  const positionals: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '-t') {
      systemTempTemplate = true;
      index += 1;
    } else if (arg === '-p' || arg === '--tmpdir') {
      explicitDirectory = args[index + 1] ?? '';
      index += 1;
    } else if (arg?.startsWith('--tmpdir=') === true) {
      explicitDirectory = arg.slice('--tmpdir='.length);
    } else if (arg !== undefined && !arg.startsWith('-')) {
      positionals.push(arg);
    }
  }
  return { explicitDirectory, positionals, systemTempTemplate };
};

const isTrustedMktemp = (word: Word, environment: Environment): boolean => {
  const parsed = staticCommandOf(soleCommandExpansion(word));
  if (
    parsed?.head !== 'mktemp' ||
    commandIsShadowed(parsed, environment) ||
    ['TMPDIR', 'TMP', 'TEMP'].some(
      (name) => environment.bindings.has(name) || environment.temps.has(name),
    ) ||
    !parsed.args.some(
      (argument) => argument === '-d' || argument === '--directory' || /^-[^-]*d/u.test(argument),
    )
  ) {
    return false;
  }
  const { explicitDirectory, positionals, systemTempTemplate } = mktempArguments(parsed.args);
  if (explicitDirectory !== null && !isSafeTemporaryTemplate(explicitDirectory)) {
    return false;
  }
  if (positionals.length === 0 || systemTempTemplate || explicitDirectory !== null) {
    return true;
  }
  const [template] = positionals;
  return positionals.length === 1 && template !== undefined && isSafeTemporaryTemplate(template);
};

const expansionVariable = (part: WordPart): string | null => {
  if (part.type === 'SimpleExpansion') {
    const match = /^\$(?<name>[A-Za-z_][A-Za-z0-9_]*|[0-9]+|!)$/u.exec(part.text);
    return match?.groups?.['name'] ?? null;
  }
  if (
    part.type === 'ParameterExpansion' &&
    part.indirect !== true &&
    part.length !== true &&
    part.operator === undefined &&
    part.index === undefined &&
    part.slice === undefined &&
    part.replace === undefined &&
    /^(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+|!)$/u.test(part.parameter)
  ) {
    return part.parameter;
  }
  return null;
};

interface ScalarExpansion {
  readonly prefix: string;
  readonly quoted: boolean;
  readonly suffix: string;
  readonly variable: string;
}

const scalarExpansion = (word: Word): ScalarExpansion | null => {
  const fragments: (
    | { readonly kind: 'literal'; readonly value: string }
    | { readonly kind: 'variable'; readonly quoted: boolean; readonly variable: string }
  )[] = [];
  const collect = (parts: readonly WordPart[], quoted: boolean): boolean => {
    for (const part of parts) {
      switch (part.type) {
        case 'Literal':
        case 'SingleQuoted':
        case 'AnsiCQuoted': {
          fragments.push({ kind: 'literal', value: part.value });
          break;
        }
        case 'DoubleQuoted':
        case 'LocaleString': {
          if (!collect(part.parts, true)) {
            return false;
          }
          break;
        }
        case 'SimpleExpansion':
        case 'ParameterExpansion': {
          const variable = expansionVariable(part);
          if (variable === null) {
            return false;
          }
          fragments.push({ kind: 'variable', quoted, variable });
          break;
        }
        case 'ArithmeticExpansion':
        case 'BraceExpansion':
        case 'CommandExpansion':
        case 'ExtendedGlob':
        case 'ProcessSubstitution': {
          return false;
        }
        default: {
          return false;
        }
      }
    }
    return true;
  };
  if (!collect(word.parts ?? [], false)) {
    return null;
  }
  const variables = fragments.filter(
    (fragment): fragment is Extract<(typeof fragments)[number], { readonly kind: 'variable' }> =>
      fragment.kind === 'variable',
  );
  if (variables.length !== 1) {
    return null;
  }
  const [variable] = variables;
  if (variable === undefined) {
    return null;
  }
  const variableIndex = fragments.indexOf(variable);
  return {
    prefix: fragments
      .slice(0, variableIndex)
      .map((fragment) => (fragment.kind === 'literal' ? fragment.value : ''))
      .join(''),
    quoted: variable.quoted,
    suffix: fragments
      .slice(variableIndex + 1)
      .map((fragment) => (fragment.kind === 'literal' ? fragment.value : ''))
      .join(''),
    variable: variable.variable,
  };
};

const quotedExpansion = (
  word: Word,
): { readonly variable: string; readonly suffix: string } | null => {
  const parts = word.parts ?? [];
  if (parts.length !== 1 || parts[0]?.type !== 'DoubleQuoted') {
    return null;
  }
  const children = parts[0].parts;
  if (children.length < 1 || children.length > 2) {
    return null;
  }
  const [firstChild] = children;
  const variable = firstChild === undefined ? null : expansionVariable(firstChild);
  if (variable === null) {
    return null;
  }
  const [, suffixPart] = children;
  if (suffixPart !== undefined && suffixPart.type !== 'Literal') {
    return null;
  }
  return { variable, suffix: suffixPart?.value ?? '' };
};

const trustedTempWord = (word: Word, environment: Environment): ShellWord | null => {
  const expansion = quotedExpansion(word);
  if (expansion === null || !environment.temps.has(expansion.variable)) {
    return null;
  }
  const { suffix, variable } = expansion;
  if (
    (suffix !== '' && !suffix.startsWith('/')) ||
    suffix.split('/').includes('..') ||
    suffix.includes('\0')
  ) {
    return null;
  }
  return {
    source: word.text,
    value: `${TRUSTED_TEMP_ROOT}/${variable}${suffix}`,
    kind: 'trusted-temp-path',
    range: rangeOf(word),
    quoted: true,
    variable,
  };
};

const boundWord = (word: Word, environment: Environment): ShellWord | null => {
  const expansion = scalarExpansion(word);
  if (expansion === null) {
    return null;
  }
  const { prefix, quoted, suffix, variable } = expansion;
  const binding = environment.bindings.get(variable);
  if (
    binding === undefined ||
    binding.kind === 'dynamic' ||
    binding.kind === 'trusted-temp-path' ||
    (binding.kind === 'background-pid' && (prefix !== '' || suffix !== '')) ||
    suffix.split('/').includes('..') ||
    prefix.split('/').includes('..')
  ) {
    return null;
  }
  const value = `${prefix}${binding.value}${suffix}`;
  if (
    !quoted &&
    (/\s/u.test(value) || value.includes('*') || value.includes('?') || value.includes('['))
  ) {
    return null;
  }
  return { ...binding, source: word.text, value, range: rangeOf(word), quoted, variable };
};

const backgroundPidWord = (word: Word, environment: Environment): ShellWord | null => {
  const expansion = scalarExpansion(word);
  if (
    !environment.backgroundPidAvailable ||
    expansion?.variable !== '!' ||
    expansion.prefix !== '' ||
    expansion.suffix !== ''
  ) {
    return null;
  }
  return {
    source: word.text,
    value: BACKGROUND_PID_VALUE,
    kind: 'background-pid',
    range: rangeOf(word),
    quoted: expansion.quoted,
    variable: '!',
  };
};

export {
  DYNAMIC_VALUE,
  BACKGROUND_PID_VALUE,
  backgroundPidWord,
  boundWord,
  cloneEnvironment,
  emptyEnvironment,
  isQuotedPart,
  isTrustedMktemp,
  staticGeneratedValue,
  trustedTempWord,
  wordIsStatic,
};
export type { Environment };
