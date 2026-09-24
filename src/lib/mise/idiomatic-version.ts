import { assertSafe } from './inspection-error';

// A closed grammar for version selectors, never ToolRequest paths/backends/commands.
// This deliberately does not change config.ts's [tools] contract.
const release = String.raw`v?(?:[0-9]+|[xX*])(?:\.(?:[0-9]+|[xX*])){0,3}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?`;
const exact = new RegExp(`^${release}$`, 'u');
const comparator = new RegExp(String.raw`^(?:>=|<=|>|<|=|\^|~)?${release}$`, 'u');
const operator = /^(?:>=|<=|>|<|=|\^|~)$/u;
const trim = (source: string): string =>
  source.replaceAll(/^\p{White_Space}+|\p{White_Space}+$/gu, '');
const stripBom = (source: string): string => source.replace(/^\uFEFF/u, '');

const versionRange = (source: string): boolean => {
  const tokens = trim(source).split(/\p{White_Space}+/u);
  if (tokens.length === 3 && tokens[1] === '-') {
    return exact.test(tokens[0] ?? '') && exact.test(tokens[2] ?? '');
  }
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index] ?? '';
    if (operator.test(token)) {
      index += 1;
      if (!exact.test(tokens[index] ?? '')) {
        return false;
      }
    } else if (!comparator.test(token)) {
      return false;
    }
  }
  return true;
};

const assertVersionSelector = (value: unknown, context: string): void => {
  assertSafe(
    typeof value === 'string' &&
      (/^(?:latest|system|lts(?:\/(?:\*|[a-z][a-z0-9-]*))?)$/u.test(value) ||
        value.split('||').every((part) => versionRange(part))),
    `${context}: unverified idiomatic version.`,
  );
};

// Backend/mod.rs::normalize_idiomatic_contents: only whitespace introduces an
// inline comment. A '#' within a token remains part of the version to validate.
const versionLines = (source: string): string[] =>
  stripBom(source)
    .split(/\r?\n/u)
    .map((line) => trim(line).replace(/(?:^|\p{White_Space})#.*$/u, ''))
    .map((line) => trim(line))
    .filter((line) => line !== '');

export { assertVersionSelector, stripBom, versionLines };
