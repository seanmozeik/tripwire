import type { Command } from 'unbash';

import type { ShellWord, SourceRange } from './types';
import { wordIsStatic } from './values';

const rangeOf = (node: { readonly pos: number; readonly end: number }): SourceRange => ({
  start: node.pos,
  end: node.end,
});

const basename = (value: string): string => {
  const index = value.lastIndexOf('/');
  return index === -1 ? value : value.slice(index + 1);
};

const staticCommandWords = (command: Command): ShellWord[] | null => {
  if (
    command.name === undefined ||
    command.prefix.length > 0 ||
    command.redirects.length > 0 ||
    !wordIsStatic(command.name) ||
    command.suffix.some((word) => !wordIsStatic(word))
  ) {
    return null;
  }
  return [command.name, ...command.suffix].map((word) => ({
    source: word.text,
    value: word.value,
    kind: 'literal',
    range: rangeOf(word),
    quoted: (word.parts ?? []).some(
      (part) =>
        part.type === 'SingleQuoted' ||
        part.type === 'DoubleQuoted' ||
        part.type === 'AnsiCQuoted' ||
        part.type === 'LocaleString',
    ),
  }));
};

export { basename, rangeOf, staticCommandWords };
