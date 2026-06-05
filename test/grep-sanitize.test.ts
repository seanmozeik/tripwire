import { describe, expect, test } from 'bun:test';

import { sanitizeGrepFlags } from '../src/lib/grep-sanitize';

describe('sanitizeGrepFlags', () => {
  test.each([
    ['grep -rn def file', 'grep -n def file'],
    ['grep -rln x src/', 'grep -ln x src/'],
    ['grep -nE pat f', 'grep -n pat f'],
    ['grep -r foo .', 'grep foo .'],
    ['grep --recursive --extended-regexp pat f', 'grep pat f'],
    ["rg -rn -i 'x' lib/", "rg -n -i 'x' lib/"],
    ['grep -A3 -r pat f', 'grep -A3 pat f'],
    ['grep -rA3 pat f', 'grep -A3 pat f'],
    ['grep -e -r f', 'grep -e -r f'],
    ['grep foo -r', 'grep foo'],
    ['cat -r file', 'cat -r file'],
    ['grep -rn a f && echo -r', 'grep -n a f && echo -r'],
  ])('%s -> %s', (input, expected) => {
    expect(sanitizeGrepFlags(input)).toBe(expected);
  });

  test.each([
    ['grep -Rln x src/', 'grep -ln x src/'],
    ['egrep -E pat f', 'egrep pat f'],
    ['fgrep --dereference-recursive pat f', 'fgrep pat f'],
    ['rg --recursive -- foo -r', 'rg -- foo -r'],
    ['grep -A 3 -r pat f', 'grep -A 3 pat f'],
    ['grep -m 5 -E pat f', 'grep -m 5 pat f'],
    ['grep -d recurse -r pat f', 'grep -d recurse pat f'],
    ['grep -D read -R pat f', 'grep -D read pat f'],
    ['grep pat f | rg -REn x', 'grep pat f | rg -n x'],
    ['/bin/grep -rn pat f', '/bin/grep -n pat f'],
  ])('handles edge case %s', (input, expected) => {
    expect(sanitizeGrepFlags(input)).toBe(expected);
  });
});
