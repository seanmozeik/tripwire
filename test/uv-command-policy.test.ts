import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';

bunTest.describe('uv forwarded commands (policy data only)', () => {
  bunTest.test.each([
    'uv run --no-sync rm -rf /protected',
    'uv --offline run --frozen rm -rf /protected',
    'uv run --no-sync -- /bin/rm -rf /protected',
    'env uv run --no-sync rm -rf /protected',
    'uv run --no-sync uv run --no-sync rm -rf /protected',
    'uv run --no-sync git reset --hard',
    'uv run --project /protected rm -rf dist',
    'uv run --directory /protected rm -rf dist',
    'uv run --no-sync "$PROGRAM"',
    'uv run --no-sync rm -rf /protected # tripwire-allow: fixture',
  ])('denies %s', (command) => {
    bunTest.expect(decideBash(command).kind).toBe('deny');
  });
  bunTest.test.each([
    'uv run --no-sync printf hello',
    'uv run --no-sync git status',
    'uv --offline run --no-sync -- printf hello',
  ])('preserves ordinary command handling: %s', (command) => {
    bunTest.expect(decideBash(command).kind).toBe('allow');
  });
});
