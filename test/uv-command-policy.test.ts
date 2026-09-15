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

bunTest.describe('uv dependency setup guidance', () => {
  bunTest.test.each([
    'uv run --with pandas python -c "print(1)"',
    'uv run --with=pandas python -c "print(1)"',
    'uv run --with-requirements requirements.txt python -c "print(1)"',
    'uv run --with-editable . python -c "print(1)"',
  ])('gives a complete setup path: %s', (command) => {
    const result = decideBash(command);
    bunTest.expect(result.kind).toBe('deny');
    for (const step of [
      'pyproject.toml',
      'uv sync',
      'uv run --no-sync python -c',
      '--python',
      '3.12',
    ]) {
      bunTest.expect(result.message).toContain(step);
    }
  });
  bunTest.test('accepts the recommended invocation', () => {
    bunTest.expect(decideBash('uv run python -c "print(1)"').kind).toBe('allow');
    bunTest
      .expect(decideBash('uv run --python 3.12 --no-sync python -c "print(1)"').kind)
      .toBe('allow');
  });
  bunTest.test('leaves dependency-like child arguments alone', () => {
    bunTest.expect(decideBash('uv run --no-sync printf --with pandas').kind).toBe('allow');
    bunTest.expect(decideBash('uv run --no-sync -- printf --with=pandas').kind).toBe('allow');
  });
});
