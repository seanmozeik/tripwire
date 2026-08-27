import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { chmod, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { resolveTripwireCommand } from '../src/lib/runtime-command';

let root = '';

beforeEach(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'tripwire-runtime-'));
});

afterEach(async () => {
  delete process.env['TRIPWIRE_FORCE_PORTABLE'];
  await rm(root, { force: true, recursive: true });
});

describe('runtime command resolution', () => {
  test('selects the optional native executable on Apple Silicon', async () => {
    const native = path.join(root, 'tripwire');
    await writeFile(native, '#!/bin/sh\n');
    await chmod(native, 0o755);
    const resolvedNative = await realpath(native);

    expect(
      resolveTripwireCommand({
        architecture: 'arm64',
        moduleUrl: pathToFileURL(path.join(root, 'tripwire-cli.js')),
        nativeResolver: () => native,
        platform: 'darwin',
      }),
    ).toEqual({ arguments: [], executable: resolvedNative, kind: 'native' });
  });

  test('selects the portable Bun bundle on every other platform', () => {
    const portable = path.join(root, 'tripwire.js');
    expect(
      resolveTripwireCommand({
        architecture: 'x64',
        bunExecutable: '/usr/local/bin/bun',
        platform: 'linux',
        portableExecutable: portable,
      }),
    ).toEqual({ arguments: [portable], executable: '/usr/local/bin/bun', kind: 'portable' });
  });

  test('falls back safely when the optional package is unavailable', () => {
    const portable = path.join(root, 'tripwire.js');
    expect(
      resolveTripwireCommand({
        architecture: 'arm64',
        nativeResolver: () => path.join(root, 'missing'),
        platform: 'darwin',
        portableExecutable: portable,
      }).kind,
    ).toBe('portable');
  });

  test('supports an explicit portable-path diagnostic override', async () => {
    const native = path.join(root, 'tripwire');
    await writeFile(native, '#!/bin/sh\n');
    await chmod(native, 0o755);
    process.env['TRIPWIRE_FORCE_PORTABLE'] = '1';

    expect(
      resolveTripwireCommand({
        architecture: 'arm64',
        nativeResolver: () => native,
        platform: 'darwin',
        portableExecutable: path.join(root, 'tripwire.js'),
      }).kind,
    ).toBe('portable');
  });
});
