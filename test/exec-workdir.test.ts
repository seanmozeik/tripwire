import * as bunTest from 'bun:test';
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { decide } from '../src/dispatch';

bunTest.test(
  'exec_command uses workdir for protected relative targets and falls back to event cwd',
  () => {
    const root = mkdtempSync(path.join(tmpdir(), 'tripwire-exec-workdir-'));
    const protectedDirectory = path.join(root, 'protected');
    const ordinaryDirectory = path.join(root, 'ordinary');
    try {
      mkdirSync(protectedDirectory);
      mkdirSync(ordinaryDirectory);
      writeFileSync(path.join(protectedDirectory, '.env'), 'fixture');
      symlinkSync('.env', path.join(protectedDirectory, 'output'));
      for (const toolName of ['exec_command', 'functions.exec_command']) {
        for (const fixture of [
          { cwd: ordinaryDirectory, workdir: protectedDirectory, expected: 'deny' },
          { cwd: protectedDirectory, workdir: ordinaryDirectory, expected: 'allow' },
          { cwd: protectedDirectory, expected: 'deny' },
          { cwd: ordinaryDirectory, expected: 'allow' },
        ] as const) {
          const result = decide({
            hook_event_name: 'PreToolUse',
            tool_name: toolName,
            cwd: fixture.cwd,
            tool_input: {
              cmd: 'python3 -c \'open("output", "w").write("value")\'',
              ...('workdir' in fixture && { workdir: fixture.workdir }),
            },
          });
          bunTest.expect(result.kind).toBe(fixture.expected);
        }
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  },
);
