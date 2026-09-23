import * as bunTest from 'bun:test';
import { cpuUsage } from 'node:process';

import { analyzeCode } from '../../src/lib/code/analyze';
import { Scopes } from '../../src/lib/code/scope';
import { parseCode } from '../../src/lib/code/syntax';

bunTest.test('nested literal loops with calls stop within a bounded amount of CPU work', () => {
  const values = Array.from({ length: 128 }, (_, index) => index + 1).join(',');
  const source = `def f(x):\n return x + 1\nt = 0\nfor a in [${values}]:\n for b in [${values}]:\n  t = f(a) + f(b) + a * b`;
  const started = cpuUsage();
  const elapsed = performance.now();
  const report = analyzeCode('python', source);
  const used = cpuUsage(started);
  bunTest.expect(report.gap).toContain('budget');
  bunTest.expect(used.user + used.system).toBeLessThan(250_000);
  bunTest.expect(performance.now() - elapsed).toBeLessThan(1000);
});

bunTest.test('returned closures retain state and released call frames do not accumulate', () => {
  const scopes = new Scopes();
  const root = scopes.create();
  const captured = scopes.create(root);
  captured.set('target', { kind: 'string', value: '/tmp/example' });
  root.set('closure', {
    kind: 'closure',
    scope: captured,
    parameters: [],
    body: parseCode('python', 'pass'),
    expression: false,
  });
  scopes.release(captured);
  for (let index = 0; index < 1000; index += 1) {
    const frame = scopes.create(root);
    scopes.release(frame);
  }
  const snapshot = scopes.snapshot();
  bunTest.expect(snapshot.size).toBe(2);
  bunTest.expect(snapshot.has(captured)).toBe(true);
  captured.set('target', { kind: 'string', value: '/' });
  Scopes.restore(snapshot);
  bunTest.expect(captured.get('target')).toEqual({ kind: 'string', value: '/tmp/example' });
  root.delete('closure');
  bunTest.expect(scopes.snapshot().size).toBe(1);
});
