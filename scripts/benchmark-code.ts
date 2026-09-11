import { performance } from 'node:perf_hooks';

import { decideBash } from '../src/dispatch';
import { codeFixtures } from '../test/fixtures/embedded-code';

// Only invoke the policy function. No fixture can reach a shell or interpreter.
const timings: number[] = [];
const cwd = '/tripwire-policy-fixture';
for (const fixture of codeFixtures) {
  decideBash(fixture.command, {}, { cwd });
}
for (let round = 0; round < 20; round += 1) {
  for (const fixture of codeFixtures) {
    const start = performance.now();
    const decision = decideBash(fixture.command, {}, { cwd });
    timings.push(performance.now() - start);
    if ((decision.kind === 'allow' || decision.kind === 'warn') !== fixture.allowed) {
      throw new Error(`Unexpected decision for ${fixture.name}`);
    }
  }
}
timings.sort((left, right) => left - right);
const percentile = (fraction: number): number =>
  Number((timings[Math.floor((timings.length - 1) * fraction)] ?? 0).toFixed(3));
process.stdout.write(
  `${JSON.stringify({
    metric: 'warm Bash parsing plus embedded-code policy, milliseconds',
    samples: timings.length,
    fixtures: codeFixtures.length,
    p50: percentile(0.5),
    p95: percentile(0.95),
    p99: percentile(0.99),
    max: percentile(1),
  })}\n`,
);
