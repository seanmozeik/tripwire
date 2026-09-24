import * as bunTest from 'bun:test';

import { joinStartup, type StartupState } from '../src/lib/bash/startup';

bunTest.test('startup joins retain the most restrictive state and first reason', () => {
  const direct: StartupState = { kind: 'direct' };
  const checked: StartupState = { kind: 'checked' };
  const first: StartupState = { kind: 'unverified', reason: 'first' };
  const second: StartupState = { kind: 'unverified', reason: 'second' };
  bunTest.expect(joinStartup()).toEqual(direct);
  bunTest.expect(joinStartup(direct, checked, direct)).toEqual(checked);
  bunTest.expect(joinStartup(checked, first, second)).toEqual(first);
  bunTest.expect(joinStartup(first, checked)).toEqual(first);
  bunTest.expect(joinStartup(second, first)).toEqual(second);
});
