import * as bunTest from 'bun:test';

import { decideBash } from '../src/dispatch';

// From an Astra search refusal at 2026-09-10T23:41:18Z (11 September local).
// All commands are inert policy input. No GitHub requests are sent.
bunTest.test.each([
  "gh api --method GET search/issues -f q='repo:example/project status' -f sort=updated -f per_page=20",
  'gh api search/issues -f q=sample --method=GET',
  'gh api -XGET search/issues -F per_page=20',
  'gh api -X=GET search/issues -Fper_page=20',
  'gh api search/issues --method POST --method GET -f q=sample',
  "gh api repos/example/project --jq '.name'",
])('allows read request: %s', (command) => {
  bunTest.expect(decideBash(command).kind).toBe('allow');
});

bunTest.test.each([
  'gh api search/issues -f q=sample',
  'gh api search/issues -fq=sample',
  'gh api repos/example/project -XDELETE',
  'gh api repos/example/project -XGET -XDELETE',
  'gh api repos/example/project --method=GET --method=PATCH',
  'gh api search/issues -f --method=GET',
  'gh api search/issues --header --method=GET -f q=sample',
  'gh api repos/example/project --input body.json',
  'gh api --method GET search/issues --input body.json',
  'gh api --method GET search/issues -F query=@.env',
  'gh api --method GET search/issues --field=query=@-',
  "gh api graphql --method GET -f 'query=mutation { placeholder }'",
  'gh api repos/example/project --method "$METHOD"',
  'gh api search/issues --unknown=GET -f q=sample',
])('preserves mutation review: %s', (command) => {
  bunTest.expect(decideBash(command).kind).toBe('deny');
});
