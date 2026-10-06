// Checks that the UI's Privacy mode masks the same as Go's logx.Sanitize:
// both run internal/logx/testdata/sanitize.json. Needs type stripping:
//
//	node --experimental-strip-types scripts/privacy-check.mjs
import { readFileSync } from 'node:fs';
import { maskDomains, maskHosts, maskIPs, maskURLs } from '../src/privacy.ts';

const table = JSON.parse(readFileSync(new URL('../../internal/logx/testdata/sanitize.json', import.meta.url), 'utf8'));
// As hide() in state.svelte.ts.
const hide = (s) => maskIPs(maskDomains(maskURLs(maskHosts(s, table.hosts))));
let bad = 0;
for (const c of table.cases) {
  const got = hide(c.in);
  if (got !== c.want) {
    bad++;
    console.error(`${JSON.stringify(c.in)}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(c.want)}`);
  }
}
if (bad) {
  console.error(`privacy.ts and logx.Sanitize differ in ${bad} of ${table.cases.length} cases`);
  process.exit(1);
}
console.log(`privacy.ts agrees with logx.Sanitize: ${table.cases.length} cases`);
