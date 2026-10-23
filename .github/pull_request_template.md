## What and why

## Checklist

- [ ] `npm test` passes
- [ ] `npx tsc` passes
- [ ] Security-sensitive change: added a test that fails without the fix (broke the code, ran the whole test file, restored it)
- [ ] README and docs updated if behavior changed
- [ ] No new runtime dependency
- [ ] Works without network access beyond the provider
- [ ] Minting or credential-changing paths go through `requireAuth`; DB writes re-sign the row
- [ ] No em dashes in user-facing text

Platforms tested on:
