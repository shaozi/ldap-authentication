# AGENTS.md - guidance for AI coding agents working in this repo

## What this repo is

`ldap-authentication` - a small Node.js library that authenticates users against an
LDAP/AD server. It is a thin wrapper around `ldapts` (its only runtime dependency).

There is **no build step**. The package is published as-is:

- `index.js` - CJS implementation (all runtime logic lives here)
- `index.mjs` - ESM re-export entry point
- `index.d.ts` - hand-written TypeScript types (keep in sync with `index.js` and the README)
- `test/` - jasmine integration specs (require a running LDAP server)
- `example/` - runnable usage examples (require a running LDAP server)
- `docker/` + `docker-compose.yml` - the seeded OpenLDAP test server
- `dist/` - **stale legacy build (gitignored, not referenced by package.json, not
  published). Ignore it; do not edit or "fix" it.**

## Running the tests

The specs are integration tests against a seeded OpenLDAP container:

1. `docker compose -f docker-compose.yml up -d` - LDAP on `ldap://localhost:1389`,
   LDAPS on `ldaps://localhost:1636`
2. Wait until an admin bind succeeds (server is ready when this works)
3. `INGITHUB=true npm test` - the `INGITHUB` env var switches the specs from the
   docker-internal URL (`ldap://ldap:1389`) to `ldap://localhost:1389`
4. `docker compose -f docker-compose.yml down`

Or all of the above in one shot: `npm run test:local` (`scripts/test-local.sh`).

Seeded data (see `docker/ldap/*.ldif`): domain `dc=example,dc=com`; users
`cn=gauss` and `cn=einstein` in `ou=users` (both with password `password`); group
`cn=科学A部` in `ou=groups` containing gauss; admin
`cn=read-only-admin,dc=example,dc=com` (password `password`).
`test/binary.spec.js` MUTATES the directory (adds `jpegPhoto` to gauss), so spec
order matters - keep the deterministic order: in jasmine 7 the env options
(`random`, `seed`, `stopSpecOnExpectationFailure`) must be nested under the `env`
key in `loadConfig` (see `test/jasmine.js`).

## Code style

Prettier (`.prettierrc`): no semicolons, single quotes, 2-space indent, trailing
commas in `es5`. Match the existing style when editing `index.js`.

## Version control - IMPORTANT: this is a Jujutsu (jj) repo

This repo is managed with **jj** (see `.jj/`). Do NOT use `git commit` for commits;
use jj:

1. `jj describe -m "<message>"` - commits the current working-copy changes
   (after `jj describe`, jj may warn that the commit became immutable and create an
   empty working-copy commit on top - that is normal and harmless)
2. `jj bookmark move master` - move the local `master` bookmark to the new commit
   (defaults to the working copy, `@`)
3. `jj git push --bookmark master` - push to `origin`
   (`git@github.com:shaozi/ldap-authentication.git`). The remote prints a
   "Bypassed rule violations ... Changes must be made through a pull request"
   notice on master - that is expected (maintainer bypass) and not an error.

The maintainer works detached (no branch); commits go on the `master` bookmark
with a single descriptive message, e.g.
`"Add fetchUsers() to search all users via paged admin-bound lookup (#3); bump to 4.1.0"`.

## Releases

1. Bump `version` in **both** `package.json` and `package-lock.json` (the lockfile
   has it twice: top-level and under `packages."").version`). Follow semver
   (new feature = e.g. 4.1.0, docs/deps-only = patch).
2. Commit + push as above.
3. `jj tag set vN.N.N -r @-` (tag the just-pushed master commit), then
   `git push origin vN.N.N` (jj has no tag push in this version).
4. `gh release create vN.N.N --title "vN.N.N" --notes "..."` - creating the
   release triggers `.github/workflows/npm-publish.yml` (OIDC), which runs
   `npm ci && npm publish`.
5. Verify: `gh run list` (the `Publish Package` run should succeed) and
   `npm view ldap-authentication@N.N.N`. Note that the npm registry's packument
   can lag the publish by a couple of minutes - check the
   `https://registry.npmjs.org/ldap-authentication` `time`/`versions` before
   re-publishing. The legacy `publish.yml` workflow also triggers on release and
   its `npm publish` step fails with E404 because it duplicates the other
   workflow - that failure is expected/harmless; `publish.yml` is a candidate
   for deletion.

## CI

`integration-test.yml` runs on push/PR to `master`: builds the LDAP container from
`docker-compose.yml`, runs `npm ci` + `npm run test` with `INGITHUB=true` on a
Node 22.x/24.x matrix. Release events additionally trigger the publish workflows.

## When adding a new option

Update all of: the validation in `index.js` (`authenticateResult` /
`fetchUsers`), the JSDoc in `index.js`, `index.d.ts` (`AuthenticationOptions` and
/ or `FetchUsersOptions`), and the README (Parameters list, the
options-by-mode table, and an example if the option changes behavior). Add or
extend the specs in `test/` (integration specs run against the seeded container).
