# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |
| < 1.0 | no |

Fixes are made on the latest release. Releases before 1.0.0 were published
without a stability commitment and are not maintained.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting, on the
[Security tab](https://github.com/unc-network/akips/security/advisories) of
this repository. That keeps the report private until there is something to
announce, and it does not require a public issue.

If that is unavailable to you, open an issue asking for a private contact
without describing the problem in it.

Useful things to include:

- what an attacker gains, and what access they need to start
- the version of this package, and of AKiPS if it is relevant
- steps to reproduce, ideally against a server you control
- **no real credentials, hostnames or captured output** — see below

You should get an acknowledgment within five working days. This is a small
project with one maintainer, so a fix may take longer than the
acknowledgment; you will be told which release to expect it in. Credit is
offered in the changelog unless you would rather not be named.

## Scope

**In scope**

- the `akips` Python package
- the site scripts under `akips_setup/`, which run on the AKiPS server itself
  and therefore deserve more care than the client does
- anything causing this package to disclose a credential it was trusted with

**Not in scope**

- vulnerabilities in AKiPS itself. This package is a client; it cannot fix the
  server. Report those to AKiPS support, who have handled such reports
  promptly in our experience
- behavior that requires credentials the attacker already holds, unless it
  crosses a privilege boundary such as a read-only account reaching a
  read-write one
- the security of your own AKiPS deployment, its network placement, or its
  account policy

## How this package handles credentials

Worth stating plainly, because it shapes what counts as a vulnerability here.

AKiPS 26.6 applications authenticate with bearer tokens. This package sends
them in the Authorization header, keeping them out of request URLs. Older
deployments can still use passwords sent as request parameters; that legacy
authentication is deprecated by AKiPS and scheduled for removal in 28.1.
Credentials are held in memory on the client for the
lifetime of an `AKIPS` instance and are never written to disk by this package.

In August 2026 we reported to AKiPS that, on 26.5, the legacy HTTP Log API
could return request URLs containing `api-rw` passwords to callers holding
`api-ro`. This prompted the earlier move to POST for legacy sections that
accepted it, keeping their passwords out of request URLs. Application
authentication addresses this exposure through bearer headers and API
permissions assigned to individual applications. This client uses the header
form so its token is kept out of request URLs.

Retained HTTP logs and copies held by proxies or load balancers may still
contain legacy credentials. Switching this client to a token does not remove
those entries, and this package's diagnostic redaction does not alter server
or infrastructure logs. Both legacy account holders and application token
holders with HTTP Log access can read retained entries. Follow the migration
sequence below before granting or restoring that access.

Because those credentials travel in requests, and because AKiPS stores SNMP
community strings and v3 passwords as ordinary device attributes, replies and
error messages can carry secrets. This package therefore redacts credential
parameters and sensitive attribute values from:

- its own log output, at every level
- exception messages, including the whole `__cause__` and `__context__` chain
  rather than only the exception raised
- the response URL and Authorization headers on requests attached to HTTP errors

**A failure of any of that is a vulnerability in this package.** If you can
make `akips` write a credential to a log, an exception, or a traceback, please
report it.

Redaction applies to logs and exceptions, not to data returned to the caller.
A reply legitimately containing an SNMP community is returned as-is, because
the caller asked for it. What you print, persist or forward is yours to
handle.

## Migrating authentication and cleaning retained logs

Contact AKiPS support early to plan log cleanup and any required maintenance
window. For deployments moving to application tokens, use this order:

1. **Restrict HTTP Log access first.** Turn off the legacy HTTP Log API in
   **Web API Settings** to block access through `api-ro`. Separately revoke
   existing applications with HTTP Log permission, replacing them without
   that permission if their other APIs are still needed. Application
   permissions cannot be edited, and the legacy switches do not restrict
   tokens. Restrict access to exported logs and infrastructure copies too.
2. **Inventory and migrate clients.** Include `api-ro` and `api-rw` consumers,
   HTTP Log readers, site scripts, scheduled jobs, and ad hoc requests. Give
   each integration an application with only the APIs it needs and send
   tokens in the Authorization bearer header. Leave HTTP Log permission out
   of ordinary integrations; defer new log-reader applications until cleanup
   is verified.
3. **Stop credential-bearing URLs before the final cleanup.** Migrate or
   pause legacy GET clients, including this package's legacy Site Scripts
   calls, even when a script only reads data. Also stop clients using tokens
   in the `tok` query parameter. Legacy POST clients may remain temporarily
   only after verifying that new requests do not put credentials in URLs or
   logs. Keep log access restricted while URL credentials are still
   being generated; an early cleanup can help, but new requests can undo it.
4. **Retire or rotate exposed credentials.** Retire unused legacy credentials;
   coordinate password changes with consumers that still need them. Cover
   both `api-ro` and `api-rw`: a recovered read-only password can also grant
   APIs outside a token's scope. Revoke any tokens previously sent in URLs.
   Cleanup cannot invalidate credentials already copied by a reader. If
   compromise is suspected, revoke or rotate promptly; if replacement
   credentials also reach logs during migration, replace them again after
   those requests stop.
5. **Perform the final cleanup with AKiPS support.** Ask support for
   assistance with their offered legacy-password log-cleanup script. Follow
   their instructions and confirm which retained logs it covers. Schedule
   the final pass after the last credential-bearing URL request. Separately
   address proxy, load-balancer, exported, and archived copies; do not assume
   the AKiPS script cleans those or removes URL tokens.
6. **Verify, then enable designated log readers.** Confirm retained logs and
   new requests no longer expose valid credentials before creating and
   distributing dedicated applications with HTTP Log permission. Keep the
   legacy HTTP Log switch off while shared legacy accounts remain in use;
   token readers do not require that switch to be enabled.

The timing depends on which clients remain:

| Remaining use | When HTTP Log access can resume |
| --- | --- |
| All clients use bearer headers | After exposed credentials are retired or rotated and cleanup is verified. |
| Some legacy clients use POST | After verifying they do not log credentials, rotating exposed passwords, and verifying cleanup; keep legacy HTTP Log off. |
| Legacy GET, legacy Site Scripts, or query-token clients remain | Keep access restricted until those credential-bearing requests stop and the final rotation and cleanup are complete. |
| Legacy HTTP Log readers remain | Migrate them to dedicated tokens after cleanup; do not restore shared `api-ro` log access while other legacy consumers remain. |

These conditions can overlap. Use the most restrictive applicable timing;
switching only the log reader to a token does not make retained passwords safe.

## For contributors

Test data is invented, never captured. AKiPS replies routinely carry
credentials in fields that look like any other, so a fixture built from a real
reply can publish a secret without anyone noticing. Read real output for its
shape, then write the fixture from scratch with obviously fake values, and use
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) addresses rather than
real ones.

Realism in a fixture is never worth a real value. A parser cannot tell the
difference.
