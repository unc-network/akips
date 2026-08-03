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

AKiPS authenticates web API calls with a password sent as a request parameter.
That is the only authentication the API offers, so this package has no
alternative to using it. Credentials are held in memory on the client for the
lifetime of an `AKIPS` instance and are never written to disk by this package.

Because those credentials travel in requests, and because AKiPS stores SNMP
community strings and v3 passwords as ordinary device attributes, replies and
error messages can carry secrets. This package therefore redacts credential
parameters and sensitive attribute values from:

- its own log output, at every level
- exception messages, including the whole `__cause__` and `__context__` chain
  rather than only the exception raised
- the response URL attached to HTTP errors

**A failure of any of that is a vulnerability in this package.** If you can
make `akips` write a credential to a log, an exception, or a traceback, please
report it.

Redaction applies to logs and exceptions, not to data returned to the caller.
A reply legitimately containing an SNMP community is returned as-is, because
the caller asked for it. What you print, persist or forward is yours to
handle.

## For contributors

Test data is invented, never captured. AKiPS replies routinely carry
credentials in fields that look like any other, so a fixture built from a real
reply can publish a secret without anyone noticing. Read real output for its
shape, then write the fixture from scratch with obviously fake values, and use
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) addresses rather than
real ones.

Realism in a fixture is never worth a real value. A parser cannot tell the
difference.
