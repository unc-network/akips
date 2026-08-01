# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
From 1.0.0 onward, a breaking change requires a major release. Releases before
1.0.0 could break compatibility in a minor release; those are marked
**Breaking** below.

> Entries for 0.5.1 and earlier were reconstructed from git history and release
> tags after the fact, by comparing the public API at each tag. They record the
> user-visible changes but are not as detailed as entries written at the time.

## [1.0.0] - unreleased

The first release to commit to a stable API. Return shapes that disagreed with
each other are settled, the public methods are annotated, and the package ships
a `py.typed` marker, so what a caller gets back is now something a type checker
can see rather than something to be discovered at runtime.

Those corrections are breaking, and they are gathered here deliberately: better
to face them once than to meet them one at a time across several releases. From
here, a breaking change means a 2.0.

**Upgrading:** see [MIGRATING.md](MIGRATING.md) for what to change, with before
and after for each one.

### Added

- `ro_password` and `rw_password` on the client, and each call now
  authenticates as the account its API section requires. AKiPS ships two API
  accounts and its sections do not all accept the same one: `api-script`
  needs `api-rw`, `api-msg` needs `api-ro`, and `api-db` takes either. A
  single client could therefore never reach the whole API, and callers had to
  construct two of them and remember which was which.

  ```py
  api = AKIPS('akips.example.com', ro_password='...', rw_password='...')
  ```

  Where either account will do, the read only one is preferred. A section
  needing an account whose password was not supplied raises
  `AkipsCredentialError` before the request is made, naming the section, the
  account and the argument to pass, rather than letting AKiPS reject it.
  `call()` takes `user='ro'` or
  `user='rw'` for the sections this module does not model and for a command
  needing more rights than its section usually does.

  `username` and `password` still work: with `api-ro` or `api-rw` they fill
  that account, and with any other name that pair is used for every section,
  which is how a custom AKiPS API account will work once AKiPS offers them.
  Constructing a client with no password at all is now refused. **Breaking**
  for that case, which could never have authenticated anyway.
- A warning when a call names an API section AKiPS does not publish, which is
  usually a typo. `SECTION_USERS` now lists all ten documented sections, so it
  serves as both the account mapping and the list of what exists. Unknown
  sections are warned about rather than refused, because AKiPS may add
  sections and `call()` exists so that reaching one need not wait for a
  release here. Each section is warned about once per client, so a poll loop
  does not fill a log.
- `verify` accepts a path to a CA bundle as well as `True` or `False`, which
  requests has always supported but the annotation and documentation did not
  mention. This is how to trust a server whose certificate chain is missing an
  intermediate without turning verification off entirely.
- Type annotations on every public method, and an `akips/py.typed` marker so
  consumers type checking their own code see real types instead of `Any`.
  The annotations are checked with mypy in CI, so what the marker promises is
  verified here rather than discovered downstream.
- `timeout` on the client, defaulting to the 30 seconds already in use. It can
  be changed on an existing client with `api.timeout = 60`. Previously `_get`
  accepted a timeout that nothing forwarded, so callers had to subclass to
  reach it.
- `get_group_availability()` — availability statistics for a group over a time
  period, from the `api-availability` section.
- `get_ups_battery_status()` — which UPS batteries are not reporting as
  normal, defaulting to `unknown`, `batteryLow` and `batteryDepleted`. This is
  the battery's own condition, which UPS-MIB reports separately from where the
  UPS draws its output. Note that the numeric readings such as estimated
  minutes remaining are not available this way: AKiPS keeps those in its time
  series database, and reading them with `mget` returns the gauge's scaling
  factor, which is the same for every device.
- `get_ups_output_source()` — which UPS devices are not running on mains
  power. Returns the abnormal sources by default (`bypass`, `battery`,
  `booster`, `reducer`), since that is the list worth acting on; pass
  `states=None` for every UPS whatever its state. Note this is the output
  source rather than the battery's own health, which UPS-MIB reports
  separately as `upsBatteryStatus`.
- `get_liebert_battery_test()` — the result of the last UPS battery self test,
  defaulting to failures only. The vendor is in the name deliberately:
  battery test results are not in the standard UPS-MIB, so this reads an
  attribute only Liebert and Vertiv equipment reports, and against another
  vendor's fleet it would return nothing, which reads as good news. Another
  vendor's equivalent attribute can be passed to reuse the same parsing.

  Both return the parsed enum, so a caller gets the state and when it last
  changed rather than a raw string. These are the first callers of the enum
  parser, which had been kept unused pending evidence that the format
  generalised beyond ping and SNMP state; it does.
- `call()` — send a request to any API section and parse the reply in one of
  the shapes AKiPS replies in: `raw`, `lines`, `key_value`, `attributes`,
  `csv` or `csv_dict`. It replaces `cmd()`, which could only reach `api-db`
  and could only return the reply unparsed. Sections do not share a parameter
  vocabulary, so `api-db` takes a command string while the others take their
  own named parameters:

  ```py
  api.call("mget * TH840-A * *", output="attributes")
  api.call(section="api-msg", params={"time": "last1h"}, output="lines")
  ```

### Changed

- `get_unreachable()` reports `child` as the matched string. It was a one
  element tuple, the only field in that structure with a surprising type.
  **Breaking.**
- `get_device()` is keyed by device name, keeping the parent, child and
  attribute levels AKiPS stores its data in. It previously dropped the parent
  level and put the device name back as a `"name"` key sitting beside the
  child dictionaries, so the obvious loop over the result raised
  `AttributeError` on that one entry, and a child named `name` would have
  collided with it. Asking for one device now gives a dictionary with one key,
  the same shape `get_devices()` and `get_attributes()` return. **Breaking.**
- `get_device()` returns `None` when a response parses to nothing, instead of a
  dictionary holding only the name that was asked for, which a caller could not
  tell apart from a device that has no attributes. **Breaking.**
- An attribute with nothing after the equals is `None` from every method. It
  was `""` from `get_device()`, `None` from `get_attributes()`, and
  `get_devices()` dropped the line entirely, which could leave a device out of
  its own listing. **Breaking.**
- `get_unreachable()` returns `None` when nothing is reported down. It was the
  only one of eleven methods returning an empty container rather than `None`.
  **Breaking.**
- `get_msg()` renames two parameters: `time` becomes `period` and `type`
  becomes `msg_type`. `type` shadowed a builtin and `time` a standard library
  module, and `period` is what every other method here already calls a time
  filter. The request AKiPS receives is unchanged; only the Python argument
  names differ. **Breaking** for callers passing them by keyword, which is the
  usual way. `get_msg()` shipped in 0.5.1, so the exposure is small.
- Suppressing TLS warnings for `verify=False` is scoped to this client's own
  requests. It previously disabled urllib3 warnings for the whole process,
  silencing them for every other library in the calling application.
- `cmd()` is deprecated in favour of `call()`. It still works and still returns
  the reply unparsed, but now raises a `DeprecationWarning`. It will be removed
  in a future major release.
- Each reply shape is now parsed in exactly one place, shared between the
  specific methods and `call()`. `get_devices()`, `get_device()` and
  `get_attributes()` had each carried their own copy of the same
  `{parent} {child} {attribute} = {value}` parser, and three methods each
  hand-rolled CSV. No behavior changed; the existing tests passed untouched
  across the rewiring.
- The private `_get()` no longer takes a `timeout` argument; it reads the
  client's. This is internal, but noted because reaching into `_get` was the
  only way to change the timeout before, so anyone who subclassed to do that
  should pass `timeout` to the constructor instead and drop the subclass.

### Fixed

- **Credentials no longer reach the log or a traceback when a request fails.**
  AKiPS authenticates by query string, and requests reports the URL it was
  fetching in its exception messages, so the password appeared in full. The
  handler logged that message directly, and re-raised an exception still
  carrying it, so it also landed in any traceback the caller rendered. Both
  are scrubbed now. Anyone who has run a failing request against a previous
  release should treat the AKiPS password in those logs as exposed and
  rotate it.

  The whole exception chain is scrubbed, not only the exception raised.
  requests raises its error *from* the urllib3 one that caused it, and that
  inner exception holds the same URL — in its message and in a `url`
  attribute of its own. Anything rendering a full traceback renders the
  chain, so a failed call in an application that stores tracebacks would
  otherwise have written the password to wherever those are kept. The
  `response.url` on an `HTTPError` is scrubbed too, since error reporters
  read it separately from the message.

  Scrubbing can never mask the original failure: if an attribute turns out to
  be read only, the message is still cleaned and the original exception is
  still what reaches the caller.

  SNMP credentials no longer reach the debug log either. AKiPS keeps them as
  ordinary device attributes, so a reply to something as innocent as
  `get_device()` carries the community string and the v3 auth and priv
  passwords. Attribute values are now redacted wherever a reply is rendered
  for logging, and `get_device()` and `get_unreachable()` no longer dump their
  whole parsed result at debug level, which is how those values reached the
  log even once the reply itself was filtered. The caller still receives the
  real values; only what is logged changes.

  An error reply from AKiPS is also filtered before it is logged or raised.
  No AKiPS error seen so far echoes a credential back, so this is defence in
  depth rather than an observed leak. Only the query parameter form is
  removed there, never the password as a literal, because a short password
  would otherwise rewrite matching characters anywhere in a reply.
- `get_unreachable()` warns when it cannot parse a line instead of dropping it
  silently. That call is how a consumer learns what is broken, so a dropped
  line meant a device reported down was invisible, and under reporting an
  outage is the worst thing it can do. The warning carries a count and a
  sample.
- `get_unreachable()` no longer loses `ip4addr` depending on the order the
  server sent its lines. The SNMP branch set the address to None
  unconditionally, so it survived only when the SNMP line came first. `child`
  and `index` were the same last writer wins; the ping line now wins all
  three, since it is the only one carrying an address.
- `get_msg()` splits records on the blank line that terminates each one,
  rather than by recognising header lines. A message body line can look
  exactly like a header — `OSPF-MIB ospfNbrState 4 full` does — and turned one
  message into two, both with empty bodies. Records it cannot read are counted
  and warned about rather than dropped silently.
- `get_msg()` accepts only 4 or 6 as the IP version. The character class was
  `[4|6]`, which also matched a literal pipe.
- `get_unreachable()` reports the earliest event start for a device that is
  down on both ping and SNMP. Both branches overwrote the value before the
  comparison meant to keep the earlier one ran, so it compared a value against
  itself and whichever line arrived last won. The start time of an outage was
  therefore arbitrary for any device failing both checks.
- `get_msg()` no longer raises `IndexError` when a message line arrives before
  any header. It popped an empty list, failing the entire call.
- `cmd()` validates its output format before making the request, so an
  unsupported format fails whether or not the server returned anything.
- `_get()` takes a copy of the parameters it is given. Credentials were written
  into the dictionary the caller passed in, leaving the password somewhere
  redaction could not reach.
- `_parse_enum()` accepts descriptions containing spaces, such as
  `Ethernet 1`, which it previously rejected as not being an enum at all.
- `get_events()` logs the event type it was asked for rather than the built-in
  `type`.
- The six methods taking a `groups` list no longer share a mutable default
  argument.

## [0.6.0] - 2026-07-31

A maintenance release covering supported Python versions, dependency
security, and release automation. The client's own code is unchanged from
0.5.1 apart from the version string: every public method has the same
signature and behavior. The only difference an installer sees is the
raised Python floor.

Prototype `api-availability` methods remain disabled pending further
testing, so they are not part of this release.

### Added

- Python 3.14 to the supported and tested versions.
- Automatic tagging, GitHub release creation, and PyPI publishing when a
  new version reaches `main`. Release notes are taken from this file, and
  pre-release versions are refused on every route into the production
  publish.
- A security audit workflow running `pip-audit` against the locked
  dependencies on changes and weekly, plus ruff's `S` rules, which port
  bandit's static security checks into the existing lint pass.
- This changelog, backfilled from git history and release tags.
- `AI.md`, recording how AI tooling is used in this project and what it
  has and has not touched.

### Changed

- Updated all locked dependencies, clearing eleven security advisories.
  Every remaining fix required Python 3.10 or newer, which is what
  prompted the version floor below.
- Replaced pylama with ruff for linting. pylama has been unreleased since
  2022 and depends on `pkg_resources`, which recent setuptools removed. The
  same rules carry over: pycodestyle, pyflakes, and a 128 character line
  length. `setup.cfg` is gone, since it only held pylama's configuration.
- Replaced pdoc3 with pdoc for API documentation. pdoc3 has been unreleased
  since 2021 and imports `distutils`, which left the standard library in
  3.12. The module page moves from `docs/akips/index.html` to
  `docs/akips.html`; the previous path redirects, so existing links keep
  working.
- API documentation is now generated and published by CI on every push to
  `main`, rather than being generated by hand and committed. The published
  site tracks `main` and no longer follows `develop`.
- Publishing now uses separate `pypi` and `testpypi` environments instead
  of one shared environment named `prod`, so production releases and
  TestPyPI rehearsals can be governed independently.
- CI runs on pinned runner images rather than `-latest`, so moving to a
  new Ubuntu is a deliberate change rather than one that arrives on
  GitHub's schedule.

### Removed

- Python 3.9 support. The minimum supported version is now 3.10.
  **Breaking** for anyone still on 3.9, which reached end of life in
  October 2025.
- All long-lived PyPI and TestPyPI API tokens. Publishing is entirely
  through trusted publishing, so the project stores no credential that
  could leak or need rotating.

## [0.5.1] - 2025-11-19

### Added

- `get_msg()` — retrieve syslog and trap messages from the `api-msg` section.

### Changed

- Reorganized the source so methods are grouped by the AKiPS API section they
  use (`api-db`, `api-script`, `api-msg`).

## [0.5.0] - 2025-11-14

### Added

- Redaction of sensitive request parameters in debug logging, so passwords no
  longer appear in `logger.debug` output.

### Changed

- Documentation updates.

## [0.4.5] - 2025-10-06

### Changed

- Expanded the README usage examples and regenerated the API documentation.
- Poetry dependency updates.

## [0.4.4] - 2025-10-02

### Added

- Group filtering (`group_filter` and `groups`) on `get_events()`.

### Fixed

- `get_group_membership()` when querying a specific device key.

## [0.4.3] - 2025-10-02

### Fixed

- Typo in the `mget` command built by `get_attributes()`. Thanks to
  [@kvncampos](https://github.com/kvncampos).

## [0.4.2] - 2025-04-01

### Added

- `get_attributes()` — attribute queries filtered by device, child, attribute,
  value, and group membership.

### Removed

- `get_status()`, superseded by `get_attributes()`. **Breaking.**

## [0.4.1] - 2025-04-01

Published to PyPI at the time, but not tagged until later. The `v0.4.1` tag was
added retroactively, pointing at the commit whose contents match the published
0.4.1 wheel.

### Added

- `cmd()` — experimental low-level passthrough for raw api-db command strings.
- `time_interval` parameter on `get_series()`. Thanks to
  [@kvncampos](https://github.com/kvncampos).

## [0.4.0] - 2025-02-20

### Added

- GitHub Actions workflows for code quality (pylama, black) and pytest across
  the supported Python matrix.
- Contributing guide.

### Changed

- Formatted the codebase with black.
- Updated repository references to the `unc-network` organization.

### Removed

- Python 3.8 support. The minimum supported version is now 3.9.

## [0.3.1] - 2024-09-17

### Changed

- Packaging and publish workflow updates following the repository move to the
  `unc-network` organization.

## [0.3.0] - 2024-05-14

### Added

- `set_group_membership()` — assign or clear manual group membership through the
  `web_manual_grouping` site script, with validation of the device, group, and
  mode arguments.
- `device` filter on `get_group_membership()`.

### Changed

- `get_device_by_ip()` now resolves names through the `web_find_device_by_ip`
  site script in the `api-script` section.

### Removed

- `get_maintenance_mode()` and `set_maintenance_mode()`, replaced by
  `set_group_membership()` against the `maintenance_mode` group. **Breaking.**

## [0.2.3] - 2024-05-14

### Added

- `timezone` constructor option for the AKiPS server timezone, defaulting to
  `America/New_York`.
- Internal helper for parsing enum-typed attribute values.

## [0.2.2] - 2024-05-13

### Added

- `get_aggregate()` — aggregate counter values over a time period.

## [0.2.1] - 2024-04-12

### Changed

- Widened the supported Python range from `^3.10` to `>=3.8.1,<4.0`.

## [0.2.0] - 2024-04-11

### Added

- `get_series()` — time-series counter values via the `cseries` command.
- Group filtering on device and attribute queries.

## [0.1.5] - 2023-10-11

### Added

- Device and group membership queries.
- Mock-based unit tests for the response parsers.

### Changed

- Renamed the request helper `akips_get()` to `_get()`, making it private.
  **Breaking** for anyone who called it directly.

## [0.1.4] - 2023-09-25

First tagged release. Provides the `AKIPS` client with `get_devices()`,
`get_device()`, `get_device_by_ip()`, `get_unreachable()`,
`get_group_membership()`, `get_maintenance_mode()`, `set_maintenance_mode()`,
`get_status()`, and `get_events()`, along with the `AkipsError` exception.

Releases before this one are not tagged in git and are not recorded here.

[1.0.0]: https://github.com/unc-network/akips/compare/v0.6.0...develop
[0.6.0]: https://github.com/unc-network/akips/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/unc-network/akips/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/unc-network/akips/compare/v0.4.5...v0.5.0
[0.4.5]: https://github.com/unc-network/akips/compare/v0.4.4...v0.4.5
[0.4.4]: https://github.com/unc-network/akips/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/unc-network/akips/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/unc-network/akips/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/unc-network/akips/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/unc-network/akips/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/unc-network/akips/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/unc-network/akips/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/unc-network/akips/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/unc-network/akips/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/unc-network/akips/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/unc-network/akips/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/unc-network/akips/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/unc-network/akips/releases/tag/v0.1.4
