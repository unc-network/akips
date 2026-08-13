# Site scripts

AKiPS can be extended with Perl functions that run on the server, and two of
this module's methods depend on one each. They are reproduced here so both can
be installed without hunting through a catalogue.

| File | Used by | Where it came from |
| --- | --- | --- |
| [web_manual_grouping.pl](web_manual_grouping.pl) | `set_group_membership()` | AKiPS's site scripts page, listed as "Web API to Add/Delete Manual group" |
| [web_find_device_by_ip.pl](web_find_device_by_ip.pl) | `get_device_by_ip()` | AKiPS support directly — **not published** |

## These are AKiPS's, not ours

Both were written and are published by AKiPS, on their
[site scripts page](https://www.akips.com/customer-support/site-scripts/).
They are copied here unmodified, and they are **not covered by this
repository's MIT license**.

They came by different routes, and that changes what to do with each.

`web_manual_grouping` **is published**. Install AKiPS's current version, since
their page is authoritative; the copy here is byte identical as of the date in
its header and exists as the record of what the module was coded against.

`web_find_device_by_ip` **is not published anywhere**. AKiPS support wrote it
for this project in February 2023, so there is no public version to compare
against and this copy is the only reference. Ask support if you need to know
whether a newer one exists.

It exists because the addresses configured on a device are held in a CSV file
on the server rather than in the AKiPS database — the same file the GUI shows
as its "Device to IP Mapping" report — so no `mget` against device attributes
can find them. AKiPS noted the script may be customized as long as the
function name still begins `web_`, though doing so makes the result yours to
maintain and the module's parsing would have to keep step.

Neither carries a version or date of its own, so nothing can track a revision
automatically. Each file spells out exactly what the corresponding Python
method relies on, so a newer script can be checked against it rather than
adopted blind.

One file per function, matching how AKiPS publishes them, so a copy here can
be compared against a fresh download without extracting a sub from a larger
file first.

## Installing

For each file:

1. Paste the function into **Admin > Site Scripting** on the AKiPS server.
2. Create the `api-rw` user under **Admin > Users / Profiles > User Settings**.
3. Turn on **Site Script Functions** under **Admin > API > Web API Settings**.

Both are prerequisites rather than enhancements. Without them the two methods
above cannot work, whatever credentials you hold — `get_device_by_ip()` will
warn that the site script may not be installed, and `set_group_membership()`
will raise with whatever the server said.

## Other scripts

AKiPS publishes many more on the same page, including device discovery,
rewalk, rename and delete, which this module may wrap in future. Two things
are worth knowing before adopting any of them:

- Prefer forms that read SNMP parameters from the server's own configuration
  rather than taking them as arguments. `web_discover_device` does this when
  `snmp_param` is omitted, which keeps credentials out of the request, the
  server's HTTP log, and any proxy in the path.
- None of them report success. They do the work and return nothing, so an
  empty reply means only that nothing complained. Verify the outcome rather
  than trusting the silence.
