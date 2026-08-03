[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/akips.svg)](https://img.shields.io/pypi/pyversions/akips)
[![PyPI](https://img.shields.io/pypi/v/akips.svg)](https://pypi.python.org/pypi/akips)
[![Downloads](https://static.pepy.tech/badge/akips)](https://pepy.tech/project/akips)
[![GitHub contributors](https://img.shields.io/github/contributors/unc-network/akips.svg)](https://GitHub.com/unc-network/akips/graphs/contributors/)

# akips

This akips module provides a simple way for python scripts to interact with 
the [AKiPS Network Monitoring Software](http://akips.com) API interface.

## Installation

To install akips, simply use pip:

```console
pip install akips
```

### AKiPS Setup

AKiPS includes a way to extend the server through custom perl scripts.  They publish a list from
their [Support - Site scripts](https://www.akips.com/customer-support/site-scripts/) page, along
with install instructions.

This module can use additional routines included in the *akips_setup* directory of 
this repository, [site_scripting.pl](akips_setup/site_scripting.pl).

## Usage Examples

### Connect to AKiPS

AKiPS ships two API accounts, `api-ro` and `api-rw`, and its API sections do
not all accept the same one. Give the client the passwords for whichever
accounts you need and each call authenticates as the right one.

```py
import pprint
from akips import AKIPS

api = AKIPS('akips.example.com', ro_password='something')
```

Reading data needs `ro_password` alone. Add `rw_password` for the calls that
go through the AKiPS site scripts, which require the read write account:

```py
api = AKIPS('akips.example.com', ro_password='something', rw_password='other')
```

| API section | Account required | Methods |
| --- | --- | --- |
| `api-db` | either, prefers `api-ro` | most of the client |
| `api-msg` | `api-ro` | `get_msg`, `get_syslog`, `get_traps` |
| `api-script` | `api-rw` | `get_device_by_ip`, `set_group_membership` |
| `api-availability` | `api-ro` | `get_group_availability`, `get_device_availability`, `get_event_availability` |

AKiPS publishes six further sections that this module does not wrap. `call()`
reaches those too, choosing the account the same way.

Asking for a call whose account has no password raises `AkipsCredentialError`
before any request is made, naming what to pass.

Other options worth knowing:

```py
api = AKIPS(
    'akips.example.com',
    ro_password='something',
    timeout=10,          # seconds, applied to every call, default 30
    verify='/etc/ssl/certs/akips-ca.pem',   # or True, or False to skip checks
    timezone='America/New_York',   # how the server reports its timestamps
)
```

`timeout` can also be changed later with `api.timeout = 60`.

`verify` takes a path to a CA bundle as well as `True` or `False`. A path is
how to trust a server whose certificate chain is missing an intermediate,
which is common on an internal deployment, without turning verification off
everywhere.

If you use a custom AKiPS API account, pass `username` and `password` instead
and that pair is used for every section.

### List all devices, the inventory view (with an optional group filter)

This reads the **`sys` child only**, and asks it for six attributes:
`ip4addr`, `SNMPv2-MIB.sysName`, `SNMPv2-MIB.sysDescr`,
`SNMPv2-MIB.sysObjectID`, `SNMPv2-MIB.sysLocation` and
`SNMPv2-MIB.sysContact` — the values AKiPS shows read only on its device edit
page, being what SNMP reported rather than what an operator set, plus the
address.

Both the child and the six are fixed rather than arguments, because this is
the inventory view: every device comes back carrying all six, as `None` where
it reported no value, so you can list or tabulate them without checking each
key first. Anything else the server returns for a device is kept alongside
them.

`sysObjectID` identifies the model, such as `ARUBA-MIB.ap225`. It is often the
field an inventory actually wants, and is more reliably populated than
`sysLocation`.

For other attributes or other children, use `get_attributes`. For everything a
single device holds, see `get_device` below.

Because it asks for one child, this is the only method here that does **not**
keep the child level: the result is flattened to device and attribute. Every
other method returning attributes keeps all three, so `get_device` below is one
dictionary deeper.

```py
devices = api.get_devices(groups=['a10'])
pprint.pp(devices, sort_dicts=True, width=120, indent=4)
```

```text
{   'TH840-A': {   'SNMPv2-MIB.sysContact': 'Networking',
                   'SNMPv2-MIB.sysDescr': 'Thunder Series Unified Application Service Gateway TH840 ACOS',
                   'SNMPv2-MIB.sysLocation': 'Datacenter A',
                   'SNMPv2-MIB.sysName': 'TH840-A',
                   'SNMPv2-MIB.sysObjectID': 'A10-COMMON-MIB.a10AX.38',
                   'ip4addr': '192.168.20.15'},
    'TH840-B': {   'SNMPv2-MIB.sysContact': None,
                   'SNMPv2-MIB.sysDescr': 'Thunder Series Unified Application Service Gateway TH840 ACOS',
                   'SNMPv2-MIB.sysLocation': 'Datacenter B',
                   'SNMPv2-MIB.sysName': 'TH840-B',
                   'SNMPv2-MIB.sysObjectID': 'A10-COMMON-MIB.a10AX.38',
                   'ip4addr': '192.168.30.25'}}
```

### List all data for a specific device, the deep dive

Every child and attribute one device holds, which varies by device type. Where
`get_devices` above answers "what do I have", this answers "what is on this
one".

```py
device = api.get_device('TH840-A')
pprint.pp(device, sort_dicts=True, width=120, indent=4)
```

The result keeps the parent, child and attribute levels AKiPS stores, so it is
keyed by device name just as `get_devices` is.

```text
{   'TH840-A': {   'Ethernet1': {'IF-MIB.ifAlias': None, 'IF-MIB.ifDescr': 'Ethernet 1'},
                   'sys': {   'SNMPv2-MIB.sysLocation': 'Datacenter A',
                              'SNMPv2-MIB.sysName': 'TH840-A',
                              'ip4addr': '192.168.20.15'}}}
```

An attribute the device reported no value for is `None`.

### What the values mean

AKiPS gives every attribute a type, and the type decides how to read its
value. A `1` usually means "this is a counter" rather than "the value is one",
which is why several attributes in these examples read that way.

| Type | Value | Example |
| --- | --- | --- |
| counter | always `1` | `1` |
| gauge | a scaling factor, positive to multiply and negative to divide | `-2` |
| enum | `{number},{text}` | `2,up` |
| integer | a whole number | `100287` |
| RTT | microseconds, not milliseconds | `430` |
| text | up to 2000 characters | `Datacenter A` |
| timestamp | seconds since the Unix epoch | `1406787487` |
| uptime | seconds since the state last changed | `13095` |

**Counters and gauges hold no reading here.** The configuration database these
methods read holds their definition, which is identical on every device; a
gauge's value is its scale, not a measurement. The readings are in the time
series database, which `get_latest_values()` and `get_series()` read.

An enum arrives from `mget` with two more fields, when it was created and when
it last changed, which is where `'SNMP.snmpState': '2,up,1581605551,1706545348,'`
in the output above comes from. The UPS helpers parse that form for you.

### Lookup the AKiPS device key for a specific IP address

```py
device_key = api.get_device_by_ip(ipaddr='192.168.20.15')
print(device_key)
```

```text
TH840-A
```

This is the key AKiPS stores the device under, which is what every other method
means by a device. Note it needs `rw_password`: AKiPS exposes the lookup as a
site script rather than a database query, so it is the one read here that a
read only client cannot make.

### Get attributes for a specific device and child

```py
attributes = api.get_attributes(device="TH840-A", child="sys")
pprint.pp(attributes, sort_dicts=True, width=120, indent=4)
```

```text
{   'TH840-A': {   'sys': {   'SNMP.community': 'private',
                              'SNMP.discover_oids': '2440',
                              'SNMP.discover_runtime': '0',
                              'SNMP.discover_tt': '1759478985',
                              'SNMP.discover_walks': '57',
                              'SNMP.discover_walks_fail': '0',
                              'SNMP.discover_walks_ok': '57',
                              'SNMP.discover_walks_unknown': '0',
                              'SNMP.ipaddr': '192.168.20.15',
                              'SNMP.lost': '1',
                              'SNMP.maxrep': '20',
                              'SNMP.rtt': '1',
                              'SNMP.rx': '1',
                              'SNMP.snmpState': '2,up,1581605551,1706545348,',
                              'SNMP.tx': '1',
                              'SNMP.version': '2',
                              'SNMPv2-MIB.sysContact': 'Networking',
                              'SNMPv2-MIB.sysDescr': 'Thunder Series Unified Application Service Gateway TH840 ACOS',
                              'SNMPv2-MIB.sysLocation': 'Datacenter A',
                              'SNMPv2-MIB.sysName': 'TH840-A',
                              'SNMPv2-MIB.sysObjectID': 'A10-COMMON-MIB.a10AX.38',
                              'SNMPv2-MIB.sysUpTime': '1749494858,1759502716',
                              'ifXTable': '1',
                              'ip4addr': '192.168.20.15',
                              'mac_md5': 'a34558cd34432f618f5b29fb4376b5a2'}}}
```

Note the `SNMP.community` in there. AKiPS stores SNMP community strings and v3
authentication and privacy passwords as ordinary device attributes, so a reply
like this one carries credentials in fields that look like any other. This
module redacts them from its own debug logging, but anything you print, persist
or forward is yours to handle. It is also why a captured reply should never
become a test fixture without every value in it being replaced first.

### Get a specific attribute over all devices (with optional group filter)

```py
attributes = api.get_attributes(attribute='SNMPv2-MIB.sysUpTime',groups=['a10'])
pprint.pp(attributes, sort_dicts=True, width=120, indent=4)
```

```text
{   'TH840-A': {'sys': {'SNMPv2-MIB.sysUpTime': '1749494858,1759502176'}},
    'TH840-B': {'sys': {'SNMPv2-MIB.sysUpTime': '1738681335,1759502177'}}}
```

### Get list of devices in a specific group

```py
group_list = api.get_group_membership(groups=["a10"])
pprint.pp(group_list, sort_dicts=True, width=120, indent=4)
```

```text
{   'TH840-A': ['A10', 'admin', 'Core-Routers', 'Not-Core', 'OpsCenter', 'Ungrouped', 'user '],
    'TH840-B': ['A10', 'admin', 'Core-Routers', 'Not-Core', 'OpsCenter', 'Ungrouped', 'user ']}
```

### Get list of groups for a specific device

```py
group_list = api.get_group_membership(device="TH840-A")
pprint.pp(group_list, sort_dicts=True, width=120, indent=4)
```

```text
{'TH840-A': ['A10', 'admin', 'Core-Routers', 'Not-Core', 'OpsCenter', 'Ungrouped', 'user ']}
```

### UPS power and battery

Three helpers return only the UPS devices in a state worth acting on, rather
than every UPS that reports the attribute.

```py
on_battery = api.get_ups_output_source()      # any source but 'normal'
weak = api.get_ups_battery_status()           # any state but 'batteryNormal'
failed = api.get_liebert_battery_test()       # failed self tests only
pprint.pp(on_battery, sort_dicts=False, width=100)
```

```text
{'ups-1': {'number': '5',
           'value': 'battery',
           'description': '',
           'created': datetime.datetime(2016, 7, 27, 16, 1, 51, tzinfo=<DstTzInfo 'America/New_York' ...>),
           'modified': datetime.datetime(2026, 7, 1, 4, 57, 1, tzinfo=<DstTzInfo 'America/New_York' ...>),
           'name': 'ups-1',
           'child': 'ups'}}
```

`modified` is when the UPS last changed state, which is worth reading: minutes
old is an event, months old is usually an inventory problem rather than an
outage.

Numbers such as estimated runtime are not in the configuration database, for
the reason under *What the values mean* above: a gauge there is a scale, not a
measurement. Ask the time series database instead:

```py
runtime = api.get_latest_values('UPS-MIB.upsEstimatedMinutesRemaining',
                                child='battery')
```

```text
{'ups-1': {'battery': {'attribute': 'UPS-MIB.upsEstimatedMinutesRemaining',
                       'value': 42.0,
                       'time': datetime.datetime(2026, 8, 2, 12, 44, tzinfo=<DstTzInfo 'America/New_York' ...>)}}}
```

### Syslog and traps

`get_msg()` returns both message types. `get_syslog()` and `get_traps()` are
the same call with the type filled in, so it cannot be misspelled.

```py
traps = api.get_traps(period='last15m')
syslog = api.get_syslog(period='last15m', device='TH840-A')
pprint.pp(traps, sort_dicts=False, width=100)
```

```text
[{'time': '1436232275',
  'type': 'trap',
  'ip_ver': '4',
  'ip_addr': '192.0.2.26',
  'message': 'IF-MIB linkDown 0 ENUM 2,down'}]
```

Ask for one type. On a large fleet an unfiltered hour can be hundreds of
thousands of messages, almost all of it syslog, where the traps alone are a few
thousand. Note also that `limit` fills from the *start* of the window, so it
returns the oldest matches rather than the newest; for recent activity, narrow
`period` instead.

### Availability

Three modes: a summary per group, a row per device and child, and the up and
down events behind those totals.

```py
groups = api.get_group_availability()
devices = api.get_device_availability(group='Datacenter-A')
outages = api.get_event_availability(device='TH840-A', period='last7d')
pprint.pp(groups, sort_dicts=False, width=100)
```

```text
[{'child': 'ping4',
  'attr': 'PING.icmpState',
  'group name': 'Datacenter-A',
  'total time': '86400',
  'match time': '86372',
  'group target': '9990',
  'tf': 'last24h'}]
```

`match time` over `total time` is the availability, and `group target` is the
figure AKiPS is configured to expect, in basis points, so `9990` is 99.90%.
Reporting against that beats inventing a threshold of your own.

Device and event mode return nothing at all unless scoped, so both require a
`device` or a `group` and raise `ValueError` without one. All three default to
`period='last24h'`, a rolling day; `last1d` would be *today so far*, which
shrinks to minutes just after midnight.

### Anything else, with call()

The methods above cover the common queries. `call()` is there for everything
else: it reaches any AKiPS API section and parses the reply in whichever shape
that section replies in.

```py
# an ad-hoc query against api-db, parsed like get_attributes would
data = api.call('mget * TH840-A * *', output='attributes')

# a section that takes its own parameters rather than a command string
messages = api.call(section='api-msg', params={'time': 'last1h'}, output='lines')
```

Output formats, and where each one turns up:

| `output` | Result | AKiPS replies this way for |
| --- | --- | --- |
| `raw` | `str`, the reply unchanged | anything, and the default |
| `lines` | list of non-blank lines | anything |
| `key_value` | `{key: value}` | `mgroup` |
| `attributes` | `{parent: {child: {attribute: value}}}` | `mget` |
| `csv` | list of rows as lists | replies with no header row |
| `csv_dict` | list of rows as dicts | replies whose first row is the header |

Sections do not share a parameter vocabulary: `api-db` takes a command string,
while the others take their own named parameters. Pass `command` for the first
and `params` for the rest, or both to combine them.

The account is chosen from the section, as with any other call. For a section
this module does not model, or a command needing more rights than its section
usually does, pass `user='ro'` or `user='rw'`.

`call()` replaces `cmd()`, which reached only `api-db` and could only return
the reply unparsed. `cmd()` still works but raises a `DeprecationWarning`.

## API Errors

An `AkipsError` is raised when AKiPS itself replies with an error message. The
output below came from giving it an invalid password and making a call.

```py
api = AKIPS('server', ro_password='badpassword')
device = api.get_device('TH840-A')
```

```text
Web API request failed: ERROR: api-db invalid username/password

Traceback (most recent call last):
  ...
akips.exceptions.AkipsError: ERROR: api-db invalid username/password
```

An `AkipsCredentialError` is raised instead when the client has no password for
the account a call needs. This is a configuration problem rather than a reply
from AKiPS, so it is raised before any request is made:

```py
api = AKIPS('server', ro_password='something')
api.set_group_membership('TH840-A', 'maintenance_mode', 'assign')
```

```text
akips.exceptions.AkipsCredentialError: api-script requires the api-rw account,
but no rw_password was given to AKIPS()
```

`AkipsCredentialError` subclasses both `AkipsError` and `ValueError`, so
catching either of those still catches it.

## Upgrading

[MIGRATING.md](https://github.com/unc-network/akips/blob/develop/MIGRATING.md)
covers what changes when moving to 1.0, with before and after for each one.

## API Documentation

[API Documentation](https://unc-network.github.io/akips/docs/akips.html)

## Contributing

[CONTRIBUTING.md](https://github.com/unc-network/akips/blob/develop/CONTRIBUTING.md)

## Bugs/Requests

Please use the [GitHub issue tracker](https://github.com/unc-network/akips/issues) 
to submit bugs or request features.
