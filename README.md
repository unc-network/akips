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
| `api-msg` | `api-ro` | `get_msg` |
| `api-script` | `api-rw` | `get_device_by_ip`, `set_group_membership` |
| `api-availability` | either, prefers `api-ro` | `get_group_availability` |

Asking for a call whose account has no password raises `AkipsCredentialError`
before any request is made, naming what to pass.

Other options worth knowing:

```py
api = AKIPS(
    'akips.example.com',
    ro_password='something',
    timeout=10,          # seconds, applied to every call, default 30
    verify=False,        # skip TLS verification, for a self signed certificate
    timezone='America/New_York',   # how the server reports its timestamps
)
```

`timeout` can also be changed later with `api.timeout = 60`.

If you use a custom AKiPS API account, pass `username` and `password` instead
and that pair is used for every section.

### List all devices, the inventory view (with an optional group filter)

Every device carries the same handful of fields, as `None` where it reported no
value, so you can list or tabulate them without checking each key first.
Anything else the server returns for a device is kept alongside them. For
everything a single device holds, see `get_device` below.

```py
devices = api.get_devices(groups=['a10'])
pprint.pp(devices, sort_dicts=True, width=120, indent=4)
```

The above code will output the text below.

```text
{   'TH840-A': {   'SNMPv2-MIB.sysDescr': 'Thunder Series Unified Application Service Gateway TH840 ACOS',
                   'SNMPv2-MIB.sysLocation': 'Datacenter A',
                   'SNMPv2-MIB.sysName': 'TH840-A',
                   'ip4addr': '192.168.20.15'},
    'TH840-B': {   'SNMPv2-MIB.sysDescr': 'Thunder Series Unified Application Service Gateway TH840 ACOS',
                   'SNMPv2-MIB.sysLocation': 'Datacenter B',
                   'SNMPv2-MIB.sysName': 'TH840-B',
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

### Lookup the AKiPS device key for a specific IP address

```py
device_key = api.get_device_by_ip(ipaddr='192.168.20.15')
pprint.pp(device_key, sort_dicts=True, width=120, indent=4)
```

The above code will return the key used by AKiPS for the device with this IP.

```text
'TH840-A'
```

### Get attributes for a specific device and child

```py
attributes = api.get_attributes(device="TH840-A", child="sys")
pprint.pp(attributes, sort_dicts=True, width=120, indent=4)
```

The above code will return the key used by AKiPS for the device with this IP.

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

### Get a specific attribute over all devices (with optional group filter)

```py
attributes = api.get_attributes(attribute='SNMPv2-MIB.sysUpTime',groups=['a10'])
pprint.pp(attributes, sort_dicts=True, width=120, indent=4)
```

The above code will return the following data.

```text
{   'TH840-A': {'sys': {'SNMPv2-MIB.sysUpTime': '1749494858,1759502176'}},
    'TH840-B': {'sys': {'SNMPv2-MIB.sysUpTime': '1738681335,1759502177'}}}
```

### Get list of devices in a specific group

```py
group_list = api.get_group_membership(groups=["a10"])
pprint.pp(group_list, sort_dicts=True, width=120, indent=4)
```

The above code will return the following data.

```text
{   'TH840-A': ['A10', 'admin', 'Core-Routers', 'Not-Core', 'OpsCenter', 'Ungrouped', 'user '],
    'TH840-B': ['A10', 'admin', 'Core-Routers', 'Not-Core', 'OpsCenter', 'Ungrouped', 'user ']}
```

### Get list of groups for a specific device

```py
group_list = api.get_group_membership(device="TH840-A")
pprint.pp(group_list, sort_dicts=True, width=120, indent=4)
```

The above code will return the following data.

```text
{'TH840-A': ['A10', 'admin', 'Core-Routers', 'Not-Core', 'OpsCenter', 'Ungrouped', 'user ']}
```

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

## API Documentation

[API Documentation](https://unc-network.github.io/akips/docs/akips.html)

## Contributing

[CONTRIBUTING.md](https://github.com/unc-network/akips/blob/develop/CONTRIBUTING.md)

## Bugs/Requests

Please use the [GitHub issue tracker](https://github.com/unc-network/akips/issues) 
to submit bugs or request features.
