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

```py
import pprint
from akips import AKIPS

api = AKIPS('akips.example.com',username='api-ro',password='something')
```

### List all devices (with an optional group filter)

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

### List all data for a specific device

```py
device = api.get_device('TH840-A')
pprint.pp(device, sort_dicts=True, width=120, indent=4)
```

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

## API Errors

An AkipsError exception will be thrown if the AKiPS API responds with an error message.
The output below was generated by providing an invalid password and making a call.

```py
api = AKIPS('server' ,username='api-ro', password='badpassword')
device = api.get_device('TH840-A')
```

```text
% ./akips_test.py
Web API request failed: ERROR: api-db invalid username/password

Traceback (most recent call last):
  File "/Users/test/project/akips_test/./akips_test.py", line 25, in <module>
    device = api.get_device('TH840-A')
  File "/Users/test/project/akips_test/venv/lib/python3.10/site-packages/akips/__init__.py", line 93, in get_device
    text = self._get(params=params)
  File "/Users/test/project/akips_test/venv/lib/python3.10/site-packages/akips/__init__.py", line 502, in _get
    raise AkipsError(message=r.text)
akips.exceptions.AkipsError: ERROR: api-db invalid username/password
```

## API Documentation

[API Documentation](https://unc-network.github.io/akips/docs/akips/index.html)

## Contributing

[CONTRIBUTING.md](https://github.com/unc-network/akips/blob/develop/CONTRIBUTING.md)

## Bugs/Requests

Please use the [GitHub issue tracker](https://github.com/unc-network/akips/issues) 
to submit bugs or request features.
