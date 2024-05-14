""" This akips python module provides a simple way for python scripts to interact with
the AKiPS Network Monitoring Software Web API interface. """
__version__ = '0.3.0'

import io
import re
import logging
from datetime import datetime
import requests
import pytz
import csv

from akips.exceptions import AkipsError

# Logging configuration
logger = logging.getLogger(__name__)


class AKIPS:
    """ Class to handle interactions with AKiPS API """

    def __init__(self, server, username='api-ro', password=None,
                 verify=True, timezone='America/New_York'):
        self.server = server
        self.username = username
        self.password = password
        self.verify = verify
        self.server_timezone = timezone
        self.session = requests.Session()

        if not verify:
            requests.packages.urllib3.disable_warnings()    # pylint: disable=no-member

    def get_devices(self, group_filter='any', groups=[]):
        """
        Pull a list of key attributes for multiple devices.  Can be filtered by group
        but the default is all devices.

        AKiPS command syntax:
            `mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [value {text|/regex/|integer|ipaddr}] [profile {profile name}]
                [any|all|not group {group name} ...]`
        """
        attributes = [
            'ip4addr',
            'SNMPv2-MIB.sysName',
            'SNMPv2-MIB.sysDescr',
            'SNMPv2-MIB.sysLocation'
        ]
        cmd_attributes = "|".join(attributes)
        params = {
            'cmds': f'mget text * sys /{cmd_attributes}/',
        }
        if groups:
            # [any|all|not group {group name} ...]
            group_list = " ".join(groups)
            params['cmds'] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            data = {}
            # Data comes back as 'plain/text' type so we have to parse it
            lines = text.split('\n')
            for line in lines:
                match = re.match(r'^(\S+)\s(\S+)\s(\S+)\s=\s(.*)$', line)
                if match:
                    if match.group(1) not in data:
                        # Populate a default entry for all desired fields
                        data[match.group(1)] = dict.fromkeys(attributes)
                    # Save this attribute value to data
                    data[match.group(1)][match.group(3)] = match.group(4)
            logger.debug("Found {} devices in akips".format(len(data.keys())))
            return data
        return None

    def get_device(self, name):
        """
        Pull the entire configuration for a single device.

        AKiPS command syntax:
            `mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [value {text|/regex/|integer|ipaddr}] [profile {profile name}]
                [any|all|not group {group name} ...]`
        """
        params = {
            'cmds': f'mget * {name} * *'
        }
        text = self._get(params=params)
        if text:
            data = {}
            # Data comes back as 'plain/text' type so we have to parse it.  Example:
            lines = text.split('\n')
            for line in lines:
                match = re.match(r'^(\S+)\s(\S+)\s(\S+)\s=(\s(.*))?$', line)
                if match:
                    name = match.group(1)
                    if match.group(2) not in data:
                        # initialize the dict of attributes
                        data[match.group(2)] = {}
                    if match.group(5):
                        # Save this attribute value to data
                        data[match.group(2)][match.group(3)] = match.group(5)
                    else:
                        # save a blank string if there was nothing after equals
                        data[match.group(2)][match.group(3)] = ''
            if name:
                data['name'] = name
            logger.debug("Found device {} in akips".format(data))
            return data
        return None

    def get_device_by_ip(self, ipaddr, use_cache=True):
        """
        Devices may have additional IP addresses recorded in akips, but only one primary
        name and address.  Search for a device name by an alternate IP address.

        AKiPS user "api-rw" is required to run api scripts.  This call makes use of a
        special site script and not the normal web API commands.
        """
        params = {
            'function': 'web_find_device_by_ip',
            'ipaddr': ipaddr
        }
        text = self._get(section='/api-script/', params=params)
        if text:
            lines = text.split('\n')
            for line in lines:
                match = re.match(r"IP Address (\S+) is configured on (\S+)", line)
                if match:
                    address = match.group(1)
                    device_name = match.group(2)
                    logger.debug(f"Found {address} on device {device_name}")
                    return device_name
        return None

    def get_unreachable(self):
        """
        Pull a list of unreachable IPv4 ping devices

        AKiPS command syntax:
            `mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [value {text|/regex/|integer|ipaddr}] [profile {profile name}]
                [any|all|not group {group name} ...]`
        """
        params = {
            'cmds': 'mget * * * /PING.icmpState|SNMP.snmpState/ value /down/',
        }
        text = self._get(params=params)
        data = {}
        if text:
            lines = text.split('\n')
            for line in lines:
                match = re.match(r'^(\S+)\s(\S+)\s(\S+)\s=\s(\S+),(\S+),(\S+),(\S+),(\S+)?$', line)
                if match:
                    # epoch fields are in the server's timezone
                    name = match.group(1)
                    attribute = match.group(3)
                    event_start = datetime.fromtimestamp(
                        int(match.group(7)), tz=pytz.timezone(self.server_timezone))
                    if name not in data:
                        # populate a starting point for this device
                        data[name] = {
                            'name': name,
                            'ping_state': 'n/a',
                            'snmp_state': 'n/a',
                            'event_start': event_start  # epoch in local timezone
                        }
                    if attribute == 'PING.icmpState':
                        data[name]['child'] = match.group(2),
                        data[name]['ping_state'] = match.group(5)
                        data[name]['index'] = match.group(4)
                        data[name]['device_added'] = datetime.fromtimestamp(
                            int(match.group(6)), tz=pytz.timezone(self.server_timezone))
                        data[name]['event_start'] = datetime.fromtimestamp(
                            int(match.group(7)), tz=pytz.timezone(self.server_timezone))
                        data[name]['ip4addr'] = match.group(8)
                    elif attribute == 'SNMP.snmpState':
                        data[name]['child'] = match.group(2),
                        data[name]['snmp_state'] = match.group(5)
                        data[name]['index'] = match.group(4)
                        data[name]['device_added'] = datetime.fromtimestamp(
                            int(match.group(6)), tz=pytz.timezone(self.server_timezone))
                        data[name]['event_start'] = datetime.fromtimestamp(
                            int(match.group(7)), tz=pytz.timezone(self.server_timezone))
                        data[name]['ip4addr'] = None
                    if event_start < data[name]['event_start']:
                        data[name]['event_start'] = event_start
            logger.debug("Found {} devices in akips".format(len(data)))
            logger.debug("data: {}".format(data))

        return data

    def get_group_membership(self, device='*', group_filter='any', groups=[]):
        """
        Pull a list of device names to group memberships.  Defaults to all devices
        and all groups (including the special 'maintenance_mode' group).

        AKiPS command syntax:
            `mgroup {type} [{parent regex}]
                [any|all|not group {group name} ...]`
        """
        params = {
            'cmds': f'mgroup {device} *',
        }
        if groups:
            group_list = " ".join(groups)
            params['cmds'] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            data = {}
            # Data comes back as 'plain/text' type so we have to parse it
            lines = text.split('\n')
            for line in lines:
                match = re.match(r'^(\S+)\s=\s(.*)$', line)
                if match:
                    if match.group(1) not in data:
                        # Populate a default entry for all desired fields
                        data[match.group(1)] = match.group(2).split(',')
            logger.debug("Found {} device and group mappings in akips".format(len(data.keys())))
            return data
        return None

    def set_group_membership(self, device, group, mode):
        """
        Update manual grouping rules for a device, including the special
        'maintenance_mode' group.  The web api script fails silently if the device or group
        does not exist.

        AKiPS user "api-rw" is required to run api scripts.  This call makes use of a
        special site script and not the normal web API commands.
        """
        if not device:
            raise ValueError("a valid device name must be provided for manual grouping update")
        if not group:
            raise ValueError("a valid group name must be provided for manual grouping update")
        if mode not in ('assign', 'clear'):
            raise ValueError("mode must be 'assign' or 'clear' for manual grouping update")
        params = {
            'function': 'web_manual_grouping',
            'type': 'device',
            'group': group,    # group_name
            'mode': mode,      # 'assign' or 'clear' for device memberships
            'device': device   # device_name
        }
        text = self._get(section='/api-script/', params=params)
        if text:
            logger.error("Web API request failed: {}".format(text))
            raise AkipsError(message=text)
        return None

    def get_status(self, device='*', child='*', attribute='*'):
        """
        Pull the status values we are most interested in

        AKiPS command syntax:
            `mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [value {text|/regex/|integer|ipaddr}] [profile {profile name}]
                [any|all|not group {group name} ...]`
        """
        pass

    def get_events(self, event_type='all', period='last1h'):
        """
        Pull a list of events.

        AKiPS command syntax:
            `mget event {all,critical,enum,threshold,uptime}
            time {time filter} [{parent regex} {child regex}
            {attribute regex}] [profile {profile name}]
            [any|all|not group {group name} ...]`
        """
        params = {
            'cmds': f'mget event {event_type} time {period}'
        }
        text = self._get(params=params)
        if text:
            data = []
            lines = text.split('\n')
            for line in lines:
                match = re.match(r'^(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(.*)$', line)
                if match:
                    entry = {
                        'epoch': match.group(1),
                        'parent': match.group(2),
                        'child': match.group(3),
                        'attribute': match.group(4),
                        'type': match.group(5),
                        'flags': match.group(6),
                        'details': match.group(7),
                    }
                    data.append(entry)
            logger.debug("Found {} events of type {} in akips".format(len(data), type))
            return data
        return None

    # Time-series commands

    def get_series(self, period='last1h', device='*', attribute='*', get_dict=True,
                   group_filter='any', groups=[]):
        """
        Pull a series of counter values.

        AKiPS command syntax:
            `cseries avg
            time {time filter} type parent child attribute
            [any|all|not group {group name} ...]`
        """
        params = {
            'cmds': f'cseries avg time {period} * {device} * {attribute}'
        }
        if groups:
            group_list = " ".join(groups)
            params['cmds'] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            # Parse output in CSV format
            buff = io.StringIO(text)
            if get_dict:
                # parse each row as a dictionary, key will be column header
                reader = csv.DictReader(buff)
            else:
                # parse each row as a list, will have a column header row
                reader = csv.reader(buff)
            csv_to_list = [row for row in reader]
            logger.debug("Found {} series entries".format(len(csv_to_list)))
            return csv_to_list
        return None

    def get_aggregate(self, period='last1h', device='*', attribute='*',
                      operator='avg', interval='300', group_filter='any', groups=[]):
        """
        Aggregate counter values in intervals over a period of time.

        AKiPS command syntax:
            `aggregate interval {avg|total seconds}
            time {time filter} type parent child attribute
            [any|all|not group {group name} ...]`
        """
        params = {
            'cmds': f'aggregate interval {operator} {interval} time {period} * {device} * {attribute}'
        }
        if groups:
            group_list = " ".join(groups)
            params['cmds'] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            # Text should be one CSV line followed by one blank line
            lines = text.split('\n')
            values = lines[0].split(',')
            logger.debug("Found {} aggregate values".format(len(values)))
            return values
        return None

    # Base operations

    def _parse_enum(self, enum_string):
        """
        Attributes with a type of enum return five values separated by commas.
        """
        match = re.match(r'^(\S*),(\S*),(\S*),(\S*),(\S*)$', enum_string)
        if match:
            entry = {
                'number': match.group(1),       # list number (from MIB)
                'value': match.group(2),        # text value (from MIB)
                # 'created': match.group(3),      # time created (epoch timestamp)
                # 'modified': match.group(4),     # time modified (epoch timestamp)
                'description': match.group(5)   # child description
            }
            entry['created'] = datetime.fromtimestamp(
                int(match.group(3)), tz=pytz.timezone(self.server_timezone))
            entry['modified'] = datetime.fromtimestamp(
                int(match.group(4)), tz=pytz.timezone(self.server_timezone))
            return entry
        else:
            raise AkipsError(message=f'Not a ENUM type value: {enum_string}')

    def _get(self, section='/api-db/', params=None, timeout=30):
        """
        Call HTTP GET against the AKiPS server
        """
        server_url = 'https://' + self.server + section
        params['username'] = self.username
        params['password'] = self.password

        if 'cmds' in params:
            logger.debug("akips command: {}".format(params['cmds']))
        try:
            r = self.session.get(server_url, params=params, verify=self.verify, timeout=timeout)
            r.raise_for_status()
        except requests.exceptions.HTTPError as errh:
            logger.error(errh)
            raise
        except requests.exceptions.ConnectionError as errc:
            logger.error(errc)
            raise
        except requests.exceptions.Timeout as errt:
            logger.error(errt)
            raise
        except requests.exceptions.RequestException as err:
            logger.error(err)
            raise

        # AKiPS can return a raw error message if something fails
        if re.match(r'^ERROR:', r.text):
            logger.error("Web API request failed: {}".format(r.text))
            raise AkipsError(message=r.text)
        else:
            logger.debug("akips output: {}".format(r.text))
            return r.text
