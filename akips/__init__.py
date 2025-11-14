"""
This akips python module provides a simple way for python scripts to interact with
the AKiPS Network Monitoring Software Web API interface.
"""

__version__ = "0.5.0"

import csv
import io
import logging
import re
from datetime import datetime

import pytz
import requests

from akips.exceptions import AkipsError

# Logging configuration
logger = logging.getLogger(__name__)


class AKIPS:
    """
    A class to handle interactions with the AKiPS Web API

    Attributes:
        server (str): The AKiPS server hostname or IP address
        username (str): The AKiPS API username (default: "api-ro")
        password (str): The AKiPS API password
        verify (bool): Whether to verify SSL certificates (default: True)
        server_timezone (str): Timezone of the AKiPS server (default: "America/New_York")
    """

    def __init__(
        self,
        server,
        username="api-ro",
        password=None,
        verify=True,
        timezone="America/New_York",
    ):
        self.server = server
        self.username = username
        self.password = password
        self.verify = verify
        self.server_timezone = timezone
        self.session = requests.Session()

        if not verify:
            requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member

    def get_devices(self, group_filter="any", groups=[]):
        """
        Pull a list of all devices and their key attributes, optionally filtered by group
        membership.  Key attributes include IP address, sysName, sysDescr, and sysLocation.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A dictionary of device names to attribute dictionaries, or None if no devices found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        attributes = [
            "ip4addr",
            "SNMPv2-MIB.sysName",
            "SNMPv2-MIB.sysDescr",
            "SNMPv2-MIB.sysLocation",
        ]
        cmd_attributes = "|".join(attributes)
        params = {
            "cmds": f"mget text * sys /{cmd_attributes}/",
        }
        if groups:
            # [any|all|not group {group name} ...]
            group_list = " ".join(groups)
            params["cmds"] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            data = {}
            # Data comes back as 'plain/text' type so we have to parse it
            lines = text.split("\n")
            for line in lines:
                match = re.match(r"^(\S+)\s(\S+)\s(\S+)\s=\s(.*)$", line)
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
        Pull all configuration attributes for a single device.  The name is the
        primary device key in AKiPS which might be an IP address or hostname
        depending on your AKiPS settings.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            name (str): The device name to retrieve
        Returns:
            A dictionary of device attributes, or None if the device was not found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {"cmds": f"mget * {name} * *"}
        text = self._get(params=params)
        if text:
            data = {}
            # Data comes back as 'plain/text' type so we have to parse it.  Example:
            lines = text.split("\n")
            for line in lines:
                match = re.match(r"^(\S+)\s(\S+)\s(\S+)\s=(\s(.*))?$", line)
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
                        data[match.group(2)][match.group(3)] = ""
            if name:
                data["name"] = name
            logger.debug("Found device {} in akips".format(data))
            return data
        return None

    def get_device_by_ip(self, ipaddr):
        """
        Return the device name (primary key) for a device matching the given IP address.
        AKiPS records additional IP addresses when found on devices, so this function
        can be used to find the primary device name (primary key) from any known IP address.

        Supporting AKiPS site script function (which requires the api-rw user):

            web_find_device_by_ip(ipaddr)

        Args:
            ipaddr (str): IP address to search for
        Returns:
            the device name (str) if found, or None if no match is found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {"function": "web_find_device_by_ip", "ipaddr": ipaddr}
        text = self._get(section="api-script", params=params)
        if text:
            lines = text.split("\n")
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
        Pull a list of unreachable devices by Ping and SNMP state.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Returns:
            A dictionary of device names to their unreachable attributes
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": "mget * * * /PING.icmpState|SNMP.snmpState/ value /down/",
        }
        text = self._get(params=params)
        data = {}
        if text:
            lines = text.split("\n")
            for line in lines:
                match = re.match(
                    r"^(\S+)\s(\S+)\s(\S+)\s=\s(\S+),(\S+),(\S+),(\S+),(\S+)?$", line
                )
                if match:
                    # epoch fields are in the server's timezone
                    name = match.group(1)
                    attribute = match.group(3)
                    event_start = datetime.fromtimestamp(
                        int(match.group(7)), tz=pytz.timezone(self.server_timezone)
                    )
                    if name not in data:
                        # populate a starting point for this device
                        data[name] = {
                            "name": name,
                            "ping_state": "n/a",
                            "snmp_state": "n/a",
                            "event_start": event_start,  # epoch in local timezone
                        }
                    if attribute == "PING.icmpState":
                        data[name]["child"] = (match.group(2),)
                        data[name]["ping_state"] = match.group(5)
                        data[name]["index"] = match.group(4)
                        data[name]["device_added"] = datetime.fromtimestamp(
                            int(match.group(6)), tz=pytz.timezone(self.server_timezone)
                        )
                        data[name]["event_start"] = datetime.fromtimestamp(
                            int(match.group(7)), tz=pytz.timezone(self.server_timezone)
                        )
                        data[name]["ip4addr"] = match.group(8)
                    elif attribute == "SNMP.snmpState":
                        data[name]["child"] = (match.group(2),)
                        data[name]["snmp_state"] = match.group(5)
                        data[name]["index"] = match.group(4)
                        data[name]["device_added"] = datetime.fromtimestamp(
                            int(match.group(6)), tz=pytz.timezone(self.server_timezone)
                        )
                        data[name]["event_start"] = datetime.fromtimestamp(
                            int(match.group(7)), tz=pytz.timezone(self.server_timezone)
                        )
                        data[name]["ip4addr"] = None
                    if event_start < data[name]["event_start"]:
                        data[name]["event_start"] = event_start
            logger.debug("Found {} devices in akips".format(len(data)))
            logger.debug("data: {}".format(data))

        return data

    def get_group_membership(self, device="*", group_filter="any", groups=[]):
        """
        Pull a list of device names to group memberships.  Defaults to all devices
        and all groups (including the special 'maintenance_mode' group).

        Supporting AKiPS command syntax:

            mgroup {type} [{parent regex}]
                [any|all|not group {group name} ...]

        Args:
            device (str): device name or pattern to match (default: '*')
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A dictionary of device names to lists of group names, or None if no devices found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": f"mgroup * {device}",
        }
        if groups:
            group_list = " ".join(groups)
            params["cmds"] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            data = {}
            # Data comes back as 'plain/text' type so we have to parse it
            lines = text.split("\n")
            for line in lines:
                match = re.match(r"^(\S+)\s=\s(.*)$", line)
                if match:
                    if match.group(1) not in data:
                        # Populate a default entry for all desired fields
                        data[match.group(1)] = match.group(2).split(",")
            logger.debug(
                "Found {} device and group mappings in akips".format(len(data.keys()))
            )
            return data
        return None

    def set_group_membership(self, device, group, mode):
        """
        Update manual grouping rules for a device, including the special 'maintenance_mode'
        group.  The web api script fails silently if the device or group does not exist.

        Supporting AKiPS site script function (which requires the api-rw user):

            web_manual_grouping(type, group, mode, device)

        Args:
            device (str): device name to update
            group (str): group name to update
            mode (str): 'assign' to add device to group, 'clear' to remove device from group
        Returns:
            None
        Raises:
            ValueError: if invalid parameters are provided
            AkipsError: if the AKiPS server returns an error
        """
        if not device:
            raise ValueError(
                "a valid device name must be provided for manual grouping update"
            )
        if not group:
            raise ValueError(
                "a valid group name must be provided for manual grouping update"
            )
        if mode not in ("assign", "clear"):
            raise ValueError(
                "mode must be 'assign' or 'clear' for manual grouping update"
            )
        params = {
            "function": "web_manual_grouping",
            "type": "device",
            "group": group,  # group_name
            "mode": mode,  # 'assign' or 'clear' for device memberships
            "device": device,  # device_name
        }
        text = self._get(section="api-script", params=params)
        if text:
            logger.error("Web API request failed: {}".format(text))
            raise AkipsError(message=text)
        return None

    def get_attributes(
        self,
        device="*",
        child="*",
        attribute="*",
        value=None,
        group_filter="any",
        groups=[],
    ):
        """
        Pull attribute values with variable search criteria.  Search criteria defaults to
        a wildcard match but can be filtered by 'device' name or pattern, 'child' name or pattern,
        'attribute' name or pattern, and/or attribute 'value' or pattern.  Additionally,
        results can be filtered by group membership using 'any', 'all', or 'not' operators
        along with one or more group names.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            device (str): device name or pattern to match (default: '*')
            child (str): child name or pattern to match (default: '*')
            attribute (str): attribute name or pattern to match (default: '*')
            value (str): value or pattern to match (default: None)
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A nested dictionary of device names to child names to attribute names and values,
            or None if no devices found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": f"mget * {device} {child} {attribute}",
        }
        if value:
            # [value {text|/regex/|integer|ipaddr}]
            params["cmds"] += f" value {value}"
        if groups:
            # [any|all|not group {group name} ...]
            group_list = " ".join(groups)
            params["cmds"] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            data = {}
            lines = text.split("\n")
            for line in lines:
                m = re.match(
                    r"^(?P<d>\S+)\s(?P<c>\S+)\s(?P<a>\S+)\s=(\s(?P<v>.*))?$", line
                )
                if m:
                    if m.group("d") not in data:
                        # add device key if needed
                        data[m.group("d")] = {}
                    if m.group("c") not in data[m.group("d")]:
                        # add child key if needed
                        data[m.group("d")][m.group("c")] = {}
                    data[m.group("d")][m.group("c")][m.group("a")] = m.group("v")
            logger.debug("Found {} devices in akips".format(len(data.keys())))
            return data
        return None

    def get_events(
        self,
        event_type="all",
        period="last1h",
        device="*",
        child="*",
        attribute="*",
        group_filter="any",
        groups=[],
    ):
        """
        Pull a list of events over a time period with optional filtering by device,
        child, attribute, and/or group membership.  Defaults to all event types over
        the last hour.  Review AKiPS documentation for details on event types and
        time filter syntax.

        Supporting AKiPS command syntax:

            mget event {all,critical,enum,threshold,uptime}
                time {time filter} [{parent regex} {child regex}
                {attribute regex}] [profile {profile name}]
                [any|all|not group {group name} ...]

        Args:
            event_type (str): type of events to retrieve (default: 'all')
            period (str): time period to retrieve events from (default: 'last1h')
            device (str): device name or pattern to match (default: '*')
            child (str): child name or pattern to match (default: '*')
            attribute (str): attribute name or pattern to match (default: '*')
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A list of event dictionaries, or None if no events found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": f"mget event {event_type} time {period} {device} {child} {attribute}"
        }
        if groups:
            # [any|all|not group {group name} ...]
            group_list = " ".join(groups)
            params["cmds"] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            data = []
            lines = text.split("\n")
            for line in lines:
                match = re.match(
                    r"^(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(\S+)\s(.*)$", line
                )
                if match:
                    entry = {
                        "epoch": match.group(1),
                        "parent": match.group(2),
                        "child": match.group(3),
                        "attribute": match.group(4),
                        "type": match.group(5),
                        "flags": match.group(6),
                        "details": match.group(7),
                    }
                    data.append(entry)
            logger.debug("Found {} events of type {} in akips".format(len(data), type))
            return data
        return None

    # Time-series commands

    def get_series(
        self,
        period="last1h",
        time_interval=60,
        device="*",
        attribute="*",
        get_dict=True,
        group_filter="any",
        groups=[],
    ):
        """
        Pull a series of counter values with average values over a time period with optional
        filtering by device, attribute, and/or group membership.  Defaults to all devices
        and attributes over the last hour with 60 second intervals.  Review AKiPS documentation
        for details on time filter syntax.

        Supporting AKiPS command syntax:

            cseries [interval total|avg {secs}] time {time filter}
                {type} {parent regex} {child regex} {attribute regex}
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            period (str): time period to retrieve series from (default: 'last1h')
            time_interval (int): interval in seconds for series data points (default: 60)
            device (str): device name or pattern to match (default: '*')
            attribute (str): attribute name or pattern to match (default: '*')
            get_dict (bool): return each row as a dictionary (default: True)
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A list of series data rows (as dictionaries or lists), or None if no data found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": f"cseries interval avg {time_interval} time {period} * {device} * {attribute}"
        }
        if groups:
            group_list = " ".join(groups)
            params["cmds"] += f" {group_filter} group {group_list}"
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

    def get_aggregate(
        self,
        period="last1h",
        device="*",
        attribute="*",
        operator="avg",
        interval="300",
        group_filter="any",
        groups=[],
    ):
        """
        Pull aggregate counter values over a period of time with optional filtering
        by device, attribute, and/or group membership.  Defaults to all devices
        and attributes over the last hour with average aggregation every 300 seconds.  Review
        AKiPS documentation for details on time filter syntax.

        Supporting AKiPS command syntax:

            aggregate [interval total|avg {secs}] time {time filter}
                {type} {parent regex} {child regex} {attribute regex}
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            period (str): time period to retrieve series from (default: 'last1h')
            device (str): device name or pattern to match (default: '*')
            attribute (str): attribute name or pattern to match (default: '*')
            operator (str): aggregation operator, 'avg' or 'total seconds' (default: 'avg')
            interval (str): interval in seconds for aggregation points (default: '300')
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A list of aggregate values, or None if no data found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": f"aggregate interval {operator} {interval} time {period} * {device} * {attribute}"
        }
        if groups:
            group_list = " ".join(groups)
            params["cmds"] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if text:
            # Text should be one CSV line followed by one blank line
            lines = text.split("\n")
            values = lines[0].split(",")
            logger.debug("Found {} aggregate values".format(len(values)))
            return values
        return None

    # Low-level operations

    def cmd(self, cmd, output="raw"):
        """
        Experimental and may be removed in future releases.  Currently only a shortcut
        to send raw AKiPS api-db command strings to the server and return raw output for
        debugging.

        Args:
            cmd (str): AKiPS command string to send
            output (str): desired output format, currently only 'raw' is supported
        Returns:
            The command output in the desired format, or None if no output
        Raises:
            ValueError: if an invalid output format is provided
            AkipsError: if the AKiPS server returns an error
        """

        params = {"cmds": f"{cmd}"}
        text = self._get(params=params)
        if text:
            if output == "raw":
                return text
            else:
                raise ValueError("Invalid output value provided to cmd.")
        return None

    # Base operations

    def _parse_enum(self, enum_string):
        """
        Attributes with a type of enum return five values separated by commas.

        Args:
            enum_string (str): the raw enum string from AKiPS
        Returns:
            A dictionary with keys: number, value, created, modified, description
        Raises:
            AkipsError: if the provided string is not a valid enum type value
        """
        match = re.match(r"^(\S*),(\S*),(\S*),(\S*),(\S*)$", enum_string)
        if match:
            entry = {
                "number": match.group(1),  # list number (from MIB)
                "value": match.group(2),  # text value (from MIB)
                # 'created': match.group(3),      # time created (epoch timestamp)
                # 'modified': match.group(4),     # time modified (epoch timestamp)
                "description": match.group(5),  # child description
            }
            entry["created"] = datetime.fromtimestamp(
                int(match.group(3)), tz=pytz.timezone(self.server_timezone)
            )
            entry["modified"] = datetime.fromtimestamp(
                int(match.group(4)), tz=pytz.timezone(self.server_timezone)
            )
            return entry
        else:
            raise AkipsError(message=f"Not a ENUM type value: {enum_string}")

    def _redact_sensitive_params(self, params):
        """Return a copy of params with sensitive keys redacted from logging output."""
        SENSITIVE_KEYS = ("password", "pass", "token", "secret", "key", "community")

        def is_sensitive(k):
            return any(s in k.lower() for s in SENSITIVE_KEYS)

        return {k: ("****" if is_sensitive(k) else v) for k, v in params.items()}

    def _get(self, section="api-db", params=None, timeout=30):
        """
        Base HTTP GET against the AKiPS server for web API calls.

        Section options are individually enabled via the AKiPS Web API Settings page.
            api-availability      : Availability, default off
            api-db                : Config and Events, default off
            api-config-viewer     : Config Viewer, default off
            api-http-log          : HTTP Log, default off
            api-flow              : NetFlow, default off
            api-flow-timeseries   : NetFlow Time-series, default off
            api-script            : Site Script Functions, default off
            api-spm               : Switch Port Mapper, default off
            api-msg               : Syslog and Traps, default off
            api-unused-interfaces : Unused Interface, default off

        Args:
            section (str): API section to call (default: 'api-db')
            params (dict): dictionary of parameters to pass to the server
            timeout (int): HTTP timeout in seconds (default: 30)
        Returns:
            text output from the server
        Raises:
            AkipsError: if the AKiPS server returns an error
            requests.exceptions.HTTPError: for HTTP error responses
            requests.exceptions.ConnectionError: for connection errors
            requests.exceptions.Timeout: for request timeouts
            requests.exceptions.RequestException: for HTTP request errors
        """
        server_url = f"https://{self.server}/{section}"
        params["username"] = self.username
        params["password"] = self.password

        logger.debug("GET url: {}".format(server_url))
        logger.debug("GET params: {}".format(self._redact_sensitive_params(params)))

        try:
            r = self.session.get(
                server_url, params=params, verify=self.verify, timeout=timeout
            )
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
        if re.match(r"^ERROR:", r.text):
            logger.error("Web API request failed: {}".format(r.text))
            raise AkipsError(message=r.text)
        else:
            logger.debug("akips output: {}".format(r.text))
            return r.text
