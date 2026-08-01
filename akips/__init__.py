"""
This akips python module provides a simple way for python scripts to interact with
the AKiPS Network Monitoring Software Web API interface.
"""

__version__ = "1.0.0.dev3"

import csv
import io
import logging
import re
import warnings
from datetime import datetime
from typing import Any, cast

import pytz
import requests
import urllib3

from akips.exceptions import AkipsCredentialError, AkipsError

# Logging configuration
logger = logging.getLogger(__name__)


class AKIPS:
    """
    A class to handle interactions with the AKiPS Web API

    AKiPS ships two API accounts, api-ro and api-rw, and its sections do not
    all accept the same one.  Supply the passwords for whichever accounts you
    need and each call uses the right one; see SECTION_USERS below for the
    mapping.  A caller only reading data needs ro_password alone.

        api = AKIPS('akips.example.com', ro_password='...', rw_password='...')

    Attributes:
        server (str): The AKiPS server hostname or IP address
        ro_password (str): password for the api-ro account
        rw_password (str): password for the api-rw account
        username (str): kept for callers who set it directly.  With 'api-ro'
            or 'api-rw' the password given alongside fills that account; with
            any other name, that pair is used for every section, which is how
            to use a custom AKiPS API account
        password (str): the password paired with username
        verify (bool): Whether to verify SSL certificates (default: True)
        server_timezone (str): Timezone of the AKiPS server (default: "America/New_York")
        timeout (int): HTTP timeout in seconds applied to every call
            (default: 30).  Assign to it to change the timeout of an
            existing client, e.g. api.timeout = 60
    """

    # The account each section requires.  None means either will do, in which
    # case the read only account is preferred.  Sections absent from this
    # table are treated as None; pass user= to call() to override.
    SECTION_USERS: dict[str, str | None] = {
        "api-db": None,
        "api-script": "api-rw",
        "api-msg": "api-ro",
        "api-availability": None,
    }

    def __init__(
        self,
        server: str,
        username: str = "api-ro",
        password: str | None = None,
        verify: bool = True,
        timezone: str = "America/New_York",
        timeout: int = 30,
        ro_password: str | None = None,
        rw_password: str | None = None,
    ) -> None:
        self.server = server
        self.username = username
        self.password = password
        self.ro_password = ro_password
        self.rw_password = rw_password
        self.verify = verify
        self.server_timezone = timezone
        self.timeout = timeout
        self.session = requests.Session()

        # A username other than the two built in accounts is used for every
        # section.  AKiPS does not offer custom API accounts yet, but this is
        # where they will land, and it keeps working for anyone already
        # passing username and password directly.
        self._account_override: tuple[str, str] | None = None
        if password is not None:
            if username == "api-ro" and self.ro_password is None:
                self.ro_password = password
            elif username == "api-rw" and self.rw_password is None:
                self.rw_password = password
            elif username not in ("api-ro", "api-rw"):
                self._account_override = (username, password)

        if (
            self._account_override is None
            and self.ro_password is None
            and self.rw_password is None
        ):
            raise AkipsCredentialError(
                "No AKiPS password provided.  Pass ro_password, rw_password, "
                "or a username and password pair."
            )

    # ---------------------------------------------------------------------------
    # api-db interface methods, these use the 'api-ro' or 'api-rw' user

    # entities commands

    def get_devices(
        self, group_filter: str = "any", groups: list[str] | None = None
    ) -> dict[str, dict[str, str | None]] | None:
        """
        Pull a list of all devices and their key attributes, optionally filtered by group
        membership.  Key attributes include IP address, sysName, sysDescr, and sysLocation.

        This is the inventory view: every device carries all four of the
        attributes above, as None where it reported no value, so they can be
        listed or tabulated without checking each key first.  Anything else
        the server returns for a device is kept alongside them rather than
        dropped.  For everything a single device holds, see get_device().

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
            data: dict[str, dict[str, str | None]] = {}
            for parent, children in self._parse_attributes(text).items():
                # Every requested attribute is present, as None where the
                # device reported no value for it
                entry: dict[str, str | None] = dict.fromkeys(attributes)
                for child_attributes in children.values():
                    entry.update(child_attributes)
                data[parent] = entry
            logger.debug("Found {} devices in akips".format(len(data.keys())))
            return data
        return None

    def get_device(
        self, name: str
    ) -> dict[str, dict[str, dict[str, str | None]]] | None:
        """
        Pull all configuration attributes for a single device.  The name is the
        primary device key in AKiPS which might be an IP address or hostname
        depending on your AKiPS settings.

        This is the deep dive: every child and attribute this device holds,
        which varies by device type.  For the same fields across every device,
        see get_devices().

        The reply keeps the parent, child and attribute levels AKiPS stores it
        in, so the result is keyed by device name exactly as get_devices and
        get_attributes are.  Asking for one device gives a dictionary with one
        key rather than a differently shaped one.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            name (str): The device name to retrieve
        Returns:
            A dictionary of the device name to its child names to attribute
            names and values, or None if the device was not found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {"cmds": f"mget * {name} * *"}
        text = self._get(params=params)
        if text:
            data = self._parse_attributes(text)
            if not data:
                # A reply that parses to nothing is not found, rather than a
                # device that happens to have no attributes
                return None
            logger.debug("Found device {} in akips".format(data))
            return data
        return None

    def get_unreachable(self) -> dict[str, dict[str, Any]] | None:
        """
        Pull a list of unreachable devices by Ping and SNMP state.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Returns:
            A dictionary of device names to their unreachable attributes, or
            None if nothing was reported as down
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": "mget * * * /PING.icmpState|SNMP.snmpState/ value /down/",
        }
        text = self._get(params=params)
        if text:
            data: dict[str, dict[str, Any]] = {}
            unparsed = []
            lines = text.split("\n")
            for line in lines:
                match = re.match(
                    r"^(\S+)\s(\S+)\s(\S+)\s=\s(\S+),(\S+),(\S+),(\S+),(\S+)?$", line
                )
                if not match:
                    if line.strip():
                        # A line reporting a device down that this does not
                        # understand must not vanish: under reporting an
                        # outage is the worst thing this call can do.
                        unparsed.append(line)
                    continue
                # epoch fields are in the server's timezone
                name = match.group(1)
                attribute = match.group(3)
                event_start = datetime.fromtimestamp(
                    int(match.group(7)), tz=pytz.timezone(self.server_timezone)
                )
                device_added = datetime.fromtimestamp(
                    int(match.group(6)), tz=pytz.timezone(self.server_timezone)
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
                    data[name]["ping_state"] = match.group(5)
                    # A device down on both checks reports one child, index
                    # and address.  Ping wins them, because it is the only
                    # line carrying an address, and assigning here while the
                    # SNMP branch below only fills gaps makes the result the
                    # same whichever order the lines arrive in.
                    data[name]["child"] = match.group(2)
                    data[name]["index"] = match.group(4)
                    data[name]["device_added"] = device_added
                    data[name]["ip4addr"] = match.group(8)
                elif attribute == "SNMP.snmpState":
                    data[name]["snmp_state"] = match.group(5)
                    data[name].setdefault("child", match.group(2))
                    data[name].setdefault("index", match.group(4))
                    data[name].setdefault("device_added", device_added)
                    data[name].setdefault("ip4addr", None)
                # A device down on both ping and SNMP has two start times; the
                # outage began at the earlier of them.  This has to be the only
                # place event_start is set, or the comparison is against the
                # value just written from this same line and the last line seen
                # would always win.
                if event_start < data[name]["event_start"]:
                    data[name]["event_start"] = event_start
            if unparsed:
                logger.warning(
                    "Could not parse {} of {} unreachable lines from akips, "
                    "those devices are missing from the result.  First: {}".format(
                        len(unparsed), len(unparsed) + len(data), unparsed[0][:200]
                    )
                )
            logger.debug("Found {} devices in akips".format(len(data)))
            logger.debug("data: {}".format(data))
            return data
        return None

    def get_attributes(
        self,
        device: str = "*",
        child: str = "*",
        attribute: str = "*",
        value: str | None = None,
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> dict[str, dict[str, dict[str, str | None]]] | None:
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
            data = self._parse_attributes(text)
            logger.debug("Found {} devices in akips".format(len(data.keys())))
            return data
        return None

    # group commands

    def get_group_membership(
        self,
        device: str = "*",
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> dict[str, list[str]] | None:
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
            data = {
                device_name: groups_value.split(",")
                for device_name, groups_value in self._parse_key_value(text).items()
            }
            logger.debug(
                "Found {} device and group mappings in akips".format(len(data.keys()))
            )
            return data
        return None

    # event commands

    def get_events(
        self,
        event_type: str = "all",
        period: str = "last1h",
        device: str = "*",
        child: str = "*",
        attribute: str = "*",
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> list[dict[str, str]] | None:
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
            logger.debug(
                "Found {} events of type {} in akips".format(len(data), event_type)
            )
            return data
        return None

    # time series commands

    def get_series(
        self,
        period: str = "last1h",
        time_interval: int = 60,
        device: str = "*",
        attribute: str = "*",
        get_dict: bool = True,
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> list[dict[str, str]] | list[list[str]] | None:
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
            # Rows as dictionaries keyed by the header row, or as plain lists
            # with that header row kept as the first entry
            csv_to_list = self._parse_csv(text, header=get_dict)
            logger.debug("Found {} series entries".format(len(csv_to_list)))
            return csv_to_list
        return None

    def get_aggregate(
        self,
        period: str = "last1h",
        device: str = "*",
        attribute: str = "*",
        operator: str = "avg",
        interval: str = "300",
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> list[str] | None:
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
            # One CSV row of values, followed by a blank line
            rows = cast(list[list[str]], self._parse_csv(text))
            values = rows[0] if rows else []
            logger.debug("Found {} aggregate values".format(len(values)))
            return values
        return None

    # Low-level operations

    # The reply shapes call() can parse, mapped to the parser for each
    OUTPUT_FORMATS = ("raw", "lines", "key_value", "attributes", "csv", "csv_dict")

    def call(
        self,
        command: str | None = None,
        section: str = "api-db",
        params: dict[str, Any] | None = None,
        output: str = "raw",
        user: str | None = None,
    ) -> Any:
        """
        Send an arbitrary request to any AKiPS web API section and parse the
        reply in one of the shapes AKiPS replies in.

        This is the general purpose call for anything the specific methods do
        not cover.  It parses with the same routines they use, so an ad-hoc
        query returns the same shape its dedicated method would.

        Sections do not share a parameter vocabulary.  api-db takes a command
        string, while api-script, api-msg and api-availability each take their
        own named parameters, so pass 'command' for the first and 'params' for the
        others.  Passing both adds the command to the given parameters.

        Output formats, and where each one occurs:

            raw        the reply unchanged, as a string
            lines      a list of non-blank lines
            key_value  '{key} = {value}' lines, as from mgroup
            attributes '{parent} {child} {attribute} = {value}' lines, as from
                       mget, nested by parent, child, then attribute
            csv        CSV rows as lists, for replies with no header row
            csv_dict   CSV rows as dictionaries keyed by the header row

        Args:
            command (str): command string for the api-db section, shorthand
                for params={'cmds': command}
            section (str): API section to call (default: 'api-db')
            params (dict): parameters for sections that take no command string
            output (str): one of the formats listed above (default: 'raw')
            user (str): force the 'ro' or 'rw' account, for a section
                whose requirement is not in SECTION_USERS, or a command
                needing more rights than its section usually does
        Returns:
            The reply in the requested shape, or None if the server returned
            nothing
        Raises:
            ValueError: if output is not a supported format, or if neither
                command nor params was provided
            AkipsError: if the AKiPS server returns an error
        """
        # Check before making the request, so a bad argument fails the same way
        # whether or not the server returned anything
        if output not in self.OUTPUT_FORMATS:
            raise ValueError(
                "Invalid output value provided to call, expected one of {}".format(
                    ", ".join(self.OUTPUT_FORMATS)
                )
            )
        if command is None and params is None:
            raise ValueError("call requires either a command or a params dictionary")

        request_params = dict(params or {})
        if command is not None:
            request_params["cmds"] = command

        text = self._get(section=section, params=request_params, user=user)
        if not text:
            return None

        if output == "raw":
            return text
        if output == "lines":
            return self._parse_lines(text)
        if output == "key_value":
            return self._parse_key_value(text)
        if output == "attributes":
            return self._parse_attributes(text)
        if output == "csv_dict":
            return self._parse_csv(text, header=True)
        return self._parse_csv(text)

    def cmd(self, cmd: str, output: str = "raw") -> str | None:
        """
        Deprecated since 1.0.0, use call() instead, which reaches every API
        section and can parse the reply rather than only returning it raw.

        Args:
            cmd (str): AKiPS command string to send
            output (str): desired output format, only 'raw' is supported
        Returns:
            The command output, or None if no output
        Raises:
            ValueError: if an invalid output format is provided
            AkipsError: if the AKiPS server returns an error
        """
        warnings.warn(
            "cmd() is deprecated and will be removed in a future release, "
            "use call() instead",
            DeprecationWarning,
            stacklevel=2,
        )
        if output != "raw":
            raise ValueError("Invalid output value provided to cmd.")
        return cast("str | None", self.call(command=cmd))

    # ---------------------------------------------------------------------------
    # api-script methods, these require the 'api-rw' user

    def get_device_by_ip(self, ipaddr: str) -> str | None:
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

    def set_group_membership(self, device: str, group: str, mode: str) -> None:
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

    # ---------------------------------------------------------------------------
    # api-msg methods, these require the 'api-ro' user

    # 'period' and 'msg_type' map to the AKiPS query parameters 'time' and
    # 'type'.  They are deliberately named apart from those, because 'type' is
    # a builtin and 'time' a standard library module, and because 'period' is
    # what the rest of this module already calls a time filter.
    def get_msg(
        self,
        period: str = "last1h",
        addr: str | None = None,
        msg_type: str | None = None,
        device: str | None = None,
        regex: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, str]] | None:
        """
        Retrieve syslog or trap messages from the AKiPS api-msg database. The api-msg
        access requires username to be 'api-ro'.

        Supporting AKiPS web API syntax:

            https://{server}/api-msg?password={pw};time={time filter};
                [addr={ip filter}];[type=syslog|trap];[device={name}|{regex}];
                [regex={regex filter}];[limit={qty messages}]

        Args:
            period (str): Required, time period to retrieve messages from (default: 'last1h')
            addr (str): IP address to filter messages by (default: None)
            msg_type (str): message type, 'syslog' or 'trap' (default: syslog and traps)
            device (str): device name to filter messages by (default: None)
            regex (str): regex pattern to filter message content by (default: None)
            limit (int): maximum number of messages to return (default: None)
        Returns:
            A list of message values, or None if no data found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """

        params = {"time": period}
        if msg_type in ("syslog", "trap"):
            params["type"] = msg_type
        if addr:
            params["addr"] = addr
        if device:
            params["device"] = device
        if regex:
            params["regex"] = regex
        if limit:
            params["limit"] = str(limit)
        text = self._get(section="api-msg", params=params)
        if text:
            # Each syslog or trap message contains:
            #     header line: {system timestamp} {type} {IP version} {IP address}
            #     message line(s): {message text}
            #     blank terminating line
            #
            # Records are split on that blank line rather than by recognising
            # each header, because a body line can look exactly like a header
            # and would otherwise start a new record in the middle of a
            # message, turning one message into two with empty bodies.
            data = []
            unparsed = 0
            for record in re.split(r"\n\s*\n", text):
                lines = [line for line in record.split("\n") if line.strip()]
                if not lines:
                    continue
                header = re.match(
                    r"^(?P<time>\S+)\s(?P<type>\S+)\s(?P<ip_ver>[46])\s(?P<ip_addr>\S+)$",
                    lines[0],
                )
                if not header:
                    unparsed += 1
                    continue
                data.append(
                    {
                        "time": header.group("time"),
                        "type": header.group("type"),
                        "ip_ver": header.group("ip_ver"),
                        "ip_addr": header.group("ip_addr"),
                        # Everything after the header is the message, whatever
                        # any of those lines happen to look like
                        "message": "\n".join(lines[1:]),
                    }
                )
            if unparsed:
                logger.warning(
                    "Could not parse {} of {} message records from akips, "
                    "those messages are missing from the result".format(
                        unparsed, unparsed + len(data)
                    )
                )
            logger.debug("Found {} messages in akips".format(len(data)))
            return data
        return None

    # ---------------------------------------------------------------------------
    # api-availability methods for availability statistics

    def get_group_availability(
        self, period: str = "last1d", report: str = "ping4", group: str | None = None
    ) -> list[dict[str, str]] | None:
        """
        Retrieve availability statistics for a group of devices over a time period.

        # output format: {child},{attr},{group name},{total time},{match time},{group target},{tf}[;{group tf}]
        # example: nm-availability mode group time last1w report ping4

        ping4,PING.icmpState,1-Building-4,11688115,11687711,9990,last1w
        ping4,PING.icmpState,1-Fraser,8213270,8213190,9990,last1w
        ping4,PING.icmpState,1-Building-16,44541195,44540002,9990,last1w
        ping4,PING.icmpState,Accedian,1766635,1766635,9890,last1w;mon to sat 6:00 to 20:00
        ping4,PING.icmpState,Aerohive,589475,589475,9999,last1w;mon to fri 7:00 to 19:00; sat 8:00 to 18:00
        """
        params = {
            "maintenance": "off",  # 'on' or 'off', show/hide maintenance mode devices
            "mode": "group",  # 'group', 'device' or 'events'
            "time": period,  # time filter, refer to programming guide
            "report": report,  # 'ping4', 'ping6', 'snmp', 'ifstatus'. Any combination, comma separated,
            # "entity": device,    # {device} [{child}] to filter by device or child
            "group": group,  # {group name} to filter by group
            # "profile": ""        # {profile name} to filter by profile
        }
        text = self._get(section="api-availability", params=params)
        if text:
            # This endpoint sends no header row, so the column names come from
            # here rather than from the reply
            column_headers = [
                "child",
                "attr",
                "group name",
                "total time",
                "match time",
                "group target",
                "tf",
            ]
            csv_to_list = self._parse_csv(text, fieldnames=column_headers)
            logger.debug("Found {} entries".format(len(csv_to_list)))
            return cast("list[dict[str, str]]", csv_to_list)
        return None

    # Commented out for now till it can be fully tested.
    # def get_device_availability(self, time="last1d", report="ping4", device=None):
    #     """
    #     Retrieve availability statistics for a device over a time period.

    #     # output format: {parent},{child},{attr},{total time},{match time},{group target}
    #     # example: nm-availability mode device time last1w report snmp,ping4 group Accedian

    #     accedian-131-2-7,ping4,PING.icmpState,136020,136020,9890
    #     accedian-131-2-7,sys,SNMP.snmpState,136020,136020,9890
    #     accedian-131-2-8,ping4,PING.icmpState,136020,136020,9890
    #     accedian-131-2-8,sys,SNMP.snmpState,136020,136020,9890
    #     accedian-131-2-9,ping4,PING.icmpState,136020,136020,9890
    #     accedian-131-2-9,sys,SNMP.snmpState,136020,136020,9890
    #     """
    #     pass

    # Commented out for now till it can be fully tested.
    # def get_event_availability(self, time="last1d", report="ping4", device=None):
    #     """
    #     Retrieve availability statistics for pairs of up/down events.

    #     # output format: {parent},{child},{down},{up},{total time},{match_time}
    #     # example: nm-availability mode events time last1M report ping4 entity cisco-131-16-1

    #     cisco-131-16-1,ping4,1603822871,1603822916,2389764,2388341
    #     cisco-131-16-1,ping4,1603088563,1603089823,2389764,2388341
    #     cisco-131-16-1,ping4,1603060380,1603060498,2389764,2388341
    #     """
    #     pass

    # ---------------------------------------------------------------------------
    # Response parsers
    #
    # AKiPS replies in a handful of shapes.  Each one is parsed in exactly one
    # place here, so the specific methods above and the generic call() below
    # cannot drift apart in how they read the same reply.

    @staticmethod
    def _parse_lines(text: str) -> list[str]:
        """
        Split a reply into its non-blank lines.

        Args:
            text (str): the raw reply from AKiPS
        Returns:
            A list of lines with blank ones removed
        """
        return [line for line in text.split("\n") if line.strip()]

    @staticmethod
    def _parse_key_value(text: str) -> dict[str, str]:
        """
        Parse lines of '{key} = {value}', the shape mgroup replies in.

        Args:
            text (str): the raw reply from AKiPS
        Returns:
            A dictionary of keys to their unsplit values
        """
        data = {}
        for line in text.split("\n"):
            match = re.match(r"^(\S+)\s=\s(.*)$", line)
            if match:
                data[match.group(1)] = match.group(2)
        return data

    @staticmethod
    def _parse_attributes(text: str) -> dict[str, dict[str, dict[str, str | None]]]:
        """
        Parse lines of '{parent} {child} {attribute} = {value}', the shape
        mget replies in.  An attribute with nothing after the equals has no
        value and is recorded as None.

        Args:
            text (str): the raw reply from AKiPS
        Returns:
            A nested dictionary of parent, child, attribute to value
        """
        data: dict[str, dict[str, dict[str, str | None]]] = {}
        for line in text.split("\n"):
            match = re.match(r"^(\S+)\s(\S+)\s(\S+)\s=(\s(.*))?$", line)
            if match:
                parent, child, attribute = (
                    match.group(1),
                    match.group(2),
                    match.group(3),
                )
                data.setdefault(parent, {}).setdefault(child, {})[attribute] = (
                    match.group(5)
                )
        return data

    @staticmethod
    def _parse_csv(
        text: str, fieldnames: list[str] | None = None, header: bool = False
    ) -> list[dict[str, str]] | list[list[str]]:
        """
        Parse a CSV reply.  AKiPS is not consistent about header rows, so the
        caller says which shape to expect rather than this guessing.

        Args:
            text (str): the raw reply from AKiPS
            fieldnames (list): column names for a reply that carries no header
            header (bool): treat the first row as the header row
        Returns:
            A list of rows, as dictionaries when column names are known from
            either fieldnames or a header row, otherwise as lists
        """
        buff = io.StringIO(text)
        if fieldnames is not None:
            return list(csv.DictReader(buff, fieldnames=fieldnames))
        if header:
            return list(csv.DictReader(buff))
        return [row for row in csv.reader(buff) if row]

    # ---------------------------------------------------------------------------
    # Base operations

    def _parse_enum(self, enum_string: str) -> dict[str, Any]:
        """
        Attributes with a type of enum return five values separated by commas.

        Args:
            enum_string (str): the raw enum string from AKiPS
        Returns:
            A dictionary with keys: number, value, created, modified, description
        Raises:
            AkipsError: if the provided string is not a valid enum type value
        """
        # The trailing description is free text and routinely contains spaces,
        # so it takes the rest of the line rather than a non-whitespace run
        match = re.match(r"^(\S*),(\S*),(\S*),(\S*),(.*)$", enum_string)
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

    def _credentials_for(
        self, section: str, user: str | None = None
    ) -> tuple[str, str]:
        """
        Pick the AKiPS account a request should authenticate as.

        Args:
            section (str): API section being called
            user (str): force an account, 'ro' or 'rw', for a section whose
                requirement is not known or differs from the usual one
        Returns:
            A tuple of the username and password to send
        Raises:
            AkipsCredentialError: if the account this call needs has no password
            ValueError: if user names an account that does not exist
        """
        if self._account_override is not None:
            # A custom account stands in for both
            return self._account_override

        required = user if user is not None else self.SECTION_USERS.get(section)
        if required in ("ro", "api-ro"):
            required = "api-ro"
        elif required in ("rw", "api-rw"):
            required = "api-rw"
        elif required is not None:
            raise ValueError(
                f"Unknown AKiPS account {required!r}, expected 'ro' or 'rw'"
            )

        if required is None:
            # Either account works here, so use the lesser privileged one
            if self.ro_password is not None:
                return ("api-ro", self.ro_password)
            return ("api-rw", str(self.rw_password))

        password = self.ro_password if required == "api-ro" else self.rw_password
        if password is None:
            argument = "ro_password" if required == "api-ro" else "rw_password"
            raise AkipsCredentialError(
                f"{section} requires the {required} account, but no {argument} "
                f"was given to AKIPS()"
            )
        return (required, password)

    def _redact_sensitive_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of params with sensitive keys redacted from logging output."""
        SENSITIVE_KEYS = ("password", "pass", "token", "secret", "key", "community")

        def is_sensitive(k: str) -> bool:
            return any(s in k.lower() for s in SENSITIVE_KEYS)

        return {k: ("****" if is_sensitive(k) else v) for k, v in params.items()}

    def _redact_text(self, text: str) -> str:
        """
        Remove credentials from arbitrary text before it is logged or raised.

        Matching on the query parameter covers the value whatever it looks
        like once URL encoded, and replacing the passwords this client holds
        covers them appearing anywhere else.

        Args:
            text (str): text that may contain credentials
        Returns:
            The text with any credential replaced by '****'
        """
        text = re.sub(r"((?:password|passwd|pass)=)[^&\s]*", r"\1****", text)
        for secret in (self.password, self.ro_password, self.rw_password):
            if secret:
                text = text.replace(secret, "****")
        return text

    def _scrub_exception(self, err: BaseException) -> None:
        """
        Strip credentials from an exception raised by requests, in place.

        AKiPS authenticates by query string and requests puts the failing URL
        in its exception messages, so an untouched exception carries the
        password into any log line or traceback that renders it.  Rewriting
        the arguments keeps the exception's type and traceback, which a
        caller may be relying on, while making the text safe.

        Note that an HTTPError also holds the response object, whose url
        attribute still contains the query string it was fetched with.

        Args:
            err (BaseException): the exception to scrub, modified in place
        """
        original = str(err)
        redacted = self._redact_text(original)
        if redacted != original:
            err.args = (redacted,)

    def _get(
        self,
        section: str = "api-db",
        params: dict[str, Any] | None = None,
        user: str | None = None,
    ) -> str:
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
            user (str): force the 'ro' or 'rw' account for this request
        Returns:
            text output from the server
        Raises:
            AkipsCredentialError: if the account this section needs has no
                password
            AkipsError: if the AKiPS server returns an error
            requests.exceptions.HTTPError: for HTTP error responses
            requests.exceptions.ConnectionError: for connection errors
            requests.exceptions.Timeout: for request timeouts
            requests.exceptions.RequestException: for HTTP request errors
        """
        server_url = f"https://{self.server}/{section}"

        # Work on a copy so credentials are never written into the dictionary
        # the caller passed in, and so params is optional as documented
        params = dict(params or {})
        username, password = self._credentials_for(section, user)
        params["username"] = username
        params["password"] = password

        logger.debug("GET url: {}".format(server_url))
        logger.debug("GET params: {}".format(self._redact_sensitive_params(params)))

        try:
            with warnings.catch_warnings():
                if not self.verify:
                    # Scoped to this request on purpose.  Disabling urllib3
                    # warnings globally would also silence them for every
                    # other library in the calling application.  Note that
                    # the warnings filter is process wide while this block
                    # runs, so a concurrent thread could miss a warning.
                    warnings.simplefilter(
                        "ignore", urllib3.exceptions.InsecureRequestWarning
                    )
                r = self.session.get(
                    server_url, params=params, verify=self.verify, timeout=self.timeout
                )
            r.raise_for_status()
        except requests.exceptions.RequestException as err:
            # One handler for every requests failure: HTTPError,
            # ConnectionError and Timeout are all RequestException, and each
            # was doing the same thing here.  The exception is scrubbed before
            # it is logged or re-raised, because requests reports the URL it
            # was fetching and AKiPS puts the password in that URL.
            self._scrub_exception(err)
            logger.error("AKiPS request failed: {}".format(err))
            raise

        # AKiPS can return a raw error message if something fails
        if re.match(r"^ERROR:", r.text):
            logger.error("Web API request failed: {}".format(r.text))
            raise AkipsError(message=r.text)
        else:
            logger.debug("akips output: {}".format(r.text))
            return r.text
