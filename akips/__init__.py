"""
This akips python module provides a simple way for python scripts to interact with
the AKiPS Network Monitoring Software Web API interface.
"""

__version__ = "1.0.0.dev8"

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

    Four of the ten sections have methods of their own here: api-db,
    api-script, api-msg and api-availability.  The rest are reached through
    call(), which sends a request to any section and parses the reply in the
    same shapes those methods use.

    Attributes:
        server (str): The AKiPS server hostname or IP address
        ro_password (str): password for the api-ro account
        rw_password (str): password for the api-rw account
        username (str): kept for callers who set it directly.  With 'api-ro'
            or 'api-rw' the password given alongside fills that account; with
            any other name, that pair is used for every section, which is how
            to use a custom AKiPS API account
        password (str): the password paired with username
        verify (bool | str): Whether to verify TLS certificates (default:
            True).  A path to a CA bundle can be given instead, which is
            how to trust a server whose chain is missing an intermediate
            without turning verification off entirely
        server_timezone (str): Timezone of the AKiPS server (default: "America/New_York")
        timeout (int): HTTP timeout in seconds applied to every call
            (default: 30).  Assign to it to change the timeout of an
            existing client, e.g. api.timeout = 60
    """

    # Every API section AKiPS publishes, mapped to the account it accepts, as
    # documented on the server's own Web API settings page.  Every section
    # takes api-ro except api-script, which requires api-rw, and api-db, which
    # takes either: api-ro for read-only commands and api-rw for all of them.
    # None marks that pair, where the read only account is preferred and a
    # command needing more rights is reached with user='rw'.
    #
    # Only api-db reads a username at all.  The others authenticate on the
    # password alone, so the username sent alongside is ignored there.
    #
    # This doubles as the list of sections known to exist.  Calling one that
    # is not here is warned about rather than refused, because AKiPS may add
    # sections and waiting for a release here would defeat the point of
    # call().  Each section is also disabled by default on the server, so a
    # section listed here can still be rejected until it is enabled.
    SECTION_USERS: dict[str, str | None] = {
        "api-availability": "api-ro",
        "api-config-viewer": "api-ro",
        "api-db": None,
        "api-flow": "api-ro",
        "api-flow-timeseries": "api-ro",
        "api-http-log": "api-ro",
        "api-msg": "api-ro",
        "api-script": "api-rw",
        "api-spm": "api-ro",
        "api-unused-interfaces": "api-ro",
    }

    def __init__(
        self,
        server: str,
        username: str = "api-ro",
        password: str | None = None,
        verify: bool | str = True,
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
        # Sections warned about already, so a caller legitimately using a
        # section this release does not know about is told once rather
        # than on every call
        self._unknown_sections: set[str] = set()

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
        device's AKiPS name, its one primary key, which is either its sysName
        or its IP address depending on how the server is set to name devices.
        It is assigned at discovery, but a server can be told to reassign
        devices already discovered from the other source, and an operator can
        change one by hand, so a caller storing these as identifiers of its own
        should not assume they never change.  A device keyed by name still
        carries its address as an attribute, and get_device_by_ip() resolves
        an address back to the key.

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
            logger.debug(
                "Found device {} with {} children in akips".format(
                    name, len(data.get(name, {}))
                )
            )
            return data
        return None

    # The children ping and SNMP state are reported under.  Naming them saves
    # AKiPS walking every child of every device, which is most of the cost of
    # this query: on a 16,000 device fleet the wildcard took 10.5s against
    # 5.0s here, for the same rows.  ping6 is listed though most sites monitor
    # over IPv4 alone, because a device reachable only over IPv6 going down is
    # exactly what this call must not miss, and an alternative that matches
    # nothing costs nothing.
    UNREACHABLE_CHILDREN = "ping4|ping6|sys"

    def get_unreachable(
        self, children: str = UNREACHABLE_CHILDREN
    ) -> dict[str, dict[str, Any]] | None:
        """
        Pull a list of unreachable devices by Ping and SNMP state.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Note the {type} field is left off here.  These are enum attributes, so
        narrowing with 'mget text' returns no rows at all rather than an
        error, even though it is the obvious thing to reach for.

        Args:
            children (str): regex of children to search, defaulting to the
                ones AKiPS reports these attributes under.  Pass '*' for
                every child of every device, which is correct for a site
                naming them differently and considerably slower
        Returns:
            A dictionary of device names to their unreachable attributes, or
            None if nothing was reported as down
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        # '*' is the wildcard rather than a pattern, so it is the one value
        # that must not be wrapped in slashes
        child = children if children == "*" else f"/{children}/"
        params = {
            "cmds": f"mget * * {child} /PING.icmpState|SNMP.snmpState/ value /down/",
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

    # UPS helpers

    # UPS output sources other than 'normal'.  A UPS reporting any of these is
    # not running on mains, which is what an operator wants to know about.
    #
    # In MIB order, since UPS-MIB numbers them other(1) none(2) normal(3)
    # bypass(4) battery(5) booster(6) reducer(7).  'none' is a UPS delivering
    # no output at all and 'other' one that cannot classify its own source;
    # both are here for the same reason 'unknown' is in the battery states
    # below, because a UPS that cannot answer the question is worth looking
    # at too.
    UPS_ABNORMAL_OUTPUT_SOURCES = (
        "other",
        "none",
        "bypass",
        "battery",
        "booster",
        "reducer",
    )

    # The child the UPS itself is reported under, as against 'battery' for the
    # battery attributes below.  Naming it keeps AKiPS from walking every
    # child of every device, which is most of the cost of the query.
    UPS_CHILD = "ups"

    # Battery states other than batteryNormal.  'unknown' is included because
    # a UPS that cannot report its own battery is worth looking at too.
    UPS_ABNORMAL_BATTERY_STATES = ("unknown", "batteryLow", "batteryDepleted")

    # The attribute Liebert and Vertiv equipment reports battery test results
    # in.  Battery test results are not in the standard UPS-MIB, so every
    # vendor uses its own; this one is named in the method that reads it.
    LIEBERT_BATTERY_TEST_ATTRIBUTE = "LIEBERT-GP-POWER-MIB.lgpPwrBatteryTestResult"

    def get_ups_battery_status(
        self,
        states: tuple[str, ...] | list[str] | None = UPS_ABNORMAL_BATTERY_STATES,
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> dict[str, dict[str, Any]] | None:
        """
        Pull the UPS devices whose battery is not reporting as normal.

        UPS-MIB reports the battery's own condition, separately from where the
        UPS is drawing its output, which get_ups_output_source() reads.  By
        default this returns only the states other than batteryNormal.

        This is the battery's condition, not how long it would last.  AKiPS
        keeps the numeric readings such as upsEstimatedMinutesRemaining in its
        time series database rather than alongside these, so they come from
        get_series() rather than from here.  Reading them with mget returns
        the gauge's scaling factor, which is identical for every device.

        Args:
            states (list): battery states to report, defaulting to everything
                except batteryNormal.  Pass None for every UPS whatever its
                battery state
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A dictionary of device names to the parsed state, or None if no
            device matched.  Each entry carries the enum fields described on
            _parse_enum, where 'value' is the battery state and 'modified' is
            when it last changed, plus the device 'name' and 'child'
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        return self._get_enum_attribute(
            "UPS-MIB.upsBatteryStatus",
            child="battery",
            values=states,
            group_filter=group_filter,
            groups=groups,
        )

    def get_ups_output_source(
        self,
        states: tuple[str, ...] | list[str] | None = UPS_ABNORMAL_OUTPUT_SOURCES,
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> dict[str, dict[str, Any]] | None:
        """
        Pull the UPS devices that are not running on mains power.

        UPS-MIB reports where a UPS is drawing its output from, which is
        'normal' when all is well.  By default this returns every other value,
        so the result is the list of UPSes worth looking at.  That includes
        'none', a UPS delivering no output at all, and 'other', one that
        cannot classify its own source.

        Note this is the output source, not the battery's own health, which
        UPS-MIB reports separately as upsBatteryStatus.

        Args:
            states (list): output sources to report, defaulting to everything
                except 'normal'.  Pass None for every UPS whatever its state
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A dictionary of device names to the parsed state, or None if no
            device matched.  Each entry carries the enum fields described on
            _parse_enum, where 'value' is the output source and 'modified' is
            when it last changed, plus the device 'name' and 'child'
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        return self._get_enum_attribute(
            "UPS-MIB.upsOutputSource",
            child=self.UPS_CHILD,
            values=states,
            group_filter=group_filter,
            groups=groups,
        )

    def get_liebert_battery_test(
        self,
        results: tuple[str, ...] | list[str] | None = ("failed",),
        attribute: str = LIEBERT_BATTERY_TEST_ATTRIBUTE,
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> dict[str, dict[str, Any]] | None:
        """
        Pull the results of the last battery self test on Liebert and Vertiv
        UPS equipment.

        By default this returns only the failures, which is the list of
        batteries to replace.  Pass results=None for every UPS and its last
        result.

        The vendor is in the name on purpose.  Battery test results are not in
        the standard UPS-MIB, so this reads an attribute only Liebert and
        Vertiv equipment reports.  Run against another vendor's fleet it
        returns nothing, which would otherwise read as good news.  Another
        vendor's equivalent attribute can be passed to reuse the same parsing
        and shape.

        Args:
            results (list): test results to report, defaulting to failures
                only.  Pass None for every UPS whatever its last result
            attribute (str): the vendor attribute holding the result
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A dictionary of device names to the parsed result, or None if no
            device matched.  Each entry carries the enum fields described on
            _parse_enum, where 'value' is the test result and 'modified' is
            when it last changed, plus the device 'name' and 'child'
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        return self._get_enum_attribute(
            attribute,
            child="battery",
            values=results,
            group_filter=group_filter,
            groups=groups,
        )

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

    # The columns every cseries reply starts with, before the timestamps
    SERIES_FIXED_COLUMNS = ("parent", "child", "child description", "attribute")

    def get_latest_values(
        self,
        attribute: str,
        device: str = "*",
        child: str = "*",
        period: str = "last1h",
        time_interval: int = 300,
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> dict[str, dict[str, dict[str, Any]]] | None:
        """
        Pull the most recent reading of a numeric attribute for each device.

        Numeric attributes do not hold a reading in the config database that
        get_attributes() reads; that holds the counter or gauge definition,
        which is the same for every device.  The readings live in the time
        series database, so this asks for a short series and keeps the last
        value in it.

        The final interval of a series is usually still being filled and comes
        back empty, so the last column is not the answer; this returns the
        last column that has a value, along with when it was measured.  Values
        are already scaled by AKiPS, so what comes back is in the attribute's
        real units.

        Supporting AKiPS command syntax:

            cseries [interval total|avg {secs}] time {time filter}
                {type} {parent regex} {child regex} {attribute regex}
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            attribute (str): the attribute to read
            device (str): device name or pattern to match (default: '*')
            child (str): child name or pattern to match (default: '*')
            period (str): how far back to look (default: 'last1h').  It only
                has to be long enough to contain one completed interval
            time_interval (int): seconds per interval (default: 300)
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A dictionary of device names to child names to the reading, each
            with 'value', 'time' and 'attribute'.  A device with no reading in
            the period is present with a value of None rather than dropped.
            None if nothing matched at all
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {
            "cmds": f"cseries interval avg {time_interval} time {period} "
            f"* {device} {child} {attribute}"
        }
        if groups:
            # [any|all|not group {group name} ...]
            group_list = " ".join(groups)
            params["cmds"] += f" {group_filter} group {group_list}"
        text = self._get(params=params)
        if not text:
            return None

        data: dict[str, dict[str, dict[str, Any]]] = {}
        unreadable = []
        rows = cast(list[dict[str, str]], self._parse_csv(text, header=True))
        for row in rows:
            parent = row.get("parent")
            child_name = row.get("child")
            if not parent or not child_name:
                continue
            # Everything after the fixed columns is a timestamped reading, in
            # order, because the reader keeps the header's column order
            readings = [
                (column, value)
                for column, value in row.items()
                if column not in self.SERIES_FIXED_COLUMNS and value
            ]
            entry: dict[str, Any] = {
                "attribute": row.get("attribute", attribute),
                "value": None,
                "time": None,
            }
            if readings:
                column, value = readings[-1]
                try:
                    entry["value"] = float(value)
                except ValueError:
                    unreadable.append(f"{parent} {child_name} = {value}")
                    continue
                try:
                    entry["time"] = pytz.timezone(self.server_timezone).localize(
                        datetime.strptime(column, "%Y-%m-%d %H:%M")
                    )
                except ValueError:
                    # A column heading in a shape this does not recognize is
                    # not worth losing the reading over
                    entry["time"] = None
            data.setdefault(parent, {})[child_name] = entry

        if unreadable:
            logger.warning(
                "Could not read {} of {} {} values from akips, those are "
                "missing from the result.  First: {}".format(
                    len(unreadable),
                    len(unreadable) + len(rows),
                    attribute,
                    unreadable[0],
                )
            )
        logger.debug("Found readings for {} devices".format(len(data)))
        return data

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

    # Low-level operations, kept for compatibility

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

    # The message types AKiPS keeps, and what get_msg accepts.  None asks for
    # both, which is what the api-msg section returns when the parameter is
    # left off.
    MSG_TYPES = ("syslog", "trap")

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

        This is the highest volume call here, and worth filtering.  Measured on
        a 17,000 device fleet, an unfiltered 'last1h' returned 472,014 messages
        in 5.5 seconds; the same hour asking only for traps returned 5,160 in
        0.8 seconds.  Syslog is the bulk of it, and a single appliance can be a
        large share of that on its own.  See get_traps() and get_syslog().

        Args:
            period (str): Required, time period to retrieve messages from
                (default: 'last1h').  'lastNm' and 'lastNh' are rolling
                windows of the length they name, measured back from the moment
                of the call.  'lastNd' is calendar relative, meaning N-1 whole
                days plus today so far, so 'last1d' is today rather than 24
                hours; use 'last24h' for a rolling day
            addr (str): IP address to filter messages by (default: None)
            msg_type (str): message type, 'syslog' or 'trap', or None for both
                (default: None).  See get_syslog() and get_traps(), which name
                the type rather than asking a caller to spell it
            device (str): device name to filter messages by (default: None)
            regex (str): regex pattern to filter message content by (default: None)
            limit (int): maximum number of messages to return (default: None).
                AKiPS fills this from the start of the window, so it returns
                the oldest matching messages rather than the newest, and there
                is no ordering parameter to ask for the other end.  For recent
                activity narrow 'period' instead: 'last15m' with no limit costs
                far less than an hour of messages thrown away after the fact
        Returns:
            A list of dictionaries, each with 'time', 'type', 'ip_ver',
            'ip_addr' and 'message', or None if no data found
        Raises:
            ValueError: if msg_type is not 'syslog', 'trap' or None
            AkipsError: if the AKiPS server returns an error
        """

        # Checked rather than quietly ignored.  An unrecognized type used to be
        # dropped, so a caller asking for 'traps' or 'Syslog' was sent no type
        # at all and got both back believing it had filtered to one.
        if msg_type is not None and msg_type not in self.MSG_TYPES:
            raise ValueError(
                "Invalid msg_type provided to get_msg, expected one of {}, "
                "or None for both".format(", ".join(self.MSG_TYPES))
            )
        params = {"time": period}
        if msg_type is not None:
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

    def get_syslog(
        self,
        period: str = "last1h",
        addr: str | None = None,
        device: str | None = None,
        regex: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, str]] | None:
        """
        Retrieve syslog messages, leaving traps out.

        The same as get_msg(msg_type='syslog') with every other filter
        forwarded, named so the type does not have to be spelled correctly to
        take effect.

        Syslog is the high volume half of api-msg: an unfiltered hour was
        465,936 messages on a 17,000 device fleet, one appliance accounting
        for a large share of it.  Pass a shorter period, a device or a regex
        unless the whole of it is wanted.

        Args:
            period (str): time period to retrieve messages from
                (default: 'last1h').  'lastNm' and 'lastNh' are rolling
                windows of the length they name; 'lastNd' is calendar
                relative, so 'last1d' is today rather than 24 hours
            addr (str): IP address to filter messages by (default: None)
            device (str): device name to filter messages by (default: None)
            regex (str): regex pattern to filter message content by
                (default: None)
            limit (int): maximum number of messages to return (default: None).
                This returns the oldest matching messages, not the newest;
                narrow 'period' for recent activity
        Returns:
            A list of dictionaries, each with 'time', 'type', 'ip_ver',
            'ip_addr' and 'message', or None if no data found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        return self.get_msg(
            period=period,
            msg_type="syslog",
            addr=addr,
            device=device,
            regex=regex,
            limit=limit,
        )

    def get_traps(
        self,
        period: str = "last1h",
        addr: str | None = None,
        device: str | None = None,
        regex: str | None = None,
        limit: int | None = None,
    ) -> list[dict[str, str]] | None:
        """
        Retrieve SNMP traps, leaving syslog out.

        The same as get_msg(msg_type='trap') with every other filter
        forwarded, named so the type does not have to be spelled correctly to
        take effect.

        Asking for traps is what makes this call cheap enough to poll: on a
        17,000 device fleet an hour of traps was 5,160 messages against
        472,014 for an unfiltered hour.

        The body of a trap is a varbind list, one per line, as
        '{module} {attribute} {instance} {type} {value}'.  It is returned as
        the raw 'message' text; this does not split it up.

        Args:
            period (str): time period to retrieve messages from
                (default: 'last1h').  'lastNm' and 'lastNh' are rolling
                windows of the length they name; 'lastNd' is calendar
                relative, so 'last1d' is today rather than 24 hours
            addr (str): IP address to filter messages by (default: None)
            device (str): device name to filter messages by (default: None)
            regex (str): regex pattern to filter message content by
                (default: None)
            limit (int): maximum number of messages to return (default: None).
                This returns the oldest matching messages, not the newest;
                narrow 'period' for recent activity
        Returns:
            A list of dictionaries, each with 'time', 'type', 'ip_ver',
            'ip_addr' and 'message', or None if no data found
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        return self.get_msg(
            period=period,
            msg_type="trap",
            addr=addr,
            device=device,
            regex=regex,
            limit=limit,
        )

    # ---------------------------------------------------------------------------
    # api-availability methods, these require the 'api-ro' user

    # AKiPS has two kinds of time filter and they are easy to confuse.
    # 'lastNd' is calendar relative: it means N-1 whole days plus today so
    # far, so 'last1d' is today and measures minutes just after midnight.
    # 'lastNh' and 'lastNm' are rolling windows of the length they name.
    #
    # These methods default to the rolling form.  An availability figure is a
    # percentage of the window it was measured over, and a caller asking for
    # 'the last day' and rendering the answer should not silently get a
    # five minute sample that reads as a reliable 100% every night.
    AVAILABILITY_PERIOD = "last24h"

    def get_group_availability(
        self,
        period: str = AVAILABILITY_PERIOD,
        report: str = "ping4",
        group: str | None = None,
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

        Args:
            period (str): time filter, refer to the AKiPS programming guide
                (default: 'last24h').  'lastNd' is calendar relative, meaning
                N-1 whole days plus today so far, so 'last1d' is today rather
                than 24 hours and shrinks to minutes just after midnight.
                'lastNh' and 'lastNm' are rolling windows of the length they
                name.  'total time' in the reply is the window measured
            report (str): 'ping4', 'ping6', 'snmp' or 'ifstatus', in any
                combination, comma separated (default: 'ping4')
            group (str): group name to filter by, or every group
        Returns:
            A list of dictionaries, one per group, or None if nothing matched
        Raises:
            AkipsError: if the AKiPS server returns an error
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

    def get_device_availability(
        self,
        period: str = AVAILABILITY_PERIOD,
        report: str = "ping4",
        device: str | None = None,
        group: str | None = None,
    ) -> list[dict[str, str]] | None:
        """
        Retrieve availability statistics per device over a time period.

        Where group mode summarises a whole group, this reports each device
        and child separately, so a device checked by both ping and SNMP
        appears on two rows.

        A device or a group is required.  Unlike group mode, device mode
        answers an unscoped call with an empty body rather than an error,
        which would reach the caller as None and read as 'nothing to report'.

        # output format: {parent},{child},{attr},{total time},{match time},{group target}
        # example: nm-availability mode device time last1w report snmp,ping4 group Accedian

        accedian-131-2-7,ping4,PING.icmpState,136020,136020,9890
        accedian-131-2-7,sys,SNMP.snmpState,136020,136020,9890
        accedian-131-2-8,ping4,PING.icmpState,136020,136020,9890
        accedian-131-2-8,sys,SNMP.snmpState,136020,136020,9890

        'group target' is the availability AKiPS is configured to expect, in
        basis points, so 9890 is 98.90% and 10000 is 100.00%.  It is set per
        group, so a caller can report against the target already agreed on
        the server rather than inventing a threshold of its own.

        Args:
            period (str): time filter, refer to the AKiPS programming guide
                (default: 'last24h').  'lastNd' is calendar relative, meaning
                N-1 whole days plus today so far, so 'last1d' is today rather
                than 24 hours and shrinks to minutes just after midnight.
                'lastNh' and 'lastNm' are rolling windows of the length they
                name.  'total time' in the reply is the window measured
            report (str): 'ping4', 'ping6', 'snmp' or 'ifstatus', in any
                combination, comma separated (default: 'ping4')
            device (str): device to filter by, as '{device}' or
                '{device} {child}'.  This is the device's AKiPS name, its one
                primary key, which is either its sysName or its IP address
                depending on how the server names devices; get_device_by_ip()
                resolves an address to it
            group (str): group name to filter by
        Returns:
            A list of dictionaries, one per device and child, or None if
            nothing matched
        Raises:
            ValueError: if neither device nor group is given
            AkipsError: if the AKiPS server returns an error
        """
        # Checked before the request, so a call that could only ever come back
        # empty fails as the mistake it is rather than as good news
        if device is None and group is None:
            raise ValueError(
                "get_device_availability needs a device or a group to scope it, "
                "an unscoped call returns nothing at all"
            )
        params = {
            "maintenance": "off",  # 'on' or 'off', show/hide maintenance mode devices
            "mode": "device",  # 'group', 'device' or 'events'
            "time": period,  # time filter, refer to programming guide
            "report": report,  # 'ping4', 'ping6', 'snmp', 'ifstatus'. Any combination, comma separated,
            "entity": device,  # {device} [{child}] to filter by device or child
            "group": group,  # {group name} to filter by group
        }
        text = self._get(section="api-availability", params=params)
        if text:
            # This endpoint sends no header row, so the column names come from
            # here rather than from the reply.  They are not group mode's
            # columns; each mode of nm-availability returns its own.
            column_headers = [
                "parent",
                "child",
                "attr",
                "total time",
                "match time",
                "group target",
            ]
            csv_to_list = self._parse_csv(text, fieldnames=column_headers)
            logger.debug("Found {} entries".format(len(csv_to_list)))
            return cast("list[dict[str, str]]", csv_to_list)
        return None

    def get_event_availability(
        self,
        period: str = AVAILABILITY_PERIOD,
        report: str = "ping4",
        device: str | None = None,
        group: str | None = None,
    ) -> list[dict[str, str]] | None:
        """
        Retrieve the up and down event pairs behind a device's availability.

        Where device mode gives the totals, this gives the outages that
        produced them, one row per pair.

        # output format: {parent},{child},{down},{up},{total time},{match time}
        # example: nm-availability mode events time last1M report ping4 entity cisco-131-16-1

        cisco-131-16-1,ping4,1603822871,1603822916,2389764,2388341
        cisco-131-16-1,ping4,1603088563,1603089823,2389764,2388341
        cisco-131-16-1,ping4,1603060380,1603060498,2389764,2388341

        'down' and 'up' are epoch seconds bounding a single outage, so a
        device that went down twice comes back as two rows.  Both are empty
        for a device that stayed up, which still reports the window it was
        measured over.

        Take the length of an outage as 'up' minus 'down'.  'total time' and
        'match time' describe the measurement rather than the row they sit
        beside: every row in a reply carries the same 'total time', the
        length of the window, and a device's 'match time' is that less the
        time it spent down.  Measured against a live server, a device with
        outages of 44 and 46 seconds came back with a 'match time' 90 below
        'total time' on both of its rows, while devices in the same reply
        that stayed up had the two equal.

        So 'total time' is not the length of the outage on its row.  Reading
        it that way gives the whole measurement window as the duration of a
        one minute flap.

        These columns are not the ones group or device mode returns, so the
        three modes are parsed separately rather than sharing a field list.

        Args:
            period (str): time filter, refer to the AKiPS programming guide
                (default: 'last24h').  'lastNd' is calendar relative, meaning
                N-1 whole days plus today so far, so 'last1d' is today rather
                than 24 hours and shrinks to minutes just after midnight.
                'lastNh' and 'lastNm' are rolling windows of the length they
                name.  'total time' in the reply is the window measured
            report (str): 'ping4', 'ping6', 'snmp' or 'ifstatus', in any
                combination, comma separated (default: 'ping4')
            device (str): device to filter by, as '{device}' or
                '{device} {child}'.  This is the device's AKiPS name, its one
                primary key, which is either its sysName or its IP address
                depending on how the server names devices; get_device_by_ip()
                resolves an address to it
            group (str): group name to filter by
        Returns:
            A list of dictionaries, one per up and down pair, or None if
            nothing matched
        Raises:
            ValueError: if neither device nor group is given
            AkipsError: if the AKiPS server returns an error
        """
        # Same as device mode, confirmed against a server: without a scope the
        # reply is empty rather than an error, which would arrive as None and
        # read as 'no outages'
        if device is None and group is None:
            raise ValueError(
                "get_event_availability needs a device or a group to scope it, "
                "an unscoped call returns nothing at all"
            )
        params = {
            "maintenance": "off",  # 'on' or 'off', show/hide maintenance mode devices
            "mode": "events",  # 'group', 'device' or 'events'
            "time": period,  # time filter, refer to programming guide
            "report": report,  # 'ping4', 'ping6', 'snmp', 'ifstatus'. Any combination, comma separated,
            "entity": device,  # {device} [{child}] to filter by device or child
            "group": group,  # {group name} to filter by group
        }
        text = self._get(section="api-availability", params=params)
        if text:
            # This endpoint sends no header row, so the column names come from
            # here rather than from the reply
            column_headers = [
                "parent",
                "child",
                "down",
                "up",
                "total time",
                "match time",
            ]
            csv_to_list = self._parse_csv(text, fieldnames=column_headers)
            logger.debug("Found {} entries".format(len(csv_to_list)))
            return cast("list[dict[str, str]]", csv_to_list)
        return None

    # ---------------------------------------------------------------------------
    # Generic operations, these reach any API section
    #
    # call() is not fixed to one section the way the methods above are.  It
    # takes the section as an argument and picks the account from
    # SECTION_USERS, which is how the sections with no methods of their own
    # here are reached.

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

    # ---------------------------------------------------------------------------
    # Response parsers
    #
    # AKiPS replies in a handful of shapes.  Each one is parsed in exactly one
    # place here, so the specific methods above and the generic call() cannot
    # drift apart in how they read the same reply.

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

    def _get_enum_attribute(
        self,
        attribute: str,
        child: str = "*",
        values: tuple[str, ...] | list[str] | None = None,
        group_filter: str = "any",
        groups: list[str] | None = None,
    ) -> dict[str, dict[str, Any]] | None:
        """
        Pull one enum typed attribute and return it parsed, keyed by device.

        Shared by the methods that ask 'which devices are in a bad state', in
        which the interesting answer is the enum's text value and when it last
        changed.  Filtering by value is done by AKiPS rather than here, so a
        fleet wide query does not fetch every device to discard most of them.

        Supporting AKiPS command syntax:

            mget {type} [{parent regex} [{child regex} [{attribute regex}]]]
                [descr {/regex/}] [value {text|integer|/regex/}]
                [profile {profile name}] [any|all|not group {group name} ...]

        Args:
            attribute (str): the attribute to read
            child (str): child name or pattern to match (default: '*')
            values (list): only report these enum values, or None for all
            group_filter (str): 'any', 'all', or 'not' operators for group filtering (default: 'any')
            groups (list): list of group names to filter by (if any)
        Returns:
            A dictionary of device names to the parsed enum with the device
            'name' and 'child' added, or None if nothing matched
        Raises:
            AkipsError: if the AKiPS server returns an error
        """
        params = {"cmds": f"mget * * {child} {attribute}"}
        if values:
            # [value {text|/regex/|integer|ipaddr}]
            params["cmds"] += " value /{}/".format("|".join(values))
        if groups:
            # [any|all|not group {group name} ...]
            params["cmds"] += f" {group_filter} group {' '.join(groups)}"
        text = self._get(params=params)
        if not text:
            return None

        data: dict[str, dict[str, Any]] = {}
        unparsed = []
        for parent, children in self._parse_attributes(text).items():
            for child_name, attributes in children.items():
                for value in attributes.values():
                    if value is None:
                        continue
                    try:
                        entry = self._parse_enum(value)
                    except AkipsError:
                        # One device reporting something unexpected should not
                        # cost the answer for every other device
                        unparsed.append(f"{parent} {child_name} = {value}")
                        continue
                    entry["name"] = parent
                    entry["child"] = child_name
                    if parent in data:
                        # Keyed by device, so a device reporting this on more
                        # than one child would quietly lose all but one
                        logger.warning(
                            "{} reports {} on more than one child, "
                            "keeping {!r} and discarding {!r}".format(
                                parent, attribute, data[parent]["child"], child_name
                            )
                        )
                        continue
                    data[parent] = entry
        if unparsed:
            logger.warning(
                "Could not parse {} of {} {} values from akips, those devices "
                "are missing from the result.  First: {}".format(
                    len(unparsed), len(unparsed) + len(data), attribute, unparsed[0]
                )
            )
        logger.debug("Found {} devices reporting {}".format(len(data), attribute))
        return data

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

    # Substrings that mark a name as holding a credential, whether it is a
    # query parameter or an AKiPS attribute.  Matching loosely is deliberate:
    # over redacting costs a value in a debug log, under redacting leaks one.
    SENSITIVE_KEYS = ("password", "pass", "token", "secret", "key", "community")

    @classmethod
    def _is_sensitive_key(cls, name: str) -> bool:
        """Whether a parameter or attribute name looks like it holds a credential."""
        return any(s in name.lower() for s in cls.SENSITIVE_KEYS)

    def _redact_sensitive_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of params with sensitive keys redacted from logging output."""
        return {
            k: ("****" if self._is_sensitive_key(k) else v) for k, v in params.items()
        }

    def _redact_text(self, text: str, literals: bool = True) -> str:
        """
        Remove credentials from arbitrary text before it is logged or raised.

        Matching on the query parameter covers the value whatever it looks
        like once URL encoded.  Replacing the passwords this client holds
        catches them appearing outside a query string, but is unsafe for text
        that carries device data: a short password would rewrite every
        innocent occurrence of the same characters.  Pass literals=False for
        anything that is not a URL or an error message.

        Args:
            text (str): text that may contain credentials
            literals (bool): also replace the configured passwords wherever
                they appear (default: True)
        Returns:
            The text with any credential replaced by '****'
        """
        text = re.sub(r"((?:password|passwd|pass)=)[^&\s]*", r"\1****", text)

        # AKiPS keeps SNMP credentials as ordinary device attributes, so a
        # reply to something as innocent as get_device carries the community
        # string and the v3 auth and priv passwords.
        def redact_attribute(match: "re.Match[str]") -> str:
            if self._is_sensitive_key(match.group(2)):
                return f"{match.group(1)}****"
            return match.group(0)

        text = re.sub(r"^(\S+\s\S+\s(\S+)\s=\s).*$", redact_attribute, text, flags=re.M)

        if literals:
            for secret in (self.password, self.ro_password, self.rw_password):
                if secret:
                    text = text.replace(secret, "****")
        return text

    def _scrub_exception(self, err: BaseException) -> None:
        """
        Strip credentials from an exception and everything it chains to.

        AKiPS authenticates by query string and requests puts the failing URL
        in its exception messages, so an untouched exception carries the
        password into any log line or traceback that renders it.

        The whole chain has to be scrubbed, not just the exception raised.
        requests raises its own error from the urllib3 one that caused it, and
        that inner exception holds the same URL, in its message and in a url
        attribute.  Anything rendering a full traceback renders the chain, so
        leaving it means the password reaches wherever tracebacks are kept.

        Rewriting in place keeps each exception's type and traceback, which a
        caller may be relying on, while making the text safe.

        Args:
            err (BaseException): the exception to scrub, modified in place
                along with its __cause__ and __context__ chain
        """
        seen: set[int] = set()
        pending: list[BaseException | None] = [err]
        while pending:
            node = pending.pop()
            if node is None or id(node) in seen:
                continue
            seen.add(id(node))

            original = str(node)
            redacted = self._redact_text(original)
            if redacted != original:
                node.args = (redacted,)

            # urllib3 keeps the URL as an attribute of its own, which no
            # amount of message rewriting reaches
            url = getattr(node, "url", None)
            if isinstance(url, str):
                try:
                    node.url = self._redact_text(url)  # type: ignore[attr-defined]
                except AttributeError:
                    pass

            # A requests HTTPError carries the response it came from, and its
            # url is the one that was fetched, credentials and all.  Error
            # reporters read that separately from the message.
            response = getattr(node, "response", None)
            if response is not None and isinstance(getattr(response, "url", None), str):
                try:
                    response.url = self._redact_text(response.url)
                except AttributeError:
                    pass

            pending.append(node.__cause__)
            pending.append(node.__context__)

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

        if section not in self.SECTION_USERS and section not in self._unknown_sections:
            # Warned rather than refused: AKiPS may add sections, and call()
            # exists so that reaching one does not have to wait for a release
            # here.  A typo lands here too, which is the point.
            self._unknown_sections.add(section)
            logger.warning(
                "Unknown AKiPS API section {!r}, continuing anyway in case "
                "this server offers one this release does not know about.  "
                "Known sections: {}".format(
                    section, ", ".join(sorted(self.SECTION_USERS))
                )
            )

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
            # Defence in depth: no AKiPS error seen so far echoes a credential
            # back, but this text goes into a log and an exception message.
            # Only the query parameter form is removed, never the password as
            # a literal, because a short one would rewrite matching characters
            # anywhere in the reply.
            message = self._redact_text(r.text, literals=False)
            logger.error("Web API request failed: {}".format(message))
            raise AkipsError(message=message)
        else:
            logger.debug(
                "akips output: {}".format(self._redact_text(r.text, literals=False))
            )
            return r.text
