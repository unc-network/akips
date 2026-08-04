# web_manual_grouping - a site script for the akips Python module.
#
# AUTHORED AND PUBLISHED BY AKIPS, not written here.  This is the version
# the akips Python module was developed and tested against, kept here as
# the reference for what its behavior assumes.
#
#   Obtained   from the AKiPS site scripts page, listed there as
#              "Web API to Add/Delete Manual group"
#              https://www.akips.com/customer-support/site-scripts/
#   Compared   2026-08-03, byte identical to their page that day
#   Used by    set_group_membership()
#
# Install AKiPS's current version; their page is authoritative.  This copy is
# here as the record of what the module was coded against, since these scripts
# carry no version or date of their own.  If their page differs, the module
# may need updating to match, so what it relies on is spelled out below.
#
# What set_group_membership() depends on in this version:
#
#   - the parameter names type, group, mode, device and child
#   - that a successful call prints nothing.  Any output at all is treated as
#     a failure and raised as AkipsError, so a version that reported success
#     would make every call appear to fail
#
# The module currently sends type=device only, never sends child, and accepts
# only the assign and clear modes, so it reaches less than this version
# implements.
#
# Not covered by this repository's MIT license.
#
# Manual group membership, and the group lifecycle.  There is no stock
# Web API path to grouping, which makes this the only way to move a device
# in or out of maintenance mode.

sub web_manual_grouping
{
  # Usage: curl -s "https://{akips-server}/api-script?password={api-rw-pwd};function=web_manual_grouping;type=device;group=maintenance_mode;device={device_name};mode={assign|clear}"

  my $type   = cgi_param ('type')   || "";
  my $group  = cgi_param ('group')  || "";
  my $mode   = cgi_param ('mode')   || "";
  my $device = cgi_param ('device') || "";
  my $child  = cgi_param ('child')  || "";
  my $entity;

  if ($type eq "") {
     errlog ($ERR_DEBUG, "type is missing");
     return;
  }
  elsif ($group eq "") {
     errlog ($ERR_DEBUG, "group is missing");
     return;
  }
  elsif ($mode eq "") {
     errlog ($ERR_DEBUG, "mode is missing");
     return;
  }

  if ($mode eq "assign" || $mode eq "clear") {
     if ($device ne "" && $child ne "") {
        $entity = $device." ".$child;
     }
     else {
        if ($device ne "") {
           $entity = $device;
        }
        else {
           errlog ($ERR_DEBUG, "device is missing");
           return;
        }
     }
  }

  group_manual_load_cfg ();

  given ($mode) {
     when ("add") {
        group_manual_add ($type, $group);
     }

     when ("assign") {
        group_manual_assign ($type, $entity, $group);
     }

     when ("clear") {
        group_manual_clear ($type, $entity, $group);
     }

     when ("delete") {
        group_manual_delete ($type, $group);
     }
  }

  group_manual_save_cfg ();
  adb_flush ();
}
