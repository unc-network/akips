# web_delete_device - a site script for the akips Python module.
#
# AUTHORED AND PUBLISHED BY AKIPS, not written here.  This is the version the
# akips Python module was developed and tested against, kept here as the
# reference for what its behavior assumes.
#
#   Obtained   from the AKiPS site scripts page
#              https://www.akips.com/customer-support/site-scripts/
#   Compared   2026-08-14, byte identical to their page that day
#   Used by    delete_device()
#
# Install AKiPS's current version; their page is authoritative.  This copy is
# here as the record of what the module was coded against, since these scripts
# carry no version or date of their own.  If their page differs, the module
# may need updating to match, so what it relies on is spelled out below.
#
# What delete_device() depends on in this version:
#
#   - the parameter name device_names
#   - that it is read in SCALAR context and split on commas here.  Several
#     devices are therefore ONE comma joined parameter, not a repeated key.
#     Passing a list from requests would send repeated keys, cgi_param would
#     return one of them, and the call would delete fewer devices than asked
#     with nothing reported.  delete_device() refuses a name containing a
#     comma for this reason, and sends exactly one name.
#   - that a successful call prints nothing.  Any output at all is treated as
#     a failure and raised as AkipsError, so a version that reported success
#     would make every call appear to fail.
#
# It validates nothing and reports nothing.  There is no check that a name
# exists, no output on success, and none on failure, so silence is not
# evidence that anything happened.  That is why delete_device() confirms the
# device is present before the call and gone after it, rather than trusting
# the reply.
#
# What this script does NOT settle: whether the samples, events and
# availability held against a device go with it.  That is a property of
# AKiPS's own config_delete_device built in and is not visible here.  Treat
# the operation as irreversible.
#
# Not covered by this repository's MIT license.

# Site script to delete device[s] 
sub web_delete_device
{
   my $device_names;
   my @device_to_be_deleted;

   $device_names = cgi_param ("device_names");
   @device_to_be_deleted = split(',', $device_names);

   if (scalar (@device_to_be_deleted) > 0 ) {
      config_delete_device (@device_to_be_deleted);
   }
}