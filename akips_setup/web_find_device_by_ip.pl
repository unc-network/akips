# web_find_device_by_ip - a site script for the akips Python module.
#
# AUTHORED BY AKIPS, not written here, and not published by them.  This is
# the version the akips Python module was developed and tested against, kept
# here as the reference for what its behavior assumes.
#
#   Source     AKiPS support, written for us by David Altoft on ticket
#              3565.  It is NOT on their published site scripts page, so
#              there is no public version to compare this against
#   Obtained   2023-02-09
#   Used by    get_device_by_ip()
#
# Because this one is unpublished, there is nowhere to check it against and
# this copy is the reference.  Ask AKiPS support if you need to know whether
# a newer version exists.  What the module relies on is spelled out below, so
# a replacement can be checked against it.
#
# AKiPS said this may be customized, as long as the function name still
# begins 'web_'.
# Doing so makes the result yours to maintain, and the module's parsing
# below would have to be kept in step with it.
#
# What get_device_by_ip() depends on in this version, exactly:
#
#   "IP Address %s is configured on %s"        parsed for the device name
#   "IP Address %s is not configured on any devices"   treated as a real miss
#
# Anything else is warned about as an unrecognized reply.  Those two sentences
# are matched as written, so a version that rewords either one would make the
# lookup return None for every address, or warn on every miss.
#
# Not covered by this repository's MIT license.
#
# Resolves an IP address to the device AKiPS holds it under.  Per AKiPS on
# the ticket above, the addresses configured on a device are held only in
# /home/akips/etc/ip2name.cfg, a CSV file, and are NOT entries in the AKiPS
# database.  That is why an mget against device attributes cannot find them
# and why this script exists.  The GUI shows the same file as the 'Device to
# IP Mapping' report.
#
# It matters because a device answers on several addresses but is stored
# under one, so a trap or syslog message arriving from a secondary interface
# cannot otherwise be attributed to it.

sub web_find_device_by_ip
{
   # Usage: curl -s "https://{akips-server}/api-script?password={api-rw-pwd};function=web_find_device_by_ip;ipaddr={ip-address}"
   
   our $IP2NAME_CFG  = "${HOME_ETC}/ip2name.cfg";
   my $ipaddr        = cgi_param ('ipaddr')    || "";
   my $found_device = 0;
   
   my $IN;
   my $line;
   my %dev;

   if ($ipaddr eq "") {
      errlog ($ERR_DEBUG, "web_find_device_by_ip site-script IP missing");
      printf "IP address is missing\n";
      return;
   }
   
   open ($IN, "<", $IP2NAME_CFG) or EXIT_FATAL ("Could not open $IP2NAME_CFG: $!");

   while ($line = <$IN>) {
      chomp $line;
      %dev = ();
      ($dev{devipaddr}, $dev{device}, $dev{ttime}) = split (",", $line);

      if ($dev{devipaddr} eq $ipaddr) {
         printf "IP Address %s is configured on %s\n", $ipaddr, $dev{device};
         $found_device = 1;
       }
   }
   close $IN;
   
   if ($found_device == 0) {
      printf "IP Address %s is not configured on any devices\n", $ipaddr;
   }
   
   adb_flush ();
}
