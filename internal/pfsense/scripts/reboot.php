<?php
error_reporting(0);
require_once("config.inc");
require_once("system.inc");

syslog(LOG_INFO, "NetShim: System reboot requested by user");

// Schedule reboot for 3 seconds from now to allow HTTP response
if (function_exists('system_reboot')) {
    // pfSense 2.x function
    system_reboot();
    echo "SUCCESS:REBOOT_INITIATED";
} else {
    // Fallback - use shell command with delay
    exec("nohup /bin/sh -c 'sleep 3 && /sbin/shutdown -r now' > /dev/null 2>&1 &");
    echo "SUCCESS:REBOOT_SCHEDULED";
}
?>