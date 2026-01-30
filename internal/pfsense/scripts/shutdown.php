<?php
error_reporting(0);
require_once("config.inc");
require_once("system.inc");

syslog(LOG_INFO, "NetShim: System shutdown requested by user");

// Schedule shutdown for 3 seconds from now to allow HTTP response
if (function_exists('system_halt')) {
    // pfSense 2.x function
    system_halt();
    echo "SUCCESS:SHUTDOWN_INITIATED";
} else {
    // Fallback - use shell command with delay
    exec("nohup /bin/sh -c 'sleep 3 && /sbin/shutdown -p now' > /dev/null 2>&1 &");
    echo "SUCCESS:SHUTDOWN_SCHEDULED";
}
?>