<?php
require_once("config.inc");
require_once("interfaces.inc");
require_once("util.inc");

// Get WAN interface - check for PPPoE first
$wan_if = 'wan';
$ifreal = get_real_interface($wan_if);

// For PPPoE, the actual traffic goes through pppoe interface
if (isset($config['interfaces']['wan']['ipaddr']) && $config['interfaces']['wan']['ipaddr'] == 'pppoe') {
    // Try to find pppoe interface
    $pppoe_if = get_real_interface($wan_if);
    if (strpos($pppoe_if, 'pppoe') !== false || strpos($pppoe_if, 'ng') !== false) {
        $ifreal = $pppoe_if;
    }
}

if (!$ifreal) {
    // Fallback: try to detect WAN from routing table
    exec('/usr/bin/netstat -rn -f inet 2>/dev/null | grep default', $route_output);
    if (!empty($route_output)) {
        $parts = preg_split('/\s+/', trim($route_output[0]));
        if (count($parts) >= 4) {
            $ifreal = $parts[3];
        }
    }
}

$bytes_in = 0;
$bytes_out = 0;

if ($ifreal) {
    $ifstats = pfSense_get_interface_stats($ifreal);

    if ($ifstats) {
        // Normalize keys (pfSense versions may differ)
        if (isset($ifstats['inbytes']))
            $bytes_in = floatval($ifstats['inbytes']);
        elseif (isset($ifstats['bytes received']))
            $bytes_in = floatval($ifstats['bytes received']);

        if (isset($ifstats['outbytes']))
            $bytes_out = floatval($ifstats['outbytes']);
        elseif (isset($ifstats['bytes transmitted']))
            $bytes_out = floatval($ifstats['bytes transmitted']);
    }

    // Fallback to netstat if no stats
    if ($bytes_in == 0 && $bytes_out == 0) {
        exec("/usr/bin/netstat -I " . escapeshellarg($ifreal) . " -b -n 2>/dev/null | tail -1", $netstat_out);
        if (!empty($netstat_out)) {
            $parts = preg_split('/\s+/', trim($netstat_out[0]));
            // netstat -I output: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
            if (count($parts) >= 10) {
                $bytes_in = floatval($parts[6]);
                $bytes_out = floatval($parts[9]);
            }
        }
    }
}

echo json_encode(array(
    'interface' => $ifreal ? $ifreal : 'unknown',
    'bytes_in' => $bytes_in,
    'bytes_out' => $bytes_out,
    'timestamp' => time()
));
?>