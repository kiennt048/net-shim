<?php
error_reporting(0);
require_once("config.inc");
require_once("interfaces.inc");
require_once("filter.inc");

$target_if = strtolower(getenv('INTERFACE'));
$enabled = getenv('ENABLED');

// Check if this is an unassigned interface request
if (strpos($target_if, '_unassigned_') === 0) {
    // This is an unassigned physical NIC - we need to assign it first
    $physical_port = str_replace('_unassigned_', '', $target_if);

    if ($enabled != '1') {
        // Cannot disable an unassigned interface
        die("ERROR:CANNOT_DISABLE_UNASSIGNED");
    }

    // Acquire lock to prevent race condition when assigning interfaces
    $lock_file = fopen('/tmp/netshim_assign.lock', 'c');
    if (!$lock_file || !flock($lock_file, LOCK_EX)) {
        die("ERROR:LOCK_FAILED");
    }

    // Reload config to get latest state
    $config = parse_config(true);

    // Check if physical port is already assigned
    foreach ($config['interfaces'] as $ifname => $if_conf) {
        if (isset($if_conf['if']) && $if_conf['if'] == $physical_port) {
            flock($lock_file, LOCK_UN);
            fclose($lock_file);
            die("ERROR:ALREADY_ASSIGNED");
        }
    }

    // Find next available OPT number
    $opt_counter = 1;
    foreach ($config['interfaces'] as $ifname => $if_conf) {
        if (preg_match('/^opt(\d+)$/', $ifname, $matches)) {
            $num = intval($matches[1]);
            if ($num >= $opt_counter) {
                $opt_counter = $num + 1;
            }
        }
    }

    $new_ifname = 'opt' . $opt_counter;

    // Create new interface entry
    $config['interfaces'][$new_ifname] = array(
        'if' => $physical_port,
        'enable' => '',
        'descr' => strtoupper($new_ifname),
        'ipaddr' => '',
        'subnet' => ''
    );

    write_config("NetShim: Assigned $physical_port as $new_ifname");

    // Release lock after config is written
    flock($lock_file, LOCK_UN);
    fclose($lock_file);
    interface_configure($new_ifname, true, true);

    // Reconfigure routing and filter for new interface
    if (function_exists('system_routing_configure')) {
        system_routing_configure();
    }
    if (function_exists('setup_gateways_monitor')) {
        setup_gateways_monitor();
    }
    if (function_exists('filter_configure_sync')) {
        filter_configure_sync();
    }

    syslog(LOG_INFO, "NetShim: Assigned $physical_port as $new_ifname and enabled");

    echo "SUCCESS:$new_ifname";
    exit;
}

// Standard interface enable/disable logic
if (!isset($config['interfaces'][$target_if])) {
    die("ERROR:IF_NOT_FOUND");
}

// Ensure automatic outbound NAT is configured
if (!isset($config['nat'])) {
    $config['nat'] = array();
}
if (!isset($config['nat']['outbound'])) {
    $config['nat']['outbound'] = array();
}
$config['nat']['outbound']['mode'] = 'automatic';

if ($enabled == '1') {
    $config['interfaces'][$target_if]['enable'] = '';
    write_config("NetShim: Enabled $target_if");
    interface_configure($target_if, true, true);
    syslog(LOG_INFO, "NetShim: Enabled $target_if");
} else {
    if (isset($config['interfaces'][$target_if]['enable'])) {
        unset($config['interfaces'][$target_if]['enable']);
    }
    write_config("NetShim: Disabled $target_if");
    interface_configure($target_if, false, true);
    syslog(LOG_INFO, "NetShim: Disabled $target_if");
}

// Reconfigure routing after interface change
if (function_exists('system_routing_configure')) {
    system_routing_configure();
}

// Restart gateway monitoring
if (function_exists('setup_gateways_monitor')) {
    setup_gateways_monitor();
}

// Use filter_configure_sync() for complete filter reload
if (function_exists('filter_configure_sync')) {
    filter_configure_sync();
}

echo "SUCCESS";
?>