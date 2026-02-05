<?php
error_reporting(0);
require_once("config.inc");
require_once("gwlb.inc");
require_once("util.inc");

$data = array();

// Method 1: Try return_gateways_status() - the standard way
if (function_exists('return_gateways_status')) {
    $gateways_status = return_gateways_status(true);

    if (is_array($gateways_status) && !empty($gateways_status)) {
        foreach ($gateways_status as $name => $gw) {
            // Only return IPv4 gateways
            if (isset($gw['ipprotocol']) && $gw['ipprotocol'] != 'inet') {
                continue;
            }

            $status = 'online';
            if (isset($gw['status'])) {
                if ($gw['status'] == 'force_down' || $gw['status'] == 'down') {
                    $status = 'offline';
                } elseif ($gw['status'] == 'loss' || $gw['status'] == 'highloss') {
                    $status = 'warning';
                } elseif ($gw['status'] == 'delay' || $gw['status'] == 'highdelay') {
                    $status = 'warning';
                }
            }

            $data[] = array(
                'name' => isset($gw['name']) ? $gw['name'] : $name,
                'interface' => isset($gw['friendlyiface']) ? $gw['friendlyiface'] : (isset($gw['interface']) ? $gw['interface'] : ''),
                'gateway' => isset($gw['gateway']) ? $gw['gateway'] : '',
                'monitor' => isset($gw['monitor']) ? $gw['monitor'] : (isset($gw['monitorip']) ? $gw['monitorip'] : ''),
                'status' => $status,
                'delay' => isset($gw['delay']) ? $gw['delay'] : '0 ms',
                'stddev' => isset($gw['stddev']) ? $gw['stddev'] : '0 ms',
                'loss' => isset($gw['loss']) ? $gw['loss'] : '0%'
            );
        }
    }
}

// Method 2: If no gateways found, try to build from config
if (empty($data) && isset($config['gateways']['gateway_item'])) {
    foreach ($config['gateways']['gateway_item'] as $gw) {
        // Skip IPv6
        if (isset($gw['ipprotocol']) && $gw['ipprotocol'] == 'inet6') {
            continue;
        }

        // Try to get status from dpinger
        $status = 'unknown';
        $delay = '0 ms';
        $loss = '0%';

        $dpinger_file = "/var/run/dpinger_" . $gw['name'] . ".sock";
        if (!file_exists($dpinger_file)) {
            $dpinger_file = "/tmp/dpinger_" . $gw['name'] . ".status";
        }

        if (file_exists($dpinger_file)) {
            $dpinger_data = @file_get_contents($dpinger_file);
            if ($dpinger_data) {
                // Format: name srcip delay_us stddev_us loss_pct
                $parts = explode(' ', trim($dpinger_data));
                if (count($parts) >= 5) {
                    $delay_us = intval($parts[2]);
                    $loss_pct = floatval($parts[4]);
                    $delay = round($delay_us / 1000, 2) . ' ms';
                    $loss = $loss_pct . '%';
                    $status = ($loss_pct > 50) ? 'offline' : (($loss_pct > 10) ? 'warning' : 'online');
                }
            }
        }

        $data[] = array(
            'name' => $gw['name'],
            'interface' => isset($gw['interface']) ? strtoupper($gw['interface']) : '',
            'gateway' => isset($gw['gateway']) ? $gw['gateway'] : '',
            'monitor' => isset($gw['monitor_disable']) ? '' : (isset($gw['gateway']) ? $gw['gateway'] : ''),
            'status' => $status,
            'delay' => $delay,
            'stddev' => '0 ms',
            'loss' => $loss
        );
    }
}

// Method 3: Try to detect default gateway from routing table
if (empty($data)) {
    exec('/usr/bin/netstat -rn -f inet 2>/dev/null | grep "^default"', $route_output);
    if (!empty($route_output)) {
        $parts = preg_split('/\s+/', trim($route_output[0]));
        if (count($parts) >= 4) {
            $gw_ip = $parts[1];
            $gw_if = $parts[3];

            // Try to ping to check status
            $status = 'unknown';
            exec("/sbin/ping -c 1 -W 1 " . escapeshellarg($gw_ip) . " 2>/dev/null", $ping_out, $ping_ret);
            if ($ping_ret === 0) {
                $status = 'online';
            }

            $data[] = array(
                'name' => 'DEFAULT_GW',
                'interface' => $gw_if,
                'gateway' => $gw_ip,
                'monitor' => $gw_ip,
                'status' => $status,
                'delay' => '0 ms',
                'stddev' => '0 ms',
                'loss' => '0%'
            );
        }
    }
}

echo json_encode($data);
?>