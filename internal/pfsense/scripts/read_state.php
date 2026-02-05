<?php
error_reporting(0);
require_once("config.inc");
require_once("interfaces.inc");
require_once("util.inc");

$data = array();

// Get raw ifconfig output for all interfaces
exec('/sbin/ifconfig -a', $ifconfig_output);
$ifconfig_data = parse_ifconfig($ifconfig_output);

// Get routing table for gateway detection
exec('/usr/bin/netstat -rn -f inet', $netstat_output);
$routing_table = parse_routing_table($netstat_output);

foreach ($config['interfaces'] as $ifname => $if_conf) {
    $ifreal = get_real_interface($ifname);
    if (!$ifreal)
        continue;

    // Skip VPN interfaces (wireguard, openvpn, ipsec, gre, l2tp, pptp)
    if (preg_match('/^(tun_wg|wg|ovpn|ipsec|enc|gre|gif|l2tp|pptp|ng\d+_)/', $ifreal)) {
        continue;
    }

    // Check enabled state
    $is_enabled = isset($if_conf['enable']);

    // Get interface info from ifconfig directly
    $ifconfig_info = isset($ifconfig_data[$ifreal]) ? $ifconfig_data[$ifreal] : array();

    // Get stats
    $stats = pfSense_get_interface_stats($ifreal);

    // Determine current mode
    $mode = 'static';
    if (isset($if_conf['ipaddr'])) {
        if ($if_conf['ipaddr'] == 'dhcp') {
            $mode = 'dhcp';
        } elseif ($if_conf['ipaddr'] == 'pppoe') {
            $mode = 'pppoe';
        }
    }

    // Initialize variables
    $ipaddr = 'N/A';
    $subnet = '';
    $gateway = '';

    // Initialize PPPoE config fields
    $pppoe_username = '';
    $pppoe_password = '';
    $pppoe_vlan_enable = false;
    $pppoe_vlan_id = '';
    $pppoe_vlan_desc = '';

    // Extract PPPoE configuration if mode is PPPoE
    if ($mode == 'pppoe') {
        $ppp_if = isset($if_conf['if']) ? $if_conf['if'] : '';

        // Find PPPoE configuration in config
        if (isset($config['ppps']['ppp'])) {
            $ppp_list = array();

            // Handle both single entry and array
            $has_numeric_keys = false;
            foreach (array_keys($config['ppps']['ppp']) as $k) {
                if (is_int($k)) {
                    $has_numeric_keys = true;
                    break;
                }
            }

            if ($has_numeric_keys) {
                $ppp_list = $config['ppps']['ppp'];
            } elseif (!empty($config['ppps']['ppp'])) {
                $ppp_list = array($config['ppps']['ppp']);
            }

            // Find matching PPP entry
            foreach ($ppp_list as $ppp) {
                if (!is_array($ppp))
                    continue;

                if (isset($ppp['if']) && $ppp['if'] == $ppp_if) {
                    // Extract username
                    $pppoe_username = isset($ppp['username']) ? $ppp['username'] : '';

                    // Extract password (base64 encoded in config)
                    if (isset($ppp['password'])) {
                        $pppoe_password = base64_decode($ppp['password']);
                    }

                    // Check if using VLAN
                    if (isset($ppp['ports'])) {
                        $ports = $ppp['ports'];
                        // Check if ports contain VLAN notation (e.g., "re0.100")
                        if (strpos($ports, '.') !== false) {
                            $pppoe_vlan_enable = true;
                            $parts = explode('.', $ports);
                            $pppoe_vlan_id = isset($parts[1]) ? $parts[1] : '';

                            // Find VLAN description
                            if (isset($config['vlans']['vlan'])) {
                                $vlan_list = array();
                                $has_numeric_keys = false;
                                foreach (array_keys($config['vlans']['vlan']) as $k) {
                                    if (is_int($k)) {
                                        $has_numeric_keys = true;
                                        break;
                                    }
                                }

                                if ($has_numeric_keys) {
                                    $vlan_list = $config['vlans']['vlan'];
                                } else {
                                    $vlan_list = array($config['vlans']['vlan']);
                                }

                                foreach ($vlan_list as $vlan) {
                                    if (is_array($vlan) && isset($vlan['tag']) && $vlan['tag'] == $pppoe_vlan_id) {
                                        $pppoe_vlan_desc = isset($vlan['descr']) ? $vlan['descr'] : '';
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    break;
                }
            }
        }
    }

    // Get gateway from config first (for static mode)
    if (isset($if_conf['gateway'])) {
        $gw_name = $if_conf['gateway'];
        if (isset($config['gateways']['gateway_item'])) {
            foreach ($config['gateways']['gateway_item'] as $gw) {
                if ($gw['name'] == $gw_name) {
                    $gateway = $gw['gateway'];
                    break;
                }
            }
        }
    }

    // MODE-SPECIFIC LOGIC
    if ($mode == 'pppoe') {
        // PPPoE: Read from PPP interface (pppoe0, pppoe1, etc.)
        $ppp_if = isset($if_conf['if']) ? $if_conf['if'] : '';

        if ($ppp_if && isset($ifconfig_data[$ppp_if])) {
            // Get IP from PPP interface
            if (isset($ifconfig_data[$ppp_if]['inet'])) {
                $ipaddr = $ifconfig_data[$ppp_if]['inet'];
            }

            // Get subnet from PPP interface
            if (isset($ifconfig_data[$ppp_if]['netmask'])) {
                $subnet = strval($ifconfig_data[$ppp_if]['netmask']);
            }

            // Get gateway from PPP interface (point-to-point destination)
            if (isset($ifconfig_data[$ppp_if]['destination'])) {
                $gateway = $ifconfig_data[$ppp_if]['destination'];
            }

            // Fallback: Get gateway from routing table for PPP interface
            if (empty($gateway) && isset($routing_table[$ppp_if])) {
                $gateway = $routing_table[$ppp_if];
            }
        }
    } elseif ($mode == 'dhcp') {
        // DHCP: Read from physical interface
        if (isset($ifconfig_data[$ifreal]['inet'])) {
            $ipaddr = $ifconfig_data[$ifreal]['inet'];
        }

        if (isset($ifconfig_data[$ifreal]['netmask'])) {
            $subnet = strval($ifconfig_data[$ifreal]['netmask']);
        }

        // Get DHCP gateway dynamically (runtime only)
        if (empty($gateway) && $is_enabled) {
            // Priority 1: Read from DHCP lease file
            $lease_file = "/var/db/dhclient.leases." . $ifreal;
            if (file_exists($lease_file)) {
                $lease_content = file_get_contents($lease_file);
                if (preg_match('/option routers ([\d.]+);/', $lease_content, $matches)) {
                    $gateway = $matches[1];
                }
            }

            // Priority 2: Try get_interface_info
            if (empty($gateway)) {
                $ifinfo = get_interface_info($ifreal);
                if (isset($ifinfo['gateway'])) {
                    $gateway = $ifinfo['gateway'];
                } elseif (isset($ifinfo['gatewayv4'])) {
                    $gateway = $ifinfo['gatewayv4'];
                }
            }

            // Priority 3: Fallback to routing table
            if (empty($gateway) && isset($routing_table[$ifreal])) {
                $gateway = $routing_table[$ifreal];
            }
        }
    } else {
        // Static mode: Read from config first (avoids showing alias IPs)
        if (isset($if_conf['ipaddr']) && $if_conf['ipaddr'] != 'dhcp' && $if_conf['ipaddr'] != 'pppoe') {
            $ipaddr = $if_conf['ipaddr'];
        } elseif (isset($ifconfig_data[$ifreal]['inet'])) {
            $ipaddr = $ifconfig_data[$ifreal]['inet'];
        }

        if (isset($if_conf['subnet']) && !empty($if_conf['subnet'])) {
            $subnet = strval($if_conf['subnet']);
        } elseif (isset($ifconfig_data[$ifreal]['netmask'])) {
            $subnet = strval($ifconfig_data[$ifreal]['netmask']);
        }
    }

    // Defensive stats key normalization
    $bytes_in = intval($stats['inbytes'] ?? $stats['bytes received'] ?? 0);
    $bytes_out = intval($stats['outbytes'] ?? $stats['bytes transmitted'] ?? 0);

    // Initialize DHCP Server config fields
    $dhcp_server_enable = false;
    $dhcp_lease_time = '';
    $dhcp_dns1 = '';
    $dhcp_dns2 = '';
    $dhcp_pool_start = '';
    $dhcp_pool_end = '';

    // Extract DHCP Server configuration from dhcpd section (pfSense format)
    if ($mode == 'static' && isset($config['dhcpd'][$ifname])) {
        $dhcp_conf = $config['dhcpd'][$ifname];

        // Check if DHCP is enabled (enable tag must be present)
        if (isset($dhcp_conf['enable'])) {
            $dhcp_server_enable = true;

            // Extract pool range
            if (isset($dhcp_conf['range']['from']) && isset($dhcp_conf['range']['to'])) {
                $dhcp_pool_start = $dhcp_conf['range']['from'];
                $dhcp_pool_end = $dhcp_conf['range']['to'];
            }

            // Extract lease time
            if (isset($dhcp_conf['defaultleasetime'])) {
                $dhcp_lease_time = strval($dhcp_conf['defaultleasetime']);
            }

            // Extract DNS servers
            if (isset($dhcp_conf['dnsserver']) && is_array($dhcp_conf['dnsserver'])) {
                if (isset($dhcp_conf['dnsserver'][0])) {
                    $dhcp_dns1 = $dhcp_conf['dnsserver'][0];
                }
                if (isset($dhcp_conf['dnsserver'][1])) {
                    $dhcp_dns2 = $dhcp_conf['dnsserver'][1];
                }
            }
        }
    }

    // Get status
    $status = 'down';
    if (!$is_enabled) {
        $status = 'disabled';
    } elseif ($mode == 'pppoe') {
        // For PPPoE, check the PPP interface status
        $ppp_if = isset($if_conf['if']) ? $if_conf['if'] : '';
        if ($ppp_if && isset($ifconfig_data[$ppp_if])) {
            $ppp_info = $ifconfig_data[$ppp_if];
            if (isset($ppp_info['status'])) {
                $status = strtolower($ppp_info['status']);
            } elseif (isset($ppp_info['flags']) && strpos($ppp_info['flags'], 'UP') !== false) {
                if (strpos($ppp_info['flags'], 'RUNNING') !== false) {
                    $status = 'up';
                } else {
                    $status = 'no carrier';
                }
            }
        }
    } elseif (isset($ifconfig_info['status'])) {
        $status = strtolower($ifconfig_info['status']);
    } elseif (isset($ifconfig_info['flags']) && strpos($ifconfig_info['flags'], 'UP') !== false) {
        if (strpos($ifconfig_info['flags'], 'RUNNING') !== false) {
            $status = 'up';
        } else {
            $status = 'no carrier';
        }
    }

    $data[$ifname] = array(
        'name' => $ifname,
        'display_name' => strtoupper($ifname),
        'real_if' => $ifreal,
        'ipaddr' => $ipaddr,
        'subnet' => $subnet,
        'subnet_mask' => '',
        'gateway' => $gateway,
        'status' => $status,
        'bytes_in' => $is_enabled ? $bytes_in : 0,
        'bytes_out' => $is_enabled ? $bytes_out : 0,
        'mode' => $mode,
        'description' => $if_conf['descr'] ?? '',
        'mtu' => $if_conf['mtu'] ?? '',
        'mss' => $if_conf['mss'] ?? '',
        'enabled' => $is_enabled,
        'pppoe_username' => $pppoe_username,
        'pppoe_password' => $pppoe_password,
        'pppoe_vlan_enable' => $pppoe_vlan_enable,
        'pppoe_vlan_id' => $pppoe_vlan_id,
        'pppoe_vlan_desc' => $pppoe_vlan_desc,
        'dhcp_server_enable' => $dhcp_server_enable,
        'dhcp_lease_time' => $dhcp_lease_time,
        'dhcp_dns1' => $dhcp_dns1,
        'dhcp_dns2' => $dhcp_dns2,
        'dhcp_pool_start' => $dhcp_pool_start,
        'dhcp_pool_end' => $dhcp_pool_end
    );
}

// ===== DETECT UNASSIGNED PHYSICAL NICs =====
// Get list of all physical NICs
exec('/sbin/ifconfig -l', $if_list_output);
if (!empty($if_list_output)) {
    $all_physical_ifs = explode(' ', trim($if_list_output[0]));

    // Get list of already assigned interfaces
    $assigned_ports = array();
    foreach ($config['interfaces'] as $ifname => $if_conf) {
        if (isset($if_conf['if'])) {
            $port = $if_conf['if'];
            $assigned_ports[$port] = true;
            // Also mark VLAN parent interfaces as used
            if (strpos($port, '.') !== false) {
                $parts = explode('.', $port);
                $assigned_ports[$parts[0]] = true;
            }
        }
    }

    // Also check PPPoE configs for used ports
    if (isset($config['ppps']['ppp'])) {
        $ppp_list = is_array($config['ppps']['ppp']) ? $config['ppps']['ppp'] : array($config['ppps']['ppp']);
        foreach ($ppp_list as $ppp) {
            if (is_array($ppp) && isset($ppp['ports'])) {
                $port = $ppp['ports'];
                $assigned_ports[$port] = true;
                if (strpos($port, '.') !== false) {
                    $parts = explode('.', $port);
                    $assigned_ports[$parts[0]] = true;
                }
            }
        }
    }

    // Pattern for physical NICs (common FreeBSD/pfSense drivers)
    $nic_pattern = '/^(em|igb|ix|ixl|ixv|vmx|vtnet|re|bge|hn|axe|cxgb|msk|bce|nfe|rl|sis|ste|vr|xl|dc|fxp|gem|hme|le|sk|ti|tl|wb)\d+$/';

    // Counter for unassigned interfaces
    $opt_counter = 1;

    // Find next available OPT number
    foreach ($config['interfaces'] as $ifname => $if_conf) {
        if (preg_match('/^opt(\d+)$/', $ifname, $matches)) {
            $num = intval($matches[1]);
            if ($num >= $opt_counter) {
                $opt_counter = $num + 1;
            }
        }
    }

    foreach ($all_physical_ifs as $nic) {
        // Skip if not a physical NIC pattern
        if (!preg_match($nic_pattern, $nic)) {
            continue;
        }

        // Skip if already assigned
        if (isset($assigned_ports[$nic])) {
            continue;
        }

        // This is an unassigned physical NIC - add to output
        $ifconfig_info = isset($ifconfig_data[$nic]) ? $ifconfig_data[$nic] : array();

        // Determine status from flags
        $status = 'down';
        if (isset($ifconfig_info['flags'])) {
            if (strpos($ifconfig_info['flags'], 'UP') !== false && strpos($ifconfig_info['flags'], 'RUNNING') !== false) {
                $status = 'no carrier'; // UP but not assigned = no carrier
            }
        }

        // Generate a suggested interface name
        $suggested_name = 'opt' . $opt_counter;
        $opt_counter++;

        $data['_unassigned_' . $nic] = array(
            'name' => '_unassigned_' . $nic,
            'display_name' => strtoupper($nic) . ' (Unassigned)',
            'real_if' => $nic,
            'ipaddr' => 'N/A',
            'subnet' => '',
            'subnet_mask' => '',
            'gateway' => '',
            'status' => 'disabled',
            'bytes_in' => 0,
            'bytes_out' => 0,
            'mode' => 'static',
            'description' => 'Available network port - click enable to assign',
            'mtu' => '',
            'mss' => '',
            'enabled' => false,
            'unassigned' => true,  // Flag to indicate this is unassigned
            'physical_port' => $nic,
            'suggested_name' => $suggested_name,
            'pppoe_username' => '',
            'pppoe_password' => '',
            'pppoe_vlan_enable' => false,
            'pppoe_vlan_id' => '',
            'pppoe_vlan_desc' => '',
            'dhcp_server_enable' => false,
            'dhcp_lease_time' => '',
            'dhcp_dns1' => '',
            'dhcp_dns2' => '',
            'dhcp_pool_start' => '',
            'dhcp_pool_end' => ''
        );
    }
}

// Helper: Parse ifconfig output
function parse_ifconfig($lines)
{
    $interfaces = array();
    $current_if = null;

    foreach ($lines as $line) {
        // Match interface line: pppoe0: flags=...
        if (preg_match('/^([a-z0-9_.]+):\s+flags=/', $line, $matches)) {
            $current_if = $matches[1];

            // Extract flags
            if (preg_match('/<(.+?)>/', $line, $flag_matches)) {
                $interfaces[$current_if] = array(
                    'flags' => $flag_matches[1]
                );
            } else {
                $interfaces[$current_if] = array();
            }
        } elseif ($current_if && preg_match('/^\s+(.+)/', $line, $matches)) {
            $content = trim($matches[1]);

            // Parse PPPoE point-to-point: inet 100.71.100.2 --> 100.71.99.1 netmask 0xffffffff
            if (preg_match('/^inet\s+([\d.]+)\s+-->\s+([\d.]+)\s+netmask\s+(0x[0-9a-f]+)/', $content, $ppp_matches)) {
                $interfaces[$current_if]['inet'] = $ppp_matches[1];
                $interfaces[$current_if]['destination'] = $ppp_matches[2]; // Gateway for PPPoE
                $netmask_hex = hexdec($ppp_matches[3]);
                $cidr = $netmask_hex == 0xffffffff ? 32 : (32 - log((~$netmask_hex & 0xFFFFFFFF) + 1, 2));
                $interfaces[$current_if]['netmask'] = strval(intval($cidr));
            }
            // Parse standard inet: inet 192.168.1.1 netmask 0xffffff00 broadcast 192.168.1.255
            elseif (preg_match('/^inet\s+([\d.]+)\s+netmask\s+(0x[0-9a-f]+)/', $content, $inet_matches)) {
                $interfaces[$current_if]['inet'] = $inet_matches[1];
                $netmask_hex = hexdec($inet_matches[2]);
                $cidr = 32 - log((~$netmask_hex & 0xFFFFFFFF) + 1, 2);
                $interfaces[$current_if]['netmask'] = strval(intval($cidr));
            }

            // Parse status line
            if (preg_match('/^status:\s+(.+)$/', $content, $status_matches)) {
                $interfaces[$current_if]['status'] = trim($status_matches[1]);
            }
        }
    }

    return $interfaces;
}

// Helper: Parse routing table to extract gateways
function parse_routing_table($lines)
{
    $gateways = array();
    $in_table = false;

    foreach ($lines as $line) {
        // Skip header lines
        if (strpos($line, 'Destination') !== false || strpos($line, 'Internet:') !== false) {
            $in_table = true;
            continue;
        }

        if (!$in_table)
            continue;

        // Match default route: default  192.168.1.1  UGS  0  12345  re0
        if (preg_match('/^default\s+([\d.]+)\s+\w+\s+\d+\s+\d+\s+(\S+)/', $line, $matches)) {
            $gateway_ip = $matches[1];
            $interface = $matches[2];

            if (!isset($gateways[$interface])) {
                $gateways[$interface] = $gateway_ip;
            }
        }
        // Match 0.0.0.0/X routes (common for PPPoE): 0.0.0.0/1  100.71.99.1  UGS  0  123  pppoe0
        elseif (preg_match('/^0\.0\.0\.0\/\d+\s+([\d.]+)\s+\w+\s+\d+\s+\d+\s+(\S+)/', $line, $matches)) {
            $gateway_ip = $matches[1];
            $interface = $matches[2];

            if (!isset($gateways[$interface])) {
                $gateways[$interface] = $gateway_ip;
            }
        }
    }

    return $gateways;
}

echo json_encode($data);
?>