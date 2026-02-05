<?php
error_reporting(0);
require_once("config.inc");
require_once("interfaces.inc");
require_once("util.inc");
require_once("filter.inc");

$payload = getenv('NETSHIM_PAYLOAD');
if (!$payload)
    die("ERROR:NO_PAYLOAD");

$req = json_decode($payload, true);
if (!$req)
    die("ERROR:INVALID_JSON");

if (empty($req['interface']))
    die("ERROR:MISSING_INTERFACE");
if (empty($req['mode']))
    die("ERROR:MISSING_MODE");

$target_if = strtolower($req['interface']);

if (!isset($config['interfaces'][$target_if])) {
    die("ERROR:IF_NOT_FOUND");
}

$if_conf = &$config['interfaces'][$target_if];

// Helper function to restore physical interface when switching from PPPoE
function restore_physical_interface(&$if_conf, $target_if, &$config)
{
    $current_if_name = $if_conf['if'];

    if (strpos($current_if_name, 'pppoe') !== 0) {
        return; // Not a PPPoE interface
    }

    syslog(LOG_INFO, "NetShim: Switching from PPPoE on $target_if - restoring physical interface");

    $physical_port = '';
    $ppp_idx_to_remove = -1;

    if (isset($config['ppps']['ppp']) && is_array($config['ppps']['ppp'])) {
        $ppp_list = array();
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

        foreach ($ppp_list as $idx => $ppp) {
            if (!is_array($ppp))
                continue;
            if (isset($ppp['if']) && $ppp['if'] == $current_if_name) {
                $ppp_idx_to_remove = $idx;
                if (isset($ppp['ports'])) {
                    $physical_port = $ppp['ports'];
                    if (strpos($physical_port, '.') !== false) {
                        $parts = explode('.', $physical_port);
                        $physical_port = $parts[0];
                    }
                }
                break;
            }
        }

        if ($ppp_idx_to_remove >= 0) {
            unset($ppp_list[$ppp_idx_to_remove]);
            $config['ppps']['ppp'] = array_values($ppp_list);
            syslog(LOG_INFO, "NetShim: Removed PPPoE config for $current_if_name");
        }
    }

    if (!empty($physical_port)) {
        $if_conf['if'] = $physical_port;
        syslog(LOG_INFO, "NetShim: Restored physical interface $physical_port for $target_if");
    } else {
        exec('/sbin/ifconfig -l', $if_list_output);
        if (!empty($if_list_output)) {
            $all_ifs = explode(' ', trim($if_list_output[0]));
            foreach ($all_ifs as $candidate_if) {
                if (preg_match('/^(em|igb|ix|vmx|vtnet|re|bge|hn|axe)\d+$/', $candidate_if)) {
                    $is_used = false;
                    foreach ($config['interfaces'] as $other_name => $other_conf) {
                        if ($other_name != $target_if && isset($other_conf['if']) && $other_conf['if'] == $candidate_if) {
                            $is_used = true;
                            break;
                        }
                    }
                    if (!$is_used) {
                        $if_conf['if'] = $candidate_if;
                        syslog(LOG_INFO, "NetShim: Auto-detected physical interface $candidate_if for $target_if");
                        break;
                    }
                }
            }
        }
    }

    exec('/sbin/ifconfig ' . escapeshellarg($current_if_name) . ' down 2>&1');
}

switch ($req['mode']) {
    case 'static':
        restore_physical_interface($if_conf, $target_if, $config);

        if (isset($if_conf['ipaddr']) && ($if_conf['ipaddr'] == 'dhcp' || $if_conf['ipaddr'] == 'pppoe')) {
            unset($if_conf['ipaddr']);
        }

        $if_conf['ipaddr'] = $req['ipaddr'];
        $if_conf['subnet'] = $req['subnet'];

        if (!empty($req['gateway'])) {
            $gw_name = $target_if . '_STATIC_GW';
            $gw_found = false;

            if (isset($config['gateways']['gateway_item'])) {
                foreach ($config['gateways']['gateway_item'] as &$gw) {
                    if ($gw['interface'] == $target_if && $gw['gateway'] == $req['gateway']) {
                        $gw_found = true;
                        $gw_name = $gw['name'];
                        break;
                    }
                }
            }

            if (!$gw_found) {
                if (!isset($config['gateways'])) {
                    $config['gateways'] = array();
                }
                if (!isset($config['gateways']['gateway_item'])) {
                    $config['gateways']['gateway_item'] = array();
                }

                $config['gateways']['gateway_item'][] = array(
                    'interface' => $target_if,
                    'gateway' => $req['gateway'],
                    'name' => $gw_name,
                    'weight' => '1',
                    'ipprotocol' => 'inet',
                    'descr' => 'Static gateway for ' . strtoupper($target_if)
                );
            }

            $if_conf['gateway'] = $gw_name;
        } else {
            if (isset($if_conf['gateway'])) {
                unset($if_conf['gateway']);
            }
        }

        // DHCP Server configuration
        if (!empty($req['dhcp_server_enable'])) {
            if (isset($if_conf['gateway'])) {
                unset($if_conf['gateway']);
            }

            if (!isset($config['dhcpbackend']) || $config['dhcpbackend'] != 'kea') {
                $config['dhcpbackend'] = 'kea';
            }
            if (!isset($config['installedpackages']['keadhcp'])) {
                $config['installedpackages']['keadhcp'] = array('config' => array(array('enable' => 'enabled')));
            }
            if (!isset($config['kea']['dhcp4']['enable'])) {
                $config['kea']['dhcp4']['enable'] = 'enabled';
            }

            $ip_long = ip2long($req['ipaddr']);
            $subnet_bits = intval($req['subnet']);
            $netmask = -1 << (32 - $subnet_bits);
            $network_long = $ip_long & $netmask;
            $broadcast_long = $network_long | ~$netmask;

            if (empty($req['dhcp_pool_start'])) {
                $req['dhcp_pool_start'] = long2ip($network_long + 5);
            }
            if (empty($req['dhcp_pool_end'])) {
                $req['dhcp_pool_end'] = long2ip($broadcast_long - 5);
            }
            if (empty($req['dhcp_lease_time'])) {
                $req['dhcp_lease_time'] = '7200';
            }
            if (empty($req['dhcp_dns1'])) {
                $req['dhcp_dns1'] = '8.8.8.8';
            }
            if (empty($req['dhcp_dns2'])) {
                $req['dhcp_dns2'] = '1.1.1.1';
            }

            if (!isset($config['dhcpd'])) {
                $config['dhcpd'] = array();
            }
            if (!isset($config['dhcpd'][$target_if])) {
                $config['dhcpd'][$target_if] = array();
            }

            $config['dhcpd'][$target_if]['enable'] = '';
            $config['dhcpd'][$target_if]['range'] = array(
                'from' => $req['dhcp_pool_start'],
                'to' => $req['dhcp_pool_end']
            );
            $config['dhcpd'][$target_if]['defaultleasetime'] = $req['dhcp_lease_time'];
            $config['dhcpd'][$target_if]['maxleasetime'] = strval(intval($req['dhcp_lease_time']) * 2);

            $config['dhcpd'][$target_if]['dnsserver'] = array();
            if (!empty($req['dhcp_dns1'])) {
                $config['dhcpd'][$target_if]['dnsserver'][] = $req['dhcp_dns1'];
            }
            if (!empty($req['dhcp_dns2'])) {
                $config['dhcpd'][$target_if]['dnsserver'][] = $req['dhcp_dns2'];
            }

            $config['dhcpd'][$target_if]['gateway'] = $req['ipaddr'];

            syslog(LOG_INFO, "NetShim: Enabled DHCP server on $target_if");
        } else {
            if (isset($config['dhcpd'][$target_if])) {
                if (isset($config['dhcpd'][$target_if]['enable'])) {
                    unset($config['dhcpd'][$target_if]['enable']);
                }
                if (isset($config['dhcpd'][$target_if]['range'])) {
                    $config['dhcpd'][$target_if]['range']['from'] = '';
                    $config['dhcpd'][$target_if]['range']['to'] = '';
                }
                if (isset($config['dhcpd'][$target_if]['dnsserver'])) {
                    unset($config['dhcpd'][$target_if]['dnsserver']);
                }
                if (isset($config['dhcpd'][$target_if]['defaultleasetime'])) {
                    unset($config['dhcpd'][$target_if]['defaultleasetime']);
                }
                if (isset($config['dhcpd'][$target_if]['maxleasetime'])) {
                    unset($config['dhcpd'][$target_if]['maxleasetime']);
                }
                if (isset($config['dhcpd'][$target_if]['gateway'])) {
                    unset($config['dhcpd'][$target_if]['gateway']);
                }

                syslog(LOG_INFO, "NetShim: Disabled DHCP server on $target_if");
            }
        }
        break;

    case 'dhcp':
        restore_physical_interface($if_conf, $target_if, $config);

        $if_conf['ipaddr'] = 'dhcp';

        if (isset($if_conf['subnet']))
            unset($if_conf['subnet']);

        if (isset($if_conf['gateway'])) {
            $old_gw_name = $if_conf['gateway'];
            unset($if_conf['gateway']);

            $gateway_in_use = false;
            foreach ($config['interfaces'] as $other_if => $other_conf) {
                if ($other_if != $target_if && isset($other_conf['gateway']) && $other_conf['gateway'] == $old_gw_name) {
                    $gateway_in_use = true;
                    break;
                }
            }

            if (!$gateway_in_use && isset($config['gateways']['gateway_item']) && is_array($config['gateways']['gateway_item'])) {
                foreach ($config['gateways']['gateway_item'] as $idx => $gw) {
                    if ($gw['name'] == $old_gw_name && $gw['interface'] == $target_if) {
                        unset($config['gateways']['gateway_item'][$idx]);
                        break;
                    }
                }
                $config['gateways']['gateway_item'] = array_values($config['gateways']['gateway_item']);
            }
        }
        break;

    case 'pppoe':
        if (empty($req['pppoe_username']))
            die("ERROR:PPPOE_USERNAME_REQUIRED");
        if (!empty($req['pppoe_vlan_enable']) && empty($req['pppoe_vlan_id'])) {
            die("ERROR:VLAN_ID_REQUIRED");
        }
        if (!empty($req['pppoe_vlan_id'])) {
            $vlan_id = intval($req['pppoe_vlan_id']);
            if ($vlan_id < 1 || $vlan_id > 4094) {
                die("ERROR:INVALID_VLAN_ID");
            }
        }

        $current_if = $if_conf['if'];
        $physical_if = $current_if;

        if (!isset($config['ppps']) || !is_array($config['ppps'])) {
            $config['ppps'] = array();
        }
        if (!isset($config['ppps']['ppp']) || !is_array($config['ppps']['ppp'])) {
            $config['ppps']['ppp'] = array();
        }

        $ppp_list = array();
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

        $existing_ppp_idx = -1;
        $existing_ppp_if = '';

        foreach ($ppp_list as $idx => $ppp) {
            if (!is_array($ppp))
                continue;

            if (isset($ppp['if']) && $ppp['if'] == $current_if) {
                $existing_ppp_idx = $idx;
                $existing_ppp_if = $ppp['if'];
                if (isset($ppp['ports'])) {
                    $physical_if = $ppp['ports'];
                    if (strpos($physical_if, '.') !== false) {
                        $parts = explode('.', $physical_if);
                        $physical_if = $parts[0];
                    }
                }
                break;
            }
        }

        $pppoe_physical_port = $physical_if;

        if (!empty($req['pppoe_vlan_enable']) && !empty($req['pppoe_vlan_id'])) {
            $vlan_id = intval($req['pppoe_vlan_id']);
            $vlan_if = $physical_if . '.' . $vlan_id;

            if (!isset($config['vlans']) || !is_array($config['vlans'])) {
                $config['vlans'] = array();
            }
            if (!isset($config['vlans']['vlan'])) {
                $config['vlans']['vlan'] = array();
            }

            $vlan_found = false;
            $vlan_list = array();

            if (!empty($config['vlans']['vlan'])) {
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
            }

            foreach ($vlan_list as $idx => $vlan) {
                if (is_array($vlan) && isset($vlan['if']) && isset($vlan['tag'])) {
                    if ($vlan['if'] == $physical_if && intval($vlan['tag']) == $vlan_id) {
                        $vlan_found = true;
                        if (!empty($req['pppoe_vlan_desc'])) {
                            $vlan_list[$idx]['descr'] = $req['pppoe_vlan_desc'];
                        }
                        break;
                    }
                }
            }

            if (!$vlan_found) {
                $vlan_desc = !empty($req['pppoe_vlan_desc']) ? $req['pppoe_vlan_desc'] : "VLAN $vlan_id";
                $vlan_list[] = array(
                    'if' => $physical_if,
                    'tag' => strval($vlan_id),
                    'pcp' => '',
                    'descr' => $vlan_desc,
                    'vlanif' => $vlan_if
                );
            }

            $config['vlans']['vlan'] = array_values($vlan_list);
            $pppoe_physical_port = $vlan_if;

            interfaces_vlan_configure($vlan_if);

            syslog(LOG_INFO, "NetShim: Created/updated VLAN $vlan_id on $physical_if");
        }

        if ($existing_ppp_idx >= 0) {
            $ppp_list[$existing_ppp_idx]['username'] = $req['pppoe_username'];
            if (!empty($req['pppoe_password'])) {
                $ppp_list[$existing_ppp_idx]['password'] = base64_encode($req['pppoe_password']);
            }
            $ppp_list[$existing_ppp_idx]['ports'] = $pppoe_physical_port;
            $pppoe_ifname = $existing_ppp_if;
        } else {
            if (empty($req['pppoe_password'])) {
                die("ERROR:PPPOE_PASSWORD_REQUIRED");
            }

            $max_ptpid = -1;
            foreach ($ppp_list as $ppp) {
                if (is_array($ppp) && isset($ppp['ptpid'])) {
                    $ptpid = intval($ppp['ptpid']);
                    if ($ptpid > $max_ptpid) {
                        $max_ptpid = $ptpid;
                    }
                }
            }
            $new_ptpid = $max_ptpid + 1;
            $pppoe_ifname = 'pppoe' . $new_ptpid;

            $ppp_list[] = array(
                'ptpid' => strval($new_ptpid),
                'type' => 'pppoe',
                'if' => $pppoe_ifname,
                'ports' => $pppoe_physical_port,
                'username' => $req['pppoe_username'],
                'password' => base64_encode($req['pppoe_password'])
            );
        }

        $config['ppps']['ppp'] = array_values($ppp_list);

        $if_conf['if'] = $pppoe_ifname;
        $if_conf['ipaddr'] = 'pppoe';

        if (isset($if_conf['subnet']))
            unset($if_conf['subnet']);
        if (isset($if_conf['gateway']))
            unset($if_conf['gateway']);

        break;

    default:
        die("ERROR:INVALID_MODE");
}

if (!empty($req['mtu'])) {
    $mtu = intval($req['mtu']);
    if ($mtu < 576 || $mtu > 9000) {
        die("ERROR:INVALID_MTU");
    }
    $if_conf['mtu'] = strval($mtu);
} else {
    if (isset($if_conf['mtu'])) {
        unset($if_conf['mtu']);
    }
}

if (!empty($req['mss'])) {
    $mss = intval($req['mss']);
    if ($mss < 536 || $mss > 8960) {
        die("ERROR:INVALID_MSS");
    }
    $if_conf['mss'] = strval($mss);
} else {
    if (isset($if_conf['mss'])) {
        unset($if_conf['mss']);
    }
}

if (!empty($req['description'])) {
    $if_conf['descr'] = $req['description'];
}

$log_msg = "NetShim: Applying $target_if - Mode: " . $req['mode'];
if ($req['mode'] == 'pppoe') {
    $log_msg .= ", User: " . $req['pppoe_username'];
}
syslog(LOG_INFO, $log_msg);

// ===================================================================
// AUTOMATIC OUTBOUND NAT CONFIGURATION
// Ensure all traffic going through WAN is NAT'd by WAN address
// ===================================================================

// Initialize NAT structure if not exists
if (!isset($config['nat'])) {
    $config['nat'] = array();
}
if (!isset($config['nat']['outbound'])) {
    $config['nat']['outbound'] = array();
}

// Set outbound NAT mode to automatic
// This ensures pfSense auto-generates NAT rules for all internal networks
$config['nat']['outbound']['mode'] = 'automatic';

syslog(LOG_INFO, "NetShim: Outbound NAT set to automatic mode");

write_config("NetShim: Updated $target_if to " . $req['mode']);

// Reconfigure the specific interface
interface_configure($target_if, true, true);

// Reconfigure routing (gateways, static routes)
system_routing_configure();

// Restart gateway monitoring (dpinger) to detect gateway status properly
if (function_exists('setup_gateways_monitor')) {
    setup_gateways_monitor();
}

// Regenerate DNS resolver configuration
if (function_exists('system_resolvconf_generate')) {
    system_resolvconf_generate();
}

// Use filter_configure_sync() for complete filter reload including NAT
// This is more thorough than filter_configure() and waits for completion
if (function_exists('filter_configure_sync')) {
    filter_configure_sync();
} else {
    filter_configure();
}

// Handle DHCP server restart if enabled
if ($req['mode'] == 'static' && isset($req['dhcp_server_enable'])) {
    if ($req['dhcp_server_enable']) {
        exec('/usr/local/etc/rc.d/kea restart 2>&1', $dhcp_output, $dhcp_retval);
        if ($dhcp_retval === 0) {
            syslog(LOG_INFO, "NetShim: KEA DHCP service restarted successfully");
        } else {
            syslog(LOG_WARNING, "NetShim: KEA DHCP restart returned code $dhcp_retval");
        }
    }
}

if (function_exists('opcache_reset')) {
    opcache_reset();
}

syslog(LOG_INFO, "NetShim: Configuration applied successfully for $target_if");
echo "SUCCESS";
?>