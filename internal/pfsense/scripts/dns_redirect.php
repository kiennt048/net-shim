<?php
error_reporting(0);
require_once("config.inc");
require_once("filter.inc");

$action = strtolower(trim(getenv('ACTION')));
$iface = strtolower(trim(getenv('INTERFACE')));
$enable = trim(getenv('ENABLE'));
$target_port = trim(getenv('TARGET_PORT'));
$target = trim(getenv('TARGET'));
$descr = trim(getenv('DESCR'));
$descr_v6 = '';

if ($iface === '') {
    $iface = 'lan';
}
if ($target_port === '' || !is_numeric($target_port)) {
    $target_port = '5353';
}
if ($target === '') {
    $target = 'lanip';
}
if ($descr === '') {
    $descr = 'NetShim: DNS Redirect to AdGuard';
}
$descr_v6 = $descr . ' (IPv6)';

function find_dns_rule_index($rules, $descr) {
    if (!is_array($rules)) {
        return -1;
    }
    foreach ($rules as $idx => $rule) {
        if (!is_array($rule)) {
            continue;
        }
        if (isset($rule['descr']) && $rule['descr'] === $descr) {
            return $idx;
        }
    }
    return -1;
}

if ($action === 'get') {
    $result = array(
        'present' => false,
        'enabled' => false,
        'interface' => $iface,
        'target' => $target,
        'local_port' => $target_port,
        'dstport' => '53'
    );

    $rules = array();
    if (isset($config['nat']) && isset($config['nat']['rule'])) {
        $rules = $config['nat']['rule'];
    }
    $idx = find_dns_rule_index($rules, $descr);
    $idx6 = find_dns_rule_index($rules, $descr_v6);
    if ($idx >= 0) {
        $rule = $rules[$idx];
        $result['present'] = true;
        $result['interface'] = isset($rule['interface']) ? $rule['interface'] : $iface;
        $result['target'] = isset($rule['target']) ? $rule['target'] : $target;
        $result['local_port'] = isset($rule['local-port']) ? $rule['local-port'] : $target_port;
        $result['dstport'] = isset($rule['dstport']) ? $rule['dstport'] : '53';
        $result['enabled'] = !isset($rule['disabled']);
        if ($idx6 >= 0) {
            $rule6 = $rules[$idx6];
            $result['enabled'] = $result['enabled'] && !isset($rule6['disabled']);
        } else {
            $result['enabled'] = false;
        }
    }

    echo json_encode($result);
    exit;
}

if ($action !== 'set') {
    die("ERROR:INVALID_ACTION");
}

if (!isset($config['nat'])) {
    $config['nat'] = array();
}
if (!isset($config['nat']['rule']) || !is_array($config['nat']['rule'])) {
    $config['nat']['rule'] = array();
}

$rules = &$config['nat']['rule'];
$idx = find_dns_rule_index($rules, $descr);
$idx6 = find_dns_rule_index($rules, $descr_v6);

$rule = array(
    'interface' => $iface,
    'ipprotocol' => 'inet',
    'protocol' => 'tcp/udp',
    'source' => array('any' => ''),
    'destination' => array('any' => ''),
    'dstport' => '53',
    'target' => $target,
    'local-port' => strval($target_port),
    'descr' => $descr
);

$target6 = $target;
if ($target === 'lanip') {
    $target6 = 'lanip6';
}

$rule6 = $rule;
$rule6['ipprotocol'] = 'inet6';
$rule6['target'] = $target6;
$rule6['descr'] = $descr_v6;

if ($idx >= 0) {
    $existing = $rules[$idx];
    if (is_array($existing)) {
        $rule['created'] = isset($existing['created']) ? $existing['created'] : array('time' => time(), 'username' => 'NetShim');
    }
    $rule['updated'] = array('time' => time(), 'username' => 'NetShim');
    $rules[$idx] = array_merge($existing, $rule);
} else {
    $rule['created'] = array('time' => time(), 'username' => 'NetShim');
    $rules[] = $rule;
    $idx = count($rules) - 1;
}

if ($idx6 >= 0) {
    $existing = $rules[$idx6];
    if (is_array($existing)) {
        $rule6['created'] = isset($existing['created']) ? $existing['created'] : array('time' => time(), 'username' => 'NetShim');
    }
    $rule6['updated'] = array('time' => time(), 'username' => 'NetShim');
    $rules[$idx6] = array_merge($existing, $rule6);
} else {
    $rule6['created'] = array('time' => time(), 'username' => 'NetShim');
    $rules[] = $rule6;
    $idx6 = count($rules) - 1;
}

if ($enable === '1') {
    if (isset($rules[$idx]['disabled'])) {
        unset($rules[$idx]['disabled']);
    }
    if (isset($rules[$idx6]['disabled'])) {
        unset($rules[$idx6]['disabled']);
    }
} else {
    $rules[$idx]['disabled'] = '';
    $rules[$idx6]['disabled'] = '';
}

write_config("NetShim: Updated DNS redirect rule");

if (function_exists('filter_configure_sync')) {
    filter_configure_sync();
}

echo "SUCCESS";
?>
