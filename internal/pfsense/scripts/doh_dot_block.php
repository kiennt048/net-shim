<?php
error_reporting(0);
require_once("config.inc");
require_once("filter.inc");

$action = strtolower(trim(getenv('ACTION')));
$iface = strtolower(trim(getenv('INTERFACE')));
$enable_doh = trim(getenv('ENABLE_DOH')) === '1';
$enable_dot = trim(getenv('ENABLE_DOT')) === '1';
$alias_name = trim(getenv('ALIAS_NAME'));
$hosts_raw = trim(getenv('DOH_HOSTS'));
$descr_doh = trim(getenv('DESCR_DOH'));
$descr_dot = trim(getenv('DESCR_DOT'));
$descr_doh_v6 = '';
$descr_dot_v6 = '';

if ($iface === '') {
    $iface = 'lan';
}
if ($alias_name === '') {
    $alias_name = 'NetShim_DoH';
}
if ($descr_doh === '') {
    $descr_doh = 'NetShim: Block DoH';
}
if ($descr_dot === '') {
    $descr_dot = 'NetShim: Block DoT';
}
$descr_doh_v6 = $descr_doh . ' (IPv6)';
$descr_dot_v6 = $descr_dot . ' (IPv6)';

function normalize_list($value) {
    if (!is_array($value)) {
        return array();
    }
    $has_numeric = false;
    foreach (array_keys($value) as $k) {
        if (is_int($k)) {
            $has_numeric = true;
            break;
        }
    }
    if ($has_numeric) {
        return $value;
    }
    return array($value);
}

function parse_hosts($raw) {
    $parts = preg_split('/[\s,]+/', $raw);
    $hosts = array();
    foreach ($parts as $part) {
        $host = strtolower(trim($part));
        if ($host === '') {
            continue;
        }
        if (preg_match('/^[a-z0-9.-]+\.[a-z]{2,}$/', $host)) {
            $hosts[] = $host;
        }
    }
    return array_values(array_unique($hosts));
}

function find_rule_index($rules, $descr) {
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

function build_block_rule($iface, $protocol, $port, $descr, $dest_addr = '') {
    $rule = array(
        'type' => 'block',
        'interface' => $iface,
        'ipprotocol' => 'inet',
        'protocol' => $protocol,
        'source' => array('any' => ''),
        'destination' => array('any' => ''),
        'descr' => $descr,
        'tracker' => time(),
        'created' => array('time' => time(), 'username' => 'NetShim'),
    );

    if ($dest_addr !== '') {
        $rule['destination'] = array(
            'address' => $dest_addr,
            'port' => $port,
        );
    } else {
        $rule['destination'] = array(
            'any' => '',
            'port' => $port,
        );
    }

    return $rule;
}

$hosts = parse_hosts($hosts_raw);
if (empty($hosts)) {
    $hosts = array('example.invalid');
}

if ($action === 'get') {
    $aliases = array();
    if (isset($config['aliases']['alias'])) {
        $aliases = normalize_list($config['aliases']['alias']);
    }

    $alias_present = false;
    foreach ($aliases as $alias) {
        if (isset($alias['name']) && $alias['name'] === $alias_name) {
            $alias_present = true;
            break;
        }
    }

    $rules = array();
    if (isset($config['filter']['rule'])) {
        $rules = normalize_list($config['filter']['rule']);
    }

    $doh_idx = find_rule_index($rules, $descr_doh);
    $dot_idx = find_rule_index($rules, $descr_dot);
    $doh6_idx = find_rule_index($rules, $descr_doh_v6);
    $dot6_idx = find_rule_index($rules, $descr_dot_v6);

    $result = array(
        'alias_present' => $alias_present,
        'doh_present' => $doh_idx >= 0,
        'dot_present' => $dot_idx >= 0,
        'doh_enabled' => $doh_idx >= 0 && $doh6_idx >= 0 ? (!isset($rules[$doh_idx]['disabled']) && !isset($rules[$doh6_idx]['disabled'])) : false,
        'dot_enabled' => $dot_idx >= 0 && $dot6_idx >= 0 ? (!isset($rules[$dot_idx]['disabled']) && !isset($rules[$dot6_idx]['disabled'])) : false,
    );

    echo json_encode($result);
    exit;
}

if ($action !== 'set') {
    die('ERROR:INVALID_ACTION');
}

if (!isset($config['aliases'])) {
    $config['aliases'] = array();
}
$aliases = array();
if (isset($config['aliases']['alias'])) {
    $aliases = normalize_list($config['aliases']['alias']);
}

$alias_idx = -1;
foreach ($aliases as $idx => $alias) {
    if (isset($alias['name']) && $alias['name'] === $alias_name) {
        $alias_idx = $idx;
        break;
    }
}

$address = implode(' ', $hosts);
$alias_entry = array(
    'name' => $alias_name,
    'type' => 'host',
    'address' => $address,
    'descr' => 'NetShim DoH Hostnames',
);

if ($alias_idx >= 0) {
    $aliases[$alias_idx] = array_merge($aliases[$alias_idx], $alias_entry);
} else {
    $aliases[] = $alias_entry;
}

$config['aliases']['alias'] = array_values($aliases);

if (!isset($config['filter'])) {
    $config['filter'] = array();
}
$rules = array();
if (isset($config['filter']['rule'])) {
    $rules = normalize_list($config['filter']['rule']);
}

$doh_idx = find_rule_index($rules, $descr_doh);
$dot_idx = find_rule_index($rules, $descr_dot);
$doh6_idx = find_rule_index($rules, $descr_doh_v6);
$dot6_idx = find_rule_index($rules, $descr_dot_v6);

if ($doh_idx < 0) {
    $rule = build_block_rule($iface, 'tcp', '443', $descr_doh, $alias_name);
    array_unshift($rules, $rule);
    $doh_idx = 0;
} else {
    $rules[$doh_idx] = array_merge($rules[$doh_idx], build_block_rule($iface, 'tcp', '443', $descr_doh, $alias_name));
}

if ($dot_idx < 0) {
    $rule = build_block_rule($iface, 'tcp', '853', $descr_dot, '');
    array_unshift($rules, $rule);
    $dot_idx = 0;
} else {
    $rules[$dot_idx] = array_merge($rules[$dot_idx], build_block_rule($iface, 'tcp', '853', $descr_dot, ''));
}

if ($doh6_idx < 0) {
    $rule = build_block_rule($iface, 'tcp', '443', $descr_doh_v6, $alias_name);
    $rule['ipprotocol'] = 'inet6';
    array_unshift($rules, $rule);
    $doh6_idx = 0;
} else {
    $rule = build_block_rule($iface, 'tcp', '443', $descr_doh_v6, $alias_name);
    $rule['ipprotocol'] = 'inet6';
    $rules[$doh6_idx] = array_merge($rules[$doh6_idx], $rule);
}

if ($dot6_idx < 0) {
    $rule = build_block_rule($iface, 'tcp', '853', $descr_dot_v6, '');
    $rule['ipprotocol'] = 'inet6';
    array_unshift($rules, $rule);
    $dot6_idx = 0;
} else {
    $rule = build_block_rule($iface, 'tcp', '853', $descr_dot_v6, '');
    $rule['ipprotocol'] = 'inet6';
    $rules[$dot6_idx] = array_merge($rules[$dot6_idx], $rule);
}

if ($enable_doh) {
    if (isset($rules[$doh_idx]['disabled'])) {
        unset($rules[$doh_idx]['disabled']);
    }
    if (isset($rules[$doh6_idx]['disabled'])) {
        unset($rules[$doh6_idx]['disabled']);
    }
} else {
    $rules[$doh_idx]['disabled'] = '';
    $rules[$doh6_idx]['disabled'] = '';
}

if ($enable_dot) {
    if (isset($rules[$dot_idx]['disabled'])) {
        unset($rules[$dot_idx]['disabled']);
    }
    if (isset($rules[$dot6_idx]['disabled'])) {
        unset($rules[$dot6_idx]['disabled']);
    }
} else {
    $rules[$dot_idx]['disabled'] = '';
    $rules[$dot6_idx]['disabled'] = '';
}

$config['filter']['rule'] = array_values($rules);

write_config("NetShim: Updated DoH/DoT blocking rules");

if (function_exists('filter_configure_sync')) {
    filter_configure_sync();
}

echo "SUCCESS";
?>
