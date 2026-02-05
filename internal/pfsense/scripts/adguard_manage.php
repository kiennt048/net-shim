<?php
error_reporting(0);
require_once("util.inc");

set_time_limit(0);

$action = strtolower(trim(getenv('ACTION')));
$reinstall = trim(getenv('REINSTALL')) === '1';

$agh_dir = '/usr/local/AdGuardHome';
$agh_bin = $agh_dir . '/AdGuardHome';
$agh_conf = $agh_dir . '/AdGuardHome.yaml';
$agh_url = 'https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh';

$admin_user = trim(getenv('ADMIN_USER'));
$admin_pass = trim(getenv('ADMIN_PASS'));
$dns_port = trim(getenv('DNS_PORT'));
$web_port = trim(getenv('WEB_PORT'));
$web_host = trim(getenv('WEB_HOST'));
$bind_hosts = trim(getenv('BIND_HOSTS'));
$upstreams = trim(getenv('UPSTREAM_DNS'));
$bootstraps = trim(getenv('BOOTSTRAP_DNS'));

if ($dns_port === '' || !is_numeric($dns_port)) {
    $dns_port = '5353';
}
if ($web_port === '' || !is_numeric($web_port)) {
    $web_port = '3000';
}
$dns_port = preg_replace('/\\D/', '', $dns_port);
$web_port = preg_replace('/\\D/', '', $web_port);
if ($web_host === '') {
    $web_host = '0.0.0.0';
}
if ($bind_hosts === '') {
    $bind_hosts = '0.0.0.0';
}
if ($upstreams === '') {
    $upstreams = '127.0.0.1:53';
}
if ($bootstraps === '') {
    $bootstraps = '1.1.1.1,8.8.8.8';
}

function run_cmd($cmd, &$code = null) {
    $output = array();
    $rc = 0;
    exec($cmd . ' 2>&1', $output, $rc);
    if (!is_null($code)) {
        $code = $rc;
    }
    return implode("\n", $output);
}

function ensure_config_exists($agh_dir, $agh_bin, $agh_conf) {
    if (file_exists($agh_conf)) {
        return true;
    }
    if (!file_exists($agh_bin)) {
        return false;
    }

    run_cmd('cd ' . escapeshellarg($agh_dir) . ' && ./AdGuardHome -s start');
    sleep(2);
    run_cmd('cd ' . escapeshellarg($agh_dir) . ' && ./AdGuardHome -s stop');

    return file_exists($agh_conf);
}

function get_indent($line) {
    if (preg_match('/^(\s*)/', $line, $matches)) {
        return strlen($matches[1]);
    }
    return 0;
}

function find_block_indices($lines, $key, $indent) {
    $start = -1;
    $end = -1;
    $pattern = '/^' . str_repeat(' ', $indent) . preg_quote($key, '/') . ':/';
    $count = count($lines);
    for ($i = 0; $i < $count; $i++) {
        if (preg_match($pattern, $lines[$i])) {
            $start = $i;
            $end = $i + 1;
            for ($j = $i + 1; $j < $count; $j++) {
                $line = $lines[$j];
                if (trim($line) === '') {
                    $end = $j + 1;
                    continue;
                }
                $line_indent = get_indent($line);
                if ($line_indent <= $indent) {
                    $end = $j;
                    break;
                }
                $end = $j + 1;
            }
            break;
        }
    }
    return array($start, $end);
}

function set_top_level(&$lines, $key, $value) {
    $pattern = '/^' . preg_quote($key, '/') . ':/';
    $count = count($lines);
    for ($i = 0; $i < $count; $i++) {
        if (preg_match($pattern, $lines[$i])) {
            $lines[$i] = $key . ': ' . $value;
            return;
        }
    }
    $lines[] = $key . ': ' . $value;
}

function set_scalar_in_block(&$block, $key, $value) {
    $pattern = '/^\s{2}' . preg_quote($key, '/') . ':/';
    $count = count($block);
    for ($i = 0; $i < $count; $i++) {
        if (preg_match($pattern, $block[$i])) {
            $block[$i] = '  ' . $key . ': ' . $value;
            return;
        }
    }
    array_splice($block, 1, 0, '  ' . $key . ': ' . $value);
}

function set_list_in_block(&$block, $key, $values) {
    $pattern = '/^\s{2}' . preg_quote($key, '/') . ':/';
    $count = count($block);
    $start = -1;
    $end = -1;
    for ($i = 0; $i < $count; $i++) {
        if (preg_match($pattern, $block[$i])) {
            $start = $i;
            $end = $i + 1;
            for ($j = $i + 1; $j < $count; $j++) {
                if (trim($block[$j]) === '') {
                    $end = $j + 1;
                    continue;
                }
                $indent = get_indent($block[$j]);
                if ($indent <= 2) {
                    $end = $j;
                    break;
                }
                $end = $j + 1;
            }
            break;
        }
    }

    $new_block = array('  ' . $key . ':');
    foreach ($values as $val) {
        if ($val === '') {
            continue;
        }
        $new_block[] = '    - ' . $val;
    }

    if ($start >= 0) {
        array_splice($block, $start, $end - $start, $new_block);
    } else {
        array_splice($block, 1, 0, $new_block);
    }
}

function update_dns_block(&$lines, $dns_port, $bind_hosts, $upstreams, $bootstraps) {
    list($start, $end) = find_block_indices($lines, 'dns', 0);
    $bind_list = array_filter(array_map('trim', explode(',', $bind_hosts)));
    $upstream_list = array_filter(array_map('trim', explode(',', $upstreams)));
    $bootstrap_list = array_filter(array_map('trim', explode(',', $bootstraps)));

    if ($start < 0) {
        $block = array('dns:');
    } else {
        $block = array_slice($lines, $start, $end - $start);
    }

    set_scalar_in_block($block, 'port', $dns_port);
    set_list_in_block($block, 'bind_hosts', $bind_list);
    set_list_in_block($block, 'upstream_dns', $upstream_list);
    set_list_in_block($block, 'bootstrap_dns', $bootstrap_list);

    if ($start < 0) {
        $lines[] = '';
        $lines = array_merge($lines, $block);
    } else {
        array_splice($lines, $start, $end - $start, $block);
    }
}

function update_http_block(&$lines, $web_host, $web_port) {
    list($start, $end) = find_block_indices($lines, 'http', 0);
    $address = $web_host . ':' . $web_port;

    if ($start < 0) {
        $block = array('http:', '  address: ' . $address);
        $lines[] = '';
        $lines = array_merge($lines, $block);
        return;
    }

    $block = array_slice($lines, $start, $end - $start);
    set_scalar_in_block($block, 'address', $address);
    array_splice($lines, $start, $end - $start, $block);
}

function update_users_block(&$lines, $admin_user, $admin_pass) {
    if ($admin_user === '' || $admin_pass === '') {
        return;
    }
    $hash = password_hash($admin_pass, PASSWORD_BCRYPT);
    if ($hash === false) {
        return;
    }
    $block = array(
        'users:',
        '  - name: ' . $admin_user,
        '    password: ' . $hash,
    );

    list($start, $end) = find_block_indices($lines, 'users', 0);
    if ($start < 0) {
        $lines[] = '';
        $lines = array_merge($lines, $block);
    } else {
        array_splice($lines, $start, $end - $start, $block);
    }
}

function configure_adguard($agh_dir, $agh_bin, $agh_conf, $admin_user, $admin_pass, $dns_port, $web_host, $web_port, $bind_hosts, $upstreams, $bootstraps) {
    if (!file_exists($agh_bin)) {
        return 'ERROR:ADGUARD_NOT_INSTALLED';
    }

    run_cmd('cd ' . escapeshellarg($agh_dir) . ' && ./AdGuardHome -s stop');

    if (!ensure_config_exists($agh_dir, $agh_bin, $agh_conf)) {
        return 'ERROR:CONFIG_NOT_FOUND';
    }

    $lines = file($agh_conf, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return 'ERROR:READ_CONFIG_FAILED';
    }

    update_dns_block($lines, $dns_port, $bind_hosts, $upstreams, $bootstraps);
    update_http_block($lines, $web_host, $web_port);
    set_top_level($lines, 'bind_host', $web_host);
    set_top_level($lines, 'bind_port', $web_port);
    update_users_block($lines, $admin_user, $admin_pass);

    $written = file_put_contents($agh_conf, implode("\n", $lines) . "\n");
    if ($written === false) {
        return 'ERROR:WRITE_CONFIG_FAILED';
    }

    run_cmd('cd ' . escapeshellarg($agh_dir) . ' && ./AdGuardHome -s start');

    return 'SUCCESS';
}

if ($action === 'install') {
    if (!is_dir($agh_dir) || !file_exists($agh_bin) || $reinstall) {
        $flag = $reinstall ? '-r' : '';
        $cmd = "fetch -o - " . escapeshellarg($agh_url) . " | sh -s -- -v -o /usr/local " . $flag;
        $output = run_cmd($cmd, $rc);
        if ($rc !== 0) {
            echo "ERROR:INSTALL_FAILED\n" . $output;
            exit;
        }
    }

    $result = configure_adguard($agh_dir, $agh_bin, $agh_conf, $admin_user, $admin_pass, $dns_port, $web_host, $web_port, $bind_hosts, $upstreams, $bootstraps);
    if ($result !== 'SUCCESS') {
        echo $result;
        exit;
    }

    echo "SUCCESS";
    exit;
}

if ($action === 'configure') {
    $result = configure_adguard($agh_dir, $agh_bin, $agh_conf, $admin_user, $admin_pass, $dns_port, $web_host, $web_port, $bind_hosts, $upstreams, $bootstraps);
    echo $result;
    exit;
}

if ($action === 'verify') {
    $report = array();
    $report[] = "Binary: " . (file_exists($agh_bin) ? "OK ($agh_bin)" : "MISSING");
    $report[] = "Config: " . (file_exists($agh_conf) ? "OK ($agh_conf)" : "MISSING");

    if (file_exists($agh_bin)) {
        $status = run_cmd('cd ' . escapeshellarg($agh_dir) . ' && ./AdGuardHome -s status');
        $report[] = "Service status: " . trim($status);
    }

    $dns_check = run_cmd("sockstat -4 -l | grep -E ':{$dns_port}[[:space:]]' | head -5");
    if ($dns_check !== '') {
        $report[] = "DNS listen (IPv4):\n" . $dns_check;
    } else {
        $report[] = "DNS listen (IPv4): Not detected";
    }

    $web_check = run_cmd("sockstat -4 -l | grep -E ':{$web_port}[[:space:]]' | head -5");
    if ($web_check !== '') {
        $report[] = "Web listen (IPv4):\n" . $web_check;
    } else {
        $report[] = "Web listen (IPv4): Not detected";
    }

    echo implode("\n\n", $report);
    exit;
}

if ($action === 'debug') {
    $log = run_cmd("clog /var/log/system.log | grep -i adguard | tail -50");
    if ($log === '') {
        $log = run_cmd("tail -50 /var/log/system.log | grep -i adguard");
    }
    if ($log === '') {
        $log = "No AdGuard log entries found.";
    }
    echo $log;
    exit;
}

if ($action === 'restart') {
    if (!file_exists($agh_bin)) {
        echo "ERROR:ADGUARD_NOT_INSTALLED";
        exit;
    }
    $output = run_cmd('cd ' . escapeshellarg($agh_dir) . ' && ./AdGuardHome -s restart', $rc);
    if ($rc !== 0) {
        echo "ERROR:RESTART_FAILED\n" . $output;
        exit;
    }
    echo "SUCCESS";
    exit;
}

echo "ERROR:INVALID_ACTION";
?>
