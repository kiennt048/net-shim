<?php
error_reporting(0);
require_once("config.inc");
require_once("util.inc");
require_once("interfaces.inc");
require_once("filter.inc");
require_once("rrd.inc");
require_once("shaper.inc");

$config_file = '/cf/conf/config.xml';
$backup_file = '/cf/conf/config.xml.pre-restore.' . date('Y-m-d_H-i-s');

// Get the uploaded config content from environment
$new_config = getenv('NETSHIM_CONFIG_DATA');
if (empty($new_config)) {
    die("ERROR:NO_CONFIG_DATA");
}

// Validate XML structure
libxml_use_internal_errors(true);
$xml = simplexml_load_string($new_config);
if ($xml === false) {
    $errors = libxml_get_errors();
    libxml_clear_errors();
    die("ERROR:INVALID_XML - " . (isset($errors[0]) ? $errors[0]->message : "Parse failed"));
}

// Check if it looks like a pfSense config
if (!isset($xml->version) || !isset($xml->system)) {
    die("ERROR:NOT_PFSENSE_CONFIG - missing version or system section");
}

// Get current revision time for verification
$old_revision = isset($config['revision']['time']) ? $config['revision']['time'] : 0;

// Backup current config before restore
if (file_exists($config_file)) {
    if (!copy($config_file, $backup_file)) {
        syslog(LOG_WARNING, "NetShim: Failed to create backup before restore");
        die("ERROR:BACKUP_FAILED");
    }
    syslog(LOG_INFO, "NetShim: Created pre-restore backup at $backup_file");
}

// Write new config file
$bytes_written = file_put_contents($config_file, $new_config);
if ($bytes_written === false) {
    // Restore backup if write failed
    if (file_exists($backup_file)) {
        copy($backup_file, $config_file);
    }
    die("ERROR:WRITE_FAILED");
}

// Verify file was written correctly
$written_content = file_get_contents($config_file);
if ($written_content !== $new_config) {
    // Restore backup
    if (file_exists($backup_file)) {
        copy($backup_file, $config_file);
    }
    die("ERROR:WRITE_VERIFICATION_FAILED");
}

// Clear cached config and reload
if (function_exists('clear_cached_conf')) {
    clear_cached_conf();
}

// Parse the new config
$config = parse_config(true);
if (!$config) {
    // Restore backup on parse failure
    if (file_exists($backup_file)) {
        copy($backup_file, $config_file);
    }
    die("ERROR:PARSE_FAILED");
}

// ===================================================================
// ENSURE AUTOMATIC OUTBOUND NAT
// ===================================================================
if (!isset($config['nat'])) {
    $config['nat'] = array();
}
if (!isset($config['nat']['outbound'])) {
    $config['nat']['outbound'] = array();
}
$config['nat']['outbound']['mode'] = 'automatic';
syslog(LOG_INFO, "NetShim: Outbound NAT set to automatic mode");

// Write config to signal reload
write_config("NetShim: Configuration restored from backup file");

// Apply system configuration
syslog(LOG_INFO, "NetShim: Applying restored configuration...");

// Reconfigure all interfaces
if (function_exists('interfaces_configure')) {
    interfaces_configure();
}

// Reconfigure routing (gateways, static routes)
if (function_exists('system_routing_configure')) {
    system_routing_configure();
}

// Restart gateway monitoring (dpinger)
if (function_exists('setup_gateways_monitor')) {
    setup_gateways_monitor();
}

// Regenerate DNS resolver configuration
if (function_exists('system_resolvconf_generate')) {
    system_resolvconf_generate();
}

// Use filter_configure_sync() for complete filter reload including NAT
if (function_exists('filter_configure_sync')) {
    filter_configure_sync();
} elseif (function_exists('filter_configure')) {
    filter_configure();
}

// Sync to secondary if HA
if (function_exists('pfSense_handle_custom_code')) {
    pfSense_handle_custom_code("/usr/local/pkg/pfsense-pkg-haproxy/haproxy.inc");
}

syslog(LOG_INFO, "NetShim: Configuration restore completed successfully");

// Verify the new config was loaded by checking revision
$new_config_check = parse_config(true);
$new_revision = isset($new_config_check['revision']['time']) ? $new_config_check['revision']['time'] : 0;

// Return detailed success with verification
echo "SUCCESS:bytes_written=$bytes_written,old_rev=$old_revision,new_rev=$new_revision";
?>