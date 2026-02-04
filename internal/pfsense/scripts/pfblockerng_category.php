<?php
/**
 * NetShim pfBlockerNG Category Management Script
 *
 * Manages web filtering categories via pfBlockerNG-devel DNSBL groups.
 * Called by Go application with CLI arguments or environment variable.
 *
 * Usage:
 *   CLI:  php pfblockerng_category.php [action] [category] [state]
 *   ENV:  NETSHIM_PAYLOAD='{"action":"set","category":"Gambling","state":"on"}'
 *
 * Actions:
 *   set [category] [on|off] - Enable/disable a specific category
 *   get all                 - Get status of all categories
 */

error_reporting(0);

// =============================================================================
// CATEGORY DEFINITIONS
// =============================================================================

define('NETSHIM_CATEGORIES', array(
    'Vietnam_Filter' => array(
        'url'   => 'https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts',
        'descr' => 'Vietnamese ads and tracking domains'
    ),
    'Fake_News' => array(
        'url'   => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-only/hosts',
        'descr' => 'Fake news and misinformation sites'
    ),
    'Gambling' => array(
        'url'   => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts',
        'descr' => 'Gambling and betting websites'
    ),
    'Porn_Adult' => array(
        'url'   => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts',
        'descr' => 'Adult and pornographic content'
    ),
    'Social_Media' => array(
        'url'   => 'https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social-only/hosts',
        'descr' => 'Social media platforms'
    ),
    'Malware_Phishing' => array(
        'url'   => 'https://urlhaus.abuse.ch/downloads/hostfile/',
        'descr' => 'Malware and phishing domains'
    ),
    'Crypto_Mining' => array(
        'url'   => 'https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt',
        'descr' => 'Cryptocurrency mining scripts'
    )
));

define('NETSHIM_ALIAS_PREFIX', 'NetShim_');
define('PFBLOCKERNG_DNSBL_DIR', '/var/db/pfblockerng/dnsbl/');
define('PFBLOCKERNG_UPDATE_SCRIPT', '/usr/local/www/pfblockerng/pfblockerng.php');

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Output JSON response and exit
 */
function json_response($data, $exit_code = 0) {
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit($exit_code);
}

/**
 * Output error response and exit
 */
function error_response($message, $code = 'ERROR') {
    json_response(array(
        'status'  => 'error',
        'code'    => $code,
        'message' => $message
    ), 1);
}

/**
 * Check if pfBlockerNG-devel is installed
 */
function check_pfblockerng_installed() {
    global $config;

    // Check if package is installed
    if (!file_exists(PFBLOCKERNG_UPDATE_SCRIPT)) {
        return false;
    }

    // Check if DNSBL is configured
    if (!isset($config['installedpackages']['pfblockerngdnsbl'])) {
        return false;
    }

    return true;
}

/**
 * Get the alias name for a category
 */
function get_alias_name($category_key) {
    return NETSHIM_ALIAS_PREFIX . $category_key;
}

/**
 * Find existing DNSBL group by alias name
 * Returns array with 'index' and 'config' or null if not found
 */
function find_dnsbl_group($alias_name) {
    global $config;

    if (!isset($config['installedpackages']['pfblockerngdnsbl']['config'])) {
        return null;
    }

    $groups = &$config['installedpackages']['pfblockerngdnsbl']['config'];

    // Handle single entry vs array
    if (!is_array($groups)) {
        return null;
    }

    // Check if it's a single associative array (only one group)
    if (isset($groups['aliasname'])) {
        if ($groups['aliasname'] === $alias_name) {
            return array('index' => 0, 'config' => $groups, 'is_single' => true);
        }
        return null;
    }

    // It's an indexed array of groups
    foreach ($groups as $idx => $group) {
        if (is_array($group) && isset($group['aliasname']) && $group['aliasname'] === $alias_name) {
            return array('index' => $idx, 'config' => $group, 'is_single' => false);
        }
    }

    return null;
}

/**
 * Create a new DNSBL group configuration
 */
function create_dnsbl_group($category_key, $category_info) {
    $alias_name = get_alias_name($category_key);

    return array(
        'aliasname'     => $alias_name,
        'description'   => $category_info['descr'],
        'action'        => 'Unbound',
        'cron'          => 'EveryDay',
        'logging'       => 'enabled',
        'order'         => 'default',
        'row' => array(
            array(
                'format'    => 'auto',
                'state'     => 'Enabled',
                'url'       => $category_info['url'],
                'header'    => $alias_name . '_Feed'
            )
        )
    );
}

/**
 * Get the last update time for a category
 */
function get_last_updated($category_key) {
    $alias_name = get_alias_name($category_key);

    // Check multiple possible file locations
    $possible_files = array(
        PFBLOCKERNG_DNSBL_DIR . $alias_name . '.txt',
        PFBLOCKERNG_DNSBL_DIR . strtolower($alias_name) . '.txt',
        PFBLOCKERNG_DNSBL_DIR . $alias_name . '_Feed.txt',
        '/var/db/pfblockerng/' . $alias_name . '.txt'
    );

    foreach ($possible_files as $file) {
        if (file_exists($file)) {
            $mtime = filemtime($file);
            if ($mtime !== false) {
                return date('Y-m-d H:i:s', $mtime);
            }
        }
    }

    return 'Never';
}

/**
 * Check if a category is enabled
 */
function is_category_enabled($category_key) {
    $alias_name = get_alias_name($category_key);
    $group = find_dnsbl_group($alias_name);

    if ($group === null) {
        return false;
    }

    // Check the action field - 'Unbound' means enabled, 'Disabled' means disabled
    $action = isset($group['config']['action']) ? $group['config']['action'] : '';
    return ($action === 'Unbound' || $action === 'Unbound_TLD');
}

/**
 * Execute pfBlockerNG update in background (non-blocking)
 */
function execute_pfblockerng_update_background() {
    if (!file_exists(PFBLOCKERNG_UPDATE_SCRIPT)) {
        return array('success' => false, 'message' => 'pfBlockerNG update script not found');
    }

    // Run the update command in background (non-blocking)
    // Using nohup and redirecting output to avoid blocking
    $cmd = 'nohup /usr/local/bin/php -q ' . escapeshellarg(PFBLOCKERNG_UPDATE_SCRIPT) . ' update > /dev/null 2>&1 &';
    exec($cmd);

    return array(
        'success' => true,
        'message' => 'Update started in background'
    );
}

// =============================================================================
// MAIN ACTIONS
// =============================================================================

/**
 * ACTION: set - Enable or disable a category
 */
function action_set($category_key, $state) {
    global $config;

    // Validate category
    $categories = NETSHIM_CATEGORIES;
    if (!isset($categories[$category_key])) {
        error_response("Unknown category: $category_key", 'INVALID_CATEGORY');
    }

    // Validate state
    $state = strtolower($state);
    if ($state !== 'on' && $state !== 'off') {
        error_response("Invalid state: $state (must be 'on' or 'off')", 'INVALID_STATE');
    }

    $alias_name = get_alias_name($category_key);
    $category_info = $categories[$category_key];

    // Initialize DNSBL config structure if needed
    if (!isset($config['installedpackages'])) {
        $config['installedpackages'] = array();
    }
    if (!isset($config['installedpackages']['pfblockerngdnsbl'])) {
        $config['installedpackages']['pfblockerngdnsbl'] = array();
    }
    if (!isset($config['installedpackages']['pfblockerngdnsbl']['config'])) {
        $config['installedpackages']['pfblockerngdnsbl']['config'] = array();
    }

    $groups = &$config['installedpackages']['pfblockerngdnsbl']['config'];

    // Ensure groups is an array
    if (!is_array($groups)) {
        $groups = array();
    }

    // Convert single entry to array format if needed
    if (isset($groups['aliasname'])) {
        $groups = array($groups);
    }

    // Find existing group
    $existing = find_dnsbl_group($alias_name);

    if ($state === 'on') {
        if ($existing !== null) {
            // Update existing group to enable
            if ($existing['is_single']) {
                $config['installedpackages']['pfblockerngdnsbl']['config']['action'] = 'Unbound';
            } else {
                $groups[$existing['index']]['action'] = 'Unbound';
            }
            $action_msg = 'enabled';
        } else {
            // Create new group
            $new_group = create_dnsbl_group($category_key, $category_info);
            $groups[] = $new_group;
            $action_msg = 'created and enabled';
        }
    } else {
        // state === 'off'
        if ($existing !== null) {
            // Disable existing group
            if ($existing['is_single']) {
                $config['installedpackages']['pfblockerngdnsbl']['config']['action'] = 'Disabled';
            } else {
                $groups[$existing['index']]['action'] = 'Disabled';
            }
            $action_msg = 'disabled';
        } else {
            // Nothing to disable
            json_response(array(
                'status'   => 'success',
                'message'  => "Category $category_key was not configured, nothing to disable",
                'category' => $category_key,
                'enabled'  => false
            ));
        }
    }

    // Reindex array to ensure clean numeric keys
    $config['installedpackages']['pfblockerngdnsbl']['config'] = array_values($groups);

    // Write config
    write_config("NetShim: Category $category_key $action_msg");

    syslog(LOG_INFO, "NetShim: pfBlockerNG category $category_key $action_msg");

    // Execute pfBlockerNG update in background (non-blocking)
    // This allows the UI to respond quickly while the update runs
    execute_pfblockerng_update_background();

    json_response(array(
        'status'   => 'success',
        'message'  => "Category $category_key $action_msg. pfBlockerNG sync started in background.",
        'category' => $category_key,
        'enabled'  => ($state === 'on')
    ));
}

/**
 * ACTION: get - Get status of all categories
 */
function action_get() {
    $categories = NETSHIM_CATEGORIES;
    $result = array();

    foreach ($categories as $key => $info) {
        $result[$key] = array(
            'enabled'      => is_category_enabled($key),
            'last_updated' => get_last_updated($key),
            'description'  => $info['descr'],
            'url'          => $info['url']
        );
    }

    json_response(array(
        'status'     => 'success',
        'categories' => $result
    ));
}

// =============================================================================
// MAIN EXECUTION
// =============================================================================

// Load pfSense libraries
require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");

// Check if pfBlockerNG is installed
if (!check_pfblockerng_installed()) {
    error_response(
        'pfBlockerNG-devel is not installed or DNSBL is not configured. ' .
        'Please install pfBlockerNG-devel from System > Package Manager and enable DNSBL.',
        'PFBLOCKERNG_NOT_INSTALLED'
    );
}

// Parse arguments - support both CLI args and environment variable
$action = null;
$category = null;
$state = null;

// Try environment variable first (for Go integration)
$payload = getenv('NETSHIM_PAYLOAD');
if ($payload) {
    $req = json_decode($payload, true);
    if ($req) {
        $action = isset($req['action']) ? $req['action'] : null;
        $category = isset($req['category']) ? $req['category'] : null;
        $state = isset($req['state']) ? $req['state'] : null;
    }
}

// Fall back to CLI arguments
if ($action === null && isset($argv[1])) {
    $action = $argv[1];
}
if ($category === null && isset($argv[2])) {
    $category = $argv[2];
}
if ($state === null && isset($argv[3])) {
    $state = $argv[3];
}

// Validate action
if (empty($action)) {
    error_response('No action specified. Usage: php pfblockerng_category.php [set|get] [category] [on|off]', 'NO_ACTION');
}

// Lock config during modifications
$lock_acquired = false;
if ($action === 'set') {
    $lock_acquired = lock('config', LOCK_EX);
}

try {
    switch (strtolower($action)) {
        case 'set':
            if (empty($category)) {
                error_response('Category is required for set action', 'MISSING_CATEGORY');
            }
            if (empty($state)) {
                error_response('State (on/off) is required for set action', 'MISSING_STATE');
            }
            action_set($category, $state);
            break;

        case 'get':
            action_get();
            break;

        default:
            error_response("Unknown action: $action. Valid actions: set, get", 'INVALID_ACTION');
    }
} finally {
    // Release lock if acquired
    if ($lock_acquired) {
        unlock('config');
    }
}
