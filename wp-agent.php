<?php
/**
 * Plugin Name: WP-Agent
 * Plugin URI:  https://inled.es/wp-agent
 * Description: Gives AI agents secure access to your WordPress via API keys. Manage named keys, log every access and action, and cut access instantly with a reversible panic button.
 * Version:     1.0.0
 * Author:      Inled Group
 * Author URI:  https://inled.es
 * License:     GPL-2.0-or-later
 * Text Domain: wp-agent
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPA_VERSION', '1.0.0' );
define( 'WPA_PLUGIN_FILE', __FILE__ );
define( 'WPA_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPA_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WPA_OPTION_KEYS', 'wpa_keys' );
define( 'WPA_OPTION_PANIC', 'wpa_panic' );
define( 'WPA_OPTION_PERMS', 'wpa_perms' );
define( 'WPA_OPTION_WHITELIST', 'wpa_exec_whitelist' );
define( 'WPA_OPTION_BLACKLIST', 'wpa_exec_blacklist' );
define( 'WPA_LOG_TABLE', 'wpa_logs' );
define( 'WPA_API_NS', 'wp-agent/v1' );

require_once WPA_PLUGIN_DIR . 'includes/class-wp-agent-logger.php';
require_once WPA_PLUGIN_DIR . 'includes/class-wp-agent-keys.php';
require_once WPA_PLUGIN_DIR . 'includes/class-wp-agent-exec.php';
require_once WPA_PLUGIN_DIR . 'includes/class-wp-agent-api.php';
require_once WPA_PLUGIN_DIR . 'includes/class-wp-agent-admin.php';

register_activation_hook( __FILE__, 'wpa_activate' );
function wpa_activate() {
	WPAgent_Logger::maybe_create_table();
	add_option( 'wpa_table_ready', 1 );
	add_option( WPA_OPTION_KEYS, array() );
	add_option( WPA_OPTION_PANIC, 0 );
	add_option( WPA_OPTION_PERMS, array( 'read' => 1, 'exec' => 0 ) );
	add_option( WPA_OPTION_WHITELIST, WPAgent_Exec::default_whitelist() );
	add_option( WPA_OPTION_BLACKLIST, array() );
}

add_action( 'plugins_loaded', 'wpa_plugins_loaded' );
function wpa_plugins_loaded() {
	WPAgent_Logger::init();
	WPAgent_Keys::init();
	WPAgent_Api::init();
	WPAgent_Admin::init();
}
