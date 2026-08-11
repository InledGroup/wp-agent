<?php
/**
 * Uninstall de WP-Agent: elimina opciones y la tabla de logs.
 *
 * @package WP-Agent
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

delete_option( 'wpa_keys' );
delete_option( 'wpa_panic' );
delete_option( 'wpa_exec_whitelist' );

$table = $wpdb->prefix . 'wpa_logs';
$wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
