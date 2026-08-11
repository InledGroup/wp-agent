<?php
/**
 * Gestión de los logs de acceso del plugin WP-Agent.
 *
 * @package WP-Agent
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Registro de accesos y acciones en una tabla dedicada.
 */
class WPAgent_Logger {

	/**
	 * Initializes the logger and ensures the table exists.
	 */
	public static function init() {
		// Recreates the table if it was never created or was dropped.
		if ( ! get_option( 'wpa_table_ready' ) ) {
			self::maybe_create_table();
			update_option( 'wpa_table_ready', 1 );
		}
	}

	/**
	 * Devuelve el nombre real de la tabla de logs.
	 *
	 * @return string
	 */
	public static function table() {
		global $wpdb;
		return $wpdb->prefix . WPA_LOG_TABLE;
	}

	/**
	 * Crea (o actualiza) la tabla de logs con dbDelta.
	 */
	public static function maybe_create_table() {
		global $wpdb;

		$table   = self::table();
		$charset = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			key_name VARCHAR(191) NOT NULL DEFAULT '',
			key_id VARCHAR(191) NOT NULL DEFAULT '',
			action VARCHAR(191) NOT NULL DEFAULT '',
			method VARCHAR(10) NOT NULL DEFAULT 'GET',
			endpoint VARCHAR(255) NOT NULL DEFAULT '',
			status INT NOT NULL DEFAULT 200,
			ip VARCHAR(100) NOT NULL DEFAULT '',
			user_agent VARCHAR(255) NOT NULL DEFAULT '',
			details LONGTEXT NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY created_at (created_at),
			KEY key_name (key_name),
			KEY action (action)
		) {$charset};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	/**
	 * Añade una entrada al log.
	 *
	 * @param array $args Datos de la entrada.
	 * @return int|false
	 */
	public static function log( $args = array() ) {
		global $wpdb;

		$defaults = array(
			'key_name'   => '',
			'key_id'     => '',
			'action'     => '',
			'method'     => 'GET',
			'endpoint'   => '',
			'status'     => 200,
			'ip'         => self::client_ip(),
			'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 250 ) : '',
			'details'    => '',
			'created_at' => current_time( 'mysql' ),
		);

		$data = wp_parse_args( $args, $defaults );
		if ( is_array( $data['details'] ) ) {
			$data['details'] = wp_json_encode( $data['details'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES );
		}
		foreach ( $data as $k => $v ) {
			$data[ $k ] = is_string( $v ) ? sanitize_text_field( $v ) : $v;
		}

		$inserted = $wpdb->insert( self::table(), $data ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		self::prune();
		return $inserted;
	}

	/**
	 * Devuelve la IP real del cliente (con soporte para proxies simples).
	 *
	 * @return string
	 */
	public static function client_ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP' ) as $header ) {
			if ( ! empty( $_SERVER[ $header ] ) ) {
				$candidates = explode( ',', sanitize_text_field( wp_unslash( $_SERVER[ $header ] ) ) );
				$ip         = trim( $candidates[0] );
				break;
			}
		}
		return substr( $ip, 0, 100 );
	}

	/**
	 * Mantiene el log acotado (máximo de filas).
	 */
	protected static function prune() {
		global $wpdb;
		$table   = self::table();
		$max     = apply_filters( 'wpa_max_log_entries', 20000 );
		$count   = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		if ( $count > $max ) {
			$delete = $count - $max;
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} ORDER BY id ASC LIMIT %d", $delete ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		}
	}

	/**
	 * Logs agrupados por día (para el panel).
	 *
	 * @return array Lista de días con recuento.
	 */
	public static function get_days() {
		global $wpdb;
		$table = self::table();
		return $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			"SELECT DATE(created_at) AS day, COUNT(*) AS total FROM {$table} GROUP BY DATE(created_at) ORDER BY day DESC LIMIT 90"
		);
	}

	/**
	 * Logs de un día concreto.
	 *
	 * @param string $day Fecha en formato Y-m-d.
	 * @param int    $limit Número de entradas a devolver.
	 * @return array
	 */
	public static function get_day( $day, $limit = 1000 ) {
		global $wpdb;
		$table = self::table();
		$day   = sanitize_text_field( $day );
		return $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				"SELECT * FROM {$table} WHERE DATE(created_at) = %s ORDER BY id DESC LIMIT %d",
				$day,
				$limit
			)
		);
	}

	/**
	 * Borra los logs de un día concreto.
	 *
	 * @param string $day Fecha en formato Y-m-d.
	 * @return int Filas borradas.
	 */
	public static function delete_day( $day ) {
		global $wpdb;
		$table = self::table();
		$day   = sanitize_text_field( $day );
		return $wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE DATE(created_at) = %s", $day ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/**
	 * Borra todo el log.
	 *
	 * @return int Filas borradas.
	 */
	public static function clear_all() {
		global $wpdb;
		$table = self::table();
		return $wpdb->query( "TRUNCATE TABLE {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}
}
