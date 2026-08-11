<?php
/**
 * API key management for WP-Agent.
 *
 * @package WP-Agent
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Creates, revokes and validates named API keys.
 *
 * Only the key hash is stored (wp_hash_password), never the plaintext key.
 */
class WPAgent_Keys {

	const PERMS = array( 'read', 'exec' );

	/**
	 * Initializes key management.
	 */
	public static function init() {
	}

	/**
	 * Returns all keys.
	 *
	 * @return array
	 */
	public static function all() {
		$keys = get_option( WPA_OPTION_KEYS, array() );
		return is_array( $keys ) ? $keys : array();
	}

	/**
	 * Returns a single key by id (with normalized fields).
	 *
	 * @param string $id Key id.
	 * @return array|null
	 */
	public static function get( $id ) {
		foreach ( self::all() as $key ) {
			if ( isset( $key['id'] ) && $key['id'] === $id ) {
				return self::normalize( $key );
			}
		}
		return null;
	}

	/**
	 * Generates a new key and stores only its hash.
	 *
	 * @param string $name Agent name.
	 * @return array {id, name, key} where key is shown only once.
	 */
	public static function create( $name ) {
		$name = sanitize_text_field( $name );
		if ( '' === $name ) {
			$name = __( 'Unnamed agent', 'wp-agent' );
		}

		$plain = 'wpa_' . wp_generate_password( 40, false, false );

		$keys   = self::all();
		$record = array(
			'id'        => wp_generate_uuid4(),
			'name'      => $name,
			'hash'      => wp_hash_password( $plain ),
			'status'    => 'active',
			'perms'     => array(
				'read' => 1,
				'exec' => 0,
			),
			'override'  => 0,
			'whitelist' => array(),
			'wl_enabled'=> 1,
			'blacklist' => array(),
			'created'   => current_time( 'mysql' ),
			'last_used' => '',
		);
		$keys[] = $record;
		update_option( WPA_OPTION_KEYS, $keys );

		return array(
			'id'   => $record['id'],
			'name' => $name,
			'key'  => $plain,
		);
	}

	/**
	 * Revokes a key (kept for history).
	 *
	 * @param string $id Key id.
	 * @return bool
	 */
	public static function revoke( $id ) {
		$keys = self::all();
		$done = false;
		foreach ( $keys as &$key ) {
			if ( isset( $key['id'] ) && $key['id'] === $id ) {
				$key['status'] = 'revoked';
				$done          = true;
			}
		}
		unset( $key );
		if ( $done ) {
			update_option( WPA_OPTION_KEYS, $keys );
		}
		return $done;
	}

	/**
	 * Reactivates a revoked key.
	 *
	 * @param string $id Key id.
	 * @return bool
	 */
	public static function reactivate( $id ) {
		$keys = self::all();
		$done = false;
		foreach ( $keys as &$key ) {
			if ( isset( $key['id'] ) && $key['id'] === $id ) {
				$key['status'] = 'active';
				$done          = true;
			}
		}
		unset( $key );
		if ( $done ) {
			update_option( WPA_OPTION_KEYS, $keys );
		}
		return $done;
	}

	/**
	 * Permanently deletes a key.
	 *
	 * @param string $id Key id.
	 * @return bool
	 */
	public static function delete( $id ) {
		$keys = self::all();
		$keys = array_values( array_filter(
			$keys,
			static function ( $key ) use ( $id ) {
				return ! ( isset( $key['id'] ) && $key['id'] === $id );
			}
		) );
		update_option( WPA_OPTION_KEYS, $keys );
		return true;
	}

	/**
	 * Sets the per-token permissions.
	 *
	 * @param string $id    Key id.
	 * @param array  $perms Permission map (read/exec booleans).
	 * @return bool
	 */
	public static function set_perms( $id, $perms ) {
		$keys = self::all();
		$done = false;
		foreach ( $keys as &$key ) {
			if ( isset( $key['id'] ) && $key['id'] === $id ) {
				$key['perms'] = array(
					'read' => ! empty( $perms['read'] ) ? 1 : 0,
					'exec' => ! empty( $perms['exec'] ) ? 1 : 0,
				);
				$done         = true;
			}
		}
		unset( $key );
		if ( $done ) {
			update_option( WPA_OPTION_KEYS, $keys );
		}
		return $done;
	}

	/**
	 * Sets whether the token permissions override the global ones.
	 *
	 * @param string $id       Key id.
	 * @param bool   $override True to let token perms override global perms.
	 * @return bool
	 */
	public static function set_override( $id, $override ) {
		$keys = self::all();
		$done = false;
		foreach ( $keys as &$key ) {
			if ( isset( $key['id'] ) && $key['id'] === $id ) {
				$key['override'] = $override ? 1 : 0;
				$done            = true;
			}
		}
		unset( $key );
		if ( $done ) {
			update_option( WPA_OPTION_KEYS, $keys );
		}
		return $done;
	}

	/**
	 * Sets the per-token command whitelist and blacklist.
	 *
	 * @param string $id          Key id.
	 * @param array  $whitelist   Commands allowed for this token.
	 * @param array  $blacklist   Commands blocked for this token.
	 * @param bool   $wl_enabled  Whether the token whitelist is enabled.
	 * @return bool
	 */
	public static function set_lists( $id, $whitelist = array(), $blacklist = array(), $wl_enabled = true ) {
		$keys = self::all();
		$done = false;
		foreach ( $keys as &$key ) {
			if ( isset( $key['id'] ) && $key['id'] === $id ) {
				$key['whitelist']  = self::clean_lines( $whitelist );
				$key['blacklist']  = self::clean_lines( $blacklist );
				$key['wl_enabled'] = $wl_enabled ? 1 : 0;
				$done              = true;
			}
		}
		unset( $key );
		if ( $done ) {
			update_option( WPA_OPTION_KEYS, $keys );
		}
		return $done;
	}

	/**
	 * Normalizes raw lines into a trimmed, non-empty list.
	 *
	 * @param mixed $lines Raw value.
	 * @return array
	 */
	protected static function clean_lines( $lines ) {
		if ( is_array( $lines ) ) {
			$lines = implode( "\n", $lines );
		}
		$lines = (string) $lines;
		$lines = preg_split( '/\r?\n/', $lines );
		return array_values( array_filter( array_map( 'trim', $lines ), static function ( $l ) {
			return '' !== $l;
		} ) );
	}

	/**
	 * Validates a plaintext key against the stored hashes.
	 *
	 * @param string $plain Key received.
	 * @return array|null Normalized key record if valid and active.
	 */
	public static function validate( $plain ) {
		if ( ! is_string( $plain ) || '' === $plain ) {
			return null;
		}
		foreach ( self::all() as $key ) {
			if ( isset( $key['hash'], $key['status'] ) && 'active' === $key['status'] && wp_check_password( $plain, $key['hash'] ) ) {
				return self::normalize( $key );
			}
		}
		return null;
	}

	/**
	 * Marks a key as used.
	 *
	 * @param string $id Key id.
	 */
	public static function mark_used( $id ) {
		$keys = self::all();
		foreach ( $keys as &$key ) {
			if ( isset( $key['id'] ) && $key['id'] === $id ) {
				$key['last_used'] = current_time( 'mysql' );
			}
		}
		unset( $key );
		update_option( WPA_OPTION_KEYS, $keys );
	}

	/**
	 * Returns the global permissions.
	 *
	 * @return array {read: bool, exec: bool}
	 */
	public static function global_perms() {
		$defaults = array(
			'read' => 1,
			'exec' => 0,
		);
		$perms    = get_option( WPA_OPTION_PERMS, array() );
		$perms    = is_array( $perms ) ? array_merge( $defaults, $perms ) : $defaults;
		return array(
			'read' => ! empty( $perms['read'] ),
			'exec' => ! empty( $perms['exec'] ),
		);
	}

	/**
	 * Sets the global permissions.
	 *
	 * @param array $perms {read: bool, exec: bool}
	 */
	public static function set_global_perms( $perms ) {
		update_option(
			WPA_OPTION_PERMS,
			array(
				'read' => ! empty( $perms['read'] ) ? 1 : 0,
				'exec' => ! empty( $perms['exec'] ) ? 1 : 0,
			)
		);
	}

	/**
	 * Effective permission for a token and a given permission.
	 *
	 * If the token has "override" enabled, its own perms win.
	 * Otherwise both global and token perms must allow it.
	 *
	 * @param array  $key  Normalized key record.
	 * @param string $perm Permission key (read|exec).
	 * @return bool
	 */
	public static function permission( $key, $perm ) {
		$key = self::normalize( $key );
		if ( ! in_array( $perm, self::PERMS, true ) ) {
			return false;
		}

		$token = ! empty( $key['perms'][ $perm ] );

		if ( ! empty( $key['override'] ) ) {
			return $token;
		}

		$global = self::global_perms();
		return ! empty( $global[ $perm ] ) && $token;
	}

	/**
	 * Normalizes a key record with defaults for old records.
	 *
	 * @param array $key Raw key record.
	 * @return array
	 */
	protected static function normalize( $key ) {
		$defaults = array(
			'perms'      => array(
				'read' => 1,
				'exec' => 0,
			),
			'override'   => 0,
			'whitelist'  => array(),
			'wl_enabled' => 1,
			'blacklist'  => array(),
			'status'     => 'active',
		);
		$key       = array_merge( $defaults, $key );
		if ( ! is_array( $key['whitelist'] ) ) {
			$key['whitelist'] = array();
		}
		if ( ! is_array( $key['blacklist'] ) ) {
			$key['blacklist'] = array();
		}
		return $key;
	}
}
