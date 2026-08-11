<?php
/**
 * Ejecución de comandos wp-cli / WordPress de forma segura.
 *
 * @package WP-Agent
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Valida y ejecuta comandos contra una whitelist.
 *
 * El agente envía un comando estilo wp-cli ("wp option get blogname" o
 * "option get blogname"). Se comprueba contra la whitelist configurable y se
 * ejecuta con escapeshellarg en el binario wp del servidor si existe.
 */
class WPAgent_Exec {

	/**
	 * Whitelist por defecto (primer comando de la línea).
	 *
	 * @return array
	 */
	public static function default_whitelist() {
		return array(
			'option list',
			'option get',
			'option update',
			'option delete',
			'post list',
			'post get',
			'post update',
			'post delete',
			'post meta list',
			'post meta get',
			'post meta update',
			'user list',
			'user get',
			'plugin list',
			'plugin status',
			'theme list',
			'theme status',
			'cache flush',
			'core check-update',
			'core version',
			'db check',
			'db size',
			'search-replace --dry-run',
			'plugin update',
			'plugin activate',
			'plugin deactivate',
			'transient delete',
			'cron event list',
			'cron event run',
		);
	}

	/**
	 * Whitelist activa.
	 *
	 * @return array
	 */
	public static function whitelist() {
		$list = get_option( WPA_OPTION_WHITELIST, self::default_whitelist() );
		if ( ! is_array( $list ) ) {
			$list = self::default_whitelist();
		}
		$list = array_values( array_filter( array_map( 'trim', $list ) ) );
		return apply_filters( 'wpa_exec_whitelist', $list );
	}

	/**
	 * Whether the global whitelist is enabled.
	 *
	 * @return bool
	 */
	public static function whitelist_enabled() {
		return (bool) get_option( WPA_OPTION_WHITELIST_ENABLED, 1 );
	}

	/**
	 * Blacklist global de comandos (se aplica siempre, antes que la whitelist).
	 *
	 * @return array
	 */
	public static function blacklist() {
		$list = get_option( WPA_OPTION_BLACKLIST, array() );
		if ( ! is_array( $list ) ) {
			$list = array();
		}
		$list = array_values( array_filter( array_map( 'trim', $list ) ) );
		return apply_filters( 'wpa_exec_blacklist', $list );
	}

	/**
	 * Whitelist efectiva para una clave (o null si no hay restricción).
	 *
	 * Reglas:
	 * - Con override activado, la whitelist del token reemplaza a la global.
	 *   Si la whitelist del token está deshabilitada => null (sin restricción).
	 *   Si está habilitada pero vacía => array() (bloquear todo).
	 * - Sin override, se unen la global (si está habilitada) y la del token
	 *   (si está habilitada).
	 *
	 * @param array|null $key Clave normalizada, o null para usar solo la global.
	 * @return array|null
	 */
	public static function whitelist_for_key( $key = null ) {
		$global = self::whitelist_enabled() ? self::whitelist() : array();

		if ( empty( $key ) ) {
			return $global;
		}

		$key       = WPAgent_Keys::normalize( $key );
		$wl_enabled = ! empty( $key['wl_enabled'] );
		$token_wl   = is_array( $key['whitelist'] ) ? $key['whitelist'] : array();

		if ( ! empty( $key['override'] ) ) {
			if ( ! $wl_enabled ) {
				return null;
			}
			return $token_wl;
		}

		if ( $wl_enabled && ! empty( $token_wl ) ) {
			return array_values( array_unique( array_merge( $global, $token_wl ) ) );
		}

		return $global;
	}

	/**
	 * Blacklist efectiva para una clave.
	 *
	 * Con override activado la blacklist del token reemplaza a la global;
	 * sin override se unen ambas.
	 *
	 * @param array|null $key Clave normalizada, o null para usar solo la global.
	 * @return array
	 */
	public static function blacklist_for_key( $key = null ) {
		$global = self::blacklist();

		if ( empty( $key ) ) {
			return $global;
		}

		$key      = WPAgent_Keys::normalize( $key );
		$token_bl = is_array( $key['blacklist'] ) ? $key['blacklist'] : array();

		if ( ! empty( $key['override'] ) ) {
			return $token_bl;
		}

		return array_values( array_unique( array_merge( $global, $token_bl ) ) );
	}

	/**
	 * Comprueba si un comando coincide con alguna entrada de una lista
	 * (por palabras completas: la entrada debe ser prefijo del comando).
	 *
	 * @param string $command Comando normalizado.
	 * @param array  $list    Lista de entradas.
	 * @return bool
	 */
	protected static function matches_list( $command, $list ) {
		foreach ( (array) $list as $entry ) {
			$entry = trim( (string) $entry );
			if ( '' === $entry ) {
				continue;
			}
			if ( $command === $entry || 0 === strpos( $command, $entry . ' ' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Comprueba si un comando está en la blacklist efectiva de una clave.
	 *
	 * @param string     $command Comando normalizado, sin el "wp".
	 * @param array|null $key     Clave normalizada.
	 * @return bool
	 */
	public static function is_blacklisted( $command, $key = null ) {
		$command = trim( (string) $command );
		if ( '' === $command ) {
			return false;
		}
		return self::matches_list( $command, self::blacklist_for_key( $key ) );
	}

	/**
	 * Comprueba si un comando (normalizado) está permitido para una clave.
	 *
	 * @param string     $command Comando normalizado, sin el "wp".
	 * @param array|null $key     Clave normalizada.
	 * @return bool
	 */
	public static function is_allowed( $command, $key = null ) {
		$command = trim( (string) $command );
		if ( '' === $command ) {
			return false;
		}

		$whitelist = self::whitelist_for_key( $key );
		if ( null === $whitelist ) {
			// Whitelist deshabilitada para esta clave: solo aplica la blacklist.
			return ! self::is_blacklisted( $command, $key );
		}

		if ( self::is_blacklisted( $command, $key ) ) {
			return false;
		}

		return self::matches_list( $command, $whitelist );
	}

	/**
	 * Localiza el binario de wp-cli en el servidor.
	 *
	 * @return string|null
	 */
	public static function wp_binary() {
		$candidates = array(
			'wp',
			'/usr/local/bin/wp',
			'/usr/bin/wp',
			'/opt/wp-cli/bin/wp',
			'WP_PATH_OVERRIDE',
		);

		$override = apply_filters( 'wpa_wp_binary', '' );
		if ( '' !== $override && is_string( $override ) && trim( $override ) !== '' ) {
			return trim( $override );
		}

		foreach ( $candidates as $candidate ) {
			if ( 'WP_PATH_OVERRIDE' === $candidate ) {
				continue;
			}
			if ( self::command_exists( $candidate ) ) {
				return $candidate;
			}
		}
		return null;
	}

	/**
	 * Comprueba si un comando existe en el sistema.
	 *
	 * @param string $command Nombre del binario.
	 * @return bool
	 */
	protected static function command_exists( $command ) {
		if ( false === strpos( $command, '/' ) ) {
			$found = @shell_exec( 'command -v ' . escapeshellarg( $command ) . ' 2>/dev/null' ); // phpcs:ignore
			return is_string( $found ) && trim( $found ) !== '';
		}
		return is_file( $command ) && is_executable( $command );
	}

	/**
	 * Ejecuta un comando permitido y devuelve la salida.
	 *
	 * @param string     $command Comando estilo wp-cli, con o sin el prefijo "wp".
	 * @param int        $timeout Timeout en segundos.
	 * @param array|null $key     Clave normalizada (para sus listas de comandos).
	 * @return array {success, output, command}
	 */
	public static function run( $command, $timeout = 60, $key = null ) {
		$command = self::normalize( $command );

		if ( '' === $command ) {
			return array(
				'success' => false,
				'output'  => 'Empty command.',
				'command' => '',
			);
		}

		if ( ! self::is_allowed( $command, $key ) ) {
			return array(
				'success' => false,
				'output'  => 'Command not allowed: ' . $command,
				'command' => $command,
			);
		}

		$binary = self::wp_binary();
		if ( null === $binary ) {
			return array(
				'success' => false,
				'output'  => 'wp-cli is not available on this server.',
				'command' => $command,
			);
		}

		$timeout = max( 1, min( (int) $timeout, 300 ) );
		$args    = $command;

		$cmd = escapeshellarg( $binary )
			. ' --path=' . escapeshellarg( ABSPATH )
			. ' --allow-root --quiet ' . $args;

		$output = array();
		$code   = 1;
		exec( $cmd . ' 2>&1', $output, $code ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.system_calls_exec, WordPress.Security.EscapeOutput

		return array(
			'success' => 0 === $code,
			'output'  => implode( "\n", $output ),
			'command' => $command,
			'exit'    => $code,
		);
	}

	/**
	 * Normaliza el comando: quita prefijo "wp", recorta espacios y controles.
	 *
	 * @param string $command Comando bruto.
	 * @return string
	 */
	public static function normalize( $command ) {
		$command = is_string( $command ) ? $command : '';
		$command = trim( $command );
		$command = preg_replace( '/[\x00-\x1F\x7F]+/', ' ', $command );
		$command = preg_replace( '/\s{2,}/', ' ', $command );
		$command = trim( $command );

		// Acepta tanto "wp option get x" como "option get x".
		if ( 0 === strpos( $command, 'wp ' ) ) {
			$command = substr( $command, 3 );
			$command = trim( $command );
		}

		return $command;
	}

	/**
	 * Resultado formateado para la API.
	 *
	 * @param array $result Resultado de run().
	 * @return WP_REST_Response
	 */
	public static function response( $result ) {
		$status = ! empty( $result['success'] ) ? 200 : 400;
		return new WP_REST_Response(
			array(
				'success' => ! empty( $result['success'] ),
				'command' => isset( $result['command'] ) ? $result['command'] : '',
				'output'  => isset( $result['output'] ) ? $result['output'] : '',
				'exit'    => isset( $result['exit'] ) ? $result['exit'] : null,
			),
			$status
		);
	}
}
