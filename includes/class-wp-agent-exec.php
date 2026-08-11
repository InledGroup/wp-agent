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
	 * Comprueba si un comando está en la blacklist global.
	 *
	 * @param string $command Comando normalizado, sin el "wp".
	 * @return bool
	 */
	public static function is_blacklisted( $command ) {
		$command = trim( (string) $command );
		if ( '' === $command ) {
			return false;
		}
		foreach ( self::blacklist() as $blocked ) {
			$blocked = trim( (string) $blocked );
			if ( '' === $blocked ) {
				continue;
			}
			if ( $command === $blocked || 0 === strpos( $command, $blocked . ' ' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Comprueba si un comando (normalizado) está permitido por la whitelist.
	 *
	 * La coincidencia es por prefijo: el comando debe empezar por alguna
	 * entrada de la whitelist (se compara por palabras completas).
	 *
	 * @param string $command Comando normalizado, sin el "wp".
	 * @return bool
	 */
	public static function is_allowed( $command ) {
		$command = trim( (string) $command );
		if ( '' === $command ) {
			return false;
		}
		if ( self::is_blacklisted( $command ) ) {
			return false;
		}

		foreach ( self::whitelist() as $allowed ) {
			$allowed = trim( (string) $allowed );
			if ( '' === $allowed ) {
				continue;
			}
			// Coincidencia exacta o "comando subcomando" que empieza por la entrada.
			if ( $command === $allowed || 0 === strpos( $command, $allowed . ' ' ) ) {
				return true;
			}
		}
		return false;
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
	 * @param string $command Comando estilo wp-cli, con o sin el prefijo "wp".
	 * @param int    $timeout Timeout en segundos.
	 * @return array {success, output, command}
	 */
	public static function run( $command, $timeout = 60 ) {
		$command = self::normalize( $command );

		if ( '' === $command ) {
			return array(
				'success' => false,
				'output'  => 'Empty command.',
				'command' => '',
			);
		}

		if ( ! self::is_allowed( $command ) ) {
			return array(
				'success' => false,
				'output'  => 'Command not allowed by the whitelist: ' . $command,
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
