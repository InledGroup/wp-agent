<?php
/**
 * API REST de WP-Agent.
 *
 * @package WP-Agent
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Expone endpoints REST protegidos por API key para agentes de IA.
 */
class WPAgent_Api {

	/**
	 * Inicializa la API REST.
	 */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	/**
	 * Registra las rutas REST.
	 */
	public static function register_routes() {
		$ns = WPA_API_NS;

		register_rest_route(
			$ns,
			'/me',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'me' ),
				'permission_callback' => array( __CLASS__, 'authorize' ),
			)
		);

		register_rest_route(
			$ns,
			'/content',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'content' ),
				'permission_callback' => array( __CLASS__, 'authorize_read' ),
				'args'                => array(
					'post_type' => array(
						'default'           => 'post',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'per_page'  => array(
						'default'           => 50,
						'sanitize_callback' => 'absint',
					),
					'page'      => array(
						'default'           => 1,
						'sanitize_callback' => 'absint',
					),
					'search'    => array(
						'default'           => '',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'tax'       => array(
						'default'           => '',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'term'      => array(
						'default'           => '',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		register_rest_route(
			$ns,
			'/content/(?P<id>\d+)',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'content_single' ),
				'permission_callback' => array( __CLASS__, 'authorize_read' ),
				'args'                => array(
					'id' => array(
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			$ns,
			'/types',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'types' ),
				'permission_callback' => array( __CLASS__, 'authorize_read' ),
			)
		);

		register_rest_route(
			$ns,
			'/taxonomies',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'taxonomies' ),
				'permission_callback' => array( __CLASS__, 'authorize_read' ),
				'args'                => array(
					'tax' => array(
						'default'           => '',
						'sanitize_callback' => 'sanitize_text_field',
					),
				),
			)
		);

		register_rest_route(
			$ns,
			'/search',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'search' ),
				'permission_callback' => array( __CLASS__, 'authorize_read' ),
				'args'                => array(
					'q'        => array(
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'per_page' => array(
						'default'           => 20,
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			$ns,
			'/exec',
			array(
				'methods'             => array( 'POST', 'GET' ),
				'callback'            => array( __CLASS__, 'exec' ),
				'permission_callback' => array( __CLASS__, 'authorize_exec' ),
				'args'                => array(
					'command' => array(
						'required'          => true,
						'sanitize_callback' => 'sanitize_text_field',
					),
					'timeout' => array(
						'default'           => 60,
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		// Documentation endpoint: requires a valid key but no specific permission,
		// so agents can always read it.
		register_rest_route(
			$ns,
			'/docs',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'docs' ),
				'permission_callback' => array( __CLASS__, 'authorize' ),
			)
		);
	}

	/**
	 * Valida la API key en la cabecera Authorization: Bearer <clave>.
	 *
	 * @param WP_REST_Request $request Petición REST.
	 * @return bool|WP_Error
	 */
	public static function authenticate( $request ) {
		$plain = self::bearer_key();

		// Pánico activo: se registra el intento y se corta el acceso a todos.
		if ( get_option( WPA_OPTION_PANIC, 0 ) ) {
			WPAgent_Logger::log(
				array(
					'action'   => 'auth',
					'method'   => $request->get_method(),
					'endpoint' => $request->get_route(),
					'status'   => 503,
					'details'  => array( 'reason' => 'panic' ),
				)
			);
			return new WP_Error(
				'wpa_panic',
				__( 'API access is temporarily disabled (panic mode).', 'wp-agent' ),
				array( 'status' => 503 )
			);
		}

		$key = WPAgent_Keys::validate( $plain );

		if ( ! $key ) {
			WPAgent_Logger::log(
				array(
					'action'   => 'auth',
					'method'   => $request->get_method(),
					'endpoint' => $request->get_route(),
					'status'   => 401,
					'details'  => array( 'reason' => 'invalid_key' ),
				)
			);
			return new WP_Error(
				'wpa_invalid_key',
				__( 'Invalid or revoked API key.', 'wp-agent' ),
				array( 'status' => 401 )
			);
		}

		WPAgent_Keys::mark_used( $key['id'] );

		// Registrar el acceso a la petición para los handlers.
		$request->set_param( 'wpa_key', $key );

		WPAgent_Logger::log(
			array(
				'key_name' => $key['name'],
				'key_id'   => $key['id'],
				'action'   => 'request',
				'method'   => $request->get_method(),
				'endpoint' => $request->get_route(),
				'status'   => 200,
				'details'  => $request->get_params(),
			)
		);

		return true;
	}

	/**
	 * Permission callback para endpoints de solo autenticación (/me, /docs).
	 *
	 * @param WP_REST_Request $request Petición REST.
	 * @return bool|WP_Error
	 */
	public static function authorize( $request ) {
		return self::authenticate( $request );
	}

	/**
	 * Permission callback para endpoints de lectura (requiere permiso read).
	 *
	 * @param WP_REST_Request $request Petición REST.
	 * @return bool|WP_Error
	 */
	public static function authorize_read( $request ) {
		$auth = self::authenticate( $request );
		if ( is_wp_error( $auth ) ) {
			return $auth;
		}

		$key = $request->get_param( 'wpa_key' );
		if ( ! WPAgent_Keys::permission( $key, 'read' ) ) {
			WPAgent_Logger::log(
				array(
					'key_name' => $key['name'],
					'key_id'   => $key['id'],
					'action'   => 'denied',
					'method'   => $request->get_method(),
					'endpoint' => $request->get_route(),
					'status'   => 403,
					'details'  => array( 'reason' => 'no_read_permission' ),
				)
			);
			return new WP_Error(
				'wpa_no_read',
				__( 'This API key does not have read permission.', 'wp-agent' ),
				array( 'status' => 403 )
			);
		}

		return true;
	}

	/**
	 * Extrae la clave del header Authorization: Bearer.
	 *
	 * @return string
	 */
	protected static function bearer_key() {		$header = '';
		if ( function_exists( 'getallheaders' ) ) {
			$headers = getallheaders();
			if ( isset( $headers['Authorization'] ) ) {
				$header = $headers['Authorization'];
			} elseif ( isset( $headers['authorization'] ) ) {
				$header = $headers['authorization'];
			}
		}
		if ( '' === $header && isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$header = sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
		}
		if ( preg_match( '/^Bearer\s+(.+)$/i', $header, $m ) ) {
			return trim( $m[1] );
		}
		return '';
	}

	/**
	 * GET /me — información del agente, el sitio y la clave usada.
	 *
	 * @param WP_REST_Request $request Petición.
	 * @return WP_REST_Response
	 */
	public static function me( $request ) {
		$key = $request->get_param( 'wpa_key' );

		return new WP_REST_Response(
			array(
				'agent'     => array(
					'id'     => $key['id'],
					'name'   => $key['name'],
					'exec'   => WPAgent_Keys::permission( $key, 'exec' ),
					'read'   => WPAgent_Keys::permission( $key, 'read' ),
					'status' => $key['status'],
				),
				'site'      => array(
					'name'    => get_bloginfo( 'name' ),
					'url'     => home_url( '/' ),
					'version' => get_bloginfo( 'version' ),
				),
				'endpoints' => array(
					'GET /wp-json/' . WPA_API_NS . '/docs',
					'GET /wp-json/' . WPA_API_NS . '/me',
					'GET /wp-json/' . WPA_API_NS . '/content?post_type=post',
					'GET /wp-json/' . WPA_API_NS . '/content/{id}',
					'GET /wp-json/' . WPA_API_NS . '/types',
					'GET /wp-json/' . WPA_API_NS . '/taxonomies?tax={taxonomy}',
					'GET /wp-json/' . WPA_API_NS . '/search?q={termino}',
					'POST /wp-json/' . WPA_API_NS . '/exec {"command":"option get blogname"}',
				),
			)
		);
	}

	/**
	 * GET /content — lists published content of any post type.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function content( $request ) {
		$post_type = $request->get_param( 'post_type' );
		$per_page  = (int) $request->get_param( 'per_page' );
		$page      = (int) $request->get_param( 'page' );

		$public = array_keys( self::public_post_types() );

		if ( '' === $post_type || 'all' === $post_type ) {
			$post_type = $public;
		} else {
			if ( ! in_array( $post_type, $public, true ) ) {
				return new WP_Error( 'wpa_invalid_post_type', __( 'Invalid or private post type.', 'wp-agent' ), array( 'status' => 400 ) );
			}
			$post_type = array( $post_type );
		}

		$args = array(
			'post_type'      => $post_type,
			'posts_per_page' => $per_page,
			'paged'          => $page,
			'post_status'    => 'publish',
		);

		$search = $request->get_param( 'search' );
		if ( '' !== $search ) {
			$args['s'] = $search;
		}

		$tax = $request->get_param( 'tax' );
		$term = $request->get_param( 'term' );
		if ( '' !== $tax && '' !== $term ) {
			if ( ! taxonomy_exists( $tax ) ) {
				return new WP_Error( 'wpa_invalid_taxonomy', __( 'Invalid taxonomy.', 'wp-agent' ), array( 'status' => 400 ) );
			}
			$args['tax_query'] = array(
				array(
					'taxonomy' => $tax,
					'field'    => 'slug',
					'terms'    => $term,
				),
			);
		}

		$query = new WP_Query( $args );
		$items = array();

		foreach ( $query->posts as $post ) {
			$items[] = self::content_item( $post );
		}

		return new WP_REST_Response(
			array(
				'total' => $query->found_posts,
				'pages' => $query->max_num_pages,
				'items' => $items,
			)
		);
	}

	/**
	 * GET /content/{id} — full detail of a single content item.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function content_single( $request ) {
		$post = get_post( (int) $request->get_param( 'id' ) );
		if ( ! $post || 'publish' !== $post->post_status || ! self::is_public_post_type( $post->post_type ) ) {
			return new WP_Error( 'wpa_not_found', __( 'Content not found.', 'wp-agent' ), array( 'status' => 404 ) );
		}
		return new WP_REST_Response( self::content_item( $post, true ) );
	}

	/**
	 * Serializes a post into a generic item.
	 *
	 * @param WP_Post $post Post object.
	 * @param bool    $full Whether to include content, meta and terms.
	 * @return array
	 */
	protected static function content_item( $post, $full = false ) {
		$item = array(
			'id'        => $post->ID,
			'type'      => $post->post_type,
			'title'     => get_the_title( $post ),
			'slug'      => $post->post_name,
			'excerpt'   => wp_strip_all_tags( get_the_excerpt( $post ) ),
			'date'      => $post->post_date,
			'updated'   => $post->post_modified,
			'permalink' => get_permalink( $post ),
		);

		if ( $full ) {
			$item['content'] = apply_filters( 'the_content', $post->post_content );

			$thumbnail = get_post_thumbnail_id( $post );
			$item['featured_image'] = $thumbnail ? wp_get_attachment_url( $thumbnail ) : '';

			$item['terms'] = array();
			$taxonomies   = get_object_taxonomies( $post->post_type, 'names' );
			foreach ( $taxonomies as $taxonomy ) {
				$terms = get_the_terms( $post, $taxonomy );
				if ( $terms && ! is_wp_error( $terms ) ) {
					$item['terms'][ $taxonomy ] = array_map(
						static function ( $t ) {
							return array(
								'id'   => $t->term_id,
								'name' => $t->name,
								'slug' => $t->slug,
							);
						},
						$terms
					);
				}
			}

			$item['meta'] = array();
			foreach ( get_post_meta( $post->ID ) as $key => $values ) {
				if ( 0 === strpos( $key, '_' ) ) {
					continue;
				}
				$item['meta'][ $key ] = array_map( 'maybe_unserialize', $values );
			}
		}

		return $item;
	}

	/**
	 * GET /types — lists registered public post types.
	 *
	 * @return WP_REST_Response
	 */
	public static function types() {
		$items = array();
		foreach ( self::public_post_types() as $name => $type ) {
			$items[] = array(
				'name'       => $name,
				'label'      => $type->labels->name,
				'singular'   => $type->labels->singular_name,
				'rest_base'  => $type->rest_base,
				'taxonomies' => get_object_taxonomies( $name, 'names' ),
			);
		}
		return new WP_REST_Response( $items );
	}

	/**
	 * GET /taxonomies — lists registered public taxonomies and their terms.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response|WP_Error
	 */
	public static function taxonomies( $request ) {
		$tax = $request->get_param( 'tax' );
		if ( '' !== $tax ) {
			if ( ! taxonomy_exists( $tax ) || ! is_taxonomy_viewable( $tax ) ) {
				return new WP_Error( 'wpa_invalid_taxonomy', __( 'Invalid taxonomy.', 'wp-agent' ), array( 'status' => 400 ) );
			}
			$taxonomies = array( $tax );
		} else {
			$taxonomies = array_keys( get_taxonomies( array( 'public' => true ), 'names' ) );
		}

		$items = array();
		foreach ( $taxonomies as $taxonomy ) {
			$object = get_taxonomy( $taxonomy );
			$entry  = array(
				'name'       => $taxonomy,
				'label'      => $object->labels->name,
				'types'      => $object->object_type,
				'terms'      => array(),
			);

			$terms = get_terms(
				array(
					'taxonomy'   => $taxonomy,
					'hide_empty' => false,
				)
			);
			foreach ( $terms as $term ) {
				if ( is_wp_error( $term ) ) {
					continue;
				}
				$entry['terms'][] = array(
					'id'    => $term->term_id,
					'name'  => $term->name,
					'slug'  => $term->slug,
					'count' => $term->count,
				);
			}

			$items[] = $entry;
		}

		return new WP_REST_Response( $items );
	}

	/**
	 * GET /search — searches across all public post types.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public static function search( $request ) {
		$q        = $request->get_param( 'q' );
		$per_page = (int) $request->get_param( 'per_page' );

		$args = array(
			'post_type'      => array_keys( self::public_post_types() ),
			'post_status'    => 'publish',
			's'              => $q,
			'posts_per_page' => $per_page,
		);

		$query = new WP_Query( $args );
		$items = array();

		foreach ( $query->posts as $post ) {
			$items[] = self::content_item( $post );
		}

		return new WP_REST_Response(
			array(
				'total' => $query->found_posts,
				'items' => $items,
			)
		);
	}

	/**
	 * Public (viewable) post types on this site.
	 *
	 * @return WP_Post_Type[]
	 */
	protected static function public_post_types() {
		$types = get_post_types( array( 'public' => true ), 'objects' );
		return $types ? $types : array();
	}

	/**
	 * Whether a post type is public and viewable.
	 *
	 * @param string $post_type Post type name.
	 * @return bool
	 */
	protected static function is_public_post_type( $post_type ) {
		return array_key_exists( $post_type, self::public_post_types() );
	}

	/**
	 * Permission callback para /exec: clave válida + permiso exec + whitelist.
	 *
	 * @param WP_REST_Request $request Petición REST.
	 * @return bool|WP_Error
	 */
	public static function authorize_exec( $request ) {
		$auth = self::authenticate( $request );
		if ( is_wp_error( $auth ) ) {
			return $auth;
		}

		$key = $request->get_param( 'wpa_key' );

		if ( ! WPAgent_Keys::permission( $key, 'exec' ) ) {
			WPAgent_Logger::log(
				array(
					'key_name' => isset( $key['name'] ) ? $key['name'] : '',
					'key_id'   => isset( $key['id'] ) ? $key['id'] : '',
					'action'   => 'exec_denied',
					'method'   => $request->get_method(),
					'endpoint' => $request->get_route(),
					'status'   => 403,
					'details'  => array( 'reason' => 'no_exec_permission' ),
				)
			);
			return new WP_Error(
				'wpa_no_exec',
				__( 'This API key does not have permission to run commands.', 'wp-agent' ),
				array( 'status' => 403 )
			);
		}

		// Comprobar whitelist/blacklist antes de autorizar.
		$command = WPAgent_Exec::normalize( $request->get_param( 'command' ) );
		if ( '' === $command || ! WPAgent_Exec::is_allowed( $command ) ) {
			WPAgent_Logger::log(
				array(
					'key_name' => isset( $key['name'] ) ? $key['name'] : '',
					'key_id'   => isset( $key['id'] ) ? $key['id'] : '',
					'action'   => 'exec_denied',
					'method'   => $request->get_method(),
					'endpoint' => $request->get_route(),
					'status'   => 403,
					'details'  => array( 'reason' => 'not_in_whitelist', 'command' => $command ),
				)
			);
			return new WP_Error(
				'wpa_command_not_allowed',
				sprintf( __( 'Command not allowed: %s', 'wp-agent' ), $command ),
				array( 'status' => 403 )
			);
		}

		return true;
	}

	/**
	 * POST /exec — ejecuta un comando wp-cli permitido.
	 *
	 * @param WP_REST_Request $request Petición.
	 * @return WP_REST_Response
	 */
	public static function exec( $request ) {
		$key     = $request->get_param( 'wpa_key' );
		$command = WPAgent_Exec::normalize( $request->get_param( 'command' ) );
		$timeout = (int) $request->get_param( 'timeout' );

		$result = WPAgent_Exec::run( $command, $timeout );

		WPAgent_Logger::log(
			array(
				'key_name' => isset( $key['name'] ) ? $key['name'] : '',
				'key_id'   => isset( $key['id'] ) ? $key['id'] : '',
				'action'   => 'exec',
				'method'   => $request->get_method(),
				'endpoint' => $request->get_route(),
				'status'   => ! empty( $result['success'] ) ? 200 : 400,
				'details'  => array(
					'command' => $command,
					'exit'    => isset( $result['exit'] ) ? $result['exit'] : null,
				),
			)
		);

		return WPAgent_Exec::response( $result );
	}

	/**
	 * GET /docs — documentación markdown de la API para agentes de IA.
	 *
	 * @param WP_REST_Request $request Petición.
	 * @return WP_REST_Response
	 */
	public static function docs( $request ) {
		$key  = $request->get_param( 'wpa_key' );
		$site = get_bloginfo( 'name' );

		$md  = "# WP-Agent API\n\n";
		$md .= sprintf( "Welcome to the WordPress site **%s** — managed via the WP-Agent plugin (by [Inled Group](https://inled.es)).\n\n", esc_html( $site ) );
		$md .= "This is the machine-readable documentation your AI agent should follow. Read it completely before making requests.\n\n";
		$md .= "## Authentication\n\n";
		$md .= "Every request must include your API key in the `Authorization` header:\n\n";
		$md .= "```\nAuthorization: Bearer wpa_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n```\n\n";
		$md .= sprintf( "Your key is **%s** (id `%s`).\n\n", esc_html( $key['name'] ), esc_html( $key['id'] ) );
		$md .= "## Base URL\n\n";
		$md .= sprintf( "```\n%s/wp-json/%s\n```\n\n", esc_url( home_url( '/' ) ), WPA_API_NS );

		$md .= "## Available permissions\n\n";
		$perms = WPAgent_Keys::permission( $key, 'read' );
		$exec  = WPAgent_Keys::permission( $key, 'exec' );
		$md .= sprintf( "- `read`: **%s** — access to `/content`, `/content/{id}`, `/types`, `/taxonomies` and `/search`.\n", $perms ? 'granted' : 'denied' );
		$md .= sprintf( "- `exec`: **%s** — ability to run wp-cli commands through `/exec`.\n", $exec ? 'granted' : 'denied' );
		$md .= "\n";

		$md .= "## Endpoints\n\n";
		$md .= "### `GET /me`\n\n";
		$md .= "Returns information about the current agent and site.\n\n";
		$md .= "```\ncurl -H \"Authorization: Bearer wpa_...\" \"" . esc_url( home_url( '/' ) ) . "wp-json/" . WPA_API_NS . "/me\"\n```\n\n";

		$md .= "### `GET /docs`\n\n";
		$md .= "Returns this documentation.\n\n";

		$md .= "### `GET /content`\n\n";
		$md .= "Lists published content of any post type. Query parameters: `post_type` (default `post`, or `all`), `per_page`, `page`, `search`, `tax` + `term` (filter by term slug).\n\n";
		$md .= "```\ncurl -H \"Authorization: Bearer wpa_...\" \"" . esc_url( home_url( '/' ) ) . "wp-json/" . WPA_API_NS . "/content?post_type=all&per_page=20\"\n```\n\n";

		$md .= "### `GET /content/{id}`\n\n";
		$md .= "Returns a single content item with its full content, terms and meta.\n\n";

		$md .= "### `GET /types`\n\n";
		$md .= "Returns the registered public post types.\n\n";

		$md .= "### `GET /taxonomies`\n\n";
		$md .= "Returns the registered public taxonomies with their terms. Optional `?tax={taxonomy}` to filter.\n\n";

		$md .= "### `GET /search?q={term}`\n\n";
		$md .= "Searches across all public content types.\n\n";

		if ( $exec ) {
			$md .= "### `POST /exec`\n\n";
			$md .= "Runs a wp-cli command on the site. Send a JSON body:\n\n";
			$md .= "```json\n{\"command\": \"option get blogname\"}\n```\n\n";
			$md .= "Accepted forms: `\"option get blogname\"` or `\"wp option get blogname\"`. Optional `timeout` (seconds, max 300).\n\n";
			$md .= "Only commands matching the configured whitelist are allowed. The global blacklist always applies.\n\n";
			$md .= "```\ncurl -X POST -H \"Authorization: Bearer wpa_...\" -H \"Content-Type: application/json\" \\\n  -d '{\"command\":\"option get blogname\"}' \\\n  \"" . esc_url( home_url( '/' ) ) . "wp-json/" . WPA_API_NS . "/exec\"\n```\n\n";
		}

		$md .= "## Allowed commands (whitelist)\n\n";
		$md .= "```\n" . implode( "\n", WPAgent_Exec::whitelist() ) . "\n```\n\n";

		$blacklist = WPAgent_Exec::blacklist();
		if ( ! empty( $blacklist ) ) {
			$md .= "## Globally blocked commands (blacklist)\n\n";
			$md .= "```\n" . implode( "\n", $blacklist ) . "\n```\n\n";
		}

		$md .= "## Error responses\n\n";
		$md .= "- `401` invalid or missing key.\n";
		$md .= "- `403` valid key but permission denied (missing read/exec, or command not in whitelist).\n";
		$md .= "- `404` resource not found.\n";
		$md .= "- `503` panic mode is active on the site.\n";

		return new WP_REST_Response(
			array(
				'format' => 'markdown',
				'docs'   => $md,
			)
		);
	}
}
