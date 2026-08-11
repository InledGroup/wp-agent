<?php
/**
 * WP-Agent admin panel.
 *
 * @package WP-Agent
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin panel: API key management, access log and panic mode.
 */
class WPAgent_Admin {

	/**
	 * Registers admin hooks.
	 */
	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'styles' ) );
		add_action( 'admin_post_wpa_create_key', array( __CLASS__, 'handle_create_key' ) );
		add_action( 'admin_post_wpa_revoke_key', array( __CLASS__, 'handle_revoke_key' ) );
		add_action( 'admin_post_wpa_reactivate_key', array( __CLASS__, 'handle_reactivate_key' ) );
		add_action( 'admin_post_wpa_delete_key', array( __CLASS__, 'handle_delete_key' ) );
		add_action( 'admin_post_wpa_save_key_perms', array( __CLASS__, 'handle_save_key_perms' ) );
		add_action( 'admin_post_wpa_save_global_perms', array( __CLASS__, 'handle_save_global_perms' ) );
		add_action( 'admin_post_wpa_panic_on', array( __CLASS__, 'handle_panic_on' ) );
		add_action( 'admin_post_wpa_panic_off', array( __CLASS__, 'handle_panic_off' ) );
		add_action( 'admin_post_wpa_save_whitelist', array( __CLASS__, 'handle_save_whitelist' ) );
		add_action( 'admin_post_wpa_save_blacklist', array( __CLASS__, 'handle_save_blacklist' ) );
		add_action( 'admin_post_wpa_clear_logs', array( __CLASS__, 'handle_clear_logs' ) );
		add_action( 'admin_post_wpa_delete_log_day', array( __CLASS__, 'handle_delete_log_day' ) );
	}

	/**
	 * Registers the admin menu.
	 */
	public static function menu() {
		add_menu_page(
			__( 'WP-Agent', 'wp-agent' ),
			__( 'WP-Agent', 'wp-agent' ),
			'manage_options',
			'wp-agent',
			array( __CLASS__, 'render' ),
			'dashicons-rest-api',
			3
		);
	}

	/**
	 * Loads the admin stylesheet.
	 */
	public static function styles() {
		wp_enqueue_style( 'wpa-admin', WPA_PLUGIN_URL . 'assets/css/admin.css', array(), WPA_VERSION );
	}

	/**
	 * Renders the main panel with tabs.
	 */
	public static function render() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'keys'; // phpcs:ignore WordPress.Security.NonceVerification
		if ( ! in_array( $tab, array( 'keys', 'logs', 'setup', 'settings' ), true ) ) {
			$tab = 'keys';
		}

		$panic = (bool) get_option( WPA_OPTION_PANIC, 0 );

		?>
		<div class="wrap wpa-wrap">
			<h1>WP-Agent</h1>
			<p class="description">
				<?php esc_html_e( 'AI agent access via API keys. Built by', 'wp-agent' ); ?>
				<a href="https://inled.es" target="_blank" rel="noopener noreferrer">Inled Group</a>.
			</p>

			<?php
			if ( $panic ) {
				echo '<div class="notice notice-error wpa-panic-banner"><p><strong>' . esc_html__( 'PANIC MODE ACTIVE', 'wp-agent' ) . '</strong> — ' . esc_html__( 'All API access is blocked. Keys are preserved.', 'wp-agent' ) . '</p></div>';
			}
			?>

			<h2 class="nav-tab-wrapper">
				<a href="?page=wp-agent&tab=keys" class="nav-tab <?php echo 'keys' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'API Keys', 'wp-agent' ); ?></a>
				<a href="?page=wp-agent&tab=logs" class="nav-tab <?php echo 'logs' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Access Log', 'wp-agent' ); ?></a>
				<a href="?page=wp-agent&tab=setup" class="nav-tab <?php echo 'setup' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Agent Setup', 'wp-agent' ); ?></a>
				<a href="?page=wp-agent&tab=settings" class="nav-tab <?php echo 'settings' === $tab ? 'nav-tab-active' : ''; ?>"><?php esc_html_e( 'Settings', 'wp-agent' ); ?></a>
			</h2>

			<?php if ( 'keys' === $tab ) : ?>
				<?php self::render_keys_tab( $panic ); ?>
			<?php elseif ( 'logs' === $tab ) : ?>
				<?php self::render_logs_tab(); ?>
			<?php elseif ( 'setup' === $tab ) : ?>
				<?php self::render_setup_tab(); ?>
			<?php else : ?>
				<?php self::render_settings_tab(); ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * API keys tab.
	 *
	 * @param bool $panic Panic mode state.
	 */
	protected static function render_keys_tab( $panic ) {
		$keys = WPAgent_Keys::all();

		// Newly created key notice (shown once).
		$new_key = get_transient( 'wpa_new_key_' . get_current_user_id() );
		if ( $new_key ) {
			delete_transient( 'wpa_new_key_' . get_current_user_id() );
			echo '<div class="notice notice-success wpa-new-key"><p><strong>' . esc_html__( 'Key created. Copy it now: it will not be shown again.', 'wp-agent' ) . '</strong></p>';
			echo '<pre class="wpa-key-plain">' . esc_html( $new_key['key'] ) . '</pre>';
			echo '<p class="wpa-key-name">' . esc_html( sprintf( __( 'Name: %s', 'wp-agent' ), $new_key['name'] ) ) . '</p></div>';
		}

		$global = WPAgent_Keys::global_perms();

		?>
		<div class="wpa-cols">
			<div class="wpa-card">
				<h2><?php esc_html_e( 'New API key', 'wp-agent' ); ?></h2>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'wpa_create_key' ); ?>
					<input type="hidden" name="action" value="wpa_create_key">
					<p>
						<label for="wpa-key-name"><?php esc_html_e( 'Agent name (e.g. ChatGPT, Copilot, Claude…)', 'wp-agent' ); ?></label>
						<input type="text" id="wpa-key-name" name="name" class="regular-text" required>
					</p>
					<?php submit_button( __( 'Create key', 'wp-agent' ), 'primary', 'submit', false ); ?>
				</form>

				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpa-panic-form">
					<?php wp_nonce_field( 'wpa_panic_toggle' ); ?>
					<input type="hidden" name="action" value="<?php echo $panic ? 'wpa_panic_off' : 'wpa_panic_on'; ?>">
					<h2><?php esc_html_e( 'Panic mode', 'wp-agent' ); ?></h2>
					<p class="description"><?php esc_html_e( 'Blocks all agents instantly. Keys are preserved and can be reactivated.', 'wp-agent' ); ?></p>
					<?php if ( $panic ) : ?>
						<?php submit_button( __( 'Restore access', 'wp-agent' ), 'secondary', 'submit', false ); ?>
					<?php else : ?>
						<?php submit_button( __( 'Activate panic mode', 'wp-agent' ), 'button button-link-delete', 'submit', false ); ?>
					<?php endif; ?>
				</form>
			</div>

			<div class="wpa-card">
				<h2><?php esc_html_e( 'Existing keys', 'wp-agent' ); ?></h2>
				<?php if ( empty( $keys ) ) : ?>
					<p><?php esc_html_e( 'No keys created yet.', 'wp-agent' ); ?></p>
				<?php else : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Name', 'wp-agent' ); ?></th>
								<th><?php esc_html_e( 'Status', 'wp-agent' ); ?></th>
								<th><?php esc_html_e( 'Permissions', 'wp-agent' ); ?></th>
								<th><?php esc_html_e( 'Last used', 'wp-agent' ); ?></th>
								<th><?php esc_html_e( 'Actions', 'wp-agent' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $keys as $key ) : ?>
								<tr class="<?php echo 'active' === $key['status'] ? '' : 'wpa-revoked'; ?>">
									<td>
										<strong><?php echo esc_html( $key['name'] ); ?></strong>
										<div class="wpa-key-id"><?php echo esc_html( substr( $key['id'], 0, 8 ) ); ?>…</div>
									</td>
									<td>
										<?php if ( 'active' === $key['status'] ) : ?>
											<span class="wpa-badge wpa-badge--active"><?php esc_html_e( 'Active', 'wp-agent' ); ?></span>
										<?php else : ?>
											<span class="wpa-badge wpa-badge--revoked"><?php esc_html_e( 'Revoked', 'wp-agent' ); ?></span>
										<?php endif; ?>
									</td>
									<td>
										<?php if ( 'active' === $key['status'] ) : ?>
											<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wpa-perms-form">
												<?php wp_nonce_field( 'wpa_save_key_perms_' . $key['id'] ); ?>
												<input type="hidden" name="action" value="wpa_save_key_perms">
												<input type="hidden" name="id" value="<?php echo esc_attr( $key['id'] ); ?>">
												<?php
												foreach ( WPAgent_Keys::PERMS as $perm ) {
													$checked = ! empty( $key['perms'][ $perm ] ) ? 'checked' : '';
													echo '<label class="wpa-perm-label"><input type="checkbox" name="perms[' . esc_attr( $perm ) . ']" value="1" ' . $checked . '> ' . esc_html( $perm ) . '</label>';
												}
												?>
												<label class="wpa-perm-label" title="<?php esc_attr_e( 'When checked, this key ignores global settings and only uses its own (permissions, whitelist and blacklist).', 'wp-agent' ); ?>">
													<input type="checkbox" name="override" value="1" <?php echo ! empty( $key['override'] ) ? 'checked' : ''; ?>> <?php esc_html_e( 'override global', 'wp-agent' ); ?>
												</label>
												<details class="wpa-lists">
													<summary><?php esc_html_e( 'Command whitelist / blacklist', 'wp-agent' ); ?></summary>
													<label class="wpa-perm-label">
														<input type="checkbox" name="wl_enabled" value="1" <?php echo ! empty( $key['wl_enabled'] ) ? 'checked' : ''; ?>>
														<?php esc_html_e( 'Enable whitelist for this key', 'wp-agent' ); ?>
													</label>
													<label class="wpa-field-label" for="wpa-wl-<?php echo esc_attr( $key['id'] ); ?>"><?php esc_html_e( 'Whitelist (one command per line)', 'wp-agent' ); ?></label>
													<textarea id="wpa-wl-<?php echo esc_attr( $key['id'] ); ?>" name="whitelist" class="large-text code" rows="5" placeholder="option get&#10;post list"><?php echo esc_textarea( implode( "\n", $key['whitelist'] ) ); ?></textarea>
													<label class="wpa-field-label" for="wpa-bl-<?php echo esc_attr( $key['id'] ); ?>"><?php esc_html_e( 'Blacklist (one command per line)', 'wp-agent' ); ?></label>
													<textarea id="wpa-bl-<?php echo esc_attr( $key['id'] ); ?>" name="blacklist" class="large-text code" rows="3"><?php echo esc_textarea( implode( "\n", $key['blacklist'] ) ); ?></textarea>
													<p class="description"><?php esc_html_e( 'With "override global" on, these replace the global lists (empty whitelist = block everything). Off, they are added to the global lists.', 'wp-agent' ); ?></p>
												</details>
												<?php submit_button( __( 'Save', 'wp-agent' ), 'button button-small', 'submit', false ); ?>
											</form>
										<?php else : ?>
											<span class="wpa-muted">—</span>
										<?php endif; ?>
									</td>
									<td><?php echo esc_html( $key['last_used'] ? $key['last_used'] : '—' ); ?></td>
									<td>
										<?php if ( 'active' === $key['status'] ) : ?>
											<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="inline">
												<?php wp_nonce_field( 'wpa_revoke_key_' . $key['id'] ); ?>
												<input type="hidden" name="action" value="wpa_revoke_key">
												<input type="hidden" name="id" value="<?php echo esc_attr( $key['id'] ); ?>">
												<button class="button button-small" onclick="return confirm('<?php echo esc_js( __( 'Revoke this key?', 'wp-agent' ) ); ?>')"><?php esc_html_e( 'Revoke', 'wp-agent' ); ?></button>
											</form>
										<?php else : ?>
											<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="inline">
												<?php wp_nonce_field( 'wpa_reactivate_key_' . $key['id'] ); ?>
												<input type="hidden" name="action" value="wpa_reactivate_key">
												<input type="hidden" name="id" value="<?php echo esc_attr( $key['id'] ); ?>">
												<button class="button button-small"><?php esc_html_e( 'Reactivate', 'wp-agent' ); ?></button>
											</form>
										<?php endif; ?>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="inline">
											<?php wp_nonce_field( 'wpa_delete_key_' . $key['id'] ); ?>
											<input type="hidden" name="action" value="wpa_delete_key">
											<input type="hidden" name="id" value="<?php echo esc_attr( $key['id'] ); ?>">
											<button class="button button-small" onclick="return confirm('<?php echo esc_js( __( 'Permanently delete this key?', 'wp-agent' ) ); ?>')"><?php esc_html_e( 'Delete', 'wp-agent' ); ?></button>
										</form>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
					<p class="description">
						<?php
						printf(
							/* translators: %1$s: global read permission, %2$s: global exec permission. */
							esc_html__( 'Global permissions: read = %1$s, exec = %2$s. Keys with "override global" use only their own permissions, whitelist and blacklist.', 'wp-agent' ),
							$global['read'] ? esc_html__( 'allowed', 'wp-agent' ) : esc_html__( 'blocked', 'wp-agent' ),
							$global['exec'] ? esc_html__( 'allowed', 'wp-agent' ) : esc_html__( 'blocked', 'wp-agent' )
						);
						?>
					</p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Agent setup tab: copyable prompt for AI agents.
	 */
	protected static function render_setup_tab() {
		$keys  = WPAgent_Keys::all();
		$active = array_filter( $keys, static function ( $k ) {
			return 'active' === $k['status'];
		} );

		$prompts  = array();
		$selected = '';
		foreach ( $active as $k ) {
			$prompts[ $k['id'] ] = self::build_agent_prompt( $k );
			if ( '' === $selected ) {
				$selected = $k['id'];
			}
		}

		?>
		<div class="wpa-card">
			<h2><?php esc_html_e( 'Send this prompt to your AI agent', 'wp-agent' ); ?></h2>
			<p class="description">
				<?php esc_html_e( 'Pick the API key to embed, copy the markdown below and paste it into the instructions (system prompt) of your AI agent. It points the agent to the machine-readable /docs endpoint.', 'wp-agent' ); ?>
			</p>

			<?php if ( empty( $active ) ) : ?>
				<p class="description"><?php esc_html_e( 'Create an API key first: it will be inserted into the prompt.', 'wp-agent' ); ?></p>
			<?php else : ?>
				<p>
					<label for="wpa-setup-key"><strong><?php esc_html_e( 'API key:', 'wp-agent' ); ?></strong></label>
					<select id="wpa-setup-key" class="regular-text">
						<?php foreach ( $active as $k ) : ?>
							<option value="<?php echo esc_attr( $k['id'] ); ?>">
								<?php echo esc_html( $k['name'] . ' (' . substr( $k['id'], 0, 8 ) . '…)' ); ?>
							</option>
						<?php endforeach; ?>
					</select>
				</p>
			<?php endif; ?>

			<textarea id="wpa-agent-prompt" class="large-text code wpa-prompt" rows="22" readonly><?php echo esc_textarea( $prompts[ $selected ] ?? '' ); ?></textarea>
			<p>
				<button type="button" class="button button-primary" id="wpa-copy-prompt"><?php esc_html_e( 'Copy prompt', 'wp-agent' ); ?></button>
				<span class="wpa-copy-ok" id="wpa-copy-ok"><?php esc_html_e( 'Copied to clipboard.', 'wp-agent' ); ?></span>
			</p>
		</div>

		<script>
		(function () {
			var prompts = <?php echo wp_json_encode( $prompts ); ?>;
			var select  = document.getElementById('wpa-setup-key');
			var ta      = document.getElementById('wpa-agent-prompt');
			if (select && ta) {
				select.addEventListener('change', function () {
					ta.value = prompts[select.value] || '';
				});
			}
			var btn = document.getElementById('wpa-copy-prompt');
			if (btn && ta) {
				btn.addEventListener('click', function () {
					ta.focus();
					ta.select();
					var done = function () {
						var ok = document.getElementById('wpa-copy-ok');
						if (ok) { ok.style.display = 'inline'; }
					};
					if (navigator.clipboard && window.isSecureContext) {
						navigator.clipboard.writeText(ta.value).then(done, done);
					} else {
						try { document.execCommand('copy'); } catch (e) {}
						done();
					}
				});
			}
		})();
		</script>
		<?php
	}

	/**
	 * Builds the markdown prompt for an AI agent.
	 *
	 * @param array|null $key Key record (optional).
	 * @return string
	 */
	protected static function build_agent_prompt( $key ) {
		$site_name = get_bloginfo( 'name' );
		$base_url  = home_url( '/' );
		$api_root  = $base_url . 'wp-json/' . WPA_API_NS;

		$lines   = array();
		$lines[] = '# WP-Agent — API instructions for your AI agent';
		$lines[] = '';
		$lines[] = sprintf( 'You are an AI agent with API access to the WordPress site "%s".', $site_name );
		$lines[] = 'Authenticate every request by sending your API key in the Authorization header:';
		$lines[] = '';
		$lines[] = '    Authorization: Bearer wpa_...';
		$lines[] = '';

		if ( $key ) {
			$lines[] = sprintf( 'Agent name: %s', $key['name'] );
			$lines[] = sprintf( 'Token id: %s', $key['id'] );
			$lines[] = 'API key: wpa_...  (replace wpa_... with the full wpa_ key that was shown when this token was created — it is not stored on the server)';
			$lines[] = '';
		}

		$lines[] = 'Base URL:';
		$lines[] = '';
		$lines[] = '    ' . $api_root;
		$lines[] = '';
		$lines[] = 'Workflow:';
		$lines[] = '';
		$lines[] = '1. First call GET /docs to read the machine-readable API documentation. Follow it exactly.';
		$lines[] = '2. Call GET /me to verify your identity and permissions.';
		$lines[] = '3. Explore the site with GET /types and GET /taxonomies, then GET /content (any post type) and GET /content/{id} for details. Use GET /search for full-text search.';
		$lines[] = '4. If you have exec permission, you may run whitelisted wp-cli commands via POST /exec.';
		$lines[] = '';

		$lines[] = 'Current permissions:';
		$lines[] = '';
		if ( $key ) {
			$lines[] = sprintf( '- read: %s', WPAgent_Keys::permission( $key, 'read' ) ? 'granted' : 'denied' );
			$lines[] = sprintf( '- exec: %s', WPAgent_Keys::permission( $key, 'exec' ) ? 'granted' : 'denied' );
		} else {
			$lines[] = '- read: pending (no key configured yet)';
			$lines[] = '- exec: pending (no key configured yet)';
		}
		$lines[] = '';
		$lines[] = 'Every access and action is logged on the site. The site owner can revoke your key or activate panic mode at any time.';
		$lines[] = 'Never expose your API key in logs, screenshots or shared conversations.';

		return implode( "\n", $lines );
	}

	/**
	 * Settings tab: global permissions, whitelist and blacklist.
	 */
	protected static function render_settings_tab() {
		$global = WPAgent_Keys::global_perms();

		?>
		<div class="wpa-cols">
			<div class="wpa-card">
				<h2><?php esc_html_e( 'Global permissions', 'wp-agent' ); ?></h2>
				<p class="description">
					<?php esc_html_e( 'Apply to every key unless the key has "override global" enabled. A permission is only granted when BOTH the global setting and the key setting allow it.', 'wp-agent' ); ?>
				</p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'wpa_save_global_perms' ); ?>
					<input type="hidden" name="action" value="wpa_save_global_perms">
					<p>
						<label><input type="checkbox" name="perms[read]" value="1" <?php echo $global['read'] ? 'checked' : ''; ?>> <?php esc_html_e( 'Allow read access (/books, /books/{id}, /categories, /search)', 'wp-agent' ); ?></label><br>
						<label><input type="checkbox" name="perms[exec]" value="1" <?php echo $global['exec'] ? 'checked' : ''; ?>> <?php esc_html_e( 'Allow exec access (/exec, restricted to the whitelist)', 'wp-agent' ); ?></label>
					</p>
					<?php submit_button( __( 'Save global permissions', 'wp-agent' ), 'primary', 'submit', false ); ?>
				</form>
			</div>

			<div class="wpa-card">
				<h2><?php esc_html_e( 'Command whitelist (wp-cli)', 'wp-agent' ); ?></h2>
				<p class="description">
					<?php esc_html_e( 'A command is allowed if it starts with any entry (one per line). Agents with exec permission can only run these commands.', 'wp-agent' ); ?>
				</p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'wpa_save_whitelist' ); ?>
					<input type="hidden" name="action" value="wpa_save_whitelist">
					<p>
						<label>
							<input type="checkbox" name="enabled" value="1" <?php echo WPAgent_Exec::whitelist_enabled() ? 'checked' : ''; ?>>
							<?php esc_html_e( 'Enable the global whitelist', 'wp-agent' ); ?>
						</label>
					</p>
					<p>
						<textarea name="whitelist" class="large-text code" rows="14"><?php echo esc_textarea( implode( "\n", WPAgent_Exec::whitelist() ) ); ?></textarea>
					</p>
					<p class="description"><?php esc_html_e( 'When disabled, the whitelist does not restrict any command. The blacklist is always enforced.', 'wp-agent' ); ?></p>
					<?php submit_button( __( 'Save whitelist', 'wp-agent' ), 'primary', 'submit', false ); ?>
				</form>
			</div>

			<div class="wpa-card">
				<h2><?php esc_html_e( 'Global blacklist', 'wp-agent' ); ?></h2>
				<p class="description">
					<?php esc_html_e( 'Always enforced, before the whitelist. Commands starting with any entry are blocked for every key. Use this for dangerous operations (e.g. db drop, user delete).', 'wp-agent' ); ?>
				</p>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
					<?php wp_nonce_field( 'wpa_save_blacklist' ); ?>
					<input type="hidden" name="action" value="wpa_save_blacklist">
					<p>
						<textarea name="blacklist" class="large-text code" rows="8" placeholder="db drop&#10;core download&#10;plugin delete"><?php echo esc_textarea( implode( "\n", WPAgent_Exec::blacklist() ) ); ?></textarea>
					</p>
					<?php submit_button( __( 'Save blacklist', 'wp-agent' ), 'primary', 'submit', false ); ?>
				</form>
			</div>
		</div>
		<?php
	}

	/**
	 * Access log tab.
	 */
	protected static function render_logs_tab() {
		$days = WPAgent_Logger::get_days();
		$day  = isset( $_GET['day'] ) ? sanitize_text_field( wp_unslash( $_GET['day'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification

		?>
		<div class="wpa-card">
			<h2><?php esc_html_e( 'Recorded accesses', 'wp-agent' ); ?></h2>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" onsubmit="return confirm('<?php echo esc_js( __( 'Delete ALL records?', 'wp-agent' ) ); ?>')">
				<?php wp_nonce_field( 'wpa_clear_logs' ); ?>
				<input type="hidden" name="action" value="wpa_clear_logs">
				<?php submit_button( __( 'Clear full log', 'wp-agent' ), 'button button-link-delete', 'submit', false ); ?>
			</form>

			<?php if ( '' !== $day ) : ?>
				<p>
					<a href="?page=wp-agent&tab=logs">&larr; <?php esc_html_e( 'Back to days', 'wp-agent' ); ?></a>
					<strong><?php echo esc_html( $day ); ?></strong>
				</p>
				<?php self::render_day_logs( $day ); ?>
			<?php else : ?>
				<?php if ( empty( $days ) ) : ?>
					<p><?php esc_html_e( 'No accesses recorded yet.', 'wp-agent' ); ?></p>
				<?php else : ?>
					<table class="widefat striped">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Day', 'wp-agent' ); ?></th>
								<th><?php esc_html_e( 'Accesses', 'wp-agent' ); ?></th>
								<th><?php esc_html_e( 'Actions', 'wp-agent' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $days as $d ) : ?>
								<tr>
									<td><a href="?page=wp-agent&tab=logs&day=<?php echo esc_attr( $d->day ); ?>"><?php echo esc_html( $d->day ); ?></a></td>
									<td><?php echo esc_html( $d->total ); ?></td>
									<td>
										<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="inline" onsubmit="return confirm('<?php echo esc_js( __( 'Delete this day?', 'wp-agent' ) ); ?>')">
											<?php wp_nonce_field( 'wpa_delete_log_day_' . $d->day ); ?>
											<input type="hidden" name="action" value="wpa_delete_log_day">
											<input type="hidden" name="day" value="<?php echo esc_attr( $d->day ); ?>">
											<button class="button button-small"><?php esc_html_e( 'Delete day', 'wp-agent' ); ?></button>
										</form>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Renders a single day's log detail.
	 *
	 * @param string $day Date Y-m-d.
	 */
	protected static function render_day_logs( $day ) {
		$logs = WPAgent_Logger::get_day( $day );
		if ( empty( $logs ) ) {
			echo '<p>' . esc_html__( 'No accesses on that day.', 'wp-agent' ) . '</p>';
			return;
		}
		?>
		<table class="widefat striped">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Time', 'wp-agent' ); ?></th>
					<th><?php esc_html_e( 'Key', 'wp-agent' ); ?></th>
					<th><?php esc_html_e( 'Action', 'wp-agent' ); ?></th>
					<th><?php esc_html_e( 'Endpoint', 'wp-agent' ); ?></th>
					<th><?php esc_html_e( 'Status', 'wp-agent' ); ?></th>
					<th><?php esc_html_e( 'IP', 'wp-agent' ); ?></th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $logs as $log ) : ?>
					<tr>
						<td><?php echo esc_html( mysql2date( 'H:i:s', $log->created_at ) ); ?></td>
						<td><?php echo esc_html( $log->key_name ? $log->key_name : '—' ); ?></td>
						<td><?php echo esc_html( $log->action ); ?></td>
						<td><?php echo esc_html( $log->endpoint ); ?></td>
						<td><?php echo esc_html( $log->status ); ?></td>
						<td><?php echo esc_html( $log->ip ); ?></td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Creates a key.
	 */
	public static function handle_create_key() {
		self::guard( 'wpa_create_key' );
		$name = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
		$made = WPAgent_Keys::create( $name );

		set_transient( 'wpa_new_key_' . get_current_user_id(), $made, 60 );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=keys' ) );
		exit;
	}

	/**
	 * Revokes a key.
	 */
	public static function handle_revoke_key() {
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		self::guard( 'wpa_revoke_key_' . $id );
		WPAgent_Keys::revoke( $id );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=keys' ) );
		exit;
	}

	/**
	 * Reactivates a key.
	 */
	public static function handle_reactivate_key() {
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		self::guard( 'wpa_reactivate_key_' . $id );
		WPAgent_Keys::reactivate( $id );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=keys' ) );
		exit;
	}

	/**
	 * Permanently deletes a key.
	 */
	public static function handle_delete_key() {
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		self::guard( 'wpa_delete_key_' . $id );
		WPAgent_Keys::delete( $id );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=keys' ) );
		exit;
	}

	/**
	 * Saves a key's per-token permissions, override, whitelist and blacklist.
	 */
	public static function handle_save_key_perms() {
		$id = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		self::guard( 'wpa_save_key_perms_' . $id );

		$perms = isset( $_POST['perms'] ) && is_array( $_POST['perms'] ) ? wp_unslash( $_POST['perms'] ) : array();
		WPAgent_Keys::set_perms(
			$id,
			array(
				'read' => ! empty( $perms['read'] ),
				'exec' => ! empty( $perms['exec'] ),
			)
		);
		WPAgent_Keys::set_override( $id, ! empty( $_POST['override'] ) );

		$whitelist  = isset( $_POST['whitelist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['whitelist'] ) ) : '';
		$blacklist  = isset( $_POST['blacklist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['blacklist'] ) ) : '';
		WPAgent_Keys::set_lists( $id, $whitelist, $blacklist, ! empty( $_POST['wl_enabled'] ) );

		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=keys' ) );
		exit;
	}

	/**
	 * Saves the global permissions.
	 */
	public static function handle_save_global_perms() {
		self::guard( 'wpa_save_global_perms' );

		$perms = isset( $_POST['perms'] ) && is_array( $_POST['perms'] ) ? wp_unslash( $_POST['perms'] ) : array();
		WPAgent_Keys::set_global_perms(
			array(
				'read' => ! empty( $perms['read'] ),
				'exec' => ! empty( $perms['exec'] ),
			)
		);

		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=settings' ) );
		exit;
	}

	/**
	 * Saves the command whitelist and its enabled state.
	 */
	public static function handle_save_whitelist() {
		self::guard( 'wpa_save_whitelist' );
		$raw   = isset( $_POST['whitelist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['whitelist'] ) ) : '';
		$lines = preg_split( '/\r?\n/', $raw );
		$lines = array_values( array_filter( array_map( 'trim', $lines ), static function ( $l ) {
			return '' !== $l;
		} ) );
		update_option( WPA_OPTION_WHITELIST, $lines );
		update_option( WPA_OPTION_WHITELIST_ENABLED, empty( $_POST['enabled'] ) ? 0 : 1 );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=settings' ) );
		exit;
	}

	/**
	 * Saves the global blacklist.
	 */
	public static function handle_save_blacklist() {
		self::guard( 'wpa_save_blacklist' );
		$raw   = isset( $_POST['blacklist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['blacklist'] ) ) : '';
		$lines = preg_split( '/\r?\n/', $raw );
		$lines = array_values( array_filter( array_map( 'trim', $lines ), static function ( $l ) {
			return '' !== $l;
		} ) );
		update_option( WPA_OPTION_BLACKLIST, $lines );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=settings' ) );
		exit;
	}

	/**
	 * Activates panic mode.
	 */
	public static function handle_panic_on() {
		self::guard( 'wpa_panic_toggle' );
		update_option( WPA_OPTION_PANIC, 1 );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=keys' ) );
		exit;
	}

	/**
	 * Deactivates panic mode.
	 */
	public static function handle_panic_off() {
		self::guard( 'wpa_panic_toggle' );
		update_option( WPA_OPTION_PANIC, 0 );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=keys' ) );
		exit;
	}

	/**
	 * Clears the full log.
	 */
	public static function handle_clear_logs() {
		self::guard( 'wpa_clear_logs' );
		WPAgent_Logger::clear_all();
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=logs' ) );
		exit;
	}

	/**
	 * Deletes a specific day from the log.
	 */
	public static function handle_delete_log_day() {
		$day = isset( $_POST['day'] ) ? sanitize_text_field( wp_unslash( $_POST['day'] ) ) : '';
		self::guard( 'wpa_delete_log_day_' . $day );
		WPAgent_Logger::delete_day( $day );
		wp_safe_redirect( admin_url( 'admin.php?page=wp-agent&tab=logs' ) );
		exit;
	}

	/**
	 * Verifies nonce and capabilities; redirects on failure.
	 *
	 * @param string $nonce Nonce action.
	 */
	protected static function guard( $nonce ) {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( $nonce ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'wp-agent' ) );
		}
	}
}
