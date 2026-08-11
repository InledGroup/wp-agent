=== WP-Agent ===
Contributors: inled
Tags: api, rest, ai, agent, api-key
Requires at least: 5.8
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Gives AI agents (ChatGPT, Copilot, Claude...) secure access to your site content via API keys. Built by Inled Group (https://inled.es).

== Description ==

WP-Agent lets artificial intelligence agents access your WordPress content (any public post type: posts, pages, custom post types) through an API-key-protected REST API. With a per-key permission, agents can also run wp-cli commands remotely, restricted by a configurable whitelist.

= Features =

* REST API protected by named API keys.
* Keys are stored as hashes (never in plaintext).
* Create, revoke and reactivate keys from the admin panel.
* Permission system: global permissions plus per-token permissions, with optional per-token override.
* Global command blacklist, always enforced before the whitelist.
* Remote wp-cli execution via POST /exec, restricted to a configurable whitelist.
* Full log of every access and action (including executed commands), organized by day.
* View the full log and delete it (per day or all).
* Panic mode: blocks every agent instantly without deleting keys. Reversible.
* Machine-readable API documentation at GET /docs for AI agents.
* Endpoints: /docs, /me, /content, /content/{id}, /types, /taxonomies, /search, /exec.

== Installation ==

1. Upload the `wp-agent` folder to `/wp-content/plugins/`.
2. Activate the plugin under "Plugins".
3. Open the "WP-Agent" menu and create a key with the agent name.
4. Use the key in the `Authorization: Bearer <key>` header against `/wp-json/wp-agent/v1/...`.
5. To run commands: enable the exec permission (global and/or on the key) and POST to `/wp-json/wp-agent/v1/exec` with `{"command":"option get blogname"}`.

== Usage example ==

    # Read content
    curl -H "Authorization: Bearer wpa_xxx" https://your-site.com/wp-json/wp-agent/v1/books

    # Run a wp-cli command (if the key has exec permission)
    curl -X POST -H "Authorization: Bearer wpa_xxx" \
      -d '{"command":"option get blogname"}' \
      https://your-site.com/wp-json/wp-agent/v1/exec

== Changelog ==

= 1.0.0 =
* Initial version.
