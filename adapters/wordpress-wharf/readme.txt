=== Wharf Security Adapter ===
Contributors: hyperpolymath
Tags: security, firewall, database-proxy, post-quantum
Requires at least: 6.0
Tested up to: 6.7
Stable tag: 1.0.0
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Dashboard widget and status display for sites protected by Project Wharf.

== Description ==

Project Wharf is a Sovereign Web Hypervisor — an external security layer that sits
between the internet and your WordPress site. This adapter plugin provides a
dashboard widget showing the protection status.

**This plugin does NO security work itself.** All security enforcement is handled by
the yacht-agent, a separate Rust daemon that:

* Proxies all database queries through an AST-aware SQL parser
* Blocks SQL injection at the wire protocol level (not regex)
* Monitors file integrity via BLAKE3 cryptographic hashes
* Enforces write policies (immutable tables, no DROP/ALTER)
* Uses ML-DSA-87 post-quantum signatures for the control plane

= What This Plugin Does =

* Adds a "Wharf Security Status" widget to your WordPress dashboard
* Shows query statistics (total, blocked, audited)
* Displays firewall mode and signature scheme
* Adds an admin bar indicator (green = protected, grey = agent unreachable)
* Caches agent responses for 30 seconds to minimise overhead

= What This Plugin Does NOT Do =

* Does not implement any security features (that's the yacht-agent's job)
* Does not modify your database or files
* Does not phone home or collect telemetry
* Does not require an account or subscription

== Installation ==

1. Install and configure Project Wharf on your server (see https://github.com/hyperpolymath/project-wharf)
2. Upload the `wharf-adapter` folder to `/wp-content/plugins/`
3. Activate the plugin through the 'Plugins' menu
4. Visit your Dashboard to see the Wharf Security Status widget

= Configuration =

Set the `WHARF_AGENT_URL` environment variable if your yacht-agent runs on a
non-default address:

    define('WHARF_AGENT_URL', 'http://agent:9001');

Default is `http://localhost:9001`.

== Changelog ==

= 1.0.0 =
* Initial release
* Dashboard widget with query stats
* Admin bar status indicator
* Agent health monitoring
