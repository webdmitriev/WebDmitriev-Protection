=== WebDmitriev Protection ===
Contributors: webdmitriev
Tags: security, firewall, htaccess, limit login, bruteforce
Requires at least: 6.0
Tested up to: 6.7
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lightweight security module, attack protection, and file integrity monitoring.

== Description ==

WebDmitriev Protection is a compact and efficient security solution for WordPress sites:

* **Brute-Force Protection:** Limits failed login attempts on `wp-login.php`.
* **Entry Point Security:** Disables XML-RPC and prevents user enumeration via REST API and author query parameters.
* **File Integrity Guard:** Monitors critical files (`.htaccess` and `wp-config.php`) for unauthorized changes.
* **Uploads Directory Guard:** Automatically blocks PHP execution inside `/wp-content/uploads/`.
* **Lightweight WAF:** Filters dangerous URL parameters (SQLi/XSS), blocks malicious User-Agent signatures, and manages IP blacklists.

== Installation ==

1. Upload the `webdmitriev-protection` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to 'WD Protection' in the admin dashboard to configure settings and view threat logs.

== Frequently Asked Questions ==

= How does the plugin block brute-force attacks? =
It tracks failed login attempts by IP address. If an IP exceeds 5 failed attempts within 15 minutes, access to the login form is temporarily blocked.

= What happens if wp-config.php or .htaccess is edited? =
The plugin calculates MD5 hashes of critical files. If a modification is detected, a notice appears in the admin panel allowing you to inspect and approve the new file state.

== Screenshots ==

1. Overview of the threat log and security status dashboard.
2. IP Blacklist configuration and firewall controls.

== Changelog ==

= 1.0.0 =
* Initial public release.