<?php
/**
 * Fired when the plugin is uninstalled via WordPress Admin.
 *
 * @package WebDmitriev_Protection
 */

// If uninstall not called from WordPress, then exit.
if (!defined('WP_UNINSTALL_PLUGIN')) {
  exit;
}

global $wpdb;

// 1. Delete custom security logs table
$table_name = $wpdb->base_prefix . 'webdmitriev_protection_logs';
$wpdb->query("DROP TABLE IF EXISTS {$table_name}"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// 2. Delete all plugin options from wp_options
$options_to_delete = array(
  'webdmitriev_protection_modified_root_htaccess',
  'webdmitriev_protection_modified_wp_config',
  'webdmitriev_protection_root_htaccess_hash',
  'webdmitriev_protection_wp_config_hash',
  'webdmitriev_protection_blacklisted_ips',
);

foreach ($options_to_delete as $option) {
  delete_option($option);
}

// 3. Delete all plugin transients (email throttling, rate limits, etc.)
$wpdb->query(
  "DELETE FROM {$wpdb->options} 
   WHERE option_name LIKE '_transient_webdmitriev_protection_%' 
   OR option_name LIKE '_transient_timeout_webdmitriev_protection_%'"
); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// 4. Clear scheduled Cron tasks
wp_clear_scheduled_hook('webdmitriev_protection_daily_file_integrity_check');