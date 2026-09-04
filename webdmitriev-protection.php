<?php
/**
 * Plugin Name: WebDmitriev Protection
 * Description: Lightweight security and attack protection module.
 * Version: 1.0.0
 * Author: webdmitriev
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: webdmitriev-protection
 * Domain Path: /languages
 *
 * @package WebDmitriev_Protection
 */

if (!defined('ABSPATH')) {
  exit;
}

/*  Copyright (C) 2026 webdmitriev

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

define('WEBDMITRIEV_PROTECTION_PATH', plugin_dir_path(__FILE__));
define('WEBDMITRIEV_PROTECTION_VERSION', '1.0.0');

class WebDmitriev_Protection {

  /**
   * Instance object.
   *
   * @var WebDmitriev_Protection|null
   */
  private static $instance = null;

  /**
   * Get singleton instance.
   *
   * @return WebDmitriev_Protection
   */
  public static function get_instance() {
    if (null === self::$instance) {
      self::$instance = new self();
    }
    return self::$instance;
  }

  private function __construct() {
    register_activation_hook(__FILE__, array($this, 'activate'));
    register_deactivation_hook(__FILE__, array($this, 'deactivate'));

    add_action('admin_menu', array($this, 'add_admin_menu'));
    
    // Prefixed admin_post actions
    add_action('admin_post_webdmitriev_protection_clear_logs', array($this, 'clear_logs'));
    add_action('admin_post_webdmitriev_protection_run_manual_scan', array($this, 'run_manual_scan'));
    add_action('admin_post_webdmitriev_protection_approve_hashes', array($this, 'approve_hashes'));
    add_action('admin_post_webdmitriev_protection_save_blacklist', array($this, 'save_blacklist'));

    // Modules loading
    require_once WEBDMITRIEV_PROTECTION_PATH . 'modules/entry-points.php';
    new WebDmitriev_Protection_Entry_Points();

    require_once WEBDMITRIEV_PROTECTION_PATH . 'modules/file-guard.php';
    new WebDmitriev_Protection_File_Guard();

    require_once WEBDMITRIEV_PROTECTION_PATH . 'modules/firewall.php';
    new WebDmitriev_Protection_Firewall();

    require_once WEBDMITRIEV_PROTECTION_PATH . 'modules/dashboard-widget.php';
    new WebDmitriev_Protection_Dashboard_Widget();
  }

  public function deactivate() {
    wp_clear_scheduled_hook('webdmitriev_protection_daily_file_integrity_check');
  }

  public function run_manual_scan() {
    if (!current_user_can('manage_options') || !check_admin_referer('webdmitriev_protection_scan_action', 'webdmitriev_protection_scan_nonce')) {
      wp_die(esc_html__('Access denied.', 'webdmitriev-protection'));
    }

    $file_guard = new WebDmitriev_Protection_File_Guard();
    $file_guard->run_daily_security_scan();

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection&scanned=1'));
    exit;
  }

  public function approve_hashes() {
    if (!current_user_can('manage_options') || !check_admin_referer('webdmitriev_protection_approve_hashes_action', 'webdmitriev_protection_approve_hashes_nonce')) {
      wp_die(esc_html__('Access denied.', 'webdmitriev-protection'));
    }

    WebDmitriev_Protection_File_Guard::approve_file_hashes();

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection&approved=1'));
    exit;
  }

  public function save_blacklist() {
    if (!current_user_can('manage_options') || !check_admin_referer('webdmitriev_protection_save_blacklist_action', 'webdmitriev_protection_save_blacklist_nonce')) {
      wp_die(esc_html__('Access denied.', 'webdmitriev-protection'));
    }

    $raw_ips  = isset($_POST['blacklisted_ips']) ? sanitize_textarea_field(wp_unslash($_POST['blacklisted_ips'])) : '';
    $ip_array = array_filter(array_map('trim', explode("\n", $raw_ips)));

    // IP Validation
    $clean_ips = array();
    foreach ($ip_array as $ip) {
      if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $clean_ips[] = $ip;
      }
    }

    update_option('webdmitriev_protection_blacklisted_ips', $clean_ips);

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection&saved_ips=1'));
    exit;
  }

  public function activate() {
    global $wpdb;
    $table_name      = $wpdb->base_prefix . 'webdmitriev_protection_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS {$table_name} (
      id bigint(20) NOT NULL AUTO_INCREMENT,
      created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
      event_type varchar(50) NOT NULL,
      severity varchar(20) DEFAULT 'warning' NOT NULL,
      ip_address varchar(45) NOT NULL,
      message text NOT NULL,
      PRIMARY KEY  (id)
    ) {$charset_collate};";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
  }

  public static function log_event($type, $message, $ip = '', $severity = 'warning') {
    global $wpdb;
    $table_name = $wpdb->base_prefix . 'webdmitriev_protection_logs';

    if (empty($ip)) {
      $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';
    }

    $wpdb->insert(
      $table_name,
      array(
        'event_type' => sanitize_text_field($type),
        'severity'   => sanitize_text_field($severity),
        'ip_address' => sanitize_text_field($ip),
        'message'    => sanitize_textarea_field($message),
      )
    );

    // Send critical alert notification
    if ('critical' === $severity) {
      $transient_key = 'webdmitriev_protection_mail_' . md5($type . $ip);

      if (!get_transient($transient_key)) {
        $admin_email = get_option('admin_email');

        /* translators: 1: Site name, 2: Event type */
        $subject = sprintf(
          __('[%1$s] Critical Security Threat: %2$s', 'webdmitriev-protection'),
          get_bloginfo('name'),
          $type
        );

        $body  = __("A critical security threat has been recorded:\n\n", 'webdmitriev-protection');
        $body .= sprintf(__("Event Type: %s\n", 'webdmitriev-protection'), $type);
        $body .= sprintf(__("IP Address: %s\n", 'webdmitriev-protection'), $ip);
        $body .= sprintf(__("Date and Time: %s\n", 'webdmitriev-protection'), current_time('mysql'));
        $body .= sprintf(__("Details: %s\n\n", 'webdmitriev-protection'), $message);
        $body .= sprintf(__("More details in the dashboard: %s", 'webdmitriev-protection'), admin_url('admin.php?page=webdmitriev-protection'));

        if (wp_mail($admin_email, $subject, $body)) {
          set_transient($transient_key, true, 900);
        }
      }
    }
  }

  public function add_admin_menu() {
    add_menu_page(
      __('WD Protection', 'webdmitriev-protection'),
      __('WD Protection', 'webdmitriev-protection'),
      'manage_options',
      'webdmitriev-protection',
      array($this, 'render_admin_page'),
      'dashicons-shield',
      80
    );

    add_submenu_page(
      'webdmitriev-protection',
      __('Security Logs', 'webdmitriev-protection'),
      __('Security Logs', 'webdmitriev-protection'),
      'manage_options',
      'webdmitriev-protection-logs',
      array($this, 'render_admin_page')
    );
  }

  public function render_admin_page() {
    if (!current_user_can('manage_options')) {
      return;
    }

    global $wpdb;
    $table_name = $wpdb->base_prefix . 'webdmitriev_protection_logs';

    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    $logs             = $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY id DESC LIMIT 50");
    $htaccess_changed = get_option('webdmitriev_protection_modified_root_htaccess');
    $wpconfig_changed = get_option('webdmitriev_protection_modified_wp_config');
    $blacklisted_ips  = get_option('webdmitriev_protection_blacklisted_ips', array());

    require_once WEBDMITRIEV_PROTECTION_PATH . 'admin/admin-page.php';
  }

  public function clear_logs() {
    if (!current_user_can('manage_options') || !check_admin_referer('webdmitriev_protection_clear_logs_action', 'webdmitriev_protection_clear_logs_nonce')) {
      wp_die(esc_html__('Access denied.', 'webdmitriev-protection'));
    }

    global $wpdb;
    $table_name = $wpdb->base_prefix . 'webdmitriev_protection_logs';
    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    $wpdb->query("TRUNCATE TABLE {$table_name}");

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection'));
    exit;
  }
}

WebDmitriev_Protection::get_instance();