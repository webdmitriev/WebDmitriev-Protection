<?php
/**
 * Dashboard Widget module with Status Badges for WebDmitriev Protection.
 *
 * @package WebDmitriev_Protection
 */

if (!defined('ABSPATH')) {
  exit;
}

class WD_Protection_Dashboard_Widget {

  public function __construct() {
    add_action('wp_dashboard_setup', array($this, 'add_dashboard_widget'));
  }

  /**
   * Register the security log dashboard widget.
   */
  public function add_dashboard_widget() {
    if (!current_user_can('manage_options')) {
      return;
    }

    wp_add_dashboard_widget(
      'wd_protection_logs_widget',
      __('Security Log & System Status', 'webdmitriev-protection'),
      array($this, 'render_dashboard_widget')
    );
  }

  /**
   * Render the widget content with status badges and recent logs.
   */
  public function render_dashboard_widget() {
    // 1. Render Protection Status Badges Top Bar
    $this->render_status_badges();

    // 2. Get recent logs from database (limit to 5 items)
    $logs = $this->get_recent_logs(5);

    if (empty($logs)) {
      echo '<p style="margin-top: 15px;">' . esc_html__('No security events logged yet. Your site is safe!', 'webdmitriev-protection') . '</p>';
      return;
    }

    echo '<table class="widefat fixed striped" style="border:none; box-shadow:none; margin-top: 10px;">';
    echo '<thead>';
    echo '<tr>';
    echo '<th>' . esc_html__('Event', 'webdmitriev-protection') . '</th>';
    echo '<th>' . esc_html__('IP Address', 'webdmitriev-protection') . '</th>';
    echo '<th>' . esc_html__('Date', 'webdmitriev-protection') . '</th>';
    echo '</tr>';
    echo '</thead>';
    echo '<tbody>';

    foreach ($logs as $log) {
      $badge_style = ('warning' === $log->severity || 'critical' === $log->severity)
        ? 'background: #f8d7da; color: #721c24; padding: 2px 6px; border-radius: 3px; font-weight: bold;'
        : 'background: #e2e3e5; color: #383d41; padding: 2px 6px; border-radius: 3px;';

      echo '<tr>';
      echo '<td>';
      echo '<span style="' . esc_attr($badge_style) . '">' . esc_html($log->event_type) . '</span><br>';
      echo '<small>' . esc_html($log->message) . '</small>';
      echo '</td>';
      echo '<td><code>' . esc_html($log->ip_address) . '</code></td>';
      echo '<td><small>' . esc_html(wp_date('Y-m-d H:i', strtotime($log->created_at))) . '</small></td>';
      echo '</tr>';
    }

    echo '</tbody>';
    echo '</table>';

    $logs_page_url = admin_url('admin.php?page=webdmitriev-protection');
    echo '<p style="margin-top: 12px; text-align: right;">';
    echo '<a class="button button-secondary" href="' . esc_url($logs_page_url) . '">' . esc_html__('View Full Security Log', 'webdmitriev-protection') . ' &rarr;</a>';
    echo '</p>';
  }

  /**
   * Render top status indicators for security modules.
   */
  private function render_status_badges() {
    // Check if any critical file modifications were flagged
    $is_wp_config_modified  = get_option('wd_prot_modified_wp_config', false);
    $is_htaccess_modified   = get_option('wd_prot_modified_root_htaccess', false);

    $integrity_ok = !$is_wp_config_modified && !$is_htaccess_modified;

    $badge_active_style = 'display: inline-block; background: #d4edda; color: #155724; border: 1px solid #c3e6cb; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;';
    $badge_alert_style  = 'display: inline-block; background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: 600;';

    echo '<div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #f0f0f1;">';

    // WAF Badge
    echo '<div style="' . esc_attr($badge_active_style) . '">';
    echo '&#10003; ' . esc_html__('WAF: Active', 'webdmitriev-protection');
    echo '</div>';

    // BruteForce Badge
    echo '<div style="' . esc_attr($badge_active_style) . '">';
    echo '&#10003; ' . esc_html__('BruteForce: Active', 'webdmitriev-protection');
    echo '</div>';

    // File Integrity Badge
    if ($integrity_ok) {
      echo '<div style="' . esc_attr($badge_active_style) . '">';
      echo '&#10003; ' . esc_html__('Integrity: OK', 'webdmitriev-protection');
      echo '</div>';
    } else {
      echo '<div style="' . esc_attr($badge_alert_style) . '">';
      echo '&#9888; ' . esc_html__('Integrity: Alert', 'webdmitriev-protection');
      echo '</div>';
    }

    echo '</div>';
  }

  /**
   * Helper method to query recent events from database.
   *
   * @param int $limit Number of records to return.
   * @return array
   */
  private function get_recent_logs($limit = 5) {
    global $wpdb;

    $table_name = $wpdb->prefix . 'wd_protection_logs';

    if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table_name)) !== $table_name) {
      return array();
    }

    $limit = absint($limit);
    // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    return $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY id DESC LIMIT {$limit}");
  }
}