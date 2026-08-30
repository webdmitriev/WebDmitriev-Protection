<?php
/**
 * Plugin Name: WebDmitriev Protection
 * Description: Легковесный модуль безопасности и защиты от атак.
 * Version: 1.0.0
 * Author: webdmitriev
 */

if (!defined('ABSPATH')) {
  exit;
}

define('WD_PROT_PATH', plugin_dir_path(__FILE__));
define('WD_PROT_VERSION', '1.0.0');

class WebDmitriev_Protection {

  private static $instance = null;

  public static function get_instance() {
    if (null === self::$instance) {
      self::$instance = new self();
    }
    return self::$instance;
  }

  private function __construct() {
    register_activation_hook(__FILE__, array($this, 'activate'));

    add_action('admin_menu', array($this, 'add_admin_menu'));
    add_action('admin_post_wd_clear_logs', array($this, 'clear_logs'));

    // Загрузка модуля защиты точек входа
    require_once WD_PROT_PATH . 'modules/entry-points.php';
    new WD_Protection_Entry_Points();
  }

  public function activate() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'wd_protection_logs';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
      id bigint(20) NOT NULL AUTO_INCREMENT,
      created_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
      event_type varchar(50) NOT NULL,
      severity varchar(20) DEFAULT 'warning' NOT NULL,
      ip_address varchar(45) NOT NULL,
      message text NOT NULL,
      PRIMARY KEY  (id)
    ) $charset_collate;";

    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
  }

  public static function log_event($type, $message, $ip = '', $severity = 'warning') {
    global $wpdb;
    $table_name = $wpdb->prefix . 'wd_protection_logs';

    if (empty($ip)) {
      $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
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

    // Отправка критических уведомлений на email админа
    if ($severity === 'critical') {
      $admin_email = get_option('admin_email');
      $subject = '[' . get_bloginfo('name') . '] Критическая угроза безопасности';
      $body = "Зафиксирована подозрительная активность:\n\n";
      $body .= "Тип: {$type}\n";
      $body .= "IP: {$ip}\n";
      $body .= "Детали: {$message}\n";
      $body .= "Дата: " . current_time('mysql') . "\n";

      wp_mail($admin_email, $subject, $body);
    }
  }

  public function add_admin_menu() {
    add_menu_page(
      'WD Protection',
      'WD Protection',
      'manage_options',
      'webdmitriev-protection',
      array($this, 'render_admin_page'),
      'dashicons-shield',
      80
    );
  }

  public function render_admin_page() {
    global $wpdb;
    $table_name = $wpdb->prefix . 'wd_protection_logs';
    $logs = $wpdb->get_results("SELECT * FROM $table_name ORDER BY id DESC LIMIT 50");
    ?>
    <div class="wrap">
      <h1>WebDmitriev Protection — Уведомления и Логи</h1>

      <form method="post" action="<?php echo admin_url('admin-post.php'); ?>" style="margin-bottom: 20px;">
        <input type="hidden" name="action" value="wd_clear_logs">
        <?php wp_nonce_field('wd_clear_logs_action', 'wd_clear_logs_nonce'); ?>
        <submit class="button button-secondary">Очистить лог</submit>
      </form>

      <table class="wp-list-table widefat fixed striped">
        <thead>
          <tr>
            <th style="width: 160px;">Дата</th>
            <th style="width: 100px;">Уровень</th>
            <th style="width: 130px;">Тип</th>
            <th style="width: 130px;">IP-адрес</th>
            <th>Сообщение</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($logs)): ?>
            <tr><td colspan="5">Подозрительных событий не зафиксировано.</td></tr>
          <?php else: ?>
            <?php foreach ($logs as $log): ?>
              <tr>
                <td><?php echo esc_html($log->created_at); ?></td>
                <td>
                  <span style="color: <?php echo $log->severity === 'critical' ? 'red' : 'orange'; ?>; font-weight: bold;">
                    <?php echo esc_html(strtoupper($log->severity)); ?>
                  </span>
                </td>
                <td><code><?php echo esc_html($log->event_type); ?></code></td>
                <td><code><?php echo esc_html($log->ip_address); ?></code></td>
                <td><?php echo esc_html($log->message); ?></td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
    <?php
  }

  public function clear_logs() {
    if (!current_user_can('manage_options') || !check_admin_referer('wd_clear_logs_action', 'wd_clear_logs_nonce')) {
      wp_die('Доступ запрещен');
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'wd_protection_logs';
    $wpdb->query("TRUNCATE TABLE $table_name");

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection'));
    exit;
  }
}

WebDmitriev_Protection::get_instance();