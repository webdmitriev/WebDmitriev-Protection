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
    register_deactivation_hook(__FILE__, array($this, 'deactivate'));

    add_action('admin_menu', array($this, 'add_admin_menu'));
    add_action('admin_post_wd_clear_logs', array($this, 'clear_logs'));
    add_action('admin_post_wd_run_manual_scan', array($this, 'run_manual_scan'));
    add_action('admin_post_wd_approve_hashes', array($this, 'approve_hashes'));

    // Загрузка модуля 1: Точки входа
    require_once WD_PROT_PATH . 'modules/entry-points.php';
    new WD_Protection_Entry_Points();

    // Загрузка модуля 2: Защита файлов
    require_once WD_PROT_PATH . 'modules/file-guard.php';
    new WD_Protection_File_Guard();
  }

  public function deactivate() {
    wp_clear_scheduled_hook('wd_daily_file_integrity_check');
  }

  // Добавляем обработчик ручного запуска сканирования
  public function run_manual_scan() {
    if (!current_user_can('manage_options') || !check_admin_referer('wd_scan_action', 'wd_scan_nonce')) {
      wp_die('Доступ запрещен');
    }

    $file_guard = new WD_Protection_File_Guard();
    $file_guard->run_daily_security_scan();

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection&scanned=1'));
    exit;
  }

  public function approve_hashes() {
    if (!current_user_can('manage_options') || !check_admin_referer('wd_approve_hashes_action', 'wd_approve_hashes_nonce')) {
      wp_die('Доступ запрещен');
    }

    WD_Protection_File_Guard::approve_file_hashes();

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection&approved=1'));
    exit;
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

    $htaccess_changed = get_option('wd_prot_modified_root_htaccess');
    $wpconfig_changed = get_option('wd_prot_modified_wp_config');
    ?>
    <div class="wrap">
      <h1>WebDmitriev Protection — Уведомления и Логи</h1>

      <?php if (isset($_GET['scanned'])): ?>
        <div class="notice notice-success is-dismissible"><p>Сканирование файлов успешно завершено!</p></div>
      <?php endif; ?>

      <?php if (isset($_GET['approved'])): ?>
        <div class="notice notice-success is-dismissible"><p>Новые версии файлов утверждены как эталонные!</p></div>
      <?php endif; ?>

      <?php if ($htaccess_changed || $wpconfig_changed): ?>
        <div class="notice notice-warning" style="border-left-color: #ffb900; padding: 12px 15px;">
          <p style="margin: 0 0 10px 0; font-size: 14px;">
            <strong>⚠️ Зафиксированы изменения в критических файлах!</strong><br>
            Если вы проводили запланированные работы по правке <code>.htaccess</code> или <code>wp-config.php</code>, нажмите кнопку ниже, чтобы утвердить их.
          </p>
          <form method="post" action="<?php echo admin_url('admin-post.php'); ?>">
            <input type="hidden" name="action" value="wd_approve_hashes">
            <?php wp_nonce_field('wd_approve_hashes_action', 'wd_approve_hashes_nonce'); ?>
            <button type="submit" class="button button-primary">Принять текущие изменения как эталон</button>
          </form>
        </div>
      <?php endif; ?>

      <div style="display: flex; gap: 10px; margin-bottom: 20px;">
        <form method="post" action="<?php echo admin_url('admin-post.php'); ?>">
          <input type="hidden" name="action" value="wd_run_manual_scan">
          <?php wp_nonce_field('wd_scan_action', 'wd_scan_nonce'); ?>
          <button type="submit" class="button button-secondary">Запустить сканирование файлов</button>
        </form>

        <form method="post" action="<?php echo admin_url('admin-post.php'); ?>">
          <input type="hidden" name="action" value="wd_clear_logs">
          <?php wp_nonce_field('wd_clear_logs_action', 'wd_clear_logs_nonce'); ?>
          <button type="submit" class="button button-secondary">Очистить лог</button>
        </form>
      </div>

      <!-- ТАБЛИЦА ЛОГОВ -->
      <table class="wp-list-table widefat fixed striped">
        <thead>
          <tr>
            <th style="width: 160px;">Дата</th>
            <th style="width: 100px;">Уровень</th>
            <th style="width: 180px;">Тип</th>
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