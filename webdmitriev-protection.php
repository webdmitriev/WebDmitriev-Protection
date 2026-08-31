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
    add_action('admin_post_wd_save_blacklist', array($this, 'save_blacklist'));

    // Загрузка модуля 1: Точки входа
    require_once WD_PROT_PATH . 'modules/entry-points.php';
    new WD_Protection_Entry_Points();

    // Загрузка модуля 2: Защита файлов
    require_once WD_PROT_PATH . 'modules/file-guard.php';
    new WD_Protection_File_Guard();

    // Загрузка модуля 3: Firewall
    require_once WD_PROT_PATH . 'modules/firewall.php';
    new WD_Protection_Firewall();
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

  public function save_blacklist() {
    if (!current_user_can('manage_options') || !check_admin_referer('wd_save_blacklist_action', 'wd_save_blacklist_nonce')) {
      wp_die('Доступ запрещен');
    }

    $raw_ips = isset($_POST['blacklisted_ips']) ? sanitize_textarea_field($_POST['blacklisted_ips']) : '';
    $ip_array = array_filter(array_map('trim', explode("\n", $raw_ips)));

    // Валидация IP-адресов
    $clean_ips = array();
    foreach ($ip_array as $ip) {
      if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $clean_ips[] = $ip;
      }
    }

    update_option('wd_prot_blacklisted_ips', $clean_ips);

    wp_redirect(admin_url('admin.php?page=webdmitriev-protection&saved_ips=1'));
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
      // Ключ для защиты от спама одинаковыми письмами с одного IP
      $transient_key = 'wd_prot_mail_' . md5($type . $ip);

      // Если аналогичное письмо отправлялось меньше 15 минут назад — пропускаем отправку
      if (!get_transient($transient_key)) {
        $admin_email = get_option('admin_email');
        $subject = '[' . get_bloginfo('name') . '] Критическая угроза безопасности: ' . $type;

        $body = "Зафиксирована критическая угроза безопасности:\n\n";
        $body .= "Тип события: {$type}\n";
        $body .= "IP-адрес: {$ip}\n";
        $body .= "Дата и время: " . current_time('mysql') . "\n";
        $body .= "Детали: {$message}\n\n";
        $body .= "Подробнее в панеле управления: " . admin_url('admin.php?page=webdmitriev-protection');

        if (wp_mail($admin_email, $subject, $body)) {
          // Блокируем отправку дубликатов писем по этому событию на 15 минут (900 секунд)
          set_transient($transient_key, true, 900);
        }
      }
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
    if (!current_user_can('manage_options')) {
      return;
    }

    global $wpdb;
    $table_name = $wpdb->prefix . 'wd_protection_logs';

    // Подготовка данных для View
    $logs = $wpdb->get_results("SELECT * FROM {$table_name} ORDER BY id DESC LIMIT 50");
    $htaccess_changed = get_option('wd_prot_modified_root_htaccess');
    $wpconfig_changed = get_option('wd_prot_modified_wp_config');
    $blacklisted_ips  = get_option('wd_prot_blacklisted_ips', array());

    // Подключение View-файла
    require_once WD_PROT_PATH . 'admin/admin-page.php';
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