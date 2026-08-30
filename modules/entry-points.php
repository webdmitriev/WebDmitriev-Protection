<?php
if (!defined('ABSPATH')) {
  exit;
}

class WD_Protection_Entry_Points {

  private $max_attempts = 5;      // Макс. попыток входа
  private $lockout_time = 900;   // Блокировка на 15 минут (в секундах)

  public function __construct() {
    // 1. Полная блокировка XML-RPC
    add_filter('xmlrpc_enabled', '__return_false');
    add_action('init', array($this, 'block_xmlrpc_requests'));

    // 2. Защита от брутфорса формы авторизации (wp-login.php)
    add_action('wp_login_failed', array($this, 'handle_failed_login'));
    add_filter('authenticate', array($this, 'check_bruteforce_lockout'), 30, 3);

    // 3. Скрытие версии WP и перечисления пользователей (User Enumeration)
    remove_action('wp_head', 'wp_generator');
    add_action('template_redirect', array($this, 'block_user_enumeration'));
    add_filter('rest_endpoints', array($this, 'disable_user_rest_endpoints'));
  }

  // Блокировка физических запросов к xmlrpc.php
  public function block_xmlrpc_requests() {
    if (strpos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false) {
      $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
      WebDmitriev_Protection::log_event('xmlrpc_blocked', 'Попытка обращения к xmlrpc.php', $ip, 'warning');
      wp_die('XML-RPC отключен из соображений безопасности.', 'Access Denied', array('response' => 403));
    }
  }

  // Обработка неудачной попытки входа
  public function handle_failed_login($username) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $transient_key = 'wd_login_attempts_' . md5($ip);

    $attempts = get_transient($transient_key);
    $attempts = $attempts ? $attempts + 1 : 1;

    set_transient($transient_key, $attempts, $this->lockout_time);

    WebDmitriev_Protection::log_event(
      'failed_login',
      sprintf('Неудачный вход для логина "%s" (Попытка %d из %d)', sanitize_text_field($username), $attempts, $this->max_attempts),
      $ip,
      'warning'
    );

    if ($attempts >= $this->max_attempts) {
      WebDmitriev_Protection::log_event(
        'bruteforce_lockout',
        sprintf('IP заблокирован на 15 минут за брутфорс логина "%s"', sanitize_text_field($username)),
        $ip,
        'critical'
      );
    }
  }

  // Проверка блокировки перед авторизацией
  public function check_bruteforce_lockout($user, $username, $password) {
    if (empty($username)) return $user;

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $transient_key = 'wd_login_attempts_' . md5($ip);
    $attempts = get_transient($transient_key);

    if ($attempts && $attempts >= $this->max_attempts) {
      return new WP_Error(
        'wd_ip_blocked',
        '<strong>ОШИБКА</strong>: Слишком много неудачных попыток входа. Ваш IP временно заблокирован.'
      );
    }

    return $user;
  }

  // Блокировка сканирования пользователей через ?author=1
  public function block_user_enumeration() {
    if (!is_admin() && isset($_GET['author'])) {
      $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
      WebDmitriev_Protection::log_event('user_scan_blocked', 'Заблокирована попытка перечисления пользователей через ?author=', $ip, 'warning');
      wp_die('Сканирование пользователей запрещено.', 'Forbidden', array('response' => 403));
    }
  }

  // Отключение эндпоинта пользователей в REST API (/wp-json/wp/v2/users)
  public function disable_user_rest_endpoints($endpoints) {
    if (!is_user_logged_in()) {
      if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
      }
      if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
        unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
      }
    }
    return $endpoints;
  }
}