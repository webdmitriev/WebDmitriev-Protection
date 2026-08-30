<?php
if (!defined('ABSPATH')) {
  exit;
}

class WD_Protection_Firewall {

  public function __construct() {
    // Запускаем файрвол на самом раннем этапе инициализации
    add_action('plugins_loaded', array($this, 'run_firewall'), 1);

    // Отправляем заголовки безопасности
    add_action('send_headers', array($this, 'set_security_headers'));
  }

  /**
   * Простановка заголовков безопасности HTTP
   */
  public function set_security_headers() {
    if (headers_sent()) return;

    // Защита от встраивания в iframe (кликджекинг)
    header('X-Frame-Options: SAMEORIGIN');
    // Запрет браузеру угадывать MIME-тип файла
    header('X-Content-Type-Options: nosniff');
    // Защита от XSS на стороне браузера
    header('X-XSS-Protection: 1; mode=block');
    // Политика передачи Referrer
    header('Referrer-Policy: strict-origin-when-cross-origin');
  }

  /**
   * Главная точка фильтрации входящего трафика
   */
  public function run_firewall() {
    if (is_admin()) return; // Пропускаем проверку внутри админки

    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // 1. Проверка черного списка IP
    $this->check_ip_blacklist($ip);

    // 2. Проверка вредоносного User-Agent
    $this->check_user_agent($ip);

    // 3. Базовая фильтрация SQLi / XSS в GET-запросах
    $this->check_request_payload($ip);
  }

  /**
   * Блокировка IP из черного списка
   */
  private function check_ip_blacklist($ip) {
    $blacklisted_ips = get_option('wd_prot_blacklisted_ips', array());

    if (in_array($ip, $blacklisted_ips)) {
      WebDmitriev_Protection::log_event(
        'firewall_ip_blocked',
        'Заблокирован доступ с IP из черного списка',
        $ip,
        'warning'
      );
      $this->block_access('Доступ с вашего IP-адреса ограничен.');
    }
  }

  /**
   * Проверка ботов по сигнатурам User-Agent
   */
  private function check_user_agent($ip) {
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

    if (empty($user_agent)) return;

    // Распространенные вредоносные сканеры и хакерские утилиты
    $bad_bots = array(
      'sqlmap', 'nikto', 'netsparker', 'dirbuster', 'nmap',
      'absinthe', 'masscan', 'havij', 'w3af', 'zgrab'
    );

    foreach ($bad_bots as $bot) {
      if (stripos($user_agent, $bot) !== false) {
        WebDmitriev_Protection::log_event(
          'firewall_bot_blocked',
          sprintf('Заблокирован вредоносный бот/сканер: %s', sanitize_text_field($user_agent)),
          $ip,
          'critical'
        );
        $this->block_access('Доступ запрещен.');
      }
    }
  }

  /**
   * Анализ параметров URI и GET на наличие атак
   */
  private function check_request_payload($ip) {
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';

    // Набор опасных шаблонов (SQLi, Directory Traversal, XSS)
    $dangerous_patterns = array(
      '/union\s+select/i',
      '/base64_decode/i',
      '/\.\.\/\.\.\//', // Попытка выхода из директории (../../)
      '/<script.*?>/i',
      '/GLOBALS\s*=\s*\[/i',
      '/_REQUEST\s*=\s*\[/i'
    );

    foreach ($dangerous_patterns as $pattern) {
      if (preg_match($pattern, urldecode($request_uri))) {
        WebDmitriev_Protection::log_event(
          'firewall_attack_blocked',
          sprintf('Заблокирована попытка атаки в URL: %s', sanitize_text_field($request_uri)),
          $ip,
          'critical'
        );
        $this->block_access('Запрос заблокирован системой безопасности.');
      }
    }
  }

  /**
   * Прерывание выполнения и высылка 403 ошибки
   */
  private function block_access($reason) {
    wp_die($reason, 'Access Denied', array('response' => 403));
  }
}