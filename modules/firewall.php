<?php
/**
 * Application Firewall (WAF) module for WebDmitriev Protection.
 *
 * @package WebDmitriev_Protection
 */

if (!defined('ABSPATH')) {
  exit;
}

class WebDmitriev_Protection_Firewall {

  public function __construct() {
    // Run firewall at the earliest initialization stage.
    add_action('plugins_loaded', array($this, 'run_firewall'), 1);

    // Send HTTP security headers.
    add_action('send_headers', array($this, 'set_security_headers'));
  }

  /**
   * Helper method to retrieve clean Remote IP Address.
   *
   * @return string
   */
  private function get_ip_address() {
    return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';
  }

  /**
   * Set HTTP security headers.
   */
  public function set_security_headers() {
    if (headers_sent()) {
      return;
    }

    // Protect against clickjacking (iframe embedding).
    header('X-Frame-Options: SAMEORIGIN');
    // Prevent MIME-type sniffing.
    header('X-Content-Type-Options: nosniff');
    // Enable browser XSS protection.
    header('X-XSS-Protection: 1; mode=block');
    // Control referrer header privacy.
    header('Referrer-Policy: strict-origin-when-cross-origin');
  }

  /**
   * Main entry point for filtering incoming traffic.
   */
  public function run_firewall() {
    if (is_admin()) {
      return; // Skip checks inside WordPress admin area.
    }

    $ip = $this->get_ip_address();

    // 1. Check IP against blacklist.
    $this->check_ip_blacklist($ip);

    // 2. Check for malicious User-Agent.
    $this->check_user_agent($ip);

    // 3. Basic payload inspection for SQLi/XSS/Traversal in GET requests.
    $this->check_request_payload($ip);
  }

  /**
   * Block requests from blacklisted IPs.
   *
   * @param string $ip Client IP address.
   */
  private function check_ip_blacklist($ip) {
    $blacklisted_ips = get_option('webdmitriev_protection_blacklisted_ips', array());

    if (is_array($blacklisted_ips) && in_array($ip, $blacklisted_ips, true)) {
      WebDmitriev_Protection::log_event(
        'firewall_ip_blocked',
        'Blocked access attempt from blacklisted IP address',
        $ip,
        'warning'
      );

      $this->block_access(__('Access from your IP address has been restricted.', 'webdmitriev-protection'));
    }
  }

  /**
   * Check for suspicious/malicious User-Agent signatures.
   *
   * @param string $ip Client IP address.
   */
  private function check_user_agent($ip) {
    $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';

    if (empty($user_agent)) {
      return;
    }

    // Known scanner signatures and hacking utilities.
    $bad_bots = array(
      'sqlmap', 'nikto', 'netsparker', 'dirbuster', 'nmap',
      'absinthe', 'masscan', 'havij', 'w3af', 'zgrab',
    );

    foreach ($bad_bots as $bot) {
      if (false !== stripos($user_agent, $bot)) {
        WebDmitriev_Protection::log_event(
          'firewall_bot_blocked',
          sprintf(
            /* translators: %s: Malicious User-Agent string */
            __('Blocked malicious bot/scanner signature: %s', 'webdmitriev-protection'),
            $user_agent
          ),
          $ip,
          'critical'
        );

        $this->block_access(__('Access denied by security firewall.', 'webdmitriev-protection'));
      }
    }
  }

  /**
   * Analyze URI payload for common injection/traversal patterns.
   *
   * @param string $ip Client IP address.
   */
  private function check_request_payload($ip) {
    $raw_uri     = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
    $request_uri = urldecode($raw_uri);

    if (empty($request_uri)) {
      return;
    }

    // Dangerous signatures (SQLi, Directory Traversal, XSS, Global modifications).
    $dangerous_patterns = array(
      '/union\s+select/i',
      '/base64_decode/i',
      '/\.\.\/\.\.\//',
      '/<script.*?>/i',
      '/GLOBALS\s*=\s*\[/i',
      '/_REQUEST\s*=\s*\[/i',
    );

    foreach ($dangerous_patterns as $pattern) {
      if (preg_match($pattern, $request_uri)) {
        WebDmitriev_Protection::log_event(
          'firewall_attack_blocked',
          sprintf(
            /* translators: %s: Suspicious URI payload */
            __('Blocked attack attempt in request URL: %s', 'webdmitriev-protection'),
            $raw_uri
          ),
          $ip,
          'critical'
        );

        $this->block_access(__('Request blocked by security firewall.', 'webdmitriev-protection'));
      }
    }
  }

  /**
   * Terminate script execution with a 403 HTTP status.
   *
   * @param string $reason Localized error message to display.
   */
  private function block_access($reason) {
    wp_die(
      esc_html($reason),
      esc_html__('Access Denied', 'webdmitriev-protection'),
      array('response' => 403)
    );
  }
}