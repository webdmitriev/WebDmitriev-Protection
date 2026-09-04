<?php
/**
 * Protection against brute-force attacks, XML-RPC exploitation, and user enumeration.
 *
 * @package WebDmitriev_Protection
 */

if (!defined('ABSPATH')) {
  exit;
}

class WebDmitriev_Protection_Entry_Points {

  /**
   * Maximum allowed login attempts before lockout.
   *
   * @var int
   */
  private $max_attempts = 5;

  /**
   * Lockout duration in seconds (15 minutes).
   *
   * @var int
   */
  private $lockout_time = 900;

  public function __construct() {
    // 1. Full XML-RPC restriction
    add_filter('xmlrpc_enabled', '__return_false');
    add_action('init', array($this, 'block_xmlrpc_requests'));

    // 2. Brute-force protection for login form (wp-login.php)
    add_action('wp_login_failed', array($this, 'handle_failed_login'));
    add_filter('authenticate', array($this, 'check_bruteforce_lockout'), 30, 3);

    // 3. Hide WP version & prevent user enumeration
    remove_action('wp_head', 'wp_generator');
    add_action('template_redirect', array($this, 'block_user_enumeration'));
    add_filter('rest_endpoints', array($this, 'disable_user_rest_endpoints'));
  }

  /**
   * Helper method to get clean Remote IP Address.
   *
   * @return string
   */
  private function get_ip_address() {
    return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '0.0.0.0';
  }

  /**
   * Block direct request to xmlrpc.php file.
   */
  public function block_xmlrpc_requests() {
    $request_uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';

    if (false !== strpos($request_uri, 'xmlrpc.php')) {
      $ip = $this->get_ip_address();

      WebDmitriev_Protection::log_event(
        'xmlrpc_blocked',
        'Attempted request to xmlrpc.php',
        $ip,
        'warning'
      );

      wp_die(
        esc_html__('XML-RPC service is disabled for security reasons.', 'webdmitriev-protection'),
        esc_html__('Access Denied', 'webdmitriev-protection'),
        array('response' => 403)
      );
    }
  }

  /**
   * Handle failed login attempt and increment count.
   *
   * @param string $username Username or email attempted.
   */
  public function handle_failed_login($username) {
    $ip            = $this->get_ip_address();
    $transient_key = 'webdmitriev_protection_login_attempts_' . md5($ip);

    $attempts = get_transient($transient_key);
    $attempts = $attempts ? $attempts + 1 : 1;

    set_transient($transient_key, $attempts, $this->lockout_time);

    WebDmitriev_Protection::log_event(
      'failed_login',
      sprintf(
        /* translators: 1: Username, 2: Current attempt count, 3: Max attempts count */
        __('Failed login attempt for user "%1$s" (Attempt %2$d of %3$d)', 'webdmitriev-protection'),
        sanitize_text_field($username),
        $attempts,
        $this->max_attempts
      ),
      $ip,
      'warning'
    );

    if ($attempts >= $this->max_attempts) {
      WebDmitriev_Protection::log_event(
        'bruteforce_lockout',
        sprintf(
          /* translators: %s: Username */
          __('IP locked for 15 minutes due to brute-force attempts on username "%s"', 'webdmitriev-protection'),
          sanitize_text_field($username)
        ),
        $ip,
        'critical'
      );
    }
  }

  /**
   * Check if IP is currently locked out before processing authentication.
   *
   * @param WP_User|WP_Error|null $user     WP_User or WP_Error object.
   * @param string                $username Username or email.
   * @param string                $password Password.
   * @return WP_User|WP_Error
   */
  public function check_bruteforce_lockout($user, $username, $password) {
    if (empty($username)) {
      return $user;
    }

    $ip            = $this->get_ip_address();
    $transient_key = 'webdmitriev_protection_login_attempts_' . md5($ip);
    $attempts      = get_transient($transient_key);

    if ($attempts && $attempts >= $this->max_attempts) {
      return new WP_Error(
        'webdmitriev_protection_ip_blocked',
        sprintf(
          '<strong>%1$s</strong>: %2$s',
          esc_html__('ERROR', 'webdmitriev-protection'),
          esc_html__('Too many failed login attempts. Your IP is temporarily blocked.', 'webdmitriev-protection')
        )
      );
    }

    return $user;
  }

  /**
   * Block author scanning attempts via ?author=1 parameter.
   */
  public function block_user_enumeration() {
    if (!is_admin() && isset($_GET['author'])) {
      $author = sanitize_text_field(wp_unslash($_GET['author']));
      if (!empty($author)) {
        $ip = $this->get_ip_address();

        WebDmitriev_Protection::log_event(
          'user_scan_blocked',
          'Blocked user enumeration attempt via ?author= query',
          $ip,
          'warning'
        );

        wp_die(
          esc_html__('User enumeration scanning is strictly forbidden.', 'webdmitriev-protection'),
          esc_html__('Forbidden', 'webdmitriev-protection'),
          array('response' => 403)
        );
      }
    }
  }

  /**
   * Disable REST API user endpoints for non-authenticated visitors.
   *
   * @param array $endpoints REST API Endpoints array.
   * @return array
   */
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