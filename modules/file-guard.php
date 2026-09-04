<?php
/**
 * File guard and integrity scanner module.
 *
 * @package WebDmitriev_Protection
 */

if (!defined('ABSPATH')) {
  exit;
}

class WebDmitriev_Protection_File_Guard {

  public function __construct() {
    add_action('admin_init', array($this, 'ensure_uploads_htaccess_protection'));
    add_action('webdmitriev_protection_daily_file_integrity_check', array($this, 'run_daily_security_scan'));

    if (!wp_next_scheduled('webdmitriev_protection_daily_file_integrity_check')) {
      wp_schedule_event(time(), 'daily', 'webdmitriev_protection_daily_file_integrity_check');
    }
  }

  /**
   * Initializes WP_Filesystem API safely.
   *
   * @return bool
   */
  private function init_filesystem() {
    global $wp_filesystem;

    if (empty($wp_filesystem)) {
      require_once ABSPATH . 'wp-admin/includes/file.php';
      WP_Filesystem();
    }

    return !empty($wp_filesystem);
  }

  /**
   * Ensures .htaccess protection exists in the uploads directory.
   */
  public function ensure_uploads_htaccess_protection() {
    if (!$this->init_filesystem()) {
      return;
    }

    global $wp_filesystem;
    $upload_dir    = wp_upload_dir();
    $htaccess_file = trailingslashit($upload_dir['basedir']) . '.htaccess';

    // Rules combining both Apache 2.2 and 2.4 compatibility
    $rules  = "# BEGIN WebDmitriev Protection Uploads Guard\n";
    $rules .= "<FilesMatch \"\.(?i:php|phtml|php3|php4|php5|php7|phps|suspected)$\">\n";
    $rules .= "    <IfModule mod_authz_core.c>\n";
    $rules .= "        Require all denied\n";
    $rules .= "    </IfModule>\n";
    $rules .= "    <IfModule !mod_authz_core.c>\n";
    $rules .= "        Order Allow,Deny\n";
    $rules .= "        Deny from all\n";
    $rules .= "    </IfModule>\n";
    $rules .= "</FilesMatch>\n";
    $rules .= "# END WebDmitriev Protection Uploads Guard\n";

    if (!$wp_filesystem->exists($htaccess_file)) {
      $wp_filesystem->put_contents($htaccess_file, $rules, FS_CHMOD_FILE);
    } else {
      $content = $wp_filesystem->get_contents($htaccess_file);
      if (false === strpos($content, 'WebDmitriev Protection Uploads Guard')) {
        $wp_filesystem->put_contents($htaccess_file, $rules . "\n" . $content, FS_CHMOD_FILE);
      }
    }
  }

  /**
   * Daily security scanner execution.
   */
  public function run_daily_security_scan() {
    $this->scan_uploads_for_php();
    $this->check_critical_files_hashes();
  }

  /**
   * Recursively scans the uploads folder for executable PHP files.
   */
  public function scan_uploads_for_php() {
    $upload_dir = wp_upload_dir();
    $basedir    = $upload_dir['basedir'];

    if (!is_dir($basedir)) {
      return;
    }

    $directory       = new RecursiveDirectoryIterator($basedir, RecursiveDirectoryIterator::SKIP_DOTS);
    $iterator        = new RecursiveIteratorIterator($directory);
    $found_php_files = array();

    foreach ($iterator as $file) {
      $ext = strtolower($file->getExtension());
      if ('.htaccess' === $file->getFilename()) {
        continue;
      }

      if (in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'suspected'), true)) {
        $found_php_files[] = $file->getPathname();
      }
    }

    if (!empty($found_php_files)) {
      $file_list = implode(', ', array_slice($found_php_files, 0, 5));
      $count     = count($found_php_files);

      WebDmitriev_Protection::log_event(
        'suspicious_php_in_uploads',
        sprintf(
          /* translators: 1: Count of PHP files found, 2: Comma-separated list of file paths */
          __('Detected %1$d executable PHP file(s) in uploads directory! Sample: %2$s', 'webdmitriev-protection'),
          $count,
          $file_list
        ),
        'LOCAL',
        'critical'
      );
    }
  }

  /**
   * Checks critical system files against standard hashes.
   *
   * @return bool
   */
  public function check_critical_files_hashes() {
    $critical_files = array(
      'wp_config'     => ABSPATH . 'wp-config.php',
      'root_htaccess' => ABSPATH . '.htaccess',
    );

    $has_modifications = false;

    foreach ($critical_files as $key => $file_path) {
      if (!file_exists($file_path)) {
        continue;
      }

      $current_hash = md5_file($file_path);
      $option_name  = 'webdmitriev_protection_hash_' . $key;
      $saved_hash   = get_option($option_name);

      if (!$saved_hash) {
        update_option($option_name, $current_hash);
      } elseif ($saved_hash !== $current_hash) {
        $has_modifications = true;

        update_option('webdmitriev_protection_modified_' . $key, true);

        WebDmitriev_Protection::log_event(
          'critical_file_modified',
          sprintf(
            /* translators: %s: File name */
            __('Critical file modification detected: %s', 'webdmitriev-protection'),
            basename($file_path)
          ),
          'LOCAL',
          'critical'
        );
      }
    }

    return $has_modifications;
  }

  /**
   * Re-approves file hashes after planned administrative modifications.
   */
  public static function approve_file_hashes() {
    $critical_files = array(
      'wp_config'     => ABSPATH . 'wp-config.php',
      'root_htaccess' => ABSPATH . '.htaccess',
    );

    foreach ($critical_files as $key => $file_path) {
      if (file_exists($file_path)) {
        update_option('webdmitriev_protection_hash_' . $key, md5_file($file_path));
        delete_option('webdmitriev_protection_modified_' . $key);
      }
    }
  }
}