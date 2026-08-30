<?php
if (!defined('ABSPATH')) {
  exit;
}

class WD_Protection_File_Guard {

  public function __construct() {
    add_action('admin_init', array($this, 'ensure_uploads_htaccess_protection'));
    add_action('wd_daily_file_integrity_check', array($this, 'run_daily_security_scan'));

    if (!wp_next_scheduled('wd_daily_file_integrity_check')) {
      wp_schedule_event(time(), 'daily', 'wd_daily_file_integrity_check');
    }
  }

  public function ensure_uploads_htaccess_protection() {
    $upload_dir = wp_upload_dir();
    $htaccess_file = trailingslashit($upload_dir['basedir']) . '.htaccess';

    $rules = "# BEGIN WD Protection Uploads Guard\n";
    $rules .= "<FilesMatch \"\.(?i:php|phtml|php3|php4|php5|php7|phps|suspected)$\">\n";
    $rules .= "    Order Allow,Deny\n";
    $rules .= "    Deny from all\n";
    $rules .= "</FilesMatch>\n";
    $rules .= "# END WD Protection Uploads Guard\n";

    if (!file_exists($htaccess_file)) {
      file_put_contents($htaccess_file, $rules);
    } else {
      $content = file_get_contents($htaccess_file);
      if (strpos($content, 'WD Protection Uploads Guard') === false) {
        file_put_contents($htaccess_file, $rules . "\n" . $content);
      }
    }
  }

  public function run_daily_security_scan() {
    $this->scan_uploads_for_php();
    $this->check_critical_files_hashes();
  }

  public function scan_uploads_for_php() {
    $upload_dir = wp_upload_dir();
    $basedir = $upload_dir['basedir'];

    if (!is_dir($basedir)) return;

    $directory = new RecursiveDirectoryIterator($basedir, RecursiveDirectoryIterator::SKIP_DOTS);
    $iterator = new RecursiveIteratorIterator($directory);
    $found_php_files = array();

    foreach ($iterator as $file) {
      $ext = strtolower($file->getExtension());
      if ($file->getFilename() === '.htaccess') continue;

      if (in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'suspected'))) {
        $found_php_files[] = $file->getPathname();
      }
    }

    if (!empty($found_php_files)) {
      $file_list = implode(", ", array_slice($found_php_files, 0, 5));
      $count = count($found_php_files);

      WebDmitriev_Protection::log_event(
        'suspicious_php_in_uploads',
        sprintf('Обнаружено %d PHP-файлов в папке uploads! Пакет: %s', $count, $file_list),
        'LOCAL',
        'critical'
      );
    }
  }

  public function check_critical_files_hashes() {
    $critical_files = array(
      'wp_config' => ABSPATH . 'wp-config.php',
      'root_htaccess' => ABSPATH . '.htaccess',
    );

    $has_modifications = false;

    foreach ($critical_files as $key => $file_path) {
      if (!file_exists($file_path)) continue;

      $current_hash = md5_file($file_path);
      $option_name = 'wd_prot_hash_' . $key;
      $saved_hash = get_option($option_name);

      if (!$saved_hash) {
        update_option($option_name, $current_hash);
      } elseif ($saved_hash !== $current_hash) {
        $has_modifications = true;

        // Сохраняем флаг модификации для вывода баннера в админке
        update_option('wd_prot_modified_' . $key, true);

        WebDmitriev_Protection::log_event(
          'critical_file_modified',
          sprintf('Файл %s был изменен!', basename($file_path)),
          'LOCAL',
          'critical'
        );
      }
    }

    return $has_modifications;
  }

  /**
   * Переутверждение хэшей после запланированных правок
   */
  public static function approve_file_hashes() {
    $critical_files = array(
      'wp_config' => ABSPATH . 'wp-config.php',
      'root_htaccess' => ABSPATH . '.htaccess',
    );

    foreach ($critical_files as $key => $file_path) {
      if (file_exists($file_path)) {
        update_option('wd_prot_hash_' . $key, md5_file($file_path));
        delete_option('wd_prot_modified_' . $key);
      }
    }
  }
}