<?php
/**
 * Вызывается при полном удалении плагина через админ-панель WordPress.
 *
 * @package WebDmitriev_Protection
 */

// Если файл вызван напрямую, а не через WordPress — выходим
if (!defined('WP_UNINSTALL_PLUGIN')) {
  exit;
}

global $wpdb;

// 1. Удаление пользовательской таблицы логов
$table_name = $wpdb->prefix . 'wd_protection_logs';
$wpdb->query("DROP TABLE IF EXISTS {$table_name}"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// 2. Удаление всех опций плагина из таблицы wp_options
$options_to_delete = array(
  'wd_prot_modified_root_htaccess',
  'wd_prot_modified_wp_config',
  'wd_prot_root_htaccess_hash',
  'wd_prot_wp_config_hash',
  'wd_prot_blacklisted_ips',
);

foreach ($options_to_delete as $option) {
  delete_option($option);
}

// 3. Удаление всех транзиентов (временных записей блокировки писем и т.д.)
$wpdb->query(
  "DELETE FROM {$wpdb->options} 
   WHERE option_name LIKE '_transient_wd_prot_%' 
   OR option_name LIKE '_transient_timeout_wd_prot_%'"
); // phpcs:ignore WordPress.DB.DirectDatabaseQuery

// 4. Очистка запланированных задач (Cron) на случай, если крон не был снят при деактивации
wp_clear_scheduled_hook('wd_daily_file_integrity_check');