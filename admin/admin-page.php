<?php
/**
 * Admin view for WebDmitriev Protection plugin.
 *
 * @package WebDmitriev_Protection
 */

if (!defined('ABSPATH')) {
  exit;
}

// Данные передаются из главного класса через переменные: $logs, $htaccess_changed, $wpconfig_changed, $blacklisted_ips
?>
<div class="wrap">
  <h1><?php esc_html_e('WebDmitriev Protection — Уведомления и Управление', 'webdmitriev-protection'); ?></h1>

  <?php if (isset($_GET['scanned'])): ?>
    <div class="notice notice-success is-dismissible">
      <p><?php esc_html_e('Сканирование файлов успешно завершено!', 'webdmitriev-protection'); ?></p>
    </div>
  <?php endif; ?>

  <?php if (isset($_GET['approved'])): ?>
    <div class="notice notice-success is-dismissible">
      <p><?php esc_html_e('Новые версии файлов утверждены как эталонные!', 'webdmitriev-protection'); ?></p>
    </div>
  <?php endif; ?>

  <?php if (isset($_GET['saved_ips'])): ?>
    <div class="notice notice-success is-dismissible">
      <p><?php esc_html_e('Черный список IP-адресов обновлен!', 'webdmitriev-protection'); ?></p>
    </div>
  <?php endif; ?>

  <?php if ($htaccess_changed || $wpconfig_changed): ?>
    <div class="notice notice-warning" style="border-left-color: #ffb900; padding: 12px 15px;">
      <p style="margin: 0 0 10px 0; font-size: 14px;">
        <strong><?php esc_html_e('⚠️ Зафиксированы изменения в критических файлах!', 'webdmitriev-protection'); ?></strong><br>
        <?php 
          printf(
            /* translators: 1: .htaccess file name, 2: wp-config.php file name */
            esc_html__('Если вы проводили запланированные работы по правке %1$s или %2$s, нажмите кнопку ниже, чтобы утвердить их.', 'webdmitriev-protection'),
            '<code>.htaccess</code>',
            '<code>wp-config.php</code>'
          ); 
        ?>
      </p>
      <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="wd_approve_hashes">
        <?php wp_nonce_field('wd_approve_hashes_action', 'wd_approve_hashes_nonce'); ?>
        <button type="submit" class="button button-primary"><?php esc_html_e('Принять текущие изменения как эталон', 'webdmitriev-protection'); ?></button>
      </form>
    </div>
  <?php endif; ?>

  <div style="display: flex; gap: 10px; margin-bottom: 20px;">
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
      <input type="hidden" name="action" value="wd_run_manual_scan">
      <?php wp_nonce_field('wd_scan_action', 'wd_scan_nonce'); ?>
      <button type="submit" class="button button-secondary"><?php esc_html_e('Запустить сканирование файлов', 'webdmitriev-protection'); ?></button>
    </form>

    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
      <input type="hidden" name="action" value="wd_clear_logs">
      <?php wp_nonce_field('wd_clear_logs_action', 'wd_clear_logs_nonce'); ?>
      <button type="submit" class="button button-secondary"><?php esc_html_e('Очистить лог', 'webdmitriev-protection'); ?></button>
    </form>
  </div>

  <!-- ТАБЛИЦА ЛОГОВ -->
  <h2><?php esc_html_e('Лог событий и угроз', 'webdmitriev-protection'); ?></h2>
  <table class="wp-list-table widefat fixed striped" style="margin-bottom: 30px;">
    <thead>
      <tr>
        <th style="width: 160px;"><?php esc_html_e('Дата', 'webdmitriev-protection'); ?></th>
        <th style="width: 100px;"><?php esc_html_e('Уровень', 'webdmitriev-protection'); ?></th>
        <th style="width: 180px;"><?php esc_html_e('Тип', 'webdmitriev-protection'); ?></th>
        <th style="width: 130px;"><?php esc_html_e('IP-адрес', 'webdmitriev-protection'); ?></th>
        <th><?php esc_html_e('Сообщение', 'webdmitriev-protection'); ?></th>
      </tr>
    </thead>
    <tbody>
      <?php if (empty($logs)): ?>
        <tr><td colspan="5"><?php esc_html_e('Подозрительных событий не зафиксировано.', 'webdmitriev-protection'); ?></td></tr>
      <?php else: ?>
        <?php foreach ($logs as $log): ?>
          <?php $severity_color = ($log->severity === 'critical') ? '#d63638' : '#dba617'; ?>
          <tr>
            <td><?php echo esc_html($log->created_at); ?></td>
            <td>
              <span style="color: <?php echo esc_attr($severity_color); ?>; font-weight: bold;">
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

  <!-- НАСТРОЙКА ЧЕРНОГО СПИСКА IP -->
  <h2><?php esc_html_e('Черный список IP-адресов (Firewall)', 'webdmitriev-protection'); ?></h2>
  <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="max-width: 600px;">
    <input type="hidden" name="action" value="wd_save_blacklist">
    <?php wp_nonce_field('wd_save_blacklist_action', 'wd_save_blacklist_nonce'); ?>

    <p><?php esc_html_e('Укажите IP-адреса для блокировки (каждый с новой строки):', 'webdmitriev-protection'); ?></p>
    <textarea name="blacklisted_ips" rows="5" class="large-text code"><?php echo esc_textarea(implode("\n", $blacklisted_ips)); ?></textarea>

    <p style="margin-top: 10px;">
      <button type="submit" class="button button-primary"><?php esc_html_e('Сохранить черный список', 'webdmitriev-protection'); ?></button>
    </p>
  </form>
</div>