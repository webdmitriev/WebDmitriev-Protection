<?php
if (!defined('ABSPATH')) {
  exit;
}

// Данные передаются из главного класса через переменные: $logs, $htaccess_changed, $wpconfig_changed, $blacklisted_ips
?>
<div class="wrap">
  <h1>WebDmitriev Protection — Уведомления и Управление</h1>

  <?php if (isset($_GET['scanned'])): ?>
    <div class="notice notice-success is-dismissible"><p>Сканирование файлов успешно завершено!</p></div>
  <?php endif; ?>

  <?php if (isset($_GET['approved'])): ?>
    <div class="notice notice-success is-dismissible"><p>Новые версии файлов утверждены как эталонные!</p></div>
  <?php endif; ?>

  <?php if (isset($_GET['saved_ips'])): ?>
    <div class="notice notice-success is-dismissible"><p>Черный список IP-адресов обновлен!</p></div>
  <?php endif; ?>

  <?php if ($htaccess_changed || $wpconfig_changed): ?>
    <div class="notice notice-warning" style="border-left-color: #ffb900; padding: 12px 15px;">
      <p style="margin: 0 0 10px 0; font-size: 14px;">
        <strong>⚠️ Зафиксированы изменения в критических файлах!</strong><br>
        Если вы проводили запланированные работы по правке <code>.htaccess</code> или <code>wp-config.php</code>, нажмите кнопку ниже, чтобы утвердить их.
      </p>
      <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="wd_approve_hashes">
        <?php wp_nonce_field('wd_approve_hashes_action', 'wd_approve_hashes_nonce'); ?>
        <button type="submit" class="button button-primary">Принять текущие изменения как эталон</button>
      </form>
    </div>
  <?php endif; ?>

  <div style="display: flex; gap: 10px; margin-bottom: 20px;">
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
      <input type="hidden" name="action" value="wd_run_manual_scan">
      <?php wp_nonce_field('wd_scan_action', 'wd_scan_nonce'); ?>
      <button type="submit" class="button button-secondary">Запустить сканирование файлов</button>
    </form>

    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
      <input type="hidden" name="action" value="wd_clear_logs">
      <?php wp_nonce_field('wd_clear_logs_action', 'wd_clear_logs_nonce'); ?>
      <button type="submit" class="button button-secondary">Очистить лог</button>
    </form>
  </div>

  <!-- ТАБЛИЦА ЛОГОВ -->
  <h2>Лог событий и угроз</h2>
  <table class="wp-list-table widefat fixed striped" style="margin-bottom: 30px;">
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
              <span style="color: <?php echo $log->severity === 'critical' ? '#d63638' : '#dba617'; ?>; font-weight: bold;">
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
  <h2>Черный список IP-адресов (Firewall)</h2>
  <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="max-width: 600px;">
    <input type="hidden" name="action" value="wd_save_blacklist">
    <?php wp_nonce_field('wd_save_blacklist_action', 'wd_save_blacklist_nonce'); ?>

    <p>Укажите IP-адреса для блокировки (каждый с новой строки):</p>
    <textarea name="blacklisted_ips" rows="5" class="large-text code"><?php echo esc_textarea(implode("\n", $blacklisted_ips)); ?></textarea>

    <p style="margin-top: 10px;">
      <button type="submit" class="button button-primary">Сохранить черный список</button>
    </p>
  </form>
</div>