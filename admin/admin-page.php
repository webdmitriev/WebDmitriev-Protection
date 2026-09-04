<?php
/**
 * Admin view for WebDmitriev Protection plugin.
 *
 * @package WebDmitriev_Protection
 */

if (!defined('ABSPATH')) {
  exit;
}

// Data passed from main class: $logs, $htaccess_changed, $wpconfig_changed, $blacklisted_ips
?>
<div class="wrap">
  <h1><?php esc_html_e('WebDmitriev Protection — Notifications & Settings', 'webdmitriev-protection'); ?></h1>

  <?php if (isset($_GET['scanned']) && '1' === sanitize_text_field(wp_unslash($_GET['scanned']))): ?>
    <div class="notice notice-success is-dismissible">
      <p><?php esc_html_e('File scan successfully completed!', 'webdmitriev-protection'); ?></p>
    </div>
  <?php endif; ?>

  <?php if (isset($_GET['approved']) && '1' === sanitize_text_field(wp_unslash($_GET['approved']))): ?>
    <div class="notice notice-success is-dismissible">
      <p><?php esc_html_e('New versions of files have been approved as reference!', 'webdmitriev-protection'); ?></p>
    </div>
  <?php endif; ?>

  <?php if (isset($_GET['saved_ips']) && '1' === sanitize_text_field(wp_unslash($_GET['saved_ips']))): ?>
    <div class="notice notice-success is-dismissible">
      <p><?php esc_html_e('The blacklist of IP addresses has been updated!', 'webdmitriev-protection'); ?></p>
    </div>
  <?php endif; ?>

  <?php if ($htaccess_changed || $wpconfig_changed): ?>
    <div class="notice notice-warning" style="border-left-color: #ffb900; padding: 12px 15px;">
      <p style="margin: 0 0 10px 0; font-size: 14px;">
        <strong><?php esc_html_e('⚠️ Changes have been recorded in critical files!', 'webdmitriev-protection'); ?></strong><br>
        <?php 
          printf(
            /* translators: 1: .htaccess file name, 2: wp-config.php file name */
            esc_html__('If you have completed scheduled edits on %1$s or %2$s, please click the button below to approve them.', 'webdmitriev-protection'),
            '<code>.htaccess</code>',
            '<code>wp-config.php</code>'
          ); 
        ?>
      </p>
      <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="webdmitriev_protection_approve_hashes">
        <?php wp_nonce_field('webdmitriev_protection_approve_hashes_action', 'webdmitriev_protection_approve_hashes_nonce'); ?>
        <button type="submit" class="button button-primary"><?php esc_html_e('Accept current changes as a standard', 'webdmitriev-protection'); ?></button>
      </form>
    </div>
  <?php endif; ?>

  <div style="display: flex; gap: 10px; margin-bottom: 20px;">
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
      <input type="hidden" name="action" value="webdmitriev_protection_run_manual_scan">
      <?php wp_nonce_field('webdmitriev_protection_scan_action', 'webdmitriev_protection_scan_nonce'); ?>
      <button type="submit" class="button button-secondary"><?php esc_html_e('Start scanning files', 'webdmitriev-protection'); ?></button>
    </form>

    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
      <input type="hidden" name="action" value="webdmitriev_protection_clear_logs">
      <?php wp_nonce_field('webdmitriev_protection_clear_logs_action', 'webdmitriev_protection_clear_logs_nonce'); ?>
      <button type="submit" class="button button-secondary"><?php esc_html_e('Clear log', 'webdmitriev-protection'); ?></button>
    </form>
  </div>

  <!-- EVENT LOG TABLE -->
  <h2><?php esc_html_e('Event and Threat Log', 'webdmitriev-protection'); ?></h2>
  <table class="wp-list-table widefat fixed striped" style="margin-bottom: 30px;">
    <thead>
      <tr>
        <th style="width: 160px;"><?php esc_html_e('Date', 'webdmitriev-protection'); ?></th>
        <th style="width: 100px;"><?php esc_html_e('Severity', 'webdmitriev-protection'); ?></th>
        <th style="width: 180px;"><?php esc_html_e('Type', 'webdmitriev-protection'); ?></th>
        <th style="width: 130px;"><?php esc_html_e('IP Address', 'webdmitriev-protection'); ?></th>
        <th><?php esc_html_e('Message', 'webdmitriev-protection'); ?></th>
      </tr>
    </thead>
    <tbody>
      <?php if (empty($logs)): ?>
        <tr><td colspan="5"><?php esc_html_e('No suspicious events recorded.', 'webdmitriev-protection'); ?></td></tr>
      <?php else: ?>
        <?php foreach ($logs as $log): ?>
          <?php $severity_color = ('critical' === $log->severity) ? '#d63638' : '#dba617'; ?>
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

  <!-- IP BLACKLIST FORM -->
  <h2><?php esc_html_e('Blacklist of IP addresses (Firewall)', 'webdmitriev-protection'); ?></h2>
  <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="max-width: 600px;">
    <input type="hidden" name="action" value="webdmitriev_protection_save_blacklist">
    <?php wp_nonce_field('webdmitriev_protection_save_blacklist_action', 'webdmitriev_protection_save_blacklist_nonce'); ?>

    <p><?php esc_html_e('Specify the IP addresses to block (each on a new line):', 'webdmitriev-protection'); ?></p>
    <textarea name="blacklisted_ips" rows="5" class="large-text code"><?php echo esc_textarea(implode("\n", is_array($blacklisted_ips) ? $blacklisted_ips : array())); ?></textarea>

    <p style="margin-top: 10px;">
      <button type="submit" class="button button-primary"><?php esc_html_e('Save blacklist', 'webdmitriev-protection'); ?></button>
    </p>
  </form>
</div>