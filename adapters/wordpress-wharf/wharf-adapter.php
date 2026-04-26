<?php
/**
 * Plugin Name: Wharf Security Adapter
 * Plugin URI: https://github.com/hyperpolymath/project-wharf
 * Description: Dashboard widget and status display for sites protected by Project Wharf (yacht-agent).
 * Version: 1.0.0
 * Author: Jonathan D.A. Jewell
 * Author URI: https://github.com/hyperpolymath
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wharf-adapter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This plugin is a thin adapter — it does NO security work itself.
 * All security enforcement is handled by the yacht-agent (a separate Rust daemon).
 * This plugin simply reads status from the agent's API and displays it in wp-admin.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WHARF_ADAPTER_VERSION', '1.0.0');
define('WHARF_AGENT_URL', getenv('WHARF_AGENT_URL') ?: 'http://localhost:9001');

/**
 * Register the dashboard widget
 */
function wharf_add_dashboard_widget() {
    wp_add_dashboard_widget(
        'wharf_security_status',
        'Wharf Security Status',
        'wharf_render_dashboard_widget'
    );
}
add_action('wp_dashboard_setup', 'wharf_add_dashboard_widget');

/**
 * Fetch stats and status from yacht-agent API
 *
 * Merges /stats (query counters) and /status (mooring, components) into a
 * flat array the dashboard widget expects.
 *
 * /stats returns: {"queries":{"allowed":N,"blocked":N,"audited":N},"mooring_sessions":N,"integrity_checks":N}
 * /status returns: {"status":"active","moored":bool,"version":"...","components":{...}}
 */
function wharf_fetch_agent_stats() {
    $cache_key = 'wharf_agent_stats';
    $cached = get_transient($cache_key);
    if ($cached !== false) {
        return $cached;
    }

    $request_args = array('timeout' => 3, 'sslverify' => false);

    // Fetch /stats
    $stats_response = wp_remote_get(WHARF_AGENT_URL . '/stats', $request_args);
    if (is_wp_error($stats_response)) {
        return array('error' => $stats_response->get_error_message());
    }
    $stats_data = json_decode(wp_remote_retrieve_body($stats_response), true);
    if (!is_array($stats_data)) {
        return array('error' => 'Invalid response from yacht-agent /stats');
    }

    // Fetch /status
    $status_response = wp_remote_get(WHARF_AGENT_URL . '/status', $request_args);
    if (is_wp_error($status_response)) {
        return array('error' => $status_response->get_error_message());
    }
    $status_data = json_decode(wp_remote_retrieve_body($status_response), true);
    if (!is_array($status_data)) {
        return array('error' => 'Invalid response from yacht-agent /status');
    }

    // Map nested responses to flat format for the widget
    $merged = array(
        'queries_allowed' => isset($stats_data['queries']['allowed']) ? $stats_data['queries']['allowed'] : 0,
        'queries_blocked' => isset($stats_data['queries']['blocked']) ? $stats_data['queries']['blocked'] : 0,
        'queries_audited' => isset($stats_data['queries']['audited']) ? $stats_data['queries']['audited'] : 0,
        'moored'          => !empty($status_data['moored']),
        'firewall_mode'   => isset($status_data['components']['shield']) ? $status_data['components']['shield'] : 'unknown',
        'signature_scheme' => 'ed25519',
        'version'         => isset($status_data['version']) ? $status_data['version'] : 'unknown',
    );

    set_transient($cache_key, $merged, 30);
    return $merged;
}

/**
 * Render the dashboard widget
 */
function wharf_render_dashboard_widget() {
    $stats = wharf_fetch_agent_stats();

    if (isset($stats['error'])) {
        echo '<p style="color:#d63638"><strong>Agent Unreachable:</strong> ';
        echo esc_html($stats['error']);
        echo '</p>';
        echo '<p>Ensure yacht-agent is running at <code>' . esc_html(WHARF_AGENT_URL) . '</code></p>';
        return;
    }

    $queries_allowed = isset($stats['queries_allowed']) ? intval($stats['queries_allowed']) : 0;
    $queries_blocked = isset($stats['queries_blocked']) ? intval($stats['queries_blocked']) : 0;
    $moored = !empty($stats['moored']);
    $firewall = isset($stats['firewall_mode']) ? esc_html($stats['firewall_mode']) : 'unknown';
    $sig_scheme = isset($stats['signature_scheme']) ? esc_html($stats['signature_scheme']) : 'unknown';

    echo '<table class="widefat" style="border:0">';

    // Status indicator
    $status_color = $moored ? '#00a32a' : '#dba617';
    $status_label = $moored ? 'Moored (Connected)' : 'Unmoored (Standalone)';
    echo '<tr><td><strong>Status</strong></td>';
    echo '<td><span style="color:' . $status_color . '">&#9679;</span> ' . $status_label . '</td></tr>';

    // Query stats
    $total = $queries_allowed + $queries_blocked;
    echo '<tr><td><strong>DB Queries</strong></td>';
    echo '<td>' . number_format($total) . ' total (' . number_format($queries_blocked) . ' blocked)</td></tr>';

    // Firewall
    echo '<tr><td><strong>Firewall</strong></td>';
    echo '<td>' . $firewall . '</td></tr>';

    // Signature scheme
    echo '<tr><td><strong>Signatures</strong></td>';
    echo '<td>' . $sig_scheme . '</td></tr>';

    echo '</table>';

    echo '<p style="margin-top:12px;color:#757575;font-size:12px">';
    echo 'Protected by <a href="https://github.com/hyperpolymath/project-wharf" target="_blank">Project Wharf</a>';
    echo ' &mdash; The Sovereign Web Hypervisor';
    echo '</p>';
}

/**
 * Add admin bar indicator
 */
function wharf_admin_bar_item($admin_bar) {
    $stats = wharf_fetch_agent_stats();
    $is_healthy = !isset($stats['error']);

    $admin_bar->add_node(array(
        'id'    => 'wharf-status',
        'title' => ($is_healthy ? '&#9679; ' : '&#9675; ') . 'Wharf',
        'href'  => admin_url(),
        'meta'  => array(
            'title' => $is_healthy ? 'Wharf: Protected' : 'Wharf: Agent unreachable',
        ),
    ));
}
add_action('admin_bar_menu', 'wharf_admin_bar_item', 100);
