<?php
/**
 * Wharf Settings Override for Drupal
 *
 * Include this file at the end of your settings.php:
 *   include_once '/path/to/wharf/adapters/drupal/settings.php';
 *
 * This configures Drupal to work with the Wharf/Yacht security model:
 *   - Routes database through the Yacht Agent proxy
 *   - Disables dangerous features in production
 *   - Enforces read-only filesystem policies
 *
 * @package Wharf
 * @version 0.1.0
 */

// Ensure we're being included from Drupal
if (!defined('DRUPAL_ROOT')) {
  die('This file must be included from Drupal settings.php');
}

/**
 * Wharf Database Configuration
 *
 * Override the database connection to route through the Yacht Agent proxy.
 */
$databases['default']['default'] = [
  'database' => getenv('DRUPAL_DB_NAME') ?: 'drupal',
  'username' => getenv('DRUPAL_DB_USER') ?: 'drupal',
  'password' => getenv('DRUPAL_DB_PASS') ?: '',
  'host' => '127.0.0.1',  // Yacht Agent proxy
  'port' => '3307',       // Yacht Agent port
  'driver' => 'mysql',
  'prefix' => '',
  'collation' => 'utf8mb4_general_ci',
  'init_commands' => [
    'isolation_level' => "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED",
  ],
];

/**
 * Wharf Security Settings
 *
 * These settings lock down Drupal for production use with Wharf.
 */

// Disable update module functionality (updates via Wharf only)
$config['update.settings']['check']['disabled_extensions'] = TRUE;

// Disable file system changes via UI
$settings['file_chmod_directory'] = 0755;
$settings['file_chmod_file'] = 0644;

// Trusted host patterns (prevents host header injection)
// IMPORTANT: Update these to match your actual domains
$settings['trusted_host_patterns'] = [
  '^example\.com$',
  '^staging\.example\.com$',
  '^localhost$',
];

// Disable error display in production
$config['system.logging']['error_level'] = 'hide';

// Private file path (outside web root)
$settings['file_private_path'] = '/var/private/drupal';

// Config sync directory (managed by Wharf)
$settings['config_sync_directory'] = '/var/config/drupal/sync';

// Disable rebuild access (security)
$settings['rebuild_access'] = FALSE;

// Hash salt (should be unique per installation - set via environment)
$settings['hash_salt'] = getenv('DRUPAL_HASH_SALT') ?: 'CHANGE_THIS_TO_A_RANDOM_STRING';

/**
 * Wharf-specific flags
 *
 * These are read by the Yacht Agent to understand Drupal's state.
 */
$settings['wharf'] = [
  'enabled' => TRUE,
  'adapter_version' => '0.1.0',
  'moored' => FALSE,  // Set to TRUE during mooring operations
];

/**
 * Production performance settings
 */
$config['system.performance']['css']['preprocess'] = TRUE;
$config['system.performance']['js']['preprocess'] = TRUE;
$config['system.performance']['cache']['page']['max_age'] = 3600;

/**
 * Disable dangerous modules in production
 *
 * These modules should only be enabled during development or via Wharf mooring.
 */
$settings['wharf_disabled_modules'] = [
  'devel',
  'kint',
  'webprofiler',
  'update',
  'dblog',  // Use syslog instead
];
