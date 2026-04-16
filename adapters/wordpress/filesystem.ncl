# WordPress Filesystem Policy for Wharf
#
# This configuration defines which paths are writable in a WordPress installation.
# The Yacht Agent enforces these rules to prevent code injection attacks.

{
  adapter = "wordpress",
  version = "0.1.0",

  # WordPress-specific path mappings
  paths = {
    # Core WordPress files (ALWAYS immutable)
    immutable = [
      "/wp-admin",
      "/wp-includes",
      "/index.php",
      "/wp-config.php",
      "/wp-settings.php",
      "/wp-load.php",
      "/wp-blog-header.php",
      "/wp-cron.php",
      "/wp-login.php",
      "/wp-signup.php",
      "/xmlrpc.php",  # Consider disabling entirely
      "/.htaccess",
    ],

    # Theme files (immutable in production)
    # Change via Wharf mooring only
    themes_immutable = true,
    themes_path = "/wp-content/themes",

    # Plugin files (immutable in production)
    # Install/update via Wharf mooring only
    plugins_immutable = true,
    plugins_path = "/wp-content/plugins",

    # Must-Use plugins (immutable)
    mu_plugins_path = "/wp-content/mu-plugins",

    # Uploads (writable, but no PHP execution)
    uploads = {
      path = "/wp-content/uploads",
      writable = true,
      php_execution = false,
      htaccess_override = false,

      # Scan uploads for malicious content
      virus_scan = true,

      # Block dangerous extensions
      blocked_extensions = [
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".exe", ".sh", ".bat", ".cmd",
        ".htaccess", ".htpasswd",
      ],
    },

    # Cache directory (writable, volatile - RAM disk recommended)
    cache = {
      path = "/wp-content/cache",
      writable = true,
      php_execution = false,
      volatile = true,  # OK to wipe on restart
    },

    # Upgrade directory (writable during mooring only)
    upgrade = {
      path = "/wp-content/upgrade",
      writable_during_mooring = true,
      writable_normally = false,
    },

    # Debug log (writable, but no PHP execution)
    debug_log = {
      path = "/wp-content/debug.log",
      writable = true,
      php_execution = false,
    },
  },

  # wp-config.php hardening
  wp_config = {
    # These constants should be set and locked
    required_constants = [
      "DISALLOW_FILE_EDIT",      # Disable theme/plugin editor
      "DISALLOW_FILE_MODS",      # Disable plugin/theme install/update (via WP admin)
      "WP_AUTO_UPDATE_CORE",     # Control auto-updates
    ],

    # Recommended values (enforced by Wharf)
    enforced_values = {
      "DISALLOW_FILE_EDIT" = true,
      "DISALLOW_FILE_MODS" = true,
      "WP_AUTO_UPDATE_CORE" = false,
      "AUTOMATIC_UPDATER_DISABLED" = true,
      "WP_DEBUG" = false,
      "WP_DEBUG_LOG" = false,
      "WP_DEBUG_DISPLAY" = false,
      "SCRIPT_DEBUG" = false,
    },
  },

  # .htaccess rules to inject (Apache)
  htaccess = {
    # Block PHP execution in uploads
    uploads_block = '''
<Directory /wp-content/uploads>
    <FilesMatch "\.ph(p[345]?|tml)$">
        Require all denied
    </FilesMatch>
    php_flag engine off
</Directory>
''',

    # Block direct access to sensitive files
    security_block = '''
# Block access to sensitive files
<FilesMatch "^(wp-config\.php|readme\.html|license\.txt|xmlrpc\.php)$">
    Require all denied
</FilesMatch>

# Block access to hidden files
<FilesMatch "^\\.">
    Require all denied
</FilesMatch>
''',
  },

  # Nginx rules (if using Nginx instead of Apache)
  nginx = {
    # Block PHP in uploads
    uploads_block = '''
location ~* /wp-content/uploads/.*\.php$ {
    deny all;
}
''',

    # Block sensitive files
    security_block = '''
location ~* /(wp-config\.php|readme\.html|license\.txt|xmlrpc\.php)$ {
    deny all;
}

location ~ /\. {
    deny all;
}
''',
  },
}
