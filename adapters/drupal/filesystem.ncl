# Drupal Filesystem Policy for Wharf
#
# Drupal has a better separation of concerns than WordPress:
# - Public files in sites/default/files
# - Private files outside web root
# - Config in a separate sync directory
#
# This makes it easier to lock down.

{
  adapter = "drupal",
  version = "0.1.0",

  paths = {
    # Core Drupal files (ALWAYS immutable)
    immutable = [
      "/core",
      "/index.php",
      "/update.php",
      "/web.config",
      "/sites/default/settings.php",
      "/sites/default/services.yml",
      "/.htaccess",
    ],

    # Modules (immutable in production)
    modules_immutable = true,
    modules_paths = [
      "/modules/contrib",
      "/modules/custom",
      "/sites/all/modules",
    ],

    # Themes (immutable in production)
    themes_immutable = true,
    themes_paths = [
      "/themes/contrib",
      "/themes/custom",
      "/sites/all/themes",
    ],

    # Public files (writable, no PHP execution)
    public_files = {
      path = "/sites/default/files",
      writable = true,
      php_execution = false,
      htaccess_override = false,

      # Scan for malware
      virus_scan = true,

      # Block dangerous extensions
      blocked_extensions = [
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".exe", ".sh", ".bat", ".cmd",
        ".htaccess", ".htpasswd",
      ],
    },

    # Private files (outside web root)
    private_files = {
      path = "/var/private/drupal",
      writable = true,
      php_execution = false,
      web_accessible = false,
    },

    # Config sync directory
    config_sync = {
      path = "/var/config/drupal/sync",
      writable_during_mooring = true,
      writable_normally = false,
    },

    # Temporary files
    temp = {
      path = "/tmp/drupal",
      writable = true,
      php_execution = false,
      volatile = true,
    },
  },

  # Drupal-specific security settings
  security = {
    # Disable these features via settings.php
    disable_in_production = [
      "update_module",
      "devel_module",
      "views_ui_module",
    ],

    # Enforce these settings
    enforce = {
      "rebuild_access" = false,
      "error_level" = "hide",
    },
  },

  # .htaccess rules
  htaccess = {
    files_block = '''
<Directory /sites/default/files>
    <FilesMatch "\.ph(p[345]?|tml)$">
        Require all denied
    </FilesMatch>
    php_flag engine off
</Directory>
''',
  },
}
