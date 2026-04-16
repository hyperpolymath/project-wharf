# Generic LAMP Filesystem Policy for Wharf
#
# For custom PHP applications that don't use a standard CMS.
# This provides a sensible default that can be customized.

{
  adapter = "generic-lamp",
  version = "0.1.0",

  description = "Generic policy for custom PHP applications",

  paths = {
    # Web root - immutable by default
    web_root = {
      path = "/var/www/html",
      policy = "read_only",
    },

    # Common writable directories (customize per app)
    writable_dirs = [
      {
        path = "/var/www/html/uploads",
        writable = true,
        php_execution = false,
        create_if_missing = true,
      },
      {
        path = "/var/www/html/cache",
        writable = true,
        php_execution = false,
        volatile = true,
      },
      {
        path = "/var/www/html/logs",
        writable = true,
        php_execution = false,
      },
      {
        path = "/tmp/php-sessions",
        writable = true,
        php_execution = false,
        volatile = true,
      },
    ],

    # Files to protect
    protected_files = [
      ".env",
      "config.php",
      "config.ini",
      "settings.php",
      ".htaccess",
      ".htpasswd",
      "composer.json",
      "composer.lock",
    ],
  },

  # Generic database protection
  database = {
    # Tables containing user credentials - always lock
    lock_patterns = [
      ".*users.*",
      ".*admins.*",
      ".*credentials.*",
      ".*passwords.*",
      ".*tokens.*",
      ".*sessions.*",
      ".*config.*",
      ".*settings.*",
    ],

    # Tables likely to be content - allow writes
    allow_patterns = [
      ".*posts.*",
      ".*comments.*",
      ".*messages.*",
      ".*logs.*",
      ".*cache.*",
    ],
  },

  # Generic security headers
  headers = {
    strip = ["Server", "X-Powered-By"],
    add = {
      "X-Frame-Options" = "DENY",
      "X-Content-Type-Options" = "nosniff",
      "X-XSS-Protection" = "1; mode=block",
    },
  },
}
