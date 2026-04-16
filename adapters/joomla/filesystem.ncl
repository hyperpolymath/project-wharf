# Joomla Filesystem Policy for Wharf
#
# Joomla is architecturally similar to WordPress (monolithic design).
# configuration.php is the equivalent of wp-config.php.

{
  adapter = "joomla",
  version = "0.1.0",

  paths = {
    # Core Joomla files (ALWAYS immutable)
    immutable = [
      "/administrator",
      "/api",
      "/cli",
      "/components",
      "/includes",
      "/installation",  # Should be removed after setup
      "/language",
      "/layouts",
      "/libraries",
      "/modules",
      "/plugins",
      "/index.php",
      "/configuration.php",
      "/.htaccess",
      "/web.config",
      "/robots.txt",
    ],

    # Templates (immutable in production)
    templates_immutable = true,
    templates_path = "/templates",

    # Media directory (writable, no PHP execution)
    media = {
      path = "/media",
      writable = true,
      php_execution = false,

      # Most media is Joomla's own assets - be careful
      subdirs_writable = [
        "/media/com_content",
        "/media/editors",
      ],
    },

    # Images directory (writable, no PHP execution)
    images = {
      path = "/images",
      writable = true,
      php_execution = false,

      blocked_extensions = [
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".exe", ".sh", ".bat", ".cmd",
        ".htaccess", ".htpasswd",
      ],
    },

    # Cache directory (writable, volatile)
    cache = {
      path = "/cache",
      writable = true,
      php_execution = false,
      volatile = true,
    },

    # Logs directory (writable, no PHP execution)
    logs = {
      path = "/administrator/logs",
      writable = true,
      php_execution = false,
    },

    # Temporary directory (writable, volatile)
    tmp = {
      path = "/tmp",
      writable = true,
      php_execution = false,
      volatile = true,
    },
  },

  # Joomla-specific database tables
  database = {
    # Tables to lock down
    lock_down = [
      "#__users",
      "#__user_usergroup_map",
      "#__usergroups",
      "#__extensions",
      "#__menu",
      "#__menu_types",
      "#__modules",
      "#__modules_menu",
      "#__template_styles",
    ],

    # Tables to allow writes
    allow_write = [
      "#__content",
      "#__contentitem_tag_map",
      "#__contact_details",
      "#__categories",
      "#__tags",
      "#__session",
      "#__user_keys",
    ],

    # Hybrid rules (similar to WordPress wp_options)
    hybrid = {
      table = "#__extensions",
      rules = [
        {
          action = "deny",
          column = "name",
          matches = ".*",
          comment = "Extension changes require Wharf mooring",
        },
      ],
    },
  },
}
