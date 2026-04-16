# Moodle Filesystem Policy for Wharf
#
# Moodle has a security advantage: moodledata directory sits OUTSIDE the web root.
# This makes it easier to lock down than WordPress/Joomla.

{
  adapter = "moodle",
  version = "0.1.0",

  paths = {
    # Core Moodle files (ALWAYS immutable)
    # The entire web root should be read-only in production
    immutable = [
      "/admin",
      "/auth",
      "/backup",
      "/blocks",
      "/cache",
      "/calendar",
      "/cohort",
      "/comment",
      "/config.php",
      "/course",
      "/enrol",
      "/files",
      "/filter",
      "/grade",
      "/group",
      "/index.php",
      "/install",
      "/lib",
      "/local",
      "/login",
      "/message",
      "/mod",
      "/my",
      "/notes",
      "/pix",
      "/plagiarism",
      "/portfolio",
      "/question",
      "/rating",
      "/report",
      "/repository",
      "/rss",
      "/search",
      "/tag",
      "/theme",
      "/user",
      "/webservice",
    ],

    # Moodle Data Directory (OUTSIDE web root - this is the key!)
    # This directory is writable but not web-accessible
    moodledata = {
      path = "/var/moodledata",  # Must match $CFG->dataroot
      writable = true,
      web_accessible = false,
      php_execution = false,

      # Subdirectories
      subdirs = {
        "cache" = { writable = true, volatile = true },
        "filedir" = { writable = true },  # User uploads
        "lang" = { writable = true },
        "localcache" = { writable = true, volatile = true },
        "lock" = { writable = true },
        "muc" = { writable = true, volatile = true },
        "sessions" = { writable = true },
        "temp" = { writable = true, volatile = true },
        "trashdir" = { writable = true },
      },
    },
  },

  # Moodle config.php settings to enforce
  config = {
    # These should be set in config.php
    required = {
      "$CFG->directorypermissions" = "0755",
      "$CFG->disableupdatenotifications" = true,
      "$CFG->disableupdateautodeploy" = true,
      "$CFG->preventexecpath" = true,
    },

    # Security settings
    security = {
      # Force secure cookies
      "$CFG->cookiesecure" = true,

      # HTTP only cookies
      "$CFG->cookiehttponly" = true,

      # Disable admin via web in production
      "$CFG->preventscheduledtaskchanges" = true,
    },
  },

  # Moodle database tables
  database = {
    # Tables with hundreds of tables - key ones to lock
    lock_down = [
      "mdl_user",
      "mdl_config",
      "mdl_config_plugins",
      "mdl_role",
      "mdl_role_capabilities",
      "mdl_role_assignments",
      "mdl_context",
    ],

    # Content tables (allow writes)
    allow_write = [
      "mdl_forum_posts",
      "mdl_forum_discussions",
      "mdl_quiz_attempts",
      "mdl_assign_submission",
      "mdl_assign_grades",
      "mdl_log",
      "mdl_logstore_standard_log",
      "mdl_session",
    ],
  },
}
