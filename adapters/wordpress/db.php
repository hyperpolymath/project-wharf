<?php
/**
 * Wharf Database Drop-in for WordPress
 *
 * This file replaces WordPress's default database driver with a proxy
 * that routes queries through the Yacht Agent for security enforcement.
 *
 * Installation:
 *   1. Copy this file to wp-content/db.php
 *   2. Ensure the Yacht Agent is running on 127.0.0.1:3307
 *
 * The Yacht Agent:
 *   - Parses SQL queries using an AST (not regex!)
 *   - Enforces the "Virtual Sharding" policy from Nickel config
 *   - Blocks writes to immutable tables (wp_users, wp_options, etc.)
 *   - Allows writes to content tables (wp_comments, orders, etc.)
 *
 * @package Wharf
 * @version 0.1.0
 */

// Only load if WordPress is requesting database access
if (!defined('ABSPATH')) {
    die('Direct access not permitted.');
}

/**
 * Wharf Database Connection
 *
 * Routes database connections through the Yacht Agent proxy.
 */
class Wharf_DB extends wpdb {

    /**
     * The proxy host (Yacht Agent)
     */
    const PROXY_HOST = '127.0.0.1';

    /**
     * The proxy port (Yacht Agent listens here)
     */
    const PROXY_PORT = 3307;

    /**
     * Whether to enable debug logging
     */
    const DEBUG = false;

    /**
     * Connect to the database via the Yacht Agent proxy.
     *
     * @param bool $allow_bail Optional. Allows the function to bail.
     * @return bool True on success, false on failure.
     */
    public function db_connect($allow_bail = true) {
        $this->is_mysql = true;

        // Override the host to route through the Yacht Agent
        $host = self::PROXY_HOST . ':' . self::PROXY_PORT;

        if (self::DEBUG) {
            error_log('[Wharf] Connecting via proxy: ' . $host);
        }

        // Check if mysqli extension is available
        if (function_exists('mysqli_connect')) {
            $this->dbh = mysqli_init();

            // Set connection timeout
            mysqli_options($this->dbh, MYSQLI_OPT_CONNECT_TIMEOUT, 10);

            // Connect to the proxy
            $connected = @mysqli_real_connect(
                $this->dbh,
                self::PROXY_HOST,
                $this->dbuser,
                $this->dbpassword,
                null,
                self::PROXY_PORT,
                null,
                MYSQLI_CLIENT_FOUND_ROWS
            );

            if (!$connected) {
                $this->dbh = null;

                if (self::DEBUG) {
                    error_log('[Wharf] Connection failed: ' . mysqli_connect_error());
                }

                if ($allow_bail) {
                    $this->bail(
                        sprintf(
                            '<h1>Error establishing a database connection</h1>' .
                            '<p>The Wharf Yacht Agent may not be running. ' .
                            'Expected proxy at %s:%d</p>',
                            self::PROXY_HOST,
                            self::PROXY_PORT
                        )
                    );
                }

                return false;
            }

            // Select the database
            if ($this->dbname) {
                if (!mysqli_select_db($this->dbh, $this->dbname)) {
                    if (self::DEBUG) {
                        error_log('[Wharf] Database selection failed: ' . $this->dbname);
                    }
                    return false;
                }
            }

            // Set charset
            $this->set_charset($this->dbh);

            $this->ready = true;

            if (self::DEBUG) {
                error_log('[Wharf] Database connection established via proxy');
            }

            return true;
        }

        return false;
    }

    /**
     * Log query for debugging (only in debug mode)
     *
     * @param string $query The SQL query.
     */
    protected function log_query($query) {
        if (self::DEBUG) {
            // Truncate long queries for logging
            $log_query = strlen($query) > 500 ? substr($query, 0, 500) . '...' : $query;
            error_log('[Wharf Query] ' . $log_query);
        }
    }

    /**
     * Perform a query with Wharf logging.
     *
     * @param string $query The SQL query.
     * @return int|bool Number of rows affected/selected or false on error.
     */
    public function query($query) {
        $this->log_query($query);
        return parent::query($query);
    }
}

// Replace the global $wpdb with our Wharf version
$wpdb = new Wharf_DB(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
