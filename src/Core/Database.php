<?php
declare(strict_types=1);

namespace DPXL\Shield\Core;

class Database {

    private const SCHEMA_VERSION_OPTION = 'dpxl_shield_db_version';
    private const SCHEMA_VERSION = '1.2.0';

    public static function createTables(): void {
        global $wpdb;

        $charset = $wpdb->get_charset_collate();

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $tables = self::getTableDefinitions($wpdb->prefix, $charset);

        foreach ($tables as $sql) {
            dbDelta($sql);
        }

        self::runMigrations($wpdb);

        update_option(self::SCHEMA_VERSION_OPTION, self::SCHEMA_VERSION);
    }

    /**
     * Idempotent ALTERs for changes dbDelta cannot apply on existing tables.
     *
     * dbDelta only adds columns/indexes — it never modifies an existing column
     * definition, so extending an ENUM must be done explicitly. MODIFY to the
     * full, current ENUM is safe to run repeatedly.
     */
    private static function runMigrations(\wpdb $wpdb): void {
        $scanResults = $wpdb->prefix . 'dpxl_shield_scan_results';

        // Schema 1.1.0: add 'vulnerable_version' to scan_results.issue_type.
        if (self::tableExists($wpdb, $scanResults)) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query(
                "ALTER TABLE `{$scanResults}`
                 MODIFY COLUMN issue_type
                 ENUM('modified_core','modified_plugin','malware_signature','heuristic','php_in_uploads','vulnerable_version','unknown') NOT NULL"
            );
        }
    }

    private static function tableExists(\wpdb $wpdb, string $table): bool {
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        return (string) $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table;
    }

    /**
     * Self-healing: creates tables if they don't exist.
     * Called on every boot to handle zip-based plugin upgrades that bypass
     * the activation hook (which is the only place createTables() normally runs).
     */
    public static function maybeCreateTables(): void {
        $stored = get_option(self::SCHEMA_VERSION_OPTION, '');

        if ($stored === self::SCHEMA_VERSION) {
            return; // Tables already at current schema — nothing to do.
        }

        self::createTables();
    }

    public static function dropAllTables(): void {
        global $wpdb;

        $tableNames = [
            'dpxl_shield_traffic_log',
            'dpxl_shield_blocked_ips',
            'dpxl_shield_country_blocks',
            'dpxl_shield_custom_patterns',
            'dpxl_shield_login_events',
            'dpxl_shield_scan_results',
            'dpxl_shield_file_checksums',
            'dpxl_shield_audit_log',
            'dpxl_shield_rate_buckets',
            'dpxl_shield_api_tokens',
        ];

        foreach ($tableNames as $name) {
            $table = $wpdb->prefix . $name;
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $wpdb->query("DROP TABLE IF EXISTS `{$table}`");
        }

        delete_option(self::SCHEMA_VERSION_OPTION);
    }

    /** @return string[] */
    private static function getTableDefinitions(string $prefix, string $charset): array {
        return [

            // ── Traffic Log ──────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_traffic_log (
                id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                timestamp     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                ip            VARCHAR(45)     NOT NULL,
                method        VARCHAR(10)     NOT NULL,
                uri           TEXT            NOT NULL,
                query_string  TEXT,
                status_code   SMALLINT        NOT NULL DEFAULT 200,
                user_agent    TEXT,
                referer       TEXT,
                waf_action    ENUM('pass','block','challenge','log_only') NOT NULL DEFAULT 'pass',
                waf_rule_id   VARCHAR(50),
                response_time FLOAT,
                is_bot        TINYINT(1)      NOT NULL DEFAULT 0,
                country       VARCHAR(2),
                PRIMARY KEY  (id),
                INDEX idx_ip        (ip),
                INDEX idx_timestamp (timestamp),
                INDEX idx_waf_action (waf_action)
            ) {$charset};",

            // ── Blocked IPs ───────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_blocked_ips (
                id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                ip           VARCHAR(45)     NOT NULL,
                cidr         VARCHAR(50),
                reason       VARCHAR(255)    NOT NULL,
                source       ENUM('manual','auto_waf','auto_brute','auto_rate','auto_honeypot','auto_country','auto_anomaly') NOT NULL,
                blocked_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at   DATETIME,
                is_permanent TINYINT(1)      NOT NULL DEFAULT 0,
                block_count  INT UNSIGNED    NOT NULL DEFAULT 1,
                last_attempt DATETIME,
                PRIMARY KEY  (id),
                UNIQUE KEY uk_ip       (ip),
                INDEX idx_expires   (expires_at),
                INDEX idx_permanent (is_permanent)
            ) {$charset};",

            // ── Country Blocks ────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_country_blocks (
                id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                country_code CHAR(2)         NOT NULL,
                country_name VARCHAR(100)    NOT NULL,
                mode         ENUM('block','allow') NOT NULL DEFAULT 'block',
                created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY  (id),
                UNIQUE KEY uk_country (country_code)
            ) {$charset};",

            // ── Custom Patterns ───────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_custom_patterns (
                id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                field      ENUM('user_agent','referer','hostname','url') NOT NULL,
                pattern    VARCHAR(500)    NOT NULL,
                match_type ENUM('contains','equals','regex') NOT NULL DEFAULT 'contains',
                action     ENUM('block','log_only') NOT NULL DEFAULT 'block',
                reason     VARCHAR(255),
                created_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                PRIMARY KEY (id),
                INDEX idx_field (field)
            ) {$charset};",

            // ── Login Events ──────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_login_events (
                id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                timestamp  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                user_login VARCHAR(60)     NOT NULL,
                ip         VARCHAR(45)     NOT NULL,
                user_agent TEXT,
                result     ENUM('success','failure','blocked','2fa_required','2fa_failed') NOT NULL,
                country    VARCHAR(2),
                PRIMARY KEY (id),
                INDEX idx_ip        (ip),
                INDEX idx_user      (user_login),
                INDEX idx_timestamp (timestamp)
            ) {$charset};",

            // ── Scan Results ──────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_scan_results (
                id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                scan_id      VARCHAR(36)     NOT NULL,
                scanned_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                file_path    TEXT            NOT NULL,
                issue_type   ENUM('modified_core','modified_plugin','malware_signature','heuristic','php_in_uploads','vulnerable_version','unknown') NOT NULL,
                severity     ENUM('critical','high','medium','low') NOT NULL,
                signature_id VARCHAR(50),
                details      TEXT,
                status       ENUM('new','acknowledged','resolved','false_positive') NOT NULL DEFAULT 'new',
                PRIMARY KEY  (id),
                INDEX idx_scan_id (scan_id),
                INDEX idx_status  (status)
            ) {$charset};",

            // ── File Checksums ────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_file_checksums (
                id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                file_path   VARCHAR(500)    NOT NULL,
                checksum    CHAR(64)        NOT NULL,
                file_type   ENUM('core','plugin','theme','shieldwp') NOT NULL,
                recorded_at DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY  (id),
                UNIQUE KEY uk_path    (file_path(255)),
                INDEX idx_file_type (file_type)
            ) {$charset};",

            // ── Audit Log ─────────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_audit_log (
                id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                timestamp   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                event_type  VARCHAR(50)     NOT NULL,
                severity    ENUM('critical','high','medium','low','info') NOT NULL,
                actor_ip    VARCHAR(45),
                actor_user  BIGINT UNSIGNED,
                description TEXT            NOT NULL,
                context     JSON,
                chain_hash  CHAR(64)        NOT NULL,
                PRIMARY KEY  (id),
                INDEX idx_severity   (severity),
                INDEX idx_event_type (event_type),
                INDEX idx_timestamp  (timestamp)
            ) {$charset};",

            // ── Rate Buckets ──────────────────────────────────────────────
            "CREATE TABLE {$prefix}dpxl_shield_rate_buckets (
                id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                bucket_key   VARCHAR(100)    NOT NULL,
                count        INT UNSIGNED    NOT NULL DEFAULT 0,
                window_start DATETIME        NOT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY uk_bucket   (bucket_key),
                INDEX idx_window (window_start)
            ) {$charset};",

            // ── API tokens (read-only integration credentials) ────────────
            // token_hash is SHA-256 of the plaintext, which is never stored.
            // token_lookup is the clear-text leading fragment: it finds the row
            // with an indexed lookup so the hash comparison can stay constant
            // time, and it is what the admin sees to tell tokens apart.
            "CREATE TABLE {$prefix}dpxl_shield_api_tokens (
                id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                label        VARCHAR(60)     NOT NULL,
                token_hash   CHAR(64)        NOT NULL,
                token_lookup VARCHAR(20)     NOT NULL,
                created_at   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_used_at DATETIME        NULL DEFAULT NULL,
                last_used_ip VARCHAR(45)     NULL DEFAULT NULL,
                PRIMARY KEY  (id),
                UNIQUE KEY uk_lookup (token_lookup),
                INDEX idx_hash (token_hash)
            ) {$charset};",
        ];
    }
}
