<?php
declare(strict_types=1);

namespace DPXL\Shield\Tools;

use DPXL\Shield\Alerts\SmtpMonitor;
use DPXL\Shield\Core\Options;

/**
 * Collects environment diagnostic data for the admin panel.
 *
 * Each check returns:
 *   status  → ok | warning | error
 *   label   → human-readable name
 *   value   → current value/state
 *   note    → optional explanation
 */
class Diagnostics {

    /**
     * @return array<string, array{status: string, label: string, value: string, note: string}>
     */
    public function run(): array {
        return [
            'php_version'        => $this->checkPhpVersion(),
            'wp_version'         => $this->checkWpVersion(),
            'openssl'            => $this->checkExtension('openssl'),
            'mbstring'           => $this->checkExtension('mbstring'),
            'hash'               => $this->checkExtension('hash'),
            'json'               => $this->checkExtension('json'),
            'curl'               => $this->checkExtension('curl'),
            'apcu'               => $this->checkApcu(),
            'opcache'            => $this->checkOpcache(),
            'extended_mode'      => $this->checkExtendedMode(),
            'client_ip'          => $this->checkClientIp(),
            'wp_config_perms'    => $this->checkFilePerms(ABSPATH . 'wp-config.php', '0400-0640'),
            'uploads_perms'      => $this->checkDirPerms(wp_upload_dir()['basedir'] ?? '', '0755'),
            'maxmind_db'         => $this->checkMaxMindDb(),
            'wp_cron'            => $this->checkWpCron(),
            'threat_feed'        => $this->checkThreatFeed(),
            'disk_space'         => $this->checkDiskSpace(),
            'mysql_version'      => $this->checkMysqlVersion(),
            'smtp_delivery'      => $this->checkSmtpDelivery(),
        ];
    }

    // ── Checks ─────────────────────────────────────────────────────────────

    /**
     * Whether mail is actually leaving the site.
     *
     * Worth a row of its own because it is the one failure that hides itself:
     * every other check here can be reported by email, and this one cannot.
     *
     * @return array{status:string,label:string,value:string,note:string}
     */
    private function checkSmtpDelivery(): array {
        if (!Options::get('smtp_monitor_enabled', true)) {
            return ['status' => 'warning', 'label' => 'Envio de e-mails', 'value' => 'Não monitorado', 'note' => ''];
        }

        $state = SmtpMonitor::status();

        if (!$state['healthy']) {
            return [
                'status' => 'error',
                'label'  => 'Envio de e-mails',
                'value'  => sprintf('Falhando (%d tentativas seguidas)', $state['failures']),
                'note'   => $state['last_error'] !== ''
                    ? 'Último erro: ' . $state['last_error']
                    : 'O servidor não informou o motivo.',
            ];
        }

        if ($state['last_success'] === '') {
            // Never seen a send succeed. Not a problem by itself — a quiet site
            // may simply not have sent anything yet — so it is not an error.
            return [
                'status' => 'warning',
                'label'  => 'Envio de e-mails',
                'value'  => 'Sem envio registrado ainda',
                'note'   => 'Nenhuma mensagem saiu deste site desde que o monitoramento começou.',
            ];
        }

        return [
            'status' => 'ok',
            'label'  => 'Envio de e-mails',
            'value'  => 'Funcionando',
            'note'   => 'Último envio bem-sucedido em ' . $state['last_success'] . ' UTC.',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkThreatFeed(): array {
        if (!get_option('dpxl_shield_threat_feed_enabled', true)) {
            return ['status' => 'warning', 'label' => 'Feed de ameaças', 'value' => 'Desligado', 'note' => ''];
        }

        $version    = (string) get_option('dpxl_shield_threat_feed_version', '');
        $lastStatus = (string) get_option('dpxl_shield_threat_feed_last_status', '');
        $lastRun    = (int) get_option('dpxl_shield_threat_feed_last_run', 0);

        if ($lastRun === 0) {
            $status = 'warning';
        } elseif (in_array($lastStatus, ['ok', 'no_change'], true)) {
            $status = 'ok';
        } elseif (in_array($lastStatus, ['sig_fail', 'hash_fail'], true)) {
            $status = 'error';
        } else {
            $status = 'warning';
        }

        $value = $version !== ''
            ? 'v' . $version . ($lastStatus !== '' ? ' (' . $lastStatus . ')' : '')
            : ($lastRun === 0 ? 'Never run' : '(' . ($lastStatus ?: 'pending') . ')');

        $notes = [
            'sig_fail'  => 'Feed failed signature/integrity verification and was NOT applied. Possible feed-channel tampering.',
            'hash_fail' => 'Feed failed signature/integrity verification and was NOT applied. Possible feed-channel tampering.',
            'net_fail'  => 'Could not reach the feed. Rules stay at the last good version.',
            'no_pubkey' => 'No feed public key or ext-sodium — feed cannot be verified.',
        ];

        $note = $notes[$lastStatus] ?? '';

        return ['status' => $status, 'label' => 'Feed de ameaças', 'value' => $value, 'note' => $note];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkPhpVersion(): array {
        $version = PHP_VERSION;
        $status  = version_compare($version, '8.1', '>=') ? 'ok' : 'error';

        return [
            'status' => $status,
            'label'  => 'Versão do PHP',
            'value'  => $version,
            'note'   => $status === 'error' ? 'É necessário PHP 8.1 ou superior.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkWpVersion(): array {
        global $wp_version;
        $current = $wp_version ?? 'unknown';
        $status  = version_compare($current, '6.4', '>=') ? 'ok' : 'error';

        return [
            'status' => $status,
            'label'  => 'Versão do WordPress',
            'value'  => $current,
            'note'   => $status === 'error' ? 'É necessário WordPress 6.4 ou superior.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkExtension(string $name): array {
        $loaded = extension_loaded($name);

        return [
            'status' => $loaded ? 'ok' : 'error',
            'label'  => "Extensão PHP: {$name}",
            'value'  => $loaded ? 'Carregada' : 'Não carregada',
            'note'   => $loaded ? '' : "O DPXL Shield precisa da extensão {$name}.",
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkApcu(): array {
        $loaded = extension_loaded('apcu') && function_exists('apcu_fetch');
        $enabled = $loaded && (bool) ini_get('apc.enabled');

        return [
            'status' => ($loaded && $enabled) ? 'ok' : 'warning',
            'label'  => 'Cache APCu',
            'value'  => ($loaded && $enabled) ? 'Disponível' : ($loaded ? 'Carregado, mas desligado' : 'Indisponível'),
            'note'   => (!$loaded || !$enabled) ? 'Sem APCu, a limitação de taxa conta no banco de dados, e com a Proteção Estendida só depois que o WordPress carrega.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkOpcache(): array {
        $loaded  = extension_loaded('Zend OPcache');
        $enabled = $loaded && (bool) ini_get('opcache.enable');

        return [
            'status' => ($loaded && $enabled) ? 'ok' : 'warning',
            'label'  => 'OPcache',
            'value'  => ($loaded && $enabled) ? 'Ativado' : 'Desligado ou indisponível',
            'note'   => (!$loaded || !$enabled) ? 'O OPcache melhora o desempenho geral do PHP.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkExtendedMode(): array {
        $active = defined('DPXL_SHIELD_EXTENDED_ACTIVE');

        return [
            'status' => $active ? 'ok' : 'warning',
            'label'  => 'Proteção Estendida (WAF)',
            'value'  => $active ? 'Ativa' : 'Inativa (modo básico)',
            'note'   => $active ? '' : 'A Proteção Estendida intercepta requisições antes do WordPress carregar. Ative em Firewall → Proteção Estendida.',
        ];
    }

    /**
     * Whether visitor IPs are being read correctly.
     *
     * Forwarding headers are only believed from a trusted proxy (see ClientIp).
     * A site behind a CDN or proxy that is not Cloudflare and not on the local
     * network sees every visitor as the proxy's IP until that proxy is listed —
     * and then one visitor's lockout would lock out everyone behind the proxy.
     *
     * @return array{status:string,label:string,value:string,note:string}
     */
    private function checkClientIp(): array {
        $resolved  = \DPXL\Shield\Core\ClientIp::current();
        $remote    = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
        $forwarded = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ($_SERVER['HTTP_X_REAL_IP'] ?? ''));

        if ($forwarded !== '' && $resolved === $remote) {
            return [
                'status' => 'warning',
                'label'  => 'Detecção do IP do visitante',
                'value'  => sprintf('Usando %s (cabeçalho de proxy ignorado)', $remote),
                'note'   => 'Esta requisição chegou com um cabeçalho X-Forwarded-For vindo de um endereço que não é um proxy confiável. Se o site fica atrás de uma CDN ou proxy (que não seja a Cloudflare), adicione os IPs dele em wp-config.php: define(\'DPXL_SHIELD_TRUSTED_PROXIES\', \'IP-ou-faixa, ...\');',
            ];
        }

        return [
            'status' => 'ok',
            'label'  => 'Detecção do IP do visitante',
            'value'  => $resolved,
            'note'   => '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkFilePerms(string $path, string $expectedRange): array {
        if (!file_exists($path)) {
            return ['status' => 'warning', 'label' => 'Permissões do arquivo: ' . basename($path), 'value' => 'Arquivo não encontrado', 'note' => ''];
        }

        $perms  = substr(sprintf('%o', fileperms($path)), -4);
        $oct    = octdec($perms);
        $status = ($oct <= octdec('0640')) ? 'ok' : 'warning';

        return [
            'status' => $status,
            'label'  => 'Permissões do arquivo: ' . basename($path),
            'value'  => $perms,
            'note'   => $status === 'warning' ? "Recomendado: {$expectedRange}. As permissões atuais podem estar abertas demais." : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkDirPerms(string $path, string $expected): array {
        if (!is_dir($path)) {
            return ['status' => 'warning', 'label'  => 'Diretório: uploads', 'value'  => 'Não encontrado', 'note' => ''];
        }

        $perms  = substr(sprintf('%o', fileperms($path)), -4);
        $oct    = octdec($perms);
        $status = ($oct <= octdec('0755')) ? 'ok' : 'warning';

        return [
            'status' => $status,
            'label'  => 'Diretório: uploads',
            'value'  => $perms,
            'note'   => $status === 'warning' ? "Recomendado: {$expected}." : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkMaxMindDb(): array {
        $path   = defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH . 'data/GeoLite2-Country.mmdb' : '';
        $exists = $path && file_exists($path);

        $version    = (string) get_option('dpxl_shield_geo_db_version', '');
        $lastStatus = (string) get_option('dpxl_shield_geo_db_last_status', '');
        $lastRun    = (int) get_option('dpxl_shield_geo_db_last_run', 0);
        $enabled    = (bool) get_option('dpxl_shield_geo_db_enabled', true);

        // The DB is what actually makes country features work, so a missing file
        // is the headline regardless of how the last update run went.
        if (!$exists) {
            return [
                'status' => 'warning',
                'label'  => 'Base GeoLite2 da MaxMind',
                'value'  => $enabled ? 'Ainda não instalada' : 'Não instalada (atualização automática desligada)',
                'note'   => $enabled
                    ? 'Country features stay idle until the database downloads. It installs itself on the daily update — or use "Check now" in All Options to fetch it immediately.'
                    : 'Auto-update is disabled, so the database will never download. Enable it in All Options → Firewall.',
            ];
        }

        // Stale is a real risk here: MaxMind requires redistributed copies to be
        // under 30 days old, and an old DB silently mislabels traffic.
        $ageDays = (int) floor((time() - (int) filemtime($path)) / DAY_IN_SECONDS);

        $verificationFailed = in_array($lastStatus, ['sig_fail', 'hash_fail'], true);
        $stale              = $ageDays > 30;

        if ($verificationFailed) {
            $status = 'error';
        } elseif ($stale || !$enabled || $lastRun === 0) {
            $status = 'warning';
        } else {
            $status = 'ok';
        }

        $value = 'Present (' . $this->humanSize((int) filesize($path)) . ')'
            . ($version !== '' ? ' · ' . $version : '')
            . ($lastStatus !== '' ? ' · ' . $lastStatus : '');

        if ($verificationFailed) {
            $note = 'The downloaded database failed signature/integrity verification and was NOT applied. Possible feed-channel tampering.';
        } elseif ($stale) {
            $note = "Database is {$ageDays} days old. MaxMind requires redistributed copies to stay under 30 days — check that the daily cron is running.";
        } elseif (!$enabled) {
            $note = 'Auto-update is disabled; this database will go stale. Enable it in All Options → Firewall.';
        } elseif ($lastStatus === 'net_fail') {
            $note = 'Could not reach the feed on the last run. The current database stays in use.';
        } elseif ($lastRun === 0) {
            $note = 'Auto-update has not run yet.';
        } else {
            $note = '';
        }

        return [
            'status' => $status,
            'label'  => 'Base GeoLite2 da MaxMind',
            'value'  => $value,
            'note'   => $note,
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkWpCron(): array {
        $lastRun = (int) get_option('dpxl_shield_last_cron_run', 0);
        $ago     = $lastRun ? (time() - $lastRun) : PHP_INT_MAX;
        $status  = $ago < 7200 ? 'ok' : ($lastRun === 0 ? 'warning' : 'error');
        $label   = $lastRun ? gmdate('Y-m-d H:i:s', $lastRun) . ' UTC' : 'Never';

        return [
            'status' => $status,
            'label'  => 'WP Cron',
            'value'  => $label,
            'note'   => $status === 'error' ? 'O cron do DPXL Shield não roda há mais de 2 horas. Confira a configuração do WP-Cron.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkDiskSpace(): array {
        $free   = (float) @disk_free_space(WP_CONTENT_DIR);
        $status = $free > 50 * 1024 * 1024 ? 'ok' : ($free > 10 * 1024 * 1024 ? 'warning' : 'error');

        return [
            'status' => $status,
            'label'  => 'Espaço em disco (wp-content)',
            'value'  => $this->humanSize((int) $free) . ' livres',
            'note'   => $status !== 'ok' ? 'Pouco espaço em disco pode atrapalhar a varredura e o armazenamento dos logs.' : '',
        ];
    }

    /** @return array{status:string,label:string,value:string,note:string} */
    private function checkMysqlVersion(): array {
        global $wpdb;
        $version = $wpdb->get_var('SELECT VERSION()') ?? 'unknown';
        $status  = version_compare($version, '5.7', '>=') ? 'ok' : 'warning';

        return [
            'status' => $status,
            'label'  => 'Versão do MySQL / MariaDB',
            'value'  => $version,
            'note'   => $status === 'warning' ? 'Recomendado MySQL 5.7+ ou MariaDB 10.4+.' : '',
        ];
    }

    private function humanSize(int $bytes): string {
        if ($bytes >= 1073741824) {
            return round($bytes / 1073741824, 1) . ' GB';
        }

        if ($bytes >= 1048576) {
            return round($bytes / 1048576, 1) . ' MB';
        }

        return round($bytes / 1024, 1) . ' KB';
    }
}
