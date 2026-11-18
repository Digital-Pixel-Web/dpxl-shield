<?php
declare(strict_types=1);

namespace DPXL\Shield\Admin;

use DPXL\Shield\Core\Options;
use DPXL\Shield\Bootstrap\AutoPrepend;
use DPXL\Shield\Alerts\ReportData;
use DPXL\Shield\Alerts\PdfReport;
use DPXL\Shield\Alerts\ReportI18n;
use DPXL\Shield\Threat\ThreatFeedUpdater;
use DPXL\Shield\Threat\GeoDbUpdater;

/**
 * Registers the plugin admin menu and all sub-pages.
 * Enqueues admin scripts and styles.
 */
class AdminMenu {

    private const CAPABILITY  = 'manage_options';
    private const MENU_SLUG   = 'dpxl-shield';
    private const VIEWS_DIR   = __DIR__ . '/Views/';

    public function registerHooks(): void {
        add_action('admin_menu',            [$this, 'addMenuPages']);
        add_action('admin_enqueue_scripts', [$this, 'enqueueAssets']);
        add_action('admin_notices',         [$this, 'maybeExtendedProtectionNotice']);
        add_filter('gettext', [$this, 'translatePluginStrings'], 20, 3);
        add_action('admin_post_dpxl_shield_download_htaccess_backup', [$this, 'downloadHtaccessBackup']);
        add_action('admin_post_dpxl_shield_enable_extended',          [$this, 'enableExtendedFromPost']);
        add_action('admin_post_dpxl_shield_download_report_pdf',      [$this, 'downloadReportPdf']);
        add_action('admin_post_dpxl_shield_check_feed',               [$this, 'checkFeed']);
    }

    // ── Menu pages ─────────────────────────────────────────────────────────

    public function addMenuPages(): void {
        add_menu_page(
            __('DPXL Shield', 'dpxl-shield'),
            __('DPXL Shield', 'dpxl-shield'),
            self::CAPABILITY,
            self::MENU_SLUG,
            [$this, 'renderDashboard'],
            self::getMenuIcon(),
            25
        );

        add_submenu_page(self::MENU_SLUG, __('Painel', 'dpxl-shield'), __('Painel', 'dpxl-shield'), self::CAPABILITY, self::MENU_SLUG, [$this, 'renderDashboard']);
        add_submenu_page(self::MENU_SLUG, __('Firewall', 'dpxl-shield'), __('Firewall', 'dpxl-shield'), self::CAPABILITY, 'dpxl-shield-firewall', [$this, 'renderFirewall']);
        add_submenu_page(self::MENU_SLUG, __('Varredura', 'dpxl-shield'), __('Varredura', 'dpxl-shield'), self::CAPABILITY, 'dpxl-shield-scan', [$this, 'renderScan']);
        add_submenu_page(self::MENU_SLUG, __('Segurança de Login', 'dpxl-shield'), __('Segurança de Login', 'dpxl-shield'), self::CAPABILITY, 'dpxl-shield-login', [$this, 'renderLoginSecurity']);
        add_submenu_page(self::MENU_SLUG, __('Ferramentas', 'dpxl-shield'), __('Ferramentas', 'dpxl-shield'), self::CAPABILITY, 'dpxl-shield-tools', [$this, 'renderTools']);
        add_submenu_page(self::MENU_SLUG, __('Todas as Opções', 'dpxl-shield'), __('Todas as Opções', 'dpxl-shield'), self::CAPABILITY, 'dpxl-shield-options', [$this, 'renderAllOptions']);
    }

    // ── Asset enqueue ──────────────────────────────────────────────────────


    public static function getBrandLogoUrl(): string {
        return (defined('DPXL_SHIELD_URL') ? DPXL_SHIELD_URL : '') . 'assets/img/dpxl-shield-mark.svg';
    }

    public static function getMenuIcon(): string {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path fill="#a7aaad" d="M10 1l8 3v6c0 5-4 8-8 9C6 18 2 15 2 10V4l8-3z"/></svg>';
        return 'data:image/svg+xml;base64,' . base64_encode($svg);
    }

    public static function renderPageTitle(string $title, string $actionsHtml = ''): void {
        echo '<h1 class="dpxl-page-title">';
        echo '<span class="dpxl-page-title__brand">';
        echo '<img class="dpxl-page-title__logo" src="' . esc_url(self::getBrandLogoUrl()) . '" alt="DPXL Shield">';
        echo '<span class="dpxl-page-title__text">' . esc_html($title) . '</span>';
        echo '</span>';
        if ($actionsHtml !== '') {
            echo $actionsHtml; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
        }
        echo '</h1>';
    }

    /**
     * PHP 8.1: passing null to a typed string parameter throws TypeError even from
     * non-strict callers. WordPress/Elementor can pass null to the gettext filter
     * (e.g. __( $variable ) where $variable is null). Accepting mixed + null-guarding
     * prevents the fatal 500 on any admin page.
     *
     * @param mixed $translated
     * @param mixed $text
     * @param mixed $domain
     */
    public function translatePluginStrings($translated, $text, $domain): string {
        if (!is_string($domain) || $domain !== 'dpxl-shield') {
            return is_string($translated) ? $translated : (string) ($translated ?? '');
        }

        if (!is_string($text)) {
            return is_string($translated) ? $translated : (string) ($translated ?? '');
        }

        static $map = [
            'Dashboard' => 'Painel',
            'Firewall' => 'Firewall',
            'Scan' => 'Varredura',
            'Login Security' => 'Segurança de Login',
            'Tools' => 'Ferramentas',
            'All Options' => 'Todas as Opções',
            'Settings' => 'Configurações',
            'Two-Factor Authentication' => 'Autenticação de Dois Fatores',
            'Learn more' => 'Saiba mais',
            'Editing user: %s (you)' => 'Editando usuário: %s (você)',
            'Two-Factor Authentication is ACTIVE for this account.' => 'A autenticação de dois fatores está ATIVA para esta conta.',
            'Deactivate 2FA' => 'Desativar 2FA',
            'Regenerate Recovery Codes' => 'Gerar novos códigos de recuperação',
            '1. Scan Code or Enter Key' => '1. Escaneie o QR Code ou digite a chave',
            'Loading QR code…' => 'Carregando QR Code…',
            'Loading…' => 'Carregando…',
            '2. Enter Code from App' => '2. Digite o código do aplicativo',
            'Loading recovery codes…' => 'Carregando códigos de recuperação…',
            'Download Codes' => 'Baixar códigos',
            'Activate' => 'Ativar',
            'Server Time:' => 'Hora do servidor:',
            'Detected IP:' => 'IP detectado:',
            'Brute Force Protection' => 'Proteção contra força bruta',
            'Lock out after X failed login attempts' => 'Bloquear após X tentativas de login malsucedidas',
            'Count failures over X minutes' => 'Contabilizar falhas ao longo de X minutos',
            'Notify by email when locked out' => 'Notificar por e-mail quando houver bloqueio',
            'Enforce 2FA by Role' => 'Exigir 2FA por função',
            'Additional Options' => 'Opções adicionais',
            'Check passwords against breach database (HaveIBeenPwned)' => 'Verificar senhas em base de vazamentos (HaveIBeenPwned)',
            'Hide WordPress login errors (generic message)' => 'Ocultar erros de login do WordPress (mensagem genérica)',
            'Disable XML-RPC authentication' => 'Desativar autenticação XML-RPC',
            'Save Changes' => 'Salvar alterações',
            'Loading protection status…' => 'Carregando status da proteção…',
            'Protection from known threats' => 'Proteção contra ameaças conhecidas',
            'Detection of security issues' => 'Detecção de problemas de segurança',
            'Brute Force + 2FA Active' => 'Força bruta + 2FA ativos',
            'Manage Firewall' => 'Gerenciar Firewall',
            'Manage Scan' => 'Gerenciar Varredura',
            'Manage Login' => 'Gerenciar Login',
            'Notifications' => 'Notificações',
            'Firewall Summary' => 'Resumo do Firewall',
            'Block Type' => 'Tipo de bloqueio',
            'Today' => 'Hoje',
            'Week' => 'Semana',
            'Month' => 'Mês',
            'Total Attacks Blocked' => 'Total de ataques bloqueados',
            'Top Countries (Last 7 Days)' => 'Principais países (últimos 7 dias)',
            'Recent Login Attempts' => 'Tentativas de login recentes',
            'Successful' => 'Bem-sucedidos',
            'Failed' => 'Falhos',
            'Show more' => 'Ver mais',
            'Extended Protection' => 'Proteção Estendida',
            'WAF' => 'WAF',
            'Rules' => 'Regras',
            'IP Blocklist' => 'Lista de bloqueio de IPs',
            'Brute Force' => 'Força bruta',
            'Top IPs Blocked' => 'IPs mais bloqueados',
            'Country' => 'País',
            'Hits' => 'Ocorrências',
            'Actions' => 'Ações',
            'Blocking' => 'Bloqueios',
            'Start New Scan' => 'Iniciar nova varredura',
            'Cancel Scan' => 'Cancelar varredura',
            'Scan Options & Scheduling' => 'Opções e agendamento da varredura',
            'Spam Check' => 'Verificação de spam',
            'Block Check' => 'Verificação de bloqueios',
            'Server State' => 'Estado do servidor',
            'Files Changed' => 'Arquivos alterados',
            'Malware Scan' => 'Varredura de malware',
            'Content Safety' => 'Segurança do conteúdo',
            'Public Files' => 'Arquivos públicos',
            'Pass Audit' => 'Auditoria de senhas',
            'Email Log' => 'Enviar log por e-mail',
            'Results Found' => 'Resultados encontrados',
            'Repair All Repairable' => 'Reparar todos os reparáveis',
            'Files Scanned' => 'Arquivos verificados',
            'Issues Found' => 'Problemas encontrados',
            'Critical' => 'Crítico',
            'No security issues found. Your site is clean.' => 'Nenhum problema de segurança encontrado. Seu site está limpo.',
            'Live Traffic' => 'Tráfego ao vivo',
            'All Hits' => 'Todos os acessos',
            'Human' => 'Humano',
            'Bot / Crawler' => 'Robô / rastreador',
            'Suspicious' => 'Suspeito',

            // Varredura de tradução da 1.9.3: tudo o que as views pediam ao filtro
            // e não encontrava, e por isso chegava ao usuário em inglês.
            '26 characters' => '26 caracteres',
            'API tokens' => 'Tokens de API',
            'Add endpoint' => 'Adicionar destino',
            'Available: /status, /events, /traffic, /scan-results.' => 'Disponíveis: /status, /events, /traffic, /scan-results.',
            'Backup downloaded. Ready to apply or already applied.' => 'Backup baixado. Pronto para aplicar, ou já aplicado.',
            'Blocklist Checks' => 'Checagens de blocklist',
            'Copy' => 'Copiar',
            'Copy this token now — it will not be shown again.' => 'Copie este token agora — ele não será mostrado de novo.',
            'Could not download the country database.' => 'Não foi possível baixar a base de países.',
            'Could not reach the feed for WAF rules.' => 'Não foi possível acessar o feed de regras do WAF.',
            'IP geolocation by %s, licensed under CC BY 4.0.' => 'Geolocalização de IP por %s, sob licença CC BY 4.0.',
            'Create token' => 'Criar token',
            'Critical only' => 'Somente críticos',
            'Date' => 'Data',
            'Destination' => 'Destino',
            'Detected server: %s' => 'Servidor detectado: %s',
            'Enable Extended Protection' => 'Ativar a Proteção Estendida',
            'Enabled' => 'Ativado',
            'Events are queued during the request and delivered after the response is sent, so a slow endpoint never adds latency to your site.' => 'Os eventos são enfileirados durante a requisição e entregues depois que a resposta sai, então um destino lento nunca deixa o seu site mais lento.',
            'Everything' => 'Tudo',
            'Extended Protection Active' => 'Proteção Estendida ativa',
            'Extended Protection inactive. Follow the steps below to enable it safely.' => 'Proteção Estendida inativa. Siga os passos abaixo para ativá-la com segurança.',
            'Feed cannot be verified on this server (missing key or sodium).' => 'O feed não pode ser verificado neste servidor (falta a chave ou a extensão sodium).',
            'Filter by IP, reason…' => 'Filtrar por IP, motivo…',
            'For systems that prefer to pull rather than receive. A token grants read-only access to the audit log, traffic log, scan results and firewall status — nothing can be changed through it.' => 'Para sistemas que preferem buscar em vez de receber. O token dá acesso somente de leitura ao log de auditoria, ao log de tráfego, aos resultados de varredura e ao estado do firewall — nada pode ser alterado por ele.',
            'Generic JSON (SIEM)' => 'JSON genérico (SIEM)',
            'Country database auto-update is disabled.' => 'A atualização automática da base de países está desligada.',
            'Country database installed/updated (%s).' => 'Base de países instalada/atualizada (%s).',
            'Country database is already up to date.' => 'A base de países já está atualizada.',
            'Country database verification failed — rejected.' => 'A verificação da base de países falhou — base rejeitada.',
            'Give each integration its own token so you can revoke one without disturbing the others. Revoking takes effect immediately.' => 'Dê um token próprio a cada integração, assim você revoga um sem mexer nos outros. A revogação vale na hora.',
            'High and above' => 'Alto e acima',
            'How to use it' => 'Como usar',
            'Idle' => 'Parado',
            'Login page limit (req/min)' => 'Limite da tela de login (req/min)',
            'Low and above' => 'Baixo e acima',
            'Medium and above' => 'Médio e acima',
            'Name' => 'Nome',
            'No country database is available in the feed yet.' => 'Ainda não há base de países disponível no feed.',
            'Outbound webhooks' => 'Webhooks de saída',
            'Plain HTTP is refused — these payloads describe attacks on your site and must not travel in the clear.' => 'HTTP sem TLS é recusado — esses envios descrevem ataques ao seu site e não podem trafegar abertos.',
            'Push security events to Slack, Discord, PagerDuty or any SIEM as they happen. Each endpoint has its own severity threshold, so a chat channel can take only the serious ones while a SIEM takes everything.' => 'Envie eventos de segurança para Slack, Discord, PagerDuty ou qualquer SIEM assim que acontecem. Cada destino tem seu próprio limite de severidade, então um canal de chat pode receber só o que é grave enquanto um SIEM recebe tudo.',
            'REST API limit (req/min)' => 'Limite da API REST (req/min)',
            'Required. The automatic setup starts right after the backup download.' => 'Obrigatório. A instalação automática começa logo depois que o backup é baixado.',
            'Save' => 'Salvar',
            'Scan Options &amp; Scheduling' => 'Opções e agendamento da varredura',
            'Send events from' => 'Enviar eventos a partir de',
            'Send the token as a bearer credential. Collections are cursor-paginated: pass the next_cursor value from each response as ?after= on the following call.' => 'Envie o token como credencial bearer. As coleções são paginadas por cursor: passe o next_cursor de cada resposta como ?after= na chamada seguinte.',
            'Signing secret (optional)' => 'Segredo de assinatura (opcional)',
            'Signs each payload so your receiver can verify it really came from this site. Leave blank when editing to keep the current value.' => 'Assina cada envio para que o destinatário possa conferir que ele veio mesmo deste site. Deixe em branco ao editar para manter o valor atual.',
            'Spamhaus DQS key' => 'Chave DQS da Spamhaus',
            'The threat feed is disabled.' => 'O feed de ameaças está desligado.',
            'This product includes GeoLite2 data created by MaxMind, available from %s.' => 'Este produto inclui dados GeoLite2 criados pela MaxMind, disponíveis em %s.',
            'User' => 'Usuário',
            'WAF rules are already up to date.' => 'As regras do WAF já estão atualizadas.',
            'WAF rules updated to version %s.' => 'Regras do WAF atualizadas para a versão %s.',
            'WAF rules verification failed — rejected.' => 'A verificação das regras do WAF falhou — regras rejeitadas.',
            'Web Application Firewall' => 'Firewall de aplicação web',
            'Webhook URL (HTTPS)' => 'URL do webhook (HTTPS)',
            'Whitelist' => 'Lista de permissões',
            'XML-RPC limit (req/min)' => 'Limite do XML-RPC (req/min)',
            'Spamhaus refuses lookups that reach it through a public DNS resolver, which is what most shared hosting uses — without a key the blocklist checks cannot run and will report as unavailable. A key from spamhaus.com gives this site its own query zone — Spamhaus offers a free tier for non-commercial use with low volumes. The key is left out of settings exports, since sharing one key across sites exhausts its quota.' => 'A Spamhaus recusa consultas que chegam por um resolvedor de DNS público, que é o que a maioria das hospedagens compartilhadas usa — sem chave, as checagens de blocklist não rodam e aparecem como indisponíveis. Uma chave de spamhaus.com dá a este site uma zona de consulta própria; a Spamhaus tem um plano gratuito para uso não comercial e volume baixo. A chave fica de fora da exportação de configurações, porque compartilhar uma chave entre sites esgota a cota dela.',
            'IP' => 'IP',
            'URL' => 'URL',
            'Blocked' => 'Bloqueado',
            'Show Advanced Filters' => 'Mostrar filtros avançados',
            'Live Update' => 'Atualização ao vivo',
            'Response' => 'Resposta',
            'All' => 'Todos',
            'Apply Filters' => 'Aplicar filtros',
            'Reset' => 'Redefinir',
            'Audit Log' => 'Log de auditoria',
            'Audit Log Options' => 'Opções do log de auditoria',
            'Whois Lookup' => 'Consulta Whois',
            'Import / Export Options' => 'Opções de importação / exportação',
            'Diagnostics' => 'Diagnóstico',
            'Restore Defaults' => 'Restaurar padrões',
            'Cancel' => 'Cancelar',
            'Save All' => 'Salvar tudo',
            'Search All Options…' => 'Buscar em todas as opções…',
            'Expand All' => 'Expandir tudo',
            'Settings saved.' => 'Configurações salvas.',
            'Global Options' => 'Opções globais',
            'General Options' => 'Opções gerais',
            'Enable Firewall' => 'Ativar firewall',
            'Enable Traffic Logging' => 'Ativar registro de tráfego',
            'Enable Honeypots' => 'Ativar honeypots',
            'Email Alert Preferences' => 'Preferências de alertas por e-mail',
            'Enable Email Alerts' => 'Ativar alertas por e-mail',
            'Alert Email Address' => 'E-mail para alertas',
            'Enable Activity Reports' => 'Ativar relatórios de atividade',
            'Report Frequency' => 'Frequência do relatório',
            'Attach PDF report to email' => 'Anexar relatório em PDF ao e-mail',
            'Download report now' => 'Baixar relatório agora',
            'Download PDF' => 'Baixar PDF',
            'Daily' => 'Diário',
            'Weekly' => 'Semanal',
            'Monthly' => 'Mensal',
            'Firewall Options' => 'Opções do firewall',
            'Basic Firewall Options' => 'Opções básicas do firewall',
            'SQL Injection Protection' => 'Proteção contra SQL Injection',
            'XSS Protection' => 'Proteção contra XSS',
            'Path Traversal (LFI) Protection' => 'Proteção contra Path Traversal (LFI)',
            'Remote File Inclusion Protection' => 'Proteção contra inclusão remota de arquivos',
            'Enable Brute Force Protection' => 'Ativar proteção contra força bruta',
            'Threat Feed' => 'Feed de ameaças',
            'Auto-update WAF rules from the threat feed' => 'Atualizar regras do WAF automaticamente pelo feed de ameaças',
            'Check for rule updates now' => 'Verificar atualizações de regras agora',
            'Check now' => 'Verificar agora',
            'Scan Options' => 'Opções de varredura',
            'Scan Scheduling' => 'Agendamento da varredura',
            'Scan Content' => 'Conteúdo da varredura',
            'Scan WordPress core files' => 'Verificar arquivos do núcleo do WordPress',
            'Scan plugin files' => 'Verificar arquivos de plugins',
            'Scan theme files' => 'Verificar arquivos de temas',
            'Scan uploads directory' => 'Verificar diretório de uploads',
            'Scan post content for malicious links' => 'Verificar conteúdo de posts em busca de links maliciosos',
            'Login Security Options' => 'Opções de segurança de login',
            'Extended Protection setup finished.' => 'A configuração da Proteção Estendida foi concluída.',
            'Extended Protection is not active. Your firewall loads after WordPress, reducing protection.' => 'A Proteção Estendida não está ativa. Seu firewall é carregado depois do WordPress, reduzindo a proteção.',
            'Enable now' => 'Ativar agora',
            'You do not have permission to download this file.' => 'Você não tem permissão para baixar este arquivo.',
            'You do not have permission to enable Extended Protection.' => 'Você não tem permissão para ativar a Proteção Estendida.',
            'You do not have permission to view this page.' => 'Você não tem permissão para visualizar esta página.',
            'View not found:' => 'Visualização não encontrada:',
            'Please download a backup of your current .htaccess file before enabling Extended Protection.' => 'Baixe um backup do arquivo .htaccess atual antes de ativar a Proteção Estendida.',
            'Automatic .htaccess setup is only available for Apache or LiteSpeed. Use the manual snippet for this server.' => 'A configuração automática do .htaccess está disponível apenas para Apache ou LiteSpeed. Use o trecho manual para este servidor.',
            'DPXL Shield could not write the managed block to .htaccess. Check file permissions or use the manual snippet.' => 'O DPXL Shield não conseguiu gravar o bloco gerenciado no .htaccess. Verifique as permissões do arquivo ou use o trecho manual.',
            'Extended Protection is active. The WAF is now loading before WordPress.' => 'A Proteção Estendida está ativa. O WAF agora é carregado antes do WordPress.',
            'Extended Protection has been disabled. Managed server rules were removed where possible.' => 'A Proteção Estendida foi desativada. As regras gerenciadas do servidor foram removidas sempre que possível.',
            'WordPress HTTP API is unavailable, so DPXL Shield could not verify Extended Protection.' => 'A API HTTP do WordPress não está disponível, então o DPXL Shield não pôde verificar a Proteção Estendida.',
            'Loopback test completed with HTTP %d, but the DPXL Shield prepend marker was not detected. On LiteSpeed this usually means the <IfModule LiteSpeed> / php_value directive was ignored by the PHP handler or server cache served the response without PHP.' => 'O teste de loopback terminou com HTTP %d, mas o marcador prepend do DPXL Shield não foi detectado. No LiteSpeed isso normalmente significa que a diretiva <IfModule LiteSpeed> / php_value foi ignorada pelo manipulador de PHP ou que o cache do servidor entregou a resposta sem executar PHP.',
            'DPXL Shield could not write the managed block to .htaccess. Trying .user.ini fallback.' => 'O DPXL Shield não conseguiu gravar o bloco gerenciado no .htaccess. Tentando o fallback via .user.ini.',
            'The .htaccess file is not writable. Trying .user.ini fallback.' => 'O arquivo .htaccess não está gravável. Tentando o fallback via .user.ini.',
            'Extended Protection is active through .user.ini. The WAF is now loading before WordPress.' => 'A Proteção Estendida está ativa via .user.ini. O WAF agora é carregado antes do WordPress.',
            'The .user.ini fallback was written. Some hosts cache .user.ini for a few minutes; refresh this page shortly to confirm Extended Protection.' => 'O fallback via .user.ini foi gravado. Algumas hospedagens mantêm cache do .user.ini por alguns minutos; atualize esta página em instantes para confirmar a Proteção Estendida.',
            'The .htaccess rule was ignored by the server and DPXL Shield could not enable the .user.ini fallback automatically. Use the manual configuration snippet.' => 'A regra do .htaccess foi ignorada pelo servidor e o DPXL Shield não conseguiu ativar automaticamente o fallback via .user.ini. Use o trecho de configuração manual.',
            'The .user.ini file is not writable or cannot be created: %s' => 'O arquivo .user.ini não está gravável ou não pôde ser criado: %s',
            'DPXL Shield could not create the safe prepend loader for the .user.ini fallback.' => 'O DPXL Shield não conseguiu criar o loader seguro para o fallback via .user.ini.',
            'DPXL Shield could not write the .user.ini fallback.' => 'O DPXL Shield não conseguiu gravar o fallback via .user.ini.',
            'The .user.ini fallback was written, but the server has not applied it yet. Some hosts cache .user.ini for a few minutes.' => 'O fallback via .user.ini foi gravado, mas o servidor ainda não aplicou a configuração. Algumas hospedagens mantêm cache do .user.ini por alguns minutos.',
            'DPXL Shield could not verify Extended Protection.' => 'O DPXL Shield não conseguiu verificar a Proteção Estendida.',
            'Invalid IP address.' => 'Endereço IP inválido.',
            'Invalid field or empty pattern.' => 'Campo inválido ou padrão vazio.',
            'Pattern is required.' => 'O padrão é obrigatório.',
            'A scan is already running.' => 'Já existe uma varredura em andamento.',
            'Scan queued. DPXL Shield will start it through WP-Cron immediately.' => 'Varredura enfileirada. O DPXL Shield iniciará a execução pelo WP-Cron imediatamente.',
            'Cancellation requested. The scanner will stop at the next safe checkpoint.' => 'Cancelamento solicitado. O scanner será interrompido no próximo ponto seguro.',
            'Invalid file path.' => 'Caminho de arquivo inválido.',
            'Invalid payload.' => 'Carga útil inválida.',
            'Empty body.' => 'Corpo vazio.',
            'Administrator' => 'Administrador',
            'Editor' => 'Editor',
            'Author' => 'Autor',
            'Contributor' => 'Colaborador',
            'Standard' => 'Padrão',
            'Checking…' => 'Verificando…',
            'Blacklist checks' => 'Verificações em listas de bloqueio',
            'Download Backup & Enable' => 'Baixar backup e ativar',
            'Apply Extended Protection' => 'Aplicar Proteção Estendida',
            'Detected server:' => 'Servidor detectado:',
            'Manual configuration fallback' => 'Configuração manual alternativa',
            'Backup current .htaccess' => 'Fazer backup do .htaccess atual',
            'Backup download registered at %s' => 'Backup registrado em %s',
            'Writable' => 'Gravável',
            '.htaccess path' => 'Caminho do .htaccess',
            'Safe prepend loader' => 'Loader seguro de prepend',
            'Plugin WAF file' => 'Arquivo WAF do plugin',
            'Yes' => 'Sim',
            'No' => 'Não',
            'IP Address' => 'Endereço IP',
            'Custom Pattern' => 'Padrão personalizado',
            'Filter by Type, Detail, or Reason…' => 'Filtrar por tipo, detalhe ou motivo…',
            'Filter' => 'Filtrar',
            'Unblock' => 'Desbloquear',
            'Make Permanent' => 'Tornar permanente',
            'Export All IPs' => 'Exportar todos os IPs',
            'Show DPXL Shield Automatic Blocks' => 'Mostrar bloqueios automáticos do DPXL Shield',
            'Detail' => 'Detalhe',
            'Reason' => 'Motivo',
            'Expiration' => 'Expiração',
            'Block Count' => 'Contagem de bloqueios',
            'Rule Added' => 'Regra adicionada',
            'Last Attempt' => 'Última tentativa',
            'No blocks active' => 'Nenhum bloqueio ativo',
            'Download Codes' => 'Baixar códigos',
            'Recovery codes generated. Download and store them in a safe place.' => 'Códigos de recuperação gerados. Baixe e guarde em um local seguro.',
            '2FA activated successfully. Save your recovery codes now.' => '2FA ativado com sucesso. Salve seus códigos de recuperação agora.',
            'Enter the 6-digit code from your authenticator app, or a backup code:' => 'Digite o código de 6 dígitos do aplicativo autenticador ou um código de recuperação:',
            'Verify' => 'Verificar',
            'Backup codes remaining: %d' => 'Códigos de recuperação restantes: %d',
            '2FA is ACTIVE for this account.' => 'O 2FA está ATIVO para esta conta.',
            '2FA is not active.' => 'O 2FA não está ativo.',
            'Set Up Two-Factor Authentication' => 'Configurar autenticação de dois fatores',
            'Reconfigure / Regenerate backup codes' => 'Reconfigurar / gerar novos códigos de recuperação',
            'Authenticator App' => 'Aplicativo autenticador',
            'Two-factor authentication required.' => 'Autenticação de dois fatores obrigatória.',
            'Invalid authentication code. Please try again.' => 'Código de autenticação inválido. Tente novamente.',
            'Logging mode:' => 'Modo de registro:',
            'Integrity:' => 'Integridade:',
            'Verify Log Chain' => 'Verificar cadeia do log',
            'All Severities' => 'Todas as severidades',
            'High' => 'Alto',
            'Medium' => 'Médio',
            'Low' => 'Baixo',
            'Info' => 'Informação',
            'All Event Types' => 'Todos os tipos de evento',
            'Authentication' => 'Autenticação',
            'User / Permissions' => 'Usuário / Permissões',
            'Plugins / Updates' => 'Plugins / Atualizações',
            'Site Settings' => 'Configurações do site',
            'Type' => 'Tipo',
            'Time' => 'Horário',
            'Event' => 'Evento',
            'Actor' => 'Autor',
            'User/Permissions' => 'Usuário/Permissões',
            'Plugin/Updates' => 'Plugin/Atualizações',
            'Content' => 'Conteúdo',
            'Copy Diagnostics' => 'Copiar diagnóstico',
            'Run Diagnostics' => 'Executar diagnóstico',
            'Click "Run Diagnostics" to start.' => 'Clique em "Executar diagnóstico" para começar.',
            'Export' => 'Exportar',
            'Download all DPXL Shield settings as a signed JSON file.' => 'Baixe todas as configurações do DPXL Shield como um arquivo JSON assinado.',
            'WAF rules, blocking config, scan settings, alert preferences, login security settings' => 'Regras WAF, configuração de bloqueios, configurações de varredura, preferências de alerta e segurança de login',
            'Logs, scan results, TOTP secrets and webhook endpoints are NOT exported' => 'Logs, resultados de varredura, segredos TOTP e webhooks NÃO são exportados',
            'Export Options' => 'Exportar opções',
            'Import' => 'Importar',
            'This will overwrite your current settings. Make sure to export a backup first.' => 'Isso substituirá suas configurações atuais. Exporte um backup antes de continuar.',
            'Choose File' => 'Escolher arquivo',
            'No file selected' => 'Nenhum arquivo selecionado',
            'Import Options' => 'Importar opções',
            'Import/Export' => 'Importação/Exportação',
            'Location' => 'Localização',
            'Page Visited' => 'Página visitada',
            'Request Detail' => 'Detalhes da requisição',
            'Block This IP' => 'Bloquear este IP',

            'Close' => 'Fechar',
            'Lookup' => 'Consultar',
            'Results for:' => 'Resultados para:',
            'Raw WHOIS response' => 'Resposta WHOIS bruta',
            'Looking up…' => 'Consultando…',
            'Enter IP address or domain…' => 'Digite um endereço IP ou domínio…',
            'Add to Whitelist' => 'Adicionar à lista de permissões',
            'Block Range /24' => 'Bloquear faixa /24',
            'Verify Log Chain' => 'Verificar cadeia do log',
            'Integrity:' => 'Integridade:',
            'All Severities' => 'Todas as severidades',
            'Medium' => 'Médio',
            'Low' => 'Baixo',
            'Info' => 'Informação',
            'All Event Types' => 'Todos os tipos de evento',
            'Authentication' => 'Autenticação',
            'User / Permissions' => 'Usuário / Permissões',
            'Plugins / Updates' => 'Plugins / Atualizações',
            'Site Settings' => 'Configurações do site',
            'Filter' => 'Filtrar',
            'Type' => 'Tipo',
            'Time' => 'Horário',
            'Event' => 'Evento',
            'Actor' => 'Agente',
            'User/Permissions' => 'Usuário/Permissões',
            'Plugin/Updates' => 'Plugin/Atualizações',
            'Content' => 'Conteúdo',
            'Disabled' => 'Desativado',
            'Preview' => 'Pré-visualização',
            'Significant Events' => 'Eventos significativos',
            'All Events' => 'Todos os eventos',
            'Copy Diagnostics' => 'Copiar diagnóstico',
            'Run Diagnostics' => 'Executar diagnóstico',
            'Click "Run Diagnostics" to start.' => 'Clique em "Executar diagnóstico" para começar.',
            'Download all DPXL Shield settings as a signed JSON file.' => 'Baixe todas as configurações do DPXL Shield como um arquivo JSON assinado.',
            'WAF rules, blocking config, scan settings, alert preferences, login security settings' => 'Regras do WAF, configurações de bloqueio, opções de varredura, preferências de alertas e segurança de login',
            'Logs, scan results, TOTP secrets and webhook endpoints are NOT exported' => 'Logs, resultados de varredura, segredos TOTP e webhooks NÃO são exportados',
            'This will overwrite your current settings. Make sure to export a backup first.' => 'Isso substituirá suas configurações atuais. Faça um backup exportando antes.',
            'Choose File' => 'Escolher arquivo',
            'No file selected' => 'Nenhum arquivo selecionado',
            'Error loading data. Please try again.' => 'Erro ao carregar os dados. Tente novamente.',
            'Are you sure?' => 'Tem certeza?',
            'Report Frequency' => 'Frequência do relatório',
            'Login attempt threshold' => 'Limite de tentativas de login',
            'Window (minutes)' => 'Janela (minutos)',
            'Rate Limiting' => 'Limitação de taxa',
            'Full scan hour (0–23 UTC)' => 'Hora da varredura completa (0–23 UTC)',
            'Allow on-demand scans' => 'Permitir varreduras sob demanda',
            'Log retention (hours)' => 'Retenção de logs (horas)',
            'Logging mode' => 'Modo de registro',
            'HIBP password audit' => 'Auditoria de senhas HIBP',
            'Generic login error messages' => 'Mensagens genéricas de erro de login',
            'Live Traffic Options' => 'Opções de tráfego ao vivo',
            'Tool Options' => 'Opções de ferramentas',
            'Block IP Range /24' => 'Bloquear faixa /24',
            'Add to Whitelist' => 'Adicionar à lista de permissões',
            'If DPXL Shield cannot update .htaccess automatically because of server permissions or hosting restrictions, add the configuration below manually and keep the downloaded .htaccess backup before changing anything. The auto_prepend_file rule should point to the safe prepend loader, not directly to the plugin folder.' => 'Se o DPXL Shield não conseguir atualizar o .htaccess automaticamente por permissões do servidor ou restrições da hospedagem, adicione a configuração abaixo manualmente e mantenha o backup baixado do .htaccess antes de alterar qualquer coisa. A regra auto_prepend_file deve apontar para o loader seguro, não diretamente para a pasta do plugin.',
            'Block Type:' => 'Tipo de bloqueio:',
            'Block IP' => 'Bloquear IP',
            'IP / CIDR' => 'IP / CIDR',
            'Source' => 'Origem',
            'Expires' => 'Expira em',
            'Block countries below' => 'Bloquear países abaixo',
            'Allow only countries below' => 'Permitir apenas países abaixo',
            'Add Custom Pattern' => 'Adicionar padrão personalizado',
            'Field' => 'Campo',
            'Pattern' => 'Padrão',
            'Match' => 'Correspondência',
            'Contains' => 'Contém',
            'Equals' => 'Igual',
            'Regex' => 'Regex',
            'Action' => 'Ação',
            'Block' => 'Bloquear',
            'Log Only' => 'Apenas registrar',
            'Reason (optional)' => 'Motivo (opcional)',
            'Add Rule' => 'Adicionar regra',
            'Scan Type' => 'Tipo de varredura',
            'Malware Signatures' => 'Assinaturas de malware',
            'Reputation' => 'Reputação',
            'Blacklist checks' => 'Verificações em listas de bloqueio',
            'Scan WordPress core files' => 'Verificar arquivos do núcleo do WordPress',
            'Scan plugin files' => 'Verificar arquivos de plugins',
            'Scan theme files' => 'Verificar arquivos de temas',
            'Scan uploads directory' => 'Verificar diretório de uploads',
            'Scan post content for malicious links' => 'Verificar conteúdo em busca de links maliciosos',
        ];

        $fallback = is_string($translated) ? $translated : (string) ($translated ?? '');
        return $map[$text] ?? $fallback;
    }

    public function enqueueAssets(string $hookSuffix): void {
        // Only on our pages.
        if (!str_contains($hookSuffix, 'dpxl-shield')) {
            return;
        }

        $version = defined('DPXL_SHIELD_VERSION') ? DPXL_SHIELD_VERSION : '1.0.0';
        $url     = defined('DPXL_SHIELD_URL') ? DPXL_SHIELD_URL : '';
        $cssPath = defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH . 'assets/css/admin.css' : '';
        $jsPath  = defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH . 'assets/js/admin.js' : '';
        $cssVer  = file_exists($cssPath) ? (string) filemtime($cssPath) : $version;
        $jsVer   = file_exists($jsPath) ? (string) filemtime($jsPath) : $version;

        wp_enqueue_style(
            'dpxl-shield-admin',
            $url . 'assets/css/admin.css',
            [],
            $cssVer
        );

        $qrPath = defined('DPXL_SHIELD_PATH') ? DPXL_SHIELD_PATH . 'assets/js/qrcode-local.js' : '';
        $qrVer  = file_exists($qrPath) ? (string) filemtime($qrPath) : $version;

        wp_enqueue_script(
            'dpxl-shield-qrcode',
            $url . 'assets/js/qrcode-local.js',
            [],
            $qrVer,
            true
        );

        wp_enqueue_script(
            'dpxl-shield-admin',
            $url . 'assets/js/admin.js',
            ['dpxl-shield-qrcode'],
            $jsVer,
            true
        );

        wp_localize_script('dpxl-shield-admin', 'dpxlShield', [
            'restUrl'   => rest_url('dpxl-shield/v1/'),
            'nonce'     => wp_create_nonce('wp_rest'),
            'adminUrl'  => admin_url('admin.php'),
            'version'   => $version,
            'downloadHtaccessUrl' => wp_nonce_url(admin_url('admin-post.php?action=dpxl_shield_download_htaccess_backup'), 'dpxl_shield_download_htaccess_backup'),
            'enableExtendedUrl'   => wp_nonce_url(admin_url('admin-post.php?action=dpxl_shield_enable_extended'), 'dpxl_shield_enable_extended'),
            'downloadReportUrl'   => wp_nonce_url(admin_url('admin-post.php?action=dpxl_shield_download_report_pdf'), 'dpxl_shield_download_report_pdf'),
            'strings'   => [
                'loading'  => __('Loading…', 'dpxl-shield'),
                'error'    => __('Error loading data. Please try again.', 'dpxl-shield'),
                'saved'    => __('Settings saved.', 'dpxl-shield'),
                'confirm'  => __('Are you sure?', 'dpxl-shield'),
            ],
        ]);
    }

    // ── Extended Protection admin-post handlers ─────────────────────────

    public function downloadHtaccessBackup(): void {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to download this file.', 'dpxl-shield'));
        }

        check_admin_referer('dpxl_shield_download_htaccess_backup');

        $autoPrepend = new AutoPrepend();
        $content     = $autoPrepend->getHtaccessDownloadContent();
        $filename    = $autoPrepend->getDownloadFilename();

        $autoPrepend->markHtaccessBackupDownloaded();

        nocache_headers();
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        header('Content-Length: ' . strlen($content));

        echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- plain-text file download (the site's own .htaccess), not HTML.
        exit;
    }

    /**
     * Streams an on-demand branded PDF of the current activity report, using the
     * same figures the scheduled email carries.
     */
    public function downloadReportPdf(): void {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to download this report.', 'dpxl-shield'));
        }

        check_admin_referer('dpxl_shield_download_report_pdf');

        $data   = ReportData::collect((string) Options::get('activity_report_frequency', 'weekly'));
        $report = new PdfReport();

        ReportI18n::activate();
        try {
            $pdf = $report->render($data);
        } finally {
            ReportI18n::deactivate();
        }

        nocache_headers();
        header('Content-Type: application/pdf');
        header('Content-Disposition: attachment; filename="' . $report->filename($data) . '"');
        header('Content-Length: ' . strlen($pdf));

        echo $pdf; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- binary PDF download, not HTML.
        exit;
    }

    /**
     * Runs the threat-feed updater on demand and returns to All Options with a
     * notice carrying the result.
     */
    public function checkFeed(): void {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to do this.', 'dpxl-shield'));
        }

        check_admin_referer('dpxl_shield_check_feed');

        // "Check now" covers the whole feed: WAF rules and the country database.
        $status    = (new ThreatFeedUpdater())->run();
        $geoStatus = (new GeoDbUpdater())->run();
        set_transient(
            'dpxl_shield_feed_check_' . get_current_user_id(),
            ['rules' => $status, 'geo' => $geoStatus],
            60
        );

        wp_safe_redirect(add_query_arg(
            ['dpxl_feed_checked' => '1'],
            admin_url('admin.php?page=dpxl-shield-options')
        ));
        exit;
    }

    public function enableExtendedFromPost(): void {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to enable Extended Protection.', 'dpxl-shield'));
        }

        check_admin_referer('dpxl_shield_enable_extended');

        $result = (new AutoPrepend())->enableHtaccessAfterBackup(true);
        set_transient('dpxl_shield_extended_result_' . get_current_user_id(), $result, 60);

        wp_safe_redirect(add_query_arg(
            ['dpxl_extended_result' => '1'],
            admin_url('admin.php?page=dpxl-shield-firewall&tab=firewall#extended-protection')
        ));
        exit;
    }

    // ── Notices ────────────────────────────────────────────────────────────

    public function maybeExtendedProtectionNotice(): void {
        $screen = get_current_screen();

        if (!$screen || !str_contains($screen->id, 'dpxl-shield')) {
            return;
        }

        if (isset($_GET['dpxl_extended_result'])) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only: picks which tab or notice to show.
            $result = get_transient('dpxl_shield_extended_result_' . get_current_user_id());
            delete_transient('dpxl_shield_extended_result_' . get_current_user_id());

            if (is_array($result)) {
                $class   = !empty($result['success']) ? 'notice-success' : 'notice-error';
                $message = (string) ($result['message'] ?? __('Extended Protection setup finished.', 'dpxl-shield'));

                echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p><strong>' . esc_html__('DPXL Shield', 'dpxl-shield') . '</strong> — ' . esc_html($message) . '</p></div>';
            }
        }

        if (defined('DPXL_SHIELD_EXTENDED_ACTIVE')) {
            return;
        }

        $wizardUrl = admin_url('admin.php?page=dpxl-shield-firewall&tab=firewall#extended-protection');

        echo '<div class="notice notice-warning dpxl-notice dpxl-notice--extended-warning">';
        echo '<p><strong>' . esc_html__('DPXL Shield', 'dpxl-shield') . '</strong> — ';
        echo esc_html__('Extended Protection is not active. Your firewall loads after WordPress, reducing protection.', 'dpxl-shield') . ' ';
        echo '<a href="' . esc_url($wizardUrl) . '">' . esc_html__('Enable now', 'dpxl-shield') . ' ';
        Icons::render('arrow-right', '', 13);
        echo '</a></p>';
        echo '</div>';
    }

    // ── View renderers ─────────────────────────────────────────────────────

    public function renderDashboard(): void {
        $this->renderView('dashboard');
    }

    public function renderFirewall(): void {
        $this->renderView('firewall');
    }

    public function renderScan(): void {
        $this->renderView('scanner');
    }

    public function renderLoginSecurity(): void {
        $this->renderView('login-security');
    }

    public function renderTools(): void {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to view this page.', 'dpxl-shield'));
        }

        $tab  = sanitize_key($_GET['tab'] ?? 'live-traffic'); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only: picks which tab or notice to show.
        // Must stay in step with $toolTabs in Views/tools.php and with the
        // partials in Views/tools/. A tab missing here is still drawn in the
        // nav and still has a view file, but the whitelist silently rewrites
        // the request to live-traffic — which is how Integrações became
        // unreachable: the link was there, and clicking it landed on the
        // traffic log. ToolsTabsTest compares the three.
        $tabs = ['live-traffic', 'audit-log', 'whois', 'integrations', 'import-export', 'diagnostics'];
        $tab  = in_array($tab, $tabs, true) ? $tab : 'live-traffic';

        $wrapperFile = self::VIEWS_DIR . 'tools.php';
        if (file_exists($wrapperFile)) {
            include $wrapperFile;
        } else {
            echo '<div class="wrap"><h1>' . esc_html__('DPXL Shield', 'dpxl-shield') . '</h1>';
            echo '<p>' . esc_html__('View not found:', 'dpxl-shield') . ' tools.php</p></div>';
        }
    }

    public function renderAllOptions(): void {
        $this->renderView('all-options');
    }

    // ── Internal ───────────────────────────────────────────────────────────

    private function renderView(string $name): void {
        if (!current_user_can(self::CAPABILITY)) {
            wp_die(esc_html__('You do not have permission to view this page.', 'dpxl-shield'));
        }

        $file = self::VIEWS_DIR . $name . '.php';

        if (file_exists($file)) {
            include $file;
        } else {
            echo '<div class="wrap"><h1>' . esc_html__('DPXL Shield', 'dpxl-shield') . '</h1>';
            echo '<p>' . esc_html__('View not found:', 'dpxl-shield') . ' ' . esc_html($name) . '</p></div>';
        }
    }
}
