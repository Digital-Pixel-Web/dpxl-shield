<?php
declare(strict_types=1);

namespace DPXL\Shield\Alerts;

/**
 * Human-readable names, explanations and next steps for alert events.
 *
 * Event types are machine slugs (`new_admin_ip_login`, `fw.reputation_hit`).
 * They are fine in the audit log and in webhooks, but they must never reach
 * an email subject line or heading. This catalog maps each slug to a short
 * title, a one-sentence explanation of what actually happened, the imperative
 * next steps, and the screen the alert's button should open.
 *
 * Unknown slugs fall back to a humanised form of the slug itself, so a new
 * event type still produces a readable email before it is catalogued here.
 *
 * Language: the plugin is pt-BR first (see ReportI18n for the why), and these
 * strings are written in Portuguese rather than routed through the translation
 * filters. The alert shell has been pt-BR since 1.4.0; until 1.8.0 the catalog
 * was English, so every alert arrived half-translated.
 *
 * The strings here are also what the webhook/Slack/Discord integrations send
 * (see Integrations\PayloadBuilder), so those payloads became pt-BR too.
 */
class EventCatalog {

    /**
     * Short title — used in the subject line and as the email heading.
     */
    public static function label(string $eventType): string {
        $labels = [
            // Authentication
            'new_admin_ip_login'       => 'Login de administrador de um endereço novo',
            'brute_force_lockout'      => 'Endereço bloqueado após tentativas de login',
            'auth.lockout'             => 'Endereço bloqueado após tentativas de login',
            '2fa_activated'            => 'Verificação em duas etapas ativada',
            '2fa_deactivated'          => 'Verificação em duas etapas desativada',
            'pwned_password_login'     => 'Login com senha que aparece em vazamento',
            'pwned_password_reset'     => 'Senha redefinida após aparecer em vazamento',

            // Users
            'user.created'             => 'Nova conta de usuário criada',
            'user.deleted'             => 'Conta de usuário excluída',
            'user.role_changed'        => 'Conta promovida a administrador',

            // Firewall / traffic
            'fw.ip_blocked'            => 'Endereço de IP bloqueado',
            'fw.rule_triggered'        => 'Regra do firewall acionada',
            'fw.reputation_hit'        => 'Seu site foi listado em uma blocklist',
            'anomaly_detected'         => 'Padrão de tráfego suspeito detectado',
            'honeypot_triggered'       => 'Campo-armadilha preenchido por um robô',
            'decoy_accessed'           => 'Endereço-isca acessado',

            // Integrity / self-protection
            'file_modified'            => 'Arquivo do WordPress alterado',
            'plugin_tampered'          => 'Os arquivos do DPXL Shield foram alterados',
            'plugin_deactivated'       => 'O DPXL Shield foi desativado',
            'plugin_deleted'           => 'O DPXL Shield foi excluído',
            'integrity_store_conflict' => 'Os registros de integridade não batem entre si',

            // Scanner
            'scan_found_criticals'     => 'A varredura encontrou ameaças para revisar',
        ];

        return isset($labels[$eventType]) ? $labels[$eventType] : self::humanise($eventType);
    }

    /**
     * One sentence explaining o que aconteceu, em português.
     *
     * This is the lead paragraph of the email. The dispatcher's own
     * `description` is factual but written in English at the call site
     * (`"Admin 'x' logged in from a new IP: 1.2.3.4"`), so it travels in the
     * technical details instead of the lead — see EmailChannel::buildBody().
     */
    public static function summary(string $eventType): string {
        $summaries = [
            'new_admin_ip_login'       => 'Uma conta de administrador entrou no painel a partir de uma rede que o DPXL Shield nunca tinha visto nesta conta.',
            'brute_force_lockout'      => 'Várias tentativas de login falharam a partir do mesmo endereço, então ele foi bloqueado automaticamente.',
            'auth.lockout'             => 'Várias tentativas de login falharam a partir do mesmo endereço, então ele foi bloqueado automaticamente.',
            '2fa_activated'            => 'A verificação em duas etapas foi ativada para uma conta deste site.',
            '2fa_deactivated'          => 'A verificação em duas etapas foi desativada para uma conta deste site.',
            'pwned_password_login'     => 'Esta conta entrou usando uma senha que aparece em um vazamento público conhecido.',
            'pwned_password_reset'     => 'A senha desta conta aparecia em um vazamento público conhecido e foi redefinida.',
            'user.created'             => 'Uma nova conta foi adicionada a este site.',
            'user.deleted'             => 'Uma conta foi removida deste site.',
            'user.role_changed'        => 'Uma conta recebeu acesso de administrador. Administradores podem instalar plugins e editar qualquer conteúdo.',
            'fw.ip_blocked'            => 'Um endereço de IP passou a ser bloqueado pelo firewall deste site.',
            'fw.rule_triggered'        => 'Uma requisição casou com uma regra do firewall e foi barrada antes de chegar ao site.',
            'fw.reputation_hit'        => 'Uma blocklist externa está sinalizando este site. Buscadores e provedores de e-mail podem começar a avisar os visitantes.',
            'anomaly_detected'         => 'O motor comportamental viu um padrão de requisições típico de varredura automatizada.',
            'honeypot_triggered'       => 'Um campo escondido, invisível para pessoas, foi preenchido — sinal confiável de automação.',
            'decoy_accessed'           => 'Uma URL-isca, que nenhum visitante legítimo deveria pedir, foi acessada.',
            'file_modified'            => 'Um arquivo de que o WordPress depende mudou. Atualizações normais também mudam arquivos; fora delas, isso pode indicar invasão.',
            'plugin_tampered'          => 'Os arquivos do próprio DPXL Shield não batem mais com as somas de verificação assinadas. Malware costuma desativar o plugin de segurança primeiro.',
            'plugin_deactivated'       => 'A proteção do site está desligada neste momento.',
            'plugin_deleted'           => 'A proteção do site foi removida deste site.',
            'integrity_store_conflict' => 'As três cópias independentes da linha de base de integridade não concordam mais entre si.',
            'scan_found_criticals'     => 'A última varredura terminou com achados que precisam de revisão.',
        ];

        return isset($summaries[$eventType]) ? $summaries[$eventType] : '';
    }

    /**
     * Why this alert can show up without anything being wrong.
     *
     * Only for the event types that genuinely do fire on normal activity. Each
     * one here exists because it burned us: the IPv6 note is the rotating
     * residential prefix that alerted on every login until 1.6.3, and the
     * file note is the WordPress update that sent 89 "compromise" emails.
     * An event without a real caveat gets none — a reassurance on every alert
     * teaches the reader to discount all of them.
     */
    public static function caveat(string $eventType): string {
        $caveats = [
            'new_admin_ip_login' => 'Conexões residenciais com IPv6 trocam de rede sozinhas, às vezes todo dia. Se você reconhece o país e costuma acessar daí, provavelmente é você mesmo.',
            'file_modified'      => 'Atualizar o WordPress, um plugin ou um tema também altera arquivos. Um alerta logo depois de uma atualização costuma ser exatamente isso.',
            'anomaly_detected'   => 'Varredores automáticos passam em qualquer site exposto na internet. A maioria desses alertas não é um ataque direcionado ao seu site.',
        ];

        return isset($caveats[$eventType]) ? $caveats[$eventType] : '';
    }

    /**
     * Imperative next steps — the "O que fazer" block of the email.
     *
     * Every alert answers the reader's real question. Where the honest answer
     * is "nothing", it says so in the first line instead of leaving the reader
     * to guess, because an alert that cannot be acted on and does not say so is
     * how people learn to ignore the sender.
     *
     * @return list<string>
     */
    public static function actions(string $eventType): array {
        $actions = [
            'new_admin_ip_login' => [
                'Reconhece a origem acima e foi você quem entrou? Nenhuma ação é necessária.',
                'Não reconhece? Troque a senha desta conta e ative a verificação em duas etapas.',
            ],
            'brute_force_lockout' => [
                'Nenhuma ação é necessária: o bloqueio é automático e expira sozinho.',
                'Se o endereço for de alguém da sua equipe e a pessoa ficou de fora, remova o bloqueio em Firewall → Bloqueios.',
            ],
            'auth.lockout' => [
                'Nenhuma ação é necessária: o bloqueio é automático e expira sozinho.',
                'Se o endereço for de alguém da sua equipe e a pessoa ficou de fora, remova o bloqueio em Firewall → Bloqueios.',
            ],
            '2fa_activated' => [
                'Nenhuma ação é necessária.',
                'Se não foi a pessoa dona da conta quem ativou, revise quem tem acesso a ela.',
            ],
            '2fa_deactivated' => [
                'Confirme com a pessoa dona da conta se foi ela quem desativou.',
                'Se não foi, troque a senha da conta e reative a verificação em duas etapas.',
            ],
            'pwned_password_login' => [
                'Troque a senha desta conta agora: ela aparece em um vazamento público conhecido.',
                'Ative a verificação em duas etapas para esta conta.',
            ],
            'pwned_password_reset' => [
                'Avise a pessoa dona da conta: ela precisará definir uma senha nova para entrar.',
            ],
            'user.created' => [
                'Confirme que esta conta foi criada por alguém da sua equipe.',
                'Se o cadastro aberto não é intencional, desligue-o em Configurações → Geral do WordPress.',
            ],
            'user.deleted' => [
                'Confirme que a exclusão foi intencional. Contas removidas não voltam sozinhas.',
            ],
            'user.role_changed' => [
                'Confirme que esta promoção foi intencional.',
                'Se não foi, rebaixe a conta agora e troque a senha de quem fez a alteração.',
            ],
            'fw.ip_blocked' => [
                'Nenhuma ação é necessária: o bloqueio já está em vigor.',
                'Se o endereço for de alguém da sua equipe, remova o bloqueio em Firewall → Bloqueios.',
            ],
            'fw.rule_triggered' => [
                'Nenhuma ação é necessária: a requisição foi barrada antes de chegar ao site.',
            ],
            'fw.reputation_hit' => [
                'Rode uma varredura completa para encontrar o que motivou a listagem.',
                'Depois de limpar o site, peça a remoção no site da própria blocklist — ela não sai sozinha.',
            ],
            'anomaly_detected' => [
                'Nenhuma ação imediata é necessária.',
                'Se o mesmo endereço insistir, bloqueie-o em Firewall → Bloqueios.',
            ],
            'honeypot_triggered' => [
                'Nenhuma ação é necessária: o campo é invisível para pessoas, então o preenchimento foi automação.',
            ],
            'decoy_accessed' => [
                'Nenhuma ação é necessária: o endereço acessado não existe para visitantes legítimos.',
            ],
            'file_modified' => [
                'Acabou de atualizar o WordPress, um plugin ou um tema? Então isso é esperado.',
                'Não atualizou nada? Compare o arquivo com o original e restaure-o pela tela de Varredura.',
            ],
            'plugin_tampered' => [
                'Rode uma varredura completa agora.',
                'Se você não atualizou nem editou o DPXL Shield, trate como invasão: troque as senhas de administrador e as do painel de hospedagem.',
            ],
            'plugin_deactivated' => [
                'Reative o DPXL Shield.',
                'Se não foi você quem desativou, trate como invasão: troque as senhas de administrador e as do painel de hospedagem.',
            ],
            'plugin_deleted' => [
                'Reinstale o DPXL Shield.',
                'Se não foi você quem excluiu, trate como invasão: troque as senhas de administrador e as do painel de hospedagem.',
            ],
            'integrity_store_conflict' => [
                'Rode uma varredura completa.',
                'Se o conflito continuar depois dela, acione o suporte da Digital Pixel.',
            ],
            // Severity-neutral on purpose: since 1.8.1 this alert also fires
            // when the worst finding is `high`, so "trate o que está marcado
            // como crítico" would point at a section that is not there.
            'scan_found_criticals' => [
                'Abra os resultados e trate primeiro os achados de maior severidade.',
                'Plugins e temas desatualizados aparecem como recomendação: atualize-os quando puder.',
            ],
        ];

        return isset($actions[$eventType]) ? $actions[$eventType] : [];
    }

    /**
     * Label and admin query string for the alert's primary button.
     *
     * The button used to point every alert at the plugin's front page, which
     * made the reader hunt for the thing the email had just told them about.
     *
     * @return array{label: string, query: string}
     */
    public static function primaryLink(string $eventType): array {
        $login     = ['label' => 'Ver segurança de login', 'query' => 'page=dpxl-shield-login'];
        $traffic   = ['label' => 'Ver tráfego ao vivo',    'query' => 'page=dpxl-shield-tools&tab=live-traffic'];
        $audit     = ['label' => 'Ver log de auditoria',   'query' => 'page=dpxl-shield-tools&tab=audit-log'];
        $scan      = ['label' => 'Ver resultados da varredura', 'query' => 'page=dpxl-shield-scan'];
        $blocking  = ['label' => 'Ver bloqueios',          'query' => 'page=dpxl-shield-firewall&tab=blocking'];
        $dashboard = ['label' => 'Abrir o DPXL Shield',    'query' => 'page=dpxl-shield'];

        $links = [
            'new_admin_ip_login'       => $login,
            'brute_force_lockout'      => $blocking,
            'auth.lockout'             => $blocking,
            '2fa_activated'            => $login,
            '2fa_deactivated'          => $login,
            'pwned_password_login'     => $login,
            'pwned_password_reset'     => $login,
            'user.created'             => $audit,
            'user.deleted'             => $audit,
            'user.role_changed'        => $audit,
            'fw.ip_blocked'            => $blocking,
            'fw.rule_triggered'        => $traffic,
            'fw.reputation_hit'        => $scan,
            'anomaly_detected'         => $traffic,
            'honeypot_triggered'       => $traffic,
            'decoy_accessed'           => $traffic,
            'file_modified'            => $scan,
            'plugin_tampered'          => $scan,
            'plugin_deactivated'       => $dashboard,
            'plugin_deleted'           => $dashboard,
            'integrity_store_conflict' => $scan,
            'scan_found_criticals'     => $scan,
        ];

        return isset($links[$eventType]) ? $links[$eventType] : $dashboard;
    }

    /**
     * Context field keys the dispatchers send, and what a reader sees.
     *
     * A constant rather than a local so FieldLabelCoverageTest can compare it
     * against the keys actually dispatched across src/ — a key with no entry
     * here falls back to a humanised slug and lands in English inside an
     * otherwise pt-BR email, which is the half-translation 1.8.0 set out to
     * remove.
     *
     * @var array<string,string>
     */
    private const FIELD_LABELS = [
        'username'    => 'Usuário',
        'user_login'  => 'Usuário',
        'user_id'     => 'ID do usuário',
        'ip'          => 'Endereço IP',
        'hostname'    => 'Nome do host',
        'country'     => 'País',
        'uri'         => 'URL',
        'url'         => 'URL',
        'user_agent'  => 'Navegador',
        'referer'     => 'Veio de',
        'rule_id'     => 'Regra',
        'reason'      => 'Motivo',
        'file'        => 'Arquivo',
        'file_path'   => 'Arquivo',
        'plugin'      => 'Plugin',
        'scan_id'     => 'ID da varredura',
        'attempts'    => 'Tentativas',
        'new_role'    => 'Novo papel',
        'old_roles'   => 'Papéis anteriores',

        // Every other key the dispatchers actually send. Without an entry
        // here the fallback humanises the slug and the row lands in English
        // ("Lockout seconds") inside an otherwise pt-BR email.
        'count'                => 'Quantidade',
        'critical'             => 'Críticos',
        'domain'               => 'Domínio',
        'failures'             => 'Falhas',
        'files'                => 'Arquivos',
        'hibp_count'           => 'Aparições em vazamentos',
        'lockout_seconds'      => 'Bloqueio (segundos)',
        'method'               => 'Método',
        'metric'               => 'Métrica',
        'network_deactivating' => 'Desativação em toda a rede',
        'our_plugin'           => 'É o DPXL Shield',
        'results'              => 'Resultados',
        'timestamp'            => 'Horário',
    ];

    /**
     * Human label for a context field key (`user_id` → `ID do usuário`).
     */
    public static function fieldLabel(string $key): string {
        return isset(self::FIELD_LABELS[$key]) ? self::FIELD_LABELS[$key] : self::humanise($key);
    }

    /**
     * `fw.rule_triggered` → `Rule triggered`. Last-resort readable form for a
     * slug that has not been catalogued yet.
     */
    private static function humanise(string $slug): string {
        $slug = (string) preg_replace('/^[a-z]+\./', '', $slug);
        $slug = str_replace(['_', '-'], ' ', $slug);

        return ucfirst(trim($slug));
    }
}
