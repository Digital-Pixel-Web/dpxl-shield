/**
 * DPXL Shield — Admin JavaScript
 *
 * All data is loaded via REST API (dpxl-shield/v1/*).
 * No page-level status values are hard-coded in PHP renders.
 */
/* global dpxlShield */
'use strict';

(function () {

    // ── API helper ──────────────────────────────────────────────────────────

    const api = {
        async get(endpoint, params = {}) {
            const url = new URL(dpxlShield.restUrl + endpoint);
            Object.entries(params).forEach(([k, v]) => v !== '' && url.searchParams.set(k, v));
            const res = await fetch(url, { headers: { 'X-WP-Nonce': dpxlShield.nonce } });
            if (!res.ok) throw new Error(await parseApiError(res));
            return res.json();
        },
        async post(endpoint, body = {}) {
            const res = await fetch(dpxlShield.restUrl + endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-WP-Nonce': dpxlShield.nonce },
                body: JSON.stringify(body),
            });
            if (!res.ok) throw new Error(await parseApiError(res));
            return res.json();
        },
        async delete(endpoint) {
            const res = await fetch(dpxlShield.restUrl + endpoint, {
                method: 'DELETE',
                headers: { 'X-WP-Nonce': dpxlShield.nonce },
            });
            if (!res.ok) throw new Error(await parseApiError(res));
            return res.json();
        },
    };

    async function parseApiError(res) {
        try {
            const data = await res.json();
            return data?.message || data?.error || `HTTP ${res.status}`;
        } catch (e) {
            return `HTTP ${res.status}`;
        }
    }

    // ── UI helpers ──────────────────────────────────────────────────────────

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = String(s ?? '');
        return d.innerHTML;
    }

    function setGaugeStatus(id, status, pct, label) {
        const g = document.getElementById(id);
        if (!g) return;
        g.dataset.status = status;
        const p = g.querySelector('.dpxl-gauge__pct');
        if (p) p.textContent = pct;
        const s = g.querySelector('.dpxl-gauge__sub');
        if (s && label) s.textContent = label;
    }

    function showNotice(msg, type = 'success') {
        const el = document.createElement('div');
        el.className = `dpxl-notice dpxl-notice--${type}`;
        el.textContent = msg;
        const wrap = document.querySelector('.dpxl-wrap');
        if (wrap) wrap.insertAdjacentElement('afterbegin', el);
        setTimeout(() => el.remove(), 4000);
    }

    function setExtendedActionStatus(message, type = 'warning', loading = false) {
        const el = document.getElementById('extended-action-status');
        if (!el) return;

        el.className = `dpxl-notice dpxl-notice--${type} dpxl-extended-action-status${loading ? ' is-loading' : ''}`;
        el.textContent = message;
        el.classList.remove('dpxl-hidden');
    }

    function hideExtendedActionStatus() {
        const el = document.getElementById('extended-action-status');
        if (!el) return;
        el.classList.add('dpxl-hidden');
        el.classList.remove('is-loading');
    }

    function reloadFirewallAfterDelay(delay = 1200) {
        window.setTimeout(() => {
            const url = new URL(window.location.href);
            url.searchParams.set('tab', 'firewall');
            url.hash = 'extended-protection';
            window.location.href = url.toString();
        }, delay);
    }

    // Mirrors TrafficClassifier::classify() (src/Traffic/TrafficClassifier.php).
    // Only is_bot is persisted, so 'suspicious' is derived here from the same
    // signals the PHP classifier uses. Keep the two in sync.
    function trafficType(row) {
        if (row.waf_action === 'block') return 'blocked';
        if (row.is_bot === '1' || row.is_bot === 1) return 'bot';
        if (!String(row.user_agent || '').trim()) return 'suspicious';
        if (row.waf_action === 'log_only' || Number(row.status_code) === 403) return 'suspicious';
        return 'human';
    }

    function dots(type) {
        const map = { human: 'green', bot: 'yellow', blocked: 'red', suspicious: 'orange', unknown: 'gray' };
        const color = map[type] || 'gray';
        return `<span class="dpxl-dot dpxl-dot--${color}" title="${esc(type)}"></span>`;
    }

    function auditDot(category) {
        const map = { authentication: 'yellow', user_permissions: 'purple', plugin_themes: 'blue', firewall: 'red', site_settings: 'green', content: 'gray' };
        const color = map[category] || 'gray';
        return `<span class="dpxl-audit-dot dpxl-audit-dot--${color}"></span>`;
    }

    function formatDate(ts) {
        if (!ts) return '—';
        return new Date(ts.replace(' ', 'T') + 'Z').toLocaleString();
    }

    // ── SVG icons (mirror of src/Admin/Icons.php — keep in sync) ─────────────
    const ICONS = {
        'alert-triangle': '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
        'alert-circle': '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
        'info': '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
        'check': '<polyline points="20 6 9 17 4 12"/>',
        'check-circle': '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>',
        'x': '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
        'eye': '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
        'download': '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
        'arrow-right': '<line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>',
        'chevron-right': '<polyline points="9 18 15 12 9 6"/>',
        'chevron-down': '<polyline points="6 9 12 15 18 9"/>',
        'external-link': '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>',
        'infinity': '<path d="M18.18 8c-5.1 0-7.13 8-12.74 8-4.58 0-4.58-8 0-8 5.61 0 7.64 8 12.74 8 5.1 0 5.1-8 0-8z"/>',
        'settings': '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
        'shield': '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        'activity': '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
        'globe': '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
        'clock': '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
        'bell': '<path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/>',
        'list': '<line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/>',
        'search': '<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>',
    };

    function icon(name, cls = '', size = 16) {
        const inner = ICONS[name] || ICONS.info;
        return `<svg class="dpxl-icon ${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${inner}</svg>`;
    }

    // Severity → semantic icon, coloured via CSS (.dpxl-icon--<sev>).
    function severityIcon(s) {
        const map = { critical: 'alert-triangle', high: 'alert-triangle', medium: 'alert-circle', low: 'info', info: 'info' };
        return icon(map[s] || 'info', 'dpxl-icon--' + (s || 'info'));
    }

    // Generic status (ok/warning/error) → icon.
    function statusIcon(status) {
        const map = { ok: 'check-circle', warning: 'alert-triangle', error: 'alert-circle' };
        return icon(map[status] || 'info', 'dpxl-icon--' + (status === 'ok' ? 'ok' : status === 'error' ? 'critical' : 'medium'));
    }

    // ── Page detection ──────────────────────────────────────────────────────

    const page = new URLSearchParams(location.search).get('page') || '';
    const tab  = new URLSearchParams(location.search).get('tab')  || '';

    // ── Dashboard ───────────────────────────────────────────────────────────

    if (page === 'dpxl-shield' || page === '') {
        initDashboard();
    }

    async function initDashboard() {
        try {
            const data = await api.get('dashboard');

            // Banner
            const banner = document.getElementById('dpxl-protection-banner');
            if (banner) {
                const ok = data.firewall_ok && data.scan_ok && data.login_ok;
                banner.className = `dpxl-banner dpxl-banner--${ok ? 'ok' : 'error'}`;
                banner.innerHTML = (ok ? icon('shield', '', 20) : statusIcon('error'))
                    + `<span class="dpxl-banner__text">${ok
                        ? 'Proteção do DPXL Shield ativa'
                        : 'Proteção degradada — veja as notificações abaixo'}</span>`;
            }

            // Gauges
            setGaugeStatus('gauge-firewall', data.firewall_ok ? 'ok' : 'error', data.firewall_ok ? '100%' : '—', null);
            setGaugeStatus('gauge-scan',     data.scan_ok     ? 'ok' : 'error', data.scan_ok     ? '100%' : data.scan_issues?.total + ' issues', null);
            setGaugeStatus('gauge-login',    data.login_ok    ? 'ok' : 'error', data.login_ok    ? '100%' : '—', null);

            // Firewall summary
            const tbody = document.getElementById('firewall-summary-tbody');
            if (tbody) {
                const rows = [
                    ['Complex (WAF rules)', 0, 0, 0],
                    ['Brute Force',         0, 0, 0],
                    ['Blocklist',           0, 0, 0],
                    ['Country',             0, 0, 0],
                ];
                const total = [0, 0, 0];
                tbody.innerHTML = rows.map(r =>
                    `<tr><td>${esc(r[0])}</td><td>${r[1]}</td><td>${r[2]}</td><td>${r[3]}</td></tr>`
                ).join('') + `<tfoot><tr><td><strong>Total</strong></td><td>${data.attacks.today}</td><td>${data.attacks.week}</td><td>${data.attacks.month}</td></tr></tfoot>`;
            }

            // Attack chart (simple canvas bar chart — no library needed)
            drawAttackChart(data.attack_chart || []);

            // Recent logins
            renderLoginTable(data.recent_logins || [], 'success');

            // Top countries
            renderTopCountries(data.top_countries || [], data.geoip_ready);

            // Notifications
            renderNotifications(data);

        } catch (e) {
            showNotice('Unable to load dashboard data. ' + e.message, 'error');
            const tc = document.getElementById('top-countries');
            if (tc) tc.innerHTML = '<li class="dpxl-empty-state">Não foi possível carregar.</li>';
        }
    }

    function renderTopCountries(items, geoipReady) {
        const el = document.getElementById('top-countries');
        if (!el) return;

        if (!items.length) {
            el.innerHTML = `<li class="dpxl-empty-state">${geoipReady
                ? 'Nenhum país bloqueado nos últimos 7 dias.'
                : 'Geolocalização indisponível — configure o GeoLite2 (Ferramentas → Diagnostics).'}</li>`;
            return;
        }

        el.innerHTML = items.map(c =>
            `<li><span class="dpxl-country-code">${esc(c.country)}</span>`
            + `<span class="dpxl-country-hits">${parseInt(c.hits, 10) || 0}</span></li>`
        ).join('');
    }

    function drawAttackChart(data) {
        const canvas = document.getElementById('attacks-chart');
        if (!canvas || !canvas.getContext) return;
        const ctx = canvas.getContext('2d');
        const W = canvas.offsetWidth || 600;
        canvas.width  = W;
        canvas.height = 80;

        if (!data.length) {
            ctx.fillStyle = '#999';
            ctx.textAlign = 'center';
            ctx.fillText('No attack data for the last 24h', W / 2, 40);
            return;
        }

        const max = Math.max(...data.map(d => d.count), 1);
        const bw  = W / data.length;

        data.forEach((d, i) => {
            const h = Math.max(2, (d.count / max) * 70);
            ctx.fillStyle = '#d63638';
            ctx.fillRect(i * bw + 1, 80 - h, bw - 2, h);
        });
    }

    function renderLoginTable(items, filter) {
        const tbody = document.getElementById('recent-logins-tbody');
        if (!tbody) return;
        const filtered = items.filter(r => r.result === filter).slice(0, 10);
        if (!filtered.length) {
            tbody.innerHTML = '<tr><td colspan="3" class="dpxl-loading-cell">No records found.</td></tr>';
            return;
        }
        tbody.innerHTML = filtered.map(r =>
            `<tr><td>${esc(r.user_login)}</td><td><code>${esc(r.ip)}</code></td><td>${formatDate(r.timestamp)}</td></tr>`
        ).join('');
    }

    function renderNotifications(data) {
        const el = document.getElementById('dpxl-notifications');
        const badge = document.getElementById('notif-count');
        if (!el) return;

        const items = [];
        if (!data.extended_mode) items.push({ type: 'warning', msg: 'A Proteção Estendida não está ativa.' });
        if ((data.scan_issues?.critical || 0) > 0) items.push({ type: 'error', msg: `${data.scan_issues.critical} critical scan issue(s) found.` });

        if (badge) badge.textContent = items.length;

        el.innerHTML = items.length
            ? items.map(i => `<div class="dpxl-notice dpxl-notice--${i.type === 'error' ? 'error' : 'warning'}">${esc(i.msg)}</div>`).join('')
            : '<p style="color:#666;font-size:13px;">No notifications.</p>';
    }

    // Login tab filter
    document.querySelectorAll('.dpxl-tab[data-filter]').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.dpxl-tab[data-filter]').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            // Re-fetch and filter
            api.get('login-events', { result: btn.dataset.filter, limit: 10 }).then(d => {
                renderLoginTable(d.items || [], btn.dataset.filter);
            });
        });
    });

    // ── Firewall / Blocking ─────────────────────────────────────────────────

    if (page === 'dpxl-shield-firewall') {
        initFirewall();
    }

    async function initFirewall() {
        if (tab === '' || tab === 'firewall') {
            await loadFirewallStatus();
            await loadTopBlockedIps('24h');

            document.querySelectorAll('#top-ips-table .dpxl-tab[data-period]').forEach(btn => {
                btn.addEventListener('click', () => {
                    document.querySelectorAll('#top-ips-table .dpxl-tab[data-period]').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    loadTopBlockedIps(btn.dataset.period || '24h');
                });
            });

            document.getElementById('btn-download-htaccess')?.addEventListener('click', downloadHtaccessBackupAndEnable);
            document.getElementById('extended-enable-form')?.addEventListener('submit', enableExtendedProtection);
        }

        if (tab === 'blocking') {
            loadBlockedIps();
            loadCustomPatterns();

            // Block type toggle
            ['ip', 'country', 'pattern'].forEach(type => {
                const btn = document.getElementById(`btn-type-${type}`);
                if (!btn) return;
                btn.addEventListener('click', () => {
                    document.querySelectorAll('.dpxl-blocking-panel').forEach(p => p.classList.add('dpxl-hidden'));
                    document.querySelectorAll('.dpxl-btn[id^="btn-type-"]').forEach(b => b.classList.remove('dpxl-btn--active'));
                    document.getElementById(`panel-${type}`)?.classList.remove('dpxl-hidden');
                    btn.classList.add('dpxl-btn--active');

                    if (type === 'country') loadCountries();
                });
            });

            // Add custom pattern
            document.getElementById('btn-add-pattern')?.addEventListener('click', addCustomPattern);

            // Block IP button
            document.getElementById('btn-block-ip')?.addEventListener('click', () => {
                const ip = prompt('Enter IP address to block:');
                if (!ip) return;
                const reason = prompt('Reason (optional):') || 'Manually blocked';
                api.post('blocked-ips', { ip, reason, duration: 0 }).then(() => {
                    showNotice(`IP ${ip} bloqueado.`);
                    loadBlockedIps();
                }).catch(e => showNotice(e.message, 'error'));
            });
        }
    }


    function markHtaccessBackupDownloaded(message = 'Backup baixado. Aplicando a Proteção Estendida automaticamente…') {
        const card = document.getElementById('extended-protection');
        const btn = document.getElementById('btn-enable-extended');
        const status = document.getElementById('extended-backup-status');

        if (card) card.dataset.backupDownloaded = '1';
        if (btn && !btn.textContent.includes('Active')) btn.disabled = false;
        if (status) {
            status.textContent = message;
            status.classList.add('is-complete');
        }
    }

    function filenameFromContentDisposition(header) {
        if (!header) return 'htaccess-backup.txt';

        const utf8Match = header.match(/filename\*=UTF-8''([^;]+)/i);
        if (utf8Match && utf8Match[1]) return decodeURIComponent(utf8Match[1].replace(/["']/g, ''));

        const match = header.match(/filename=([^;]+)/i);
        if (match && match[1]) return match[1].trim().replace(/["']/g, '');

        return 'htaccess-backup.txt';
    }

    async function downloadHtaccessBackupAndEnable(event, options = {}) {
        if (event) event.preventDefault();

        const backupBtn = document.getElementById('btn-download-htaccess');
        const enableBtn = document.getElementById('btn-enable-extended');
        const originalBackupText = backupBtn ? backupBtn.textContent : '';
        const snippet = document.getElementById('extended-snippet');
        const manualFallback = document.getElementById('extended-manual-fallback');

        if (!dpxlShield.downloadHtaccessUrl) {
            setExtendedActionStatus('Backup URL not available. Recarregue a página e tente novamente.', 'error');
            showNotice('Backup URL not available. Recarregue a página e tente novamente.', 'error');
            return;
        }

        if (backupBtn) {
            backupBtn.classList.add('disabled');
            backupBtn.setAttribute('aria-disabled', 'true');
            backupBtn.textContent = 'Baixando backup…';
        }
        if (enableBtn) {
            enableBtn.disabled = true;
            enableBtn.textContent = 'Baixando backup…';
        }

        setExtendedActionStatus('Step 1 of 3: downloading your current .htaccess backup…', 'warning', true);

        try {
            const response = await fetch(dpxlShield.downloadHtaccessUrl, {
                method: 'GET',
                credentials: 'same-origin',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
            });

            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const blob = await response.blob();
            const filename = filenameFromContentDisposition(response.headers.get('content-disposition'));
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);

            markHtaccessBackupDownloaded('Backup baixado. Atualizando o .htaccess automaticamente…');
            setExtendedActionStatus('Step 2 of 3: backup downloaded. Updating .htaccess automatically…', 'warning', true);
            showNotice('Backup downloaded. DPXL Shield is updating .htaccess automatically.', 'success');

            await enableExtendedProtection(null, {
                keepButtonDisabled: true,
                skipBackupCheck: true,
                reloadAfterSuccess: options.reloadAfterSuccess !== false,
            });
        } catch (e) {
            const message = 'Automatic backup/update failed: ' + e.message + '. Use the fallback buttons or update the snippet manually.';
            setExtendedActionStatus(message, 'error');
            showNotice(message, 'error');
            if (snippet) snippet.classList.remove('dpxl-hidden');
            if (manualFallback) manualFallback.open = true;
            if (enableBtn && !enableBtn.textContent.includes('Active')) {
                enableBtn.disabled = false;
                enableBtn.textContent = 'Ativar Proteção Estendida';
            }
        } finally {
            if (backupBtn) {
                backupBtn.classList.remove('disabled');
                backupBtn.removeAttribute('aria-disabled');
                backupBtn.textContent = originalBackupText || 'Download Backup & Enable';
            }
        }
    }

    async function loadFirewallStatus() {
        try {
            const data = await api.get('firewall/status');

            setGaugeStatus('gauge-waf', data.waf_enabled ? 'ok' : 'error', data.waf_enabled ? '100%' : '—', data.extended_active ? 'Extended protection active' : 'Basic mode active');
            setGaugeStatus('gauge-rules', data.rules_count > 0 ? 'ok' : 'warning', data.rules_count > 0 ? String(data.rules_count) : '—', data.rules_count > 0 ? 'Regras ativas do WAF' : 'Nenhuma regra carregada');
            setGaugeStatus('gauge-blocklist', 'ok', String(data.blocked_count ?? 0), 'IPs bloqueados');
            setGaugeStatus('gauge-brute', data.brute_enabled ? 'ok' : 'warning', data.brute_enabled ? '100%' : '—', data.brute_enabled ? 'Proteção de login ativa' : 'Proteção de login desativada');

            const status = document.getElementById('extended-status');
            if (status) {
                status.innerHTML = data.extended_active
                    ? `${statusIcon('ok')} Extended Protection active (${esc(data.extended_method || 'auto_prepend_file')}). O WAF está sendo carregado antes do WordPress.`
                    : `${statusIcon('warning')} Proteção Estendida inativa. Siga as etapas de backup + ativação abaixo.`;
            }

            const backupStatus = document.getElementById('extended-backup-status');
            const backupDownloaded = Boolean(data.htaccess_backup_downloaded);
            const card = document.getElementById('extended-protection');
            if (card) card.dataset.backupDownloaded = backupDownloaded ? '1' : '0';
            if (backupStatus) {
                backupStatus.textContent = backupDownloaded
                    ? `Backup download registered${data.htaccess_backup_downloaded_at ? ' at ' + data.htaccess_backup_downloaded_at : ''}.`
                    : 'Required before making changes. Click either button to download the backup first.';
                backupStatus.classList.toggle('is-complete', backupDownloaded);
            }

            const writable = document.getElementById('extended-writable-status');
            if (writable) writable.textContent = data.htaccess_writable ? 'Yes' : 'No';

            const btn = document.getElementById('btn-enable-extended');
            if (btn) {
                if (data.extended_active) {
                    btn.disabled = true;
                    btn.textContent = 'Proteção Estendida ativa';
                } else {
                    btn.disabled = false;
                    btn.textContent = 'Ativar Proteção Estendida';
                }
            }

            const snippet = document.getElementById('extended-snippet');
            if (snippet && data.manual_snippet) {
                snippet.textContent = data.manual_snippet;
            }
        } catch (e) {
            const status = document.getElementById('extended-status');
            if (status) status.textContent = 'Unable to load firewall status: ' + e.message;
        }
    }

    async function loadTopBlockedIps(period = '24h') {
        const tbody = document.getElementById('top-ips-tbody') || document.querySelector('#top-ips-table tbody');
        if (!tbody) return;

        tbody.innerHTML = '<tr><td colspan="4" class="dpxl-loading-cell">Carregando…</td></tr>';

        try {
            const data = await api.get('firewall/top-ips', { period, limit: 10 });
            const items = data.items || [];

            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="4" class="dpxl-loading-cell">No blocked IPs in this period.</td></tr>';
                return;
            }

            tbody.innerHTML = items.map(row => `
                <tr>
                    <td><code>${esc(row.ip)}</code></td>
                    <td>${esc(row.country || '—')}</td>
                    <td>${esc(row.hits)}</td>
                    <td>
                        <button class="dpxl-btn dpxl-btn--sm" onclick="dpxlWhois('${esc(row.ip)}')">Whois</button>
                        <button class="dpxl-btn dpxl-btn--sm" onclick="dpxlQuickBlockIp('${esc(row.ip)}')">Block</button>
                    </td>
                </tr>
            `).join('');
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="4" class="dpxl-loading-cell">${esc(e.message)}</td></tr>`;
        }
    }

    async function enableExtendedProtection(event, options = {}) {
        if (event) event.preventDefault();

        const btn = document.getElementById('btn-enable-extended');
        const form = document.getElementById('extended-enable-form');
        const snippet = document.getElementById('extended-snippet');
        const manualFallback = document.getElementById('extended-manual-fallback');
        const card = document.getElementById('extended-protection');

        if (card && card.dataset.backupDownloaded !== '1' && !options.skipBackupCheck) {
            setExtendedActionStatus('O backup do .htaccess ainda não foi baixado. Iniciando agora o fluxo de backup + ativação…', 'warning', true);
            showNotice('Baixando primeiro o backup do .htaccess. A Proteção Estendida será ativada automaticamente em seguida.', 'warning');
            await downloadHtaccessBackupAndEnable(null, { reloadAfterSuccess: true });
            return;
        }

        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Atualizando configuração…';
        }

        setExtendedActionStatus('Etapa 2 de 3: gravando a configuração do DPXL Shield no .htaccess…', 'warning', true);

        try {
            const result = await api.post('extended/enable');

            if (result.success) {
                const message = result.message || 'A Proteção Estendida está ativa.';

                if (result.active) {
                    setExtendedActionStatus('Etapa 3 de 3: validação concluída. Recarregando a tela do Firewall…', 'success', true);
                    showNotice(message + ' Recarregando a página para mostrar o status final.', 'success');
                    if (manualFallback) manualFallback.open = false;

                    if (btn) {
                        btn.disabled = true;
                        btn.textContent = 'Proteção Estendida ativa';
                    }

                    await loadFirewallStatus();

                    if (options.reloadAfterSuccess !== false) {
                        reloadFirewallAfterDelay(1200);
                    } else {
                        hideExtendedActionStatus();
                    }
                    return;
                }

                setExtendedActionStatus(message, 'warning');
                showNotice(message, 'warning');

                if (btn) {
                    btn.disabled = false;
                    btn.textContent = 'Verificar novamente';
                }

                await loadFirewallStatus();
                return;
            }

            const message = result.message || 'A configuração automática falhou. Use o trecho manual exibido abaixo.';
            setExtendedActionStatus(message, result.code === 'backup_required' ? 'warning' : 'error');
            showNotice(message, result.code === 'backup_required' ? 'warning' : 'error');
            if (snippet) {
                snippet.textContent = result.snippet || 'Nenhum trecho retornado.';
                snippet.classList.remove('dpxl-hidden');
            }
            if (manualFallback) manualFallback.open = true;

            await loadFirewallStatus();
        } catch (e) {
            const message = 'Não foi possível ativar a Proteção Estendida via REST: ' + e.message + '.';
            setExtendedActionStatus(message + ' Usando agora o fallback seguro por formulário…', 'warning', true);
            showNotice(message + ' Usando agora o fallback seguro por formulário…', 'warning');

            if (form && event && options.allowPostFallback !== false) {
                window.setTimeout(() => form.submit(), 500);
                return;
            }

            setExtendedActionStatus(message + ' Recarregue a página e tente novamente.', 'error');
        } finally {
            if (btn && !btn.textContent.includes('Active') && !btn.textContent.includes('ativa') && !btn.textContent.includes('Verificar')) {
                btn.disabled = Boolean(options.keepButtonDisabled);
                btn.textContent = 'Ativar Proteção Estendida';
            }
        }
    }


    window.dpxlQuickBlockIp = (ip) => {
        if (!ip || !confirm(dpxlShield.strings.confirm)) return;
        api.post('blocked-ips', { ip, reason: 'Bloqueado manualmente pela visão geral do Firewall', duration: 0 })
            .then(() => { showNotice(`IP ${ip} bloqueado.`); loadFirewallStatus(); })
            .catch(e => showNotice(e.message, 'error'));
    };

    let blockedIpsPage = 0;

    async function loadBlockedIps() {
        const tbody = document.getElementById('blocked-ips-tbody');
        if (!tbody) return;
        try {
            const data = await api.get('blocked-ips', { limit: 25, offset: blockedIpsPage * 25 });
            tbody.innerHTML = (data.items || []).map(row => `
                <tr>
                    <td><input type="checkbox" value="${esc(row.ip)}"></td>
                    <td><code>${esc(row.ip)}</code></td>
                    <td>${esc(row.reason)}</td>
                    <td><span class="dpxl-badge">${esc(row.source)}</span></td>
                    <td>${row.is_permanent === '1' ? icon('infinity') + ' Permanent' : formatDate(row.expires_at)}</td>
                    <td>
                        <button class="dpxl-btn dpxl-btn--sm" onclick="dpxlUnblock('${esc(row.ip)}')">Unblock</button>
                        <button class="dpxl-btn dpxl-btn--sm" onclick="dpxlWhois('${esc(row.ip)}')">Whois</button>
                    </td>
                </tr>
            `).join('') || '<tr><td colspan="6" class="dpxl-loading-cell">No blocks active.</td></tr>';
        } catch (e) {
            tbody.innerHTML = `<tr><td colspan="6" class="dpxl-loading-cell">${esc(e.message)}</td></tr>`;
        }
    }

    window.dpxlUnblock = (ip) => {
        if (!confirm(dpxlShield.strings.confirm)) return;
        api.delete('blocked-ips/' + encodeURIComponent(ip)).then(() => {
            showNotice(`IP ${ip} unblocked.`);
            loadBlockedIps();
        }).catch(e => showNotice(e.message, 'error'));
    };

    window.dpxlWhois = (ip) => {
        const url = dpxlShield.adminUrl + '?page=dpxl-shield-tools&tab=whois&ip=' + encodeURIComponent(ip);
        window.open(url, '_blank');
    };

    async function loadCountries() {
        const container = document.getElementById('country-list-container');
        if (!container) return;
        try {
            const data = await api.get('country-blocks');
            container.innerHTML = (data.items || []).map(c =>
                `<label class="dpxl-checkbox-label"><input type="checkbox" value="${esc(c.country_code)}" checked> ${esc(c.country_name)}</label>`
            ).join('') || '<p style="color:#666;font-size:13px;">No countries bloqueado.</p>';
        } catch (e) { container.textContent = e.message; }
    }

    async function loadCustomPatterns() {
        const tbody = document.getElementById('patterns-tbody');
        if (!tbody) return;
        try {
            const data = await api.get('custom-patterns');
            tbody.innerHTML = (data.items || []).map(row => `
                <tr>
                    <td>${esc(row.field)}</td>
                    <td><code>${esc(row.pattern)}</code></td>
                    <td>${esc(row.match_type)}</td>
                    <td><span class="dpxl-badge ${row.action === 'block' ? 'dpxl-badge--red' : ''}">${esc(row.action)}</span></td>
                    <td>${esc(row.reason)}</td>
                    <td><button class="dpxl-btn dpxl-btn--sm dpxl-btn--danger" onclick="dpxlDeletePattern(${esc(row.id)})">Delete</button></td>
                </tr>
            `).join('') || '<tr><td colspan="6" class="dpxl-loading-cell">No custom patterns.</td></tr>';
        } catch (e) { tbody.innerHTML = `<tr><td colspan="6">${esc(e.message)}</td></tr>`; }
    }

    window.dpxlDeletePattern = (id) => {
        if (!confirm(dpxlShield.strings.confirm)) return;
        api.delete('custom-patterns/' + id).then(() => { showNotice('Pattern deleted.'); loadCustomPatterns(); }).catch(e => showNotice(e.message, 'error'));
    };

    function addCustomPattern() {
        const body = {
            field:      document.getElementById('pattern-field')?.value,
            pattern:    document.getElementById('pattern-value')?.value,
            match_type: document.getElementById('pattern-match')?.value,
            action:     document.getElementById('pattern-action')?.value,
            reason:     document.getElementById('pattern-reason')?.value,
        };
        if (!body.pattern) { showNotice('Pattern is required.', 'error'); return; }
        api.post('custom-patterns', body).then(() => { showNotice('Pattern added.'); loadCustomPatterns(); }).catch(e => showNotice(e.message, 'error'));
    }

    // ── Scanner ─────────────────────────────────────────────────────────────

    if (page === 'dpxl-shield-scan') {
        initScanner();
    }

    let scanPollTimer = null;
    let scannerWasRunning = false;
    let latestScanState = { running: false };

    async function initScanner() {
        const startBtn = document.getElementById('btn-start-scan');
        const cancelBtn = document.getElementById('btn-cancel-scan');
        const repairAllBtn = document.getElementById('btn-repair-all');

        startBtn?.addEventListener('click', startScan);
        cancelBtn?.addEventListener('click', cancelScan);
        repairAllBtn?.addEventListener('click', repairAll);

        document.getElementById('btn-toggle-recs')?.addEventListener('click', (e) => {
            const btn  = e.currentTarget;
            const list = document.getElementById('scan-recs-list');
            const open = list?.classList.toggle('dpxl-hidden') === false;
            btn.setAttribute('aria-expanded', String(open));
            btn.textContent = open ? 'Ocultar' : 'Mostrar';
        });

        const status = await refreshScanStatus();
        await loadScanResults(status?.running === true);

        if (status?.running) {
            startScanPolling();
        }
    }

    function startScanPolling() {
        clearInterval(scanPollTimer);
        scanPollTimer = setInterval(async () => {
            const status = await refreshScanStatus();
            await loadScanResults(status?.running === true);
        }, 3000);
    }

    async function refreshScanStatus() {
        try {
            const s = await api.get('scan/status');
            latestScanState = s;

            const startBtn  = document.getElementById('btn-start-scan');
            const cancelBtn = document.getElementById('btn-cancel-scan');
            const statusTxt = document.getElementById('scan-status-text');
            const lastRun   = document.getElementById('scan-last-run');

            setScannerGauges(s);
            updateScanStats(s);
            updateStageBar(s.current_stage, s.stage_status || {});

            if (s.running) {
                scannerWasRunning = true;
                startBtn?.classList.add('dpxl-hidden');
                cancelBtn?.classList.remove('dpxl-hidden');

                if (statusTxt) statusTxt.textContent = buildScanStatusText(s);
            } else {
                startBtn?.classList.remove('dpxl-hidden');
                cancelBtn?.classList.add('dpxl-hidden');
                clearInterval(scanPollTimer);

                if (statusTxt) {
                    if (s.current_stage === 'failed' && s.last_error) {
                        statusTxt.textContent = 'A varredura falhou: ' + s.last_error;
                    } else if (s.current_stage === 'cancelled') {
                        statusTxt.textContent = 'Varredura cancelada.';
                    } else {
                        statusTxt.textContent = s.last_scan_at ? 'Last scan: ' + formatDate(s.last_scan_at) : 'Idle';
                    }
                }

                if (scannerWasRunning) {
                    scannerWasRunning = false;
                    await loadScanResults(false);
                }
            }

            if (lastRun && s.last_scan_at) lastRun.textContent = 'Last scan: ' + formatDate(s.last_scan_at);

            if (!s.running && s.last_error && (s.current_stage === 'failed' || s.current_stage === 'cancelled')) {
                const alreadyShown = document.querySelector('.dpxl-scan-error-shown');
                if (!alreadyShown) {
                    showNotice(s.last_error, s.current_stage === 'cancelled' ? 'warning' : 'error');
                    document.querySelector('.dpxl-notice')?.classList.add('dpxl-scan-error-shown');
                }
            }

            return s;
        } catch (e) {
            const statusTxt = document.getElementById('scan-status-text');
            if (statusTxt) statusTxt.textContent = 'Could not load scan status: ' + e.message;
            showScanRunningPlaceholder('Não foi possível carregar o status da varredura. Verifique a API REST / nonce.');
            return null;
        }
    }

    function setScannerGauges(s) {
        const hasError = !!s.last_error && ['failed', 'cancelled'].includes(s.current_stage);
        setGaugeStatus('gauge-scan-type', hasError ? 'warning' : 'ok', s.running ? (s.progress ? s.progress + '%' : '…') : '100%', s.running ? 'Running' : 'Standard');
        setGaugeStatus('gauge-signatures', 'ok', '100%', 'Loaded');
        setGaugeStatus('gauge-reputation', hasError ? 'warning' : 'ok', hasError ? '!' : '100%', hasError ? 'Needs attention' : 'Blacklist checks');
    }

    function updateScanStats(s) {
        const files = document.getElementById('stat-files');
        const issues = document.getElementById('stat-issues');
        const critical = document.getElementById('stat-critical');
        const count = document.getElementById('results-count');
        const bar = document.getElementById('scan-progressbar');
        const fill = document.getElementById('scan-progressbar-fill');

        const issuesFound = Number(s.running ? (s.issues_found || 0) : (s.issue_count || s.issues_found || 0));

        if (files) files.textContent = Number(s.files_scanned || 0).toLocaleString();
        if (issues) issues.textContent = issuesFound.toLocaleString();
        setThreatBadge(count, issuesFound);
        if (critical && s.running) setCriticalStat(0);

        // Determinate progress bar during the malware scan; hidden otherwise.
        if (bar && fill) {
            if (s.running && Number(s.files_total || 0) > 0) {
                bar.hidden = false;
                fill.style.width = Math.min(100, Number(s.progress || 0)) + '%';
            } else {
                bar.hidden = true;
            }
        }
    }

    function setThreatBadge(el, n) {
        if (!el) return;
        el.textContent = Number(n).toLocaleString();
        el.classList.toggle('dpxl-hidden', Number(n) < 1);
    }

    function setCriticalStat(n) {
        const critical = document.getElementById('stat-critical');
        if (!critical) return;
        critical.textContent = Number(n).toLocaleString();
        critical.closest('.dpxl-stat')?.classList.toggle('is-zero', Number(n) < 1);
    }

    function buildScanStatusText(s) {
        const stage = prettyStage(s.current_stage);

        if (s.current_stage === 'queued') {
            return 'Varredura enfileirada. Aguardando o WP-Cron iniciar…';
        }

        if (s.current_stage === 'malware_scan') {
            const scanned = Number(s.files_scanned || 0).toLocaleString();
            const total = Number(s.files_total || 0);
            const totalTxt = total > 0 ? '/' + total.toLocaleString() : '';
            const file = s.current_file ? ' — ' + s.current_file : '';
            return `Verificando arquivos de malware: ${scanned}${totalTxt}${file}`;
        }

        return 'Verificando: ' + stage + '…';
    }

    function prettyStage(stage) {
        const labels = {
            queued: 'Queued',
            starting: 'Starting',
            spam_check: 'Spam Check',
            block_check: 'Block Check',
            server_state: 'Server State',
            file_changes: 'Files Changed',
            malware_scan: 'Varredura de Malware',
            content_safety: 'Content Safety',
            public_files: 'Public Files',
            password_audit: 'Password Audit',
            vulnerability: 'Verificação de vulnerabilidades',
            idle: 'Idle',
            cancelled: 'Cancelled',
            failed: 'Failed',
        };
        return labels[stage] || String(stage || 'Idle').replace(/_/g, ' ');
    }

    function updateStageBar(activeStage, statusMap = {}) {
        const stages = ['spam_check', 'block_check', 'server_state', 'file_changes', 'malware_scan', 'content_safety', 'public_files', 'password_audit', 'vulnerability'];

        stages.forEach(stage => {
            const el = document.getElementById(`stage-${stage}`);
            if (!el) return;

            const status = statusMap[stage] || 'pending';
            let state = 'pending';

            if (status === 'done') {
                state = 'done';
            } else if (status === 'error') {
                state = 'error';
            } else if (status !== 'cancelled' && (stage === activeStage || status === 'running')) {
                state = 'active';
            }

            el.setAttribute('data-state', state);
        });
    }

    async function startScan() {
        try {
            const list = document.getElementById('scan-results-list');
            if (list) showScanRunningPlaceholder('Iniciando varredura…');
            updateScanStats({ running: true, files_scanned: 0, issues_found: 0 });

            await api.post('scan/run');
            showNotice('Varredura enfileirada. Iniciando agora.');
            scannerWasRunning = true;
            await refreshScanStatus();
            startScanPolling();
        } catch (e) {
            showNotice(e.message, 'error');
        }
    }

    async function cancelScan() {
        try {
            await api.post('scan/cancel');
            showNotice('Cancel requested. The scan will stop at the next safe checkpoint.', 'warning');
            await refreshScanStatus();
            startScanPolling();
        } catch (e) {
            showNotice(e.message, 'error');
        }
    }

    async function loadScanResults(isRunning = latestScanState.running === true) {
        const list  = document.getElementById('scan-results-list');
        const count = document.getElementById('results-count');
        const stat  = document.getElementById('stat-issues');
        const crit  = document.getElementById('stat-critical');
        if (!list) return;

        try {
            const data = await api.get('scan/results', { status: 'new', limit: 50 });
            const items = data.items || [];

            if (!isRunning) {
                setThreatBadge(count, data.total ?? items.length);
                if (stat) stat.textContent = (data.total ?? items.length).toLocaleString();
                setCriticalStat(data.critical_total ?? items.filter(i => i.severity === 'critical').length);
            }

            const repairAllBtn = document.getElementById('btn-repair-all');
            if (repairAllBtn) {
                if (isRunning) {
                    repairAllBtn.classList.add('dpxl-hidden');
                } else {
                    const repairable = Number(data.repairable_count || 0);
                    repairAllBtn.classList.toggle('dpxl-hidden', repairable < 1);
                    repairAllBtn.textContent = repairable > 0 ? `Reparar todos os reparáveis (${repairable})` : 'Reparar todos os reparáveis';
                }
            }

            renderRecommendations(data.recommendations || [], Number(data.recommendation_total || 0));

            if (!items.length) {
                if (isRunning) {
                    showScanRunningPlaceholder('A varredura está em andamento. As ameaças aparecerão aqui se o DPXL Shield encontrar alguma.');
                } else {
                    list.innerHTML = '<div class="dpxl-empty-state dpxl-empty-state--clean">Nenhuma ameaça encontrada. Seu site está limpo.</div>';
                }
                return;
            }

            list.innerHTML = items.map(item => renderResultCard(item, false)).join('');
        } catch (e) {
            list.innerHTML = `<div class="dpxl-empty-state dpxl-empty-state--error">Não foi possível carregar os resultados: ${esc(e.message)}</div>`;
        }
    }

    // Human-readable title per issue type — cards read as real problems,
    // never as raw slugs like "modified_core".
    function scanIssueTitle(item) {
        const path = String(item.file_path || '');
        const titles = {
            modified_core:     'Arquivo do core modificado',
            modified_plugin:   'Arquivo de plugin modificado',
            malware_signature: 'Assinatura de malware detectada',
            php_in_uploads:    'PHP executável em /uploads',
            heuristic:         'Código suspeito',
            vulnerable_version:'Componente vulnerável ou desatualizado',
        };
        if (titles[item.issue_type]) return titles[item.issue_type];

        // issue_type = 'unknown' covers exposures + hardening + reputation.
        if (path === 'site/reputation')        return 'Site em lista de reputação/blocklist';
        if (path.startsWith('server/'))         return 'Recomendação de hardening';
        if (/\.env|\.git|phpinfo|wp-config/.test(path)) return 'Arquivo sensível exposto';
        return 'Item de segurança';
    }

    function renderResultCard(item, isRec) {
        const sev = String(item.severity || 'info').toLowerCase();
        const repairable = item.issue_type === 'modified_core' || item.issue_type === 'modified_plugin';
        const cls = isRec ? 'dpxl-result-item--recommendation' : `dpxl-result-item--${esc(sev)}`;

        return `
            <div class="dpxl-result-item ${cls}">
                <span class="dpxl-result-item__icon">${severityIcon(sev)}</span>
                <span class="dpxl-sev-chip dpxl-sev-chip--${esc(sev)}">${esc(sevLabel(sev))}</span>
                <div class="dpxl-result-item__title">${esc(scanIssueTitle(item))}</div>
                <p class="dpxl-result-item__desc">${esc(item.details || item.issue_type)}
                    ${item.file_path && !/^(site|server)\//.test(item.file_path) ? `<br><span class="dpxl-result-item__path">${esc(item.file_path)}</span>` : ''}
                </p>
                <div class="dpxl-result-actions">
                    ${repairable ? `<button class="dpxl-btn dpxl-btn--sm dpxl-btn--primary" onclick="dpxlRepairFile('${esc(item.file_path)}')">Reparar arquivo</button>` : ''}
                    <button class="dpxl-btn dpxl-btn--sm" onclick="dpxlDismissResult(${esc(item.id)})">Ignorar</button>
                </div>
            </div>`;
    }

    function renderRecommendations(recs, total) {
        const card = document.getElementById('scan-recs-card');
        const list = document.getElementById('scan-recs-list');
        const badge = document.getElementById('recs-count');
        if (!card || !list) return;

        if (!total) { card.classList.add('dpxl-hidden'); return; }

        card.classList.remove('dpxl-hidden');
        if (badge) badge.textContent = total.toLocaleString();
        list.innerHTML = recs.map(item => renderResultCard(item, true)).join('');
    }

    function sevLabel(sev) {
        return { critical: 'Crítico', high: 'Alto', medium: 'Médio', low: 'Baixo', info: 'Info' }[sev] || sev;
    }

    function showScanRunningPlaceholder(message) {
        const list = document.getElementById('scan-results-list');
        if (!list) return;
        list.innerHTML = `<div class="dpxl-empty-state dpxl-empty-state--running">⟳ ${esc(message)}</div>`;
    }

    window.dpxlRepairFile = (path) => {
        if (!confirm('Reparar este arquivo usando o repositório do WordPress.org?')) return;
        api.post('scan/repair', { file_path: path }).then(r => {
            showNotice(r.success ? 'Arquivo reparado.' : (r.message || 'A reparação falhou.'), r.success ? 'success' : 'error');
            loadScanResults(false);
        }).catch(e => showNotice(e.message, 'error'));
    };

    window.dpxlDismissResult = (id) => {
        api.post(`scan/dismiss/${id}`).then(() => { showNotice('Marcado como ignorado.'); loadScanResults(false); }).catch(e => showNotice(e.message, 'error'));
    };

    async function repairAll() {
        if (!confirm('Reparar todos os arquivos reparáveis? Backups serão criados antes da substituição.')) return;
        try {
            const r = await api.post('scan/repair-all');
            showNotice(`${r.repaired || 0} file(s) repaired, ${r.failed || 0} failed.`);
            loadScanResults(false);
        } catch (e) { showNotice(e.message, 'error'); }
    }

    // ── Tools: Live Traffic ─────────────────────────────────────────────────

    if (page === 'dpxl-shield-tools' && (!tab || tab === 'live-traffic')) {
        initTraffic();
    }

    let trafficPollTimer = null;
    let trafficPage = 0;

    async function initTraffic() {
        await loadTraffic();

        document.getElementById('btn-show-filters')?.addEventListener('click', () => {
            document.getElementById('advanced-filters')?.classList.toggle('dpxl-hidden');
        });

        document.getElementById('btn-apply-filters')?.addEventListener('click', () => { trafficPage = 0; loadTraffic(); });
        document.getElementById('btn-reset-filters')?.addEventListener('click', () => {
            ['filter-ip', 'filter-url'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
            ['filter-response', 'traffic-type-filter'].forEach(id => { const el = document.getElementById(id); if (el) el.selectedIndex = 0; });
            trafficPage = 0;
            loadTraffic();
        });

        const liveChk = document.getElementById('traffic-live-update');
        if (liveChk?.checked) trafficPollTimer = setInterval(loadTraffic, 5000);
        liveChk?.addEventListener('change', () => {
            clearInterval(trafficPollTimer);
            if (liveChk.checked) trafficPollTimer = setInterval(loadTraffic, 5000);
        });

        document.getElementById('btn-close-modal')?.addEventListener('click', closeModal);
        document.getElementById('modal-backdrop')?.addEventListener('click', closeModal);
    }

    async function loadTraffic() {
        const tbody = document.getElementById('traffic-tbody');
        if (!tbody) return;
        const params = {
            limit:  25,
            offset: trafficPage * 25,
            type:   document.getElementById('traffic-type-filter')?.value || '',
            ip:     document.getElementById('filter-ip')?.value || '',
            url:    document.getElementById('filter-url')?.value || '',
        };
        try {
            const data = await api.get('traffic', params);
            const items = data.items || [];
            if (!items.length) {
                tbody.innerHTML = '<tr><td colspan="7" class="dpxl-loading-cell">No traffic logged yet.</td></tr>';
                return;
            }
            tbody.innerHTML = items.map(row => {
                const type = trafficType(row);
                const status = row.status_code;
                const statusClass = status >= 400 ? 'color:var(--dpxl-error)' : 'color:var(--dpxl-ok)';
                return `<tr data-row='${JSON.stringify(row).replace(/'/g, "&#39;")}'>
                    <td>${dots(type)}</td>
                    <td>${esc(type)}</td>
                    <td>—</td>
                    <td><code style="font-size:11px;">${esc(row.uri?.substring(0, 40))}</code></td>
                    <td><code>${esc(row.ip)}</code></td>
                    <td style="${statusClass}">${esc(status)}</td>
                    <td><button class="dpxl-btn dpxl-btn--sm" onclick="dpxlShowDetail(this)" aria-label="Detalhes">${icon('eye')}</button></td>
                </tr>`;
            }).join('');
        } catch (e) { tbody.innerHTML = `<tr><td colspan="7" class="dpxl-loading-cell">${esc(e.message)}</td></tr>`; }
    }

    window.dpxlShowDetail = (btn) => {
        const row = JSON.parse(btn.closest('tr')?.dataset.row || '{}');
        const modal = document.getElementById('traffic-detail-modal');
        const detailTable = document.getElementById('request-detail-table');
        if (!modal || !detailTable) return;

        detailTable.innerHTML = [
            ['IP',         row.ip],
            ['Time',       formatDate(row.timestamp)],
            ['Method',     row.method],
            ['URL',        row.uri],
            ['Response',   row.status_code],
            ['User-Agent', row.user_agent],
            ['WAF Result', row.waf_action],
        ].map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>`).join('');

        const blockBtn = document.getElementById('modal-btn-block');
        if (blockBtn) blockBtn.onclick = () => {
            api.post('blocked-ips', { ip: row.ip, reason: 'Bloqueado pelo Tráfego ao Vivo', duration: 0 })
                .then(() => { showNotice(`IP ${row.ip} bloqueado.`); closeModal(); })
                .catch(e => showNotice(e.message, 'error'));
        };

        modal.classList.remove('dpxl-hidden');
    };

    function closeModal() {
        document.getElementById('traffic-detail-modal')?.classList.add('dpxl-hidden');
    }

    // ── Tools: Audit Log ────────────────────────────────────────────────────

    if (page === 'dpxl-shield-tools' && tab === 'audit-log') {
        initAuditLog();
    }

    async function initAuditLog() {
        await loadAuditLog();

        document.getElementById('btn-filter-audit')?.addEventListener('click', loadAuditLog);
        document.getElementById('btn-verify-chain')?.addEventListener('click', verifyChain);
        document.getElementById('btn-save-audit')?.addEventListener('click', saveAuditMode);

        // Mode selector
        document.querySelectorAll('.dpxl-mode-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                document.querySelectorAll('.dpxl-mode-btn').forEach(b => b.classList.remove('dpxl-btn--active'));
                btn.classList.add('dpxl-btn--active');
                const input = document.getElementById('audit-mode-value');
                if (input) input.value = btn.dataset.mode;
            });
        });
    }

    async function loadAuditLog() {
        const tbody = document.getElementById('audit-log-tbody');
        if (!tbody) return;
        try {
            const data = await api.get('audit-log', {
                severity:   document.getElementById('audit-severity-filter')?.value || '',
                event_type: document.getElementById('audit-type-filter')?.value || '',
                limit: 50,
            });
            const items = data.items || [];
            tbody.innerHTML = items.map(row => {
                const cat = row.event_type?.split('.')[0] || 'unknown';
                const catMap = { auth: 'authentication', user: 'user_permissions', plugin: 'plugin_themes', fw: 'firewall', settings: 'site_settings', content: 'content' };
                return `<tr>
                    <td>${auditDot(catMap[cat] || cat)}</td>
                    <td>${esc(formatDate(row.timestamp))}</td>
                    <td>${esc(row.description)}</td>
                    <td>${row.actor_user ? 'User #' + esc(row.actor_user) : '—'}</td>
                    <td><code>${esc(row.actor_ip)}</code></td>
                </tr>`;
            }).join('') || '<tr><td colspan="5" class="dpxl-loading-cell">No audit log entries.</td></tr>';
        } catch (e) { tbody.innerHTML = `<tr><td colspan="5">${esc(e.message)}</td></tr>`; }
    }

    async function verifyChain() {
        const status = document.getElementById('chain-status');
        if (status) status.textContent = 'Verifying…';
        try {
            const r = await api.post('audit-log/verify');
            if (status) status.innerHTML = r.valid
                ? `${statusIcon('ok')} Chain valid (${esc(r.total)} entries)`
                : `${statusIcon('error')} Chain broken at entry ID ${esc(r.broken_at)}`;
        } catch (e) { if (status) status.innerHTML = `${statusIcon('warning')} Verification error: ${esc(e.message)}`; }
    }

    async function saveAuditMode() {
        const mode = document.getElementById('audit-mode-value')?.value;
        if (!mode) return;
        try {
            await api.post('settings', { audit_mode: mode });
            showNotice(dpxlShield.strings.saved);
        } catch (e) { showNotice(e.message, 'error'); }
    }

    // ── Tools: Whois ────────────────────────────────────────────────────────

    if (page === 'dpxl-shield-tools' && tab === 'whois') {
        initWhois();
    }

    function initWhois() {
        const input = document.getElementById('whois-ip-input');
        document.getElementById('btn-whois-lookup')?.addEventListener('click', performWhois);
        input?.addEventListener('keydown', e => { if (e.key === 'Enter') performWhois(); });
        if (input?.value) performWhois();
    }

    async function performWhois() {
        const query = document.getElementById('whois-ip-input')?.value?.trim();
        if (!query) return;

        document.getElementById('whois-result')?.classList.add('dpxl-hidden');
        document.getElementById('whois-error')?.classList.add('dpxl-hidden');
        document.getElementById('whois-loading')?.classList.remove('dpxl-hidden');

        try {
            const data = await api.get('whois/' + encodeURIComponent(query));
            document.getElementById('whois-loading')?.classList.add('dpxl-hidden');

            // If the backend returned an error field, show it instead of a blank table.
            if (data.error || data.source === 'lookup_failed' || data.source === 'invalid_ip') {
                const errEl = document.getElementById('whois-error');
                if (errEl) {
                    errEl.textContent = data.error || 'Consulta falhou. Verifique o IP/domínio e tente novamente.';
                    errEl.classList.remove('dpxl-hidden');
                }
                return;
            }

            // Show resolved IP (may differ from query when a hostname was entered).
            const displayIp = data.ip || query;
            const resultIpEl = document.getElementById('whois-result-ip');
            if (resultIpEl) {
                resultIpEl.textContent = displayIp;
                if (data.input && data.input !== displayIp) {
                    resultIpEl.textContent += ` (${data.input})`;
                }
            }

            const table = document.getElementById('whois-detail-table');
            if (table) {
                table.innerHTML = [
                    ['Organization', data.org],
                    ['Country',      data.country],
                    ['ASN',          data.asn],
                    ['IP Range',     data.range],
                    ['Abuse Contact',data.abuse],
                    ['Source',       data.source],
                ].map(([k, v]) => v ? `<tr><td>${esc(k)}</td><td>${esc(v)}</td></tr>` : '').join('');
            }

            const rawEl = document.getElementById('whois-raw-output');
            if (rawEl) rawEl.textContent = data.raw || 'Sem dados brutos (resultado obtido via API).';

            document.getElementById('whois-btn-block')?.addEventListener('click', () => {
                api.post('blocked-ips', { ip: displayIp, reason: 'Bloqueado pela consulta Whois', duration: 0 })
                    .then(() => showNotice(`${displayIp} bloqueado.`))
                    .catch(e => showNotice(e.message, 'error'));
            }, { once: true });

            document.getElementById('whois-result')?.classList.remove('dpxl-hidden');
        } catch (e) {
            document.getElementById('whois-loading')?.classList.add('dpxl-hidden');
            const errEl = document.getElementById('whois-error');
            if (errEl) { errEl.textContent = 'Consulta falhou: ' + e.message; errEl.classList.remove('dpxl-hidden'); }
        }
    }

    // ── Tools: Import/Export ────────────────────────────────────────────────

    if (page === 'dpxl-shield-tools' && tab === 'import-export') {
        initImportExport();
    }

    function initImportExport() {
        document.getElementById('btn-export')?.addEventListener('click', async () => {
            const url = dpxlShield.restUrl + 'export';
            const a = Object.assign(document.createElement('a'), { href: url, download: '' });
            document.body.appendChild(a);
            a.click();
            a.remove();
        });

        const fileInput = document.getElementById('import-file-input');
        fileInput?.addEventListener('change', () => {
            const name = fileInput.files[0]?.name;
            document.getElementById('import-file-name').textContent = name || 'Nenhum arquivo selecionado';
            document.getElementById('btn-import')?.classList.toggle('dpxl-hidden', !name);
        });

        document.getElementById('btn-import')?.addEventListener('click', async () => {
            const file = fileInput?.files[0];
            if (!file) return;
            const json = await file.text();
            try {
                const r = await api.post('import', JSON.parse(json));
                const resultEl = document.getElementById('import-result');
                if (resultEl) {
                    resultEl.className = `dpxl-notice dpxl-notice--${r.success ? 'success' : 'error'}`;
                    resultEl.textContent = r.message;
                    resultEl.classList.remove('dpxl-hidden');
                }
            } catch (e) { showNotice(e.message, 'error'); }
        });
    }

    // ── Tools: Integrations (outbound webhooks) ─────────────────────────────

    if (page === 'dpxl-shield-tools' && tab === 'integrations') {
        initIntegrations();
    }

    function initIntegrations() {
        const container = document.getElementById('webhooks-container');
        const formCard  = document.getElementById('webhook-form-card');

        if (!container) return;

        const field = (id) => document.getElementById(id);

        const STATUS_LABELS = {
            ok:        ['green',  'Delivered'],
            http_fail: ['red',    'Rejected'],
            net_fail:  ['orange', 'Unreachable'],
            skipped:   ['gray',   'Skipped'],
        };

        function lastDelivery(last) {
            if (!last) return '<span class="dpxl-muted">Never sent</span>';

            const [colour, label] = STATUS_LABELS[last.status] || ['gray', last.status];
            const when = last.time ? new Date(last.time * 1000).toLocaleString() : '';
            const code = last.code ? ` (HTTP ${last.code})` : '';
            const why  = last.message ? `<br><span class="dpxl-muted">${esc(last.message)}</span>` : '';

            return `<span class="dpxl-dot dpxl-dot--${colour}"></span> ${esc(label)}${esc(code)}
                    <br><span class="dpxl-muted">${esc(when)}</span>${why}`;
        }

        async function load() {
            try {
                const data  = await api.get('webhooks');
                const items = data.items || [];

                if (!items.length) {
                    container.innerHTML = '<p class="dpxl-empty-state">No endpoints configured yet. Security events are not being pushed anywhere.</p>';
                    return;
                }

                container.className = '';
                container.innerHTML = `
                    <table class="dpxl-table">
                        <thead><tr>
                            <th>Name</th><th>Destination</th><th>Sends</th><th>Last delivery</th><th></th>
                        </tr></thead>
                        <tbody>${items.map(row => `
                            <tr>
                                <td>
                                    ${row.enabled ? '' : '<span class="dpxl-muted">(disabled)</span> '}
                                    <strong>${esc(row.label)}</strong>
                                    <br><code style="font-size:11px;">${esc(row.url.substring(0, 48))}${row.url.length > 48 ? '…' : ''}</code>
                                </td>
                                <td>${esc(row.format)}${row.has_secret ? ' <span class="dpxl-muted">· signed</span>' : ''}</td>
                                <td>${esc(row.min_level)}+</td>
                                <td>${lastDelivery(row.last)}</td>
                                <td style="white-space:nowrap;">
                                    <button class="dpxl-btn dpxl-btn--sm" data-test="${esc(row.id)}">Test</button>
                                    <button class="dpxl-btn dpxl-btn--sm" data-edit="${esc(row.id)}">Edit</button>
                                    <button class="dpxl-btn dpxl-btn--sm" data-remove="${esc(row.id)}">Remove</button>
                                </td>
                            </tr>`).join('')}
                        </tbody>
                    </table>`;

                container.querySelectorAll('[data-test]').forEach(b =>
                    b.addEventListener('click', () => sendTest(b.dataset.test, b)));
                container.querySelectorAll('[data-edit]').forEach(b =>
                    b.addEventListener('click', () => openForm(items.find(i => i.id === b.dataset.edit))));
                container.querySelectorAll('[data-remove]').forEach(b =>
                    b.addEventListener('click', () => remove(b.dataset.remove)));
            } catch (e) {
                container.innerHTML = `<p class="dpxl-empty-state">${esc(e.message)}</p>`;
            }
        }

        function openForm(row) {
            formCard?.classList.remove('dpxl-hidden');

            field('webhook-form-title').textContent = row ? 'Edit endpoint' : 'Add endpoint';
            field('webhook-id').value        = row?.id || '';
            field('webhook-label').value     = row?.label || '';
            field('webhook-url').value       = row?.url || '';
            field('webhook-format').value    = row?.format || 'slack';
            field('webhook-min-level').value = row?.min_level || 'medium';
            field('webhook-enabled').checked = row ? !!row.enabled : true;
            field('webhook-secret').value    = '';

            syncSecretField();
            field('webhook-label').focus();
        }

        function closeForm() {
            formCard?.classList.add('dpxl-hidden');
        }

        // PagerDuty's "secret" is really its routing key and is mandatory, so the
        // field has to say so rather than sitting there labelled "optional".
        function syncSecretField() {
            const isPagerDuty = field('webhook-format').value === 'pagerduty';
            const isGeneric   = field('webhook-format').value === 'generic';

            field('webhook-secret-label').textContent = isPagerDuty
                ? 'Integration routing key (required)'
                : 'Signing secret (optional)';

            field('webhook-secret-hint').textContent = isPagerDuty
                ? 'From the PagerDuty service integration. Leave blank when editing to keep the current key.'
                : (isGeneric
                    ? 'Signs each payload so your receiver can verify it really came from this site. Leave blank when editing to keep the current value.'
                    : 'Slack and Discord authenticate by URL, so a secret is not used for this destination.');

            field('webhook-secret-field').style.opacity = (isPagerDuty || isGeneric) ? '1' : '0.5';
        }

        async function save() {
            try {
                await api.post('webhooks', {
                    id:        field('webhook-id').value,
                    label:     field('webhook-label').value,
                    url:       field('webhook-url').value,
                    format:    field('webhook-format').value,
                    min_level: field('webhook-min-level').value,
                    secret:    field('webhook-secret').value,
                    enabled:   field('webhook-enabled').checked,
                });

                closeForm();
                showNotice('Endpoint saved.');
                load();
            } catch (e) { showNotice(e.message, 'error'); }
        }

        async function remove(id) {
            if (!confirm('Remove this endpoint? Events will stop being sent to it.')) return;

            try {
                await api.delete(`webhooks/${encodeURIComponent(id)}`);
                showNotice('Endpoint removed.');
                load();
            } catch (e) { showNotice(e.message, 'error'); }
        }

        async function sendTest(id, button) {
            const original = button.textContent;
            button.disabled = true;
            button.textContent = 'Sending…';

            try {
                const res = await api.post(`webhooks/${encodeURIComponent(id)}/test`);

                if (res.success) {
                    showNotice('Test delivered.');
                } else {
                    // Say what the endpoint actually answered — "failed" alone
                    // gives the admin nothing to act on.
                    showNotice(`Test failed: ${res.status}${res.code ? ' HTTP ' + res.code : ''}${res.message ? ' — ' + res.message : ''}`, 'error');
                }

                load();
            } catch (e) {
                showNotice(e.message, 'error');
            } finally {
                button.disabled = false;
                button.textContent = original;
            }
        }

        document.getElementById('btn-add-webhook')?.addEventListener('click', () => openForm(null));
        document.getElementById('btn-save-webhook')?.addEventListener('click', save);
        document.getElementById('btn-cancel-webhook')?.addEventListener('click', closeForm);
        document.getElementById('webhook-format')?.addEventListener('change', syncSecretField);

        load();
        initApiTokens();
    }

    function initApiTokens() {
        const container = document.getElementById('tokens-container');

        if (!container) return;

        function usedAt(row) {
            if (!row.last_used_at) return '<span class="dpxl-muted">Never used</span>';

            const when = new Date(row.last_used_at.replace(' ', 'T') + 'Z').toLocaleString();
            const from = row.last_used_ip ? `<br><span class="dpxl-muted">${esc(row.last_used_ip)}</span>` : '';

            return `${esc(when)}${from}`;
        }

        async function load() {
            try {
                const data  = await api.get('api-tokens');
                const items = data.items || [];

                container.className = '';

                if (!items.length) {
                    container.innerHTML = '<p class="dpxl-empty-state">No tokens yet. Nothing can read this site through the API.</p>';
                    return;
                }

                container.innerHTML = `
                    <table class="dpxl-table">
                        <thead><tr><th>Name</th><th>Token</th><th>Created</th><th>Last used</th><th></th></tr></thead>
                        <tbody>${items.map(row => `
                            <tr>
                                <td><strong>${esc(row.label)}</strong></td>
                                <td><code>${esc(row.masked)}</code></td>
                                <td>${esc(new Date(row.created_at.replace(' ', 'T') + 'Z').toLocaleDateString())}</td>
                                <td>${usedAt(row)}</td>
                                <td><button class="dpxl-btn dpxl-btn--sm" data-revoke="${row.id}">Revoke</button></td>
                            </tr>`).join('')}
                        </tbody>
                    </table>`;

                container.querySelectorAll('[data-revoke]').forEach(b =>
                    b.addEventListener('click', () => revoke(b.dataset.revoke)));
            } catch (e) {
                container.innerHTML = `<p class="dpxl-empty-state">${esc(e.message)}</p>`;
            }
        }

        async function create() {
            const label = document.getElementById('token-label');

            try {
                const res = await api.post('api-tokens', { label: label?.value || '' });

                // The plaintext exists only in this response — surface it and let
                // the admin copy it before anything else happens on the page.
                const notice = document.getElementById('new-token-notice');
                document.getElementById('new-token-value').textContent = res.plain;
                notice?.classList.remove('dpxl-hidden');
                notice?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

                if (label) label.value = '';
                load();
            } catch (e) { showNotice(e.message, 'error'); }
        }

        async function revoke(id) {
            if (!confirm('Revoke this token? Any integration using it will stop working immediately.')) return;

            try {
                await api.delete(`api-tokens/${encodeURIComponent(id)}`);
                showNotice('Token revoked.');
                load();
            } catch (e) { showNotice(e.message, 'error'); }
        }

        document.getElementById('btn-create-token')?.addEventListener('click', create);
        document.getElementById('btn-copy-token')?.addEventListener('click', () => {
            const value = document.getElementById('new-token-value')?.textContent;
            if (value) navigator.clipboard.writeText(value).then(() => showNotice('Token copied.'));
        });

        load();
    }

    // ── Tools: Diagnostics ──────────────────────────────────────────────────

    if (page === 'dpxl-shield-tools' && tab === 'diagnostics') {
        initDiagnostics();
    }

    function initDiagnostics() {
        document.getElementById('btn-run-diagnostics')?.addEventListener('click', runDiagnostics);
        document.getElementById('btn-copy-diagnostics')?.addEventListener('click', () => {
            const text = document.getElementById('diagnostics-container')?.innerText;
            if (text) navigator.clipboard.writeText(text).then(() => showNotice('Diagnostics copied.'));
        });
    }

    async function runDiagnostics() {
        const container = document.getElementById('diagnostics-container');
        if (!container) return;
        container.innerHTML = '<div class="dpxl-loading-cell"><div class="dpxl-spinner"></div> Executando diagnóstico…</div>';

        try {
            const data = await api.get('diagnostics');
            const checks = data.checks || {};

            const groups = {
                'PHP & WordPress': ['php_version', 'wp_version', 'mysql_version'],
                'PHP Extensions':  ['openssl', 'mbstring', 'hash', 'json', 'curl'],
                'Performance':     ['apcu', 'opcache'],
                'DPXL Shield':     ['extended_mode', 'maxmind_db', 'wp_cron'],
                'Permissions':     ['wp_config_perms', 'uploads_perms'],
                'Server':          ['disk_space'],
            };

            container.innerHTML = Object.entries(groups).map(([group, keys]) => `
                <div class="dpxl-diag-group">
                    <h3>${esc(group)}</h3>
                    ${keys.filter(k => checks[k]).map(k => {
                        const c = checks[k];
                        return `<div class="dpxl-diag-item">
                            <span class="dpxl-diag-status">${statusIcon(c.status)}</span>
                            <span class="dpxl-diag-label">${esc(c.label)}</span>
                            <span class="dpxl-diag-value">${esc(c.value)}</span>
                        </div>
                        ${c.note ? `<div class="dpxl-diag-note">${esc(c.note)}</div>` : ''}`;
                    }).join('')}
                </div>
            `).join('');
        } catch (e) { container.innerHTML = `<div class="dpxl-empty-state">${esc(e.message)}</div>`; }
    }

    // ── All Options ─────────────────────────────────────────────────────────

    if (page === 'dpxl-shield-options') {
        initAllOptions();
    }

    function initAllOptions() {
        // Accordion toggles
        document.querySelectorAll('.dpxl-option-group__toggle').forEach(btn => {
            btn.addEventListener('click', () => {
                const body = btn.nextElementSibling;
                const arrow = btn.querySelector('.dpxl-toggle-arrow');
                body?.classList.toggle('dpxl-hidden');
                if (arrow) arrow.innerHTML = icon(body?.classList.contains('dpxl-hidden') ? 'chevron-right' : 'chevron-down');
            });
        });

        // Expand all
        document.getElementById('btn-expand-all')?.addEventListener('click', () => {
            document.querySelectorAll('.dpxl-option-group__body').forEach(b => b.classList.remove('dpxl-hidden'));
        });

        // Save all
        document.getElementById('btn-save-all')?.addEventListener('click', saveAllOptions);

        // Per-group save
        document.querySelectorAll('.dpxl-btn--save-group').forEach(btn => {
            btn.addEventListener('click', () => saveGroupOptions(btn.dataset.group));
        });

        // Search
        document.getElementById('options-search')?.addEventListener('input', function () {
            const q = this.value.toLowerCase();
            document.querySelectorAll('.dpxl-option-row').forEach(row => {
                const match = !q || row.dataset.searchText?.includes(q);
                row.classList.toggle('dpxl-hidden', !match);
            });
        });
    }

    async function saveAllOptions() {
        const settings = collectFormSettings(document.getElementById('all-options-form'));
        try {
            await api.post('settings', settings);
            const saved = document.getElementById('all-options-saved');
            saved?.classList.remove('dpxl-hidden');
            setTimeout(() => saved?.classList.add('dpxl-hidden'), 3000);
        } catch (e) { showNotice(e.message, 'error'); }
    }

    async function saveGroupOptions(groupId) {
        const group = document.getElementById(`group-${groupId}`);
        if (!group) return;
        const settings = collectFormSettings(group);
        try {
            await api.post('settings', settings);
            showNotice(dpxlShield.strings.saved);
        } catch (e) { showNotice(e.message, 'error'); }
    }

    function collectFormSettings(form) {
        if (!form) return {};
        const settings = {};
        form.querySelectorAll('input, select, textarea').forEach(el => {
            if (!el.name) return;
            if (el.type === 'checkbox') settings[el.name] = el.checked ? 1 : 0;
            else settings[el.name] = el.value;
        });
        return settings;
    }

    // ── Login Security ──────────────────────────────────────────────────────

    if (page === 'dpxl-shield-login') {
        initLoginSecurity();
    }

    function initLoginSecurity() {
        // Settings form save
        document.getElementById('login-settings-form')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const settings = collectFormSettings(e.target);
            try {
                await api.post('settings', settings);
                showNotice(dpxlShield.strings.saved);
            } catch (err) { showNotice(err.message, 'error'); }
        });

        const setupPanel = document.getElementById('tab-2fa');
        if (setupPanel) {
            loadTwoFactorSetup();
        }

        document.getElementById('btn-activate-2fa')?.addEventListener('click', activateTwoFactor);
        document.getElementById('btn-download-codes')?.addEventListener('click', () => {
            const codes = getCurrentRecoveryCodes();
            if (!codes.length) {
                showNotice('Os códigos serão liberados depois que o 2FA for ativado.', 'warning');
                return;
            }
            downloadTextFile('dpxl-shield-codigos-recuperacao.txt', formatRecoveryCodesForDownload(codes));
        });
        document.getElementById('btn-regen-codes')?.addEventListener('click', regenerateTwoFactorCodes);
    }

    let currentRecoveryCodes = [];

    function getCurrentRecoveryCodes() {
        return Array.isArray(currentRecoveryCodes) ? currentRecoveryCodes : [];
    }

    async function loadTwoFactorSetup() {
        const qrContainer = document.getElementById('dpxl-qr-container');
        const manualKey = document.getElementById('totp-manual-key');
        const recoveryContainer = document.getElementById('backup-codes-container');

        if (!qrContainer || !manualKey || !recoveryContainer) return;

        try {
            const data = await api.get('2fa/setup');

            if (data.enabled) {
                qrContainer.innerHTML = '<div class="dpxl-notice dpxl-notice--success">2FA já está ativo para esta conta.</div>';
                manualKey.value = '';
                recoveryContainer.innerHTML = `<p>Códigos de recuperação restantes: ${esc(data.recovery_codes_remaining ?? 0)}</p>`;
                return;
            }

            manualKey.value = data.manual_key || '';
            manualKey.dataset.raw = data.manual_key_raw || '';
            qrContainer.innerHTML = renderQrSvg(data.provisioning_uri || '');
            recoveryContainer.innerHTML = `<p>${esc(data.recovery_message || 'Os códigos de recuperação serão gerados após a ativação.')}</p>`;
        } catch (err) {
            qrContainer.innerHTML = '<div class="dpxl-notice dpxl-notice--error">Não foi possível carregar o QR Code.</div>';
            recoveryContainer.innerHTML = '<div class="dpxl-notice dpxl-notice--error">Não foi possível carregar os dados do 2FA.</div>';
            showNotice('Erro ao carregar 2FA: ' + err.message, 'error');
        }
    }

    function renderQrSvg(text) {
        if (!text) {
            return '<div class="dpxl-notice dpxl-notice--error">URI de configuração ausente.</div>';
        }

        if (!window.DPXLQRCode || !window.DPXLQRErrorCorrectLevel) {
            return '<div class="dpxl-notice dpxl-notice--warning">QR Code local indisponível. Use a chave manual abaixo.</div>';
        }

        try {
            const qr = new window.DPXLQRCode(-1, window.DPXLQRErrorCorrectLevel.M);
            qr.addData(text);
            qr.make();

            const count = qr.getModuleCount();
            const cell = 6;
            const margin = 4;
            const size = (count + margin * 2) * cell;
            let rects = '';

            for (let row = 0; row < count; row++) {
                for (let col = 0; col < count; col++) {
                    if (qr.isDark(row, col)) {
                        rects += `<rect x="${(col + margin) * cell}" y="${(row + margin) * cell}" width="${cell}" height="${cell}"/>`;
                    }
                }
            }

            return `<svg class="dpxl-qr-svg" width="180" height="180" viewBox="0 0 ${size} ${size}" role="img" aria-label="QR Code para aplicativo autenticador"><rect width="100%" height="100%" fill="#fff"/><g fill="#111">${rects}</g></svg>`;
        } catch (err) {
            return '<div class="dpxl-notice dpxl-notice--warning">Não foi possível gerar o QR Code local. Use a chave manual abaixo.</div>';
        }
    }

    async function activateTwoFactor() {
        const input = document.getElementById('totp-code');
        const btn = document.getElementById('btn-activate-2fa');
        const recoveryContainer = document.getElementById('backup-codes-container');
        const code = (input?.value || '').replace(/\s+/g, '');

        if (!/^\d{6}$/.test(code)) {
            showNotice('Digite o código de 6 dígitos do aplicativo autenticador.', 'warning');
            input?.focus();
            return;
        }

        const original = btn ? btn.textContent : '';
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Ativando…';
        }

        try {
            const result = await api.post('2fa/activate', { code });
            currentRecoveryCodes = result.backup_codes || [];

            if (recoveryContainer && currentRecoveryCodes.length) {
                recoveryContainer.innerHTML = renderRecoveryCodes(currentRecoveryCodes);
            }

            showNotice(result.message || '2FA ativado com sucesso.');
            if (btn) btn.textContent = 'Ativado';
        } catch (err) {
            showNotice('Erro ao ativar 2FA: ' + err.message, 'error');
            if (btn) {
                btn.disabled = false;
                btn.textContent = original || 'Ativar';
            }
        }
    }

    async function regenerateTwoFactorCodes() {
        if (!confirm('Gerar novos códigos de recuperação? Os códigos antigos deixarão de funcionar.')) return;

        try {
            const result = await api.post('2fa/recovery-codes/regenerate');
            currentRecoveryCodes = result.backup_codes || [];
            showNotice(result.message || 'Novos códigos gerados.');
            downloadTextFile('dpxl-shield-codigos-recuperacao.txt', formatRecoveryCodesForDownload(currentRecoveryCodes));
        } catch (err) {
            showNotice('Erro ao gerar códigos: ' + err.message, 'error');
        }
    }

    function renderRecoveryCodes(codes) {
        return `
            <div class="dpxl-notice dpxl-notice--success">Códigos de recuperação gerados. Baixe e guarde em um local seguro.</div>
            <div class="dpxl-recovery-codes-list">
                ${codes.map(code => `<code>${esc(code)}</code>`).join('')}
            </div>
        `;
    }

    function formatRecoveryCodesForDownload(codes) {
        return [
            'DPXL Shield — Códigos de recuperação 2FA',
            'Guarde estes códigos em um local seguro. Cada código só pode ser usado uma vez.',
            '',
            ...codes,
            '',
            'Gerado em: ' + new Date().toISOString(),
        ].join('\n');
    }

    function downloadTextFile(filename, content) {
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

})();
