/**
 * AML Sentinel — Shared Topbar Shell Enhancer (P1-3, P1-4, P1-6)
 * ===============================================================
 * Auto-loaded by api-client.js across all 14 workspace pages to provide:
 *  1. Global Cmd+K / Ctrl+K Command Palette (native <dialog>, live /api/v1/search/global)
 *  2. In-App Notification & SLA Escalation Bell (/api/v1/notifications)
 *  3. Sticky WebSocket Health & Auto-Reconnect Banner
 */
(function initSentinelShell() {
    'use strict';

    if (window.__SENTINEL_SHELL_INIT__) return;
    window.__SENTINEL_SHELL_INIT__ = true;

    const STATIC_MODULES = [
        { type: 'MODULE', title: 'Executive Dashboard', subtitle: 'KPIs, Volume & Risk Posture', url: '/dashboard/executive', badge: 'VIEW' },
        { type: 'MODULE', title: 'Alert Triage Queue', subtitle: 'Prioritized L1/L2 Investigation Queue', url: '/alerts/triage', badge: 'VIEW' },
        { type: 'MODULE', title: 'Investigations & Cases', subtitle: 'Case Workbench, Evidence & Notes', url: '/dashboard', badge: 'VIEW' },
        { type: 'MODULE', title: 'Network Graph Explorer', subtitle: 'Multi-Hop Flow & Cycle Detection', url: '/network', badge: 'VIEW' },
        { type: 'MODULE', title: 'Customer 360 Dossier', subtitle: 'KYC/EDD Profiles & Risk Breakdown', url: '/customers', badge: 'VIEW' },
        { type: 'MODULE', title: 'SAR / STR Draft Editor', subtitle: '4-Eyes Narrative & XML Preview', url: '/sar/editor', badge: 'VIEW' },
        { type: 'MODULE', title: 'SAR Filing Queue', subtitle: 'MLRO Approvals & 30-Day BSA Clocks', url: '/sar/queue', badge: 'MLRO' },
        { type: 'MODULE', title: 'Compliance Ops Hub', subtitle: 'CTR, pKYC Rescreening & QA Sampling', url: '/compliance/ops', badge: 'OPS' },
        { type: 'MODULE', title: 'Rule & Threshold Builder', subtitle: 'Backtest Replay & Shadow Mode Rules', url: '/admin/rules', badge: 'ADMIN' },
        { type: 'MODULE', title: 'AI & Model Governance', subtitle: 'SR 11-7 Validation & Active Learning', url: '/ml/governance', badge: 'ML' },
        { type: 'MODULE', title: 'Risk Appetite Settings', subtitle: 'Jurisdiction & Threshold Multipliers', url: '/settings/risk-appetite', badge: 'MLRO' },
        { type: 'MODULE', title: 'Immutable Audit Vault', subtitle: 'Cryptographic Hash-Chain Ledger', url: '/audit/logs', badge: 'AUDIT' },
        { type: 'MODULE', title: 'Team & RBAC Management', subtitle: '5-Tier Access Control & SSO', url: '/admin/users', badge: 'ADMIN' },
        { type: 'MODULE', title: 'System Health & SIEM', subtitle: 'Service Probes & Outbox Telemetry', url: '/admin/health', badge: 'SRE' },
    ];

    function esc(v) {
        return typeof window.escapeHtml === 'function'
            ? window.escapeHtml(v)
            : String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    }

    function injectStyles() {
        // Styles live natively in style.css for zero-flicker Frame 0 painting; only inject fallback if missing.
        if (document.getElementById('sentinel-shell-styles')) return;
        const probe = document.querySelector('.sentinel-shell-btn');
        if (probe && window.getComputedStyle(probe).display === 'inline-flex') return;
        const style = document.createElement('style');
        style.id = 'sentinel-shell-styles';
        style.textContent = `
            .sentinel-shell-btn {
                display: inline-flex; align-items: center; justify-content: center; gap: 6px;
                height: 32px; min-height: 32px; min-width: 32px; padding: 0 10px; border-radius: 9px;
                border: 1px solid rgba(255,255,255,0.14);
                background: rgba(255,255,255,0.06); color: #E7E9EF;
                font-size: 12px; font-family: 'Inter', sans-serif; font-weight: 500;
                cursor: pointer; transition: background 0.15s, border-color 0.15s;
            }
        `;
        document.head.appendChild(style);
    }

    // ── 0. Instant Navigation Prefetch (Speculation Rules + pointerenter fallback) ──
    function installInstantPrefetch() {
        const WORKSPACE_URLS = [
            '/dashboard/executive',
            '/alerts/triage',
            '/dashboard',
            '/network',
            '/customers',
            '/sar/editor',
            '/sar/queue',
            '/compliance/ops',
            '/admin/rules',
            '/ml/governance',
            '/settings/risk-appetite',
            '/audit/logs',
            '/admin/users',
            '/admin/health',
        ];
        if (HTMLScriptElement.supports && HTMLScriptElement.supports('speculationrules')) {
            if (!document.getElementById('sentinel-speculation-rules')) {
                const sr = document.createElement('script');
                sr.id = 'sentinel-speculation-rules';
                sr.type = 'speculationrules';
                sr.textContent = JSON.stringify({
                    prefetch: [
                        {
                            where: {
                                and: [
                                    { href_matches: '/*' },
                                    { not: { href_matches: '/api/*' } },
                                    { not: { href_matches: '/login*' } },
                                    { not: { href_matches: '/rfi/*' } },
                                ],
                            },
                            eagerness: 'moderate',
                        },
                    ],
                });
                document.head.appendChild(sr);
            }
            return;
        }
        // Fallback link prefetch on hover/focus for Firefox & Safari
        const prefetched = new Set([window.location.pathname]);
        document.addEventListener('pointerenter', (e) => {
            const a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
            if (!a) return;
            const href = a.getAttribute('href') || '';
            if (!href.startsWith('/') || prefetched.has(href) || !WORKSPACE_URLS.includes(href)) return;
            prefetched.add(href);
            const link = document.createElement('link');
            link.rel = 'prefetch';
            link.as = 'document';
            link.href = href;
            document.head.appendChild(link);
        }, true);
    }

    // ── 1. Command Palette (Cmd+K / Ctrl+K) ──────────────────────────────────
    let cmdkDialog = null;
    let cmdkItems = [];
    let cmdkActiveIdx = 0;
    let cmdkTimer = null;

    function renderCmdkList(items) {
        cmdkItems = items;
        cmdkActiveIdx = 0;
        const listEl = document.getElementById('sentinel-cmdk-list');
        if (!listEl) return;
        if (!items.length) {
            listEl.innerHTML = '<div style="padding:20px;text-align:center;font-size:12.5px;color:#5C6068;">No matching accounts, cases, alerts, or views.</div>';
            return;
        }
        listEl.innerHTML = items.map((it, idx) => `
            <a class="sentinel-cmdk-item${idx === 0 ? ' active' : ''}" data-idx="${idx}" href="${esc(it.url)}">
                <div class="sentinel-cmdk-meta">
                    <span class="sentinel-cmdk-title">${esc(it.title)}</span>
                    <span class="sentinel-cmdk-sub">${esc(it.subtitle || it.type)}</span>
                </div>
                <span class="sentinel-cmdk-badge">${esc(it.badge || it.type)}</span>
            </a>
        `).join('');
    }

    function updateCmdkActive(nextIdx) {
        if (!cmdkItems.length) return;
        cmdkActiveIdx = (nextIdx + cmdkItems.length) % cmdkItems.length;
        document.querySelectorAll('#sentinel-cmdk-list .sentinel-cmdk-item').forEach((el, idx) => {
            el.classList.toggle('active', idx === cmdkActiveIdx);
            if (idx === cmdkActiveIdx) el.scrollIntoView({ block: 'nearest' });
        });
    }

    async function runCmdkSearch(rawQuery) {
        const q = (rawQuery || '').trim().toLowerCase();
        const localMatches = STATIC_MODULES.filter(
            (m) => !q || m.title.toLowerCase().includes(q) || m.subtitle.toLowerCase().includes(q)
        );
        renderCmdkList(localMatches.slice(0, 8));
        if (q.length < 2) {
            if (window.SentinelQuery) window.SentinelQuery.cancelQueries('cmdk-search');
            return;
        }

        try {
            const url = `/api/v1/search/global?q=${encodeURIComponent(q)}&limit=5`;
            const data = window.SentinelQuery
                ? await window.SentinelQuery.fetchJson(['search', 'global', q], url, {
                    abortKey: 'cmdk-search',
                    staleTime: 15000,
                })
                : await fetch(url, { credentials: 'include' }).then((r) => (r.ok ? r.json() : null));
            if (!data) return;
            const merged = [...(data.items || []), ...localMatches.slice(0, 4)];
            renderCmdkList(merged.slice(0, 14));
        } catch (err) {
            if (err && err.name === 'AbortError') return;
            /* keep static module results */
        }
    }

    function openCommandPalette() {
        if (!cmdkDialog) {
            cmdkDialog = document.createElement('dialog');
            cmdkDialog.className = 'sentinel-cmdk-dialog';
            cmdkDialog.setAttribute('aria-label', 'Global Command Palette');
            cmdkDialog.innerHTML = `
                <div class="sentinel-cmdk-inputwrap">
                    <span style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#5C6068;">⌘K</span>
                    <input id="sentinel-cmdk-input" class="sentinel-cmdk-input" type="text" placeholder="Search accounts, cases, alerts, SARs, or jump to module..." autocomplete="off" />
                    <button type="button" id="sentinel-cmdk-close" style="border:none;background:transparent;color:#5C6068;cursor:pointer;font-size:12px;">ESC</button>
                </div>
                <div id="sentinel-cmdk-list" class="sentinel-cmdk-list" role="listbox"></div>
                <div class="sentinel-cmdk-foot">
                    <span>↑↓ Navigate · ↵ Open</span>
                    <span>Sentinel Global Index</span>
                </div>
            `;
            document.body.appendChild(cmdkDialog);

            const input = cmdkDialog.querySelector('#sentinel-cmdk-input');
            cmdkDialog.querySelector('#sentinel-cmdk-close').addEventListener('click', () => cmdkDialog.close());
            cmdkDialog.addEventListener('click', (e) => {
                if (e.target === cmdkDialog) cmdkDialog.close();
            });
            input.addEventListener('input', (e) => {
                clearTimeout(cmdkTimer);
                cmdkTimer = setTimeout(() => runCmdkSearch(e.target.value), 160);
            });
            input.addEventListener('keydown', (e) => {
                if (e.key === 'ArrowDown') { e.preventDefault(); updateCmdkActive(cmdkActiveIdx + 1); }
                else if (e.key === 'ArrowUp') { e.preventDefault(); updateCmdkActive(cmdkActiveIdx - 1); }
                else if (e.key === 'Enter' && cmdkItems[cmdkActiveIdx]) {
                    e.preventDefault();
                    window.location.href = cmdkItems[cmdkActiveIdx].url;
                }
            });
        }
        const input = cmdkDialog.querySelector('#sentinel-cmdk-input');
        input.value = '';
        renderCmdkList(STATIC_MODULES.slice(0, 8));
        if (!cmdkDialog.open) cmdkDialog.showModal();
        input.focus();
    }

    // ── 2. In-App Notification Bell ──────────────────────────────────────────
    let notifPopover = null;
    let notifPollHandle = null;

    function applyNotifBadgeCount(unread) {
        const count = Number(unread || 0);
        const badge = document.getElementById('sentinel-notif-badge');
        if (badge) {
            badge.textContent = count > 99 ? '99+' : String(count);
            badge.classList.toggle('has-unread', count > 0);
        }
    }

    async function refreshNotifications(opts = {}) {
        try {
            const data = window.SentinelQuery
                ? await window.SentinelQuery.fetchJson(['notifications', 'inbox'], '/api/v1/notifications?limit=25', {
                    staleTime: 10000,
                    force: Boolean(opts.force),
                })
                : await fetch('/api/v1/notifications?limit=25', { credentials: 'include' }).then((r) => (r.ok ? r.json() : null));
            if (!data) return;
            const unread = Number(data.unread_count || 0);
            try { sessionStorage.setItem('sentinel_unread_notif_count', String(unread)); } catch (_) {}
            applyNotifBadgeCount(unread);
            renderNotifPopover(data.items || []);
        } catch (_) { /* ignore when unauthenticated */ }
    }

    function renderNotifPopover(items) {
        if (!notifPopover) return;
        const body = notifPopover.querySelector('#sentinel-notif-items');
        if (!body) return;
        if (!items.length) {
            body.innerHTML = '<div style="padding:20px;text-align:center;font-size:12px;color:#5C6068;">All clear — no SLA escalations or notifications.</div>';
            return;
        }
        body.innerHTML = items.map((n) => `
            <a class="sentinel-notif-item${n.is_read ? '' : ' unread'}" data-notif-id="${esc(n.id)}" href="${esc(n.link_url || '#')}">
                <div class="sentinel-notif-title">
                    <span>${esc(n.title)}</span>
                    <span class="sentinel-notif-sev ${esc(n.severity || 'INFO')}">${esc(n.severity || 'INFO')}</span>
                </div>
                <div class="sentinel-notif-body">${esc(n.body)}</div>
            </a>
        `).join('');

        body.querySelectorAll('.sentinel-notif-item').forEach((el) => {
            el.addEventListener('click', () => {
                const nid = el.getAttribute('data-notif-id');
                if (!nid) return;
                if (window.SentinelQuery) {
                    window.SentinelQuery.mutate({
                        optimisticKey: ['notifications', 'inbox'],
                        optimisticUpdater: (prev) => {
                            if (!prev || !Array.isArray(prev.items)) return prev;
                            let decremented = false;
                            const nextItems = prev.items.map((item) => {
                                if (item.id === nid && !item.is_read) {
                                    decremented = true;
                                    return Object.assign({}, item, { is_read: true });
                                }
                                return item;
                            });
                            const nextUnread = Math.max(0, Number(prev.unread_count || 0) - (decremented ? 1 : 0));
                            applyNotifBadgeCount(nextUnread);
                            try { sessionStorage.setItem('sentinel_unread_notif_count', String(nextUnread)); } catch (_) {}
                            return Object.assign({}, prev, { unread_count: nextUnread, items: nextItems });
                        },
                        mutationFn: () => window.SentinelApi.mutate(`/api/v1/notifications/${encodeURIComponent(nid)}/read`, { method: 'PATCH' }),
                        onError: () => {
                            const restored = window.SentinelQuery.getQueryData(['notifications', 'inbox']);
                            if (restored) {
                                applyNotifBadgeCount(restored.unread_count || 0);
                                renderNotifPopover(restored.items || []);
                            }
                        },
                        invalidateKeys: [['notifications']],
                    }).catch(() => {});
                } else {
                    fetch(`/api/v1/notifications/${encodeURIComponent(nid)}/read`, { method: 'PATCH', credentials: 'include' }).catch(() => {});
                }
            });
        });
    }

    function mountTopbarControls() {
        const container =
            document.querySelector('.sentinel-topbar-right') ||
            document.querySelector('.sentinel-topbar__right') ||
            document.querySelector('.header-nav .nav-right') ||
            document.querySelector('.header-nav');
        if (!container) return;

        // Bind to pre-rendered Frame-0 buttons when present (zero layout jump!); create only on legacy fallback pages
        let cmdBtn = document.getElementById('sentinel-cmdk-trigger');
        let bellBtn = document.getElementById('sentinel-notif-bell');
        let bellWrap = bellBtn ? bellBtn.closest('.sentinel-notif-wrap') : null;

        if (!cmdBtn) {
            cmdBtn = document.createElement('button');
            cmdBtn.type = 'button';
            cmdBtn.id = 'sentinel-cmdk-trigger';
            cmdBtn.className = 'sentinel-shell-btn';
            cmdBtn.title = 'Global Search & Command Palette (Cmd+K / Ctrl+K)';
            cmdBtn.innerHTML = '<span>Search</span><span class="sentinel-shell-kbd">⌘K</span>';
            container.insertBefore(cmdBtn, container.firstChild);
        }
        if (cmdBtn.dataset.sentinelBound !== '1') {
            cmdBtn.dataset.sentinelBound = '1';
            cmdBtn.addEventListener('click', openCommandPalette);
        }

        if (!bellBtn) {
            bellWrap = document.createElement('div');
            bellWrap.className = 'sentinel-notif-wrap';
            bellWrap.innerHTML = `
                <button type="button" id="sentinel-notif-bell" class="sentinel-shell-btn" aria-label="Notifications" title="SLA & Compliance Notifications">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                </button>
                <span id="sentinel-notif-badge" class="sentinel-notif-badge">0</span>
            `;
            container.insertBefore(bellWrap, cmdBtn.nextSibling);
            bellBtn = document.getElementById('sentinel-notif-bell');
        }
        if (!bellWrap) bellWrap = bellBtn.parentElement;

        // Hydrate unread count immediately from sessionStorage so badge never blinks on navigation
        try {
            const cachedUnread = sessionStorage.getItem('sentinel_unread_notif_count');
            if (cachedUnread !== null) applyNotifBadgeCount(cachedUnread);
        } catch (_) {}

        if (bellBtn.dataset.sentinelBound === '1') return;
        bellBtn.dataset.sentinelBound = '1';

        notifPopover = document.createElement('div');
        notifPopover.className = 'sentinel-notif-popover';
        notifPopover.innerHTML = `
            <div class="sentinel-notif-head">
                <span>Notifications &amp; SLA Escalations</span>
                <div class="sentinel-notif-actions">
                    <button type="button" id="sentinel-notif-sweep" class="sentinel-notif-linkbtn">Check SLAs</button>
                    <button type="button" id="sentinel-notif-readall" class="sentinel-notif-linkbtn">Mark all read</button>
                </div>
            </div>
            <div id="sentinel-notif-items"></div>
        `;
        document.body.appendChild(notifPopover);

        bellBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            if (profilePopover) profilePopover.classList.remove('open');
            const modMenu = document.getElementById('sentinel-modules-menu');
            if (modMenu) { modMenu.classList.remove('show'); modMenu.style.display = 'none'; }
            notifPopover.classList.toggle('open');
            if (notifPopover.classList.contains('open')) refreshNotifications();
        });
        document.addEventListener('click', (e) => {
            if (notifPopover.classList.contains('open') && !notifPopover.contains(e.target) && !bellWrap.contains(e.target)) {
                notifPopover.classList.remove('open');
            }
        });
        notifPopover.querySelector('#sentinel-notif-readall').addEventListener('click', async () => {
            if (window.SentinelQuery && window.SentinelApi) {
                try {
                    await window.SentinelQuery.mutate({
                        optimisticKey: ['notifications', 'inbox'],
                        optimisticUpdater: (prev) => {
                            const nextItems = prev && Array.isArray(prev.items)
                                ? prev.items.map((it) => Object.assign({}, it, { is_read: true }))
                                : [];
                            applyNotifBadgeCount(0);
                            try { sessionStorage.setItem('sentinel_unread_notif_count', '0'); } catch (_) {}
                            renderNotifPopover(nextItems);
                            return Object.assign({}, prev || {}, { unread_count: 0, items: nextItems });
                        },
                        mutationFn: () => window.SentinelApi.mutate('/api/v1/notifications/read-all', { method: 'POST' }),
                        onError: () => {
                            const restored = window.SentinelQuery.getQueryData(['notifications', 'inbox']);
                            if (restored) {
                                applyNotifBadgeCount(restored.unread_count || 0);
                                renderNotifPopover(restored.items || []);
                            }
                        },
                        invalidateKeys: [['notifications']],
                    });
                } catch (_) { /* rolled back */ }
            } else {
                await fetch('/api/v1/notifications/read-all', { method: 'POST', credentials: 'include' }).catch(() => {});
            }
            refreshNotifications({ force: true });
        });
        notifPopover.querySelector('#sentinel-notif-sweep').addEventListener('click', async () => {
            await fetch('/api/v1/notifications/check-sla', { method: 'POST', credentials: 'include' }).catch(() => {});
            refreshNotifications({ force: true });
        });

        refreshNotifications();
        if (window.SentinelQuery) {
            window.SentinelQuery.onInvalidate(['notifications'], () => {
                if (!document.hidden) refreshNotifications();
            });
        }
        notifPollHandle = window.setInterval(() => {
            if (!document.hidden) refreshNotifications();
        }, 60000);
        window.addEventListener('beforeunload', () => {
            if (notifPollHandle) window.clearInterval(notifPollHandle);
        });
    }

    // ── 3. Sticky WebSocket Health & Auto-Reconnect Banner ───────────────────
    let wsBanner = null;

    function ensureWsBanner() {
        if (wsBanner) return wsBanner;
        wsBanner = document.createElement('div');
        wsBanner.id = 'sentinel-ws-banner';
        wsBanner.className = 'sentinel-ws-banner';
        wsBanner.setAttribute('role', 'status');
        wsBanner.setAttribute('aria-live', 'polite');
        wsBanner.innerHTML = `
            <span class="sentinel-ws-dot"></span>
            <span id="sentinel-ws-text">Live telemetry reconnecting…</span>
            <button type="button" id="sentinel-ws-reconnect">Reconnect</button>
        `;
        wsBanner.querySelector('#sentinel-ws-reconnect').addEventListener('click', () => {
            if (typeof window.initWebSocket === 'function') {
                window.initWebSocket();
            } else {
                window.location.reload();
            }
        });
        document.body.appendChild(wsBanner);
        return wsBanner;
    }

    function setConnectionState(state, message) {
        const banner = ensureWsBanner();
        const textEl = banner.querySelector('#sentinel-ws-text');
        if (state === 'connected') {
            banner.classList.remove('visible', 'offline');
            return;
        }
        banner.classList.add('visible');
        banner.classList.toggle('offline', state === 'offline');
        if (textEl) {
            textEl.textContent = message || (state === 'offline' ? 'Offline — Live stream disconnected (polling mode)' : 'Live telemetry stream reconnecting…');
        }
    }

    window.addEventListener('offline', () => setConnectionState('offline', 'Network offline — showing cached compliance view'));
    window.addEventListener('online', () => setConnectionState('connected'));

    // Global Cmd+K / Ctrl+K shortcut
    document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
            e.preventDefault();
            openCommandPalette();
        }
    });

    // ── 4. Mobile Core Views Fallback inside Modules Dropdown (<= 768px) ─────
    function injectMobileCoreNav() {
        const menu =
            document.getElementById('sentinel-modules-menu') ||
            document.getElementById('app-modules-menu') ||
            document.querySelector('.sentinel-dropdown-menu') ||
            document.querySelector('.dropdown-menu');
        if (!menu || menu.querySelector('.sentinel-mobile-core-nav')) return;

        const isDarkDropdown = menu.classList.contains('dropdown-menu');
        const itemClass = menu.querySelector('.sentinel-dropdown-item')
            ? 'sentinel-dropdown-item'
            : (isDarkDropdown ? 'dropdown-item' : 'sentinel-dropdown-item');
        const labelClass = menu.querySelector('.sentinel-dropdown-label')
            ? 'sentinel-dropdown-label'
            : (isDarkDropdown ? 'dropdown-group-label' : 'sentinel-dropdown-label');
        const dividerClass = menu.querySelector('.sentinel-dropdown-divider')
            ? 'sentinel-dropdown-divider'
            : (isDarkDropdown ? 'dropdown-divider' : 'sentinel-dropdown-divider');

        const coreBlock = document.createElement('div');
        coreBlock.className = 'sentinel-mobile-core-nav';
        coreBlock.innerHTML = `
            <div class="${labelClass}">Core Workspace</div>
            <a href="/dashboard/executive" class="${itemClass}">Overview</a>
            <a href="/alerts/triage" class="${itemClass}">Triage Queue</a>
            <a href="/dashboard" class="${itemClass}">Investigations</a>
            <a href="/network" class="${itemClass}">Network Explorer</a>
            <div class="${dividerClass}"></div>
        `;
        menu.insertBefore(coreBlock, menu.firstChild);
    }

    // ── 5. Account & Session Popover (replaces forced /admin/users redirect) ─
    let profilePopover = null;

    function mountProfilePopover() {
        const avatarBtn = document.getElementById('sentinel-user-avatar');
        if (!avatarBtn || avatarBtn.dataset.sentinelProfileBound === '1') return;
        avatarBtn.dataset.sentinelProfileBound = '1';
        avatarBtn.removeAttribute('onclick');
        avatarBtn.setAttribute('aria-haspopup', 'true');
        avatarBtn.setAttribute('aria-expanded', 'false');

        profilePopover = document.createElement('div');
        profilePopover.className = 'sentinel-profile-popover';
        profilePopover.setAttribute('role', 'dialog');
        profilePopover.setAttribute('aria-label', 'Account Profile and Session');
        profilePopover.innerHTML = `
            <div class="sentinel-profile-head">
                <div class="sentinel-profile-name" id="sentinel-prof-user">Authenticated Analyst</div>
                <div class="sentinel-profile-meta">
                    <span class="sentinel-profile-role" id="sentinel-prof-role">SESSION</span>
                    <span id="sentinel-prof-tenant">Tenant: default</span>
                </div>
            </div>
            <div class="sentinel-profile-actions">
                <a href="/admin/users" class="sentinel-profile-action" id="sentinel-prof-rbac" style="display:none;">
                    <span>Team &amp; Access Control</span><span>→</span>
                </a>
                <a href="/compliance/ops" class="sentinel-profile-action">
                    <span>Compliance Ops Hub</span><span>→</span>
                </a>
                <button type="button" class="sentinel-profile-action sentinel-profile-action--danger" id="sentinel-prof-logout">
                    <span>Sign Out</span><span>↪</span>
                </button>
            </div>
        `;
        document.body.appendChild(profilePopover);

        async function loadProfileSession() {
            try {
                const me = window.SentinelQuery
                    ? await window.SentinelQuery.fetchJson(['auth', 'me'], '/api/v1/auth/me', { staleTime: 60000 })
                    : await fetch('/api/v1/auth/me', { credentials: 'include' }).then((r) => (r.ok ? r.json() : null));
                if (!me) return;
                const userEl = document.getElementById('sentinel-prof-user');
                const roleEl = document.getElementById('sentinel-prof-role');
                const tenantEl = document.getElementById('sentinel-prof-tenant');
                const rbacEl = document.getElementById('sentinel-prof-rbac');
                if (userEl) userEl.textContent = me.username || me.email || 'Compliance Officer';
                const role = String(me.role || 'ANALYST').toUpperCase();
                if (roleEl) roleEl.textContent = role;
                if (tenantEl) tenantEl.textContent = `Tenant: ${me.tenant_id || 'default'}`;
                if (rbacEl) rbacEl.style.display = ['ADMIN', 'MLRO', 'SUPERADMIN'].includes(role) ? 'flex' : 'none';
            } catch (_) { /* ignore */ }
        }

        avatarBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const isOpen = profilePopover.classList.toggle('open');
            avatarBtn.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
            if (isOpen) {
                if (notifPopover) notifPopover.classList.remove('open');
                loadProfileSession();
            }
        });

        profilePopover.querySelector('#sentinel-prof-logout').addEventListener('click', () => {
            if (typeof window.logout === 'function') {
                window.logout();
            } else {
                window.location.href = '/login';
            }
        });

        document.addEventListener('click', (e) => {
            if (profilePopover.classList.contains('open') && !profilePopover.contains(e.target) && !avatarBtn.contains(e.target)) {
                profilePopover.classList.remove('open');
                avatarBtn.setAttribute('aria-expanded', 'false');
            }
        });
    }

    function bootstrap() {
        injectStyles();
        installInstantPrefetch();
        mountTopbarControls();
        injectMobileCoreNav();
        mountProfilePopover();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bootstrap);
    } else {
        bootstrap();
    }

    window.SentinelShell = {
        openCommandPalette,
        refreshNotifications,
        setConnectionState,
    };
})();
