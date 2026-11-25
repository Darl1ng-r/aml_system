/**
 * AML Sentinel — Enterprise Unified HTTP Transport & Cross-Tab Session Client
 * ============================================================================
 * Loaded in <head> across all 14 workspace pages to provide ONE canonical transport:
 *  1. Automatic `credentials: 'include'` + `X-CSRF-Protection: 1` on strictly same-origin requests
 *  2. Automatic UUIDv4 `Idempotency-Key` attachment on ALL same-origin mutations (POST/PUT/PATCH/DELETE)
 *  3. Cross-tab single-flight silent 401 token refresh (Web Locks API + BroadcastChannel) to prevent
 *     Refresh Token Rotation (RTR) race collisions across open tabs
 *  4. Cross-tab logout synchronization (clears in-memory cache + redirects all tabs to /login)
 *  5. Bounded full-jitter retry (`Retry-After`-aware) on transient network/429/502/503/504 failures
 *     strictly for safe methods (GET/HEAD/OPTIONS) or idempotent keyed mutations
 *  6. Normalized `SentinelApiError` + `window.SentinelApi` helper surfacing `correlation_id`
 *  7. XSS defense-in-depth helpers (`escapeHtml`, `safeHtml`, `rawSafeHtml`)
 */
(function () {
    'use strict';

    // ── 0. Global XSS Defense-in-Depth Helpers ────────────────────────────────
    window.escapeHtml = function escapeHtml(value) {
        if (value === null || value === undefined) return '';
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;')
            .replace(/`/g, '&#96;');
    };

    window.safeHtml = function safeHtml(strings, ...values) {
        return strings.reduce((acc, str, i) => {
            if (i >= values.length) return acc + str;
            const val = values[i];
            if (val && typeof val === 'object' && val.__rawSafeHtml === true) {
                return acc + str + String(val.html || '');
            }
            return acc + str + window.escapeHtml(val);
        }, '');
    };

    window.rawSafeHtml = function rawSafeHtml(html) {
        return { __rawSafeHtml: true, html: String(html || '') };
    };

    // ── 1. UUIDv4 Idempotency Key Generator ───────────────────────────────────
    function generateIdempotencyKey() {
        if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
            return crypto.randomUUID();
        }
        if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
            const bytes = new Uint8Array(16);
            crypto.getRandomValues(bytes);
            bytes[6] = (bytes[6] & 0x0f) | 0x40;
            bytes[8] = (bytes[8] & 0x3f) | 0x80;
            const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
            return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
        }
        return `idemp-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
    }

    // ── 2. Structured Enterprise API Error ────────────────────────────────────
    class SentinelApiError extends Error {
        constructor(message, { status = 0, code = 'API_ERROR', detail = null, correlationId = null, errors = null, retryAfter = null, etag = null, body = null } = {}) {
            super(message || detail || `HTTP ${status || 'Network Error'}`);
            this.name = 'SentinelApiError';
            this.status = status;
            this.code = code;
            this.detail = detail || message || `HTTP ${status}`;
            this.correlationId = correlationId;
            this.errors = errors;
            this.retryAfter = retryAfter;
            this.etag = etag;
            this.body = body;
        }

        toUserMessage() {
            const base = typeof this.detail === 'string' ? this.detail : this.message;
            return this.correlationId ? `${base} (Ref: ${this.correlationId})` : base;
        }
    }
    window.SentinelApiError = SentinelApiError;

    // ── 3. Cross-Tab Auth Event Bus (BroadcastChannel + storage fallback) ─────
    const AUTH_CHANNEL_NAME = 'aml_sentinel_auth';
    const AUTH_STORAGE_EVENT_KEY = 'sentinel_auth_broadcast';
    const TAB_ID = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
    let authChannel = null;
    let lastCrossTabRefreshAt = 0;

    function clearClientSessionState() {
        localStorage.removeItem('jwt_token');
        localStorage.removeItem('access_token');
        localStorage.removeItem('username');
        localStorage.removeItem('role');
        localStorage.removeItem('auth_session_active');
        try { sessionStorage.clear(); } catch (_) { /* ignore */ }
        if (window.SentinelQuery && typeof window.SentinelQuery.clear === 'function') {
            try { window.SentinelQuery.clear(); } catch (_) { /* ignore */ }
        }
    }

    function handleCrossTabAuthEvent(evt) {
        if (!evt || evt.sender === TAB_ID) return;
        if (evt.type === 'AUTH_REFRESHED') {
            lastCrossTabRefreshAt = Math.max(lastCrossTabRefreshAt, Number(evt.ts || Date.now()));
        } else if (evt.type === 'AUTH_LOGOUT') {
            clearClientSessionState();
            if (!window.location.pathname.startsWith('/login') && !window.location.pathname.startsWith('/rfi/')) {
                window.location.replace('/login');
            }
        }
    }

    function broadcastAuthEvent(payload) {
        const msg = Object.assign({ sender: TAB_ID, ts: Date.now() }, payload);
        if (authChannel) {
            try { authChannel.postMessage(msg); } catch (_) { /* ignore */ }
        }
        try {
            localStorage.setItem(AUTH_STORAGE_EVENT_KEY, JSON.stringify(msg));
            localStorage.removeItem(AUTH_STORAGE_EVENT_KEY);
        } catch (_) { /* ignore */ }
    }

    if (typeof BroadcastChannel !== 'undefined') {
        try {
            authChannel = new BroadcastChannel(AUTH_CHANNEL_NAME);
            authChannel.onmessage = (e) => handleCrossTabAuthEvent(e.data);
        } catch (_) { authChannel = null; }
    }
    window.addEventListener('storage', (e) => {
        if (e.key === AUTH_STORAGE_EVENT_KEY && e.newValue) {
            try { handleCrossTabAuthEvent(JSON.parse(e.newValue)); } catch (_) { /* ignore */ }
        }
    });

    // ── 4. Unified Same-Origin Fetch Wrapper ──────────────────────────────────
    if (!window.__AML_FETCH_PATCHED__) {
        const originalFetch = window.fetch.bind(window);
        const DEFAULT_FETCH_TIMEOUT_MS = 20000;
        const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
        const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
        const RETRYABLE_STATUSES = new Set([429, 502, 503, 504]);
        const AUTH_BYPASS_RE = /\/api\/v1\/auth\/(login|refresh|logout|register|signup|mfa\/verify)/;
        let refreshPromise = null;

        function withTimeoutSignal(existingSignal, timeoutMs) {
            if (existingSignal) {
                if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function' && typeof AbortSignal.timeout === 'function') {
                    return { signal: AbortSignal.any([existingSignal, AbortSignal.timeout(timeoutMs)]), cleanup: () => {} };
                }
                return { signal: existingSignal, cleanup: () => {} };
            }
            if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function') {
                return { signal: AbortSignal.timeout(timeoutMs), cleanup: () => {} };
            }
            const ctrl = new AbortController();
            const tid = setTimeout(() => ctrl.abort(new DOMException('Request timed out', 'TimeoutError')), timeoutMs);
            return { signal: ctrl.signal, cleanup: () => clearTimeout(tid) };
        }

        function isStrictlySameOrigin(urlStr) {
            try {
                return new URL(urlStr, window.location.origin).origin === window.location.origin;
            } catch (_) {
                return false;
            }
        }

        function normalizeHeaders(rawHeaders) {
            const headers = new Headers();
            if (rawHeaders instanceof Headers) {
                rawHeaders.forEach((v, k) => headers.set(k, v));
            } else if (Array.isArray(rawHeaders)) {
                rawHeaders.forEach(([k, v]) => headers.set(k, v));
            } else if (rawHeaders && typeof rawHeaders === 'object') {
                Object.entries(rawHeaders).forEach(([k, v]) => {
                    if (v !== undefined && v !== null) headers.set(k, String(v));
                });
            }
            return headers;
        }

        function sleep(ms, signal) {
            return new Promise((resolve, reject) => {
                if (signal && signal.aborted) {
                    reject(signal.reason || new DOMException('Aborted', 'AbortError'));
                    return;
                }
                const tid = setTimeout(resolve, ms);
                if (signal) {
                    signal.addEventListener('abort', () => {
                        clearTimeout(tid);
                        reject(signal.reason || new DOMException('Aborted', 'AbortError'));
                    }, { once: true });
                }
            });
        }

        function computeRetryDelayMs(attempt, response) {
            if (response && response.headers) {
                const retryAfter = response.headers.get('Retry-After');
                if (retryAfter) {
                    const sec = Number(retryAfter);
                    if (Number.isFinite(sec) && sec > 0) {
                        return Math.min(5000, Math.round(sec * 1000));
                    }
                }
            }
            const ceiling = Math.min(2500, 300 * Math.pow(2, attempt));
            return Math.max(150, Math.round(Math.random() * ceiling));
        }

        async function runWithCrossTabRefreshLock(fn) {
            if (typeof navigator !== 'undefined' && navigator.locks && typeof navigator.locks.request === 'function') {
                return navigator.locks.request('aml_sentinel_auth_refresh', fn);
            }
            return fn();
        }

        async function attemptSilentRefresh() {
            if (refreshPromise) return refreshPromise;
            refreshPromise = runWithCrossTabRefreshLock(async () => {
                // If another browser tab rotated cookies within the last 3s, reuse the rotated cookie
                if (Date.now() - lastCrossTabRefreshAt < 3000) {
                    return true;
                }
                const { signal, cleanup } = withTimeoutSignal(null, 10000);
                try {
                    const r = await originalFetch('/api/v1/auth/refresh', {
                        method: 'POST',
                        headers: {
                            'X-CSRF-Protection': '1',
                            'X-Client-Mode': 'browser'
                        },
                        credentials: 'include',
                        signal
                    });
                    if (r.ok) {
                        lastCrossTabRefreshAt = Date.now();
                        broadcastAuthEvent({ type: 'AUTH_REFRESHED', ts: lastCrossTabRefreshAt });
                        return true;
                    }
                    if (r.status === 401 || r.status === 403) {
                        broadcastAuthEvent({ type: 'AUTH_LOGOUT', ts: Date.now() });
                    }
                    return false;
                } catch (_) {
                    return false;
                } finally {
                    cleanup();
                }
            }).finally(() => { refreshPromise = null; });
            return refreshPromise;
        }

        async function executeWithRetry(resource, baseOptions, callerSignal, timeoutMs, maxRetries) {
            for (let attempt = 0; attempt <= maxRetries; attempt++) {
                const { signal, cleanup } = withTimeoutSignal(callerSignal, timeoutMs);
                try {
                    const attemptOpts = Object.assign({}, baseOptions, { signal });
                    const response = await originalFetch(resource, attemptOpts);
                    if (RETRYABLE_STATUSES.has(response.status) && attempt < maxRetries) {
                        const waitMs = computeRetryDelayMs(attempt, response);
                        cleanup();
                        await sleep(waitMs, callerSignal);
                        continue;
                    }
                    cleanup();
                    return response;
                } catch (err) {
                    cleanup();
                    const isCallerAbort = Boolean(callerSignal && callerSignal.aborted);
                    const isTransient = !isCallerAbort && (err.name === 'TypeError' || err.name === 'TimeoutError');
                    if (isTransient && attempt < maxRetries) {
                        const waitMs = computeRetryDelayMs(attempt, null);
                        await sleep(waitMs, callerSignal);
                        continue;
                    }
                    throw err;
                }
            }
            throw new Error('Request failed after retries');
        }

        window.fetch = async function (resource, options = {}) {
            const urlStr = typeof resource === 'string' ? resource : (resource?.url || '');
            const isSameOrigin = isStrictlySameOrigin(urlStr);
            const method = String(options?.method || (typeof resource === 'object' && resource?.method) || 'GET').toUpperCase();
            const timeoutMs = Number(options?.timeoutMs) > 0 ? Number(options.timeoutMs) : DEFAULT_FETCH_TIMEOUT_MS;
            const callerSignal = options?.signal || null;

            if (isSameOrigin) {
                const mergedOptions = Object.assign({}, options);
                delete mergedOptions.timeoutMs;
                delete mergedOptions.retries;
                mergedOptions.method = method;
                if (!mergedOptions.credentials) {
                    mergedOptions.credentials = 'include';
                }

                const headers = normalizeHeaders(mergedOptions.headers);
                if (!headers.has('X-CSRF-Protection')) {
                    headers.set('X-CSRF-Protection', '1');
                }
                const isAuthEndpoint = AUTH_BYPASS_RE.test(urlStr);
                const isApiPath = new URL(urlStr, window.location.origin).pathname.startsWith('/api/');
                // Guarantee UUIDv4 Idempotency-Key on ALL same-origin API mutations (reused across retries)
                if (isApiPath && MUTATING_METHODS.has(method) && !isAuthEndpoint && !headers.has('Idempotency-Key') && !headers.has('X-Idempotency-Key')) {
                    headers.set('Idempotency-Key', generateIdempotencyKey());
                }
                mergedOptions.headers = headers;

                const hasIdempKey = headers.has('Idempotency-Key') || headers.has('X-Idempotency-Key');
                const canRetry = !isAuthEndpoint && !mergedOptions.keepalive && (SAFE_METHODS.has(method) || hasIdempKey);
                const requestedRetries = options?.retries !== undefined ? Number(options.retries) : (canRetry ? 2 : 0);
                const maxRetries = canRetry ? Math.max(0, Math.min(3, requestedRetries)) : 0;

                const response = await executeWithRetry(resource, mergedOptions, callerSignal, timeoutMs, maxRetries);

                if (response.status === 401 && !isAuthEndpoint && !mergedOptions.__retriedAfterRefresh) {
                    const refreshed = await attemptSilentRefresh();
                    if (refreshed) {
                        const retryOpts = Object.assign({}, mergedOptions, { __retriedAfterRefresh: true });
                        return executeWithRetry(resource, retryOpts, callerSignal, timeoutMs, 0);
                    }
                }
                return response;
            }

            const { signal, cleanup } = withTimeoutSignal(callerSignal, timeoutMs);
            try {
                const extOptions = Object.assign({}, options, { signal });
                delete extOptions.timeoutMs;
                delete extOptions.retries;
                return await originalFetch(resource, extOptions);
            } finally {
                cleanup();
            }
        };
        window.__AML_FETCH_PATCHED__ = true;
    }

    // ── 5. High-Level Structured API Client (`window.SentinelApi`) ────────────
    async function parseApiError(response) {
        const correlationId = response.headers.get('X-Correlation-ID') || null;
        const retryAfter = response.headers.get('Retry-After') || null;
        const etag = response.headers.get('ETag') || null;
        let body = null;
        try {
            const ct = response.headers.get('Content-Type') || '';
            if (ct.includes('application/json')) {
                body = await response.json();
            } else {
                const txt = await response.text();
                body = txt ? { detail: txt.slice(0, 300) } : null;
            }
        } catch (_) {
            body = null;
        }
        const detail = (body && (typeof body.detail === 'string' ? body.detail : (body.detail?.message || body.message)))
            || `Request failed (HTTP ${response.status})`;
        return new SentinelApiError(detail, {
            status: response.status,
            code: (body && body.code) || `HTTP_${response.status}`,
            detail,
            correlationId: (body && body.correlation_id) || correlationId,
            errors: (body && body.errors) || null,
            retryAfter,
            etag,
            body
        });
    }

    window.SentinelApi = {
        generateIdempotencyKey,
        parseApiError,

        formatError(err) {
            if (err instanceof SentinelApiError) return err.toUserMessage();
            if (err && err.name === 'AbortError') return 'Request cancelled.';
            return (err && err.message) ? String(err.message) : 'Unexpected network error.';
        },

        async request(url, options = {}) {
            const opts = Object.assign({ credentials: 'include' }, options);
            const headers = new Headers(opts.headers || {});
            if (!headers.has('Accept')) headers.set('Accept', 'application/json');
            if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData) && !(opts.body instanceof Blob) && !(opts.body instanceof URLSearchParams)) {
                if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
                opts.body = JSON.stringify(opts.body);
            }
            if (opts.ifMatch) {
                headers.set('If-Match', opts.ifMatch);
                delete opts.ifMatch;
            }
            if (opts.idempotencyKey) {
                headers.set('Idempotency-Key', opts.idempotencyKey);
                delete opts.idempotencyKey;
            }
            opts.headers = headers;

            const response = await fetch(url, opts);
            if (response.status === 304) {
                return { status: 304, notModified: true, data: null, etag: response.headers.get('ETag'), response };
            }
            if (!response.ok) {
                throw await parseApiError(response);
            }
            const etag = response.headers.get('ETag') || null;
            const replayed = response.headers.get('Idempotency-Replayed') === 'true';
            if (response.status === 204) {
                return { status: 204, notModified: false, data: null, etag, replayed, response };
            }
            const ct = response.headers.get('Content-Type') || '';
            const data = ct.includes('application/json') ? await response.json() : await response.text();
            return { status: response.status, notModified: false, data, etag, replayed, response };
        },

        async get(url, options = {}) {
            const res = await this.request(url, Object.assign({}, options, { method: 'GET' }));
            return res.data;
        },

        async mutate(url, options = {}) {
            const method = String(options.method || 'POST').toUpperCase();
            const idempotencyKey = options.idempotencyKey || generateIdempotencyKey();
            const res = await this.request(url, Object.assign({}, options, { method, idempotencyKey }));
            return res.data;
        }
    };

    // ── 6. Shared Auth Headers & Server-Side Logout ───────────────────────────
    window.getAuthHeaders = function getAuthHeaders() {
        return { 'X-CSRF-Protection': '1' };
    };

    window.logout = async function logout() {
        try {
            await fetch('/api/v1/auth/logout', {
                method: 'POST',
                headers: { 'X-CSRF-Protection': '1' },
                credentials: 'include'
            });
        } catch (e) {
            console.debug('Logout API call failed; clearing local state:', e);
        }
        clearClientSessionState();
        broadcastAuthEvent({ type: 'AUTH_LOGOUT', ts: Date.now() });
        window.location.href = '/login';
    };

    // ── 7. Role-Based Navigation Link Visibility ──────────────────────────────
    window.applyRoleBasedVisibility = function applyRoleBasedVisibility(role) {
        const userRole = (role || localStorage.getItem('role') || '').toUpperCase();
        if (!userRole) return;
        const isSuperAdmin = userRole === 'SUPER_ADMIN' || userRole === 'ADMIN';
        document.querySelectorAll('[data-role]').forEach((el) => {
            const allowed = (el.getAttribute('data-role') || '')
                .split(',')
                .map((r) => r.trim().toUpperCase())
                .filter(Boolean);
            if (!allowed.length) return;
            if (isSuperAdmin || allowed.includes(userRole)) {
                el.style.display = '';
            } else {
                el.style.display = 'none';
            }
        });
    };

    // ── 8. Deduplicated Navbar Identity Hydration ─────────────────────────────
    window.hydrateNavUser = async function hydrateNavUser() {
        try {
            let user = null;
            if (window.SentinelQuery && typeof window.SentinelQuery.fetchJson === 'function') {
                user = await window.SentinelQuery.fetchJson(['auth', 'me'], '/api/v1/auth/me', { staleTime: 60000 });
            } else {
                const res = await fetch('/api/v1/auth/me', { credentials: 'include' });
                if (res.status === 401) {
                    window.location.href = '/login';
                    return null;
                }
                if (!res.ok) return null;
                user = await res.json();
            }
            if (!user) return null;
            if (user.username) {
                localStorage.setItem('username', user.username);
                const navName = document.getElementById('navUsername');
                if (navName) navName.textContent = user.username;
                const avatarBtn = document.getElementById('sentinel-user-avatar');
                if (avatarBtn) {
                    const roleText = user.role ? ` (${user.role})` : '';
                    avatarBtn.setAttribute('title', `Signed in as ${user.username}${roleText}`);
                    avatarBtn.setAttribute('aria-label', `Profile: ${user.username}`);
                }
            }
            if (user.role) {
                localStorage.setItem('role', user.role);
                const navRole = document.getElementById('navRole');
                if (navRole) navRole.textContent = user.role;
                window.applyRoleBasedVisibility(user.role);
            }
            return user;
        } catch (e) {
            if (e && e.status === 401) {
                clearClientSessionState();
                window.location.href = '/login';
                return null;
            }
            console.debug('Navbar user hydration skipped:', e);
            return null;
        }
    };

    // ── 9. Universal Modules Dropdown Controller ──────────────────────────────
    window.toggleSentinelModules = function toggleSentinelModules(event) {
        if (event && event.stopPropagation) event.stopPropagation();
        const menu = document.getElementById('sentinel-modules-menu') || document.getElementById('app-menu-popover');
        const btn = document.getElementById('btn-sentinel-modules') || document.getElementById('btn-app-menu');
        if (!menu) return;
        const isOpen = menu.classList.toggle('show');
        menu.style.display = isOpen ? 'block' : 'none';
        if (btn) btn.setAttribute('aria-expanded', String(isOpen));
        if (isOpen) {
            document.querySelectorAll('.sentinel-notif-popover.open, .sentinel-profile-popover.open')
                .forEach((p) => p.classList.remove('open'));
        }
    };

    document.addEventListener('click', (e) => {
        const menu = document.getElementById('sentinel-modules-menu');
        const btn = document.getElementById('btn-sentinel-modules');
        if (menu && menu.classList.contains('show') && !menu.contains(e.target) && (!btn || !btn.contains(e.target))) {
            menu.classList.remove('show');
            menu.style.display = 'none';
            if (btn) btn.setAttribute('aria-expanded', 'false');
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const menu = document.getElementById('sentinel-modules-menu');
            const btn = document.getElementById('btn-sentinel-modules');
            if (menu && menu.classList.contains('show')) {
                menu.classList.remove('show');
                menu.style.display = 'none';
                if (btn) btn.setAttribute('aria-expanded', 'false');
            }
        }
    });

    document.addEventListener('DOMContentLoaded', () => {
        window.hydrateNavUser();
        const savedUser = localStorage.getItem('username');
        const savedRole = localStorage.getItem('role');
        const avatarBtn = document.getElementById('sentinel-user-avatar');
        if (avatarBtn && savedUser) {
            avatarBtn.setAttribute('title', `Signed in as ${savedUser}${savedRole ? ' (' + savedRole + ')' : ''}`);
        }
        if (!window.__SENTINEL_SHELL_INIT__ && !document.querySelector('script[src*="sentinel-shell.js"]')) {
            const s = document.createElement('script');
            s.src = '/static/sentinel-shell.js?v=20261125-cp1';
            s.defer = true;
            document.head.appendChild(s);
        }
    });
})();
