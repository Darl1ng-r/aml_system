/**
 * Shared Lightweight AML API Client & Session Helper
 * ==================================================
 * Loaded by secondary pages instead of full dashboard app.js so every page gets:
 *  1. Automatic `credentials: 'include'` + `X-CSRF-Protection: 1` on same-origin fetch()
 *  2. Real server-side session revocation on logout() (POST /api/v1/auth/logout)
 *  3. Live navbar user/role hydration via GET /api/v1/auth/me + [data-role] nav gating
 */
(function () {
    'use strict';

    // 0. Global XSS Defense-in-Depth Helpers (Wave 1 Security Hardening)
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

    // 1. Global same-origin fetch wrapper for HttpOnly cookie auth, CSRF, timeout, and single-flight 401 refresh
    if (!window.__AML_FETCH_PATCHED__) {
        const originalFetch = window.fetch.bind(window);
        const DEFAULT_FETCH_TIMEOUT_MS = 20000;
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

        async function attemptSilentRefresh() {
            if (!refreshPromise) {
                const { signal, cleanup } = withTimeoutSignal(null, 10000);
                refreshPromise = originalFetch('/api/v1/auth/refresh', {
                    method: 'POST',
                    headers: {
                        'X-CSRF-Protection': '1',
                        'X-Client-Mode': 'browser'
                    },
                    credentials: 'include',
                    signal
                })
                    .then((r) => r.ok)
                    .catch(() => false)
                    .finally(() => { cleanup(); refreshPromise = null; });
            }
            return refreshPromise;
        }

        window.fetch = async function (resource, options = {}) {
            const urlStr = typeof resource === 'string' ? resource : (resource?.url || '');
            const isSameOrigin = isStrictlySameOrigin(urlStr);
            const timeoutMs = Number(options?.timeoutMs) > 0 ? Number(options.timeoutMs) : DEFAULT_FETCH_TIMEOUT_MS;
            const { signal, cleanup } = withTimeoutSignal(options?.signal || null, timeoutMs);

            if (isSameOrigin) {
                const mergedOptions = Object.assign({}, options, { signal });
                delete mergedOptions.timeoutMs;
                if (!mergedOptions.credentials) {
                    mergedOptions.credentials = 'include';
                }
                if (mergedOptions.headers instanceof Headers) {
                    if (!mergedOptions.headers.has('X-CSRF-Protection')) {
                        mergedOptions.headers.set('X-CSRF-Protection', '1');
                    }
                } else {
                    mergedOptions.headers = Object.assign(
                        { 'X-CSRF-Protection': '1' },
                        mergedOptions.headers || {}
                    );
                }
                try {
                    const response = await originalFetch(resource, mergedOptions);
                    const isAuthEndpoint = /\/api\/v1\/auth\/(login|refresh|logout|register|signup)/.test(urlStr);
                    if (response.status === 401 && !isAuthEndpoint && !mergedOptions.__retriedAfterRefresh) {
                        const refreshed = await attemptSilentRefresh();
                        if (refreshed) {
                            const retryTimeout = withTimeoutSignal(options?.signal || null, timeoutMs);
                            try {
                                const retryOpts = Object.assign({}, mergedOptions, {
                                    __retriedAfterRefresh: true,
                                    signal: retryTimeout.signal
                                });
                                return await originalFetch(resource, retryOpts);
                            } finally {
                                retryTimeout.cleanup();
                            }
                        }
                    }
                    return response;
                } finally {
                    cleanup();
                }
            }

            try {
                const extOptions = Object.assign({}, options, { signal });
                delete extOptions.timeoutMs;
                return await originalFetch(resource, extOptions);
            } finally {
                cleanup();
            }
        };
        window.__AML_FETCH_PATCHED__ = true;
    }

    // 2. Shared auth headers helper (relies exclusively on HttpOnly session cookies + CSRF header)
    window.getAuthHeaders = function getAuthHeaders() {
        return { 'X-CSRF-Protection': '1' };
    };

    // 3. Real server-side logout (revokes HttpOnly session cookies via backend)
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
        localStorage.removeItem('jwt_token');
        localStorage.removeItem('access_token');
        localStorage.removeItem('username');
        localStorage.removeItem('role');
        localStorage.removeItem('auth_session_active');
        try { sessionStorage.clear(); } catch (_) { /* ignore */ }
        window.location.href = '/login';
    };

    // 4. Role-based nav link visibility
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

    // 5. Hydrate navbar identity from live /api/v1/auth/me
    window.hydrateNavUser = async function hydrateNavUser() {
        try {
            const res = await fetch('/api/v1/auth/me', { credentials: 'include' });
            if (res.status === 401) {
                window.location.href = '/login';
                return null;
            }
            if (!res.ok) return null;
            const user = await res.json();
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
            console.debug('Navbar user hydration skipped:', e);
            return null;
        }
    };

    // 6. Universal Modules Dropdown Controller across all 14 workspace pages
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
        // Fallback auto-loader if a page did not include sentinel-shell.js directly in <head>
        if (!window.__SENTINEL_SHELL_INIT__ && !document.querySelector('script[src*="sentinel-shell.js"]')) {
            const s = document.createElement('script');
            s.src = '/static/sentinel-shell.js?v=20261124-u2';
            s.defer = true;
            document.head.appendChild(s);
        }
    });
})();
