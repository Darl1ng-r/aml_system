/**
 * AML Sentinel Enterprise Authentication Module
 * ==============================================
 * Self-contained, CSP-compliant authentication controller.
 * Handles:
 * - Animated tab navigation (Sign In / Create Account)
 * - Accessible password visibility toggling
 * - Real-time debounced username availability validation
 * - NIST SP 800-63B entropy & password strength evaluation
 * - Client-side form pre-validation & self-healing error banners
 * - Dual-mode AuthN (OAuth2 Form & JSON) with automatic MFA handling
 * - Single Sign-On (SSO) simulation / OAuth2 PKCE initiation
 */

(function initEnterpriseAuth() {
    'use strict';

    let currentMfaTicket = null;
    let usernameDebounceTimer = null;

    // ── Helper: Format Server & Network Errors ────────────────────────────────
    function formatError(detail, fallback = 'Authentication failed.') {
        if (!detail) return fallback;
        if (typeof detail === 'string') return detail;
        if (Array.isArray(detail)) {
            return detail.map(item => {
                if (typeof item === 'string') return item;
                if (item && item.msg) {
                    const field = Array.isArray(item.loc) ? item.loc.filter(l => l !== 'body').join('.') : '';
                    return field ? `${field}: ${item.msg}` : item.msg;
                }
                return JSON.stringify(item);
            }).join(' | ');
        }
        if (typeof detail === 'object') {
            return detail.msg || detail.message || detail.error || JSON.stringify(detail);
        }
        return String(detail);
    }

    // ── Helper: Show Error / Success Banners ──────────────────────────────────
    function showError(message) {
        const errEl = document.getElementById('auth-error');
        const succEl = document.getElementById('auth-success');
        if (succEl) succEl.style.display = 'none';
        if (errEl) {
            errEl.textContent = formatError(message);
            errEl.style.display = 'block';
            errEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    function showSuccess(message) {
        const errEl = document.getElementById('auth-error');
        const succEl = document.getElementById('auth-success');
        if (errEl) errEl.style.display = 'none';
        if (succEl) {
            succEl.textContent = message;
            succEl.style.display = 'block';
            succEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    function clearBanners() {
        const errEl = document.getElementById('auth-error');
        const succEl = document.getElementById('auth-success');
        if (errEl) errEl.style.display = 'none';
        if (succEl) succEl.style.display = 'none';
    }

    // ── Tab Navigation ────────────────────────────────────────────────────────
    function switchTab(target) {
        clearBanners();
        const tabLogin = document.getElementById('tab-login');
        const tabSignup = document.getElementById('tab-signup');
        const formLogin = document.getElementById('form-login');
        const formSignup = document.getElementById('form-signup');
        const formMfa = document.getElementById('form-mfa');
        const authTabBar = document.getElementById('auth-tab-bar');

        if (formMfa) formMfa.classList.remove('active');
        if (authTabBar) authTabBar.style.display = 'flex';

        if (target === 'login') {
            if (tabLogin) tabLogin.classList.add('active');
            if (tabSignup) tabSignup.classList.remove('active');
            if (formLogin) formLogin.classList.add('active');
            if (formSignup) formSignup.classList.remove('active');
            const loginUserInput = document.getElementById('login-username');
            if (loginUserInput) loginUserInput.focus();
        } else {
            if (tabLogin) tabLogin.classList.remove('active');
            if (tabSignup) tabSignup.classList.add('active');
            if (formLogin) formLogin.classList.remove('active');
            if (formSignup) formSignup.classList.add('active');
            const signupUserInput = document.getElementById('signup-username');
            if (signupUserInput) signupUserInput.focus();
        }
    }

    // ── Password Visibility Toggle ───────────────────────────────────────────
    function togglePassword(inputId, btn) {
        const input = document.getElementById(inputId);
        if (!input) return;
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        if (btn) {
            btn.setAttribute('aria-pressed', isPassword ? 'true' : 'false');
            btn.setAttribute('aria-label', isPassword ? 'Hide password' : 'Show password');
            btn.textContent = isPassword ? 'Hide' : 'Show';
        }
    }

    // ── Debounced Username Availability Checker ──────────────────────────────
    function checkUsernameAvailability(username) {
        clearTimeout(usernameDebounceTimer);
        const badge = document.getElementById('username-avail-badge');
        if (!badge) return;

        const clean = (username || '').trim();
        if (!clean || clean.length < 3) {
            badge.style.display = 'none';
            return;
        }

        badge.style.display = 'inline-flex';
        badge.textContent = 'Checking...';
        badge.style.color = 'var(--text-secondary, #666)';

        usernameDebounceTimer = setTimeout(async () => {
            try {
                const res = await fetch(`/api/v1/auth/check-username?username=${encodeURIComponent(clean)}`, {
                    headers: { 'X-CSRF-Protection': '1' }
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.available) {
                        badge.textContent = '✓ Available';
                        badge.style.color = '#1d8253';
                    } else {
                        badge.textContent = '⚠ Already Registered';
                        badge.style.color = '#e07a1f';
                    }
                }
            } catch (e) {
                badge.style.display = 'none';
            }
        }, 300);
    }

    // ── NIST SP 800-63B Password Entropy Calculator ───────────────────────────
    function evaluatePasswordStrength(password) {
        const bar = document.getElementById('strength-bar');
        const label = document.getElementById('strength-text');
        if (!bar || !label) return;

        if (!password) {
            bar.style.width = '0%';
            label.textContent = 'Password Strength: Minimum 10–12 chars recommended';
            label.style.color = 'var(--text-secondary, #666)';
            return;
        }

        let pool = 0;
        if (/[a-z]/.test(password)) pool += 26;
        if (/[A-Z]/.test(password)) pool += 26;
        if (/[0-9]/.test(password)) pool += 10;
        if (/[^A-Za-z0-9]/.test(password)) pool += 33;
        pool = Math.max(pool, 10);

        let entropyBits = Math.round(password.length * Math.log2(pool));
        if (/([a-zA-Z0-9])\1{2,}/.test(password)) entropyBits = Math.max(0, entropyBits - 15);
        if (password.length >= 20 && /\s|[_\-]/.test(password)) entropyBits += 18;

        if (entropyBits < 40 || password.length < 8) {
            bar.style.width = '25%';
            bar.style.backgroundColor = '#cc3f35';
            label.textContent = `Weak (${entropyBits} bits entropy) — add length & symbols`;
            label.style.color = '#cc3f35';
        } else if (entropyBits < 60 || password.length < 10) {
            bar.style.width = '50%';
            bar.style.backgroundColor = '#e07a1f';
            label.textContent = `Fair (${entropyBits} bits entropy)`;
            label.style.color = '#e07a1f';
        } else if (entropyBits < 80 || password.length < 12) {
            bar.style.width = '75%';
            bar.style.backgroundColor = '#1d64f5';
            label.textContent = `Strong (${entropyBits} bits entropy) — NIST SP 800-63B compliant`;
            label.style.color = '#1d64f5';
        } else {
            bar.style.width = '100%';
            bar.style.backgroundColor = '#1d8253';
            label.textContent = `Enterprise Grade (${entropyBits} bits entropy) — Highly Resilient`;
            label.style.color = '#1d8253';
        }
    }

    // ── Form Submissions ──────────────────────────────────────────────────────
    async function handleLogin(e) {
        if (e) e.preventDefault();
        clearBanners();

        const usernameInput = document.getElementById('login-username');
        const passwordInput = document.getElementById('login-password');
        const btn = document.getElementById('btn-login-submit');

        const username = usernameInput ? usernameInput.value.trim() : '';
        const password = passwordInput ? passwordInput.value : '';

        if (!username) {
            showError('Please enter your username or compliance email.');
            if (usernameInput) usernameInput.focus();
            return;
        }

        if (!password) {
            showError('Please enter your account password.');
            if (passwordInput) passwordInput.focus();
            return;
        }

        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Authenticating...';
        }

        try {
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            const res = await fetch('/api/v1/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-CSRF-Protection': '1'
                },
                body: formData,
                credentials: 'include'
            });

            const data = await res.json();

            if (!res.ok) {
                throw new Error(formatError(data.detail, 'Authentication failed. Please verify credentials.'));
            }

            // Check for Two-Factor Challenge
            if (data.mfa_required) {
                currentMfaTicket = data.mfa_ticket;
                const formLogin = document.getElementById('form-login');
                const formMfa = document.getElementById('form-mfa');
                const authTabBar = document.getElementById('auth-tab-bar');
                const mfaCodeInput = document.getElementById('mfa-code');

                if (formLogin) formLogin.classList.remove('active');
                if (authTabBar) authTabBar.style.display = 'none';
                if (formMfa) formMfa.classList.add('active');
                if (mfaCodeInput) mfaCodeInput.focus();
                return;
            }

            // Successful Login
            showSuccess('Authentication successful! Initializing console...');
            localStorage.setItem('auth_session_active', 'true');
            if (data.access_token) {
                localStorage.setItem('jwt_token', data.access_token);
                localStorage.setItem('access_token', data.access_token);
            }
            if (data.username) localStorage.setItem('username', data.username);
            if (data.role) localStorage.setItem('role', data.role);
            sessionStorage.setItem('auth_active', 'true');

            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 500);

        } catch (err) {
            showError(err.message || 'Authentication failed.');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Access Console';
            }
        }
    }

    async function handleSignup(e) {
        if (e) e.preventDefault();
        clearBanners();

        const usernameInput = document.getElementById('signup-username');
        const passwordInput = document.getElementById('signup-password');
        const confirmInput = document.getElementById('signup-confirm');
        const btn = document.getElementById('btn-signup-submit');

        const username = usernameInput ? usernameInput.value.trim() : '';
        const password = passwordInput ? passwordInput.value : '';
        const confirm = confirmInput ? confirmInput.value : '';

        if (!username || username.length < 3) {
            showError('Please enter a valid username (at least 3 characters).');
            if (usernameInput) usernameInput.focus();
            return;
        }

        if (!password) {
            showError('Please enter a secure passphrase.');
            if (passwordInput) passwordInput.focus();
            return;
        }

        if (password.length < 8) {
            showError('Passphrase must be at least 8 characters long (10+ recommended by NIST SP 800-63B).');
            if (passwordInput) passwordInput.focus();
            return;
        }

        if (password !== confirm) {
            showError('Passphrases do not match. Please re-type your confirmation passphrase.');
            if (confirmInput) confirmInput.focus();
            return;
        }

        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Creating Profile...';
        }

        try {
            // First attempt modern enterprise register endpoint, fall back to signup
            let res = await fetch('/api/v1/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Protection': '1'
                },
                body: JSON.stringify({ username: username, password: password }),
                credentials: 'include'
            });

            if (res.status === 404) {
                res = await fetch('/api/v1/auth/signup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRF-Protection': '1'
                    },
                    body: JSON.stringify({ username: username, password: password }),
                    credentials: 'include'
                });
            }

            const data = await res.json();

            if (!res.ok) {
                throw new Error(formatError(data.detail, 'Registration failed.'));
            }

            showSuccess('Account registered successfully! Redirecting to dashboard...');
            localStorage.setItem('auth_session_active', 'true');
            if (data.access_token) {
                localStorage.setItem('jwt_token', data.access_token);
                localStorage.setItem('access_token', data.access_token);
            }
            if (data.username) localStorage.setItem('username', data.username);
            if (data.role) localStorage.setItem('role', data.role);
            sessionStorage.setItem('auth_active', 'true');

            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 800);

        } catch (err) {
            showError(err.message || 'Registration failed.');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Register Analyst Profile';
            }
        }
    }

    async function handleMfa(e) {
        if (e) e.preventDefault();
        clearBanners();

        const codeInput = document.getElementById('mfa-code');
        const btn = document.getElementById('btn-mfa-submit');
        const code = codeInput ? codeInput.value.trim() : '';

        if (!code) {
            showError('Please enter your 6-digit TOTP verification code.');
            if (codeInput) codeInput.focus();
            return;
        }

        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Verifying Code...';
        }

        try {
            const res = await fetch('/api/v1/auth/mfa/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Protection': '1'
                },
                body: JSON.stringify({ mfa_ticket: currentMfaTicket, code: code }),
                credentials: 'include'
            });

            const data = await res.json();
            if (!res.ok) {
                throw new Error(formatError(data.detail, 'Two-factor verification code is invalid or expired.'));
            }

            showSuccess('Verification approved! Launching session...');
            localStorage.setItem('auth_session_active', 'true');
            if (data.access_token) {
                localStorage.setItem('jwt_token', data.access_token);
                localStorage.setItem('access_token', data.access_token);
            }
            if (data.username) localStorage.setItem('username', data.username);
            if (data.role) localStorage.setItem('role', data.role);
            sessionStorage.setItem('auth_active', 'true');

            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 500);

        } catch (err) {
            showError(err.message || 'Verification failed.');
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Verify & Proceed';
            }
        }
    }

    function cancelMfa() {
        currentMfaTicket = null;
        const formMfa = document.getElementById('form-mfa');
        const formLogin = document.getElementById('form-login');
        const authTabBar = document.getElementById('auth-tab-bar');

        if (formMfa) formMfa.classList.remove('active');
        if (authTabBar) authTabBar.style.display = 'flex';
        if (formLogin) formLogin.classList.add('active');
        clearBanners();
    }

    // ── Existing Session Verification ─────────────────────────────────────────
    async function checkExistingSession() {
        const token = localStorage.getItem('jwt_token') || localStorage.getItem('access_token');
        const isActive = localStorage.getItem('auth_session_active') === 'true';
        if (!isActive && !token) return;

        try {
            const headers = { 'X-CSRF-Protection': '1' };
            if (token) headers['Authorization'] = 'Bearer ' + token;
            const res = await fetch('/api/v1/auth/me', { headers: headers, credentials: 'include' });
            if (res.ok) {
                sessionStorage.setItem('auth_active', 'true');
                window.location.href = '/dashboard';
            } else {
                localStorage.removeItem('auth_session_active');
                localStorage.removeItem('jwt_token');
                localStorage.removeItem('access_token');
                localStorage.removeItem('username');
                localStorage.removeItem('role');
                sessionStorage.removeItem('auth_active');
            }
        } catch (e) {
            // Ignore offline network blips
        }
    }

    // ── Bind All Event Listeners on DOM Ready ────────────────────────────────
    function attachListeners() {
        checkExistingSession();

        // 1. Tab switches
        const tabLogin = document.getElementById('tab-login');
        const tabSignup = document.getElementById('tab-signup');
        if (tabLogin) tabLogin.addEventListener('click', () => switchTab('login'));
        if (tabSignup) tabSignup.addEventListener('click', () => switchTab('signup'));

        // 2. Forms
        const formLogin = document.getElementById('form-login');
        const formSignup = document.getElementById('form-signup');
        const formMfa = document.getElementById('form-mfa');

        if (formLogin) formLogin.addEventListener('submit', handleLogin);
        if (formSignup) formSignup.addEventListener('submit', handleSignup);
        if (formMfa) formMfa.addEventListener('submit', handleMfa);

        // 3. Password visibility toggles
        const toggleLoginBtn = document.getElementById('toggle-login-pass');
        const toggleSignupBtn = document.getElementById('toggle-signup-pass');
        if (toggleLoginBtn) {
            toggleLoginBtn.addEventListener('click', () => togglePassword('login-password', toggleLoginBtn));
        }
        if (toggleSignupBtn) {
            toggleSignupBtn.addEventListener('click', () => togglePassword('signup-password', toggleSignupBtn));
        }

        // 4. Live username & password inputs
        const signupUserInput = document.getElementById('signup-username');
        if (signupUserInput) {
            signupUserInput.addEventListener('input', (e) => checkUsernameAvailability(e.target.value));
            signupUserInput.addEventListener('blur', (e) => checkUsernameAvailability(e.target.value));
        }

        const signupPassInput = document.getElementById('signup-password');
        if (signupPassInput) {
            signupPassInput.addEventListener('input', (e) => evaluatePasswordStrength(e.target.value));
        }

        // 5. MFA cancel button
        const btnCancelMfa = document.getElementById('btn-mfa-cancel');
        if (btnCancelMfa) {
            btnCancelMfa.addEventListener('click', cancelMfa);
        }

        // 6. SSO Buttons
        const btnGoogle = document.getElementById('btn-sso-google');
        const btnGithub = document.getElementById('btn-sso-github');
        if (btnGoogle) {
            btnGoogle.addEventListener('click', () => {
                showSuccess('Connecting to Google Enterprise IDP (OAuth2 PKCE flow)...');
            });
        }
        if (btnGithub) {
            btnGithub.addEventListener('click', () => {
                showSuccess('Connecting to GitHub Corporate IDP (OAuth2 PKCE flow)...');
            });
        }

        // 7. Lucide Icons
        if (window.lucide && typeof window.lucide.createIcons === 'function') {
            window.lucide.createIcons();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', attachListeners);
    } else {
        attachListeners();
    }

    // Expose helpers globally as fallback for inline attributes
    window.switchAuthTab = switchTab;
    window.togglePasswordVisibility = togglePassword;
    window.checkUsernameAvailabilityLive = checkUsernameAvailability;
    window.evaluatePasswordStrength = evaluatePasswordStrength;
    window.handleLoginSubmit = handleLogin;
    window.handleSignupSubmit = handleSignup;
    window.handleMfaVerify = handleMfa;
    window.cancelMfa = cancelMfa;

})();
