import React, { useState, useEffect, useId } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldCheck,
  Lock,
  User,
  Eye,
  EyeOff,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Sparkles,
  ArrowRight,
  KeyRound,
  ExternalLink,
  ShieldAlert,
  Building2
} from 'lucide-react';

export type AuthMode = 'login' | 'register';

export interface EnterpriseAuthProps {
  initialMode?: AuthMode;
  onSuccess?: (user: { username: string; role: string; token?: string }) => void;
  apiBaseUrl?: string;
  enableSso?: boolean;
}

interface PasswordEntropyResult {
  score: number; // 0 to 4
  entropyBits: number;
  label: string;
  color: string;
  checks: {
    length: boolean;
    hasUpper: boolean;
    hasLower: boolean;
    hasNumber: boolean;
    hasSymbol: boolean;
  };
}

export const EnterpriseAuth: React.FC<EnterpriseAuthProps> = ({
  initialMode = 'login',
  onSuccess,
  apiBaseUrl = '',
  enableSso = true,
}) => {
  const [mode, setMode] = useState<AuthMode>(initialMode);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [tenantId, setTenantId] = useState('00000000-0000-0000-0000-000000000001');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Debounced username availability states
  const [isCheckingUsername, setIsCheckingUsername] = useState(false);
  const [usernameAvailable, setUsernameAvailable] = useState<boolean | null>(null);

  const usernameId = useId();
  const passwordId = useId();
  const confirmPasswordId = useId();
  const errorAlertId = useId();

  // ── 1. NIST SP 800-63B Password Entropy Calculation ──────────────────────────
  const calculateEntropy = (pwd: string): PasswordEntropyResult => {
    const checks = {
      length: pwd.length >= 12,
      hasUpper: /[A-Z]/.test(pwd),
      hasLower: /[a-z]/.test(pwd),
      hasNumber: /[0-9]/.test(pwd),
      hasSymbol: /[^A-Za-z0-9]/.test(pwd),
    };

    if (!pwd) {
      return { score: 0, entropyBits: 0, label: 'Empty', color: 'bg-slate-700', checks };
    }

    // Character pool calculation
    let poolSize = 0;
    if (checks.hasLower) poolSize += 26;
    if (checks.hasUpper) poolSize += 26;
    if (checks.hasNumber) poolSize += 10;
    if (checks.hasSymbol) poolSize += 33;
    poolSize = Math.max(poolSize, 10);

    // NIST Shannon entropy estimation: H = L * log2(R)
    let entropyBits = Math.round(pwd.length * Math.log2(poolSize));

    // Deduct repetition penalties
    if (/([a-zA-Z0-9])\1{2,}/.test(pwd)) entropyBits = Math.max(0, entropyBits - 15);

    // Passphrase bonus (longer length with spaces or delimiter separators)
    if (pwd.length >= 20 && /\s|[_\-]/.test(pwd)) entropyBits += 18;

    let score = 0;
    let label = 'Weak';
    let color = 'bg-rose-500';

    if (entropyBits >= 80 && checks.length) {
      score = 4;
      label = 'Enterprise Grade';
      color = 'bg-emerald-500';
    } else if (entropyBits >= 60 && pwd.length >= 10) {
      score = 3;
      label = 'Strong';
      color = 'bg-teal-500';
    } else if (entropyBits >= 40 && pwd.length >= 8) {
      score = 2;
      label = 'Fair';
      color = 'bg-amber-500';
    } else {
      score = 1;
      label = 'Weak';
      color = 'bg-rose-500';
    }

    return { score, entropyBits, label, color, checks };
  };

  const entropy = calculateEntropy(password);

  // ── 2. Debounced Username Availability Check ─────────────────────────────────
  useEffect(() => {
    if (mode !== 'register' || username.trim().length < 3) {
      setUsernameAvailable(null);
      setIsCheckingUsername(false);
      return;
    }

    setIsCheckingUsername(true);
    const handler = setTimeout(async () => {
      try {
        const res = await fetch(
          `${apiBaseUrl}/api/v1/auth/check-username?username=${encodeURIComponent(username.trim())}`,
          { headers: { 'X-CSRF-Protection': '1' } }
        );
        if (res.ok) {
          const data = await res.json();
          setUsernameAvailable(Boolean(data.available));
        } else {
          setUsernameAvailable(null);
        }
      } catch {
        setUsernameAvailable(null);
      } finally {
        setIsCheckingUsername(false);
      }
    }, 400);

    return () => clearTimeout(handler);
  }, [username, mode, apiBaseUrl]);

  // ── 3. Submission Handler (Login / Register) ──────────────────────────────────
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setSuccessMessage(null);

    if (!username.trim() || !password) {
      setErrorMessage('Please provide both username and password.');
      return;
    }

    if (mode === 'register') {
      if (password.length < 10) {
        setErrorMessage('Password must be at least 10 characters per NIST SP 800-63B standards.');
        return;
      }
      if (password !== confirmPassword) {
        setErrorMessage('Passwords do not match.');
        return;
      }
      if (usernameAvailable === false) {
        setErrorMessage('Username is already taken. Please choose another identifier.');
        return;
      }
    }

    setIsLoading(true);

    try {
      if (mode === 'login') {
        const formData = new URLSearchParams();
        formData.append('username', username.trim());
        formData.append('password', password);

        const res = await fetch(`${apiBaseUrl}/api/v1/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRF-Protection': '1',
          },
          body: formData,
          credentials: 'include',
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Invalid credentials or account locked.');
        }

        // Store tokens securely and signal success
        if (typeof window !== 'undefined') {
          sessionStorage.setItem('auth_active', 'true');
          localStorage.setItem('auth_session_active', 'true');
          if (data.access_token) {
            localStorage.setItem('jwt_token', data.access_token);
            localStorage.setItem('access_token', data.access_token);
          }
          localStorage.setItem('username', data.username);
          localStorage.setItem('role', data.role);
        }

        setSuccessMessage(`Welcome back, ${data.username}! Redirecting...`);
        if (onSuccess) {
          onSuccess({ username: data.username, role: data.role, token: data.access_token });
        } else {
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 800);
        }
      } else {
        // Register mode
        const res = await fetch(`${apiBaseUrl}/api/v1/auth/register`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Protection': '1',
          },
          body: JSON.stringify({
            username: username.trim(),
            password: password,
            tenant_id: tenantId,
          }),
          credentials: 'include',
        });

        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || 'Registration failed. Check password entropy or try another username.');
        }

        if (typeof window !== 'undefined') {
          sessionStorage.setItem('auth_active', 'true');
          localStorage.setItem('auth_session_active', 'true');
          if (data.access_token) {
            localStorage.setItem('jwt_token', data.access_token);
            localStorage.setItem('access_token', data.access_token);
          }
          localStorage.setItem('username', data.username);
          localStorage.setItem('role', data.role);
        }

        setSuccessMessage('Account registered and session established! Initializing console...');
        if (onSuccess) {
          onSuccess({ username: data.username, role: data.role, token: data.access_token });
        } else {
          setTimeout(() => {
            window.location.href = '/dashboard';
          }, 900);
        }
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'An unexpected authentication error occurred.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSsoClick = (provider: 'google' | 'github') => {
    setErrorMessage(null);
    setSuccessMessage(`Redirecting to institutional ${provider.toUpperCase()} Identity Provider (PKCE)...`);
    // Redirect or trigger SSO endpoint
    setTimeout(() => {
      window.location.href = `${apiBaseUrl}/api/v1/auth/sso/${provider}`;
    }, 600);
  };

  return (
    <div className="w-full max-w-md mx-auto">
      {/* Container with Glassmorphism & Subtle Institutional Glow */}
      <div className="relative rounded-2xl bg-slate-900/90 border border-slate-800 backdrop-blur-xl shadow-2xl p-6 sm:p-8 text-slate-100 overflow-hidden">
        {/* Ambient Gradient Highlights */}
        <div
          aria-hidden="true"
          className="absolute -top-24 -left-24 w-52 h-52 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none"
        />
        <div
          aria-hidden="true"
          className="absolute -bottom-24 -right-24 w-52 h-52 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none"
        />

        {/* Brand Header */}
        <div className="flex flex-col items-center text-center mb-6">
          <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 mb-3 shadow-inner">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
            AML Sentinel Core
            <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-indigo-950 text-indigo-300 border border-indigo-800">
              NIST 800-63B
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Sign in to access your compliance investigation queue
          </p>
        </div>

        {/* Animated Sliding Tab Bar */}
        <div
          role="tablist"
          aria-label="Authentication mode selection"
          className="relative grid grid-cols-2 p-1 mb-6 rounded-lg bg-slate-800/80 border border-slate-700/60"
        >
          <button
            type="button"
            role="tab"
            id="tab-login"
            aria-selected={mode === 'login'}
            aria-controls="auth-panel"
            onClick={() => {
              setMode('login');
              setErrorMessage(null);
            }}
            className={`relative z-10 py-2 text-xs font-semibold rounded-md transition-colors duration-200 ${
              mode === 'login' ? 'text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            role="tab"
            id="tab-register"
            aria-selected={mode === 'register'}
            aria-controls="auth-panel"
            onClick={() => {
              setMode('register');
              setErrorMessage(null);
            }}
            className={`relative z-10 py-2 text-xs font-semibold rounded-md transition-colors duration-200 ${
              mode === 'register' ? 'text-white' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Create Account
          </button>
          <motion.div
            layout
            transition={{ type: 'spring', stiffness: 500, damping: 38 }}
            className={`absolute top-1 bottom-1 w-[calc(50%-4px)] rounded-md bg-indigo-600 shadow-md ${
              mode === 'login' ? 'left-1' : 'left-[calc(50%+2px)]'
            }`}
          />
        </div>

        {/* Dynamic Alerts Container */}
        <AnimatePresence mode="wait">
          {errorMessage && (
            <motion.div
              id={errorAlertId}
              role="alert"
              aria-live="polite"
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start gap-2.5"
            >
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
              <div className="flex-1 leading-relaxed">{errorMessage}</div>
            </motion.div>
          )}

          {successMessage && (
            <motion.div
              role="status"
              aria-live="polite"
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -8 }}
              className="mb-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-start gap-2.5"
            >
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
              <div className="flex-1 leading-relaxed">{successMessage}</div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Main Form */}
        <form
          id="auth-panel"
          role="tabpanel"
          aria-labelledby={mode === 'login' ? 'tab-login' : 'tab-register'}
          onSubmit={handleSubmit}
          noValidate
          className="space-y-4"
        >
          {/* Username / Officer ID */}
          <div>
            <div className="flex justify-between items-center mb-1.5">
              <label htmlFor={usernameId} className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-slate-400" />
                Officer ID / Email
              </label>
              {mode === 'register' && (
                <span className="text-[11px] flex items-center gap-1">
                  {isCheckingUsername && (
                    <span className="text-slate-400 flex items-center gap-1">
                      <RefreshCw className="w-3 h-3 animate-spin" /> checking...
                    </span>
                  )}
                  {!isCheckingUsername && usernameAvailable === true && (
                    <span className="text-emerald-400 font-medium flex items-center gap-0.5">
                      <CheckCircle2 className="w-3 h-3" /> available
                    </span>
                  )}
                  {!isCheckingUsername && usernameAvailable === false && (
                    <span className="text-amber-400 font-medium flex items-center gap-0.5">
                      <ShieldAlert className="w-3 h-3" /> registered
                    </span>
                  )}
                </span>
              )}
            </div>
            <div className="relative">
              <input
                id={usernameId}
                name="username"
                type="text"
                required
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="compliance_admin"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-800/90 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <div className="flex justify-between items-center mb-1.5">
              <label htmlFor={passwordId} className="text-xs font-medium text-slate-300 flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-slate-400" />
                {mode === 'register' ? 'Create Passphrase (12+ characters)' : 'Passphrase'}
              </label>
              {mode === 'login' && (
                <a
                  href="#forgot"
                  onClick={(e) => {
                    e.preventDefault();
                    setErrorMessage('Please contact your Lead Compliance Administrator to initiate credential recovery.');
                  }}
                  className="text-[11px] text-indigo-400 hover:text-indigo-300 transition"
                >
                  Forgot passphrase?
                </a>
              )}
            </div>
            <div className="relative">
              <input
                id={passwordId}
                name="password"
                type={showPassword ? 'text' : 'password'}
                required
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-3.5 pr-10 py-2.5 rounded-lg bg-slate-800/90 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
                aria-pressed={showPassword}
                className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200 transition focus:outline-none"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>

            {/* NIST SP 800-63B Entropy Meter (Sign-Up Mode) */}
            {mode === 'register' && (
              <div className="mt-3 p-3 rounded-lg bg-slate-800/60 border border-slate-700/60 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <span className="text-slate-400 flex items-center gap-1">
                    <Sparkles className="w-3.5 h-3.5 text-indigo-400" /> Entropy Strength:
                  </span>
                  <span className="font-semibold text-slate-200">
                    {entropy.label} ({entropy.entropyBits} bits)
                  </span>
                </div>
                {/* 4-Segment Progress Bar */}
                <div className="grid grid-cols-4 gap-1.5 h-1.5">
                  {[1, 2, 3, 4].map((step) => (
                    <div
                      key={step}
                      className={`h-full rounded-full transition-colors duration-300 ${
                        entropy.score >= step ? entropy.color : 'bg-slate-700'
                      }`}
                    />
                  ))}
                </div>
                {/* Positive Requirement Checkmarks */}
                <div className="grid grid-cols-2 gap-1.5 pt-1 text-[11px] text-slate-400">
                  <div className={`flex items-center gap-1 ${entropy.checks.length ? 'text-emerald-400' : ''}`}>
                    <CheckCircle2 className="w-3 h-3" /> 12+ characters
                  </div>
                  <div className={`flex items-center gap-1 ${entropy.checks.hasUpper && entropy.checks.hasLower ? 'text-emerald-400' : ''}`}>
                    <CheckCircle2 className="w-3 h-3" /> Mixed case letters
                  </div>
                  <div className={`flex items-center gap-1 ${entropy.checks.hasNumber ? 'text-emerald-400' : ''}`}>
                    <CheckCircle2 className="w-3 h-3" /> Numbers
                  </div>
                  <div className={`flex items-center gap-1 ${entropy.checks.hasSymbol ? 'text-emerald-400' : ''}`}>
                    <CheckCircle2 className="w-3 h-3" /> Special symbols
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Confirm Password (Sign-Up Mode) */}
          {mode === 'register' && (
            <div>
              <label htmlFor={confirmPasswordId} className="block text-xs font-medium text-slate-300 mb-1.5">
                Confirm Passphrase
              </label>
              <input
                id={confirmPasswordId}
                name="confirmPassword"
                type={showPassword ? 'text' : 'password'}
                required
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-800/90 border border-slate-700 text-white placeholder-slate-500 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent transition"
              />
            </div>
          )}

          {/* Institutional Tenant Identifier */}
          {mode === 'register' && (
            <div>
              <label className="text-xs font-medium text-slate-300 mb-1.5 flex items-center gap-1.5">
                <Building2 className="w-3.5 h-3.5 text-slate-400" />
                Assigned Tenant Partition
              </label>
              <input
                type="text"
                disabled
                value={tenantId}
                className="w-full px-3.5 py-2 rounded-lg bg-slate-800/40 border border-slate-700/50 text-slate-400 text-xs font-mono cursor-not-allowed"
              />
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isLoading}
            className="w-full py-2.5 px-4 mt-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white font-medium text-sm flex items-center justify-center gap-2 transition duration-150 shadow-lg shadow-indigo-600/20 disabled:opacity-60 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:ring-offset-2 focus:ring-offset-slate-900"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Authenticating with Argon2id...</span>
              </>
            ) : mode === 'login' ? (
              <>
                <span>Access Cockpit</span>
                <ArrowRight className="w-4 h-4" />
              </>
            ) : (
              <>
                <span>Register Officer Profile</span>
                <KeyRound className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* SSO / Institutional Identity Providers */}
        {enableSso && (
          <div className="mt-6">
            <div className="relative flex items-center justify-center mb-4">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-slate-800" />
              </div>
              <span className="relative px-2 bg-slate-900 text-[11px] text-slate-500 uppercase tracking-wider">
                Or sign in with your enterprise provider
              </span>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => handleSsoClick('google')}
                className="flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700 text-xs font-medium text-slate-300 hover:text-white transition"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24">
                  <path
                    fill="currentColor"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                Google SSO
              </button>
              <button
                type="button"
                onClick={() => handleSsoClick('github')}
                className="flex items-center justify-center gap-2 py-2 px-3 rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700 text-xs font-medium text-slate-300 hover:text-white transition"
              >
                <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
                  <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
                </svg>
                GitHub Corp
              </button>
            </div>
          </div>
        )}

        {/* Security Compliance Footer */}
        <div className="mt-6 pt-4 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-500">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-emerald-500" /> AES-256 / Argon2id Enforced
          </span>
          <span className="flex items-center gap-1">
            FIPS 140-3 &amp; OWASP ASVS <ExternalLink className="w-2.5 h-2.5" />
          </span>
        </div>
      </div>
    </div>
  );
};

export default EnterpriseAuth;
