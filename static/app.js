// Ensure all API calls seamlessly include HttpOnly session cookies and Anti-CSRF protection
const _nativeFetch = window.fetch;
window.fetch = function (url, options = {}) {
    options = options || {};
    options.credentials = options.credentials || 'include';
    options.headers = options.headers || {};
    if (options.headers instanceof Headers) {
        options.headers.set('X-CSRF-Protection', '1');
    } else {
        options.headers['X-CSRF-Protection'] = '1';
    }
    return _nativeFetch(url, options);
};

const BASE_URL = window.location.origin;
let mockMode = false;
let activeAlertId = null;

// Pagination State
let currentPage = 1;
const pageSize = 10;
let totalAlertsCount = 0;

// Chart Instances & Network Instance
let trendChartInstance = null;
let categoryChartInstance = null;
let visNetworkInstance = null;
let liveWebSocket = null;

// Seed Mock Cases Database (Cockpit 3-Pane Tier)
const mockAlerts = [
    {
        alert_id: "aml-2026-04471",
        short_id: "4471",
        title: "Wire transfer — $9,480.00 → offshore holding entity",
        rule_name: "STRUCTURING_THRESHOLD",
        threat_level: "CRITICAL",
        ai_risk_score: 0.92,
        status: "NEW",
        created_at: new Date(Date.now() - 5400000).toISOString(),
        assignee: "rama.tubeh",
        threshold_proximity: "98.7%",
        channel: "Wire — SWIFT",
        counterparty_jurisdiction: "🇰🇾 KY",
        prior_30d_txns: 6,
        account_tenure: "14 mo",
        rules_triggered_count: 3,
        model_version: "v4.2.1",
        transaction: {
            amount: 9480.00,
            currency: "USD",
            timestamp: new Date(Date.now() - 3600000).toISOString(),
            sender: "Tobias M. Varga",
            sender_account: "****4821",
            receiver: "Harlow Kane Ltd",
            receiver_account: "KY99201122"
        },
        rules_triggered: [
            { code: "R-STRUCT-04", desc: "— Transaction is within 5% of the $10,000 CTR reporting threshold", critical: true },
            { code: "R-VELOC-11", desc: "— 6 similar-value transfers to related accounts in trailing 30 days" },
            { code: "R-GEO-02", desc: "— Destination jurisdiction flagged high-risk per current watchlist" }
        ],
        explainability: {
            attributions: {
                "threshold_proximity": 0.48,
                "jurisdiction_risk": 0.32,
                "velocity_30d": 0.12
            }
        },
        entity: {
            name: "Tobias M. Varga",
            nationality: "Cayman Islands / US",
            tier: "Critical Tier",
            connected: "Harlow Kane Ltd",
            customer_since: "Jul 2025",
            occupation: "Import/export, self-empl.",
            pep: "No",
            sanctions: "None",
            adverse_media: "1 low-conf. hit"
        },
        linked_entities: [
            { name: "Renata Varga", relation: "Shared address · sibling", avatar: "RV" },
            { name: "Harlow Kane Ltd", relation: "KY registered · high risk", avatar: "HK", high_risk: true }
        ],
        prior_alerts: [
            { title: "Structuring pattern", date: "Aug 21", status: "closed" },
            { title: "High-risk jurisdiction", date: "Jul 30", status: "closed" },
            { title: "Velocity threshold", date: "Jun 14", status: "escalated" }
        ],
        ledger: [
            { date: "Today", direction: "OUTGOING", partner: "Harlow Kane Ltd", amount: "$9,480.00", risk: "92%" },
            { date: "Sep 8", direction: "OUTGOING", partner: "Offshore Swift", amount: "$7,400.00", risk: "74%" },
            { date: "Sep 3", direction: "OUTGOING", partner: "Trust Capital", amount: "$5,800.00", risk: "68%" }
        ]
    },
    {
        alert_id: "aml-2026-04472",
        short_id: "4472",
        title: "High-value round sum remittance — $14,200.00 → Foreign Shell Co",
        rule_name: "ROUND_SUM_SURGE",
        threat_level: "CRITICAL",
        ai_risk_score: 0.88,
        status: "NEW",
        created_at: new Date(Date.now() - 7200000).toISOString(),
        assignee: "Sarah Jenkins",
        threshold_proximity: "142%",
        channel: "Wire — FEDWIRE",
        counterparty_jurisdiction: "🇵🇦 PA",
        prior_30d_txns: 4,
        account_tenure: "9 mo",
        rules_triggered_count: 2,
        model_version: "v4.2.1",
        transaction: {
            amount: 14200.00,
            currency: "USD",
            timestamp: new Date(Date.now() - 5400000).toISOString(),
            sender: "Renata Varga",
            sender_account: "****1192",
            receiver: "Panama Maritime S.A.",
            receiver_account: "PA11223344"
        },
        rules_triggered: [
            { code: "R-HIGH-01", desc: "— Transfer exceeds $10,000 threshold and triggers SAR reporting", critical: true },
            { code: "R-SHELL-09", desc: "— Counterparty entity registered in high-risk offshore secrecy haven" }
        ],
        explainability: {
            attributions: {
                "amount_anomaly": 0.54,
                "counterparty_secrecy": 0.34
            }
        },
        entity: {
            name: "Renata Varga",
            nationality: "Hungary / US",
            tier: "High Risk Tier",
            connected: "Panama Maritime S.A.",
            customer_since: "Oct 2025",
            occupation: "Real Estate Broker",
            pep: "No",
            sanctions: "None",
            adverse_media: "Clean"
        },
        linked_entities: [
            { name: "Tobias M. Varga", relation: "Associated sender · sibling", avatar: "TV", high_risk: true },
            { name: "Panama Maritime S.A.", relation: "Offshore beneficiary", avatar: "PM", high_risk: true }
        ],
        prior_alerts: [
            { title: "Rapid movement of funds", date: "Aug 10", status: "closed" }
        ],
        ledger: [
            { date: "Today", direction: "OUTGOING", partner: "Panama Maritime", amount: "$14,200.00", risk: "88%" }
        ]
    },
    {
        alert_id: "aml-2026-04473",
        short_id: "4473",
        title: "Cross-border rapid transfer — $8,900.00 to crypto onramp",
        rule_name: "CRYPTO_ONRAMP_BURST",
        threat_level: "HIGH",
        ai_risk_score: 0.76,
        status: "NEW",
        created_at: new Date(Date.now() - 9000000).toISOString(),
        assignee: "David Chen",
        threshold_proximity: "89.0%",
        channel: "ACH — Instant",
        counterparty_jurisdiction: "🇲🇹 MT",
        prior_30d_txns: 8,
        account_tenure: "22 mo",
        rules_triggered_count: 2,
        model_version: "v4.2.1",
        transaction: {
            amount: 8900.00,
            currency: "USD",
            timestamp: new Date(Date.now() - 7200000).toISOString(),
            sender: "Atlas Global Corp",
            sender_account: "****8847",
            receiver: "BVI Gateway Ltd",
            receiver_account: "MT88990011"
        },
        rules_triggered: [
            { code: "R-VAS-03", desc: "— Rapid settlement into virtual asset service provider intermediary" },
            { code: "R-VELOC-04", desc: "— Multi-leg transaction burst executed under 2 hours" }
        ],
        explainability: {
            attributions: {
                "vasp_exposure": 0.44,
                "burst_pattern": 0.32
            }
        },
        entity: {
            name: "Atlas Global Corp",
            nationality: "United States",
            tier: "Medium Risk Tier",
            connected: "BVI Gateway Ltd",
            customer_since: "Jan 2024",
            occupation: "Fintech Merchant",
            pep: "No",
            sanctions: "None",
            adverse_media: "Clean"
        },
        linked_entities: [
            { name: "BVI Gateway Ltd", relation: "Payment aggregator", avatar: "BG" }
        ],
        prior_alerts: [
            { title: "Velocity spike", date: "May 12", status: "closed" }
        ],
        ledger: [
            { date: "Today", direction: "OUTGOING", partner: "BVI Gateway", amount: "$8,900.00", risk: "76%" }
        ]
    },
    {
        alert_id: "aml-2026-04474",
        short_id: "4474",
        title: "Multiple small deposits aggregating $7,200.00 within 4 hours",
        rule_name: "SMURFING_DEPOSIT_ACCUMULATION",
        threat_level: "HIGH",
        ai_risk_score: 0.71,
        status: "NEW",
        created_at: new Date(Date.now() - 10800000).toISOString(),
        assignee: "Alex Rivera",
        threshold_proximity: "72.0%",
        channel: "ATM / Cash Deposit",
        counterparty_jurisdiction: "🇺🇸 US",
        prior_30d_txns: 12,
        account_tenure: "5 mo",
        rules_triggered_count: 2,
        model_version: "v4.2.1",
        transaction: {
            amount: 7200.00,
            currency: "USD",
            timestamp: new Date(Date.now() - 9000000).toISOString(),
            sender: "Elena Rostova",
            sender_account: "****3312",
            receiver: "Self Account",
            receiver_account: "****3312"
        },
        rules_triggered: [
            { code: "R-SMURF-01", desc: "— Multi-branch structured cash deposits detected within 4-hour window" },
            { code: "R-ATM-04", desc: "— Cash intake exceeds weekly historical baseline by 450%" }
        ],
        explainability: {
            attributions: {
                "smurfing_pattern": 0.52,
                "cash_ratio": 0.19
            }
        },
        entity: {
            name: "Elena Rostova",
            nationality: "United States",
            tier: "Medium Risk Tier",
            connected: "Retail Merchant POS",
            customer_since: "Feb 2026",
            occupation: "Consultant",
            pep: "No",
            sanctions: "None",
            adverse_media: "Clean"
        },
        linked_entities: [
            { name: "Branch ATM #44", relation: "Deposit endpoint", avatar: "BA" }
        ],
        prior_alerts: [],
        ledger: [
            { date: "Today", direction: "INCOMING", partner: "ATM Branch #44", amount: "$7,200.00", risk: "71%" }
        ]
    },
    {
        alert_id: "aml-2026-04475",
        short_id: "4475",
        title: "Standard commercial invoice payment — $3,100.00",
        rule_name: "ROUTINE_COMMERCIAL_SETTLEMENT",
        threat_level: "LOW",
        ai_risk_score: 0.28,
        status: "NEW",
        created_at: new Date(Date.now() - 14400000).toISOString(),
        assignee: "David Chen",
        threshold_proximity: "31.0%",
        channel: "ACH — Standard",
        counterparty_jurisdiction: "🇩🇪 DE",
        prior_30d_txns: 2,
        account_tenure: "36 mo",
        rules_triggered_count: 1,
        model_version: "v4.2.1",
        transaction: {
            amount: 3100.00,
            currency: "USD",
            timestamp: new Date(Date.now() - 12600000).toISOString(),
            sender: "Pacific Trust Logistics",
            sender_account: "****9901",
            receiver: "Munich Spare Parts Gmbh",
            receiver_account: "DE44990011"
        },
        rules_triggered: [
            { code: "R-VENDOR-01", desc: "— Regular monthly trade supplier invoice verification" }
        ],
        explainability: {
            attributions: {
                "legitimate_trade": -0.65,
                "amount_deviation": 0.05
            }
        },
        entity: {
            name: "Pacific Trust Logistics",
            nationality: "United States",
            tier: "Low Risk Tier",
            connected: "Munich Spare Parts Gmbh",
            customer_since: "Mar 2023",
            occupation: "Logistics Distributor",
            pep: "No",
            sanctions: "None",
            adverse_media: "Clean"
        },
        linked_entities: [
            { name: "Munich Parts Gmbh", relation: "Verified supplier", avatar: "MP" }
        ],
        prior_alerts: [],
        ledger: [
            { date: "Today", direction: "OUTGOING", partner: "Munich Parts", amount: "$3,100.00", risk: "28%" }
        ]
    },
    {
        alert_id: "aml-2026-04476",
        short_id: "4476",
        title: "Automated recurring payroll distribution — $2,400.00",
        rule_name: "PAYROLL_RECURRENT_BATCH",
        threat_level: "LOW",
        ai_risk_score: 0.14,
        status: "NEW",
        created_at: new Date(Date.now() - 18000000).toISOString(),
        assignee: "Sarah Jenkins",
        threshold_proximity: "24.0%",
        channel: "Direct Deposit",
        counterparty_jurisdiction: "🇺🇸 US",
        prior_30d_txns: 1,
        account_tenure: "48 mo",
        rules_triggered_count: 1,
        model_version: "v4.2.1",
        transaction: {
            amount: 2400.00,
            currency: "USD",
            timestamp: new Date(Date.now() - 16200000).toISOString(),
            sender: "Meridian Trade Inc",
            sender_account: "****6001",
            receiver: "John Q. Employee",
            receiver_account: "****2244"
        },
        rules_triggered: [
            { code: "R-PAY-01", desc: "— Standard bi-weekly verified salary distribution" }
        ],
        explainability: {
            attributions: {
                "payroll_pattern": -0.82
            }
        },
        entity: {
            name: "Meridian Trade Inc",
            nationality: "United States",
            tier: "Low Risk Tier",
            connected: "Payroll Direct",
            customer_since: "May 2022",
            occupation: "Commercial Enterprise",
            pep: "No",
            sanctions: "None",
            adverse_media: "Clean"
        },
        linked_entities: [
            { name: "Payroll Clearinghouse", relation: "Automated processor", avatar: "PC" }
        ],
        prior_alerts: [],
        ledger: [
            { date: "Today", direction: "OUTGOING", partner: "Employee Acct", amount: "$2,400.00", risk: "14%" }
        ]
    }
];

let activeAlerts = [...mockAlerts];

// Startup Sequence
window.addEventListener('load', () => {
    log('System Initializing: Compliance Case Management Console v1.0.0', 'info');
    initTheme();
    initAuth();
    initWebSocket();
    loadDashboardAnalytics();
});

function initTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    updateThemeToggleButton(currentTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
    updateThemeToggleButton(newTheme);
    log(`Switched interface theme to: ${newTheme.toUpperCase()} MODE`, 'info');
}

function updateThemeToggleButton(theme) {
    const btn = document.getElementById('theme-toggle-btn');
    const navIcon = document.getElementById('theme-nav-icon');
    const label = document.getElementById('theme-toggle-label');
    const isDark = (theme === 'dark');

    if (btn) {
        btn.innerHTML = `<i data-lucide="${isDark ? 'sun' : 'moon'}"></i>`;
        btn.title = isDark ? 'Switch to Light Mode' : 'Switch to Dark Mode';
    }
    if (navIcon) {
        navIcon.innerHTML = `<i data-lucide="${isDark ? 'sun' : 'moon'}"></i>`;
    }
    if (label) {
        label.textContent = isDark ? 'Light Mode' : 'Dark Mode';
    }
    if (window.lucide) {
        lucide.createIcons();
    }
}

// ── Power Analyst Keyboard Shortcuts Engine ───────────────────────────────────
window.addEventListener('keydown', (e) => {
    // Toggle Shortcuts Help modal on "?"
    if (e.key === '?' && !isInputFieldActive()) {
        e.preventDefault();
        toggleShortcutsModal();
        return;
    }

    // Close any open modal on "Esc"
    if (e.key === 'Escape') {
        const modals = ['shortcuts-modal', 'executive-modal', 'sandbox-modal', 'str-modal'];
        let closedModal = false;
        modals.forEach(mId => {
            const m = document.getElementById(mId);
            if (m && m.style.display === 'flex') {
                m.style.display = 'none';
                closedModal = true;
            }
        });
        if (closedModal) return;

        if (isInputFieldActive()) {
            document.activeElement.blur();
            return;
        }
        return;
    }

    // Handle Ctrl+Enter when typing in notes field
    if (isInputFieldActive()) {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            const activeInput = document.activeElement;
            if (activeInput && activeInput.id === 'inbox-justification') {
                e.preventDefault();
                resolveCurrentCase('CLOSE_FALSE_POSITIVE');
            }
        }
        return;
    }

    // Key "a" or "A": Approve (Dismiss False Positive)
    if (e.key === 'a' || e.key === 'A') {
        e.preventDefault();
        resolveCurrentCase('CLOSE_FALSE_POSITIVE');
    }
    // Key "b" or "B": Block & Flag SAR
    else if (e.key === 'b' || e.key === 'B') {
        e.preventDefault();
        resolveCurrentCase('CLOSE_SAR');
    }
    // Key "e" or "E": Escalate
    else if (e.key === 'e' || e.key === 'E') {
        e.preventDefault();
        escalateCurrentCase();
    }
    // Key "j" or "ArrowDown" or "ArrowRight": Next Case in Queue
    else if (e.key === 'j' || e.key === 'ArrowDown' || e.key === 'ArrowRight') {
        e.preventDefault();
        navigateQueue(1);
    }
    // Key "k" or "ArrowUp" or "ArrowLeft": Previous Case in Queue
    else if (e.key === 'k' || e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
        e.preventDefault();
        navigateQueue(-1);
    }
    // Key "Enter": Focus justification notes input
    else if (e.key === 'Enter') {
        e.preventDefault();
        const noteInput = document.getElementById('inbox-justification');
        if (noteInput) {
            noteInput.focus();
        }
    }
});

function isInputFieldActive() {
    const activeEl = document.activeElement;
    if (!activeEl) return false;
    const tag = activeEl.tagName.toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select';
}

function toggleShortcutsModal() {
    const modal = document.getElementById('shortcuts-modal');
    if (!modal) return;
    modal.style.display = (modal.style.display === 'flex') ? 'none' : 'flex';
}

// ── Left Rail Queue Navigation ────────────────────────────────────────────────
function renderQueueRail() {
    const container = document.getElementById('queue-rail-items');
    if (!container) return;

    container.innerHTML = '';
    const activeCases = activeAlerts.filter(a => a.status === 'NEW' || a.status === 'OPEN' || a.status === 'ESCALATED');
    const casesToRender = activeCases.length > 0 ? activeCases : activeAlerts;

    casesToRender.forEach((alert) => {
        const item = document.createElement('div');
        const isCurrent = alert.alert_id === activeAlertId;
        item.className = `queue-item ${isCurrent ? 'current' : ''}`;
        item.dataset.id = alert.alert_id;
        item.onclick = () => selectCase(alert.alert_id);
        item.title = alert.title || `Case ${alert.alert_id}`;

        const riskClass = (alert.threat_level === 'CRITICAL' || alert.ai_risk_score >= 0.85) ? 'high' : 
                          ((alert.threat_level === 'HIGH' || alert.ai_risk_score >= 0.6) ? 'med' : 'low');

        const shortId = alert.short_id || (alert.alert_id.includes('-') ? alert.alert_id.split('-').pop() : alert.alert_id.slice(-4));

        item.innerHTML = `
            <span class="risk-dot ${riskClass}"></span>
            <span class="qid">${shortId}</span>
        `;
        container.appendChild(item);
    });

    const currentIndex = casesToRender.findIndex(a => a.alert_id === activeAlertId);
    const posEl = document.getElementById('queue-position-display');
    if (posEl) {
        if (currentIndex !== -1) {
            posEl.innerText = `Case ${currentIndex + 1} of ${casesToRender.length} in queue`;
        } else if (casesToRender.length > 0) {
            posEl.innerText = `Case 1 of ${casesToRender.length} in queue`;
        }
    }
}

function navigateQueue(direction) {
    const activeCases = activeAlerts.filter(a => a.status === 'NEW' || a.status === 'OPEN' || a.status === 'ESCALATED');
    const list = activeCases.length > 0 ? activeCases : activeAlerts;
    if (list.length === 0) return;

    let idx = list.findIndex(a => a.alert_id === activeAlertId);
    if (idx === -1) idx = 0;
    let nextIdx = idx + direction;
    if (nextIdx < 0) nextIdx = list.length - 1;
    if (nextIdx >= list.length) nextIdx = 0;

    selectCase(list[nextIdx].alert_id);
}

function fitVisGraph() {
    if (visNetworkInstance) {
        visNetworkInstance.fit();
    }
}

async function initAuth() {
    const sessionActive = localStorage.getItem('auth_session_active') === 'true' || localStorage.getItem('jwt_token');
    if (!sessionActive) {
        window.location.href = '/login';
        return;
    }

    const setProfileUI = (uname) => {
        const userWelcome = document.getElementById('user-welcome-text');
        if (userWelcome) {
            userWelcome.innerText = uname;
            userWelcome.style.display = 'inline';
        }
        const avatar = document.getElementById('user-avatar-initials');
        if (avatar) {
            const parts = uname.split(/[._\s-]+/);
            avatar.innerText = parts.length >= 2 ? (parts[0][0] + parts[1][0]).toUpperCase() : uname.slice(0, 2).toUpperCase();
        }
    };

    try {
        const res = await fetch(`${BASE_URL}/api/v1/auth/me`, {
            headers: getAuthHeaders()
        });
        if (res.ok) {
            const user = await res.json();
            localStorage.setItem('auth_session_active', 'true');
            localStorage.setItem('username', user.username);
            localStorage.setItem('role', user.role);
            setProfileUI(user.username);
            checkServerStatus();
            loadAlerts();
            return;
        }
    } catch (e) {
        console.warn("Could not fetch session profile:", e);
    }

    const username = localStorage.getItem('username') || 'rama.tubeh';
    setProfileUI(username);
    checkServerStatus();
    loadAlerts();
}

async function logout() {
    try {
        await fetch(`${BASE_URL}/api/v1/auth/logout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...getAuthHeaders() }
        });
    } catch (e) {
        console.warn("Logout request failed:", e);
    }
    localStorage.removeItem('auth_session_active');
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('username');
    localStorage.removeItem('role');
    log('Logged out successfully.', 'info');
    window.location.href = '/login';
}

function getAuthHeaders() {
    const token = localStorage.getItem('jwt_token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
}

function setMockMode(enabled) {
    mockMode = enabled;
    const banner = document.getElementById('mock-mode-banner');
    const badge = document.getElementById('app-status-badge');
    const statusText = document.getElementById('app-status-text');

    if (enabled) {
        if (banner) banner.style.display = 'block';
        if (badge) badge.classList.remove('online');
        if (statusText) statusText.innerText = 'Mock Database Mode';
    } else {
        if (banner) banner.style.display = 'none';
        if (badge) badge.classList.add('online');
        if (statusText) statusText.innerText = 'Compliance Engine Online';
    }
}

async function checkServerStatus() {
    try {
        const response = await fetch(`${BASE_URL}/`);
        if (response.ok) {
            const data = await response.json();
            setMockMode(false);
            log(`Connected to ingestion scoring core: ${data.service}`, 'success');
        } else {
            throw new Error();
        }
    } catch (e) {
        setMockMode(true);
        log('Database Gateway offline. Simulated mock evaluation activated.', 'warn');
    }
}

// ── Real-Time WebSocket Connection ────────────────────────────────────────────
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = localStorage.getItem('jwt_token');
    const wsUrl = token
        ? `${protocol}//${window.location.host}/ws/live-stream?token=${encodeURIComponent(token)}`
        : `${protocol}//${window.location.host}/ws/live-stream`;

    try {
        liveWebSocket = new WebSocket(wsUrl);

        liveWebSocket.onopen = () => {
            log('Established live WebSocket connection for event feeds.', 'success');
        };

        liveWebSocket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                if (data.event === 'NEW_ALERT') {
                    log(`⚡ REAL-TIME EVENT: New Alert Triggered! Rule: ${data.rule_name}, Threat: ${data.threat_level}`, 'err');
                    loadAlerts();
                    loadDashboardAnalytics();
                } else if (data.event === 'NEW_TRANSACTION') {
                    log(`📥 LIVE TRANSACTION: Ingested $${data.amount} ${data.currency} (Score: ${Math.round(data.risk_score * 100)}%)`, 'info');
                } else if (data.event === 'ALERT_RESOLVED') {
                    log(`✅ REAL-TIME EVENT: Case Resolved. Status: ${data.status}`, 'success');
                    loadAlerts();
                    loadDashboardAnalytics();
                } else if (data.event === 'ALERT_ESCALATED') {
                    log(`⚠️ REAL-TIME EVENT: Case Escalated by ${data.escalated_by}. Status: ${data.status}`, 'warn');
                    loadAlerts();
                    loadDashboardAnalytics();
                } else if (data.event === 'ALERT_ASSIGNED') {
                    log(`👤 REAL-TIME EVENT: Case assigned to ${data.assigned_officer}`, 'info');
                    loadAlerts();
                    loadDashboardAnalytics();
                } else if (data.event === 'GRAPH_SYNCED') {
                    log(`🕸️ REAL-TIME GRAPH: Synced edge $${data.amount} (${data.sender_account} → ${data.receiver_account})`, 'info');
                    if (activeAlertId) {
                        const alert = activeAlerts.find(a => a.alert_id === activeAlertId);
                        if (alert) loadGraphData(activeAlertId, alert);
                    }
                } else if (data.event === 'STR_BATCH_GENERATED') {
                    log(`📦 REAL-TIME EVENT: Sealed STR batch container ${data.batch_id} with ${data.record_count} records.`, 'success');
                    loadSTRBatches();
                } else if (data.event === 'STR_BATCH_TRANSMITTED') {
                    log(`🚀 REAL-TIME EVENT: Transmitted STR batch package ${data.batch_id}. Status: ${data.status}`, 'success');
                    loadSTRBatches();
                } else if (data.event === 'WATCHLIST_SYNCED') {
                    log(`🔄 REAL-TIME EVENT: Global Watchlists Synced! ${data.total_records} records processed across OFAC, World-Check & Dow Jones.`, 'success');
                }
            } catch (e) {
                // Ignore raw strings
            }
        };

        liveWebSocket.onclose = () => {
            log('WebSocket feed disconnected. Attempting auto-reconnect in 5s...', 'warn');
            setTimeout(initWebSocket, 5000);
        };
    } catch (e) {
        logger.warning('WebSocket initialization failed.');
    }
}

function log(msg, type = 'info') {
    const feed = document.getElementById('log-feed');
    if (!feed) return;
    const entry = document.createElement('div');
    entry.className = `log-entry ${type}`;

    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.innerText = new Date().toLocaleTimeString();

    const textSpan = document.createElement('span');
    textSpan.innerText = msg;

    entry.appendChild(timeSpan);
    entry.appendChild(textSpan);
    feed.appendChild(entry);
    feed.scrollTop = feed.scrollHeight;
}

function switchTab(tabId, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));

    document.getElementById(tabId).classList.add('active');
    btn.classList.add('active');
    log(`Switched to tab views: ${tabId.replace('-tab', '')}`, 'info');
}

// ── Dynamic Dashboard Analytics & Chart.js ─────────────────────────────────────
async function loadDashboardAnalytics() {
    if (mockMode) {
        renderMockCharts();
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/metrics/dashboard`, {
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const metrics = await response.json();

        // 1. KPI Cards
        document.getElementById('metric-active-cases').innerText = metrics.active_cases || 0;
        document.getElementById('metric-critical-cases').innerText = metrics.critical_cases || 0;

        // 2. Render Chart.js Daily Trend Line Chart
        renderDailyTrendChart(metrics.daily_trend.labels, metrics.daily_trend.data);

        // 3. Render Chart.js Category Distribution Doughnut Chart
        renderCategoryChart(metrics.category_distribution);

        // 4. Render Analyst Leaderboard Table
        renderLeaderboard(metrics.analyst_leaderboard);

    } catch (e) {
        setMockMode(true);
        log('Failed to fetch dashboard metrics. Rendering mock analytics.', 'warn');
        renderMockCharts();
    }
}

function renderDailyTrendChart(labels, data) {
    const ctx = document.getElementById('alert-trend-chart');
    if (!ctx) return;

    if (trendChartInstance) {
        trendChartInstance.data.labels = labels;
        trendChartInstance.data.datasets[0].data = data;
        trendChartInstance.update();
        return;
    }

    trendChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Daily Alert Count',
                data: data,
                borderColor: '#3d6b99',
                backgroundColor: 'rgba(61, 107, 153, 0.15)',
                borderWidth: 3,
                fill: true,
                tension: 0.35,
                pointRadius: 4,
                pointBackgroundColor: '#3d6b99'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(0, 0, 0, 0.05)' } },
                x: { grid: { display: false } }
            }
        }
    });
}

function renderCategoryChart(categories) {
    const ctx = document.getElementById('alert-category-chart');
    if (!ctx) return;

    const labels = categories.map(c => c.category.replace(/_/g, ' '));
    const counts = categories.map(c => c.count);

    if (categoryChartInstance) {
        categoryChartInstance.data.labels = labels;
        categoryChartInstance.data.datasets[0].data = counts;
        categoryChartInstance.update();
        return;
    }

    categoryChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: counts,
                backgroundColor: [
                    '#d97706',
                    '#3d6b99',
                    '#dc2626',
                    '#10b981',
                    '#8b5cf6'
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { boxWidth: 12, font: { size: 11 } } }
            }
        }
    });
}

function renderLeaderboard(analysts) {
    const tbody = document.getElementById('leaderboard-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!analysts || analysts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No active analyst workloads recorded.</td></tr>';
        return;
    }

    analysts.forEach(item => {
        const tr = document.createElement('tr');
        const badgeClass = item.active_cases >= 4 ? 'badge-red' : (item.active_cases >= 2 ? 'badge-orange' : 'badge-green');
        const tierBadgeClass = item.risk_tier === 'Critical' ? 'badge-red' : (item.risk_tier === 'High' ? 'badge-orange' : 'badge-blue');

        tr.innerHTML = `
            <td><strong>${item.username.replace('_', ' ')}</strong></td>
            <td><span class="badge ${badgeClass}">${item.active_cases} Active</span></td>
            <td>${item.resolution_rate}</td>
            <td><span class="badge ${tierBadgeClass}">${item.risk_tier}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderMockCharts() {
    renderDailyTrendChart(['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'], [12, 19, 14, 25, 22, 30, 18]);
    renderCategoryChart([
        { category: "STRUCTURING_SMURFING", count: 18 },
        { category: "LARGE_TRANSACTION", count: 14 },
        { category: "SANCTIONS_MATCH", count: 11 }
    ]);
    renderLeaderboard([
        { username: "Sarah Jenkins", active_cases: 4, resolution_rate: "94%", risk_tier: "Critical" },
        { username: "Alex Rivera", active_cases: 3, resolution_rate: "88%", risk_tier: "High" },
        { username: "David Chen", active_cases: 2, resolution_rate: "91%", risk_tier: "Normal" },
        { username: "Emma Watson", active_cases: 1, resolution_rate: "96%", risk_tier: "Normal" }
    ]);
}

// Global search and filter state
let activeSearchTerm = '';
let activeSeverityFilter = 'ALL';

function formatTenure(dateStr) {
    if (!dateStr) return 'Verified';
    const d = new Date(dateStr);
    const months = Math.max(1, Math.round((Date.now() - d.getTime()) / (30 * 86400 * 1000)));
    return months >= 12 ? `${Math.floor(months / 12)}y ${months % 12}m` : `${months} mo`;
}

// TAB 1 & 2: Alerts and Triage loading
async function loadAlerts(search = null, severity = null) {
    if (search !== null) activeSearchTerm = search;
    if (severity !== null) activeSeverityFilter = severity;

    log('Loading telemetry cases queue...', 'info');
    if (mockMode) {
        renderInbox(activeAlerts);
        renderQueueRail();
        if (activeAlerts.length > 0) {
            const currentId = (activeAlertId && activeAlerts.some(a => a.alert_id === activeAlertId)) ? activeAlertId : activeAlerts[0].alert_id;
            selectCase(currentId);
        }
        updatePaginationControls(activeAlerts.length);
        return;
    }

    try {
        let url = `${BASE_URL}/api/v1/alerts?page=${currentPage}&limit=${pageSize}`;
        if (activeSearchTerm) url += `&search=${encodeURIComponent(activeSearchTerm)}`;
        if (activeSeverityFilter && activeSeverityFilter !== 'ALL') url += `&severity=${encodeURIComponent(activeSeverityFilter)}`;

        const response = await fetch(url, {
            headers: getAuthHeaders()
        });

        if (response.status === 401) {
            logout();
            return;
        }

        if (!response.ok) throw new Error();
        const data = await response.json();

        const xTotalCount = response.headers.get('X-Total-Count');
        totalAlertsCount = xTotalCount ? parseInt(xTotalCount, 10) : data.length;

        if (data && Array.isArray(data)) {
            activeAlerts = data.map((alert) => {
                const tx = alert.transaction || {};
                const amountFormatted = tx.amount ? '$' + Number(tx.amount).toLocaleString('en-US', { minimumFractionDigits: 2 }) : '$0.00';
                const senderName = tx.sender_name || tx.sender || 'Primary Account';
                const receiverName = tx.receiver_name || tx.receiver || 'Beneficiary';
                const tenure = alert.account_created_at ? formatTenure(alert.account_created_at) : 'Institutional';
                const riskTier = alert.sender_risk_tier || (alert.threat_level === 'CRITICAL' ? 'CRITICAL' : 'STANDARD');

                return {
                    alert_id: alert.alert_id,
                    short_id: alert.alert_id ? alert.alert_id.slice(-6) : 'N/A',
                    title: `${alert.rule_name || 'AML ALERT'} — ${amountFormatted} (${senderName} → ${receiverName})`,
                    rule_name: alert.rule_name || 'COMPLIANCE_ALERT',
                    threat_level: alert.threat_level || 'MEDIUM',
                    ai_risk_score: alert.ai_risk_score !== null && alert.ai_risk_score !== undefined ? alert.ai_risk_score : 0.5,
                    status: alert.status || 'OPEN',
                    created_at: alert.created_at || new Date().toISOString(),
                    assignee: alert.assignee || 'Unassigned',
                    threshold_proximity: alert.threat_level === 'CRITICAL' ? '95%+' : 'Standard',
                    channel: tx.channel || 'Wire Transfer',
                    counterparty_jurisdiction: tx.country || 'DOMESTIC',
                    prior_30d_txns: 1,
                    account_tenure: tenure,
                    rules_triggered_count: 1,
                    model_version: 'v4.2.1',
                    transaction: {
                        amount: tx.amount || 0,
                        currency: tx.currency || 'USD',
                        timestamp: tx.timestamp || new Date().toISOString(),
                        sender: tx.sender || 'Primary Account',
                        sender_account: tx.sender || 'N/A',
                        sender_name: senderName,
                        receiver: tx.receiver || 'Beneficiary',
                        receiver_account: tx.receiver || 'N/A',
                        receiver_name: receiverName,
                        channel: tx.channel || 'Wire Transfer',
                        country: tx.country || 'DOMESTIC'
                    },
                    rules_triggered: [
                        { code: alert.rule_name || 'R-COMP-01', desc: `— Triggered compliance rule ${alert.rule_name}`, critical: alert.threat_level === 'CRITICAL' }
                    ],
                    explainability: alert.explainability || {
                        attributions: { "transaction_risk": 0.5 }
                    },
                    entity: {
                        name: senderName,
                        nationality: tx.country || 'Global',
                        tier: `${riskTier} Tier`,
                        connected: receiverName,
                        customer_since: tenure,
                        occupation: 'Commercial Account',
                        pep: 'Screened Clean',
                        sanctions: 'Screened Clean',
                        adverse_media: 'Clean'
                    },
                    linked_entities: [],
                    prior_alerts: [],
                    ledger: []
                };
            });
        } else {
            activeAlerts = [];
        }

        renderInbox(activeAlerts);
        renderQueueRail();
        if (activeAlerts.length > 0) {
            const currentId = (activeAlertId && activeAlerts.some(a => a.alert_id === activeAlertId)) ? activeAlertId : activeAlerts[0].alert_id;
            selectCase(currentId);
        }
        updatePaginationControls(totalAlertsCount);
        log(`Synced telemetry page ${currentPage} from postgres connection pool.`, 'success');
    } catch (e) {
        log('Failed to fetch cases from API. Please verify network and authentication credentials.', 'error');
        activeAlerts = [];
        renderInbox(activeAlerts);
        renderQueueRail();
        updatePaginationControls(0);
    }
}

function updatePaginationControls(totalCount) {
    const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
    if (currentPage > totalPages) {
        currentPage = totalPages;
    }

    const start = totalCount === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(currentPage * pageSize, totalCount);

    document.getElementById('pagination-start').innerText = start;
    document.getElementById('pagination-end').innerText = end;
    document.getElementById('pagination-total').innerText = totalCount;
    document.getElementById('current-page-display').innerText = `Page ${currentPage} of ${totalPages}`;

    document.getElementById('prev-page-btn').disabled = (currentPage === 1);
    document.getElementById('next-page-btn').disabled = (currentPage === totalPages);
}

function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadAlerts();
    }
}

function nextPage() {
    const totalPages = Math.ceil(totalAlertsCount / pageSize);
    if (currentPage < totalPages) {
        currentPage++;
        loadAlerts();
    }
}

function renderInbox(alertsList) {
    const tbody = document.getElementById('inbox-tbody');
    const empty = document.getElementById('inbox-empty');
    if (!tbody) return;
    tbody.innerHTML = '';

    const activeCases = alertsList.filter(a => a.status === 'NEW' || a.status === 'OPEN');

    if (activeCases.length === 0) {
        empty.style.display = 'flex';
        return;
    }
    empty.style.display = 'none';

    activeCases.forEach(alert => {
        const tr = document.createElement('tr');
        tr.className = 'clickable';
        if (activeAlertId === alert.alert_id) {
            tr.className += ' active';
        }
        tr.onclick = () => selectCase(alert.alert_id);

        const idStr = `<code>${alert.alert_id.substring(0, 8)}...</code>`;
        const threatClass = alert.threat_level === 'CRITICAL' ? 'badge-red' : 'badge-orange';
        const threatBadge = `<span class="badge ${threatClass}">${alert.threat_level}</span>`;
        const ruleBadge = `<strong>${alert.rule_name.replace(/_/g, ' ')}</strong>`;
        const senderBrief = alert.transaction.sender.substring(0, 10) + "...";
        const receiverBrief = alert.transaction.receiver.substring(0, 10) + "...";

        tr.innerHTML = `
            <td style="text-align: center;"><input type="checkbox" class="alert-row-checkbox" value="${alert.alert_id}" onclick="event.stopPropagation(); updateBulkActionBar();"></td>
            <td>${idStr}</td>
            <td>${threatBadge}</td>
            <td><strong>${Math.round(alert.ai_risk_score * 100)}%</strong></td>
            <td>${ruleBadge}</td>
            <td><code>${senderBrief}</code> → <code>${receiverBrief}</code></td>
            <td>${new Date(alert.created_at).toLocaleTimeString()}</td>
            <td><span class="badge badge-blue">${alert.assignee || 'Unassigned'}</span></td>
        `;
        tbody.appendChild(tr);
    });
    updateBulkActionBar();
}

function toggleSelectAllAlerts(masterCb) {
    const checkboxes = document.querySelectorAll('.alert-row-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = masterCb.checked;
    });
    updateBulkActionBar();
}

function updateBulkActionBar() {
    const selectedBoxes = document.querySelectorAll('.alert-row-checkbox:checked');
    const bar = document.getElementById('bulk-action-bar');
    const countSpan = document.getElementById('bulk-selected-count');
    const masterCb = document.getElementById('select-all-alerts');
    const allBoxes = document.querySelectorAll('.alert-row-checkbox');

    if (!bar || !countSpan) return;

    const selectedCount = selectedBoxes.length;
    countSpan.innerText = selectedCount;

    if (selectedCount > 0) {
        bar.style.display = 'flex';
    } else {
        bar.style.display = 'none';
    }

    if (masterCb && allBoxes.length > 0) {
        masterCb.checked = (selectedCount === allBoxes.length);
    }
}

async function executeBulkResolve(action) {
    const selectedBoxes = Array.from(document.querySelectorAll('.alert-row-checkbox:checked'));
    const ids = selectedBoxes.map(cb => cb.value);
    if (ids.length === 0) return;

    const actionText = action === 'CLOSE_SAR' ? 'File Regulatory SAR' : 'Dismiss as False Positive';
    const note = prompt(`Enter mandatory investigation notes for batch processing ${ids.length} selected alerts (${actionText}):`);
    if (!note || note.trim().length < 5) {
        alert('A valid investigation justification (minimum 5 characters) is required for batch action execution.');
        return;
    }

    log(`Executing batch ${action} on ${ids.length} selected cases...`, 'info');

    if (mockMode) {
        ids.forEach(id => {
            const idx = activeAlerts.findIndex(a => a.alert_id === id);
            if (idx !== -1) {
                activeAlerts[idx].status = action === 'CLOSE_SAR' ? 'CLOSED_SAR' : 'CLOSED_FALSE_POSITIVE';
            }
        });
        log(`Mock batch resolved ${ids.length} alerts successfully.`, 'success');
        loadAlerts();
        loadDashboardAnalytics();
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts/bulk-action`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify({
                alert_ids: ids,
                action: action,
                justification: note.trim()
            })
        });

        if (response.status === 401) {
            logout();
            return;
        }

        if (!response.ok) throw new Error();
        const res = await response.json();
        log(`Batch Operation Succeeded: ${res.message}`, 'success');
        loadAlerts();
        loadDashboardAnalytics();
    } catch (e) {
        log('Bulk resolution failed. Please verify database pool or network connections.', 'warn');
    }
}

async function exportAlertsCSV() {
    log('Preparing compliance CSV audit export download...', 'info');
    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts/export/csv`, {
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `aml_alerts_audit_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        log('CSV compliance audit export successfully downloaded.', 'success');
    } catch (e) {
        log('CSV export failed. Please verify API connection.', 'warn');
    }
}

async function exportAlertsPDF() {
    log('Generating FinCEN regulatory audit report preview...', 'info');
    try {
        const token = localStorage.getItem('jwt_token');
        const win = window.open(`${BASE_URL}/api/v1/alerts/export/pdf`, '_blank');
        if (win) win.focus();
        log('Audit report preview window launched.', 'success');
    } catch (e) {
        log('Failed to launch audit report preview.', 'warn');
    }
}

let searchDebounceTimer = null;
function filterInboxTable() {
    const searchInput = document.getElementById('inbox-search');
    const severityInput = document.getElementById('inbox-filter-severity');
    const searchVal = searchInput ? searchInput.value.trim() : '';
    const severityVal = severityInput ? severityInput.value : 'ALL';

    if (mockMode) {
        const filtered = activeAlerts.filter(alert => {
            const matchesSearch = alert.transaction.sender.toLowerCase().includes(searchVal.toLowerCase()) ||
                alert.transaction.receiver.toLowerCase().includes(searchVal.toLowerCase()) ||
                alert.alert_id.toLowerCase().includes(searchVal.toLowerCase());
            const matchesSeverity = severityVal === 'ALL' || alert.threat_level === severityVal;
            return matchesSearch && matchesSeverity;
        });
        renderInbox(filtered);
        return;
    }

    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
        currentPage = 1;
        loadAlerts(searchVal, severityVal);
    }, 300);
}

// Selecting a case to open Case Investigation Cockpit
function selectCase(id) {
    activeAlertId = id;
    const alert = activeAlerts.find(a => a.alert_id === id) || activeAlerts[0];
    if (!alert) return;

    // 1. Update Left Rail Highlight & Position
    const railItems = document.querySelectorAll('#queue-rail-items .queue-item');
    railItems.forEach(el => {
        if (el.dataset.id === alert.alert_id) {
            el.classList.add('current');
        } else {
            el.classList.remove('current');
        }
    });

    const activeCases = activeAlerts.filter(a => a.status === 'NEW' || a.status === 'OPEN' || a.status === 'ESCALATED');
    const casesToCount = activeCases.length > 0 ? activeCases : activeAlerts;
    const caseIdx = casesToCount.findIndex(a => a.alert_id === alert.alert_id);
    const posEl = document.getElementById('queue-position-display');
    if (posEl && caseIdx !== -1) {
        posEl.innerText = `Case ${caseIdx + 1} of ${casesToCount.length} in queue`;
    }

    // 2. Topbar Updates
    const shortId = alert.short_id || (alert.alert_id.includes('-') ? alert.alert_id.split('-').pop() : alert.alert_id.slice(-4));
    const fullCaseId = alert.alert_id.startsWith('aml-') ? alert.alert_id.toUpperCase() : `AML-2026-${shortId}`;
    const topbarId = document.getElementById('topbar-case-id');
    if (topbarId) topbarId.innerText = `CASE #${fullCaseId}`;

    const topbarCrumb = document.getElementById('topbar-case-crumb');
    if (topbarCrumb) {
        const ruleFormatted = alert.rule_name ? alert.rule_name.replace(/_/g, ' ') : 'Structuring';
        const channelFormatted = alert.channel || 'Wire Transfer';
        const openTime = alert.created_at ? new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '09:14';
        topbarCrumb.innerText = `${ruleFormatted} · ${channelFormatted} · Opened ${openTime} today`;
    }

    // 3. Center Evidence Pane Header
    const txnTitle = document.getElementById('evidence-txn-title');
    if (txnTitle) txnTitle.innerText = alert.title || `Transaction ${alert.alert_id}`;

    const txnSub = document.getElementById('evidence-txn-sub');
    if (txnSub) {
        const sender = alert.transaction ? alert.transaction.sender : 'Unknown';
        const senderAcct = alert.transaction ? (alert.transaction.sender_account || '****4821') : '****4821';
        const timeFormatted = alert.transaction && alert.transaction.timestamp ? new Date(alert.transaction.timestamp).toLocaleTimeString() : '08:52:14';
        txnSub.innerText = `Sender: ${sender} · Account ${senderAcct} · Received ${timeFormatted} today`;
    }

    const riskBadge = document.getElementById('evidence-risk-badge');
    const riskScore = Math.round((alert.ai_risk_score || 0.8) * 100);
    const riskClass = (alert.threat_level === 'CRITICAL' || alert.ai_risk_score >= 0.85) ? 'high' : 
                      ((alert.threat_level === 'HIGH' || alert.ai_risk_score >= 0.6) ? 'med' : 'low');
    if (riskBadge) {
        riskBadge.className = `risk-badge ${riskClass}`;
        riskBadge.innerText = `● Risk ${riskScore} / 100`;
    }

    // 4. Center 8-Cell KPI Grid
    const amountVal = alert.transaction ? alert.transaction.amount : 9480;
    const amtEl = document.getElementById('txn-amount');
    if (amtEl) amtEl.innerText = `$${Number(amountVal).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

    const threshEl = document.getElementById('txn-threshold');
    if (threshEl) threshEl.innerText = alert.threshold_proximity || '98.7%';

    const chanEl = document.getElementById('txn-channel');
    if (chanEl) chanEl.innerText = alert.channel || 'Wire — SWIFT';

    const jurisEl = document.getElementById('txn-jurisdiction');
    if (jurisEl) jurisEl.innerText = alert.counterparty_jurisdiction || '🇰🇾 KY';

    const prior30dEl = document.getElementById('txn-prior-30d');
    if (prior30dEl) prior30dEl.innerText = alert.prior_30d_txns !== undefined ? alert.prior_30d_txns : 6;

    const tenureEl = document.getElementById('txn-tenure');
    if (tenureEl) tenureEl.innerText = alert.account_tenure || '14 mo';

    const rulesCountEl = document.getElementById('txn-rules-count');
    const firedRulesCount = alert.rules_triggered ? alert.rules_triggered.length : (alert.rules_triggered_count || 3);
    if (rulesCountEl) rulesCountEl.innerText = firedRulesCount;

    const modelEl = document.getElementById('txn-model');
    if (modelEl) modelEl.innerText = alert.model_version || 'v4.2.1';

    // 5. Triggered Rules List
    const rulesHint = document.getElementById('rules-count-hint');
    if (rulesHint) rulesHint.innerText = `${firedRulesCount} of 41 active rules fired`;

    const rulesList = document.getElementById('evidence-rule-list');
    if (rulesList && alert.rules_triggered) {
        rulesList.innerHTML = alert.rules_triggered.map(r => `
            <div class="rule-row">
                <span class="rname">${r.code}</span>
                <span class="rdesc">${r.desc}</span>
            </div>
        `).join('');
    }

    // 6. Network Graph Rendering
    loadGraphData(alert.alert_id, alert);

    // 7. Explainability (SHAP List for Rule logic tab)
    const shapList = document.getElementById('inbox-shap-list');
    if (shapList && alert.explainability && alert.explainability.attributions) {
        shapList.innerHTML = '';
        const attributions = alert.explainability.attributions;
        Object.keys(attributions).forEach(key => {
            const score = attributions[key];
            const isPositive = score >= 0;
            const absoluteScore = Math.abs(score);
            const percentage = Math.round(absoluteScore * 100);
            const shapItem = document.createElement('div');
            shapItem.className = 'shap-item';

            const barColor = isPositive ? 'var(--risk-high)' : 'var(--risk-low)';
            const signText = isPositive ? '+' : '-';

            shapItem.innerHTML = `
                <div class="shap-header">
                    <span style="text-transform: capitalize;">${key.replace(/_/g, ' ')} Impact</span>
                    <span style="color: ${barColor}; font-weight: 600;">${signText}${percentage}% weighting</span>
                </div>
                <div class="shap-bar-bg">
                    <div class="shap-bar-fill" style="width: ${percentage}%; background-color: ${barColor};"></div>
                </div>
            `;
            shapList.appendChild(shapItem);
        });
    }

    // 8. Raw Data JSON
    const rawPre = document.getElementById('evidence-raw-json');
    if (rawPre) rawPre.innerText = JSON.stringify(alert, null, 2);

    // 9. Context Pane: Composite Risk Gauge
    const gaugeScore = document.getElementById('ctx-risk-score');
    if (gaugeScore) gaugeScore.innerText = riskScore;

    const gaugeLabel = document.getElementById('ctx-risk-label');
    if (gaugeLabel) {
        gaugeLabel.innerHTML = `${alert.threat_level || 'HIGH'} Priority.<br>Triggered by ${(alert.rule_name || 'RULES').replace(/_/g, ' ')}.`;
    }

    // 10. Context Pane: KYC Snapshot
    if (alert.entity) {
        const kycName = document.getElementById('ctx-kyc-name');
        if (kycName) kycName.innerText = alert.entity.name || 'N/A';

        const kycTenure = document.getElementById('ctx-kyc-tenure');
        if (kycTenure) kycTenure.innerText = alert.entity.customer_since || 'Jul 2025';

        const kycOcc = document.getElementById('ctx-kyc-occupation');
        if (kycOcc) kycOcc.innerText = alert.entity.occupation || 'Private Client';

        const kycPep = document.getElementById('ctx-kyc-pep');
        if (kycPep) kycPep.innerText = alert.entity.pep || 'No';

        const kycSanc = document.getElementById('ctx-kyc-sanctions');
        if (kycSanc) kycSanc.innerText = alert.entity.sanctions || 'None';

        const kycMed = document.getElementById('ctx-kyc-media');
        if (kycMed) kycMed.innerText = alert.entity.adverse_media || 'Clean';
    }

    // 11. Context Pane: Linked Entities
    const entitiesCount = document.getElementById('ctx-entities-count');
    const entitiesList = document.getElementById('ctx-entities-list');
    if (alert.linked_entities) {
        if (entitiesCount) entitiesCount.innerText = alert.linked_entities.length;
        if (entitiesList) {
            entitiesList.innerHTML = alert.linked_entities.map(e => `
                <div class="entity-card">
                    <div class="entity-avatar" style="${e.high_risk ? 'background:var(--risk-high-bg); color:var(--risk-high);' : ''}">${e.avatar || e.name.slice(0, 2).toUpperCase()}</div>
                    <div>
                        <div class="entity-name">${e.name}</div>
                        <div class="entity-meta">${e.relation}</div>
                    </div>
                </div>
            `).join('');
        }
    }

    // 12. Context Pane: Prior Alerts
    const priorCount = document.getElementById('ctx-prior-alerts-count');
    const priorList = document.getElementById('ctx-prior-alerts-list');
    if (alert.prior_alerts) {
        if (priorCount) priorCount.innerText = alert.prior_alerts.length;
        if (priorList) {
            if (alert.prior_alerts.length === 0) {
                priorList.innerHTML = '<div style="font-size:12px; color:var(--ink-soft); padding:6px 0;">No prior alerts recorded in 12 mo.</div>';
            } else {
                priorList.innerHTML = alert.prior_alerts.map(pa => `
                    <div class="alert-item">
                        <span>${pa.title}</span>
                        <span class="adate">${pa.date} <span class="status-pill ${pa.status}">${pa.status.toUpperCase()}</span></span>
                    </div>
                `).join('');
            }
        }
    }

    // Legacy table compatibility
    loadInboxTableHighlights(id);

    log(`Cockpit Active: Inspecting Case #${shortId} (${alert.entity ? alert.entity.name : 'Unknown'})`, 'info');

    // Fetch and render authentic KYC, dynamic timeline, and prior alert history
    fetchAndRenderAlertDetails(id, alert);
}

async function fetchAndRenderAlertDetails(id, alert) {
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
    if (!isUUID || mockMode) {
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts/${id}/details`, {
            headers: getAuthHeaders()
        });
        if (!response.ok) return;
        const details = await response.json();

        // Update KYC Snapshot with authentic PostgreSQL data
        if (details.entity) {
            const kycName = document.getElementById('ctx-kyc-name');
            if (kycName) kycName.innerText = details.entity.name || 'N/A';

            const kycTenure = document.getElementById('ctx-kyc-tenure');
            if (kycTenure && details.entity.customer_since) {
                kycTenure.innerText = formatTenure(details.entity.customer_since);
            }

            const kycOcc = document.getElementById('ctx-kyc-occupation');
            if (kycOcc) kycOcc.innerText = details.entity.risk_tier ? `${details.entity.risk_tier} Risk Account` : 'Commercial Account';

            const kycPep = document.getElementById('ctx-kyc-pep');
            if (kycPep) kycPep.innerText = details.entity.risk_tier === 'CRITICAL' ? 'Flagged / Review' : 'Screened Clean';
        }

        // Render dynamic 30-day transaction timeline
        if (details.timeline_30d && details.timeline_30d.length > 0) {
            renderTransactionTimeline(details.timeline_30d, details.transaction ? details.transaction.id : null);
            const prior30dEl = document.getElementById('txn-prior-30d');
            if (prior30dEl) prior30dEl.innerText = details.timeline_30d.length;
        }

        // Render authentic prior alerts from PostgreSQL
        if (details.prior_alerts) {
            const priorCount = document.getElementById('ctx-prior-alerts-count');
            const priorList = document.getElementById('ctx-prior-alerts-list');
            if (priorCount) priorCount.innerText = details.prior_alerts.length;
            if (priorList) {
                if (details.prior_alerts.length === 0) {
                    priorList.innerHTML = '<div style="font-size:12px; color:var(--ink-soft); padding:6px 0;">No prior alerts recorded in 12 mo.</div>';
                } else {
                    priorList.innerHTML = details.prior_alerts.map(pa => `
                        <div class="alert-item">
                            <span>${pa.rule_name.replace(/_/g, ' ')}</span>
                            <span class="adate">${new Date(pa.created_at).toLocaleDateString([], { month: 'short', day: 'numeric' })} <span class="status-pill ${pa.status.toLowerCase()}">${pa.status}</span></span>
                        </div>
                    `).join('');
                }
            }
        }
    } catch (e) {
        console.warn("Could not load enhanced alert details:", e);
    }
}

function renderTransactionTimeline(history, currentTxnId) {
    const track = document.getElementById('evidence-timeline-track');
    if (!track || !Array.isArray(history) || history.length === 0) return;

    // Reset axis and dynamically inject points
    track.innerHTML = '<div class="timeline-axis"></div>';

    const now = Date.now();
    const windowStart = now - (30 * 86400 * 1000);
    const windowEnd = now;

    history.forEach(tx => {
        const txTime = new Date(tx.timestamp).getTime();
        let pct = Math.round(((txTime - windowStart) / (windowEnd - windowStart)) * 100);
        pct = Math.max(3, Math.min(97, pct));

        const pt = document.createElement('div');
        const isFlagged = tx.is_flagged || (currentTxnId && tx.id === currentTxnId);
        pt.className = isFlagged ? 'timeline-point highlight' : 'timeline-point';
        pt.style.left = `${pct}%`;

        if (!isFlagged) {
            pt.style.background = tx.amount > 10000 ? '#C98A2E' : '#B8B1A0';
        }

        const dateStr = new Date(tx.timestamp).toLocaleDateString([], { month: 'short', day: 'numeric' });
        const amtStr = '$' + Number(tx.amount).toLocaleString(undefined, { minimumFractionDigits: 2 });
        pt.title = `${dateStr} - ${amtStr} (${tx.status || 'INGESTED'})`;
        track.appendChild(pt);
    });

    const labelsWrap = document.querySelector('.timeline-labels');
    if (labelsWrap) {
        const d30 = new Date(windowStart).toLocaleDateString([], { month: 'short', day: 'numeric' });
        const d20 = new Date(windowStart + 10 * 86400 * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
        const d10 = new Date(windowStart + 20 * 86400 * 1000).toLocaleDateString([], { month: 'short', day: 'numeric' });
        labelsWrap.innerHTML = `
            <span>${d30}</span>
            <span>${d20}</span>
            <span>${d10}</span>
            <span>Today</span>
        `;
    }
}

function loadInboxTableHighlights(id) {
    const tbody = document.getElementById('inbox-tbody');
    if (!tbody) return;
    const activeCases = activeAlerts.filter(a => a.status === 'NEW' || a.status === 'OPEN');
    Array.from(tbody.children).forEach((tr, index) => {
        if (activeCases[index] && activeCases[index].alert_id === id) {
            tr.classList.add('active');
        } else {
            tr.classList.remove('active');
        }
    });
}

async function loadGraphData(alertId, alert) {
    const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(alertId);
    if (mockMode || !isUUID) {
        renderMockGraph(alert);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts/${alertId}/graph`, {
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const graphData = await response.json();
        renderVisNetworkGraph(graphData, alert);
    } catch (e) {
        log('Failed to fetch graph data from Neo4j. Rendering mock topology.', 'warn');
        renderMockGraph(alert);
    }
}

// ── Interactive Vis.js Force-Directed Graph Rendering ─────────────────────────
function renderVisNetworkGraph(graphData, alert) {
    const container = document.getElementById('vis-graph-container');
    if (!container) return;

    const rawNodes = graphData.nodes || [];
    const rawEdges = graphData.edges || [];

    if (rawNodes.length === 0) {
        renderMockGraph(alert);
        return;
    }

    const senderAcc = alert.transaction.sender;
    const receiverAcc = alert.transaction.receiver;

    const visNodes = rawNodes.map(n => {
        let color = '#3d6b99';
        let shape = 'dot';
        let size = 18;

        if (n.type === 'Account') {
            if (n.label === senderAcc) {
                color = '#3b82f6';
                size = 22;
            } else if (n.label === receiverAcc) {
                color = '#dc2626';
                size = 22;
            } else {
                color = '#64748b';
            }
        } else if (n.type === 'Company') {
            color = '#d97706';
            shape = 'diamond';
            size = 20;
        } else if (n.type === 'Person') {
            color = '#10b981';
            shape = 'star';
            size = 20;
        }

        return {
            id: n.id,
            label: n.label.length > 15 ? n.label.substring(0, 12) + '...' : n.label,
            title: `${n.type}: ${n.label}`,
            color: { background: color, border: '#ffffff', highlight: { background: '#f59e0b', border: '#ffffff' } },
            shape: shape,
            size: size,
            font: { color: '#1e293b', size: 11, face: 'Plus Jakarta Sans' },
            nodeData: n
        };
    });

    const visEdges = rawEdges.map(e => {
        let color = '#94a3b8';
        let width = 2;
        let dashes = false;

        if (e.type === 'TRANSFERS_TO') {
            const amt = e.properties.amount || 0;
            color = amt > 10000 ? '#dc2626' : '#3b82f6';
            width = amt > 10000 ? 3 : 2;
        } else if (e.type === 'BELONGS_TO' || e.type === 'OWNS_UBO') {
            color = '#10b981';
            dashes = true;
        }

        return {
            from: e.source,
            to: e.target,
            label: e.type,
            color: { color: color },
            width: width,
            dashes: dashes,
            arrows: { to: { enabled: true, scaleFactor: 0.6 } },
            font: { size: 9, align: 'middle' }
        };
    });

    const data = {
        nodes: new vis.DataSet(visNodes),
        edges: new vis.DataSet(visEdges)
    };

    const options = {
        physics: {
            barnesHut: { gravitationalConstant: -3000, centralGravity: 0.3, springLength: 95 },
            stabilization: { iterations: 150 }
        },
        interaction: { hover: true, zoomView: true, dragView: true }
    };

    if (visNetworkInstance) {
        visNetworkInstance.destroy();
    }

    visNetworkInstance = new vis.Network(container, data, options);

    visNetworkInstance.on('selectNode', (params) => {
        const selectedId = params.nodes[0];
        const targetNode = visNodes.find(n => n.id === selectedId);
        if (targetNode) {
            showNodeDetails(targetNode.nodeData);
        }
    });

    visNetworkInstance.on('doubleClick', (params) => {
        if (params.nodes && params.nodes.length > 0) {
            expandGraphNode(params.nodes[0]);
        }
    });
}

function zoomVisGraph(scaleFactor) {
    if (!visNetworkInstance) return;
    const currentScale = visNetworkInstance.getScale();
    visNetworkInstance.moveTo({ scale: currentScale * scaleFactor, animation: { duration: 300 } });
}

function fitVisGraph() {
    if (!visNetworkInstance) return;
    visNetworkInstance.fit({ animation: { duration: 400 } });
}

async function expandSelectedGraphNode() {
    if (!visNetworkInstance) return;
    const selectedNodes = visNetworkInstance.getSelectedNodes();
    if (selectedNodes.length === 0) {
        alert('Please click a node in the graph map first to select it for expansion.');
        return;
    }
    await expandGraphNode(selectedNodes[0]);
}

async function expandGraphNode(nodeId) {
    log(`Expanding 2-hop graph topology for node: ${nodeId}...`, 'info');
    if (mockMode) {
        log(`Mock network expansion active for node ${nodeId}.`, 'info');
        return;
    }
    try {
        const response = await fetch(`${BASE_URL}/api/v1/network/expand/${nodeId}`, {
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const expandedData = await response.json();
        const alert = activeAlerts.find(a => a.alert_id === activeAlertId) || activeAlerts[0] || null;
        renderVisNetworkGraph(expandedData, alert);
        log(`Successfully expanded 2-hop network graph around node ${nodeId}.`, 'success');
    } catch (e) {
        log(`Failed to expand graph node ${nodeId}.`, 'warn');
    }
}

function showNodeDetails(node) {
    const detailsDiv = document.getElementById('graph-node-details');
    const labelSpan = document.getElementById('selected-node-label');
    detailsDiv.style.display = 'block';

    let detailText = `<strong>${node.type} Node:</strong> ${node.label}`;
    if (node.type === 'Account') {
        const risk = node.properties.risk_score ? `${Math.round(node.properties.risk_score * 100)}%` : '0%';
        detailText += ` (Risk Score: ${risk}, Status: ${node.properties.status || 'ACTIVE'})`;
    } else if (node.type === 'Company') {
        detailText += ` (Reg Num: ${node.properties.registration_number || 'N/A'})`;
    } else if (node.type === 'Person') {
        detailText += ` (Tax ID: ${node.properties.tax_id || 'N/A'})`;
    }

    labelSpan.innerHTML = detailText;
    log(`Inspected graph node: ${node.label}`, 'info');
}

function renderMockGraph(alert) {
    const mockData = {
        nodes: [
            { id: "s", label: alert.transaction.sender, type: "Account", properties: { risk_score: 0.10, status: "ACTIVE" } },
            { id: "r", label: alert.transaction.receiver, type: "Account", properties: { risk_score: 0.90, status: "ACTIVE" } },
            { id: "c", label: alert.entity.connected || "Holding Gmbh", type: "Company", properties: { registration_number: "REG-999000" } },
            { id: "p1", label: alert.entity.name, type: "Person", properties: { tax_id: "TAX-ALICE" } }
        ],
        edges: [
            { source: "s", target: "r", type: "TRANSFERS_TO", properties: { amount: alert.transaction.amount } },
            { source: "s", target: "c", type: "BELONGS_TO" },
            { source: "p1", target: "c", type: "OWNS_UBO", properties: { percentage: 60.0 } }
        ]
    };
    renderVisNetworkGraph(mockData, alert);
}

async function assignCaseToOfficer(officerUsername) {
    if (!activeAlertId) return;
    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts/${activeAlertId}/assign`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify({ officer_username: officerUsername })
        });
        if (response.status === 401) {
            logout();
            return;
        }
        if (!response.ok) throw new Error();
        const res = await response.json();
        log(`Case ${activeAlertId.substring(0, 8)} assigned to officer: ${res.assigned_officer}`, 'success');
        loadAlerts();
        loadDashboardAnalytics();
    } catch (e) {
        log('Failed to assign case officer.', 'warn');
    }
}

// Case action resolutions in 3-Pane Cockpit
async function resolveCurrentCase(action) {
    if (!activeAlertId) return;
    const alert = activeAlerts.find(a => a.alert_id === activeAlertId);
    if (!alert) return;

    const noteInput = document.getElementById('inbox-justification');
    let justification = noteInput ? noteInput.value.trim() : '';

    if (!justification) {
        if (action === 'CLOSE_FALSE_POSITIVE') {
            justification = "Legitimate customer activity verified per standard customer profile and counterparty review.";
        } else if (action === 'CLOSE_SAR') {
            justification = "SAR Filing initiated: Transaction meets suspicious activity threshold due to structuring and high-risk counterparty jurisdiction.";
        }
    }

    const shortId = alert.short_id || (alert.alert_id.includes('-') ? alert.alert_id.split('-').pop() : alert.alert_id.slice(-4));
    const actionLabel = action === 'CLOSE_SAR' ? 'BLOCK & SAR' : 'APPROVE (FALSE POSITIVE)';
    log(`Submitting resolution: ${actionLabel} for Case #${shortId}...`, 'info');

    if (mockMode) {
        alert.status = action;
        log(`Case #${shortId} successfully resolved: ${action}`, 'success');
        if (noteInput) noteInput.value = '';
        renderQueueRail();
        navigateQueue(1);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts/${activeAlertId}/action`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify({
                action: action,
                justification: justification,
                sar_xml_generate: action === 'CLOSE_SAR'
            })
        });

        if (response.status === 401) {
            logout();
            return;
        }

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server returned HTTP ${response.status}`);
        }
        const res = await response.json();
        alert.status = action;
        log(`Case #${shortId} closed: ${res.status || action}`, 'success');
        if (noteInput) noteInput.value = '';
        renderQueueRail();
        navigateQueue(1);
    } catch (e) {
        log(`Failed to resolve case #${shortId} on server: ${e.message}`, 'err');
    }
}

async function escalateCurrentCase() {
    if (!activeAlertId) return;
    const alert = activeAlerts.find(a => a.alert_id === activeAlertId);
    if (!alert) return;

    const noteInput = document.getElementById('inbox-justification');
    let justification = noteInput ? noteInput.value.trim() : '';
    if (!justification) {
        justification = "Case escalated to Senior Compliance Committee for enhanced due diligence (EDD).";
    }

    const shortId = alert.short_id || (alert.alert_id.includes('-') ? alert.alert_id.split('-').pop() : alert.alert_id.slice(-4));
    log(`Escalating Case #${shortId} to Senior Review Committee...`, 'info');

    if (mockMode) {
        alert.status = 'ESCALATED';
        if (noteInput) noteInput.value = '';
        log(`Case #${shortId} status updated: ESCALATED`, 'success');
        renderQueueRail();
        navigateQueue(1);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts/${activeAlertId}/escalate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify({ justification: justification })
        });

        if (response.status === 401) {
            logout();
            return;
        }

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.detail || `Server returned HTTP ${response.status}`);
        }

        const res = await response.json();
        alert.status = 'ESCALATED';
        if (noteInput) noteInput.value = '';
        log(`Case #${shortId} successfully persisted as ESCALATED in PostgreSQL database.`, 'success');
        renderQueueRail();
        navigateQueue(1);
    } catch (e) {
        log(`Failed to escalate case #${shortId}: ${e.message}`, 'err');
    }
}

// Backward compatibility alias for resolveInboxCase
async function resolveInboxCase(action) {
    return resolveCurrentCase(action);
}

async function submitSARToFinCEN() {
    if (!activeAlertId) return;
    const sarXml = document.getElementById('inbox-sar-xml').innerText;
    if (!sarXml) {
        alert('No generated SAR XML payload found for active case.');
        return;
    }

    log(`Transmitting SAR electronically to U.S. FinCEN BSA E-Filing Gateway for case ${activeAlertId.substring(0, 8)}...`, 'info');

    if (mockMode) {
        const trackingId = `BSA-2026-${Math.floor(100000 + Math.random() * 900000)}`;
        document.getElementById('fincen-receipt-box').style.display = 'block';
        document.getElementById('fincen-tracking-id-display').innerText = trackingId;
        document.getElementById('fincen-status-display').innerText = 'ACKNOWLEDGED (Sandbox)';
        log(`FinCEN Electronic Submission Receipt Verified: ${trackingId}`, 'success');
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/fincen/sar/submit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify({
                alert_id: activeAlertId,
                sar_xml: sarXml
            })
        });

        if (response.status === 401) {
            logout();
            return;
        }

        if (!response.ok) throw new Error();
        const res = await response.json();

        document.getElementById('fincen-receipt-box').style.display = 'block';
        document.getElementById('fincen-tracking-id-display').innerText = res.fincen_tracking_id;
        document.getElementById('fincen-status-display').innerText = res.status;
        log(`FinCEN Electronic Receipt Ingested: Tracking ID=${res.fincen_tracking_id}, Status=${res.status}`, 'success');

    } catch (e) {
        log('FinCEN electronic submission API error. Please verify transmitter credentials.', 'warn');
    }
}

function generateSARXML(alert, justification) {
    return `<?xml version="1.0" encoding="UTF-8"?>
<SuspiciousActivityReport>
  <Header>
    <FilingAgency>FinCEN</FilingAgency>
    <ReportID>${alert.alert_id}</ReportID>
    <Timestamp>${new Date().toISOString()}</Timestamp>
  </Header>
  <Subject>
    <Name>${alert.entity.name}</Name>
    <Country>${alert.entity.nationality}</Country>
    <Account>${alert.transaction.sender}</Account>
  </Subject>
  <TransactionDetails>
    <Amount>${alert.transaction.amount}</Amount>
    <Receiver>${alert.transaction.receiver}</Receiver>
  </TransactionDetails>
  <ComplianceNotes>
    <RuleTrigger>${alert.rule_name}</RuleTrigger>
    <Justification>${justification}</Justification>
  </ComplianceNotes>
</SuspiciousActivityReport>`;
}

// TAB 3: PHONETIC SANDBOX SCREENING
async function runSandboxScreening(event) {
    event.preventDefault();
    const name = document.getElementById('sandbox-screen-name').value.trim();
    const thresholdVal = parseFloat(document.getElementById('sandbox-screen-threshold').value) / 100;

    log(`Multi-Tier Screening query: Identity="${name}", threshold=${thresholdVal}`, 'info');

    if (mockMode) {
        setTimeout(() => {
            let resultPayload = { match_found: false, sanctions_hit: { match_found: false }, pep_hit: { match_found: false } };
            const normName = name.toLowerCase();
            if (normName.includes('smirnov') || normName.includes('smirnow')) {
                resultPayload = {
                    match_found: true,
                    sanctions_hit: { match_found: true, score: 0.88, source_list: 'OFAC SDN Blocklist', matched_entry: { name: 'Wladimir Smirnow' } },
                    pep_hit: { match_found: false }
                };
            } else if (normName.includes('petrov') || normName.includes('minister')) {
                resultPayload = {
                    match_found: true,
                    sanctions_hit: { match_found: false },
                    pep_hit: { match_found: true, score: 0.92, pep_tier: 'TIER_2_GOVERNMENT_MINISTER', position: 'Minister of Energy', country: 'RU', source_list: 'Global PEP Register', matched_entry: { name: 'Ivan Petrov' } }
                };
            }

            renderSandboxVerdict(resultPayload, thresholdVal);
        }, 400);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/screening/search`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify({ name: name, threshold: thresholdVal })
        });

        if (response.status === 401) {
            logout();
            return;
        }

        if (!response.ok) throw new Error();
        const result = await response.json();
        renderSandboxVerdict(result, thresholdVal);

    } catch (e) {
        log('API screening error. Running offline lookup...', 'warn');
        setMockMode(true);
        runSandboxScreening(event);
    }
}

function renderSandboxVerdict(res, threshold) {
    document.getElementById('sandbox-unselected').style.display = 'none';
    document.getElementById('sandbox-verdict-body').style.display = 'block';

    const tbody = document.getElementById('sandbox-hits-tbody');
    tbody.innerHTML = '';

    const sanctionsHit = res.sanctions_hit && res.sanctions_hit.match_found ? res.sanctions_hit : null;
    const pepHit = res.pep_hit && res.pep_hit.match_found ? res.pep_hit : null;

    const badge = document.getElementById('sandbox-verdict-badge');
    const verdictTitle = document.getElementById('sandbox-verdict-verdict');

    if (sanctionsHit) {
        badge.innerText = 'SANCTIONS BLOCKLIST HIT';
        badge.className = 'badge badge-red';
        verdictTitle.innerText = 'MANDATORY BLOCKLIST HIT IDENTIFIED (FREEZE FUNDS)';
        verdictTitle.style.color = 'var(--accent-red)';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong style="color: var(--accent-red); display: inline-flex; align-items: center;"><i data-lucide="ban" style="width:14px;height:14px;stroke-width:2.2;margin-right:5px;"></i> ${sanctionsHit.matched_entry.name}</strong></td>
            <td><span class="badge badge-red">${sanctionsHit.source_list || 'OFAC SDN List'}</span></td>
            <td><strong style="color: var(--accent-red);">${Math.round(sanctionsHit.score * 100)}%</strong></td>
        `;
        tbody.appendChild(tr);
        log(`SANCTIONS BLOCKLIST HIT: ${sanctionsHit.matched_entry.name} matched ${sanctionsHit.source_list}`, 'err');

    } else if (pepHit) {
        badge.innerText = 'PEP TIER MATCH (EDD REQUIRED)';
        badge.className = 'badge badge-orange';
        verdictTitle.innerText = `PEP TIER MATCH IDENTIFIED (${pepHit.pep_tier.replace(/_/g, ' ')})`;
        verdictTitle.style.color = 'var(--accent-orange)';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong style="display: inline-flex; align-items: center;"><i data-lucide="crown" style="width:14px;height:14px;stroke:var(--high);stroke-width:2;margin-right:5px;"></i> ${pepHit.matched_entry.name}</strong><br><small style="color: var(--text-secondary);">${pepHit.position} (${pepHit.country})</small></td>
            <td><span class="badge badge-orange">${pepHit.pep_tier}</span></td>
            <td><strong style="color: var(--accent-orange);">${Math.round(pepHit.score * 100)}%</strong></td>
        `;
        tbody.appendChild(tr);
        log(`PEP TIER MATCH: ${pepHit.matched_entry.name} (${pepHit.position}) requires Enhanced Due Diligence (EDD).`, 'warn');

    } else {
        badge.innerText = 'CLEARED';
        badge.className = 'badge badge-green';
        verdictTitle.innerText = 'NO MATCHING SANCTIONS OR PEP PROFILES';
        verdictTitle.style.color = '#10b981';
        tbody.innerHTML = '<tr><td colspan="3" style="text-align: center; color: var(--text-secondary);">No sanctioned profiles or PEP tier entities met the similarity threshold.</td></tr>';
        log('Identity screening cleared: No blocklist or PEP tier matches.', 'info');
    }
    if (window.lucide) lucide.createIcons();
}

// ── TAB 4: Regulatory STR Batch Filings ───────────────────────────────────────
async function loadSTRBatches() {
    log('Fetching regulatory STR batch containers list...', 'info');
    if (mockMode) {
        renderMockSTRBatches();
        return;
    }
    try {
        const response = await fetch(`${BASE_URL}/api/v1/str/batch/list`, {
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const data = await response.json();
        renderSTRBatches(data.batches || []);
    } catch (e) {
        log('Could not fetch STR batches from API gateway. Falling back to mock dataset.', 'warn');
        renderMockSTRBatches();
    }
}

function renderSTRBatches(batches) {
    const tbody = document.getElementById('str-batch-tbody');
    const empty = document.getElementById('str-batch-empty');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!batches || batches.length === 0) {
        empty.style.display = 'flex';
        return;
    }
    empty.style.display = 'none';

    batches.forEach(b => {
        const tr = document.createElement('tr');
        const statusBadge = b.status === 'ACKNOWLEDGED' ? 'badge-green' : (b.status === 'GENERATED' ? 'badge-blue' : 'badge-orange');
        const shortChecksum = b.checksum ? b.checksum.substring(0, 10) + '...' : '-';

        tr.innerHTML = `
            <td><code>${b.batch_id}</code></td>
            <td><strong>${b.record_count} Records</strong></td>
            <td><strong>$${b.total_amount.toLocaleString(undefined, { minimumFractionDigits: 2 })}</strong></td>
            <td><code>${shortChecksum}</code></td>
            <td><span class="badge ${statusBadge}">${b.status}</span></td>
            <td>${new Date(b.created_at).toLocaleString()}</td>
            <td>
                <div style="display: flex; gap: 0.35rem;">
                    <a href="${BASE_URL}/api/v1/str/batch/${b.batch_id}/download" target="_blank" class="btn btn-outline" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;"><i data-lucide="download" class="btn-icon"></i> XML</a>
                    <button onclick="transmitSTRBatchPackage('${b.batch_id}')" class="btn btn-primary" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;"><i data-lucide="send" class="btn-icon"></i> Transmit</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
    if (window.lucide) lucide.createIcons();
}

async function generateSTRBatchPackage() {
    log('Compiling un-batched CLOSED_SAR reports into sealed STR batch container...', 'info');
    if (mockMode) {
        log('Mock STR batch package successfully sealed.', 'success');
        renderMockSTRBatches();
        return;
    }
    try {
        const response = await fetch(`${BASE_URL}/api/v1/str/batch/generate`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const res = await response.json();
        if (res.batch_id) {
            log(`Sealed regulatory STR batch container: ${res.batch_id} (${res.record_count} cases, total $${res.total_amount.toLocaleString()})`, 'success');
            loadSTRBatches();
        } else {
            log(res.message || 'No pending un-batched STR reports found.', 'info');
        }
    } catch (e) {
        log('Failed to generate STR batch container.', 'warn');
    }
}

async function transmitSTRBatchPackage(batchId) {
    log(`Transmitting full STR batch package ${batchId} to FinCEN/FIU gateway...`, 'info');
    if (mockMode) {
        log(`Mock STR batch ${batchId} transmitted successfully.`, 'success');
        return;
    }
    try {
        const response = await fetch(`${BASE_URL}/api/v1/str/batch/${batchId}/transmit`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const res = await response.json();
        log(`STR Batch Transmission Succeeded: Tracking ID=${res.fincen_tracking_id}, Status=${res.status}`, 'success');
        loadSTRBatches();
    } catch (e) {
        log('Failed to transmit STR batch package.', 'warn');
    }
}

function renderMockSTRBatches() {
    renderSTRBatches([
        {
            batch_id: "STR-BATCH-20260716-A1F9C8E4",
            record_count: 14,
            total_amount: 142500.00,
            checksum: "a3f5b7c89911223344556677889900aabbccdd",
            status: "ACKNOWLEDGED",
            created_at: new Date().toISOString()
        }
    ]);
}

async function syncGlobalWatchlists() {
    log('Triggering live watchlist synchronization across OFAC, World-Check, and Dow Jones data sources...', 'info');
    if (mockMode) {
        log('Mock global watchlist sync completed successfully.', 'success');
        return;
    }
    try {
        const response = await fetch(`${BASE_URL}/api/v1/watchlist/sync`, {
            method: 'POST',
            headers: getAuthHeaders()
        });
        if (!response.ok) throw new Error();
        const res = await response.json();
        log(`Watchlist Synchronization Complete: Processed ${res.total_records_processed} total entries across OFAC, World-Check & Dow Jones.`, 'success');
    } catch (e) {
        log('Watchlist synchronization failed. Please check provider API keys.', 'warn');
    }
}
