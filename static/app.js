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

// Seed Mock Cases Database
const mockAlerts = [
    {
        alert_id: "8f3b9c2a-1122-3344-5566-778899aabbcc",
        rule_name: "LARGE_TRANSACTION_THRESHOLD",
        threat_level: "CRITICAL",
        ai_risk_score: 0.89,
        status: "NEW",
        created_at: new Date().toISOString(),
        assignee: "Sarah Jenkins",
        transaction: {
            amount: 12500.00,
            currency: "USD",
            timestamp: new Date().toISOString(),
            sender: "DE12003400567890111100",
            receiver: "US99887766554433221100"
        },
        explainability: {
            attributions: {
                "amount_pattern": 0.45,
                "sender_risk": 0.25,
                "receiver_risk": 0.12,
                "velocity_24h": 0.07
            }
        },
        entity: {
            name: "Alice Schmidt",
            nationality: "Germany",
            tier: "High Risk Tier",
            connected: "ACME Holdings Ltd",
            kyc: "KYC Verified"
        },
        ledger: [
            { date: "2026-07-14", direction: "OUTGOING", partner: "ACME Holdings", amount: "$12,500.00", risk: "89%" },
            { date: "2026-07-13", direction: "INCOMING", partner: "Broker Munich", amount: "$4,200.00", risk: "15%" },
            { date: "2026-07-10", direction: "INCOMING", partner: "Employer Gmbh", amount: "$5,000.00", risk: "8%" }
        ]
    },
    {
        alert_id: "a3f5b7c8-4455-6677-8899-001122334455",
        rule_name: "STRUCTURING_VELOCITY_24H",
        threat_level: "HIGH",
        ai_risk_score: 0.78,
        status: "NEW",
        assignee: "Alex Rivera",
        transaction: {
            amount: 9500.00,
            currency: "USD",
            timestamp: new Date(Date.now() - 3600000).toISOString(),
            sender: "DE12003400567890111100",
            receiver: "RU11223344556677889900"
        },
        explainability: {
            attributions: {
                "velocity_24h": 0.38,
                "sender_risk": 0.22,
                "receiver_risk": 0.15,
                "amount_pattern": 0.03
            }
        },
        entity: {
            name: "Carlos Santana",
            nationality: "Mexico",
            tier: "Medium Risk Tier",
            connected: "Z-Broker Corp",
            kyc: "KYC Pending Review"
        },
        ledger: [
            { date: "2026-07-14", direction: "OUTGOING", partner: "Z-Broker Corp", amount: "$9,500.00", risk: "78%" },
            { date: "2026-07-14", direction: "OUTGOING", partner: "Z-Broker Corp", amount: "$9,200.00", risk: "75%" },
            { date: "2026-07-12", direction: "INCOMING", partner: "Unknown Sender", amount: "$2,000.00", risk: "12%" }
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
    if (!btn) return;
    if (theme === 'dark') {
        btn.innerText = '☀️ Light Mode';
    } else {
        btn.innerText = '🌙 Dark Mode';
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

    // Close modal or investigation portal on "Esc"
    if (e.key === 'Escape') {
        const modal = document.getElementById('shortcuts-modal');
        if (modal && modal.style.display === 'flex') {
            toggleShortcutsModal();
            return;
        }
        if (isInputFieldActive()) {
            document.activeElement.blur();
            return;
        }
        closeInvestigationPortal();
        return;
    }

    // Ignore single-character hotkeys when typing in form fields
    if (isInputFieldActive()) {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            const activeInput = document.activeElement;
            if (activeInput && activeInput.id === 'inbox-justification') {
                e.preventDefault();
                resolveInboxCase('CLOSE_FALSE_POSITIVE');
            }
        }
        return;
    }

    const activeCases = activeAlerts.filter(a => a.status === 'NEW' || a.status === 'OPEN');
    if (activeCases.length === 0) return;

    const currentIndex = activeCases.findIndex(a => a.alert_id === activeAlertId);

    // Key "j" or "ArrowDown": Next Case
    if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault();
        const nextIdx = (currentIndex < activeCases.length - 1) ? currentIndex + 1 : 0;
        selectCase(activeCases[nextIdx].alert_id);
    }
    // Key "k" or "ArrowUp": Previous Case
    else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault();
        const prevIdx = (currentIndex > 0) ? currentIndex - 1 : activeCases.length - 1;
        selectCase(activeCases[prevIdx].alert_id);
    }
    // Key "f": Quick Dismiss as False Positive
    else if (e.key === 'f' || e.key === 'F') {
        e.preventDefault();
        if (activeAlertId) {
            const noteInput = document.getElementById('inbox-justification');
            if (noteInput && !noteInput.value.trim()) {
                noteInput.value = "Automated audit triage: Verified non-suspicious transaction pattern.";
            }
            resolveInboxCase('CLOSE_FALSE_POSITIVE');
        }
    }
    // Key "s": Quick File Regulatory SAR
    else if (e.key === 's' || e.key === 'S') {
        e.preventDefault();
        if (activeAlertId) {
            const noteInput = document.getElementById('inbox-justification');
            if (noteInput && !noteInput.value.trim()) {
                noteInput.value = "Automated audit triage: High-risk anomaly confirmed for FinCEN SAR reporting.";
            }
            resolveInboxCase('CLOSE_SAR');
        }
    }
    // Key "Enter": Focus mandatory justification input box
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

function closeInvestigationPortal() {
    activeAlertId = null;
    loadInboxTableHighlights(null);
    document.getElementById('investigation-empty-state').style.display = 'flex';
    document.getElementById('investigation-split-portal').style.display = 'none';
}

function initAuth() {
    const token = localStorage.getItem('jwt_token');
    const username = localStorage.getItem('username');
    if (token && username) {
        document.getElementById('user-welcome-text').innerText = `Welcome, ${username.replace('_', ' ')}`;
        document.getElementById('user-welcome-text').style.display = 'inline';
        document.getElementById('logout-button').style.display = 'inline';
        checkServerStatus();
        loadAlerts();
    } else {
        window.location.href = '/login';
    }
}

function logout() {
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
    const wsUrl = `${protocol}//${window.location.host}/ws/live-stream`;

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

// TAB 1 & 2: Alerts and Triage loading
async function loadAlerts() {
    log('Loading telemetry cases queue...', 'info');
    if (mockMode) {
        renderInbox(activeAlerts);
        updatePaginationControls(activeAlerts.length);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts?page=${currentPage}&limit=${pageSize}`, {
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
        
        activeAlerts = data.map((alert, idx) => {
            const seed = mockAlerts[idx % mockAlerts.length];
            return {
                ...seed,
                alert_id: alert.alert_id,
                rule_name: alert.rule_name,
                threat_level: alert.threat_level,
                ai_risk_score: alert.ai_risk_score,
                status: alert.status,
                transaction: alert.transaction,
                explainability: alert.explainability
            };
        });
        
        renderInbox(activeAlerts);
        updatePaginationControls(totalAlertsCount);
        log(`Synced telemetry page ${currentPage} from postgres connection pool.`, 'success');
    } catch (e) {
        log('Failed connection. Falling back to memory ledger data.', 'warn');
        setMockMode(true);
        renderInbox(activeAlerts);
        updatePaginationControls(activeAlerts.length);
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

function filterInboxTable() {
    const searchVal = document.getElementById('inbox-search').value.toLowerCase();
    const severityVal = document.getElementById('inbox-filter-severity').value;
    
    const filtered = activeAlerts.filter(alert => {
        const matchesSearch = alert.transaction.sender.toLowerCase().includes(searchVal) || 
                              alert.transaction.receiver.toLowerCase().includes(searchVal) ||
                              alert.alert_id.toLowerCase().includes(searchVal);
        const matchesSeverity = severityVal === 'ALL' || alert.threat_level === severityVal;
        return matchesSearch && matchesSeverity;
    });
    
    renderInbox(filtered);
}

// Selecting a case to open Case Investigation Portal
function selectCase(id) {
    activeAlertId = id;
    loadInboxTableHighlights(id);

    const alert = activeAlerts.find(a => a.alert_id === id);
    if (!alert) return;

    document.getElementById('investigation-empty-state').style.display = 'none';
    document.getElementById('investigation-split-portal').style.display = 'grid';
    document.getElementById('inbox-sar-display').style.display = 'none';

    document.getElementById('profile-name').innerText = alert.entity.name;
    document.getElementById('profile-nationality').innerText = alert.entity.nationality;
    document.getElementById('profile-tier').innerText = alert.entity.tier;
    document.getElementById('profile-connected').innerText = alert.entity.connected;
    
    const kycStatus = document.getElementById('profile-kyc-status');
    kycStatus.innerText = alert.entity.kyc;
    kycStatus.className = alert.entity.kyc.includes('Verified') ? 'badge badge-green' : 'badge badge-orange';

    const shapList = document.getElementById('inbox-shap-list');
    shapList.innerHTML = '';
    const attributions = alert.explainability.attributions;
    if (attributions) {
        Object.keys(attributions).forEach(key => {
            const score = attributions[key];
            const isPositive = score >= 0;
            const absoluteScore = Math.abs(score);
            const percentage = Math.round(absoluteScore * 100);
            const shapItem = document.createElement('div');
            shapItem.className = 'shap-item';
            
            const barColor = isPositive ? 'var(--accent-orange)' : '#10b981';
            const signText = isPositive ? '+' : '-';
            
            shapItem.innerHTML = `
                <div class="shap-header">
                    <span style="text-transform: capitalize;">${key.replace(/_/g, ' ')} Risk</span>
                    <span style="color: ${isPositive ? 'var(--accent-orange)' : '#10b981'}; font-weight: 600;">${signText}${percentage}% impact</span>
                </div>
                <div class="shap-bar-bg">
                    <div class="shap-bar-fill" style="width: ${percentage}%; background-color: ${barColor};"></div>
                </div>
            `;
            shapList.appendChild(shapItem);
        });
    }

    // Load Neo4j dynamic Vis.js network graph rendering
    loadGraphData(id, alert);

    const ledgerBody = document.getElementById('inbox-ledger-tbody');
    ledgerBody.innerHTML = '';
    alert.ledger.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${item.date}</td>
            <td><span class="badge ${item.direction === 'INCOMING' ? 'badge-green' : 'badge-orange'}">${item.direction}</span></td>
            <td><code>${item.partner}</code></td>
            <td><strong>${item.amount}</strong></td>
            <td><strong style="color: var(--accent-red);">${item.risk}</strong></td>
        `;
        ledgerBody.appendChild(tr);
    });

    document.getElementById('graph-node-details').style.display = 'none';
    log(`Auditing Case: Profile loaded for ${alert.entity.name}`, 'info');
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
    if (mockMode) {
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
        const alert = activeAlerts.find(a => a.alert_id === activeAlertId) || mockAlerts[0];
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

// Case action resolutions in Inbox
async function resolveInboxCase(action) {
    const justification = document.getElementById('inbox-justification').value.trim();
    if (!justification) {
        alert('Please fill out the Investigation Justification Notes before submitting resolution.');
        return;
    }

    log(`Posting resolution: ${action} for case ${activeAlertId.substring(0, 8)}...`, 'info');

    if (mockMode) {
        const alertIndex = activeAlerts.findIndex(a => a.alert_id === activeAlertId);
        if (alertIndex !== -1) {
            activeAlerts[alertIndex].status = action === 'CLOSE_SAR' ? 'CLOSED_SAR' : 'CLOSED_FALSE_POSITIVE';
            
            if (action === 'CLOSE_SAR') {
                const xml = generateSARXML(activeAlerts[alertIndex], justification);
                document.getElementById('inbox-sar-display').style.display = 'block';
                document.getElementById('inbox-sar-xml').innerText = xml;
                log('Regulatory SAR report successfully generated and saved.', 'success');
            } else {
                log('Alert archived as False Positive. Workload pool updated.', 'success');
            }

            setTimeout(() => {
                loadAlerts();
                loadDashboardAnalytics();
                document.getElementById('investigation-empty-state').style.display = 'flex';
                document.getElementById('investigation-split-portal').style.display = 'none';
                document.getElementById('inbox-justification').value = '';
            }, 3500);
        }
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

        if (!response.ok) throw new Error();
        const result = await response.json();

        log(`Case closed: status ${result.status}`, 'success');

        if (result.sar_xml) {
            document.getElementById('inbox-sar-display').style.display = 'block';
            document.getElementById('inbox-sar-xml').innerText = result.sar_xml;
        }

        setTimeout(() => {
            loadAlerts();
            loadDashboardAnalytics();
            document.getElementById('investigation-empty-state').style.display = 'flex';
            document.getElementById('investigation-split-portal').style.display = 'none';
            document.getElementById('inbox-justification').value = '';
        }, 3500);

    } catch (e) {
        log('API resolving failed. Please verify server status.', 'err');
    }
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
            <td><strong style="color: var(--accent-red);">🚫 ${sanctionsHit.matched_entry.name}</strong></td>
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
            <td><strong>👑 ${pepHit.matched_entry.name}</strong><br><small style="color: var(--text-secondary);">${pepHit.position} (${pepHit.country})</small></td>
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
        log('Failed to fetch STR batch containers. Displaying mock ledger.', 'warn');
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
            <td><strong>$${b.total_amount.toLocaleString(undefined, {minimumFractionDigits: 2})}</strong></td>
            <td><code>${shortChecksum}</code></td>
            <td><span class="badge ${statusBadge}">${b.status}</span></td>
            <td>${new Date(b.created_at).toLocaleString()}</td>
            <td>
                <div style="display: flex; gap: 0.35rem;">
                    <a href="${BASE_URL}/api/v1/str/batch/${b.batch_id}/download" target="_blank" class="btn btn-outline" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;">📥 XML</a>
                    <button onclick="transmitSTRBatchPackage('${b.batch_id}')" class="btn btn-primary" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;">⚡ Transmit</button>
                </div>
            </td>
        `;
        tbody.appendChild(tr);
    });
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
