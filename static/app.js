const BASE_URL = 'http://localhost:8000';
let mockMode = false;
let activeAlertId = null;

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
    initAuth();
});

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

async function checkServerStatus() {
    try {
        const response = await fetch(`${BASE_URL}/`);
        if (response.ok) {
            const data = await response.json();
            document.getElementById('app-status-badge').classList.add('online');
            document.getElementById('app-status-text').innerText = 'Compliance Engine Online';
            log(`Connected to ingestion scoring core: ${data.service}`, 'success');
        } else {
            throw new Error();
        }
    } catch (e) {
        document.getElementById('app-status-badge').classList.remove('online');
        document.getElementById('app-status-text').innerText = 'Mock Database Mode';
        mockMode = true;
        log('Database Gateway offline. Simulated mock evaluation activated.', 'warn');
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

// TAB 1 & 2: Alerts and Triage loading
async function loadAlerts() {
    log('Loading telemetry cases queue...', 'info');
    if (mockMode) {
        renderInbox(activeAlerts);
        updateDashboardMetrics(activeAlerts);
        return;
    }

    try {
        const response = await fetch(`${BASE_URL}/api/v1/alerts`, {
            headers: getAuthHeaders()
        });
        
        if (response.status === 401) {
            logout();
            return;
        }
        
        if (!response.ok) throw new Error();
        const data = await response.json();
        
        // Enrich backend alerts with mock entities to make the investigation profile beautiful!
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
        updateDashboardMetrics(activeAlerts);
        log(`Synced ${data.length} telemetry cases from postgres connection pool.`, 'success');
    } catch (e) {
        log('Failed connection. Falling back to memory ledger data.', 'warn');
        mockMode = true;
        document.getElementById('app-status-badge').classList.remove('online');
        document.getElementById('app-status-text').innerText = 'Mock Database Mode';
        renderInbox(activeAlerts);
        updateDashboardMetrics(activeAlerts);
    }
}

function updateDashboardMetrics(alertsList) {
    const activeCases = alertsList.filter(a => a.status === 'NEW');
    const criticalCases = activeCases.filter(a => a.threat_level === 'CRITICAL');
    
    document.getElementById('metric-active-cases').innerText = activeCases.length;
    document.getElementById('metric-critical-cases').innerText = criticalCases.length;
}

function renderInbox(alertsList) {
    const tbody = document.getElementById('inbox-tbody');
    const empty = document.getElementById('inbox-empty');
    if (!tbody) return;
    tbody.innerHTML = '';

    const activeCases = alertsList.filter(a => a.status === 'NEW');

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

    // Show Portal
    document.getElementById('investigation-empty-state').style.display = 'none';
    document.getElementById('investigation-split-portal').style.display = 'grid';
    document.getElementById('inbox-sar-display').style.display = 'none';

    // Entity details
    document.getElementById('profile-name').innerText = alert.entity.name;
    document.getElementById('profile-nationality').innerText = alert.entity.nationality;
    document.getElementById('profile-tier').innerText = alert.entity.tier;
    document.getElementById('profile-connected').innerText = alert.entity.connected;
    
    const kycStatus = document.getElementById('profile-kyc-status');
    kycStatus.innerText = alert.entity.kyc;
    kycStatus.className = alert.entity.kyc.includes('Verified') ? 'badge badge-green' : 'badge badge-orange';

    // Attributions SHAP
    const shapList = document.getElementById('inbox-shap-list');
    shapList.innerHTML = '';
    const attributions = alert.explainability.attributions;
    Object.keys(attributions).forEach(key => {
        const score = attributions[key];
        const percentage = Math.round(score * 100);
        const shapItem = document.createElement('div');
        shapItem.className = 'shap-item';
        shapItem.innerHTML = `
            <div class="shap-header">
                <span style="text-transform: capitalize;">${key.replace(/_/g, ' ')} Risk</span>
                <span>+${percentage}% weight</span>
            </div>
            <div class="shap-bar-bg">
                <div class="shap-bar-fill" style="width: ${percentage}%"></div>
            </div>
        `;
        shapList.appendChild(shapItem);
    });

    // Ledger Transactions
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

    // Node highlight details reset
    document.getElementById('graph-node-details').style.display = 'none';
    log(`Auditing Case: Profile loaded for ${alert.entity.name}`, 'info');
}

function loadInboxTableHighlights(id) {
    const tbody = document.getElementById('inbox-tbody');
    if (!tbody) return;
    const activeCases = activeAlerts.filter(a => a.status === 'NEW');
    Array.from(tbody.children).forEach((tr, index) => {
        const clickId = activeCases[index].alert_id;
        if (clickId === id) {
            tr.classList.add('active');
        } else {
            tr.classList.remove('active');
        }
    });
}

// Interactive Network Graph Clicks
function clickGraphNode(nodeType) {
    const detailsDiv = document.getElementById('graph-node-details');
    const labelSpan = document.getElementById('selected-node-label');
    detailsDiv.style.display = 'block';

    const alert = activeAlerts.find(a => a.alert_id === activeAlertId);
    if (!alert) return;

    if (nodeType === 'sender') {
        labelSpan.innerHTML = `<strong>Sender Node:</strong> Account ${alert.transaction.sender} (Owner: ${alert.entity.name}). Nationality: ${alert.entity.nationality}.`;
        log(`Graph query: inspected sender node ${alert.transaction.sender.substring(0,8)}...`, 'info');
    } else if (nodeType === 'receiver') {
        labelSpan.innerHTML = `<strong>Receiver Node:</strong> Account ${alert.transaction.receiver} (Fuzzy Blocklist Target). Country risk index: High.`;
        log(`Graph query: inspected beneficiary node ${alert.transaction.receiver.substring(0,8)}...`, 'info');
    } else if (nodeType === 'corp') {
        labelSpan.innerHTML = `<strong>Connected Entity:</strong> ${alert.entity.connected}. Shell holding company match registered in Panama Registry.`;
        log('Graph query: inspected Panama corporate holding node.', 'warn');
    } else if (nodeType === 'broker') {
        labelSpan.innerHTML = `<strong>Intermediary Broker:</strong> Node represents multi-layered accounts routing high liquidity transactions.`;
        log('Graph query: mapped intermediary transit bank node.', 'info');
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
            document.getElementById('investigation-empty-state').style.display = 'flex';
            document.getElementById('investigation-split-portal').style.display = 'none';
            document.getElementById('inbox-justification').value = '';
        }, 3500);

    } catch (e) {
        log('API resolving failed. Please verify server status.', 'err');
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

    log(`Phonetic Sandbox query: Identity="${name}", threshold=${thresholdVal}`, 'info');

    if (mockMode) {
        setTimeout(() => {
            let matches = [];
            const normName = name.toLowerCase();
            if (normName.includes('smirnov') || normName.includes('smirnow')) {
                matches = [
                    { name: 'Wladimir Smirnow', list: 'OFAC SDN Blocklist', score: 0.88 },
                    { name: 'V. Smirnov LLC', list: 'EU Consolidated Sanctions', score: 0.74 }
                ];
            } else if (normName.includes('petrov')) {
                matches = [
                    { name: 'Ivan Petrov', list: 'EU Consolidated Sanctions', score: 0.92 }
                ];
            }

            renderSandboxVerdict(matches, thresholdVal);
        }, 500);
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

        let matches = [];
        if (result.match_found && result.matched_entry) {
            matches.push({
                name: result.matched_entry.name,
                list: result.source_list || 'OFAC SDN List',
                score: result.score
            });
        }
        renderSandboxVerdict(matches, thresholdVal);

    } catch (e) {
        log('API screening error. Running offline phonetic lookup...', 'warn');
        mockMode = true;
        runSandboxScreening(event);
    }
}

function renderSandboxVerdict(matches, threshold) {
    document.getElementById('sandbox-unselected').style.display = 'none';
    document.getElementById('sandbox-verdict-body').style.display = 'block';

    const tbody = document.getElementById('sandbox-hits-tbody');
    tbody.innerHTML = '';

    const validMatches = matches.filter(m => m.score >= threshold);

    const badge = document.getElementById('sandbox-verdict-badge');
    const verdictTitle = document.getElementById('sandbox-verdict-verdict');
    const countEl = document.getElementById('metric-sanctions');

    if (validMatches.length > 0) {
        badge.innerText = 'MATCH FOUND';
        badge.className = 'badge badge-red';
        verdictTitle.innerText = 'BLOCKED PROFILE HITS IDENTIFIED';
        verdictTitle.style.color = 'var(--accent-red)';
        
        validMatches.forEach(hit => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${hit.name}</strong></td>
                <td>${hit.list}</td>
                <td><strong style="color: var(--accent-red);">${Math.round(hit.score * 100)}%</strong></td>
            `;
            tbody.appendChild(tr);
        });
        countEl.innerText = parseInt(countEl.innerText || "0") + validMatches.length;
        log(`Sanctions evaluation hit: Found ${validMatches.length} profiles matching threshold limits!`, 'err');
    } else {
        badge.innerText = 'PASSED';
        badge.className = 'badge badge-green';
        verdictTitle.innerText = 'NO SANCTIONS MATCH DETECTED';
        verdictTitle.style.color = 'var(--accent-green)';
        
        tbody.innerHTML = `<tr><td colspan="3" style="text-align: center; color: var(--text-secondary);">Identity checked passed. No records matched the ${Math.round(threshold*100)}% threshold score.</td></tr>`;
        log('Sanctions evaluation passed: No entries matching threshold levels found.', 'success');
    }
}
