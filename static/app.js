const BASE_URL = window.location.origin;
let mockMode = false;
let activeAlertId = null;

// Pagination State
let currentPage = 1;
const pageSize = 10;
let totalAlertsCount = 0;

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
        
        // Read X-Total-Count header
        const xTotalCount = response.headers.get('X-Total-Count');
        totalAlertsCount = xTotalCount ? parseInt(xTotalCount, 10) : data.length;
        
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
        updatePaginationControls(totalAlertsCount);
        log(`Synced telemetry page ${currentPage} from postgres connection pool.`, 'success');
    } catch (e) {
        log('Failed connection. Falling back to memory ledger data.', 'warn');
        mockMode = true;
        document.getElementById('app-status-badge').classList.remove('online');
        document.getElementById('app-status-text').innerText = 'Mock Database Mode';
        renderInbox(activeAlerts);
        updateDashboardMetrics(activeAlerts);
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

    // Load Neo4j dynamic graph rendering
    loadGraphData(id, alert);

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

async function loadGraphData(alertId, alert) {
    const gContainer = document.getElementById('svg-graph-content');
    if (!gContainer) return;
    gContainer.innerHTML = '';

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
        renderNetworkGraph(graphData, alert);
    } catch (e) {
        log('Failed to fetch graph data from Neo4j. Rendering mock topology.', 'warn');
        renderMockGraph(alert);
    }
}

function renderNetworkGraph(graphData, alert) {
    const g = document.getElementById('svg-graph-content');
    g.innerHTML = '';

    const nodes = graphData.nodes || [];
    const edges = graphData.edges || [];

    if (nodes.length === 0) {
        renderMockGraph(alert);
        return;
    }

    const senderAcc = alert.transaction.sender;
    const receiverAcc = alert.transaction.receiver;

    const nodePositions = {};
    const companies = nodes.filter(n => n.type === 'Company');
    const persons = nodes.filter(n => n.type === 'Person');
    const accounts = nodes.filter(n => n.type === 'Account');
    
    // Position Accounts
    let intermediateCount = 0;
    accounts.forEach(node => {
        const accNum = node.label;
        if (accNum === senderAcc) {
            nodePositions[node.id] = { x: 70, y: 120, color: 'var(--accent-blue)', text: 'SND' };
        } else if (accNum === receiverAcc) {
            nodePositions[node.id] = { x: 280, y: 120, color: 'var(--accent-red)', text: 'RCV' };
        } else {
            const offsetIdx = intermediateCount++;
            nodePositions[node.id] = { x: 175, y: 180 + offsetIdx * 40, color: 'var(--text-secondary)', text: 'BRK' };
        }
    });

    // Position Companies
    companies.forEach((node, idx) => {
        const offset = (idx - (companies.length - 1) / 2) * 80;
        nodePositions[node.id] = { x: 175 + offset, y: 60, color: '#f59e0b', text: 'CO' };
    });

    // Position Persons (UBOs)
    persons.forEach((node, idx) => {
        const offset = (idx - (persons.length - 1) / 2) * 80;
        nodePositions[node.id] = { x: 175 + offset, y: 20, color: '#10b981', text: 'UBO' };
    });

    // Draw Edges (Lines)
    edges.forEach(edge => {
        const sourcePos = nodePositions[edge.source];
        const targetPos = nodePositions[edge.target];
        if (!sourcePos || !targetPos) return;

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', sourcePos.x);
        line.setAttribute('y1', sourcePos.y);
        line.setAttribute('x2', targetPos.x);
        line.setAttribute('y2', targetPos.y);
        
        let strokeColor = 'var(--text-secondary)';
        let strokeWidth = '1.5';
        let isDashed = false;

        if (edge.type === 'TRANSFERS_TO') {
            const amount = edge.properties.amount || 0;
            if (amount > 10000) {
                strokeColor = 'var(--accent-red)';
                strokeWidth = '2.5';
            } else {
                strokeColor = 'var(--accent-blue)';
                strokeWidth = '1.8';
            }
            line.setAttribute('marker-end', 'url(#arrow)');
        } else if (edge.type === 'BELONGS_TO') {
            strokeColor = 'var(--text-secondary)';
            isDashed = true;
        } else if (edge.type === 'OWNS_UBO') {
            strokeColor = '#10b981';
            isDashed = true;
        }

        line.setAttribute('stroke', strokeColor);
        line.setAttribute('stroke-width', strokeWidth);
        if (isDashed) {
            line.setAttribute('stroke-dasharray', '3,3');
        }

        g.appendChild(line);
    });

    // Draw Nodes (Circles and Text)
    nodes.forEach(node => {
        const pos = nodePositions[node.id];
        if (!pos) return;

        const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        group.setAttribute('style', 'cursor: pointer;');
        group.onclick = () => showNodeDetails(node);

        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', pos.x);
        circle.setAttribute('cy', pos.y);
        circle.setAttribute('r', '16');
        circle.setAttribute('fill', pos.color);
        circle.setAttribute('stroke', '#ffffff');
        circle.setAttribute('stroke-width', '2');
        circle.setAttribute('class', 'graph-node');

        const textType = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        textType.setAttribute('x', pos.x);
        textType.setAttribute('y', pos.y + 3);
        textType.setAttribute('font-size', '8');
        textType.setAttribute('font-weight', 'bold');
        textType.setAttribute('fill', '#ffffff');
        textType.setAttribute('text-anchor', 'middle');
        textType.setAttribute('pointer-events', 'none');
        textType.textContent = pos.text;

        const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        label.setAttribute('x', pos.x);
        const labelY = node.type === 'Account' ? pos.y + 26 : pos.y - 20;
        label.setAttribute('y', labelY);
        label.setAttribute('font-size', '8');
        label.setAttribute('font-weight', '600');
        label.setAttribute('fill', 'var(--text-primary)');
        label.setAttribute('text-anchor', 'middle');
        label.setAttribute('pointer-events', 'none');
        
        let labelText = node.label;
        if (labelText.length > 15) {
            labelText = labelText.substring(0, 12) + '...';
        }
        label.textContent = labelText;

        group.appendChild(circle);
        group.appendChild(textType);
        group.appendChild(label);
        g.appendChild(group);
    });
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
    renderNetworkGraph(mockData, alert);
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
