/**
 * DB Sentinel — Core Frontend Application Logic
 * Integrates with Flask REST APIs, Chart.js visualizations, and security simulator.
 */

// Global API helper
const API = {
    async request(url, options = {}) {
        const token = localStorage.getItem('sentinel_token');
        const headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
            ...(options.headers || {})
        };

        try {
            const response = await fetch(url, { ...options, headers });
            if (response.status === 401) {
                // If not already on login page, redirect
                if (!window.location.pathname.includes('/login')) {
                    window.location.href = '/login';
                }
            }
            const data = await response.json();
            if (!response.ok && !options.ignoreError) {
                throw new Error(data.error || `HTTP error ${response.status}`);
            }
            return data;
        } catch (err) {
            console.error(`API Error [${url}]:`, err);
            throw err;
        }
    },

    get(url) {
        return this.request(url, { method: 'GET' });
    },

    post(url, body) {
        return this.request(url, { method: 'POST', body: JSON.stringify(body) });
    },

    put(url, body) {
        return this.request(url, { method: 'PUT', body: JSON.stringify(body) });
    }
};

// Toast notification helper
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const bgClass = type === 'success' ? 'bg-success' :
                    type === 'danger' || type === 'error' ? 'bg-danger' :
                    type === 'warning' ? 'bg-warning text-dark' : 'bg-primary';

    const toastEl = document.createElement('div');
    toastEl.className = `toast align-items-center text-white ${bgClass} border-0 mb-2`;
    toastEl.setAttribute('role', 'alert');
    toastEl.setAttribute('aria-live', 'assertive');
    toastEl.setAttribute('aria-atomic', 'true');
    toastEl.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                <i class="fas ${type === 'success' ? 'fa-check-circle' : type === 'danger' ? 'fa-exclamation-triangle' : 'fa-info-circle'} me-2"></i>
                ${escapeHtml(message)}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
    `;

    container.appendChild(toastEl);
    const toast = new bootstrap.Toast(toastEl, { delay: 4000 });
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function formatDate(isoStr) {
    if (!isoStr) return '—';
    try {
        const d = new Date(isoStr);
        return d.toLocaleString(undefined, {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    } catch {
        return isoStr;
    }
}

// -------------------------------------------------------------
// Authentication Controller
// -------------------------------------------------------------
const Auth = {
    async login(username, password) {
        try {
            const res = await API.post('/auth/login', { username, password });
            if (res.success && res.token) {
                localStorage.setItem('sentinel_token', res.token);
                localStorage.setItem('sentinel_user', JSON.stringify(res.user));
                window.location.href = '/';
            }
        } catch (err) {
            showToast(err.message || 'Login failed. Please check credentials.', 'danger');
        }
    },

    async register(username, password, role) {
        try {
            const res = await API.post('/auth/register', { username, password, role });
            if (res.success) {
                showToast('Registration successful! Please login.', 'success');
                setTimeout(() => window.location.href = '/login', 1000);
            }
        } catch (err) {
            showToast(err.message || 'Registration failed.', 'danger');
        }
    },

    async logout() {
        try {
            await API.post('/auth/logout', {});
        } catch (e) {
            // continue cleanup
        }
        localStorage.removeItem('sentinel_token');
        localStorage.removeItem('sentinel_user');
        window.location.href = '/login';
    },

    getUser() {
        try {
            return JSON.parse(localStorage.getItem('sentinel_user')) || null;
        } catch {
            return null;
        }
    }
};

// -------------------------------------------------------------
// Dashboard Analytics Controller
// -------------------------------------------------------------
const Dashboard = {
    queryChart: null,
    attackChart: null,
    riskChart: null,
    timer: null,

    async init() {
        await this.loadStats();
        // Refresh every 30 seconds
        this.timer = setInterval(() => this.loadStats(true), 30000);
    },

    async loadStats(isSilent = false) {
        try {
            const data = await API.get('/api/dashboard/stats');
            this.updateCards(data);
            this.renderCharts(data);
            this.renderRecentAlerts(data.recent_alerts || []);
            if (!isSilent) {
                const badge = document.getElementById('liveStatusBadge');
                if (badge) badge.innerHTML = '<span class="status-indicator status-online me-2"></span>Live Monitoring Active';
            }
        } catch (err) {
            console.error('Failed to load dashboard statistics:', err);
            if (!isSilent) showToast('Failed to load dashboard statistics', 'danger');
        }
    },

    updateCards(data) {
        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = (val !== undefined && val !== null) ? Number(val).toLocaleString() : '0';
        };

        setVal('statTotalQueries', data.total_queries);
        setVal('statBlockedQueries', data.blocked_queries);
        setVal('statFlaggedQueries', data.flagged_queries);
        setVal('statActiveAlerts', data.total_alerts);
    },

    renderCharts(data) {
        this.renderQueryTimeline(data.queries_last_24h || []);
        this.renderAttackDistribution(data.attack_type_distribution || {});
        this.renderRiskProfile(data);
    },

    renderQueryTimeline(hourlyData) {
        const ctx = document.getElementById('queryTimelineChart');
        if (!ctx) return;

        // Generate 24 hours labels
        const currentHour = new Date().getHours();
        const labels = [];
        const counts = [];
        const hourMap = {};

        hourlyData.forEach(item => {
            hourMap[item.hour] = item.count;
        });

        for (let i = 23; i >= 0; i--) {
            const h = (currentHour - i + 24) % 24;
            labels.push(`${h.toString().padStart(2, '0')}:00`);
            counts.push(hourMap[h] || 0);
        }

        if (this.queryChart) {
            this.queryChart.data.labels = labels;
            this.queryChart.data.datasets[0].data = counts;
            this.queryChart.update();
            return;
        }

        this.queryChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Queries',
                    data: counts,
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    borderWidth: 2,
                    tension: 0.35,
                    fill: true,
                    pointBackgroundColor: '#00d4ff',
                    pointBorderColor: '#0a0e17',
                    pointRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#94a3b8', maxRotation: 0, autoSkip: true, maxTicksLimit: 8 }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#94a3b8', precision: 0 }
                    }
                }
            }
        });
    },

    renderAttackDistribution(attackMap) {
        const ctx = document.getElementById('attackDistChart');
        if (!ctx) return;

        const keys = Object.keys(attackMap);
        const values = Object.values(attackMap);

        const labels = keys.length ? keys.map(k => k.replace(/_/g, ' ').toUpperCase()) : ['No Attacks'];
        const data = keys.length ? values : [1];
        const bgColors = keys.length ? ['#ef4444', '#f59e0b', '#7c3aed', '#00d4ff', '#10b981'] : ['#1e293b'];

        if (this.attackChart) {
            this.attackChart.data.labels = labels;
            this.attackChart.data.datasets[0].data = data;
            this.attackChart.data.datasets[0].backgroundColor = bgColors;
            this.attackChart.update();
            return;
        }

        this.attackChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: bgColors,
                    borderColor: '#111827',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', boxWidth: 12, padding: 12 }
                    }
                },
                cutout: '68%'
            }
        });
    },

    renderRiskProfile(data) {
        const ctx = document.getElementById('riskProfileChart');
        if (!ctx) return;

        const safe = data.safe_queries || 0;
        const flagged = data.flagged_queries || 0;
        const blocked = data.blocked_queries || 0;

        if (this.riskChart) {
            this.riskChart.data.datasets[0].data = [safe, flagged, blocked];
            this.riskChart.update();
            return;
        }

        this.riskChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Safe', 'Flagged', 'Blocked'],
                datasets: [{
                    data: [safe, flagged, blocked],
                    backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8' }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255,255,255,0.05)' },
                        ticks: { color: '#94a3b8', precision: 0 }
                    }
                }
            }
        });
    },

    renderRecentAlerts(alerts) {
        const tbody = document.getElementById('recentAlertsTbody');
        if (!tbody) return;

        if (!alerts.length) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-center text-secondary py-4">No recent security alerts recorded.</td></tr>';
            return;
        }

        tbody.innerHTML = alerts.map(a => `
            <tr>
                <td><span class="badge ${getSeverityBadge(a.severity)}">${escapeHtml(a.severity)}</span></td>
                <td class="fw-semibold text-light">${escapeHtml(a.attack_type)}</td>
                <td class="text-secondary small text-truncate" style="max-width: 250px;">${escapeHtml(a.description)}</td>
                <td class="text-secondary small">${formatDate(a.created_at)}</td>
                <td>
                    <span class="badge ${a.is_reviewed ? 'bg-secondary' : 'bg-warning text-dark'}">
                        ${a.is_reviewed ? 'Reviewed' : 'Active'}
                    </span>
                </td>
            </tr>
        `).join('');
    }
};

function getSeverityBadge(sev) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return 'bg-danger';
    if (s === 'HIGH') return 'bg-orange';
    if (s === 'MEDIUM' || s === 'WARNING') return 'bg-warning text-dark';
    return 'bg-info text-dark';
}

function getClassificationBadge(cls) {
    const c = (cls || '').toUpperCase();
    if (c === 'BLOCKED') return 'risk-badge risk-blocked';
    if (c === 'FLAGGED') return 'risk-badge risk-flagged';
    if (c === 'SUSPICIOUS') return 'risk-badge risk-suspicious';
    return 'risk-badge risk-safe';
}

// -------------------------------------------------------------
// Query Simulator & Attack Detection Controller
// -------------------------------------------------------------
const QuerySimulator = {
    presets: {
        safe: "SELECT department, COUNT(*) AS head_count, ROUND(AVG(salary), 2) AS avg_dept_salary\nFROM employees\nGROUP BY department;",
        differencing: "-- Differencing Attack: Isolating Sarah Johnson (Lead Security Architect)\nSELECT AVG(salary) AS target_salary\nFROM employees\nWHERE department = 'IT' AND designation = 'Lead Security Architect';",
        small_set: "-- Small Set Attack: Identifying specific employee via unique identifier filter\nSELECT first_name, designation, salary\nFROM employees\nWHERE employee_id = 2;",
        attribute: "-- Attribute Inference: Reconstructing confidential compensation via auxiliary attributes\nSELECT salary, ssn_last4\nFROM employees\nWHERE department = 'Finance' AND city = 'Greenwich' AND gender = 'F';",
        repeated: "-- Repeated Query Probe: Iterative sequential department queries\nSELECT AVG(salary) FROM employees WHERE department = 'IT' AND salary > 120000;"
    },

    loadPreset(name) {
        const input = document.getElementById('queryInput');
        if (input && this.presets[name]) {
            input.value = this.presets[name];
        }
    },

    async analyze() {
        const queryText = (document.getElementById('queryInput')?.value || '').trim();
        if (!queryText) {
            showToast('Please enter an SQL query to analyze.', 'warning');
            return;
        }

        const btn = document.getElementById('btnAnalyze');
        if (btn) btn.disabled = true;

        try {
            const result = await API.post('/api/query/analyze', { query: queryText });
            this.displayAnalysis(result);
            showToast('Analysis completed successfully.', 'success');
        } catch (err) {
            showToast(err.message || 'Failed to analyze query', 'danger');
        } finally {
            if (btn) btn.disabled = false;
        }
    },

    async execute() {
        const queryText = (document.getElementById('queryInput')?.value || '').trim();
        if (!queryText) {
            showToast('Please enter an SQL query to execute.', 'warning');
            return;
        }

        const btn = document.getElementById('btnExecute');
        if (btn) btn.disabled = true;

        try {
            const result = await API.post('/api/query/execute', { query: queryText });
            this.displayAnalysis(result);
            this.displayExecutionResults(result.results || []);
            showToast('Query executed safely against employee database.', 'success');
        } catch (err) {
            // Check if blocked by security
            if (err.message && err.message.toLowerCase().includes('blocked')) {
                showToast('SECURITY BLOCK: Query terminated by DB Sentinel!', 'danger');
            } else {
                showToast(err.message || 'Execution failed', 'danger');
            }
            // If error payload has details, still render them
            if (err.risk_score !== undefined || err.classification) {
                this.displayAnalysis(err);
            }
        } finally {
            if (btn) btn.disabled = false;
        }
    },

    displayAnalysis(data) {
        const panel = document.getElementById('analysisResultPanel');
        if (!panel) return;
        panel.style.display = 'block';

        const riskScore = Math.round((data.risk_score || 0) * 100);
        const classification = (data.classification || 'SAFE').toUpperCase();

        // Update Gauge & Badge
        const scoreVal = document.getElementById('riskScoreValue');
        if (scoreVal) scoreVal.textContent = `${riskScore}%`;

        const meterBar = document.getElementById('riskScoreBar');
        if (meterBar) {
            meterBar.style.width = `${riskScore}%`;
            meterBar.className = `progress-bar ${riskScore >= 80 ? 'bg-danger' : riskScore >= 50 ? 'bg-warning' : riskScore >= 30 ? 'bg-info' : 'bg-success'}`;
        }

        const classBadge = document.getElementById('classificationBadge');
        if (classBadge) {
            classBadge.className = getClassificationBadge(classification);
            classBadge.textContent = classification;
        }

        // ML vs Rule score indicators
        const mlScoreEl = document.getElementById('mlAnomalyScore');
        if (mlScoreEl) mlScoreEl.textContent = `${Math.round((data.ml_score || 0) * 100)}%`;

        const ruleScoreEl = document.getElementById('ruleScore');
        const ruleVal = data.details?.rule_score !== undefined ? data.details.rule_score : data.risk_score;
        if (ruleScoreEl) ruleScoreEl.textContent = `${Math.round((ruleVal || 0) * 100)}%`;

        // Attack types tags
        const attackContainer = document.getElementById('detectedAttacksList');
        if (attackContainer) {
            const attacks = data.attack_types || [];
            if (attacks.length) {
                attackContainer.innerHTML = attacks.map(at => `
                    <span class="badge bg-danger bg-opacity-25 text-danger border border-danger me-1 mb-1 p-2">
                        <i class="fas fa-shield-virus me-1"></i>${escapeHtml(at.toUpperCase())}
                    </span>
                `).join('');
            } else {
                attackContainer.innerHTML = '<span class="badge bg-success bg-opacity-25 text-success border border-success p-2"><i class="fas fa-check-circle me-1"></i>No Attack Patterns Detected</span>';
            }
        }

        // Attack details breakdown cards
        const detailsContainer = document.getElementById('attackDetailsContainer');
        if (detailsContainer && data.details) {
            const d = data.details;
            let html = '';

            const types = [
                { key: 'differencing', name: 'Differencing Attack', icon: 'fa-balance-scale' },
                { key: 'small_set', name: 'Small-Set / Cardinality Attack', icon: 'fa-compress-arrows-alt' },
                { key: 'repeated', name: 'Repeated Query Anomaly', icon: 'fa-history' },
                { key: 'attribute', name: 'Attribute Inference', icon: 'fa-user-secret' }
            ];

            types.forEach(t => {
                const item = d[t.key] || {};
                const score = Math.round((item.score || 0) * 100);
                const hasThreat = score > 30;

                html += `
                    <div class="col-md-6 mb-3">
                        <div class="card h-100 p-3" style="border-left: 4px solid ${hasThreat ? '#ef4444' : '#10b981'};">
                            <div class="d-flex justify-content-between align-items-center mb-2">
                                <span class="fw-semibold text-light"><i class="fas ${t.icon} me-2 text-cyan"></i>${t.name}</span>
                                <span class="badge ${hasThreat ? 'bg-danger' : 'bg-success'}">${score}%</span>
                            </div>
                            <p class="small text-secondary mb-0">${escapeHtml(item.reason || item.message || (hasThreat ? 'Suspicious pattern identified.' : 'No significant pattern match.'))}</p>
                        </div>
                    </div>
                `;
            });

            detailsContainer.innerHTML = html;
        }
    },

    displayExecutionResults(rows) {
        const resultsCard = document.getElementById('executionResultsCard');
        const thead = document.getElementById('resultsTableHead');
        const tbody = document.getElementById('resultsTableBody');
        const rowCount = document.getElementById('resultsRowCount');

        if (!resultsCard || !thead || !tbody) return;
        resultsCard.style.display = 'block';

        if (!rows || !rows.length) {
            thead.innerHTML = '';
            tbody.innerHTML = '<tr><td class="text-center text-secondary py-3">Query returned 0 rows.</td></tr>';
            if (rowCount) rowCount.textContent = '0 rows';
            return;
        }

        if (rowCount) rowCount.textContent = `${rows.length} rows returned`;

        const columns = Object.keys(rows[0]);
        thead.innerHTML = `<tr>${columns.map(c => `<th>${escapeHtml(c)}</th>`).join('')}</tr>`;

        tbody.innerHTML = rows.slice(0, 50).map(row => `
            <tr>${columns.map(c => `<td>${escapeHtml(String(row[c] !== null && row[c] !== undefined ? row[c] : 'NULL'))}</td>`).join('')}</tr>
        `).join('');
    }
};

// -------------------------------------------------------------
// Security Alerts Management
// -------------------------------------------------------------
const AlertsPage = {
    async load(page = 1) {
        const severity = document.getElementById('filterSeverity')?.value || '';
        const url = `/api/alerts?page=${page}&per_page=20${severity ? `&severity=${severity}` : ''}`;

        try {
            const res = await API.get(url);
            this.renderTable(res.alerts || []);
        } catch (err) {
            showToast('Failed to load security alerts', 'danger');
        }
    },

    renderTable(alerts) {
        const tbody = document.getElementById('alertsTableBody');
        if (!tbody) return;

        if (!alerts.length) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center text-secondary py-4">No security alerts matching criteria.</td></tr>';
            return;
        }

        tbody.innerHTML = alerts.map(a => `
            <tr>
                <td class="fw-bold">#${a.id}</td>
                <td><span class="badge ${getSeverityBadge(a.severity)}">${escapeHtml(a.severity)}</span></td>
                <td class="text-cyan fw-semibold">${escapeHtml(a.attack_type)}</td>
                <td class="text-secondary small" style="max-width: 300px;">${escapeHtml(a.description)}</td>
                <td class="small text-secondary">${formatDate(a.created_at)}</td>
                <td>
                    <span class="badge ${a.is_reviewed ? 'bg-secondary' : 'bg-warning text-dark'}">
                        ${a.is_reviewed ? 'Reviewed' : 'Active'}
                    </span>
                </td>
                <td>
                    ${!a.is_reviewed ? `
                        <button class="btn btn-sm btn-outline-cyan" onclick="AlertsPage.markReviewed(${a.id})">
                            <i class="fas fa-check me-1"></i>Acknowledge
                        </button>
                    ` : '<span class="text-secondary small">Resolved</span>'}
                </td>
            </tr>
        `).join('');
    },

    async markReviewed(id) {
        try {
            await API.put(`/api/alerts/${id}/review`, {});
            showToast(`Alert #${id} marked as reviewed`, 'success');
            this.load();
        } catch (err) {
            showToast(err.message || 'Action failed', 'danger');
        }
    }
};

// -------------------------------------------------------------
// Query History Controller
// -------------------------------------------------------------
const QueryHistoryPage = {
    async load(page = 1) {
        try {
            const res = await API.get(`/api/queries?page=${page}&per_page=25`);
            this.renderTable(res.queries || []);
        } catch (err) {
            showToast('Failed to load query history', 'danger');
        }
    },

    renderTable(queries) {
        const tbody = document.getElementById('queriesTableBody');
        if (!tbody) return;

        if (!queries.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-secondary py-4">No historical queries recorded.</td></tr>';
            return;
        }

        tbody.innerHTML = queries.map(q => {
            const riskPct = Math.round((q.risk_score || 0) * 100);
            return `
                <tr>
                    <td class="fw-bold">#${q.id}</td>
                    <td>
                        <code class="text-info small text-truncate d-block" style="max-width: 400px;" title="${escapeHtml(q.query_text)}">
                            ${escapeHtml(q.query_text)}
                        </code>
                    </td>
                    <td>
                        <span class="${getClassificationBadge(q.classification)}">
                            ${escapeHtml(q.classification)}
                        </span>
                    </td>
                    <td>
                        <div class="d-flex align-items-center">
                            <span class="me-2 small ${riskPct >= 80 ? 'text-danger' : riskPct >= 50 ? 'text-warning' : 'text-success'} fw-bold">${riskPct}%</span>
                            <div class="progress flex-grow-1" style="height: 6px; width: 60px;">
                                <div class="progress-bar ${riskPct >= 80 ? 'bg-danger' : riskPct >= 50 ? 'bg-warning' : 'bg-success'}" style="width: ${riskPct}%"></div>
                            </div>
                        </div>
                    </td>
                    <td>${q.is_blocked ? '<span class="badge bg-danger">BLOCKED</span>' : '<span class="badge bg-success">EXECUTED</span>'}</td>
                    <td class="small text-secondary">${formatDate(q.created_at)}</td>
                </tr>
            `;
        }).join('');
    }
};

// -------------------------------------------------------------
// Tamper-Evident Audit Chain Controller
// -------------------------------------------------------------
const AuditPage = {
    async load() {
        try {
            const res = await API.get('/api/audit/logs?limit=50');
            this.renderTable(res.logs || []);
        } catch (err) {
            showToast('Failed to load audit logs', 'danger');
        }
    },

    renderTable(logs) {
        const tbody = document.getElementById('auditTableBody');
        if (!tbody) return;

        if (!logs.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-center text-secondary py-4">No audit logs available.</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => `
            <tr>
                <td class="fw-bold">#${l.id}</td>
                <td><span class="badge bg-secondary">${escapeHtml(l.action)}</span></td>
                <td class="small text-secondary text-truncate" style="max-width: 280px;" title="${escapeHtml(l.details || '')}">${escapeHtml(l.details || '—')}</td>
                <td>
                    <code class="small text-cyan text-truncate d-block" style="max-width: 140px;" title="${escapeHtml(l.hash)}">
                        ${escapeHtml(l.hash ? l.hash.substring(0, 16) + '...' : '—')}
                    </code>
                </td>
                <td>
                    <code class="small text-secondary text-truncate d-block" style="max-width: 140px;" title="${escapeHtml(l.prev_hash)}">
                        ${escapeHtml(l.prev_hash ? l.prev_hash.substring(0, 16) + '...' : 'GENESIS')}
                    </code>
                </td>
                <td class="small text-secondary">${formatDate(l.created_at)}</td>
            </tr>
        `).join('');
    },

    async verifyIntegrity() {
        const banner = document.getElementById('verificationBanner');
        const btn = document.getElementById('btnVerifyChain');
        if (btn) btn.disabled = true;

        try {
            const res = await API.get('/api/audit/verify');
            if (banner) {
                banner.style.display = 'block';
                if (res.valid) {
                    banner.className = 'alert alert-success d-flex align-items-center mb-4';
                    banner.innerHTML = `
                        <i class="fas fa-check-double fa-2x me-3"></i>
                        <div>
                            <h6 class="alert-heading mb-1 fw-bold">Audit Chain Integrity Verified</h6>
                            <p class="mb-0 small">All SHA-256 block hashes are intact and validated against the genesis block. Zero tampering detected.</p>
                        </div>
                    `;
                    showToast('Audit log chain is cryptographically intact!', 'success');
                } else {
                    banner.className = 'alert alert-danger d-flex align-items-center mb-4';
                    banner.innerHTML = `
                        <i class="fas fa-radiation-alt fa-2x me-3"></i>
                        <div>
                            <h6 class="alert-heading mb-1 fw-bold">INTEGRITY BREACH DETECTED</h6>
                            <p class="mb-0 small">Audit log validation failed at Record ID: <strong>#${res.broken_at_id}</strong>. Hashes do not match expected cryptographic sequence.</p>
                        </div>
                    `;
                    showToast('SECURITY WARNING: Cryptographic hash chain mismatch!', 'danger');
                }
            }
        } catch (err) {
            showToast(err.message || 'Verification failed', 'danger');
        } finally {
            if (btn) btn.disabled = false;
        }
    }
};
