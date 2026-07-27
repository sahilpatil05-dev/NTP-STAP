/**
 * NTP-SCTAP — Premium Core Client-Side JavaScript (v2.0.0 — FIXED)
 *
 * Implements:
 *   - Socket.IO WebSockets client real-time integration
 *   - SPA navigation controller
 *   - Covert message transmitter API client
 *   - System resource monitoring gauges (CPU, RAM, Sockets)
 *   - Packet Inspector & Chronological Lifecycle Timelines
 *   - Interactive Protocol Learning Mode
 *   - Session Replay playback automation
 *   - Advanced analytics dashboards & multi-chart visuals
 *   - Export center file downloads
 *
 * Fixed Issues (v2.0.0):
 *   ✓ Socket.IO null check
 *   ✓ Safe DOM queries with fallbacks
 *   ✓ IP validation (IPv4 + hostname support)
 *   ✓ API response status checking
 *   ✓ Console buffer memory management
 *   ✓ Session replay timeout cleanup
 *   ✓ Real-time update deduplication with size limits
 *   ✓ Dashboard refresh debouncing
 *   ✓ Chart update optimization (no recreate)
 *   ✓ Reconnection event handling
 *   ✓ Fetch timeout support
 *   ✓ Dynamic replay speed adjustment
 *   ✓ Loading indicators with element resolution
 *   ✓ Button state management
 */

(function () {
    'use strict';

    /* ───────────────────────────────────────────────────────────────
       0. Constants & Configuration
       ─────────────────────────────────────────────────────────────── */
    
    // DOM Element IDs (cached at startup)
    const DOM_IDS = {
        // Layout
        sidebar: 'sidebar',
        toggleBtn: 'sidebar-toggle',
        pageTitle: 'page-title',
        
        // Connection
        connStatus: '#topbar-connection .status-dot',
        connText: '#topbar-connection span:last-child',
        systemStatusDot: 'system-status-dot',
        systemStatusText: 'system-status-text',
        
        // Monitor
        monitorCpu: 'monitor-cpu',
        monitorRam: 'monitor-ram',
        monitorDb: 'monitor-db',
        monitorDbSize: 'monitor-db-size',
        monitorPps: 'monitor-pps',
        monitorReceiver: 'monitor-receiver',
        monitorClients: 'monitor-clients',
        healthBadge: 'health-badge',
        
        // Packets
        packetsFilter: 'pkt-filter-direction',
        packetsRefresh: 'pkt-refresh-btn',
        packetsTbody: 'packets-tbody',
        
        // Messages
        messagesFilter: 'msg-filter-direction',
        messagesRefresh: 'msg-refresh-btn',
        messagesTbody: 'messages-tbody',
        
        // Threats
        threatsRefresh: 'threats-refresh-btn',
        threatsTbody: 'threats-tbody',
        
        // Sessions
        sessionsRefresh: 'sessions-refresh-btn',
        sessionsTbody: 'sessions-tbody',
        
        // Logs
        logsRefresh: 'logs-refresh-btn',
        errorsTbody: 'errors-tbody',
        
        // Forms
        transmitterForm: 'transmitter-form',
        txMessage: 'tx-message',
        txPassword: 'tx-password',
        txHost: 'tx-host',
        txPort: 'tx-port',
        exportForm: 'export-form',
        
        // Console
        activityConsole: 'activity-console',
        
        // Inspector
        inspectorPlaceholder: 'inspector-placeholder',
        inspectorContent: 'inspector-content',
        
        // Charts
        trafficChart: 'traffic-chart',
        decryptChart: 'decrypt-chart',
        rateBandwidthChart: 'rate-bandwidth-chart',
        usageChart: 'usage-distribution-chart',
        cryptoChart: 'crypto-stats-chart',
        threatTrendChart: 'threat-trend-chart',
    };

    const CONFIG = {
        SOCKET_TIMEOUT: 5000,
        CONSOLE_MAX_LINES: 200,
        DASHBOARD_DEBOUNCE_MS: 2000,
        FETCH_TIMEOUT_MS: 10000,
        DEDUP_CACHE_MAX_SIZE: 1000,
        IP_REGEX: /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/,
        HOSTNAME_REGEX: /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/,
    };

    /* ───────────────────────────────────────────────────────────────
       1. Socket.IO Initialization with Safety Checks
       ─────────────────────────────────────────────────────────────── */
    
    if (typeof io === 'undefined') {
        console.error('Socket.IO library not loaded. Real-time updates disabled.');
        document.body.innerHTML = '<div style="padding: 20px; color: red;"><strong>Error:</strong> Socket.IO not available. Refresh page.</div>';
        throw new Error('Socket.IO initialization failed');
    }

    const socket = io({
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000
    });
    
    // Chart references
    let trafficChart = null;
    let decryptChart = null;
    let bandwidthChart = null;
    let usageChart = null;
    let cryptoChart = null;
    let threatTrendChart = null;

    // Active session replay state
    let replaySteps = [];
    let replayIndex = 0;
    let replayIntervalId = null;
    let isPlayingReplay = false;
    let replayTimeoutIds = [];

    // Debouncing & throttling
    let dashboardRefreshTimeout = null;
    let lastPacketUpdate = {};
    let lastMessageUpdate = {};
    let lastThreatUpdate = {};

    // Real-time Clock
    const clockEl = document.getElementById('topbar-clock');
    function updateClock() {
        if (!clockEl) return;
        clockEl.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
    }
    setInterval(updateClock, 1000);
    updateClock();

    /* ───────────────────────────────────────────────────────────────
       2. SPA Page Routing Controller
       ─────────────────────────────────────────────────────────────── */
    const navLinks = document.querySelectorAll('.nav-link[data-page]');
    const pageTitle = document.getElementById(DOM_IDS.pageTitle);
    const sidebar = document.getElementById(DOM_IDS.sidebar);
    const toggleBtn = document.getElementById(DOM_IDS.toggleBtn);

    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener('click', () => {
            sidebar.classList.toggle('open');
            sidebar.classList.toggle('collapsed');
        });
    }

    const PAGE_TITLES = {
        dashboard: 'Security Dashboard & Resource Monitor',
        packets:   'Packet Monitor & Deep Inspector',
        messages:  'Covert Communications Log',
        threats:   'Threat Detection & Security Auditing',
        analytics: 'System Performance Analytics',
        sessions:  'Communication Session Replays',
        logs:      'System Administration & Export Center',
    };

    function navigateTo(pageName) {
        document.querySelectorAll('.page-view').forEach(p => p.classList.remove('active'));
        const target = document.getElementById('page-' + pageName);
        if (target) target.classList.add('active');

        navLinks.forEach(link => {
            link.classList.toggle('active', link.dataset.page === pageName);
        });

        if (pageTitle) pageTitle.textContent = PAGE_TITLES[pageName] || 'Dashboard';

        if (window.innerWidth <= 768 && sidebar) {
            sidebar.classList.remove('open');
            sidebar.classList.add('collapsed');
        }

        loadPageData(pageName);
    }

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            navigateTo(link.dataset.page);
        });
    });

    function loadPageData(page) {
        switch (page) {
            case 'dashboard':  loadDashboard();   break;
            case 'packets':    loadPackets();      break;
            case 'messages':   loadMessages();     break;
            case 'threats':    loadThreats();      break;
            case 'analytics':  loadAnalytics();    break;
            case 'sessions':   loadSessions();     break;
            case 'logs':       loadErrors();       break;
        }
    }

    /* ── Helper utilities ─────────────────────────────────────────── */
    
    async function apiFetch(url, options = {}) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.FETCH_TIMEOUT_MS);

        try {
            const res = await fetch(url, { 
                ...options,
                signal: controller.signal 
            });
            
            clearTimeout(timeoutId);
            
            if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            }
            
            return await res.json();
        } catch (err) {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError') {
                console.warn('API request timeout:', url);
            } else {
                console.warn('API fetch failed:', url, err.message);
            }
            return null;
        }
    }

    async function apiPost(url, payload) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.FETCH_TIMEOUT_MS);

        try {
            const res = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (!res.ok) {
                throw new Error(`HTTP ${res.status}: ${res.statusText}`);
            }
            
            return await res.json();
        } catch (err) {
            clearTimeout(timeoutId);
            if (err.name === 'AbortError') {
                console.error('API post timeout:', url);
                return { status: 'error', error: 'Request timeout. Please try again.' };
            } else {
                console.error('API post failed:', url, err.message);
                return { status: 'error', error: err.message };
            }
        }
    }

    function safeGetElement(id) {
        const el = document.getElementById(id);
        if (!el) {
            console.warn(`DOM element not found: ${id}`);
        }
        return el;
    }

    function shortId(id) {
        if (!id) return '—';
        return id.length > 10 ? id.slice(0, 10) + '…' : id;
    }

    function fmtTime(iso) {
        if (!iso) return '—';
        try {
            const d = new Date(iso);
            return d.toLocaleTimeString('en-GB', { hour12: false }) + ' ' +
                   d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
        } catch { return iso; }
    }

    function makeTag(value) {
        if (!value) return '<span class="tag tag-none">—</span>';
        const cls = 'tag-' + value.toLowerCase().replace(/[^a-z]/g, '');
        return `<span class="tag ${cls}">${value.toUpperCase()}</span>`;
    }

    function setText(id, value) {
        const el = safeGetElement(id);
        if (el) el.textContent = value !== undefined && value !== null ? value : '—';
    }

    function validateIpOrHostname(host) {
        return CONFIG.IP_REGEX.test(host) || CONFIG.HOSTNAME_REGEX.test(host);
    }

    /* ───────────────────────────────────────────────────────────────
       3. WebSocket Real-Time Event Handlers
       ─────────────────────────────────────────────────────────────── */
    
    socket.on('connect', () => {
        const connDot = document.querySelector(DOM_IDS.connStatus);
        const connTxt = document.querySelector(DOM_IDS.connText);
        const sideDot = safeGetElement(DOM_IDS.systemStatusDot);
        const sideTxt = safeGetElement(DOM_IDS.systemStatusText);

        if (connDot) connDot.className = 'status-dot online';
        if (connTxt) connTxt.textContent = 'Connected (WS)';
        if (sideDot) sideDot.className = 'status-dot online';
        if (sideTxt) sideTxt.textContent = 'System Online';
        
        appendConsole(DOM_IDS.activityConsole, 'info', 'Real-Time WebSocket Link Established.');
    });

    socket.on('disconnect', () => {
        const connDot = document.querySelector(DOM_IDS.connStatus);
        const connTxt = document.querySelector(DOM_IDS.connText);
        const sideDot = safeGetElement(DOM_IDS.systemStatusDot);
        const sideTxt = safeGetElement(DOM_IDS.systemStatusText);

        if (connDot) connDot.className = 'status-dot offline';
        if (connTxt) connTxt.textContent = 'Disconnected';
        if (sideDot) sideDot.className = 'status-dot offline';
        if (sideTxt) sideTxt.textContent = 'System Offline';
        
        appendConsole(DOM_IDS.activityConsole, 'error', 'WebSocket Connection Lost. Retrying...');
    });

    // Reconnection events (new in v2.0)
    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
        appendConsole(DOM_IDS.activityConsole, 'error', `Connection Error: ${error.message}`);
    });

    socket.on('reconnect_attempt', (attempt) => {
        console.log('Reconnection attempt #' + attempt);
        appendConsole(DOM_IDS.activityConsole, 'warn', `Reconnecting... Attempt #${attempt}`);
    });

    socket.on('reconnect', () => {
        appendConsole(DOM_IDS.activityConsole, 'success', 'Reconnected to server.');
    });

    // Real-Time System Monitoring update
    socket.on('system_monitoring', (data) => {
        if (!data) return;
        
        setText(DOM_IDS.monitorCpu, data.cpu_usage + '%');
        setText(DOM_IDS.monitorRam, data.memory_usage + '%');
        setText(DOM_IDS.monitorDb, data.db_status?.toUpperCase?.() || 'UNKNOWN');
        setText(DOM_IDS.monitorDbSize, (data.db_size_bytes / 1024).toFixed(1) + ' KB');
        setText(DOM_IDS.monitorPps, data.packets_per_second?.toFixed?.(2) || '0' + ' PPS');
        setText(DOM_IDS.monitorReceiver, data.receiver_running ? 'Listening' : 'Stopped');
        setText(DOM_IDS.monitorClients, data.connected_clients + ' Clients');
        
        const healthBadge = safeGetElement(DOM_IDS.healthBadge);
        if (healthBadge) {
            healthBadge.textContent = data.system_health?.toUpperCase?.() || 'UNKNOWN';
            healthBadge.className = 'badge ' + 
                (data.system_health === 'healthy' ? 'badge-green' : 
                 data.system_health === 'degraded' ? 'badge-amber' : 'badge-red');
        }
        
        const cpuEl = safeGetElement(DOM_IDS.monitorCpu);
        if (cpuEl) cpuEl.className = 'health-value ' + (data.cpu_usage > 85 ? 'offline' : 'online');
        
        const ramEl = safeGetElement(DOM_IDS.monitorRam);
        if (ramEl) ramEl.className = 'health-value ' + (data.memory_usage > 90 ? 'offline' : 'online');

        const recvEl = safeGetElement(DOM_IDS.monitorReceiver);
        if (recvEl) recvEl.className = 'health-value ' + (data.receiver_running ? 'online' : 'offline');
    });

    // Real-Time Packets arrival (with deduplication and cache limit)
    socket.on('packet_activity', (packet) => {
        if (!packet || lastPacketUpdate[packet.id]) return;
        
        lastPacketUpdate[packet.id] = true;
        if (Object.keys(lastPacketUpdate).length > CONFIG.DEDUP_CACHE_MAX_SIZE) {
            lastPacketUpdate = {};
        }
        
        appendConsole(DOM_IDS.activityConsole, packet.direction === 'sent' ? 'info' : 'success', 
            `${packet.direction.toUpperCase()} Packet ${shortId(packet.id)} | Size: ${packet.packet_size}B | Host: ${packet.source_host}`);
            
        const tbody = safeGetElement(DOM_IDS.packetsTbody);
        if (tbody && !tbody.querySelector(`[data-pkt-id="${packet.id}"]`)) {
            const emptyRow = tbody.querySelector('.table-empty');
            if (emptyRow) tbody.innerHTML = '';
            
            const tr = document.createElement('tr');
            tr.dataset.pktId = packet.id;
            tr.innerHTML = `
                <td title="${packet.id}">${shortId(packet.id)}</td>
                <td>${makeTag(packet.direction)}</td>
                <td>${packet.source_host}:${packet.source_port}</td>
                <td>${packet.dest_host}:${packet.dest_port}</td>
                <td>${packet.packet_size} B</td>
                <td>${makeTag(packet.payload_status)}</td>
                <td>${makeTag(packet.encryption_status)}</td>
                <td>${makeTag(packet.validation)}</td>
            `;
            tr.addEventListener('click', () => triggerPacketInspector(packet.id));
            tbody.insertBefore(tr, tbody.firstChild);
        }
        
        // Debounced dashboard refresh
        clearTimeout(dashboardRefreshTimeout);
        dashboardRefreshTimeout = setTimeout(() => {
            const dashPage = document.getElementById('page-dashboard');
            if (dashPage && dashPage.classList.contains('active')) {
                loadDashboard();
            }
        }, CONFIG.DASHBOARD_DEBOUNCE_MS);
    });

    // Real-Time Messages logs (with deduplication and cache limit)
    socket.on('message_activity', (msg) => {
        if (!msg || lastMessageUpdate[msg.id]) return;
        
        lastMessageUpdate[msg.id] = true;
        if (Object.keys(lastMessageUpdate).length > CONFIG.DEDUP_CACHE_MAX_SIZE) {
            lastMessageUpdate = {};
        }
        
        appendConsole(DOM_IDS.activityConsole, 'success', 
            `Recovered Plaintext: "${msg.plaintext}" [Session: ${shortId(msg.session_id)}]`);
            
        const tbody = safeGetElement(DOM_IDS.messagesTbody);
        if (tbody && !tbody.querySelector(`[data-msg-id="${msg.id}"]`)) {
            const emptyRow = tbody.querySelector('.table-empty');
            if (emptyRow) tbody.innerHTML = '';
            
            const tr = document.createElement('tr');
            tr.dataset.msgId = msg.id;
            tr.innerHTML = `
                <td title="${msg.id}">${shortId(msg.id)}</td>
                <td>${makeTag(msg.direction)}</td>
                <td title="${msg.plaintext}"><strong>${msg.plaintext}</strong></td>
                <td>${makeTag(msg.status)}</td>
                <td title="${msg.session_id}">${shortId(msg.session_id)}</td>
                <td>${fmtTime(msg.created_at)}</td>
            `;
            tbody.insertBefore(tr, tbody.firstChild);
        }
    });

    // Real-Time Threats detected (with deduplication and cache limit)
    socket.on('threat_activity', (threat) => {
        if (!threat || lastThreatUpdate[threat.id]) return;
        
        lastThreatUpdate[threat.id] = true;
        if (Object.keys(lastThreatUpdate).length > CONFIG.DEDUP_CACHE_MAX_SIZE) {
            lastThreatUpdate = {};
        }
        
        appendConsole(DOM_IDS.activityConsole, 'warn', 
            `!!! THREAT ALERT !!! Level: ${threat.threat_level.toUpperCase()} | Reason: ${threat.alert_reason}`);
            
        const tbody = safeGetElement(DOM_IDS.threatsTbody);
        if (tbody && !tbody.querySelector(`[data-threat-id="${threat.id}"]`)) {
            const emptyRow = tbody.querySelector('.table-empty');
            if (emptyRow) tbody.innerHTML = '';
            
            const tr = document.createElement('tr');
            tr.className = 'threat-row-alert';
            tr.dataset.threatId = threat.id;
            tr.innerHTML = `
                <td title="${threat.id}">${shortId(threat.id)}</td>
                <td>${makeTag(threat.threat_level)}</td>
                <td>${makeTag(threat.severity)}</td>
                <td>${(threat.confidence * 100).toFixed(0)}%</td>
                <td title="${threat.alert_reason}">${threat.alert_reason}</td>
                <td>${fmtTime(threat.detected_at)}</td>
            `;
            tr.addEventListener('click', () => triggerThreatInspector(threat));
            tbody.insertBefore(tr, tbody.firstChild);
        }

        loadThreats();
    });

    // Real-Time Analytics updates
    socket.on('analytics_activity', (metrics) => {
        const analyticsPage = document.getElementById('page-analytics');
        if (analyticsPage && analyticsPage.classList.contains('active')) {
            updateAnalyticsCharts(metrics);
        }
    });

    /* ───────────────────────────────────────────────────────────────
       4. Covert Message Transmitter Form
       ─────────────────────────────────────────────────────────────── */
    const transmitterForm = safeGetElement(DOM_IDS.transmitterForm);
    if (transmitterForm) {
        transmitterForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const msgInput = safeGetElement(DOM_IDS.txMessage);
            const passInput = safeGetElement(DOM_IDS.txPassword);
            const portInput = safeGetElement(DOM_IDS.txPort);
            const hostInput = safeGetElement(DOM_IDS.txHost);
            
            // Disable form while submitting
            const submitBtn = transmitterForm.querySelector('button[type="submit"]');
            if (submitBtn) submitBtn.disabled = true;
            
            try {
                const message = msgInput?.value.trim() || '';
                const password = passInput?.value.trim() || '';
                const port = Number(portInput?.value || 0);
                const host = hostInput?.value.trim() || '127.0.0.1';

                if (!message) {
                    appendConsole(DOM_IDS.activityConsole, 'error', 'Message cannot be empty.');
                    msgInput?.focus();
                    return;
                }

                if (!password) {
                    appendConsole(DOM_IDS.activityConsole, 'error', 'Password cannot be empty.');
                    passInput?.focus();
                    return;
                }

                if (!Number.isInteger(port) || port < 1 || port > 65535) {
                    appendConsole(DOM_IDS.activityConsole, 'error', 'Port must be between 1 and 65535.');
                    portInput?.focus();
                    return;
                }

                if (!validateIpOrHostname(host)) {
                    appendConsole(DOM_IDS.activityConsole, 'error', 'Invalid IP address or hostname.');
                    hostInput?.focus();
                    return;
                }

                const payload = {
                    plaintext: message,
                    password: password,
                    target_host: host,
                    target_port: port
                };
                
                appendConsole(DOM_IDS.activityConsole, 'info', `Deriving key and encrypting: "${payload.plaintext}"...`);
                const res = await apiPost('/api/messages/send', payload);
                
                if (res && res.status === 'success') {
                    msgInput.value = '';
                    appendConsole(DOM_IDS.activityConsole, 'success', `Covert transmission completed. MSG_ID: ${res.message_id}`);
                } else {
                    const error = res?.error || 'Unknown error';
                    appendConsole(DOM_IDS.activityConsole, 'error', `Transmission Failed: ${error}`);
                }
            } finally {
                if (submitBtn) submitBtn.disabled = false;
            }
        });
    }

    /* ───────────────────────────────────────────────────────────────
       5. Dashboard Controller
       ─────────────────────────────────────────────────────────────── */
    async function loadDashboard() {
        const data = await apiFetch('/api/dashboard');
        if (!data) return;

        const s = data.stats;
        setText('val-packets-sent', s.packets_sent);
        setText('val-packets-received', s.packets_received);
        setText('val-threats', s.threats_total);
        
        buildTrafficChart(s);
    }

    /* ───────────────────────────────────────────────────────────────
       6. Packets View & Deep Packet Inspector
       ─────────────────────────────────────────────────────────────── */
    async function loadPackets() {
        const filterEl = safeGetElement(DOM_IDS.packetsFilter);
        const dir = filterEl?.value || '';
        const url = dir ? `/api/packets?direction=${dir}&limit=50` : '/api/packets?limit=50';
        
        showLoading(DOM_IDS.packetsTbody, true);
        const data = await apiFetch(url);
        showLoading(DOM_IDS.packetsTbody, false);
        
        if (!data) return;

        const tbody = safeGetElement(DOM_IDS.packetsTbody);
        if (!tbody) return;

        if (!data.packets || data.packets.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="table-empty">No packets found.</td></tr>';
            return;
        }

        tbody.innerHTML = data.packets.map(p => `
            <tr class="packet-row-clickable" data-pkt-id="${p.id}">
                <td title="${p.id}">${shortId(p.id)}</td>
                <td>${makeTag(p.direction)}</td>
                <td>${p.source_host}:${p.source_port}</td>
                <td>${p.dest_host}:${p.dest_port}</td>
                <td>${p.packet_size} B</td>
                <td>${makeTag(p.payload_status)}</td>
                <td>${makeTag(p.encryption_status)}</td>
                <td>${makeTag(p.validation)}</td>
            </tr>
        `).join('');

        tbody.querySelectorAll('tr').forEach(row => {
            row.addEventListener('click', () => {
                const pktId = row.getAttribute('data-pkt-id');
                triggerPacketInspector(pktId);
            });
        });
    }

    safeGetElement(DOM_IDS.packetsFilter)?.addEventListener('change', loadPackets);
    safeGetElement(DOM_IDS.packetsRefresh)?.addEventListener('click', loadPackets);

    // Inspector Tabs Navigation
    const tabBtns = document.querySelectorAll('.ins-tab-btn');
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.ins-tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            const targetId = btn.id.replace('btn-', '') + '-content';
            document.getElementById(targetId)?.classList.add('active');
        });
    });

    // Deep Packet Inspector handler
    async function triggerPacketInspector(packetId) {
        const placeholder = safeGetElement(DOM_IDS.inspectorPlaceholder);
        const content = safeGetElement(DOM_IDS.inspectorContent);
        
        if (placeholder) placeholder.classList.add('hidden');
        if (content) {
            content.classList.remove('hidden');
            showLoading(content, true);
        }

        const data = await apiFetch(`/api/packets/${packetId}/inspect`);
        if (content) showLoading(content, false);
        
        if (!data) return;

        setText('ins-title', `Packet ${shortId(data.packet?.id)} Details`);
        const badge = document.getElementById('ins-direction-badge');
        if (badge) {
            badge.textContent = data.packet?.direction?.toUpperCase() || 'UNKNOWN';
            badge.className = 'badge ' + (data.packet?.direction === 'sent' ? 'badge-cyan' : 'badge-green');
        }

        // Render Lifecycle Timeline
        const timelineContainer = document.getElementById('ins-timeline-container');
        if (timelineContainer && data.timeline) {
            let timelineHtml = '';
            const t = data.timeline;
            
            const stages = [
                { key: 'created', label: '1. Created' },
                { key: 'encrypted', label: '2. Crypt GCM' },
                { key: 'queued', label: '3. Queued' },
                { key: 'transmitted', label: '4. Transmitted' }
            ];
            
            if (data.packet?.direction === 'received') {
                stages.push(
                    { key: 'received', label: '5. Received' },
                    { key: 'parsed', label: '6. Parsed' },
                    { key: 'threat_checked', label: '7. Scan Threat' },
                    { key: 'stored', label: '8. Stored' }
                );
            }

            stages.forEach((stage, idx) => {
                const ts = t[stage.key];
                const activeCls = ts ? 'stage-active' : 'stage-inactive';
                const timeStr = ts ? new Date(ts).toLocaleTimeString('en-GB', {fractionalSecondDigits: 3}) : '—';
                
                timelineHtml += `
                    <div class="timeline-step ${activeCls}">
                        <div class="step-label">${stage.label}</div>
                        <div class="step-time">${timeStr}</div>
                    </div>
                `;
                if (idx < stages.length - 1) {
                    timelineHtml += '<div class="timeline-arrow">→</div>';
                }
            });
            timelineContainer.innerHTML = timelineHtml;
        }

        // Render NTP Header Fields
        const f = data.fields || {};
        setText('ins-f-leap', f.leap + ' (' + getLeapText(f.leap) + ')');
        setText('ins-f-version', f.version);
        setText('ins-f-mode', f.mode + ' (' + getModeText(f.mode) + ')');
        setText('ins-f-stratum', f.stratum + ' (' + getStratumText(f.stratum) + ')');
        setText('ins-f-poll', f.poll + ' s (2^' + f.poll + ')');
        setText('ins-f-precision', f.precision + ' s (2^' + f.precision + ')');
        setText('ins-f-ref-id', f.ref_id + ' (0x' + f.ref_id_hex + ')');
        setText('ins-f-ref-time', fmtNtpTimestamp(f.ref_timestamp));
        setText('ins-f-origin-time', fmtNtpTimestamp(f.origin_timestamp));
        setText('ins-f-recv-time', fmtNtpTimestamp(f.recv_timestamp));
        setText('ins-f-tx-time', fmtNtpTimestamp(f.tx_timestamp));
        setText('ins-f-ext-len', f.extension_length + ' bytes');

        // Covert recovered text panel
        const covertBox = document.getElementById('ins-covert-box');
        if (covertBox) {
            setText('ins-c-status', data.packet?.payload_status);
            setText('ins-c-crypto', data.packet?.encryption_status);
            
            const payloadEl = document.getElementById('ins-c-payload');
            if (data.message?.plaintext) {
                payloadEl.textContent = data.message.plaintext;
                covertBox.className = 'payload-inspector-box active';
            } else if (data.packet?.payload_status === 'present') {
                payloadEl.innerHTML = `<em>Encrypted Ciphertext Block (${f.extension_length} B overhead). Decryption failed/pending password.</em>`;
                covertBox.className = 'payload-inspector-box suspicious';
            } else {
                payloadEl.textContent = '— No covert payload detected in this packet. Clean standard packet header.';
                covertBox.className = 'payload-inspector-box';
            }
        }

        // Render Raw Hex Dump
        const hexDumpEl = document.getElementById('ins-hex-dump');
        if (hexDumpEl) {
            hexDumpEl.textContent = data.hex_dump || '— No Hex Data —';
        }

        wireProtocolLearningFields();
    }

    // Protocol Learning Mode descriptions library
    const LEARNING_DATABASE = {
        leap: {
            title: "Leap Indicator (LI)",
            purpose: "A 2-bit code warning of an impending leap second to be inserted/deleted in the last minute of the current day.",
            normal: "00 (No warning), 01 (Last minute has 61 seconds), 10 (Last minute has 59 seconds).",
            security: "Value 11 ('Alarm condition', clock unsynchronized) is used by covert channels to signal receiver synchronization anomalies."
        },
        version: {
            title: "Version Number (VN)",
            purpose: "A 3-bit integer representing the NTP version. Currently, Version 4 (RFC 5905) is standard.",
            normal: "4 (Standard NTPv4). Versions 3 or older are legacy.",
            security: "Modified version numbers may bypass intrusion detection filters or indicate custom tunneling protocols."
        },
        mode: {
            title: "NTP Association Mode",
            purpose: "A 3-bit integer specifying the association mode of the packet (Client, Server, Symmetric, Broadcast).",
            normal: "3 (Client request), 4 (Server response).",
            security: "Custom covert tunnels often use mode 1/2 (Symmetric) to establish bi-directional relays."
        },
        stratum: {
            title: "Stratum Hierarchy Level",
            purpose: "An 8-bit integer indicating the distance of the host clock from the reference source.",
            normal: "0 (Unspecified), 1 (Primary reference clock), 2-15 (Secondary servers).",
            security: "High stratum values (e.g. 16) are common targets for payload injection."
        },
        poll: {
            title: "Poll Interval",
            purpose: "An 8-bit signed integer representing the maximum interval between packets (power of 2 seconds).",
            normal: "Between 4 (16s) and 17 (36.4 hours). Usually 6 (64s) or 10 (1024s).",
            security: "Extremely short poll intervals expose fast covert tunnels to timing-burst anomaly detectors."
        },
        precision: {
            title: "Precision of the Clock",
            purpose: "An 8-bit signed integer representing clock precision (power of 2 seconds).",
            normal: "Typically -18 to -20 (microsecond precision) on server-grade hardware.",
            security: "Anomalous precision levels can expose hardware virtualization or indicate simulated packets."
        },
        ref_id: {
            title: "Reference Source ID",
            purpose: "A 32-bit code identifying the particular reference clock source.",
            normal: "Standard GPS, PPS, LOCL, or the IP address of the upstream time server.",
            security: "This field represents 4 bytes of raw payload space. Advanced channels hide authentication tags here."
        },
        ref_timestamp: {
            title: "Reference Timestamp",
            purpose: "64-bit timestamp indicating when the system clock was last set or corrected.",
            normal: "Valid timestamp corresponding to synchronization history.",
            security: "Covert channels replace lower 32 fractional bits with ciphertext blocks."
        },
        origin_timestamp: {
            title: "Origin Timestamp",
            purpose: "64-bit timestamp indicating when the request departed the client.",
            normal: "Matches the client departure clock.",
            security: "Fractional bits can be manipulated for timing anomaly exploitation."
        },
        recv_timestamp: {
            title: "Receive Timestamp",
            purpose: "64-bit timestamp indicating when the request arrived at the server.",
            normal: "Logged automatically by the server socket.",
            security: "Critical for detecting timing anomalies in network transit latency."
        },
        tx_timestamp: {
            title: "Transmit Timestamp",
            purpose: "64-bit timestamp indicating when the packet departed the server.",
            normal: "Logged at network socket dispatch.",
            security: "Primary timestamp analyzed for delay jitter covert channels."
        },
        extension: {
            title: "Extension Fields Block",
            purpose: "Variable-length optional parameters after the 48-byte NTP header.",
            normal: "Standard NTP packets have zero extension fields (48 bytes total).",
            security: "Our covert channel utilizes custom extension field type 0x7363 for AES-256-GCM encrypted messages."
        }
    };

    function wireProtocolLearningFields() {
        const fields = document.querySelectorAll('.field-box[data-field]');
        fields.forEach(el => {
            el.removeEventListener('click', fieldClickHandler);
            el.addEventListener('click', fieldClickHandler);
        });
    }

    function fieldClickHandler() {
        const fields = document.querySelectorAll('.field-box[data-field]');
        fields.forEach(f => f.classList.remove('selected'));
        this.classList.add('selected');
        
        const fieldKey = this.getAttribute('data-field');
        const info = LEARNING_DATABASE[fieldKey];
        
        if (info) {
            const lCard = document.getElementById('learn-card');
            const lInstruction = document.querySelector('.learning-instruction');
            
            if (lCard) lCard.classList.remove('hidden');
            if (lInstruction) lInstruction.classList.add('hidden');
            
            setText('learn-field-title', info.title);
            setText('learn-field-purpose', info.purpose);
            setText('learn-field-normal', info.normal);
            setText('learn-field-security', info.security);
        }
    }

    function getLeapText(val) {
        const text = ["No Warning", "61s Leap", "59s Leap", "Alarm (Unsynchronized)"];
        return text[val] || "Unknown";
    }

    function getModeText(val) {
        const text = ["Reserved", "Symmetric Active", "Symmetric Passive", "Client", "Server", "Broadcast", "Control", "Private"];
        return text[val] || "Unknown";
    }

    function getStratumText(val) {
        if (val === 0) return "Kiss-o'-Death";
        if (val === 1) return "Primary Time Source";
        if (val >= 2 && val <= 15) return "Secondary Time Source";
        return "Unsynchronized / Invalid";
    }

    function fmtNtpTimestamp(val) {
        if (!val || val === 0) return "0 (Not set)";
        try {
            const unixTime = (val - 2208988800.0) * 1000.0;
            if (unixTime < 0) return val;
            return new Date(unixTime).toLocaleString('en-GB') + ` (${val.toFixed(3)})`;
        } catch {
            return val?.toFixed?.(3) || '—';
        }
    }

    /* ───────────────────────────────────────────────────────────────
       7. Messages View Controller
       ─────────────────────────────────────────────────────────────── */
    async function loadMessages() {
        const filterEl = safeGetElement(DOM_IDS.messagesFilter);
        const dir = filterEl?.value || '';
        const url = dir ? `/api/messages?direction=${dir}&limit=50` : '/api/messages?limit=50';
        
        showLoading(DOM_IDS.messagesTbody, true);
        const data = await apiFetch(url);
        showLoading(DOM_IDS.messagesTbody, false);
        
        if (!data) return;

        const tbody = safeGetElement(DOM_IDS.messagesTbody);
        if (!tbody) return;

        if (!data.messages || data.messages.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No covert messages recovered yet.</td></tr>';
            return;
        }

        tbody.innerHTML = data.messages.map(m => `
            <tr>
                <td title="${m.id}">${shortId(m.id)}</td>
                <td>${makeTag(m.direction)}</td>
                <td title="${m.plaintext || ''}"><strong>${m.plaintext || '— [CIPHERTEXT BLOCK] —'}</strong></td>
                <td>${makeTag(m.status)}</td>
                <td title="${m.session_id}">${shortId(m.session_id)}</td>
                <td>${fmtTime(m.created_at)}</td>
            </tr>
        `).join('');
    }

    safeGetElement(DOM_IDS.messagesFilter)?.addEventListener('change', loadMessages);
    safeGetElement(DOM_IDS.messagesRefresh)?.addEventListener('click', loadMessages);

    /* ───────────────────────────────────────────────────────────────
       8. Threat Intel Page & Trend Analytics
       ─────────────────────────────────────────────────────────────── */
    async function loadThreats() {
        const summary = await apiFetch('/api/threats/summary');
        if (summary) {
            setText('val-threat-critical', summary.critical);
            setText('val-threat-high', summary.high);
            setText('val-threat-medium', summary.medium);
            setText('val-threat-low', summary.low);
        }

        showLoading(DOM_IDS.threatsTbody, true);
        const data = await apiFetch('/api/threats?limit=50');
        showLoading(DOM_IDS.threatsTbody, false);
        
        if (!data) return;

        const tbody = safeGetElement(DOM_IDS.threatsTbody);
        if (!tbody) return;

        if (!data.threats || data.threats.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="table-empty">No threat signatures flagged.</td></tr>';
            return;
        }

        tbody.innerHTML = data.threats.map(t => `
            <tr class="threat-row-clickable" data-threat-id="${t.id}">
                <td title="${t.id}">${shortId(t.id)}</td>
                <td>${makeTag(t.threat_level)}</td>
                <td>${makeTag(t.severity)}</td>
                <td>${(t.confidence * 100).toFixed(0)}%</td>
                <td title="${t.alert_reason}">${t.alert_reason}</td>
                <td>${fmtTime(t.detected_at)}</td>
            </tr>
        `).join('');

        tbody.querySelectorAll('tr').forEach((row, idx) => {
            row.addEventListener('click', () => {
                if (data.threats[idx]) {
                    triggerThreatInspector(data.threats[idx]);
                }
            });
        });

        loadThreatTrendsChart();
    }

    safeGetElement(DOM_IDS.threatsRefresh)?.addEventListener('click', loadThreats);

    function triggerThreatInspector(threat) {
        const placeholder = document.getElementById('threat-placeholder');
        const content = document.getElementById('threat-content');
        
        if (placeholder) placeholder.classList.add('hidden');
        if (content) content.classList.remove('hidden');

        let details = {};
        try {
            details = typeof threat.details_json === 'string' ? JSON.parse(threat.details_json) : threat.details_json;
        } catch {
            details = {};
        }

        const levelBadge = document.getElementById('threat-lbl-level');
        if (levelBadge) {
            levelBadge.textContent = threat.threat_level?.toUpperCase?.() || 'UNKNOWN';
            levelBadge.className = 'badge ' + 
                (threat.threat_level === 'critical' ? 'badge-red' : 
                 threat.threat_level === 'high' ? 'badge-amber' : 
                 threat.threat_level === 'medium' ? 'badge-purple' : 'badge-cyan');
        }
        setText('threat-title-category', details.category || 'NTP Intrusion Anomaly');

        const sevEl = document.getElementById('threat-intel-severity');
        if (sevEl) {
            sevEl.textContent = threat.severity?.toUpperCase?.() || 'UNKNOWN';
            sevEl.className = 'intel-val ' + (threat.severity === 'critical' ? 'text-red' : 'text-amber');
        }
        setText('threat-intel-confidence', (threat.confidence * 100).toFixed(0) + '%');
        setText('threat-intel-reason', threat.alert_reason);
        setText('threat-intel-evidence', details.evidence || 'NTP header anomaly signature detected.');
        setText('threat-intel-recommendation', threat.recommendation || 'Inspect client host configuration.');

        const fieldsList = document.getElementById('threat-intel-fields');
        if (fieldsList) {
            fieldsList.innerHTML = '';
            const fields = details.affected_fields || ['header'];
            fields.forEach(field => {
                const span = document.createElement('span');
                span.className = 'badge badge-purple';
                span.textContent = field;
                fieldsList.appendChild(span);
            });
        }
    }

    async function loadThreatTrendsChart() {
        const canvas = document.getElementById(DOM_IDS.threatTrendChart);
        if (!canvas) return;

        const histCritical = await apiFetch('/api/analytics/history?metric=threats_critical&limit=15');
        const histTotal = await apiFetch('/api/analytics/history?metric=threats_total&limit=15');
        
        if (!histTotal || !histTotal.data) return;

        const labels = histTotal.data.map(d => new Date(d.recorded_at).toLocaleTimeString('en-GB', {hour: '2-digit', minute:'2-digit'})).reverse();
        const totals = histTotal.data.map(d => d.metric_value).reverse();
        const criticals = histCritical?.data ? histCritical.data.map(d => d.metric_value).reverse() : [];

        if (threatTrendChart) {
            threatTrendChart.data.labels = labels;
            threatTrendChart.data.datasets[0].data = totals;
            threatTrendChart.data.datasets[1].data = criticals;
            threatTrendChart.update();
        } else {
            threatTrendChart = new Chart(canvas, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Total Security Threats',
                            data: totals,
                            borderColor: 'rgba(245, 158, 11, 0.9)',
                            backgroundColor: 'rgba(245, 158, 11, 0.1)',
                            fill: true,
                            tension: 0.3
                        },
                        {
                            label: 'Critical Intrusion Signatures',
                            data: criticals,
                            borderColor: 'rgba(239, 68, 68, 0.9)',
                            backgroundColor: 'rgba(239, 68, 68, 0.1)',
                            fill: true,
                            tension: 0.3
                        }
                    ]
                },
                options: CHART_DEFAULTS
            });
        }
    }

    /* ───────────────────────────────────────────────────────────────
       9. Advanced Analytics Controller
       ─────────────────────────────────────────────────────────────── */
    async function loadAnalytics() {
        const data = await apiFetch('/api/analytics');
        if (!data) return;

        setText('an-pps-sent', data.throughput_sent_pps?.toFixed?.(3) || '0' + ' PPS');
        setText('an-pps-recv', data.throughput_recv_pps?.toFixed?.(3) || '0' + ' PPS');
        setText('an-latency', data.avg_latency_ms?.toFixed?.(1) || '0' + ' ms');
        setText('an-threat-freq', data.threat_frequency_pct?.toFixed?.(2) || '0' + '%');

        updateAnalyticsCharts(data);
    }

    async function updateAnalyticsCharts(data) {
        if (!data) return;
        
        updateDecryptChart(data);
        
        const bandwidthSentHist = await apiFetch('/api/analytics/history?metric=rate_sent_bps&limit=15');
        const bandwidthRecvHist = await apiFetch('/api/analytics/history?metric=rate_recv_bps&limit=15');

        if (bandwidthSentHist?.data) {
            const labels = bandwidthSentHist.data.map(d => new Date(d.recorded_at).toLocaleTimeString('en-GB', {hour: '2-digit', minute:'2-digit'})).reverse();
            const sData = bandwidthSentHist.data.map(d => d.metric_value).reverse();
            const rData = bandwidthRecvHist?.data ? bandwidthRecvHist.data.map(d => d.metric_value).reverse() : [];
            
            updateBandwidthChart(labels, sData, rData);
        }

        updateUsageChart(data);
        updateCryptoChart(data);
    }

    safeGetElement('analytics-refresh-btn')?.addEventListener('click', loadAnalytics);

    /* ───────────────────────────────────────────────────────────────
       10. Communication Sessions & Interactive Replays
       ─────────────────────────────────────────────────────────────── */
    async function loadSessions() {
        showLoading(DOM_IDS.sessionsTbody, true);
        const data = await apiFetch('/api/sessions');
        showLoading(DOM_IDS.sessionsTbody, false);
        
        if (!data) return;

        const tbody = safeGetElement(DOM_IDS.sessionsTbody);
        if (!tbody) return;

        if (!data.sessions || data.sessions.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No active communication sessions.</td></tr>';
            return;
        }

        tbody.innerHTML = data.sessions.map(s => `
            <tr class="session-row-clickable" data-session-id="${s.id}">
                <td title="${s.id}">${shortId(s.id)}</td>
                <td>${makeTag(s.status)}</td>
                <td>${s.sender_host || '—'}</td>
                <td>${s.receiver_host || '—'}</td>
                <td>${s.packets_sent}</td>
                <td>${s.packets_received}</td>
                <td>${fmtTime(s.started_at)}</td>
            </tr>
        `).join('');

        tbody.querySelectorAll('tr').forEach(row => {
            row.addEventListener('click', () => {
                const sId = row.getAttribute('data-session-id');
                triggerSessionReplay(sId);
            });
        });
    }

    safeGetElement(DOM_IDS.sessionsRefresh)?.addEventListener('click', loadSessions);

    async function triggerSessionReplay(sessionId) {
        const placeholder = document.getElementById('replay-placeholder');
        const content = document.getElementById('replay-content');

        if (placeholder) placeholder.classList.add('hidden');
        if (content) {
            content.classList.remove('hidden');
            showLoading(content, true);
        }

        stopReplayLoop();

        const data = await apiFetch(`/api/sessions/${sessionId}/replay`);
        if (content) showLoading(content, false);
        
        if (!data || data.count === 0) {
            document.getElementById('replay-step-details').innerHTML = "<h5>No packets found in this session.</h5>";
            return;
        }

        replaySteps = data.steps;
        replayIndex = 0;
        
        setText('replay-lbl-session', data.session?.status?.toUpperCase?.() || 'UNKNOWN');
        const lbl = document.getElementById('replay-lbl-session');
        if (lbl) {
            lbl.className = 'badge ' + (data.session?.status === 'active' ? 'badge-green' : 'badge-purple');
        }

        setText('replay-total-steps', replaySteps.length);
        updateReplayStepView();
    }

    // Replay button handlers (improved in v2.0)
    document.getElementById('btn-replay-play')?.addEventListener('click', startReplayPlayback);
    document.getElementById('btn-replay-pause')?.addEventListener('click', stopReplayLoop);
    document.getElementById('btn-replay-next')?.addEventListener('click', () => {
        stopReplayLoop();
        if (replayIndex < replaySteps.length - 1) {
            replayIndex++;
            updateReplayStepView();
        }
    });
    document.getElementById('btn-replay-prev')?.addEventListener('click', () => {
        stopReplayLoop();
        if (replayIndex > 0) {
            replayIndex--;
            updateReplayStepView();
        }
    });

    function startReplayPlayback() {
        if (isPlayingReplay || replaySteps.length === 0) return;
        isPlayingReplay = true;
        
        const speedSelect = document.getElementById('replay-speed');
        const delay = parseInt(speedSelect?.value) || 1500;
        
        replayIntervalId = setInterval(() => {
            if (replayIndex >= replaySteps.length - 1) {
                stopReplayLoop();
            } else {
                replayIndex++;
                updateReplayStepView();
            }
        }, delay);
        
        appendConsole(DOM_IDS.activityConsole, 'info', `Session Replay Playback Started.`);
    }

    function stopReplayLoop() {
        isPlayingReplay = false;
        if (replayIntervalId) {
            clearInterval(replayIntervalId);
            replayIntervalId = null;
        }
        
        // Clean up setTimeout timeouts
        replayTimeoutIds.forEach(id => clearTimeout(id));
        replayTimeoutIds = [];
    }

    function updateReplayStepView() {
        if (replaySteps.length === 0) return;
        
        const step = replaySteps[replayIndex];
        
        setText('replay-current-step', replayIndex + 1);
        const progressPct = ((replayIndex + 1) / replaySteps.length) * 100.0;
        const progBar = document.getElementById('replay-progress-bar');
        if (progBar) progBar.style.width = progressPct + '%';

        animateReplayPipeline(step);

        const detailsEl = document.getElementById('replay-step-details');
        if (detailsEl) {
            let threatHtml = '';
            if (step.threat) {
                threatHtml = `
                    <div class="replay-threat-warning">
                        <strong>⚠ Threat Detected!</strong> Level: ${step.threat.level?.toUpperCase?.() || 'UNKNOWN'} | Reason: ${step.threat.reason}
                    </div>
                `;
            }

            detailsEl.innerHTML = `
                <h5>Packet #${replayIndex + 1} (${shortId(step.packet_id)}) Status</h5>
                <div class="replay-detail-line"><strong>Direction:</strong> ${step.direction?.toUpperCase?.() || 'UNKNOWN'}</div>
                <div class="replay-detail-line"><strong>Hosts:</strong> ${step.source} ➔ ${step.destination}</div>
                <div class="replay-detail-line"><strong>Header Size:</strong> ${step.size} Bytes</div>
                <div class="replay-detail-line"><strong>Covert Payload:</strong> ${step.payload_status} (${step.encryption_status})</div>
                ${step.message ? `<div class="replay-message-recovered"><strong>Message Recovered:</strong> "${step.message}"</div>` : ''}
                ${threatHtml}
            `;
        }
    }

    function animateReplayPipeline(step) {
        const nodes = ['node-generated', 'node-encrypted', 'node-transmitted', 'node-received', 'node-threat', 'node-decrypted'];
        nodes.forEach(n => {
            const el = document.getElementById(n);
            if (el) el.className = 'node';
        });

        // Clean up previous timeouts
        replayTimeoutIds.forEach(id => clearTimeout(id));
        replayTimeoutIds = [];

        if (step.direction === 'sent') {
            document.getElementById('node-generated')?.classList.add('node-active');
            
            replayTimeoutIds.push(setTimeout(() => {
                if (step.encryption_status === 'encrypted') {
                    document.getElementById('node-encrypted')?.classList.add('node-active');
                }
            }, 250));
            
            replayTimeoutIds.push(setTimeout(() => {
                document.getElementById('node-transmitted')?.classList.add('node-active');
            }, 500));
        } else {
            document.getElementById('node-transmitted')?.classList.add('node-active');
            
            replayTimeoutIds.push(setTimeout(() => {
                document.getElementById('node-received')?.classList.add('node-active');
            }, 200));

            replayTimeoutIds.push(setTimeout(() => {
                if (step.threat) {
                    document.getElementById('node-threat')?.classList.add('node-active-threat');
                } else {
                    document.getElementById('node-threat')?.classList.add('node-active');
                }
            }, 400));

            replayTimeoutIds.push(setTimeout(() => {
                if (step.encryption_status === 'decrypted') {
                    document.getElementById('node-decrypted')?.classList.add('node-active');
                } else if (step.encryption_status === 'failed') {
                    document.getElementById('node-decrypted')?.classList.add('node-active-failed');
                }
            }, 600));
        }
    }

    /* ───────────────────────────────────────────────────────────────
       11. System Errors & Data Export Center
       ─────────────────────────────────────────────────────────────── */
    async function loadErrors() {
        showLoading(DOM_IDS.errorsTbody, true);
        const data = await apiFetch('/api/errors');
        showLoading(DOM_IDS.errorsTbody, false);
        
        if (!data) return;

        const tbody = safeGetElement(DOM_IDS.errorsTbody);
        if (!tbody) return;

        if (!data.errors || data.errors.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No errors registered.</td></tr>';
            return;
        }

        tbody.innerHTML = data.errors.map(e => `
            <tr>
                <td title="${e.id}">${shortId(e.id)}</td>
                <td>${makeTag(e.error_type)}</td>
                <td>${e.module}</td>
                <td title="${e.message}">${e.message}</td>
                <td>${fmtTime(e.created_at)}</td>
            </tr>
        `).join('');
    }

    safeGetElement(DOM_IDS.logsRefresh)?.addEventListener('click', loadErrors);

    // Export Center Form handler
    const exportForm = safeGetElement(DOM_IDS.exportForm);
    if (exportForm) {
        exportForm.addEventListener('submit', (e) => {
            e.preventDefault();
            
            const submitBtn = exportForm.querySelector('button[type="submit"]');
            if (submitBtn) submitBtn.disabled = true;
            
            try {
                const domain = document.getElementById('export-domain')?.value || 'packets';
                const format = document.getElementById('export-format')?.value || 'json';
                
                window.location.href = `/api/export?domain=${domain}&format=${format}`;
                appendConsole(DOM_IDS.activityConsole, 'success', `Export requested: ${domain} (${format})`);
            } finally {
                if (submitBtn) submitBtn.disabled = false;
            }
        });
    }

    /* ───────────────────────────────────────────────────────────────
       12. Chart Builders & Updates (optimized in v2.0)
       ─────────────────────────────────────────────────────────────── */
    const CHART_COLORS = {
        cyan:   'rgba(6, 182, 212, 0.8)',
        green:  'rgba(16, 185, 129, 0.8)',
        amber:  'rgba(245, 158, 11, 0.8)',
        red:    'rgba(239, 68, 68, 0.8)',
        purple: 'rgba(139, 92, 246, 0.8)',
        cyanBg:   'rgba(6, 182, 212, 0.15)',
        greenBg:  'rgba(16, 185, 129, 0.15)',
    };

    const CHART_DEFAULTS = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: { color: '#94a3b8', font: { family: "'Inter', sans-serif", size: 10 } }
            }
        },
        scales: {
            x: {
                ticks: { color: '#64748b', font: { size: 9 } },
                grid: { color: 'rgba(255,255,255,0.03)' }
            },
            y: {
                ticks: { color: '#64748b', font: { size: 9 } },
                grid: { color: 'rgba(255,255,255,0.03)' },
                beginAtZero: true
            }
        }
    };

    function buildTrafficChart(stats) {
        const canvas = document.getElementById(DOM_IDS.trafficChart);
        if (!canvas) return;

        if (trafficChart) {
            trafficChart.data.datasets[0].data = [
                stats.packets_sent || 0,
                stats.packets_received || 0,
                (stats.messages_sent || 0) + (stats.messages_received || 0),
                stats.threats_total || 0,
                stats.total_errors || 0,
            ];
            trafficChart.update();
        } else {
            trafficChart = new Chart(canvas, {
                type: 'bar',
                data: {
                    labels: ['Packets Sent', 'Packets Received', 'Covert Messages', 'Threat Alerts', 'Logged Errors'],
                    datasets: [{
                        data: [
                            stats.packets_sent || 0,
                            stats.packets_received || 0,
                            (stats.messages_sent || 0) + (stats.messages_received || 0),
                            stats.threats_total || 0,
                            stats.total_errors || 0,
                        ],
                        backgroundColor: [
                            CHART_COLORS.cyan, CHART_COLORS.green,
                            CHART_COLORS.purple, CHART_COLORS.amber, CHART_COLORS.red,
                        ],
                        borderRadius: 6,
                        borderSkipped: false,
                    }]
                },
                options: {
                    ...CHART_DEFAULTS,
                    plugins: {
                        ...CHART_DEFAULTS.plugins,
                        legend: { display: false }
                    }
                }
            });
        }
    }

    function updateDecryptChart(metrics) {
        const canvas = document.getElementById(DOM_IDS.decryptChart);
        if (!canvas) return;

        const rate = metrics.decryption_success_rate || 100;
        const failRate = 100 - rate;

        if (decryptChart) {
            decryptChart.data.datasets[0].data = [rate, failRate];
            decryptChart.update();
        } else {
            decryptChart = new Chart(canvas, {
                type: 'doughnut',
                data: {
                    labels: ['Successful Decryptions', 'Decryption Mismatch/Failed'],
                    datasets: [{
                        data: [rate, failRate],
                        backgroundColor: [CHART_COLORS.green, CHART_COLORS.red],
                        borderWidth: 0,
                        cutout: '72%',
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#94a3b8', font: { size: 10 }, padding: 12 }
                        }
                    }
                }
            });
        }
    }

    function updateBandwidthChart(labels, sentData, recvData) {
        const canvas = document.getElementById(DOM_IDS.rateBandwidthChart);
        if (!canvas) return;

        if (bandwidthChart) {
            bandwidthChart.data.labels = labels;
            bandwidthChart.data.datasets[0].data = sentData;
            bandwidthChart.data.datasets[1].data = recvData;
            bandwidthChart.update();
        } else {
            bandwidthChart = new Chart(canvas, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [
                        {
                            label: 'Sent Bandwidth (B/s)',
                            data: sentData,
                            borderColor: CHART_COLORS.cyan,
                            backgroundColor: CHART_COLORS.cyanBg,
                            fill: true,
                            tension: 0.3
                        },
                        {
                            label: 'Received Bandwidth (B/s)',
                            data: recvData,
                            borderColor: CHART_COLORS.green,
                            backgroundColor: CHART_COLORS.greenBg,
                            fill: true,
                            tension: 0.3
                        }
                    ]
                },
                options: CHART_DEFAULTS
            });
        }
    }

    function updateUsageChart(metrics) {
        const canvas = document.getElementById(DOM_IDS.usageChart);
        if (!canvas) return;

        if (usageChart) {
            usageChart.data.datasets[0].data = [metrics.proto_usage_standard || 0, metrics.proto_usage_covert || 0];
            usageChart.update();
        } else {
            usageChart = new Chart(canvas, {
                type: 'bar',
                data: {
                    labels: ['Standard NTP Packets', 'Covert Injected Packets'],
                    datasets: [{
                        data: [metrics.proto_usage_standard || 0, metrics.proto_usage_covert || 0],
                        backgroundColor: ['rgba(71, 85, 105, 0.8)', CHART_COLORS.purple],
                        borderRadius: 6
                    }]
                },
                options: {
                    ...CHART_DEFAULTS,
                    plugins: { ...CHART_DEFAULTS.plugins, legend: { display: false } }
                }
            });
        }
    }

    function updateCryptoChart(metrics) {
        const canvas = document.getElementById(DOM_IDS.cryptoChart);
        if (!canvas) return;

        if (cryptoChart) {
            cryptoChart.data.datasets[0].data = [metrics.enc_gcm_count || 0, metrics.enc_none_count || 0, metrics.enc_failed_count || 0];
            cryptoChart.update();
        } else {
            cryptoChart = new Chart(canvas, {
                type: 'pie',
                data: {
                    labels: ['Encrypted GCM', 'No Encryption', 'Decryption Failures'],
                    datasets: [{
                        data: [metrics.enc_gcm_count || 0, metrics.enc_none_count || 0, metrics.enc_failed_count || 0],
                        backgroundColor: [CHART_COLORS.green, 'rgba(100, 116, 139, 0.8)', CHART_COLORS.red],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#94a3b8', font: { size: 10 } }
                        }
                    }
                }
            });
        }
    }

    /* ───────────────────────────────────────────────────────────────
       13. Utility Functions (new in v2.0)
       ─────────────────────────────────────────────────────────────── */
    
    function showLoading(elementId, show = true) {
        const element = typeof elementId === 'string' ? safeGetElement(elementId) : elementId;
        if (!element) return;
        
        if (show) {
            element.classList.add('loading');
        } else {
            element.classList.remove('loading');
        }
    }

    function appendConsole(panelId, level, message) {
        const panel = safeGetElement(panelId);
        if (!panel) return;

        // Limit buffer to prevent DOM bloat
        if (panel.children.length >= CONFIG.CONSOLE_MAX_LINES) {
            // Remove oldest 50 lines
            for (let i = 0; i < 50; i++) {
                panel.removeChild(panel.firstChild);
            }
        }

        const line = document.createElement('div');
        line.className = 'console-line';

        const time = document.createElement('span');
        time.className = 'console-time';
        time.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });

        const tag = document.createElement('span');
        tag.className = `console-tag ${level}`;
        tag.textContent = level.toUpperCase();

        const msg = document.createElement('span');
        msg.className = 'console-msg';
        msg.textContent = message;

        line.appendChild(time);
        line.appendChild(tag);
        line.appendChild(msg);
        panel.appendChild(line);
        panel.scrollTop = panel.scrollHeight;
    }

    /* ───────────────────────────────────────────────────────────────
       14. Initial Page Loader
       ─────────────────────────────────────────────────────────────── */
    loadDashboard();

})();