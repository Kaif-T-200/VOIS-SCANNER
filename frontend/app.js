var API = window.location.origin;
var ws = null;
var currentScanId = null;
var scanResults = [];
var sortColumn = null;
var sortDirection = 'asc';
var riskChart = null;

function $(id) { return document.getElementById(id); }
function $$(sel) { return document.querySelectorAll(sel); }

function toast(msg, type) {
    type = type || 'info';
    var t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(function() { t.classList.add('show'); }, 10);
    setTimeout(function() { t.classList.remove('show'); setTimeout(function() { t.remove(); }, 300); }, 4000);
}

function debounce(fn, ms) {
    var t;
    return function() {
        var args = arguments;
        clearTimeout(t);
        t = setTimeout(function() { fn.apply(null, args); }, ms);
    };
}

document.addEventListener('DOMContentLoaded', function() {
    console.log('VOIS app.js loaded');
    initNav();
    initTheme();
    initProfile();
    initTargetPreview();
    initScanForm();
    initHistoryPage();
    initExportBtns();
    initSortHeaders();
    loadHistory();
    console.log('All initialized');
});

function initNav() {
    var items = $$('.nav-item');
    var pages = $$('.page');
    for (var i = 0; i < items.length; i++) {
        (function(item) {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                var pageName = item.getAttribute('data-page');
                if (!pageName) return;
                for (var j = 0; j < items.length; j++) items[j].classList.remove('active');
                for (var j = 0; j < pages.length; j++) pages[j].classList.remove('active');
                item.classList.add('active');
                var page = $('page-' + pageName);
                if (page) page.classList.add('active');
                if (pageName === 'history') loadHistory();
                if (pageName === 'scripts') loadScripts();
            });
        })(items[i]);
    }
}

function initTheme() {
    var saved = localStorage.getItem('theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
    else if (window.matchMedia('(prefers-color-scheme: light)').matches) document.documentElement.setAttribute('data-theme', 'light');
    var btn = $('themeToggle');
    if (btn) btn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
    });
}

function initProfile() {
    var sel = $('profile');
    if (sel) sel.addEventListener('change', function(e) {
        e.stopPropagation();
        var cp = $('customPorts');
        if (cp) cp.style.display = sel.value === 'custom' ? 'block' : 'none';
    });
}

function initTargetPreview() {
    var input = $('target');
    var timeout;
    if (input) input.addEventListener('input', function() {
        clearTimeout(timeout);
        var val = input.value.trim();
        var pv = $('targetPreview');
        if (!val) { if (pv) pv.style.display = 'none'; return; }
        timeout = setTimeout(function() {
            fetch(API + '/api/normalize?target=' + encodeURIComponent(val))
            .then(function(r) { return r.json(); })
            .then(function(d) {
                if (!pv || d.error) { if (pv) pv.style.display = 'none'; return; }
                pv.style.display = 'flex';
                var valEl = $('previewValue');
                if (valEl) valEl.textContent = d.hostname + (d.ip ? ' (' + d.ip + ')' : '') + ' - ' + d.scheme + ' - Port ' + d.port;
            })
            .catch(function() { if (pv) pv.style.display = 'none'; });
        }, 300);
    });
}

function initScanForm() {
    var form = $('scanForm');
    if (!form) return;
    form.addEventListener('submit', function(e) {
        e.preventDefault();
        e.stopPropagation();
        var payload = {
            target: $('target').value.trim(),
            scan_type: $('scanType').value,
            profile: $('profile').value,
            timing: parseInt($('timing').value),
            timeout: parseFloat($('timeout').value),
            grab_banners: $('grabBanners').checked,
            detect_os: $('detectOs').checked,
            run_scripts: $('runScripts').checked,
            traceroute: $('traceroute').checked,
            firewall_detect: $('firewallDetect').checked
        };
        if (payload.profile === 'custom') payload.ports = $('customPortsInput').value;
        setScanningState(true);
        resetResults();
        fetch(API + '/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
        .then(function(r) {
            if (!r.ok) {
                return r.text().then(function(text) {
                    try {
                        var json = JSON.parse(text);
                        throw new Error(json.detail || json.message || 'Failed');
                    } catch(e) {
                        throw new Error(text || 'Server error');
                    }
                });
            }
            return r.json();
        })
        .then(function(data) {
            currentScanId = data.scan_id;
            toast('Scan started: ' + data.target + ' -> ' + data.resolved_ip, 'success');
            connectWebSocket(currentScanId);
        })
        .catch(function(err) { toast(err.message, 'error'); setScanningState(false); });
    });
    var stopBtn = $('stopBtn');
    if (stopBtn) stopBtn.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        if (!currentScanId) return;
        fetch(API + '/api/scan/' + currentScanId + '/stop', { method: 'POST' })
        .then(function() { toast('Scan stopping...', 'warning'); })
        .catch(function(err) { console.error(err); });
    });
}

function initHistoryPage() {
    var search = $('historySearch');
    if (search) search.addEventListener('input', debounce(loadHistory, 300));
    var status = $('historyStatus');
    if (status) status.addEventListener('change', function(e) { e.stopPropagation(); loadHistory(); });
    var risk = $('historyRisk');
    if (risk) risk.addEventListener('change', function(e) { e.stopPropagation(); loadHistory(); });
    var refresh = $('refreshHistory');
    if (refresh) refresh.addEventListener('click', function(e) { e.stopPropagation(); toast('Refreshing...', 'info'); loadHistory(); });
    var clear = $('clearHistory');
    if (clear) clear.addEventListener('click', function(e) {
        e.stopPropagation();
        if (!confirm('Delete ALL scan history?')) return;
        fetch(API + '/api/scans')
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var promises = (data.scans || []).map(function(s) { return fetch(API + '/api/scan/' + s.id, { method: 'DELETE' }); });
            return Promise.all(promises);
        })
        .then(function() { toast('History cleared', 'success'); loadHistory(); })
        .catch(function() { toast('Failed', 'error'); });
    });
}

function initExportBtns() {
    var btns = $$('.btn[data-export]');
    for (var i = 0; i < btns.length; i++) {
        (function(btn) {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                if (!currentScanId) return;
                window.open(API + '/api/scan/' + currentScanId + '/export?format=' + btn.getAttribute('data-export'), '_blank');
            });
        })(btns[i]);
    }
}

function initSortHeaders() {
    var ths = $$('.results-table th[data-sort]');
    for (var i = 0; i < ths.length; i++) {
        (function(th) {
            th.addEventListener('click', function(e) {
                e.preventDefault();
                e.stopPropagation();
                var col = th.getAttribute('data-sort');
                if (sortColumn === col) sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
                else { sortColumn = col; sortDirection = 'asc'; }
                var allThs = $$('.results-table th');
                for (var j = 0; j < allThs.length; j++) allThs[j].classList.remove('sorted');
                th.classList.add('sorted');
                renderResults();
            });
        })(ths[i]);
    }
}

function connectWebSocket(scanId) {
    if (ws) ws.close();
    var proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(proto + '//' + window.location.host + '/ws/' + scanId);
    ws.onmessage = function(e) { handleProgress(JSON.parse(e.data)); };
    ws.onclose = function() { console.log('WS closed'); };
    ws.onerror = function() { toast('WebSocket error', 'error'); };
}

function handleProgress(data) {
    if (data.type === 'progress') {
        var pct = data.total > 0 ? (data.scanned / data.total * 100) : 0;
        var circumference = 2 * Math.PI * 52;
        var offset = circumference - (pct / 100) * circumference;
        var circle = document.querySelector('.progress-ring-circle');
        if (circle) circle.style.strokeDashoffset = offset;
        var rp = $('ringPercent'); if (rp) rp.textContent = Math.round(pct) + '%';
        var ds = $('detailScanned'); if (ds) ds.textContent = data.scanned + ' / ' + data.total;
        setStatus('running', 'Scanning... ' + data.scanned + '/' + data.total);
        if (data.open_ports) {
            for (var i = 0; i < data.open_ports.length; i++) {
                (function(p) {
                    if (!scanResults.find(function(r) { return r.port === p.port; })) {
                        scanResults.push(p);
                        addLivePort(p);
                        var dop = $('detailOpen'); if (dop) dop.textContent = scanResults.length;
                    }
                })(data.open_ports[i]);
            }
            renderResults();
        }
    } else if (data.type === 'version') {
        var existing = scanResults.find(function(r) { return r.port === data.port; });
        if (existing) { existing.version = data.version; existing.product = data.product; existing.banner = data.banner; renderResults(); }
    } else if (data.type === 'complete') {
        var circumference = 2 * Math.PI * 52;
        var circle = document.querySelector('.progress-ring-circle');
        if (circle) circle.style.strokeDashoffset = 0;
        var rp = $('ringPercent'); if (rp) rp.textContent = '100%';
        setStatus('completed', 'Completed - ' + data.open_ports_count + ' open ports in ' + data.elapsed.toFixed(2) + 's');
        setScanningState(false);
        var ra = $('resultsActions'); if (ra) ra.style.display = 'flex';
        if (data.risk && data.risk.level) {
            var rr = $('resultRisk');
            if (rr) { rr.textContent = data.risk.level; rr.className = 'badge badge-' + data.risk.level.toLowerCase(); }
            showRiskMeter(data.risk.score);
        }
        if (data.os_info && data.os_info.os_family) {
            var oi = $('osInfo'); if (oi) oi.style.display = 'block';
            var of2 = $('osFamily'); if (of2) of2.textContent = data.os_info.os_family + ' ' + (data.os_info.os_version || '');
            var oc = $('osConfidence'); if (oc) oc.textContent = (data.os_info.confidence || 0) + '% confidence';
        }
        if (data.scripts && data.scripts.length) {
            var sr = $('scriptsResults'); if (sr) sr.style.display = 'block';
            var so = $('scriptsOutput');
            if (so) so.innerHTML = data.scripts.map(function(s) { return '<div class="script-output"><strong>[' + s.risk.toUpperCase() + ']</strong> ' + s.name + ': ' + s.output + '</div>'; }).join('');
        }
        renderResults();
        toast('Scan complete: ' + data.open_ports_count + ' open ports', 'success');
        // Force refresh history after scan completes
        console.log('Refreshing history after scan completion (scan_id: ' + data.scan_id + ')');
        setScanningState(false);
        setTimeout(function() { 
            loadHistory();
            console.log('History refreshed');
        }, 1000);
    }
}

function addLivePort(p) {
    var lp = $('livePorts');
    if (!lp) return;
    if (lp.querySelector('.empty-state')) lp.innerHTML = '';
    var div = document.createElement('div');
    div.className = 'live-port-item';
    div.innerHTML = '<span class="port-num">' + p.port + '</span><span class="port-service">' + p.service + '</span><span class="port-latency">' + p.latency + 'ms</span>';
    lp.prepend(div);
}

function renderResults() {
    var rb = $('resultsBody');
    if (!rb || !scanResults.length) return;
    var sorted = scanResults.slice();
    if (sortColumn) sorted.sort(function(a, b) {
        var va = a[sortColumn] !== undefined ? a[sortColumn] : '';
        var vb = b[sortColumn] !== undefined ? b[sortColumn] : '';
        if (typeof va === 'number' && typeof vb === 'number') return sortDirection === 'asc' ? va - vb : vb - va;
        return sortDirection === 'asc' ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
    rb.innerHTML = sorted.map(function(p) {
        var stateClass = 'state-' + p.state.replace('|', '\\|');
        var riskClass = 'risk-' + (p.risk_level || 'info').toLowerCase();
        var cves = (p.cves || []).map(function(c) { return '<span class="cve-tag" title="' + c + '">' + c + '</span>'; }).join('');
        return '<tr><td><span class="port-badge">' + p.port + '</span></td><td><span class="' + stateClass + '">' + p.state + '</span></td><td><span class="service-name">' + p.service + '</span></td><td><span class="version-text">' + (p.version || p.product || '\u2014') + '</span></td><td><span class="risk-badge ' + riskClass + '">' + (p.risk_level || '\u2014') + '</span></td><td>' + (cves || '\u2014') + '</td><td><span class="latency-value">' + (p.latency ? p.latency + 'ms' : '\u2014') + '</span></td></tr>';
    }).join('');
}

function showRiskMeter(score) {
    var rm = $('riskMeter'); if (rm) rm.style.display = 'block';
    var rf = $('riskMeterFill');
    if (rf) { rf.style.width = Math.min(score / 10 * 100, 100) + '%'; rf.style.background = score >= 9 ? 'var(--critical)' : score >= 7 ? 'var(--danger)' : score >= 5 ? 'var(--warning)' : 'var(--success)'; }
}

function setScanningState(scanning) {
    var els = ['startBtn', 'stopBtn', 'target', 'scanType', 'profile', 'timing'];
    for (var i = 0; i < els.length; i++) {
        var el = $(els[i]);
        if (el) el.disabled = (els[i] === 'stopBtn') ? !scanning : scanning;
    }
}

function resetResults() {
    scanResults = [];
    var rb = $('resultsBody'); if (rb) rb.innerHTML = '';
    var ra = $('resultsActions'); if (ra) ra.style.display = 'none';
    var rm = $('riskMeter'); if (rm) rm.style.display = 'none';
    var oi = $('osInfo'); if (oi) oi.style.display = 'none';
    var sr = $('scriptsResults'); if (sr) sr.style.display = 'none';
    var lp = $('livePorts');
    if (lp) lp.innerHTML = '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" width="48" height="48"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg><p>Open ports will appear here</p></div>';
    var ds = $('detailScanned'); if (ds) ds.textContent = '0 / 0';
    var de = $('detailElapsed'); if (de) de.textContent = '0.00s';
    var dop = $('detailOpen'); if (dop) dop.textContent = '0';
    var rp = $('ringPercent'); if (rp) rp.textContent = '0%';
    var circle = document.querySelector('.progress-ring-circle');
    if (circle) circle.style.strokeDashoffset = 2 * Math.PI * 52;
}

function setStatus(status, text) {
    var si = $('statusIndicator'); if (si) si.className = 'status-indicator ' + status;
    var st = $('statusText'); if (st) st.textContent = text;
}

async function loadHistory() {
    var target = $('historySearch') ? $('historySearch').value : '';
    var status = $('historyStatus') ? $('historyStatus').value : '';
    var risk = $('historyRisk') ? $('historyRisk').value : '';
    var url = API + '/api/search?';
    if (target) url += 'target=' + encodeURIComponent(target) + '&';
    if (status) url += 'status=' + status + '&';
    if (risk) url += 'risk_level=' + risk + '&';
    try {
        var res = await fetch(url);
        var data = await res.json();
        renderHistory(data.scans || []);
    } catch (err) { console.error(err); }
}

function renderHistory(scans) {
    var list = $('historyList');
    if (!list) return;
    if (!scans.length) { list.innerHTML = '<div class="empty-state"><p>No scan history</p></div>'; return; }
    list.innerHTML = scans.map(function(s) {
        return '<div class="history-item" onclick="loadScan(\'' + s.id + '\')"><div class="history-info"><span class="history-target">' + s.target + ' (' + (s.resolved_ip || 'N/A') + ')</span><span class="history-meta">' + s.scan_type + ' - ' + s.start_port + '-' + s.end_port + ' - ' + new Date(s.created_at).toLocaleString() + '</span></div><div class="history-stats"><span class="badge badge-' + (s.risk_level || 'info').toLowerCase() + '">' + (s.risk_level || 'N/A') + '</span><div class="history-stat"><div class="history-stat-value">' + s.open_ports_count + '</div><div class="history-stat-label">ports</div></div><div class="history-stat"><div class="history-stat-value">' + (s.elapsed ? s.elapsed.toFixed(1) : '0') + 's</div><div class="history-stat-label">time</div></div></div><button class="delete-scan" title="Delete this scan" onclick="event.stopPropagation();deleteScan(\'' + s.id + '\')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button></div>';
    }).join('');
}

async function deleteScan(id) {
    if (!confirm('Delete this scan?')) return;
    try {
        await fetch(API + '/api/scan/' + id, { method: 'DELETE' });
        toast('Deleted', 'success');
        loadHistory();
    } catch (err) { toast('Failed', 'error'); }
}

async function loadScan(id) {
    try {
        var res = await fetch(API + '/api/scan/' + id);
        var data = await res.json();
        currentScanId = id;
        scanResults = (data.ports || []).map(function(p) {
            return { port: p.port, protocol: p.protocol, state: p.state, service: p.service, version: p.version, product: p.product, banner: p.banner, latency: p.latency, risk_level: p.risk_level, risk_score: p.risk_score, cves: p.cves ? (typeof p.cves === 'string' ? JSON.parse(p.cves) : p.cves) : [] };
        });
        var rt = $('resultTarget'); if (rt) rt.textContent = data.target + ' (' + data.resolved_ip + ')';
        if (data.risk_level) { var rr = $('resultRisk'); if (rr) { rr.textContent = data.risk_level; rr.className = 'badge badge-' + data.risk_level.toLowerCase(); } showRiskMeter(data.risk_score); }
        if (data.os_family) { var oi = $('osInfo'); if (oi) oi.style.display = 'block'; var of2 = $('osFamily'); if (of2) of2.textContent = data.os_family + ' ' + (data.os_version || ''); }
        var ra = $('resultsActions'); if (ra) ra.style.display = 'flex';
        renderResults();
        var items = $$('.nav-item'); for (var i = 0; i < items.length; i++) items[i].classList.remove('active');
        var pages = $$('.page'); for (var i = 0; i < pages.length; i++) pages[i].classList.remove('active');
        var navItem = $$('[data-page="results"]')[0]; if (navItem) navItem.classList.add('active');
        var page = $('page-results'); if (page) page.classList.add('active');
        toast('Results loaded', 'success');
    } catch (err) { toast('Failed', 'error'); }
}

var allScripts = [];
var currentScript = null;

function getScriptIcon(category) {
    var icons = {
        'vulnerability': '⚠️',
        'enumeration': '🔍',
        'brute_force': '🔓',
        'credential_check': '🔑',
        'version_detection': '📦',
        'protocol_analysis': '📡',
        'info_gathering': '📋',
        'exploit_attempt': '💣',
        'general': '⚙️'
    };
    return icons[category] || '⚙️';
}

function getRiskBadgeClass(risk) {
    return 'script-badge ' + (risk || 'info');
}

async function loadScripts() {
    try {
        var res = await fetch(API + '/api/scripts');
        var data = await res.json();
        allScripts = data.scripts || [];
        
        var grid = $('scriptsGrid');
        if (!grid) return;
        
        var el = $('scriptsCount'); if (el) el.textContent = allScripts.length;
        
        if (!allScripts.length) {
            grid.innerHTML = '<div class="empty-state"><p>No scripts available</p></div>';
            return;
        }
        
        renderScripts(allScripts);
    } catch (err) {
        console.error('Failed to load scripts:', err);
        toast('Failed to load scripts', 'error');
    }
}

function renderScripts(scripts) {
    var grid = $('scriptsGrid');
    if (!grid) return;
    
    if (!scripts.length) {
        grid.innerHTML = '<div class="empty-state" style="grid-column: 1 / -1; padding: 4rem 2rem; display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center;">' +
            '<div style="width: 48px; height: 48px; color: var(--text-muted); opacity: 0.5; margin-bottom: 1rem;">' + (icons.searchX || icons.search) + '</div>' +
            '<h3 style="color: var(--text); margin-bottom: 0.5rem; font-size: 1.2rem;">No scripts found</h3>' +
            '<p style="color: var(--text-muted); max-width: 300px; margin: 0 auto; font-size: 0.9rem;">Try adjusting your search or category filter to find what you\'re looking for.</p>' +
            '</div>';
        return;
    }
    
    grid.innerHTML = scripts.map(function(s) {
        var riskLevel = s.risk_level || 'info';
        var categoryIcon = getScriptIcon(s.category || 'general');
        var portsText = s.ports && s.ports.length ? s.ports.length + ' ports' : 'All ports';
        
        return '<div class="script-card">' +
            '<div class="script-card-header">' +
            '<div class="script-card-icon" title="' + (s.category || 'general') + '">' + categoryIcon + '</div>' +
            '<span class="script-badge ' + riskLevel + '" title="Risk Level">' + riskLevel.toUpperCase() + '</span>' +
            '</div>' +
            '<div class="script-card-title">' + s.name.replace(/_/g, ' ').toUpperCase() + '</div>' +
            '<div class="script-card-description">' + (s.description || 'No description available') + '</div>' +
            '<div class="script-card-meta">' +
            '<div class="script-card-left">' +
            '<span class="script-badge" style="background:rgba(100,150,255,0.2);color:var(--text-secondary);">' + 
            (s.category || 'general').replace(/_/g, ' ') + 
            '</span>' +
            '<span class="script-badge" style="background:rgba(150,150,255,0.2);color:var(--text-secondary);">' + 
            portsText + 
            '</span>' +
            '</div>' +
            '<div class="script-card-action">' +
            '<button onclick="showScriptModal(\'' + s.name.replace(/'/g, "\\'") + '\'); return false;">RUN</button>' +
            '</div>' +
            '</div>' +
            '</div>';
    }).join('');
}

function filterScripts() {
    var search = ($('scriptsSearch') ? $('scriptsSearch').value.toLowerCase() : '');
    var category = ($('scriptsCategory') ? $('scriptsCategory').value : '');
    
    var filtered = allScripts.filter(function(s) {
        var matchSearch = !search || s.name.toLowerCase().includes(search) || 
                         (s.description && s.description.toLowerCase().includes(search));
        var matchCategory = !category || s.category === category;
        return matchSearch && matchCategory;
    });
    
    renderScripts(filtered);
}

function showScriptModal(nameOrScript) {
    var script = (typeof nameOrScript === 'string')
        ? allScripts.find(function(s) { return s.name === nameOrScript; })
        : nameOrScript;
    if (!script) return;
    currentScript = script;
    $('modalScriptName').textContent = script.name;
    $('modalScriptDescription').textContent = script.description || 'No description available';
    $('modalScriptCategory').textContent = script.category || 'general';
    $('modalScriptRisk').innerHTML = '<span class="' + getRiskBadgeClass(script.risk_level) + '">' + 
                                      (script.risk_level || 'info').toUpperCase() + '</span>';
    $('modalScriptPorts').textContent = (script.ports && script.ports.length ? script.ports.join(', ') : 'All ports');
    $('modalScriptAuthor').textContent = script.author || 'Unknown';
    $('scriptTargetInput').value = '';
    $('scriptPortInput').value = '';
    $('scriptModal').style.display = 'flex';
}

function closeScriptModal() {
    $('scriptModal').style.display = 'none';
    currentScript = null;
}

async function executeScript() {
    if (!currentScript) return;
    
    var target = $('scriptTargetInput').value.trim();
    var port = $('scriptPortInput').value.trim();
    
    if (!target) {
        toast('Please enter a target', 'warning');
        return;
    }
    
    $('runScriptBtn').disabled = true;
    var sr = $('scriptsRunning'); if (sr) sr.textContent = parseInt(sr.textContent || 0) + 1;
    
    try {
        var url = API + '/api/scripts/' + currentScript.name + '/run';
        var res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target, port: port ? parseInt(port) : null })
        });
        
        if (!res.ok) {
            var err = await res.json();
            throw new Error(err.detail || 'Failed to run script');
        }
        
        var result = await res.json();
        displayScriptResult(result);
        toast('Script executed successfully', 'success');
        closeScriptModal();
    } catch (err) {
        toast('Script execution failed: ' + err.message, 'error');
    } finally {
        $('runScriptBtn').disabled = false;
        var sr = $('scriptsRunning'); if (sr) sr.textContent = Math.max(0, parseInt(sr.textContent) - 1);
    }
}

function displayScriptResult(result) {
    var card = $('scriptResultsCard');
    var output = $('scriptsOutput');
    
    if (!card || !output) return;
    
    card.style.display = 'block';
    
    var statusClass = result.status || 'success';
    var findings = result.findings || [];
    var statusIcon = statusClass === 'success' ? '✓' : statusClass === 'error' ? '✕' : '⏱';
    
    var html = '<div class="script-result ' + statusClass + '">' +
        '<div class="script-result-info">' +
        '<div class="script-result-name">' + statusIcon + ' ' + result.name.replace(/_/g, ' ').toUpperCase() + '</div>' +
        '<div class="script-result-meta">' +
        '<strong>' + (result.status || 'success').toUpperCase() + '</strong> | ' +
        'Time: <strong>' + (result.execution_time || 0).toFixed(2) + 's</strong> | ' +
        'Risk: <strong style="color:var(--accent)">' + (result.risk || 'info').toUpperCase() + '</strong>';
    
    if (result.target) {
        html += ' | Target: <strong>' + result.target + '</strong>';
    }
    if (result.port) {
        html += ' | Port: <strong>' + result.port + '</strong>';
    }
    html += '</div>';
    
    if (result.output) {
        var outputText = result.output.substring(0, 800);
        html += '<div class="script-result-output">' + 
            outputText.replace(/</g, '&lt;').replace(/>/g, '&gt;') + 
            (result.output.length > 800 ? '\n... (truncated)' : '') +
            '</div>';
    }
    
    if (findings && findings.length > 0) {
        html += '<div class="script-result-findings">' +
            '<strong>🔍 Findings (' + findings.length + ')</strong>' +
            '<ul>';
        findings.forEach(function(f, idx) {
            if (idx < 5) {  // Limit to first 5 findings
                var findingStr = typeof f === 'string' ? f : JSON.stringify(f);
                html += '<li>' + findingStr.substring(0, 150) + '</li>';
            }
        });
        if (findings.length > 5) {
            html += '<li><em>... and ' + (findings.length - 5) + ' more</em></li>';
        }
        html += '</ul></div>';
    }
    
    if (result.error) {
        html += '<div class="script-result-output" style="border-left-color:#f87171;color:#f87171;">❌ ' + result.error.substring(0, 300) + '</div>';
    }
    
    html += '</div>';
    
    output.innerHTML = html + output.innerHTML;
    
    // Keep last 10 results
    var results = output.querySelectorAll('.script-result');
    if (results.length > 10) {
        results[results.length - 1].remove();
    }
}

// Initialize scripts page
document.addEventListener('DOMContentLoaded', function() {
    if ($('scriptsSearch')) {
        $('scriptsSearch').addEventListener('input', filterScripts);
    }
    if ($('scriptsCategory')) {
        $('scriptsCategory').addEventListener('change', filterScripts);
    }
    if ($('clearResultsBtn')) {
        $('clearResultsBtn').addEventListener('click', function() {
            $('scriptsOutput').innerHTML = '';
            $('scriptResultsCard').style.display = 'none';
        });
    }
    
    // Close modal on outside click
    $('scriptModal').addEventListener('click', function(e) {
        if (e.target === this) closeScriptModal();
    });
});

// Original functions preserved but not used
async function runScript(name) {
    var target = prompt('Enter target:');
    if (!target) return;
    try {
        var res = await fetch(API + '/api/scripts/' + name + '/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: target }) });
        var data = await res.json();
        alert(data.name + '\nRisk: ' + data.risk + '\n\n' + data.output + (data.findings && data.findings.length ? '\n\nFindings:\n' + JSON.stringify(data.findings, null, 2) : ''));
    } catch (err) { toast('Failed', 'error'); }
}
