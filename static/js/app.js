/* === Ice-Leak-Monitor Client JS === */

// --- Activity type icons ---
var activityIcons = {
    start: '\u25B6',
    keyword: '\u{1F50D}',
    blackbird: '\u{1F426}',
    osint: '\u{1F50E}',
    github: '\u{2B22}',
    ollama: '\u{1F9E0}',
    trufflehog: '\u{1F43D}',
    gitleaks: '\u{1F50F}',
    custom: '\u{1F50E}',
    finding: '\u26A0',
    done: '\u2705',
    cancel: '\u{1F6D1}',
    error: '\u274C',
    warn: '\u26A0'
};

// --- Scan Trigger ---
async function triggerScan() {
    var btn = document.getElementById('btn-trigger-scan');
    if (btn) {
        btn.disabled = true;
        btn.textContent = 'Scan wird gestartet...';
    }

    try {
        var resp = await fetch('/api/scans/trigger', { method: 'POST' });
        var data = await resp.json();

        if (data.ok) {
            showIndicator(true);
            showCancelButton(true);
            if (btn) btn.textContent = 'Scan laeuft...';
            startPolling();
        } else {
            alert(data.message || 'Scan konnte nicht gestartet werden');
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Scan jetzt starten';
            }
        }
    } catch (e) {
        alert('Fehler: ' + e.message);
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Scan jetzt starten';
        }
    }
}

// --- Scan Cancel ---
async function cancelScan() {
    var cancelBtn = document.getElementById('btn-cancel-scan');
    if (cancelBtn) {
        cancelBtn.disabled = true;
        cancelBtn.textContent = 'Abbruch angefordert...';
    }

    try {
        var resp = await fetch('/api/scans/cancel', { method: 'POST' });
        var data = await resp.json();
        if (!data.ok) {
            alert(data.message || 'Abbruch fehlgeschlagen');
            if (cancelBtn) {
                cancelBtn.disabled = false;
                cancelBtn.textContent = 'Scan abbrechen';
            }
        }
    } catch (e) {
        alert('Fehler: ' + e.message);
        if (cancelBtn) {
            cancelBtn.disabled = false;
            cancelBtn.textContent = 'Scan abbrechen';
        }
    }
}

function showCancelButton(show) {
    var cancelBtn = document.getElementById('btn-cancel-scan');
    if (cancelBtn) {
        cancelBtn.classList.toggle('hidden', !show);
        if (show) {
            cancelBtn.disabled = false;
            cancelBtn.textContent = 'Scan abbrechen';
        }
    }
}

// --- Scan Status Polling ---
var pollInterval = null;

function startPolling() {
    if (pollInterval) return;
    pollInterval = setInterval(checkScanStatus, 2000);
}

function stopPolling() {
    if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
    }
}

async function checkScanStatus() {
    try {
        var resp = await fetch('/api/scans/progress');
        var data = await resp.json();

        showIndicator(data.running);
        updateSidebarIndicator(data);
        updateScanMonitor(data);
        updateActivityFeed(data.activities || []);

        if (data.running) {
            showCancelButton(!data.cancel_requested);
            // Show cancel hint if requested
            var hint = document.getElementById('monitor-cancel-hint');
            if (hint) hint.classList.toggle('hidden', !data.cancel_requested);
            // Disable cancel button if already requested
            var cancelBtn = document.getElementById('btn-cancel-scan');
            if (cancelBtn && data.cancel_requested) {
                cancelBtn.disabled = true;
                cancelBtn.textContent = 'Abbruch angefordert...';
            }
        }

        if (!data.running && pollInterval) {
            stopPolling();
            showCancelButton(false);
            var btn = document.getElementById('btn-trigger-scan');
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Scan jetzt starten';
            }
            // Hide monitor, reload page to show new results
            var monitor = document.getElementById('scan-monitor');
            if (monitor) monitor.classList.add('hidden');
            // Small delay so user sees final state
            setTimeout(function() { location.reload(); }, 1500);
        }
    } catch (e) {
        console.error('Poll error:', e);
    }
}

function showIndicator(running) {
    var ind = document.getElementById('scan-indicator');
    if (ind) {
        ind.classList.toggle('hidden', !running);
    }
}

function updateSidebarIndicator(data) {
    var text = document.getElementById('indicator-text');
    var stage = document.getElementById('indicator-stage');
    if (!text) return;

    if (data.running && data.stage_name) {
        text.textContent = data.stage_name;
        if (stage && data.count && data.total) {
            stage.textContent = data.count + '/' + data.total;
        } else if (stage) {
            stage.textContent = '';
        }
    } else {
        text.textContent = 'Scan laeuft...';
        if (stage) stage.textContent = '';
    }
}

// --- Live Scan Monitor ---
var lastLogCount = 0;

function updateScanMonitor(data) {
    var monitor = document.getElementById('scan-monitor');
    if (!monitor) return;

    if (data.running) {
        monitor.classList.remove('hidden');
    } else {
        monitor.classList.add('hidden');
        lastLogCount = 0;
        return;
    }

    // Stage badges
    var badges = monitor.querySelectorAll('.stage-badge');
    badges.forEach(function(badge) {
        var s = parseInt(badge.getAttribute('data-stage'), 10);
        badge.classList.toggle('stage-active', s === data.stage);
        badge.classList.toggle('stage-done', s < data.stage);
    });

    // Stage name + message
    var stageName = document.getElementById('monitor-stage-name');
    var message = document.getElementById('monitor-message');
    if (stageName) stageName.textContent = data.stage_name ? data.stage_name + ':' : '';
    if (message) message.textContent = data.message || '';

    // Counter
    var counter = document.getElementById('monitor-counter');
    if (counter) {
        if (data.total > 0) {
            counter.textContent = data.count + ' / ' + data.total;
        } else {
            counter.textContent = '';
        }
    }

    // Repos + Findings counters
    var repos = document.getElementById('monitor-repos');
    if (repos) repos.innerHTML = 'Repos: <strong>' + (data.repos_scanned_so_far || 0) + '</strong>';

    var findings = document.getElementById('monitor-findings');
    if (findings) findings.innerHTML = 'Findings: <strong>' + (data.findings_so_far || 0) + '</strong>';

    // Progress bar
    var fill = document.getElementById('monitor-progress-fill');
    if (fill) {
        fill.style.width = data.percent + '%';
        var colors = ['#539bf5', '#b083f0', '#539bf5', '#f0883e', '#57ab5a'];
        fill.style.background = data.cancel_requested ? '#f47067' : (colors[data.stage] || '#539bf5');
    }

    // Current item
    var currentItem = document.getElementById('monitor-current-item');
    if (currentItem) {
        currentItem.textContent = data.current_item || '';
    }

    // Live log
    var log = data.log || [];
    if (log.length !== lastLogCount) {
        var logEl = document.getElementById('monitor-log');
        if (logEl) {
            logEl.innerHTML = '';
            for (var i = 0; i < log.length; i++) {
                var entry = document.createElement('div');
                entry.className = 'log-entry';
                entry.innerHTML = '<span class="log-ts">' + log[i].ts + '</span> ' + escapeHtml(log[i].text);
                logEl.appendChild(entry);
            }
            logEl.scrollTop = logEl.scrollHeight;
        }
        lastLogCount = log.length;
    }
}

// --- Activity Feed ---
var lastActivityCount = 0;

function updateActivityFeed(activities) {
    var feed = document.getElementById('activity-feed');
    if (!feed) return;

    if (activities.length === 0 && lastActivityCount === 0) return;
    if (activities.length === lastActivityCount) return;

    feed.innerHTML = '';

    if (activities.length === 0) {
        feed.innerHTML = '<p class="empty-state">Keine Aktivitaeten</p>';
        lastActivityCount = 0;
        return;
    }

    // Show newest first
    for (var i = activities.length - 1; i >= 0; i--) {
        var a = activities[i];
        var row = document.createElement('div');
        row.className = 'activity-row activity-' + a.type;
        var icon = activityIcons[a.type] || '\u2022';
        row.innerHTML = '<span class="activity-icon">' + icon + '</span>' +
                         '<span class="activity-text">' + escapeHtml(a.text) + '</span>' +
                         '<span class="activity-ts">' + a.ts + '</span>';
        feed.appendChild(row);
    }
    lastActivityCount = activities.length;
}

function escapeHtml(text) {
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// --- Keywords CRUD ---
async function toggleKeyword(id) {
    try {
        var resp = await fetch('/keywords/' + id, { method: 'PATCH' });
        var data = await resp.json();
        if (data.ok) location.reload();
    } catch (e) {
        alert('Fehler: ' + e.message);
    }
}

async function deleteKeyword(id) {
    if (!confirm('Keyword wirklich loeschen?')) return;
    try {
        var resp = await fetch('/keywords/' + id, { method: 'DELETE' });
        var data = await resp.json();
        if (data.ok) {
            var row = document.getElementById('kw-' + id);
            if (row) row.remove();
        }
    } catch (e) {
        alert('Fehler: ' + e.message);
    }
}

// --- Findings ---
async function toggleFinding(id) {
    var notes = prompt('Notiz (optional):') || '';
    try {
        var resp = await fetch('/findings/' + id, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notes: notes }),
        });
        var data = await resp.json();
        if (data.ok) location.reload();
    } catch (e) {
        alert('Fehler: ' + e.message);
    }
}

// --- AI Override ---
async function setAiOverride(repoId, value) {
    try {
        var resp = await fetch('/repos/' + repoId + '/ai-override', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ai_scan_enabled: value }),
        });
        var data = await resp.json();
        if (data.ok) location.reload();
    } catch (e) {
        alert('Fehler: ' + e.message);
    }
}

// --- Repos ---
async function dismissRepo(id) {
    try {
        var resp = await fetch('/repos/' + id + '/dismiss', { method: 'POST' });
        var data = await resp.json();
        if (data.ok) location.reload();
    } catch (e) {
        alert('Fehler: ' + e.message);
    }
}

// --- Simple Bar Chart (no external deps) ---
function drawWeeklyChart(labels, counts) {
    var canvas = document.getElementById('weekly-chart');
    if (!canvas || !labels.length) return;

    var ctx = canvas.getContext('2d');
    var dpr = window.devicePixelRatio || 1;
    var rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = 250 * dpr;
    ctx.scale(dpr, dpr);

    var w = rect.width;
    var h = 250;
    var padL = 50, padR = 20, padT = 20, padB = 40;
    var chartW = w - padL - padR;
    var chartH = h - padT - padB;

    var maxVal = Math.max.apply(null, counts.concat([1]));
    var barW = Math.max(10, (chartW / labels.length) - 8);

    // Background
    ctx.fillStyle = '#2d333b';
    ctx.fillRect(0, 0, w, h);

    // Grid lines
    ctx.strokeStyle = '#444c56';
    ctx.lineWidth = 0.5;
    for (var i = 0; i <= 4; i++) {
        var y = padT + (chartH / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padL, y);
        ctx.lineTo(w - padR, y);
        ctx.stroke();

        ctx.fillStyle = '#768390';
        ctx.font = '11px sans-serif';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(maxVal - (maxVal / 4) * i), padL - 8, y + 4);
    }

    // Bars
    labels.forEach(function(label, i) {
        var x = padL + (chartW / labels.length) * i + 4;
        var barH = (counts[i] / maxVal) * chartH;
        var y = padT + chartH - barH;

        var grad = ctx.createLinearGradient(x, y, x, y + barH);
        if (counts[i] > 0) {
            grad.addColorStop(0, '#f47067');
            grad.addColorStop(1, '#f0883e');
        } else {
            grad.addColorStop(0, '#444c56');
            grad.addColorStop(1, '#373e47');
        }
        ctx.fillStyle = grad;
        ctx.fillRect(x, y, barW, barH);

        if (counts[i] > 0) {
            ctx.fillStyle = '#cdd9e5';
            ctx.font = '11px sans-serif';
            ctx.textAlign = 'center';
            ctx.fillText(counts[i], x + barW / 2, y - 6);
        }

        ctx.fillStyle = '#768390';
        ctx.font = '10px sans-serif';
        ctx.textAlign = 'center';
        ctx.save();
        ctx.translate(x + barW / 2, h - 4);
        ctx.rotate(-0.4);
        ctx.fillText(label.slice(-5), 0, 0);
        ctx.restore();
    });
}

// --- Settings: Module Toggle ---
async function toggleModule(key) {
    try {
        var resp = await fetch('/settings/modules/' + key + '/toggle', { method: 'POST' });
        var data = await resp.json();
        if (data.ok) {
            var row = document.getElementById('module-' + key);
            if (row) {
                var badge = row.querySelector('.module-status .badge');
                if (badge) {
                    if (data.is_enabled) {
                        badge.className = 'badge badge-completed';
                        badge.textContent = 'Aktiv';
                    } else {
                        badge.className = 'badge badge-skipped';
                        badge.textContent = 'Inaktiv';
                    }
                }
            }
        }
    } catch (e) {
        alert('Fehler: ' + e.message);
    }
}

async function saveModuleConfig(key) {
    var input = document.getElementById('apikey-' + key);
    if (!input) return;

    var apiKey = input.value.trim();
    if (!apiKey || apiKey.indexOf('****') !== -1) {
        alert('Bitte einen gueltigen API-Key eingeben');
        return;
    }

    try {
        var resp = await fetch('/settings/modules/' + key + '/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ api_key: apiKey }),
        });
        var data = await resp.json();
        if (data.ok) {
            input.type = 'password';
            input.value = apiKey.substring(0, 4) + '****' + apiKey.substring(apiKey.length - 4);
            // Update status indicator
            var row = document.getElementById('module-' + key);
            if (row) {
                var status = row.querySelector('.api-key-status');
                if (status) {
                    status.className = 'api-key-status api-key-ok';
                    status.textContent = 'Key konfiguriert';
                }
            }
        }
    } catch (e) {
        alert('Fehler: ' + e.message);
    }
}

// --- Init: check if scan is running + load activities ---
(async function init() {
    try {
        var resp = await fetch('/api/scans/progress');
        var data = await resp.json();

        // Always load activities even when no scan is running
        updateActivityFeed(data.activities || []);

        if (data.running) {
            showIndicator(true);
            showCancelButton(!data.cancel_requested);
            updateSidebarIndicator(data);
            updateScanMonitor(data);
            var btn = document.getElementById('btn-trigger-scan');
            if (btn) {
                btn.disabled = true;
                btn.textContent = 'Scan laeuft...';
            }
            startPolling();
        }
    } catch (e) {
        // Ignore init error
    }
})();
