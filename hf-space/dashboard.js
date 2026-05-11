// ===== RedactAI Dashboard Logic — Connected to Live Presidio API =====

const API_BASE = window.location.origin + '/api/v1';
let API_AVAILABLE = false;

// Check if API is reachable (compatible with all browsers)
async function checkAPI() {
  try {
    var controller = new AbortController();
    var timer = setTimeout(function() { controller.abort(); }, 15000);
    var res = await fetch(window.location.origin + '/api/health', { signal: controller.signal });
    clearTimeout(timer);
    if (res.ok) { API_AVAILABLE = true; return true; }
  } catch(e) {}
  return false;
}

// ---- Page Navigation (initialized in DOMContentLoaded below) ----
function switchPage(pageId) {
  document.querySelectorAll('.page').forEach(function(p) { p.classList.remove('active'); });
  document.querySelectorAll('.sidebar__link').forEach(function(l) { l.classList.remove('active'); });
  var page = document.getElementById('page-' + pageId);
  var nav = document.getElementById('nav-' + pageId);
  if (page) page.classList.add('active');
  if (nav) nav.classList.add('active');
  var title = document.getElementById('page-title');
  if (title) title.textContent = nav ? nav.textContent.trim() : pageId;
}
// Sidebar listeners are attached inside DOMContentLoaded

// ---- Live Data Store (populated from API) ----
let SCAN_HISTORY = [];
let LIVE_STATS = { total_scans: 0, total_entities: 0, avg_response_ms: 0, entity_type_breakdown: {} };

const PII_TYPE_COLORS = {
  'Person Name': '#f472b6', 'Email': '#74c0fc', 'Phone': '#51cf66',
  'Location': '#fdcb6e', 'Credit Card': '#ffd43b', 'SSN': '#ff6b6b',
  'IP Address': '#22d3ee', 'Date/Time': '#a29bfe', 'URL': '#74c0fc',
  'Username': '#a29bfe', 'Password': '#ff6b6b', 'Aadhaar': '#ff6b6b',
  'PAN Card': '#ff6b6b', 'ID Card': '#ff6b6b', 'Tax Number': '#ff6b6b',
  'Account Number': '#ffd43b',
};

// ---- Fetch Live Stats ----
async function fetchStats() {
  if (!API_AVAILABLE) return;
  try {
    const res = await fetch(API_BASE + '/stats');
    LIVE_STATS = await res.json();
    updateOverviewCards();
    renderDonutChart();
  } catch(e) {}
}

async function fetchHistory() {
  if (!API_AVAILABLE) return;
  try {
    const res = await fetch(API_BASE + '/history?per_page=50');
    const data = await res.json();
    SCAN_HISTORY = data.items || [];
    renderRecentTable();
    renderHistoryTable();
  } catch(e) {}
}

// ---- Overview Cards (live data) ----
function updateOverviewCards() {
  const el = (id) => document.getElementById(id);
  if (!el('metric-scans')) return;

  el('metric-scans').textContent = LIVE_STATS.total_scans.toLocaleString();
  el('metric-pii').textContent = LIVE_STATS.total_entities.toLocaleString();
  el('metric-redacted').textContent = LIVE_STATS.total_entities.toLocaleString();
  el('metric-ms').textContent = LIVE_STATS.avg_response_ms + 'ms';

  // Update usage counter in sidebar
  const usage = el('usage-count');
  if (usage) usage.textContent = `${LIVE_STATS.total_scans} / 1,000 docs`;

  // Update sidebar progress bar
  const fill = document.querySelector('.sidebar__plan-fill');
  if (fill) fill.style.width = Math.min(100, (LIVE_STATS.total_scans / 1000) * 100) + '%';

  // Update trend badges
  if (LIVE_STATS.total_scans > 0) {
    ['trend-scans', 'trend-pii', 'trend-redacted', 'trend-ms'].forEach(id => {
      const badge = el(id);
      if (badge) { badge.textContent = '● Live'; badge.className = 'metric-card__trend up'; }
    });
  }
}

// ---- Bar Chart (real scan activity) ----
function renderBarChart() {
  const container = document.getElementById('chart-scans');
  if (!container) return;

  // Group history by day
  const dayMap = {};
  const now = new Date();
  for (let i = 0; i < 14; i++) {
    const d = new Date(now);
    d.setDate(d.getDate() - (13 - i));
    const key = d.toISOString().split('T')[0];
    dayMap[key] = 0;
  }
  SCAN_HISTORY.forEach(h => {
    const day = h.timestamp?.split('T')[0];
    if (day && dayMap[day] !== undefined) dayMap[day]++;
  });

  const data = Object.values(dayMap);
  const labels = Object.keys(dayMap).map(d => new Date(d).getDate());
  const max = Math.max(...data, 1);

  container.innerHTML = `<div class="bar-chart">${data.map((v, i) => `
    <div class="bar-col">
      <div class="bar" style="height:${(v / max) * 100}%" title="${v} scans"></div>
      <div class="bar-label">${i % 2 === 0 ? labels[i] : ''}</div>
    </div>
  `).join('')}</div>`;

  setTimeout(() => {
    container.querySelectorAll('.bar').forEach((bar, i) => {
      const h = bar.style.height;
      bar.style.height = '0%';
      setTimeout(() => { bar.style.height = h; }, i * 30);
    });
  }, 100);
}

// ---- Donut Chart (PII Types from live stats) ----
function renderDonutChart() {
  const chart = document.getElementById('donut-chart');
  const legend = document.getElementById('donut-legend');
  if (!chart || !legend) return;

  const breakdown = LIVE_STATS.entity_type_breakdown || {};
  const items = Object.entries(breakdown).map(([label, count]) => ({
    label, count,
    color: PII_TYPE_COLORS[label] || '#' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0'),
  }));

  if (items.length === 0) {
    chart.style.background = 'conic-gradient(var(--bg-tertiary) 0deg 360deg)';
    chart.innerHTML = `<div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:100px;height:100px;border-radius:50%;background:var(--bg-card);"></div>
      <div class="donut-center"><div class="donut-center__value">0</div><div class="donut-center__label">Total PII</div></div>`;
    legend.innerHTML = '<div style="color:var(--text-muted);font-size:13px;">Scan some text to see PII breakdown</div>';
    return;
  }

  const total = items.reduce((s, d) => s + d.count, 0);
  let cumulative = 0;
  const segments = items.map(d => {
    const start = (cumulative / total) * 360;
    cumulative += d.count;
    const end = (cumulative / total) * 360;
    return { ...d, start, end };
  });

  let gradient = 'conic-gradient(';
  segments.forEach((s, i) => {
    gradient += `${s.color} ${s.start}deg ${s.end}deg`;
    if (i < segments.length - 1) gradient += ', ';
  });
  gradient += ')';

  chart.style.background = gradient;
  chart.innerHTML = `
    <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
      width:100px;height:100px;border-radius:50%;background:var(--bg-card);"></div>
    <div class="donut-center">
      <div class="donut-center__value">${total.toLocaleString()}</div>
      <div class="donut-center__label">Total PII</div>
    </div>`;

  legend.innerHTML = segments.map(s => `
    <div class="donut-legend__item">
      <div class="donut-legend__dot" style="background:${s.color}"></div>
      <span>${s.label}</span>
      <span class="donut-legend__val">${s.count}</span>
    </div>
  `).join('');
}

// ---- Recent Scans Table ----
function renderRecentTable() {
  const tbody = document.getElementById('recent-tbody');
  if (!tbody) return;
  const recent = SCAN_HISTORY.slice(0, 5);
  if (recent.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px;">No scans yet. Use the Scanner to get started!</td></tr>';
    return;
  }
  tbody.innerHTML = recent.map(s => {
    const t = new Date(s.timestamp);
    const time = t.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
    return `<tr>
      <td>${time}</td>
      <td>${s.source || 'Text Input'}</td>
      <td style="font-weight:600;color:var(--text-primary);">${s.entity_count}</td>
      <td>${(s.types || []).slice(0, 3).join(', ')}</td>
      <td><span class="badge badge--success">Completed</span></td>
      <td><button class="btn btn--ghost btn--small">View</button></td>
    </tr>`;
  }).join('');
}

// ---- Full History Table ----
let historyPage = 1;
const HISTORY_PER_PAGE = 10;

function renderHistoryTable() {
  const tbody = document.getElementById('history-tbody');
  const info = document.getElementById('pagination-info');
  if (!tbody) return;
  const totalPages = Math.max(1, Math.ceil(SCAN_HISTORY.length / HISTORY_PER_PAGE));
  const start = (historyPage - 1) * HISTORY_PER_PAGE;
  const slice = SCAN_HISTORY.slice(start, start + HISTORY_PER_PAGE);

  if (slice.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:24px;">No scan history yet</td></tr>';
    if (info) info.textContent = 'Page 1 of 1';
    return;
  }

  tbody.innerHTML = slice.map(s => {
    const t = new Date(s.timestamp);
    const dateStr = t.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
    const timeStr = t.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });
    return `<tr>
      <td>${dateStr} ${timeStr}</td>
      <td>${s.source || 'Text Input'}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${s.preview || '-'}</td>
      <td style="font-weight:600;color:var(--text-primary);">${s.entity_count}</td>
      <td>${(s.types || []).slice(0, 3).join(', ')}</td>
      <td><span class="badge badge--success">Completed</span></td>
    </tr>`;
  }).join('');

  if (info) info.textContent = `Page ${historyPage} of ${totalPages}`;
}

document.getElementById('prev-page')?.addEventListener('click', () => {
  if (historyPage > 1) { historyPage--; renderHistoryTable(); }
});
document.getElementById('next-page')?.addEventListener('click', () => {
  const totalPages = Math.ceil(SCAN_HISTORY.length / HISTORY_PER_PAGE);
  if (historyPage < totalPages) { historyPage++; renderHistoryTable(); }
});

// ---- Scanner Page — Uses Live Presidio API ----
function initScannerPage() {
  const input = document.getElementById('scan-input');
  const output = document.getElementById('scan-output');
  const entities = document.getElementById('scan-entities-grid');
  const count = document.getElementById('scan-entity-count');
  if (!input) return;

  let mode = 'highlight';
  let debounceTimer = null;

  async function process() {
    const text = input.value;
    if (!text.trim()) {
      output.innerHTML = '';
      count.textContent = '0';
      entities.innerHTML = '<span style="color:var(--text-muted);font-size:14px;">No PII detected yet.</span>';
      return;
    }

    // Try API first, then fallback to client-side
    let findings = [];
    if (API_AVAILABLE) {
      try {
        const res = await fetch(API_BASE + '/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, mode, score_threshold: 0.3 }),
        });
        const data = await res.json();

        // Show redacted text in output
        if (mode === 'redact') {
          output.innerHTML = escapeHtml(data.redacted);
        } else {
          // Build highlighted output from entities
          let result = '';
          let lastEnd = 0;
          for (const e of data.entities) {
            result += escapeHtml(text.substring(lastEnd, e.start));
            result += `<span class="pii-tag pii-tag--${e.cssClass}" title="${e.label}: ${escapeHtml(e.text)}">${escapeHtml(e.text)}</span>`;
            lastEnd = e.end;
          }
          result += escapeHtml(text.substring(lastEnd));
          output.innerHTML = result;
        }

        count.textContent = data.count;

        // Entity chips
        const summary = data.entity_summary || {};
        if (data.count === 0) {
          entities.innerHTML = '<span style="color:var(--text-muted);font-size:14px;">No PII detected.</span>';
        } else {
          entities.innerHTML = Object.entries(summary).map(([label, info]) => `
            <div class="entity-chip entity-chip--${info.cssClass || 'other'}">
              <span class="entity-chip__count">${info.count}</span>
              <span>${info.icon || ''} ${label}</span>
            </div>
          `).join('');
        }

        // Refresh stats & history
        fetchStats();
        fetchHistory();
        return;
      } catch(e) {}
    }

    // Fallback to client-side regex
    if (typeof detectPII === 'function') {
      findings = detectPII(text);
      output.innerHTML = buildHighlightedOutput(text, findings, mode);
      count.textContent = findings.length;
      const summary = getEntitySummary(findings);
      if (findings.length === 0) {
        entities.innerHTML = '<span style="color:var(--text-muted);font-size:14px;">No PII detected.</span>';
      } else {
        entities.innerHTML = Object.entries(summary).map(([label, data]) => `
          <div class="entity-chip entity-chip--${data.cssClass}">
            <span class="entity-chip__count">${data.count}</span>
            <span>${data.icon} ${label}</span>
          </div>
        `).join('');
      }
    }
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Debounced input
  input.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(process, API_AVAILABLE ? 400 : 50);
  });

  // Mode toggles
  document.querySelectorAll('#page-scanner .toggle-group__btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#page-scanner .toggle-group__btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      mode = btn.dataset.mode;
      process();
    });
  });

  // Sample button
  document.getElementById('scan-btn-sample')?.addEventListener('click', () => {
    input.value = `Hi, I'm Rahul Sharma and I need help with my account.\n\nMy email is rahul.sharma@gmail.com and my phone number is +91 9876543210.\nI live at 42 Mahatma Gandhi Road, Bangalore 560001.\n\nMy Aadhaar number is 1234-5678-9012 and PAN is ABCDE1234F.\nPlease refund to my credit card 4532-1234-5678-9012.\n\nAlso, my colleague Priya Gupta (priya.g@outlook.com, phone: 8765432109)\nreported the same issue from IP 192.168.1.42.\n\nDOB: 15/08/1995\n\nThanks,\nRahul Sharma`;
    process();
  });

  document.getElementById('scan-btn-clear')?.addEventListener('click', () => { input.value = ''; process(); });

  // Copy Redacted
  document.getElementById('scan-btn-copy')?.addEventListener('click', async () => {
    const text = input.value;
    let redacted = text;
    if (API_AVAILABLE) {
      try {
        const res = await fetch(API_BASE + '/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, mode: 'redact' }),
        });
        const data = await res.json();
        redacted = data.redacted;
      } catch(e) {}
    } else if (typeof detectPII === 'function') {
      const findings = detectPII(text);
      for (let i = findings.length - 1; i >= 0; i--) {
        redacted = redacted.substring(0, findings[i].start) + findings[i].redacted + redacted.substring(findings[i].end);
      }
    }
    navigator.clipboard.writeText(redacted).then(() => {
      const btn = document.getElementById('scan-btn-copy');
      btn.textContent = '✓ Copied!';
      setTimeout(() => btn.textContent = '📋 Copy Redacted', 2000);
    });
  });
}

// ---- File Upload — Uses Real API ----
function initFileUpload() {
  const zone = document.getElementById('upload-zone');
  const fileInput = document.getElementById('file-input');
  const browseBtn = document.getElementById('browse-btn');
  const queueCard = document.getElementById('file-queue-card');
  const queue = document.getElementById('file-queue');
  const resultsCard = document.getElementById('file-results-card');
  const resultsTbody = document.getElementById('file-results-tbody');
  if (!zone) return;

  let uploadedFiles = [];
  window.REDACTED_FILES = {}; // Store redacted content for downloading

  browseBtn?.addEventListener('click', () => fileInput.click());
  zone.addEventListener('click', (e) => { if (e.target === zone || e.target.closest('.upload-zone__icon,.upload-zone__title,.upload-zone__desc')) fileInput.click(); });

  zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault(); zone.classList.remove('dragover');
    handleFiles(e.dataTransfer.files);
  });
  fileInput.addEventListener('change', () => handleFiles(fileInput.files));

  function handleFiles(files) {
    uploadedFiles = [...files];
    queueCard.style.display = 'block';
    queue.innerHTML = uploadedFiles.map((f, i) => `
      <div class="file-item" id="file-item-${i}">
        <div class="file-item__icon">${f.name.endsWith('.csv') ? '📊' : f.name.endsWith('.json') ? '📋' : '📄'}</div>
        <div class="file-item__info">
          <div class="file-item__name">${f.name}</div>
          <div class="file-item__size">${(f.size / 1024).toFixed(1)} KB</div>
          <div class="file-item__progress"><div class="file-item__progress-bar" style="width:0%"></div></div>
        </div>
        <span class="badge" id="file-status-${i}">Queued</span>
      </div>
    `).join('');
  }

  document.getElementById('process-all-btn')?.addEventListener('click', async () => {
    resultsCard.style.display = 'none';
    const fileResults = [];

    for (let i = 0; i < uploadedFiles.length; i++) {
      const f = uploadedFiles[i];
      const bar = document.querySelector(`#file-item-${i} .file-item__progress-bar`);
      const status = document.getElementById(`file-status-${i}`);

      status.textContent = 'Scanning...';
      status.className = 'badge badge--warning';
      bar.style.width = '30%';

      if (API_AVAILABLE) {
        try {
          const formData = new FormData();
          formData.append('file', f);
          bar.style.width = '60%';

          const res = await fetch(API_BASE + '/scan/file', { method: 'POST', body: formData });
          const data = await res.json();
          bar.style.width = '100%';

          window.REDACTED_FILES[f.name] = data.redacted_text;
          fileResults.push({ name: f.name, size: f.size, entities: data.entity_count, ms: data.processing_ms, success: true });
          status.textContent = 'Done';
          status.className = 'badge badge--success';
        } catch (err) {
          bar.style.width = '100%';
          status.textContent = 'Error';
          status.className = 'badge badge--danger';
          fileResults.push({ name: f.name, size: f.size, entities: '?', ms: '-', success: false });
        }
      } else {
        // Simulate for demo
        await new Promise(r => setTimeout(r, 800));
        bar.style.width = '100%';
        status.textContent = 'Done';
        status.className = 'badge badge--success';
        fileResults.push({ name: f.name, size: f.size, entities: Math.floor(Math.random() * 50) + 5, ms: Math.floor(Math.random() * 500) });
      }
    }

    // Show results table
    resultsCard.style.display = 'block';
    resultsTbody.innerHTML = fileResults.map((r, index) => `
      <tr>
        <td>${r.name}</td>
        <td>${(r.size / 1024).toFixed(1)} KB</td>
        <td style="font-weight:600;color:var(--text-primary);">${r.entities}</td>
        <td><span class="badge ${r.success ? 'badge--success' : 'badge--danger'}">${r.success ? 'Redacted' : 'Failed'}</span></td>
        <td>
          ${r.success ? `<button class="btn btn--outline btn--small" onclick="downloadFile('${r.name}')">⬇️ Download</button>` : ''}
        </td>
      </tr>
    `).join('');

    // Refresh stats
    fetchStats();
    fetchHistory();
  });

  document.getElementById('download-all-btn')?.addEventListener('click', () => {
    let delay = 0;
    Object.keys(window.REDACTED_FILES).forEach(filename => {
      setTimeout(() => window.downloadFile(filename), delay);
      delay += 500; // 500ms stagger to prevent browser blocking multiple downloads
    });
  });
}

window.downloadFile = function(filename) {
  const content = window.REDACTED_FILES[filename];
  if (!content) return;
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'redacted_' + filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// ---- API Keys ----
function initAPIKeys() {
  const list = document.getElementById('api-keys-list');
  const createBtn = document.getElementById('create-key-btn');
  if (!list) return;

  let keys = [
    { name: 'Production Key', key: 'rda_live_sk_7f8a...3b2d', created: '2 days ago', lastUsed: '1 hour ago', status: 'active' },
    { name: 'Development Key', key: 'rda_test_sk_9c4e...1a7f', created: '1 week ago', lastUsed: '3 days ago', status: 'active' },
  ];

  function render() {
    list.innerHTML = keys.map((k, i) => `
      <div class="api-key-card">
        <div style="font-size:24px;">🔑</div>
        <div class="api-key-card__info">
          <div class="api-key-card__name">${k.name}</div>
          <div class="api-key-card__key">${k.key}</div>
          <div class="api-key-card__meta">Created ${k.created} · Last used ${k.lastUsed}</div>
        </div>
        <span class="badge badge--success">Active</span>
        <div class="api-key-card__actions">
          <button class="btn btn--ghost btn--small">📋 Copy</button>
          <button class="btn btn--danger btn--small" onclick="this.closest('.api-key-card').remove()">🗑️</button>
        </div>
      </div>
    `).join('');
  }
  render();

  createBtn?.addEventListener('click', () => {
    const id = Math.random().toString(36).substring(2, 6);
    keys.unshift({ name: 'New Key ' + id, key: 'rda_live_sk_' + Math.random().toString(36).substring(2, 14), created: 'Just now', lastUsed: 'Never', status: 'active' });
    render();
  });

  // Copy code snippets
  document.getElementById('copy-curl')?.addEventListener('click', () => {
    const code = document.querySelector('#page-api .code-block__body code').textContent;
    navigator.clipboard.writeText(code);
    const btn = document.getElementById('copy-curl');
    btn.textContent = '✓ Copied!';
    setTimeout(() => btn.textContent = '📋 Copy', 1500);
  });
}

// ---- Export History as CSV ----
document.getElementById('export-history-btn')?.addEventListener('click', () => {
  const csv = 'Date,Source,Preview,Entities,Status\n' + SCAN_HISTORY.map(s =>
    `"${s.timestamp}","${s.source}","${s.preview || ''}",${s.entity_count},"Completed"`
  ).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'redactai_history.csv';
  a.click();
});

// ---- Init Everything ----
document.addEventListener('DOMContentLoaded', function() {
  // ---- Sidebar Navigation (event delegation) ----
  var sidebarNav = document.querySelector('.sidebar__nav');
  if (sidebarNav) {
    sidebarNav.addEventListener('click', function(e) {
      var btn = e.target.closest('.sidebar__link');
      if (btn && btn.dataset.page) {
        switchPage(btn.dataset.page);
      }
    });
  }

  // Mobile menu toggle
  var menuToggle = document.getElementById('menu-toggle');
  if (menuToggle) {
    menuToggle.addEventListener('click', function() {
      document.getElementById('sidebar').classList.toggle('open');
    });
  }

  // Render charts and tables
  renderBarChart();
  renderDonutChart();
  renderRecentTable();
  renderHistoryTable();
  initScannerPage();
  initFileUpload();
  initAPIKeys();

  // Export CSV button
  var exportBtn = document.getElementById('export-history-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', function() {
      var base = API_AVAILABLE ? API_BASE : '';
      window.open(base + '/export?format=csv', '_blank');
    });
  }

  // Check API and fetch live data (non-blocking)
  checkAPI().then(function() {
    if (API_AVAILABLE) {
      fetchStats();
      fetchHistory();
    }
  });
});
