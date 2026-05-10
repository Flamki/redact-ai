// ===== RedactAI Dashboard Logic =====

// ---- Page Navigation ----
function switchPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.sidebar__link').forEach(l => l.classList.remove('active'));
  const page = document.getElementById('page-' + pageId);
  const nav = document.getElementById('nav-' + pageId);
  if (page) page.classList.add('active');
  if (nav) nav.classList.add('active');
  document.getElementById('page-title').textContent = nav ? nav.textContent.trim() : pageId;
}

document.querySelectorAll('.sidebar__link').forEach(btn => {
  btn.addEventListener('click', () => switchPage(btn.dataset.page));
});

// Mobile menu toggle
document.getElementById('menu-toggle')?.addEventListener('click', () => {
  document.getElementById('sidebar').classList.toggle('open');
});

// ---- Mock Data ----
const SCAN_HISTORY = [];
const PII_TYPE_DATA = [
  { label: 'Emails', count: 842, color: '#74c0fc' },
  { label: 'Phone Numbers', count: 634, color: '#51cf66' },
  { label: 'Person Names', count: 521, color: '#f472b6' },
  { label: 'Government IDs', count: 389, color: '#ff6b6b' },
  { label: 'Credit Cards', count: 245, color: '#ffd43b' },
  { label: 'IP Addresses', count: 132, color: '#22d3ee' },
  { label: 'Dates', count: 84, color: '#a29bfe' },
];

// Generate mock history
const sources = ['Text Input', 'File: report.csv', 'API Call', 'File: users.json', 'Text Input', 'File: logs.txt'];
const statuses = ['Completed', 'Completed', 'Completed', 'Completed', 'Completed', 'Warning'];
for (let i = 0; i < 47; i++) {
  const d = new Date(); d.setHours(d.getHours() - i * 3);
  SCAN_HISTORY.push({
    date: d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }),
    time: d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' }),
    source: sources[i % sources.length],
    preview: ['Customer data with emails and phones...', 'Employee records batch...', 'Support ticket analysis...', 'User registration dump...', 'Payment logs processing...'][i % 5],
    entities: Math.floor(Math.random() * 30) + 2,
    types: ['📧📱👤', '🆔💳📧', '📱👤📍', '📧🆔🌐', '💳📱📅'][i % 5],
    status: statuses[i % statuses.length],
  });
}

// ---- Bar Chart (Scans Over Time) ----
function renderBarChart() {
  const container = document.getElementById('chart-scans');
  if (!container) return;
  const days = 30;
  const data = Array.from({ length: days }, (_, i) => {
    const base = 8 + Math.sin(i / 4) * 5;
    return Math.floor(base + Math.random() * 8);
  });
  const max = Math.max(...data);

  const labels = Array.from({ length: days }, (_, i) => {
    const d = new Date(); d.setDate(d.getDate() - (days - 1 - i));
    return d.getDate();
  });

  container.innerHTML = `<div class="bar-chart">${data.map((v, i) => `
    <div class="bar-col">
      <div class="bar" style="height:${(v / max) * 100}%" title="${v} scans"></div>
      <div class="bar-label">${i % 5 === 0 ? labels[i] : ''}</div>
    </div>
  `).join('')}</div>`;

  // Animate bars in
  setTimeout(() => {
    container.querySelectorAll('.bar').forEach((bar, i) => {
      const h = bar.style.height;
      bar.style.height = '0%';
      setTimeout(() => { bar.style.height = h; }, i * 20);
    });
  }, 100);
}

// ---- Donut Chart (PII Types) ----
function renderDonutChart() {
  const chart = document.getElementById('donut-chart');
  const legend = document.getElementById('donut-legend');
  if (!chart || !legend) return;

  const total = PII_TYPE_DATA.reduce((s, d) => s + d.count, 0);
  let cumulative = 0;
  const segments = PII_TYPE_DATA.map(d => {
    const start = (cumulative / total) * 360;
    cumulative += d.count;
    const end = (cumulative / total) * 360;
    return { ...d, start, end };
  });

  // Build conic gradient
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
  tbody.innerHTML = SCAN_HISTORY.slice(0, 5).map(s => `
    <tr>
      <td>${s.time}</td>
      <td>${s.source}</td>
      <td style="font-weight:600;color:var(--text-primary);">${s.entities}</td>
      <td>${s.types}</td>
      <td><span class="badge badge--${s.status === 'Completed' ? 'success' : 'warning'}">${s.status}</span></td>
      <td><button class="btn btn--ghost btn--small">View</button></td>
    </tr>
  `).join('');
}

// ---- Full History Table ----
let historyPage = 1;
const HISTORY_PER_PAGE = 10;

function renderHistoryTable() {
  const tbody = document.getElementById('history-tbody');
  const info = document.getElementById('pagination-info');
  if (!tbody) return;
  const totalPages = Math.ceil(SCAN_HISTORY.length / HISTORY_PER_PAGE);
  const start = (historyPage - 1) * HISTORY_PER_PAGE;
  const slice = SCAN_HISTORY.slice(start, start + HISTORY_PER_PAGE);

  tbody.innerHTML = slice.map(s => `
    <tr>
      <td>${s.date} ${s.time}</td>
      <td>${s.source}</td>
      <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${s.preview}</td>
      <td style="font-weight:600;color:var(--text-primary);">${s.entities}</td>
      <td>${s.types}</td>
      <td><span class="badge badge--${s.status === 'Completed' ? 'success' : 'warning'}">${s.status}</span></td>
    </tr>
  `).join('');

  if (info) info.textContent = `Page ${historyPage} of ${totalPages}`;
}

document.getElementById('prev-page')?.addEventListener('click', () => {
  if (historyPage > 1) { historyPage--; renderHistoryTable(); }
});
document.getElementById('next-page')?.addEventListener('click', () => {
  const totalPages = Math.ceil(SCAN_HISTORY.length / HISTORY_PER_PAGE);
  if (historyPage < totalPages) { historyPage++; renderHistoryTable(); }
});

// ---- Scanner Page (reuse PII engine from app.js) ----
function initScannerPage() {
  const input = document.getElementById('scan-input');
  const output = document.getElementById('scan-output');
  const entities = document.getElementById('scan-entities-grid');
  const count = document.getElementById('scan-entity-count');
  if (!input || typeof detectPII === 'undefined') return;

  let mode = 'highlight';

  function process() {
    const text = input.value;
    const findings = detectPII(text);
    output.innerHTML = buildHighlightedOutput(text, findings, mode);
    count.textContent = findings.length;
    const summary = getEntitySummary(findings);
    if (findings.length === 0) {
      entities.innerHTML = '<span style="color:var(--text-muted);font-size:14px;">No PII detected yet.</span>';
    } else {
      entities.innerHTML = Object.entries(summary).map(([label, data]) => `
        <div class="entity-chip entity-chip--${data.cssClass}">
          <span class="entity-chip__count">${data.count}</span>
          <span>${data.icon} ${label}</span>
        </div>
      `).join('');
    }
  }

  input.addEventListener('input', process);

  // Toggles within scanner page
  document.querySelectorAll('#page-scanner .toggle-group__btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('#page-scanner .toggle-group__btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      mode = btn.dataset.mode;
      process();
    });
  });

  document.getElementById('scan-btn-sample')?.addEventListener('click', () => {
    input.value = `Hi, I'm Rahul Sharma and I need help with my account.\n\nMy email is rahul.sharma@gmail.com and my phone number is +91 9876543210.\nI live at 42 Mahatma Gandhi Road, Bangalore 560001.\n\nMy Aadhaar number is 1234-5678-9012 and PAN is ABCDE1234F.\nPlease refund to my credit card 4532-1234-5678-9012.\n\nAlso, my colleague Priya Gupta (priya.g@outlook.com, phone: 8765432109)\nreported the same issue from IP 192.168.1.42.\n\nDOB: 15/08/1995\n\nThanks,\nRahul Sharma`;
    process();
  });
  document.getElementById('scan-btn-clear')?.addEventListener('click', () => { input.value = ''; process(); });
  document.getElementById('scan-btn-copy')?.addEventListener('click', () => {
    const text = input.value;
    const findings = detectPII(text);
    let result = text;
    for (let i = findings.length - 1; i >= 0; i--) {
      result = result.substring(0, findings[i].start) + findings[i].redacted + result.substring(findings[i].end);
    }
    navigator.clipboard.writeText(result).then(() => {
      const btn = document.getElementById('scan-btn-copy');
      btn.textContent = '✓ Copied!';
      setTimeout(() => btn.textContent = '📋 Copy Redacted', 2000);
    });
  });
}

// ---- File Upload ----
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

  document.getElementById('process-all-btn')?.addEventListener('click', () => {
    uploadedFiles.forEach((f, i) => {
      const bar = document.querySelector(`#file-item-${i} .file-item__progress-bar`);
      const status = document.getElementById(`file-status-${i}`);
      let progress = 0;
      const interval = setInterval(() => {
        progress += Math.random() * 25;
        if (progress >= 100) {
          progress = 100;
          clearInterval(interval);
          status.textContent = 'Done';
          status.className = 'badge badge--success';

          // Show results
          if (i === uploadedFiles.length - 1) {
            resultsCard.style.display = 'block';
            resultsTbody.innerHTML = uploadedFiles.map(file => `
              <tr>
                <td>${file.name}</td>
                <td>${(file.size / 1024).toFixed(1)} KB</td>
                <td style="font-weight:600;color:var(--text-primary);">${Math.floor(Math.random() * 50) + 5}</td>
                <td><span class="badge badge--success">Redacted</span></td>
                <td><button class="btn btn--ghost btn--small">⬇ Download</button></td>
              </tr>
            `).join('');
          }
        }
        bar.style.width = progress + '%';
      }, 200 + Math.random() * 300);
    });
  });
}

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
    `"${s.date} ${s.time}","${s.source}","${s.preview}",${s.entities},"${s.status}"`
  ).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'redactai_history.csv';
  a.click();
});

// ---- Init Everything ----
document.addEventListener('DOMContentLoaded', () => {
  renderBarChart();
  renderDonutChart();
  renderRecentTable();
  renderHistoryTable();
  initScannerPage();
  initFileUpload();
  initAPIKeys();
});
