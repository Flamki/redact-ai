// ===== RedactAI — PII Detection Engine =====

const PII_PATTERNS = [
  {
    type: 'email', label: 'Email', cssClass: 'email',
    icon: '📧', redacted: '[EMAIL]',
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g
  },
  {
    type: 'phone', label: 'Phone', cssClass: 'phone',
    icon: '📱', redacted: '[PHONE]',
    regex: /(?:\+?\d{1,3}[\s\-.]?)?\(?\d{2,4}\)?[\s\-.]?\d{3,4}[\s\-.]?\d{3,4}\b/g
  },
  {
    type: 'card', label: 'Credit Card', cssClass: 'card',
    icon: '💳', redacted: '[CREDIT_CARD]',
    regex: /\b(?:\d{4}[\s\-]?){3}\d{4}\b/g
  },
  {
    type: 'id', label: 'Aadhaar', cssClass: 'id',
    icon: '🆔', redacted: '[AADHAAR]',
    regex: /\b\d{4}[\s\-]\d{4}[\s\-]\d{4}\b/g
  },
  {
    type: 'id', label: 'SSN', cssClass: 'id',
    icon: '🆔', redacted: '[SSN]',
    regex: /\b\d{3}[\-]\d{2}[\-]\d{4}\b/g
  },
  {
    type: 'id', label: 'PAN Card', cssClass: 'id',
    icon: '🆔', redacted: '[PAN]',
    regex: /\b[A-Z]{5}\d{4}[A-Z]\b/g
  },
  {
    type: 'ip', label: 'IP Address', cssClass: 'ip',
    icon: '🌐', redacted: '[IP_ADDRESS]',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g
  },
  {
    type: 'date', label: 'Date of Birth', cssClass: 'date',
    icon: '📅', redacted: '[DOB]',
    regex: /\b(?:DOB|Date of Birth|Born|Birthday)[:\s]*\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b/gi
  },
  {
    type: 'address', label: 'PIN Code', cssClass: 'address',
    icon: '📍', redacted: '[PIN_CODE]',
    regex: /\b\d{6}\b(?=\s|,|\.|$)/g
  }
];

// Common Indian & Western first names for name detection
const COMMON_NAMES = new Set([
  'rahul','priya','amit','sunita','vikram','neha','raj','anjali','suresh','pooja',
  'arun','divya','sanjay','kavitha','mohan','deepa','ramesh','lakshmi','vijay','anu',
  'arjun','sneha','ravi','meera','kiran','anita','manoj','swati','ashok','rekha',
  'john','jane','james','mary','robert','patricia','michael','jennifer','david','sarah',
  'william','emma','richard','olivia','joseph','sophia','thomas','isabella','charles','mia',
  'daniel','charlotte','matthew','amelia','anthony','harper','mark','evelyn','donald','abigail',
  'steven','emily','paul','elizabeth','andrew','madison','joshua','ella','kenneth','grace',
  'kevin','chloe','brian','victoria','george','riley','edward','aria','ronald','lily',
  'timothy','hannah','jason','natalie','jeffrey','luna','ryan','savannah','jacob','leah',
  'gary','zoe','nicholas','stella','eric','hazel','stephen','ellie','jonathan','paisley',
  'larry','audrey','justin','skylar','scott','violet','brandon','claire','benjamin','bella',
  'samuel','aurora','raymond','lucy','gregory','anna','frank','samantha','alexander','caroline',
  'patrick','genesis','jack','aaliyah','dennis','kennedy','jerry','allison','tyler','maya',
  'aaron','sarah','jose','madelyn','adam','adeline','nathan','alexa','henry','ariana'
]);

const LAST_NAMES = new Set([
  'sharma','gupta','patel','singh','kumar','das','reddy','verma','jain','mishra',
  'mehta','shah','nair','rao','iyer','mukherjee','chatterjee','banerjee','desai','pillai',
  'smith','johnson','williams','brown','jones','garcia','miller','davis','rodriguez','martinez',
  'wilson','anderson','taylor','thomas','hernandez','moore','martin','jackson','thompson','white',
  'lopez','lee','gonzalez','harris','clark','lewis','robinson','walker','perez','hall',
  'young','allen','sanchez','wright','king','scott','green','baker','adams','nelson'
]);

function detectPII(text) {
  const findings = [];
  
  // Pattern-based detection
  for (const pattern of PII_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      // Avoid overlapping with already found matches
      const overlaps = findings.some(f => 
        (match.index >= f.start && match.index < f.end) ||
        (match.index + match[0].length > f.start && match.index + match[0].length <= f.end)
      );
      if (!overlaps) {
        findings.push({
          type: pattern.type,
          label: pattern.label,
          cssClass: pattern.cssClass,
          icon: pattern.icon,
          redacted: pattern.redacted,
          value: match[0],
          start: match.index,
          end: match.index + match[0].length
        });
      }
    }
  }

  // Name detection (word-pair approach)
  const words = text.split(/(\s+|[,;.!?])/);
  let pos = 0;
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    const cleanWord = word.replace(/[^a-zA-Z]/g, '').toLowerCase();
    
    if (COMMON_NAMES.has(cleanWord) && cleanWord.length > 2) {
      // Check if next non-space word is a last name
      let nextWord = '';
      let nextIdx = i + 1;
      while (nextIdx < words.length && words[nextIdx].trim() === '') nextIdx++;
      if (nextIdx < words.length) {
        nextWord = words[nextIdx].replace(/[^a-zA-Z]/g, '').toLowerCase();
      }

      // Check if original text has capitalization (to reduce false positives)
      const isCapitalized = word[0] === word[0].toUpperCase() && word[0] !== word[0].toLowerCase();

      if (isCapitalized && (LAST_NAMES.has(nextWord) || COMMON_NAMES.has(nextWord))) {
        const fullName = text.substring(pos, pos + word.length);
        // Find the full name span
        let nameEnd = pos + word.length;
        let tempPos = pos + word.length;
        for (let j = i + 1; j <= nextIdx && j < words.length; j++) {
          tempPos += words[j].length;
        }
        nameEnd = tempPos;
        const nameValue = text.substring(pos, nameEnd);
        
        const overlaps = findings.some(f =>
          (pos >= f.start && pos < f.end) || (nameEnd > f.start && nameEnd <= f.end)
        );
        if (!overlaps && nameValue.trim().length > 3) {
          findings.push({
            type: 'name', label: 'Person Name', cssClass: 'name',
            icon: '👤', redacted: '[NAME]',
            value: nameValue.trim(),
            start: pos,
            end: pos + nameValue.trimEnd().length
          });
        }
      }
    }
    pos += word.length;
  }

  // Sort by position
  findings.sort((a, b) => a.start - b.start);
  return findings;
}

function buildHighlightedOutput(text, findings, mode = 'highlight') {
  if (findings.length === 0) return escapeHtml(text);
  
  let result = '';
  let lastEnd = 0;

  for (const f of findings) {
    // Add text before this finding
    result += escapeHtml(text.substring(lastEnd, f.start));
    
    if (mode === 'highlight') {
      result += `<span class="pii-tag pii-tag--${f.cssClass}" title="${f.label}: ${escapeHtml(f.value)}">${escapeHtml(f.value)}</span>`;
    } else {
      result += `<span class="pii-tag pii-tag--${f.cssClass}" title="Redacted ${f.label}">${f.redacted}</span>`;
    }
    lastEnd = f.end;
  }
  
  result += escapeHtml(text.substring(lastEnd));
  return result;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function getEntitySummary(findings) {
  const summary = {};
  for (const f of findings) {
    const key = f.label;
    if (!summary[key]) {
      summary[key] = { count: 0, cssClass: f.cssClass, icon: f.icon, items: [] };
    }
    summary[key].count++;
    if (!summary[key].items.includes(f.value)) {
      summary[key].items.push(f.value);
    }
  }
  return summary;
}

// ===== UI Logic =====

const SAMPLE_TEXT = `Hi, I'm Rahul Sharma and I need help with my account.

My email is rahul.sharma@gmail.com and my phone number is +91 9876543210.
I live at 42 Mahatma Gandhi Road, Bangalore 560001.

My Aadhaar number is 1234-5678-9012 and PAN is ABCDE1234F.
Please refund to my credit card 4532-1234-5678-9012.

Also, my colleague Priya Gupta (priya.g@outlook.com, phone: 8765432109) 
reported the same issue from IP 192.168.1.42.

DOB: 15/08/1995

Thanks,
Rahul Sharma`;

let currentMode = 'highlight';
let currentFindings = [];
let usePresidioAPI = false; // Will be set to true if backend is reachable

// ---- Presidio API Integration ----
const API_BASE = window.location.origin + '/api/v1';

async function checkAPIAvailability() {
  try {
    var controller = new AbortController();
    var timer = setTimeout(function() { controller.abort(); }, 5000);
    var res = await fetch(window.location.origin + '/api/health', { method: 'GET', signal: controller.signal });
    clearTimeout(timer);
    if (res.ok) {
      var data = await res.json();
      usePresidioAPI = data.engine === 'presidio';
      console.log('🛡️ Presidio API connected — using NLP-powered detection');
      return true;
    }
  } catch(e) { /* API not available, use client-side */ }
  console.log('📦 Using client-side regex detection (API not available)');
  return false;
}

async function scanWithPresidio(text, mode = 'highlight') {
  try {
    const res = await fetch(API_BASE + '/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, mode, score_threshold: 0.35 })
    });
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    // Convert API response to our format
    return data.entities.map(e => ({
      type: e.type,
      label: e.label,
      cssClass: e.cssClass,
      icon: e.icon,
      redacted: `[${e.type}]`,
      value: e.text,
      start: e.start,
      end: e.end,
      score: e.score,
    }));
  } catch(e) {
    return null; // Fallback to client-side
  }
}

// ---- UI Logic ----
function init() {
  const inputEl = document.getElementById('pii-input');
  const outputEl = document.getElementById('pii-output');
  const entitiesEl = document.getElementById('entities-grid');
  const countEl = document.getElementById('entity-count');

  if (!inputEl) return; // Not on a page with the scanner

  inputEl.value = SAMPLE_TEXT;
  let debounceTimer = null;

  async function processText() {
    const text = inputEl.value;

    // Try API first, fallback to regex
    let findings;
    if (usePresidioAPI) {
      const apiFindings = await scanWithPresidio(text, currentMode);
      findings = apiFindings || detectPII(text);
    } else {
      findings = detectPII(text);
    }
    currentFindings = findings;

    outputEl.innerHTML = buildHighlightedOutput(text, currentFindings, currentMode);

    // Update entity chips
    const summary = getEntitySummary(currentFindings);
    countEl.textContent = currentFindings.length;

    if (currentFindings.length === 0) {
      entitiesEl.innerHTML = '<span style="color: var(--text-muted); font-size: 14px;">No PII detected. Paste some text with personal information.</span>';
      return;
    }

    entitiesEl.innerHTML = Object.entries(summary).map(([label, data]) => `
      <div class="entity-chip entity-chip--${data.cssClass}">
        <span class="entity-chip__count">${data.count}</span>
        <span>${data.icon} ${label}</span>
      </div>
    `).join('');
  }

  // Debounced input to avoid hammering API
  inputEl.addEventListener('input', () => {
    clearTimeout(debounceTimer);
    if (usePresidioAPI) {
      debounceTimer = setTimeout(processText, 300);
    } else {
      processText();
    }
  });
  processText();

  // Mode toggle
  document.querySelectorAll('.toggle-group__btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.toggle-group__btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentMode = btn.dataset.mode;
      processText();
    });
  });

  // Clear button
  document.getElementById('btn-clear')?.addEventListener('click', () => {
    inputEl.value = '';
    processText();
  });

  // Sample button
  document.getElementById('btn-sample')?.addEventListener('click', () => {
    inputEl.value = SAMPLE_TEXT;
    processText();
  });

  // Copy button
  document.getElementById('btn-copy')?.addEventListener('click', async () => {
    const text = inputEl.value;
    let redactedText;
    if (usePresidioAPI) {
      try {
        const res = await fetch(API_BASE + '/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ text, mode: 'redact' })
        });
        const data = await res.json();
        redactedText = data.redacted;
      } catch(e) {
        // Fallback
        const findings = detectPII(text);
        redactedText = text;
        for (let i = findings.length - 1; i >= 0; i--) {
          redactedText = redactedText.substring(0, findings[i].start) + findings[i].redacted + redactedText.substring(findings[i].end);
        }
      }
    } else {
      const findings = detectPII(text);
      redactedText = text;
      for (let i = findings.length - 1; i >= 0; i--) {
        redactedText = redactedText.substring(0, findings[i].start) + findings[i].redacted + redactedText.substring(findings[i].end);
      }
    }
    navigator.clipboard.writeText(redactedText).then(() => {
      const btn = document.getElementById('btn-copy');
      const orig = btn.innerHTML;
      btn.innerHTML = '✓ Copied!';
      
      // Fun Confetti Popper Effect
      if (typeof confetti === 'function') {
        const rect = btn.getBoundingClientRect();
        const x = (rect.left + rect.width / 2) / window.innerWidth;
        const y = (rect.top + rect.height / 2) / window.innerHeight;
        confetti({
          particleCount: 60,
          spread: 70,
          origin: { x, y },
          colors: ['#0ea5e9', '#8b5cf6', '#f43f5e']
        });
      }

      setTimeout(() => btn.innerHTML = orig, 2000);
    });
  });

  // Scroll animations
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('animate-in');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('.feature-card, .pricing-card, .step-card, .usecase-card, .testimonial-card').forEach(el => observer.observe(el));
}

document.addEventListener('DOMContentLoaded', async () => {
  await checkAPIAvailability();
  init();
});
