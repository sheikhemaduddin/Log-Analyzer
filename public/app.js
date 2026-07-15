const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

const HISTORY_KEY = 'qa-signal-history-v1';
const SHARE_KEY = 'qa-signal-shares-v1';
const MAX_HISTORY = 25;
const MAX_LOG_STORE = 180000;

let lastBugReportText = '';
let lastAnalysis = null;
let lastLogText = '';
let lastShareId = null;
let logEditMode = true;
let searchMatchLines = [];
let searchMatchIndex = -1;
let jumpClearTimer = null;

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('qa-signal-theme', theme);
  const btn = $('#theme-toggle');
  const isDark = theme === 'dark';
  btn.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  btn.title = isDark ? 'Switch to light mode' : 'Switch to dark mode';
}

$('#theme-toggle').addEventListener('click', () => {
  const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  applyTheme(next);
});

applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');

// --- Tabs ---
let digestLoaded = false;
document.querySelectorAll('.tab').forEach((t) => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    $(`#tab-${t.dataset.tab}`).classList.add('active');
    if (t.dataset.tab === 'digest' && !digestLoaded) loadDigest();
    if (t.dataset.tab === 'history') renderHistory();
  });
});

async function loadStatus() {
  try {
    const res = await fetch('/api/health');
    const h = await res.json();
    $('#st-runtime').textContent = h.runtime;
    $('#st-runtime').classList.add('ok');
  } catch {
    $('#st-runtime').textContent = 'offline';
  }
}

loadStatus();

function setWorkspaceExpanded(expanded) {
  $('#workspace-panes').classList.toggle('is-expanded', expanded);
}

function uid() {
  return `qa_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
}

function readJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function writeJson(key, value) {
  localStorage.setItem(key, JSON.stringify(value));
}

function rootCauseFromAnalysis(a) {
  const fd = a.failureDetail || {};
  const details = fd.details || [];
  const actual = details.find((d) => /actual[_\s-]?error|error$/i.test(d.label))?.value
    || details.find((d) => d.label === 'Error')?.value
    || details.find((d) => d.label === 'Primary signal')?.value
    || fd.headline
    || a.verdictReason
    || a.firstError?.text
    || 'No root cause extracted';
  return String(actual).trim();
}

function suggestedFixes(a) {
  if (a.failureDetail?.resolution?.length) return a.failureDetail.resolution;
  if (a.issues?.[0]?.investigation?.length) return a.issues[0].investigation;
  return [];
}

function buildSharePayload(a, log) {
  return {
    v: 1,
    id: uid(),
    at: new Date().toISOString(),
    log: String(log || '').slice(0, MAX_LOG_STORE),
    analysis: {
      verdict: a.verdict,
      verdictReason: a.verdictReason,
      summary: a.summary,
      failureDetail: a.failureDetail,
      bugReport: a.bugReport,
      firstError: a.firstError,
      failedPhase: a.failedPhase,
      errorCategories: a.errorCategories,
      insights: a.insights,
      issues: (a.issues || []).slice(0, 5),
    },
  };
}

function saveHistoryEntry(a, log) {
  const entry = {
    id: uid(),
    at: new Date().toISOString(),
    verdict: a.verdict,
    headline: rootCauseFromAnalysis(a).slice(0, 180),
    source: a.summary?.logSource || 'generic',
    framework: a.summary?.framework || 'unknown',
    log: String(log || '').slice(0, MAX_LOG_STORE),
    analysis: a,
  };
  const list = readJson(HISTORY_KEY, []);
  list.unshift(entry);
  writeJson(HISTORY_KEY, list.slice(0, MAX_HISTORY));
  return entry;
}

function saveShare(payload) {
  const map = readJson(SHARE_KEY, {});
  map[payload.id] = payload;
  const ids = Object.keys(map);
  if (ids.length > 40) {
    ids.sort((x, y) => (map[x].at < map[y].at ? -1 : 1));
    ids.slice(0, ids.length - 40).forEach((id) => delete map[id]);
  }
  writeJson(SHARE_KEY, map);
  return payload.id;
}

function shareUrlFor(id) {
  const url = new URL(window.location.href);
  url.hash = `share=${id}`;
  return url.toString();
}

async function copyText(text) {
  await navigator.clipboard.writeText(text);
}

function flashBtn(btn, label = 'Done!') {
  const prev = btn.textContent;
  btn.textContent = label;
  setTimeout(() => { btn.textContent = prev; }, 1600);
}

function getLogText() {
  return $('#log-input')?.value || lastLogText || '';
}

function setLogEditMode(editing) {
  logEditMode = editing;
  const ta = $('#log-input');
  const lines = $('#log-lines');
  const btn = $('#log-edit-toggle');
  if (!ta || !lines) return;
  if (editing) {
    ta.classList.remove('is-hidden');
    lines.hidden = true;
    if (btn) btn.textContent = 'View lines';
  } else {
    ta.classList.add('is-hidden');
    lines.hidden = false;
    if (btn) btn.textContent = 'Edit';
    renderLogLines();
  }
}

function markedLineSet(a) {
  const errors = new Set();
  const warns = new Set();
  const vulns = new Set();
  const deps = new Set();
  const text = getLogText();
  const rows = text.split(/\n/);
  rows.forEach((line, idx) => {
    const n = idx + 1;
    if (/vulnerabilit/i.test(line) || /\b(low|moderate|high|critical)\b.*\b\d+\b/i.test(line) && /vuln|severity/i.test(line)) {
      vulns.add(n);
      warns.add(n);
    }
    if (/deprecat/i.test(line)) {
      deps.add(n);
      warns.add(n);
    }
  });
  (a?.errors || []).forEach((e) => { if (e.line) errors.add(Number(e.line)); });
  (a?.issues || []).forEach((i) => { if (i.line) errors.add(Number(i.line)); });
  if (a?.firstError?.line) errors.add(Number(a.firstError.line));
  (a?.warnings || []).forEach((w) => { if (w.line) warns.add(Number(w.line)); });
  return { errors, warns, vulns, deps };
}

function findLinesByRegex(re) {
  const rows = getLogText().split(/\n/);
  const hits = [];
  rows.forEach((line, idx) => {
    if (re.test(line)) hits.push(idx + 1);
  });
  return hits;
}

function resolveInsightNavigation(text) {
  const t = String(text || '');
  const lineMatch = t.match(/\bline\s+(\d+)\b/i);
  if (lineMatch) return { line: Number(lineMatch[1]), query: null, kind: 'jump' };

  if (/vulnerabilit/i.test(t) || /npm audit/i.test(t)) {
    return { line: null, query: 'vulnerabilit', kind: 'warn', patterns: [/vulnerabilit/i, /\b(critical|high|moderate|low)\s+vulnerabilit/i] };
  }
  if (/deprecat/i.test(t)) {
    return { line: null, query: 'deprecated', kind: 'warn', patterns: [/deprecat/i] };
  }
  if (/peer dependency|ERESOLVE|legacy-peer-deps/i.test(t)) {
    return { line: null, query: 'ERESOLVE', kind: 'jump', patterns: [/ERESOLVE|Conflicting peer|peerOptional|peer dependency/i] };
  }
  if (/out-of-memory|heap|OOM/i.test(t)) {
    return { line: null, query: 'out of memory', kind: 'jump', patterns: [/out of memory|heap out of memory|ENOMEM|JavaScript heap/i] };
  }
  if (/port already|EADDRINUSE/i.test(t)) {
    return { line: null, query: 'EADDRINUSE', kind: 'jump', patterns: [/EADDRINUSE|address already in use|port.*in use/i] };
  }
  if (/missing module|cannot find module/i.test(t)) {
    return { line: null, query: 'Cannot find module', kind: 'jump', patterns: [/Cannot find module|ERR_MODULE_NOT_FOUND|Module not found/i] };
  }
  if (/network\/connection|ECONNREFUSED|ENOTFOUND|cURL/i.test(t)) {
    return { line: null, query: 'connect', kind: 'jump', patterns: [/ECONNREFUSED|ENOTFOUND|ETIMEDOUT|cURL error|Failed to connect|Could not connect/i] };
  }
  if (/database/i.test(t)) {
    return { line: null, query: 'database', kind: 'jump', patterns: [/postgres|mysql|mongodb|sequelize|SQLSTATE|MongoNetwork|authentication failed/i] };
  }
  if (/HTTP\s+\d{3}/i.test(t)) {
    const codes = t.match(/HTTP\s+([\d,\s]+)/i)?.[1];
    const first = codes?.match(/\d{3}/)?.[0];
    return { line: null, query: first || 'HTTP', kind: 'warn', patterns: [/\b(4\d{2}|5\d{2})\b/] };
  }
  if (/Failed during/i.test(t)) {
    const cmd = t.match(/Failed during `([^`]+)`/i)?.[1];
    if (cmd) return { line: null, query: cmd, kind: 'jump', patterns: [new RegExp(cmd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')] };
  }
  if (/Installed .+ requires|peer requirement/i.test(t)) {
    return { line: null, query: 'Found:', kind: 'jump', patterns: [/Found:|While resolving:|Conflicting peer|Could not resolve dependency/i] };
  }

  // Fallback: use distinctive words from the insight as a log search
  const keywords = t
    .replace(/[^\w\s./:@-]+/g, ' ')
    .split(/\s+/)
    .filter((w) => w.length > 4)
    .slice(0, 3);
  if (keywords.length) {
    return { line: null, query: keywords[0], kind: 'jump', patterns: keywords.map((k) => new RegExp(k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')) };
  }
  return null;
}

function goToLogMatches(nav, { announce = true } = {}) {
  if (!nav) return false;
  setLogEditMode(false);

  if (nav.line) {
    if ($('#log-search')) $('#log-search').value = '';
    renderLogLines();
    goToLogLine(nav.line, { kind: nav.kind || 'jump' });
    return true;
  }

  let hits = [];
  if (nav.patterns?.length) {
    const seen = new Set();
    nav.patterns.forEach((re) => {
      findLinesByRegex(re).forEach((n) => {
        if (!seen.has(n)) {
          seen.add(n);
          hits.push(n);
        }
      });
    });
  }

  const q = nav.query || '';
  if ($('#log-search')) $('#log-search').value = q;
  renderLogLines();

  // Prefer regex-derived hits; fall back to current search matches
  if (hits.length) {
    searchMatchLines = hits;
    searchMatchIndex = 0;
    // ensure tags are visible for those lines
    hits.forEach((n) => {
      const el = document.getElementById(`log-src-${n}`);
      if (el) {
        el.classList.add('is-search-hit');
        if (nav.kind === 'warn') el.classList.add('is-warn');
        else el.classList.add('is-error');
      }
    });
    activateSearchMatch(0, true);
    if (announce && $('#log-search-meta')) {
      $('#log-search-meta').textContent = `1/${hits.length}`;
    }
    return true;
  }

  runLogSearch(true);
  return searchMatchLines.length > 0;
}

function renderLogLines() {
  const container = $('#log-lines');
  const text = getLogText();
  if (!container) return;
  if (!text.trim()) {
    container.innerHTML = '<div class="placeholder" style="padding:1rem">Paste or drop a log to browse lines.</div>';
    return;
  }
  const { errors, warns, vulns, deps } = markedLineSet(lastAnalysis);
  const q = ($('#log-search')?.value || '').trim();
  const qLower = q.toLowerCase();
  const rows = text.split(/\n/);
  searchMatchLines = [];

  container.innerHTML = rows.map((line, idx) => {
    const n = idx + 1;
    let cls = 'log-src-line';
    if (errors.has(n)) cls += ' is-error';
    else if (vulns.has(n)) cls += ' is-warn is-vuln';
    else if (deps.has(n)) cls += ' is-warn is-dep';
    else if (warns.has(n)) cls += ' is-warn';
    let body = esc(line || ' ');
    if (q && line.toLowerCase().includes(qLower)) {
      searchMatchLines.push(n);
      cls += ' is-search-hit';
      const re = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
      body = esc(line).replace(re, (m) => `<mark>${m}</mark>`);
    }
    return `<div class="${cls}" data-line="${n}" id="log-src-${n}"><span class="src-ln">${n}</span><span class="src-tx">${body || ' '}</span></div>`;
  }).join('');

  updateSearchMeta();
  if (searchMatchIndex >= 0 && searchMatchLines[searchMatchIndex]) {
    activateSearchMatch(searchMatchIndex, false);
  }
}

function updateSearchMeta() {
  const meta = $('#log-search-meta');
  if (!meta) return;
  const q = ($('#log-search')?.value || '').trim();
  if (!q) {
    meta.textContent = '—';
    return;
  }
  if (!searchMatchLines.length) {
    meta.textContent = '0 matches';
    return;
  }
  meta.textContent = `${searchMatchIndex + 1}/${searchMatchLines.length}`;
}

function activateSearchMatch(index, scroll = true) {
  document.querySelectorAll('.log-src-line.is-search-active').forEach((el) => el.classList.remove('is-search-active'));
  if (!searchMatchLines.length) {
    searchMatchIndex = -1;
    updateSearchMeta();
    return;
  }
  searchMatchIndex = ((index % searchMatchLines.length) + searchMatchLines.length) % searchMatchLines.length;
  const line = searchMatchLines[searchMatchIndex];
  const el = document.getElementById(`log-src-${line}`);
  if (el) {
    el.classList.add('is-search-active');
    if (scroll) el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }
  updateSearchMeta();
}

function goToLogLine(lineNum, { kind = 'jump' } = {}) {
  const n = Number(lineNum);
  if (!n || n < 1) return;
  setLogEditMode(false);
  renderLogLines();
  const el = document.getElementById(`log-src-${n}`);
  if (!el) return;
  document.querySelectorAll('.log-src-line.is-jump-active').forEach((x) => x.classList.remove('is-jump-active'));
  el.classList.add('is-jump-active');
  if (kind === 'warn') el.classList.add('is-warn');
  el.scrollIntoView({ block: 'center', behavior: 'smooth' });
  clearTimeout(jumpClearTimer);
  jumpClearTimer = setTimeout(() => el.classList.remove('is-jump-active'), 2200);
}

function wireGotoClicks(root) {
  root.querySelectorAll('[data-goto-line]').forEach((el) => {
    el.classList.add('goto-log-line');
    el.title = `Go to line ${el.getAttribute('data-goto-line')}`;
    el.addEventListener('click', () => {
      goToLogLine(el.getAttribute('data-goto-line'), {
        kind: el.getAttribute('data-goto-kind') || 'jump',
      });
    });
  });

  root.querySelectorAll('[data-goto-nav]').forEach((el) => {
    el.classList.add('goto-log-line');
    if (!el.title) el.title = 'Click to highlight matching log lines (use ↑/↓ for next match)';
    el.addEventListener('click', () => {
      try {
        const nav = JSON.parse(decodeURIComponent(el.getAttribute('data-goto-nav')));
        if (nav.patternSources?.length) {
          nav.patterns = nav.patternSources.map((src) => new RegExp(src, 'i'));
        }
        const ok = goToLogMatches(nav);
        if (!ok && el.getAttribute('data-goto-line')) {
          goToLogLine(el.getAttribute('data-goto-line'), {
            kind: el.getAttribute('data-goto-kind') || 'jump',
          });
        }
      } catch {
        /* ignore bad nav payload */
      }
    });
  });
}

function navAttr(nav) {
  if (!nav) return '';
  const payload = {
    line: nav.line || null,
    query: nav.query || null,
    kind: nav.kind || 'jump',
    patternSources: (nav.patterns || []).map((re) => re.source),
  };
  return ` data-goto-nav="${encodeURIComponent(JSON.stringify(payload))}"`;
}

function runLogSearch(resetIndex = true) {
  if (logEditMode) setLogEditMode(false);
  else renderLogLines();
  if (resetIndex) searchMatchIndex = searchMatchLines.length ? 0 : -1;
  if (searchMatchLines.length) activateSearchMatch(searchMatchIndex);
  else updateSearchMeta();
}

async function runAnalysis(log, { skipHistory = false } = {}) {
  if (!String(log || '').trim()) return;
  lastLogText = String(log);
  if ($('#log-input')) $('#log-input').value = log;
  setWorkspaceExpanded(false);
  $('#analyze-out').innerHTML = '<div class="placeholder"><span class="spinner"></span> Analyzing…</div>';
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ log }),
    });
    const a = await res.json();
    if (a.error) throw new Error(a.error);
    lastAnalysis = a;
    if (!skipHistory) saveHistoryEntry(a, log);
    const sharePayload = buildSharePayload(a, log);
    lastShareId = saveShare(sharePayload);
    renderAnalysis(a);
    setWorkspaceExpanded(true);
    setLogEditMode(false);
    renderHistory();
  } catch (e) {
    $('#analyze-out').innerHTML = `<div class="verdict failed">Error: ${esc(e.message)}</div>`;
    setWorkspaceExpanded(true);
  }
}

$('#analyze-btn').addEventListener('click', () => runAnalysis($('#log-input').value));

$('#analyze-clear').addEventListener('click', () => {
  $('#log-input').value = '';
  lastAnalysis = null;
  lastLogText = '';
  lastShareId = null;
  searchMatchLines = [];
  searchMatchIndex = -1;
  if ($('#log-search')) $('#log-search').value = '';
  setWorkspaceExpanded(false);
  setLogEditMode(true);
  $('#analyze-out').innerHTML = '<div class="placeholder">Analysis will appear here.</div>';
  renderLogLines();
  updateSearchMeta();
});

$('#log-edit-toggle')?.addEventListener('click', () => {
  setLogEditMode(!logEditMode);
});

$('#log-search')?.addEventListener('input', () => runLogSearch(true));
$('#log-search')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    e.preventDefault();
    if (e.shiftKey) activateSearchMatch(searchMatchIndex - 1);
    else activateSearchMatch(searchMatchIndex + 1);
  }
});
$('#log-search-prev')?.addEventListener('click', () => {
  if (logEditMode) runLogSearch(false);
  activateSearchMatch(searchMatchIndex <= 0 ? searchMatchLines.length - 1 : searchMatchIndex - 1);
});
$('#log-search-next')?.addEventListener('click', () => {
  if (logEditMode) runLogSearch(false);
  activateSearchMatch(searchMatchIndex + 1);
});

$('#log-input')?.addEventListener('input', () => {
  lastLogText = $('#log-input').value;
});

// --- File choose + drag/drop ---
async function loadLogFile(file) {
  if (!file) return;
  const text = await file.text();
  $('#log-input').value = text;
  lastLogText = text;
  await runAnalysis(text);
}

$('#log-file')?.addEventListener('change', (e) => {
  const file = e.target.files?.[0];
  loadLogFile(file);
  e.target.value = '';
});

const dropZone = $('#drop-zone');
let dragDepth = 0;

function setDropActive(on) {
  dropZone?.classList.toggle('is-dragover', on);
  const overlay = $('#drop-overlay');
  if (overlay) overlay.setAttribute('aria-hidden', on ? 'false' : 'true');
}

function isFileDrag(e) {
  return Array.from(e.dataTransfer?.types || []).includes('Files');
}

dropZone?.addEventListener('dragenter', (e) => {
  if (!isFileDrag(e)) return;
  e.preventDefault();
  e.stopPropagation();
  dragDepth += 1;
  setDropActive(true);
});
dropZone?.addEventListener('dragover', (e) => {
  if (!isFileDrag(e)) return;
  e.preventDefault();
  e.stopPropagation();
  setDropActive(true);
});
dropZone?.addEventListener('dragleave', (e) => {
  if (!isFileDrag(e)) return;
  e.preventDefault();
  e.stopPropagation();
  dragDepth = Math.max(0, dragDepth - 1);
  if (dragDepth === 0) setDropActive(false);
});
dropZone?.addEventListener('drop', (e) => {
  e.preventDefault();
  e.stopPropagation();
  dragDepth = 0;
  setDropActive(false);
  const file = e.dataTransfer?.files?.[0];
  if (file) loadLogFile(file);
});
// Clear stuck overlay if the drag ends outside the pane
window.addEventListener('dragend', () => {
  dragDepth = 0;
  setDropActive(false);
});
document.addEventListener('paste', () => {
  dragDepth = 0;
  setDropActive(false);
});

function buildAssessmentMarkdown(a, log) {
  const s = a.summary || {};
  const fd = a.failureDetail || {};
  const details = (fd.details || []).map((d) => `- **${d.label}:** ${d.value}`).join('\n');
  const fixes = suggestedFixes(a).map((step, i) => `${i + 1}. ${step}`).join('\n');
  const insights = (a.insights || []).map((i) => `- (${i.level}) ${i.text}`).join('\n');
  return [
    '# QA Signal Assessment',
    '',
    `- **Generated:** ${new Date().toISOString()}`,
    `- **Verdict:** ${a.verdict}`,
    `- **Reason:** ${a.verdictReason || '—'}`,
    '',
    '## Root cause',
    '',
    rootCauseFromAnalysis(a),
    '',
    '## Suggested fixes',
    '',
    fixes || '_None_',
    '',
    '## Failure details',
    '',
    fd.headline ? `**${fd.headline}**` : '_No structured failure detail_',
    fd.description || '',
    details || '',
    '',
    '## Environment',
    '',
    `- Source: ${s.logSource || '—'}`,
    `- Environment: ${s.environment || '—'}`,
    `- Framework: ${s.framework || '—'}`,
    `- Package manager: ${s.packageManager || '—'}`,
    s.nodeVersion ? `- Node: ${s.nodeVersion}` : null,
    s.exitCode != null ? `- Exit code: ${s.exitCode}` : null,
    s.totalLines != null ? `- Log lines: ${s.totalLines}` : null,
    '',
    '## Insights',
    '',
    insights || '_None_',
    '',
    a.bugReport?.copyText ? '## Bug report\n' : null,
    a.bugReport?.copyText || null,
    '',
    '## Original log (excerpt)',
    '',
    '```',
    String(log || '').slice(0, 12000),
    String(log || '').length > 12000 ? '\n…(truncated)…' : '',
    '```',
    '',
    '_Generated by QA Signal — share this file with teammates._',
  ].filter((line) => line !== null).join('\n');
}

function buildAssessmentJson(a, log) {
  return {
    tool: 'QA Signal',
    version: 1,
    generatedAt: new Date().toISOString(),
    verdict: a.verdict,
    verdictReason: a.verdictReason,
    rootCause: rootCauseFromAnalysis(a),
    suggestedFixes: suggestedFixes(a),
    summary: a.summary,
    failureDetail: a.failureDetail,
    insights: a.insights,
    bugReport: a.bugReport,
    firstError: a.firstError,
    failedPhase: a.failedPhase,
    errorCategories: a.errorCategories,
    issues: (a.issues || []).slice(0, 10),
    logExcerpt: String(log || '').slice(0, 50000),
  };
}

function downloadTextFile(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadAssessment(a) {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const base = `qa-signal-assessment-${stamp}`;
  downloadTextFile(`${base}.md`, buildAssessmentMarkdown(a, lastLogText), 'text/markdown;charset=utf-8');
  downloadTextFile(`${base}.json`, JSON.stringify(buildAssessmentJson(a, lastLogText), null, 2), 'application/json;charset=utf-8');
}

async function shareAnalysis(a) {
  if (!lastShareId) {
    lastShareId = saveShare(buildSharePayload(a, lastLogText));
  }
  // Share links are local-only: payload lives in this browser's localStorage, not on the server.
  const url = shareUrlFor(lastShareId);
  const summary = [
    `QA Signal: ${verdictLabel(a.verdict)}`,
    rootCauseFromAnalysis(a),
    '',
    `Open on this same browser/device:`,
    url,
    '',
    `(History and share data stay in your browser — not sent to other users or machines.)`,
  ].join('\n');

  if (navigator.share) {
    try {
      await navigator.share({ title: 'QA Signal analysis', text: summary, url });
      return;
    } catch { /* fall through to copy */ }
  }
  await copyText(url);
}

function restoreFromHistory(entry) {
  document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
  document.querySelectorAll('.panel').forEach((x) => x.classList.remove('active'));
  $('.tab[data-tab="analyzer"]')?.classList.add('active');
  $('#tab-analyzer')?.classList.add('active');
  $('#log-input').value = entry.log || '';
  lastLogText = entry.log || '';
  lastAnalysis = entry.analysis;
  const sharePayload = buildSharePayload(entry.analysis, entry.log);
  lastShareId = saveShare(sharePayload);
  renderAnalysis(entry.analysis);
  setWorkspaceExpanded(true);
  setLogEditMode(false);
}

function renderHistory() {
  const list = readJson(HISTORY_KEY, []);
  const out = $('#history-out');
  if (!out) return;
  if (!list.length) {
    out.innerHTML = '<div class="placeholder">No analyses yet — run Analyze to start building history.</div>';
    return;
  }
  out.innerHTML = list.map((item) => `
    <button type="button" class="history-card" data-id="${esc(item.id)}">
      <div class="history-card-top">
        <span class="history-verdict verdict-chip ${esc(item.verdict)}">${esc(verdictLabel(item.verdict))}</span>
        <span class="history-time">${esc(new Date(item.at).toLocaleString())}</span>
      </div>
      <div class="history-headline">${esc(item.headline)}</div>
      <div class="history-meta">
        <span class="tag">${esc(item.source)}</span>
        <span class="tag">${esc(item.framework)}</span>
      </div>
    </button>
  `).join('');
  out.querySelectorAll('.history-card').forEach((card) => {
    card.addEventListener('click', () => {
      const entry = list.find((x) => x.id === card.dataset.id);
      if (entry) restoreFromHistory(entry);
    });
  });
}

$('#history-clear')?.addEventListener('click', () => {
  if (!confirm('Clear all saved analysis history on this browser?')) return;
  writeJson(HISTORY_KEY, []);
  renderHistory();
});

function detailRowsFor(fd) {
  if (fd.details?.length) return fd.details;
  return [
    fd.conflict?.installed && { label: 'Installed', value: `${fd.conflict.installed}${fd.conflict.installedFrom ? ` (${fd.conflict.installedFrom})` : ''}` },
    fd.conflict?.requiredBy && { label: 'Required by', value: `${fd.conflict.requiredBy}${fd.conflict.requiredRange ? ` needs ${fd.conflict.requiredRange}` : ''}` },
    fd.conflict?.wouldInstall && { label: 'Would install', value: fd.conflict.wouldInstall },
    fd.failedPhase && { label: 'Failed phase', value: fd.failedPhase },
    fd.failedCommand && { label: 'Command', value: fd.failedCommand },
  ].filter(Boolean);
}

function renderAnalysis(a) {
  const s = a.summary;
  const isSuccess = a.verdict === 'success';
  const rootCause = rootCauseFromAnalysis(a);
  const fixes = suggestedFixes(a);
  const stat = (n, l, cls = '') => `<div class="stat"><span class="stat-n ${cls}">${n}</span><span class="stat-l">${l}</span></div>`;
  const vb = s.vulnerabilityBreakdown;

  let html = `
    <div class="report-actions">
      <button type="button" class="btn-secondary btn-sm download-assessment-btn">Download assessment</button>
      <button type="button" class="btn-ghost btn-sm share-btn">Copy local link</button>
      ${!isSuccess && a.bugReport?.hasIssue ? '<button type="button" class="btn-ghost btn-sm copy-bug-btn">Copy report</button>' : ''}
    </div>
    <div class="verdict ${a.verdict}">
      <span>${verdictLabel(a.verdict)}</span>
      <span class="verdict-reason">${esc(a.verdictReason)}</span>
    </div>`;

  // Insights always first (success + failure) — each insight is clickable
  html += `<div class="insights-box">`;
  html += `<div class="block-h">Insights <span class="hint-inline">click any insight to jump in the log</span></div>`;
  if (a.insights?.length) {
    html += a.insights.map((ins) => {
      const nav = resolveInsightNavigation(ins.text);
      const attrs = navAttr(nav);
      const clickable = nav ? ' goto-log-line' : '';
      return `<div class="insight insight-${esc(ins.level)}${clickable}"${attrs}>${esc(ins.text)}</div>`;
    }).join('');
  } else {
    html += `<div class="insight insight-info">${isSuccess ? 'No additional insights — run looks clean.' : 'No structured insights for this log.'}</div>`;
  }
  html += `</div>`;

  if (!isSuccess) {
    const rootLine = a.firstError?.line || a.issues?.[0]?.line || '';
    html += `
      <div class="root-cause-box${rootLine ? ' goto-log-line' : ''}" ${rootLine ? `data-goto-line="${rootLine}"` : ''}>
        <div class="block-h">Root cause${rootLine ? ` · click to go to L${rootLine}` : ''}</div>
        <div class="root-cause-text">${esc(rootCause)}</div>
      </div>`;
  }

  if (!isSuccess && fixes.length) {
    html += `<div class="fixes-box">`;
    html += `<div class="block-h">Suggested fixes</div>`;
    html += `<ol class="resolution-list">${fixes.map((step) => `<li>${esc(step)}</li>`).join('')}</ol>`;
    html += `</div>`;
  }

  if (!isSuccess && a.failureDetail) {
    const fd = a.failureDetail;
    html += `<div class="failure-detail-box">`;
    html += `<div class="block-h">What failed</div>`;
    html += `<div class="failure-headline">${esc(fd.headline)}</div>`;
    if (fd.description) html += `<p class="failure-desc">${esc(fd.description)}</p>`;
    const detailRows = detailRowsFor(fd);
    if (detailRows.length) {
      html += `<div class="failure-conflict">`;
      detailRows.forEach((row) => {
        const isError = /error|actual/i.test(row.label);
        html += `<div class="${isError ? 'detail-emphasis' : ''}"><span class="failure-label">${esc(row.label)}</span> ${esc(row.value)}</div>`;
      });
      html += `</div>`;
    }
    html += `</div>`;
  }

  if (!isSuccess && a.bugReport?.hasIssue) {
    html += `
      <div class="bug-report-box">
        <div class="bug-report-head">
          <span class="block-h" style="margin:0">Bug report</span>
          <button type="button" class="btn-ghost btn-sm copy-bug-btn">Copy</button>
        </div>
        <div class="bug-report-summary">${esc(a.bugReport.summary)}</div>
        <pre class="bug-report-body">${esc(a.bugReport.copyText)}</pre>
      </div>`;
  }

  if (!isSuccess && a.issues?.length && !a.failureDetail) {
    html += `<div class="block-h">Detected issues (${a.issues.length})</div>`;
    html += a.issues.slice(0, 5).map((issue) => `
      <div class="issue-card${issue.line ? ' goto-log-line' : ''}" ${issue.line ? `data-goto-line="${issue.line}"` : ''}>
        <div class="issue-title">${esc(issue.title)}</div>
        ${issue.line ? `<div class="issue-meta">Line ${issue.line} · ${esc(issue.category)} · click to jump</div>` : ''}
        <div class="issue-msg">${esc(issue.exactMessage)}</div>
      </div>`).join('');
  } else if (!isSuccess && a.issues?.length && a.failureDetail) {
    if (a.issues[0]?.line) {
      html += `<div class="block-h">Jump to signal</div>`;
      html += `<div class="log-line err goto-log-line" data-goto-line="${a.issues[0].line}"><span class="ln">L${a.issues[0].line}</span><span class="tx">${esc(a.issues[0].exactMessage || a.issues[0].title)} · click to jump</span></div>`;
    }
    if (a.issues[0]?.investigation?.length) {
      html += `<div class="block-h">Investigation steps</div>`;
      html += `<ol class="resolution-list">${a.issues[0].investigation.map((step) => `<li>${esc(step)}</li>`).join('')}</ol>`;
    }
  }

  const firstErrLine = a.firstError?.line || a.errors?.[0]?.line || a.issues?.[0]?.line || '';
  const firstWarnLine = a.warnings?.[0]?.line || '';
  const vulnNav = (s.vulnerabilities != null && s.vulnerabilities > 0)
    ? resolveInsightNavigation('npm vulnerability')
    : null;
  const depNav = (s.deprecations > 0)
    ? resolveInsightNavigation('deprecated packages')
    : null;
  const errStat = firstErrLine
    ? `<div class="stat goto-log-line" data-goto-line="${firstErrLine}" data-goto-kind="jump" title="Jump to first error"><span class="stat-n ${s.errors ? 'err' : 'ok'}">${s.errors}</span><span class="stat-l">Errors</span></div>`
    : stat(s.errors, 'Errors', s.errors ? 'err' : 'ok');
  const warnStat = firstWarnLine
    ? `<div class="stat goto-log-line" data-goto-line="${firstWarnLine}" data-goto-kind="warn" title="Jump to first warning"><span class="stat-n ${s.warnings ? 'warn' : ''}">${s.warnings}</span><span class="stat-l">Warnings</span></div>`
    : stat(s.warnings, 'Warnings', s.warnings ? 'warn' : '');
  const depStat = depNav
    ? `<div class="stat goto-log-line"${navAttr(depNav)} title="Highlight deprecation lines"><span class="stat-n">${s.deprecations}</span><span class="stat-l">Deprecated</span></div>`
    : stat(s.deprecations, 'Deprecated');
  const vulnStat = vulnNav
    ? `<div class="stat goto-log-line"${navAttr(vulnNav)} title="Highlight vulnerability lines"><span class="stat-n ${vb?.high || vb?.critical ? 'warn' : ''}">${s.vulnerabilities === null ? '—' : s.vulnerabilities}</span><span class="stat-l">Vulns</span></div>`
    : stat(s.vulnerabilities === null ? '—' : s.vulnerabilities, 'Vulns', vb?.high || vb?.critical ? 'warn' : '');

  html += `
    <div class="stats">
      ${errStat}
      ${warnStat}
      ${depStat}
      ${stat(s.exitCode === null ? '—' : s.exitCode, 'Exit code', s.exitCode === 0 ? 'ok' : (s.exitCode ? 'err' : ''))}
      ${vulnStat}
      ${stat(s.durationSec === null ? '—' : s.durationSec + 's', 'Duration')}
      ${stat(s.commandsRun || 0, 'Commands')}
      ${stat(s.stackTraceLines || 0, 'Stack lines', s.stackTraceLines ? 'warn' : '')}
    </div>
    <div class="tag-list">
      <span class="tag">source: ${esc(s.logSource)}</span>
      <span class="tag">env: ${esc(s.environment)}</span>
      <span class="tag">pm: ${esc(s.packageManager)}</span>
      <span class="tag">framework: ${esc(s.framework)}</span>
      ${s.nodeVersion ? `<span class="tag">node ${esc(s.nodeVersion)}</span>` : ''}
      ${s.npmVersion ? `<span class="tag">npm ${esc(s.npmVersion)}</span>` : ''}
      ${s.portDetected ? `<span class="tag">port: ${s.portDetected}</span>` : ''}
      ${s.packagesAdded ? `<span class="tag">+${s.packagesAdded} packages</span>` : ''}
      ${s.httpErrors?.length ? `<span class="tag">HTTP ${s.httpErrors.join(', ')}</span>` : ''}
      ${s.hasOom ? `<span class="tag warn-tag">OOM</span>` : ''}
      <span class="tag">${s.totalLines} lines</span>
    </div>`;

  if (vb) {
    html += `<div class="block-h">${isSuccess ? 'npm audit advisories' : 'Vulnerability breakdown'}</div><div class="tag-list">`;
    if (vb.critical) html += `<span class="tag err-tag">${vb.critical} critical</span>`;
    if (vb.high) html += `<span class="tag warn-tag">${vb.high} high</span>`;
    if (vb.moderate) html += `<span class="tag">${vb.moderate} moderate</span>`;
    if (vb.low) html += `<span class="tag">${vb.low} low</span>`;
    html += `</div>`;
  }

  if (!isSuccess && a.errorCategories?.length) {
    html += `<div class="block-h">Error categories</div><div class="tag-list">${a.errorCategories.map((c) => `<span class="tag err-tag">${esc(c.label)} (${c.count})</span>`).join('')}</div>`;
  }

  if (!isSuccess && a.failedPhase) {
    html += `<div class="block-h">Likely failure point</div>`;
    html += `<div class="insight insight-error goto-log-line" data-goto-line="${a.failedPhase.line}">Phase "${esc(a.failedPhase.phase)}" near line ${a.failedPhase.line} · click to jump</div>`;
  }

  if (!isSuccess && a.firstError) {
    html += `<div class="block-h">First error (log signal)</div>`;
    html += `<div class="log-line err goto-log-line" data-goto-line="${a.firstError.line}"><span class="ln">L${a.firstError.line}</span><span class="tx">${esc(a.firstError.text)}</span></div>`;
    if (a.firstError.category) html += `<div class="tag-list"><span class="tag err-tag">${esc(a.firstError.category)}</span></div>`;
  }

  if (a.phases?.length) {
    html += `<div class="block-h">Build timeline</div><div class="timeline">`;
    html += a.phases.map((p) => `
      <div class="timeline-item goto-log-line" data-goto-line="${p.line}">
        <span class="timeline-phase">${esc(p.phase)}</span>
        <span class="timeline-meta">L${p.line}${p.durationSec != null ? ` · ${p.durationSec}s` : ''} · jump</span>
      </div>`).join('');
    html += `</div>`;
  }

  if (a.commands?.length) {
    html += `<div class="block-h">Commands run</div>`;
    html += a.commands.map((c) => `<div class="log-line goto-log-line" data-goto-line="${c.line}"><span class="ln">L${c.line}</span><span class="tx">${esc(c.command)}</span></div>`).join('');
  }

  if (a.errors?.length && a.verdict !== 'success') {
    html += `<div class="block-h">Errors (${a.errors.length}) — click to jump</div>`;
    html += a.errors.map((e) => `<div class="log-line err goto-log-line" data-goto-line="${e.line}"><span class="ln">L${e.line}</span><span class="tx">${esc(e.text)}${e.category ? `<span class="line-cat">${esc(e.category)}</span>` : ''}</span></div>`).join('');
  }
  if (a.deprecations?.length) {
    html += `<div class="block-h">Deprecated packages</div><div class="tag-list">${a.deprecations.map((d) => `<span class="tag">${esc(d)}</span>`).join('')}</div>`;
  }
  if (a.warnings?.length && a.verdict !== 'success') {
    html += `<div class="block-h">Warnings (${a.warnings.length}) — click to jump</div>`;
    html += a.warnings.slice(0, 15).map((w) => `<div class="log-line warn goto-log-line" data-goto-line="${w.line}" data-goto-kind="warn"><span class="ln">L${w.line}</span><span class="tx">${esc(w.text)}</span></div>`).join('');
  }

  lastBugReportText = (!isSuccess && a.bugReport?.hasIssue) ? a.bugReport.copyText : '';
  $('#analyze-out').innerHTML = html;

  $('#analyze-out').querySelectorAll('.copy-bug-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await copyText(lastBugReportText || rootCause);
        flashBtn(btn, 'Copied!');
      } catch {
        flashBtn(btn, 'Copy failed');
      }
    });
  });
  $('#analyze-out').querySelector('.download-assessment-btn')?.addEventListener('click', (e) => {
    try {
      downloadAssessment(a);
      flashBtn(e.currentTarget, 'Downloaded');
    } catch {
      flashBtn(e.currentTarget, 'Failed');
    }
  });
  $('#analyze-out').querySelector('.share-btn')?.addEventListener('click', async (e) => {
    try {
      await shareAnalysis(a);
      flashBtn(e.currentTarget, 'Link copied');
    } catch {
      flashBtn(e.currentTarget, 'Share failed');
    }
  });
  wireGotoClicks($('#analyze-out'));
}

function verdictLabel(v) {
  return { success: '✓ Success', failed: '✕ Failed', 'errors-found': '⚠ Errors found', inconclusive: '? Inconclusive' }[v] || v;
}

function restoreSharedAnalysis() {
  const m = window.location.hash.match(/share=([A-Za-z0-9_-]+)/);
  if (!m) return;
  const map = readJson(SHARE_KEY, {});
  const payload = map[m[1]];
  if (!payload?.analysis) return;
  lastShareId = payload.id;
  lastLogText = payload.log || '';
  lastAnalysis = payload.analysis;
  $('#log-input').value = payload.log || '';
  renderAnalysis(payload.analysis);
  setWorkspaceExpanded(true);
}

restoreSharedAnalysis();
renderHistory();

// --- QA Knowledge Hub ---
let lastDigestData = null;
let digestView = 'competitors';
let digestSearchQuery = '';
let digestCompanyFilter = 'all';

function formatDigestDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  } catch {
    return '';
  }
}

function digestItemHaystack(item) {
  return [item.title, item.excerpt, item.source, ...(item.qualityTags || [])].join(' ').toLowerCase();
}

function digestCompanyHaystack(company) {
  return [company.title, company.category, company.qualityFocus, company.description].join(' ').toLowerCase();
}

function filterDigestCompanies(companies) {
  const q = digestSearchQuery.trim().toLowerCase();
  let list = companies || [];

  if (digestCompanyFilter !== 'all') {
    list = list.filter((c) => c.id === digestCompanyFilter);
  }

  if (!q) return list;

  return list
    .map((company) => {
      const companyMatch = digestCompanyHaystack(company).includes(q);
      const items = (company.items || []).filter(
        (item) => companyMatch || digestItemHaystack(item).includes(q),
      );
      return { ...company, items };
    })
    .filter((company) => company.items.length > 0 || digestCompanyHaystack(company).includes(q));
}

function filterDigestItems(items) {
  const q = digestSearchQuery.trim().toLowerCase();
  if (!q) return items || [];
  return (items || []).filter((item) => digestItemHaystack(item).includes(q));
}

function renderDigestCard(item) {
  const tags = (item.qualityTags || []).map((t) => `<span class="digest-tag">${esc(t)}</span>`).join('');
  return `
    <a class="digest-card ${item.type === 'kb' ? 'digest-card-kb' : ''}" href="${esc(item.url)}" target="_blank" rel="noopener noreferrer">
      <span class="digest-card-source">${esc(item.source)}</span>
      <span class="digest-card-title">${esc(item.title)}</span>
      ${item.excerpt ? `<span class="digest-card-excerpt">${esc(item.excerpt)}</span>` : ''}
      ${tags ? `<span class="digest-card-tags">${tags}</span>` : ''}
      ${item.publishedAt ? `<span class="digest-card-date">${esc(formatDigestDate(item.publishedAt))}</span>` : ''}
    </a>`;
}

function renderCompetitorSection(section) {
  const companies = filterDigestCompanies(section.companies || []);
  const q = digestSearchQuery.trim();

  let html = `
    <div class="digest-section digest-section-group" data-digest-section="competitors">
      <div class="digest-section-head">
        <h3 class="digest-section-title">${esc(section.title)}</h3>
      </div>
      <p class="hint digest-section-desc">${esc(section.description)}</p>`;

  if (!companies.length) {
    html += `<div class="digest-empty">${q ? `No competitor trends match “${esc(q)}”.` : 'No competitor trends loaded yet — try Refresh.'}</div>`;
    return `${html}</div>`;
  }

  html += `<div class="digest-companies">`;
  for (const company of companies) {
    html += `
      <div class="digest-company" data-company="${esc(company.id)}">
        <div class="digest-company-head">
          <div>
            <h4 class="digest-company-name">
              ${company.website
                ? `<a href="${esc(company.website)}" target="_blank" rel="noopener noreferrer">${esc(company.title)}</a>`
                : esc(company.title)}
            </h4>
            ${company.category ? `<span class="digest-company-cat">${esc(company.category)}</span>` : ''}
          </div>
        </div>
        <p class="digest-quality-focus">${esc(company.qualityFocus || company.description || '')}</p>
        <div class="digest-grid">`;
    if (!company.items?.length) {
      html += `<div class="digest-empty">${company.error ? `Feed unavailable: ${esc(company.error)}` : 'No recent posts loaded.'}</div>`;
    } else {
      html += company.items.map(renderDigestCard).join('');
    }
    html += `</div></div>`;
  }
  html += `</div></div>`;
  return html;
}

function renderSimpleSection(section, viewKey) {
  const items = filterDigestItems(section.items || []);
  const q = digestSearchQuery.trim();

  let html = `
    <div class="digest-section" data-digest-section="${viewKey}">
      <div class="digest-section-head">
        <h3 class="digest-section-title">${esc(section.title)}</h3>
        ${section.hubUrl ? `<a class="digest-hub-link" href="${esc(section.hubUrl)}" target="_blank" rel="noopener noreferrer">Browse all →</a>` : ''}
      </div>
      <p class="hint digest-section-desc">${esc(section.description)}</p>
      <div class="digest-grid">`;

  if (!items.length) {
    html += `<div class="digest-empty">${q ? `No items match “${esc(q)}”.` : 'No items loaded for this section.'}</div>`;
  } else {
    html += items.map(renderDigestCard).join('');
  }
  html += `</div></div>`;
  return html;
}

function renderCompanyFilters(companies) {
  const wrap = $('#digest-company-filters');
  if (!wrap) return;
  const signature = (companies || []).map((c) => c.id).join('|');
  if (wrap.dataset.signature === signature) {
    wrap.querySelectorAll('.digest-chip').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.companyFilter === digestCompanyFilter);
    });
    return;
  }
  wrap.dataset.signature = signature;
  const chips = ['<button type="button" class="digest-chip active" data-company-filter="all">All</button>'];
  for (const company of companies || []) {
    chips.push(`<button type="button" class="digest-chip" data-company-filter="${esc(company.id)}">${esc(company.title)}</button>`);
  }
  wrap.innerHTML = chips.join('');
  wrap.querySelectorAll('.digest-chip').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.companyFilter === digestCompanyFilter);
  });
}

function updateDigestToolbar() {
  const toolbar = $('#digest-toolbar');
  if (toolbar) toolbar.classList.toggle('hidden', digestView !== 'competitors');
}

function renderDigest(d) {
  const meta = $('#digest-meta');
  const out = $('#digest-out');
  const updated = d.fetchedAt ? new Date(d.fetchedAt).toLocaleString() : '—';
  const stats = d.stats
    ? ` · ${d.stats.companiesWithItems}/${d.stats.companies} companies · ${d.stats.totalArticles} articles · ${d.stats.qualityTagged} quality-tagged`
    : '';
  meta.textContent = `Last updated: ${updated}${d.cached ? ' (cached)' : ''}${stats}${d.errors?.length ? ` · ${d.errors.length} feed warning(s)` : ''}`;

  const competitorSection = (d.sections || []).find((s) => s.kind === 'competitor-group');
  renderCompanyFilters(competitorSection?.companies || []);
  updateDigestToolbar();

  let html = '';
  for (const section of d.sections || []) {
    if (section.kind === 'competitor-group' && digestView === 'competitors') {
      html += renderCompetitorSection(section);
    } else if (section.kind === 'kb' && digestView === 'kb') {
      html += renderSimpleSection(section, 'kb');
    } else if (section.kind === 'qa' && digestView === 'qa') {
      html += renderSimpleSection(section, 'qa');
    }
  }

  if (d.errors?.length && digestView === 'competitors') {
    html += `<div class="digest-errors">${d.errors.map((e) => `<div class="insight insight-warn">${esc(e)}</div>`).join('')}</div>`;
  }

  out.innerHTML = html || '<div class="digest-empty">Nothing to show in this section.</div>';
  digestLoaded = true;
}

async function loadDigest(refresh = false) {
  const out = $('#digest-out');
  out.innerHTML = refresh
    ? '<div class="placeholder"><span class="spinner"></span> Fetching competitor trends from 16 providers… this can take up to 20 seconds.</div>'
    : '<div class="placeholder"><span class="spinner"></span> Loading knowledge hub…</div>';
  try {
    const res = await fetch(`/api/digest${refresh ? '?refresh=1' : ''}`);
    const d = await res.json();
    if (!d.ok) throw new Error(d.error || 'Failed to load knowledge hub');
    if (!d.sections?.some((s) => s.kind === 'competitor-group')) {
      throw new Error('Competitor trends data missing — restart the server and refresh.');
    }
    lastDigestData = d;
    renderDigest(d);
  } catch (e) {
    out.innerHTML = `<div class="verdict failed">Could not load knowledge hub: ${esc(e.message)}</div>`;
  }
}

$('#digest-refresh').addEventListener('click', () => loadDigest(true));

$('#digest-search')?.addEventListener('input', (e) => {
  digestSearchQuery = e.target.value;
  if (lastDigestData) renderDigest(lastDigestData);
});

$('#digest-company-filters')?.addEventListener('click', (e) => {
  const btn = e.target.closest('.digest-chip');
  if (!btn) return;
  digestCompanyFilter = btn.dataset.companyFilter || 'all';
  if (lastDigestData) renderDigest(lastDigestData);
});

document.querySelectorAll('.digest-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    digestView = tab.dataset.digestView;
    document.querySelectorAll('.digest-tab').forEach((t) => t.classList.toggle('active', t === tab));
    updateDigestToolbar();
    if (lastDigestData) renderDigest(lastDigestData);
    else loadDigest(false);
  });
});
