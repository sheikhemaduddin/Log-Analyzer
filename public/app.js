const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

let lastBugReportText = '';

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('log-triage-theme', theme);
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

const SAMPLE_LOG = `[2026-07-09 06:17:51 UTC] Install Dependencies
$ npm install
added 425 packages, and audited 426 packages in 6s
26 vulnerabilities (1 low, 23 moderate, 2 high)
npm warn deprecated supertest@6.3.4: Please upgrade
npm warn deprecated glob@7.2.3: Old versions of glob are not supported
[2026-07-09 06:18:02 UTC] Build
$ npm run build
vite v5.4.0 building for production...
node v20.11.0
[info] Port detected from .env: 3000
[2026-07-09 06:18:20 UTC] Finished
Status : SUCCESS
[exit_code: 0]`;

$('#analyze-sample').addEventListener('click', () => { $('#log-input').value = SAMPLE_LOG; });
$('#analyze-clear').addEventListener('click', () => {
  $('#log-input').value = '';
  $('#analyze-out').innerHTML = '<div class="placeholder">Analysis will appear here.</div>';
});

$('#analyze-btn').addEventListener('click', async () => {
  const log = $('#log-input').value;
  if (!log.trim()) return;
  $('#analyze-out').innerHTML = '<div class="placeholder"><span class="spinner"></span> Analyzing…</div>';
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ log }),
    });
    const a = await res.json();
    if (a.error) throw new Error(a.error);
    renderAnalysis(a);
  } catch (e) {
    $('#analyze-out').innerHTML = `<div class="verdict failed">Error: ${esc(e.message)}</div>`;
  }
});

function renderAnalysis(a) {
  const s = a.summary;
  const stat = (n, l, cls = '') => `<div class="stat"><span class="stat-n ${cls}">${n}</span><span class="stat-l">${l}</span></div>`;
  const vb = s.vulnerabilityBreakdown;
  let html = `
    <div class="verdict ${a.verdict}">
      <span>${verdictLabel(a.verdict)}</span>
      <span class="verdict-reason">${esc(a.verdictReason)}</span>
    </div>`;

  if (a.bugReport) {
    html += `
      <div class="bug-report-box">
        <div class="bug-report-head">
          <span class="block-h" style="margin:0">Bug report — paste into Jira</span>
          <button type="button" class="btn-ghost btn-sm copy-bug-btn">Copy</button>
        </div>
        <div class="bug-report-summary">${esc(a.bugReport.summary)}</div>
        <pre class="bug-report-body">${esc(a.bugReport.copyText)}</pre>
      </div>`;
  }

  if (a.issues?.length) {
    html += `<div class="block-h">Detected issues (${a.issues.length})</div>`;
    html += a.issues.slice(0, 5).map((issue) => `
      <div class="issue-card">
        <div class="issue-title">${esc(issue.title)}</div>
        ${issue.line ? `<div class="issue-meta">Line ${issue.line} · ${esc(issue.category)}</div>` : ''}
        <div class="issue-msg">${esc(issue.exactMessage)}</div>
      </div>`).join('');
  }

  if (a.insights?.length) {
    html += `<div class="block-h">Insights</div>`;
    html += a.insights.map((ins) => `<div class="insight insight-${ins.level}">${esc(ins.text)}</div>`).join('');
  }

  html += `
    <div class="stats">
      ${stat(s.errors, 'Errors', s.errors ? 'err' : 'ok')}
      ${stat(s.warnings, 'Warnings', s.warnings ? 'warn' : '')}
      ${stat(s.deprecations, 'Deprecated')}
      ${stat(s.exitCode === null ? '—' : s.exitCode, 'Exit code', s.exitCode === 0 ? 'ok' : (s.exitCode ? 'err' : ''))}
      ${stat(s.vulnerabilities === null ? '—' : s.vulnerabilities, 'Vulns', vb?.high || vb?.critical ? 'warn' : '')}
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
    html += `<div class="block-h">Vulnerability breakdown</div><div class="tag-list">`;
    if (vb.critical) html += `<span class="tag err-tag">${vb.critical} critical</span>`;
    if (vb.high) html += `<span class="tag warn-tag">${vb.high} high</span>`;
    if (vb.moderate) html += `<span class="tag">${vb.moderate} moderate</span>`;
    if (vb.low) html += `<span class="tag">${vb.low} low</span>`;
    html += `</div>`;
  }

  if (a.errorCategories?.length) {
    html += `<div class="block-h">Error categories</div><div class="tag-list">${a.errorCategories.map((c) => `<span class="tag err-tag">${esc(c.label)} (${c.count})</span>`).join('')}</div>`;
  }

  if (a.failedPhase) {
    html += `<div class="block-h">Likely failure point</div><div class="insight insight-error">Phase "${esc(a.failedPhase.phase)}" near line ${a.failedPhase.line}</div>`;
  }

  if (a.firstError) {
    html += `<div class="block-h">First error (root cause candidate)</div>`;
    html += `<div class="log-line err"><span class="ln">L${a.firstError.line}</span><span class="tx">${esc(a.firstError.text)}</span></div>`;
    if (a.firstError.category) html += `<div class="tag-list"><span class="tag err-tag">${esc(a.firstError.category)}</span></div>`;
  }

  if (a.phases?.length) {
    html += `<div class="block-h">Build timeline</div><div class="timeline">`;
    html += a.phases.map((p) => `
      <div class="timeline-item">
        <span class="timeline-phase">${esc(p.phase)}</span>
        <span class="timeline-meta">L${p.line}${p.durationSec != null ? ` · ${p.durationSec}s` : ''}</span>
      </div>`).join('');
    html += `</div>`;
  }

  if (a.commands?.length) {
    html += `<div class="block-h">Commands run</div>`;
    html += a.commands.map((c) => `<div class="log-line"><span class="ln">L${c.line}</span><span class="tx">${esc(c.command)}</span></div>`).join('');
  }

  if (a.errors.length) {
    html += `<div class="block-h">Errors (${a.errors.length})</div>`;
    html += a.errors.map((e) => `<div class="log-line err"><span class="ln">L${e.line}</span><span class="tx">${esc(e.text)}${e.category ? `<span class="line-cat">${esc(e.category)}</span>` : ''}</span></div>`).join('');
  }
  if (a.deprecations.length) {
    html += `<div class="block-h">Deprecated packages</div><div class="tag-list">${a.deprecations.map((d) => `<span class="tag">${esc(d)}</span>`).join('')}</div>`;
  }
  if (a.warnings.length) {
    html += `<div class="block-h">Warnings (${a.warnings.length})</div>`;
    html += a.warnings.slice(0, 15).map((w) => `<div class="log-line warn"><span class="ln">L${w.line}</span><span class="tx">${esc(w.text)}</span></div>`).join('');
  }

  lastBugReportText = a.bugReport?.copyText || '';
  $('#analyze-out').innerHTML = html;
  $('#analyze-out').querySelectorAll('.copy-bug-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(lastBugReportText);
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      } catch {
        btn.textContent = 'Copy failed';
      }
    });
  });
}

function verdictLabel(v) {
  return { success: '✓ Success', failed: '✕ Failed', 'errors-found': '⚠ Errors found', inconclusive: '? Inconclusive' }[v] || v;
}
