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

// --- Tabs ---
let digestLoaded = false;
document.querySelectorAll('.tab').forEach((t) => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.panel').forEach((x) => x.classList.remove('active'));
    t.classList.add('active');
    $(`#tab-${t.dataset.tab}`).classList.add('active');
    if (t.dataset.tab === 'digest' && !digestLoaded) loadDigest();
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

async function runAnalysis(log) {
  if (!String(log || '').trim()) return;
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
    renderAnalysis(a);
    setWorkspaceExpanded(true);
  } catch (e) {
    $('#analyze-out').innerHTML = `<div class="verdict failed">Error: ${esc(e.message)}</div>`;
    setWorkspaceExpanded(true);
  }
}

$('#analyze-btn').addEventListener('click', () => runAnalysis($('#log-input').value));

$('#analyze-clear').addEventListener('click', () => {
  $('#log-input').value = '';
  setWorkspaceExpanded(false);
  $('#analyze-out').innerHTML = '<div class="placeholder">Analysis will appear here.</div>';
});

function renderAnalysis(a) {
  const s = a.summary;
  const isSuccess = a.verdict === 'success';
  const stat = (n, l, cls = '') => `<div class="stat"><span class="stat-n ${cls}">${n}</span><span class="stat-l">${l}</span></div>`;
  const vb = s.vulnerabilityBreakdown;
  let html = `
    <div class="verdict ${a.verdict}">
      <span>${verdictLabel(a.verdict)}</span>
      <span class="verdict-reason">${esc(a.verdictReason)}</span>
    </div>`;

  if (!isSuccess && a.bugReport?.hasIssue) {
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

  if (!isSuccess && a.issues?.length) {
    html += `<div class="block-h">Detected issues (${a.issues.length})</div>`;
    html += a.issues.slice(0, 5).map((issue) => `
      <div class="issue-card">
        <div class="issue-title">${esc(issue.title)}</div>
        ${issue.line ? `<div class="issue-meta">Line ${issue.line} · ${esc(issue.category)}</div>` : ''}
        <div class="issue-msg">${esc(issue.exactMessage)}</div>
      </div>`).join('');
  }

  if (!isSuccess && a.insights?.length) {
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
    html += `<div class="block-h">Likely failure point</div><div class="insight insight-error">Phase "${esc(a.failedPhase.phase)}" near line ${a.failedPhase.line}</div>`;
  }

  if (!isSuccess && a.firstError) {
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

  if (a.errors.length && a.verdict !== 'success') {
    html += `<div class="block-h">Errors (${a.errors.length})</div>`;
    html += a.errors.map((e) => `<div class="log-line err"><span class="ln">L${e.line}</span><span class="tx">${esc(e.text)}${e.category ? `<span class="line-cat">${esc(e.category)}</span>` : ''}</span></div>`).join('');
  }
  if (a.deprecations.length) {
    html += `<div class="block-h">Deprecated packages</div><div class="tag-list">${a.deprecations.map((d) => `<span class="tag">${esc(d)}</span>`).join('')}</div>`;
  }
  if (a.warnings.length && a.verdict !== 'success') {
    html += `<div class="block-h">Warnings (${a.warnings.length})</div>`;
    html += a.warnings.slice(0, 15).map((w) => `<div class="log-line warn"><span class="ln">L${w.line}</span><span class="tx">${esc(w.text)}</span></div>`).join('');
  }

  lastBugReportText = (!isSuccess && a.bugReport?.hasIssue) ? a.bugReport.copyText : '';
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
