// Log analyzer engine. Pure functions, no dependencies — fully working.
// Parses deploy/build/runtime logs and extracts a structured analysis.

const PATTERNS = {
  error: /\b(error|err!|failed|failure|fatal|exception|cannot|not found|no such|denied|refused|timed? ?out)\b/i,
  warning: /\b(warn|warning|deprecated|deprecation)\b/i,
  success: /\b(success|succeeded|complete|completed|done|ready|listening|compiled successfully|build complete)\b/i,
  exitCode: /exit[_ ]?code[:\s]+(-?\d+)/i,
  timestamp: /\b(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s?UTC|Z)?)\b/,
  npmDeprecated: /npm warn deprecated\s+(\S+)/i,
  vulnerabilities: /(\d+)\s+vulnerabilit(?:y|ies)/i,
  vulnBreakdown: /(\d+)\s+(low|moderate|high|critical)/gi,
  portDetected: /port\s+detected[^\d]*(\d+)/i,
  packagesAdded: /added\s+(\d+)\s+packages?/i,
  buildPhase: /^\[([^\]]+)\]\s*(.+)?$/,
  nodeVersion: /node(?:\.js)?\s+v?(\d+\.\d+\.\d+)/i,
  npmVersion: /npm\s+v?(\d+\.\d+\.\d+)/i,
  command: /^\$\s+(.+)$/,
  httpStatusCtx: /\b(?:HTTP\/[\d.]+\s+|status(?:\s+code)?[:\s=]+|response(?:\s+code)?[:\s=]+|returned\s+)(4\d{2}|5\d{2})\b|\b(4\d{2}|5\d{2})\s+(?:error|not found|internal server error|bad gateway|service unavailable|gateway timeout)\b/i,
  stackTrace: /^\s+at\s+.+\(.+:\d+:\d+\)/,
  oom: /heap out of memory|ENOMEM|out of memory/i,
  ansibleFailedTask: /TASK\s+\[(.+?)\]\s+\*\*\*\s+FAILED/i,
  ansibleFatal: /fatal:\s*\[([^\]]+)\]:\s*FAILED!?\s*=>\s*(.+)/i,
  ansibleRecapFailed: /failed=(\d+)/gi,
  ansibleChangedOk: /All items completed|ok=\d+.*changed=\d+/i,
};

const FALSE_POSITIVE_LINE = [
  /['"]failed['"]\s*:\s*0\b/,
  /['"]failed['"]\s*:\s*false\b/i,
  /['"]unreachable['"]\s*:\s*0\b/,
  /['"]rc['"]\s*:\s*0\b/,
  /['"]changed['"]\s*:\s*(?:True|true)/,
  /All items completed/i,
  /PLAY RECAP[\s\S]*failed=0[\s\S]*unreachable=0/i,
  /_ansible_no_log/i,
  /"msg"\s*:\s*"All items completed"/i,
];

const ERROR_CATEGORIES = [
  { id: 'module', label: 'Module / dependency', pattern: /cannot find module|module not found|ERR_MODULE_NOT_FOUND|ENOENT.*node_modules|missing script/i },
  { id: 'network', label: 'Network / connection', pattern: /ECONNREFUSED|ENOTFOUND|ETIMEDOUT|socket hang up|fetch failed|getaddrinfo|network error/i },
  { id: 'permission', label: 'Permission / auth', pattern: /EACCES|permission denied|unauthorized|forbidden|\b401\b|\b403\b/i },
  { id: 'memory', label: 'Memory / resource', pattern: /ENOMEM|out of memory|heap out of memory|JavaScript heap/i },
  { id: 'build', label: 'Build / compile', pattern: /build failed|compilation failed|syntax error|Transform failed|Rollup failed|webpack.*error/i },
  { id: 'database', label: 'Database', pattern: /SQL|postgres|mysql|mongodb|sequelize|prisma|ER_[A-Z_]+|connection.*5432|connection.*3306/i },
  { id: 'port', label: 'Port / binding', pattern: /EADDRINUSE|address already in use|port.*in use/i },
  { id: 'timeout', label: 'Timeout', pattern: /timed? out|timeout exceeded/i },
  { id: 'docker', label: 'Container', pattern: /docker|container exited|OCI runtime|kubectl/i },
  { id: 'ssl', label: 'SSL / TLS', pattern: /SSL|TLS|certificate|cert has expired|UNABLE_TO_VERIFY/i },
];

function detectPackageManager(text) {
  if (/\bpnpm\b/i.test(text)) return 'pnpm';
  if (/\byarn\b/i.test(text)) return 'yarn';
  if (/\bnpm\b/i.test(text)) return 'npm';
  return 'unknown';
}

function detectFramework(text) {
  if (/next build|\.next|next start/i.test(text)) return 'Next.js';
  if (/vinxi|@tanstack\/(react-)?start/i.test(text)) return 'TanStack Start';
  if (/vite build|vite v\d/i.test(text)) return 'Vite';
  if (/react-scripts/i.test(text)) return 'Create React App';
  if (/nuxt/i.test(text)) return 'Nuxt';
  if (/angular/i.test(text)) return 'Angular';
  if (/express|fastify|koa/i.test(text)) return 'Node.js API';
  return 'unknown';
}

function detectLogSource(text) {
  if (/ansible|PLAY \[/i.test(text)) return 'Ansible';
  if (/cloudways|cw-app|application deployment/i.test(text)) return 'Cloudways';
  if (/github actions|##\[group\]|workflow run/i.test(text)) return 'GitHub Actions';
  if (/gitlab-ci|CI_JOB_/i.test(text)) return 'GitLab CI';
  if (/docker|containerd|OCI runtime/i.test(text)) return 'Docker';
  if (/nginx|upstream timed out/i.test(text)) return 'Nginx';
  if (/pm2|PM2/i.test(text)) return 'PM2';
  if (/vercel|netlify|heroku/i.test(text)) return 'PaaS';
  return 'generic';
}

function detectEnvironment(text) {
  if (/\b(production|prod)\b/i.test(text)) return 'production';
  if (/\b(staging|stage|uat|preprod)\b/i.test(text)) return 'staging';
  if (/\b(development|dev|local)\b/i.test(text)) return 'development';
  return 'unknown';
}

function parseTimestamp(ts) {
  return Date.parse(ts.replace(' ', 'T').replace(/\s?UTC/, 'Z'));
}

function categorizeError(text) {
  for (const cat of ERROR_CATEGORIES) {
    if (cat.pattern.test(text)) return cat;
  }
  return { id: 'unknown', label: 'General error' };
}

function isFalsePositiveLine(line) {
  return FALSE_POSITIVE_LINE.some((re) => re.test(line));
}

function extractHttpStatus(line) {
  const m = line.match(PATTERNS.httpStatusCtx);
  if (!m) return null;
  return m[1] || m[2] || null;
}

function extractExactMessage(text) {
  const trimmed = String(text || '').trim();
  const msgJson = trimmed.match(/['"]msg['"]\s*:\s*['"]([^'"]+)['"]/i);
  if (msgJson) return msgJson[1];
  const errPrefix = trimmed.match(/(?:Error|ERROR|Exception|FATAL)[:\s]+(.+)/i);
  if (errPrefix) return errPrefix[1].slice(0, 240);
  const ansibleFatal = trimmed.match(PATTERNS.ansibleFatal);
  if (ansibleFatal) return ansibleFatal[2].slice(0, 240);
  return trimmed.slice(0, 240);
}

function parseAnsibleIssues(text, lines) {
  const issues = [];

  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const failedTask = trimmed.match(PATTERNS.ansibleFailedTask);
    if (failedTask) {
      issues.push({
        title: `Ansible task "${failedTask[1]}" failed`,
        exactMessage: `Task "${failedTask[1]}" reported FAILED`,
        line: i + 1,
        category: 'Ansible task failure',
        categoryId: 'ansible',
        excerpt: trimmed.slice(0, 400),
        investigation: [
          `Open the playbook and inspect task: ${failedTask[1]}`,
          'Re-run the task with -vvv for verbose module output',
          'Verify target host connectivity and permissions',
        ],
      });
    }

    const fatal = trimmed.match(PATTERNS.ansibleFatal);
    if (fatal) {
      let msg = fatal[2];
      try {
        const parsed = JSON.parse(msg.replace(/'/g, '"'));
        msg = parsed.msg || parsed.stderr || parsed.stdout || msg;
      } catch { /* keep raw */ }
      issues.push({
        title: `Ansible failure on host ${fatal[1]}`,
        exactMessage: String(msg).slice(0, 300),
        line: i + 1,
        category: 'Ansible task failure',
        categoryId: 'ansible',
        excerpt: trimmed.slice(0, 400),
        investigation: [
          `Check host ${fatal[1]} logs and SSH access`,
          'Validate variables and module arguments for this task',
          'Confirm the target service/path exists on the host',
        ],
      });
    }

    if (/['"]failed['"]\s*:\s*(?:True|true|1)\b/.test(trimmed)) {
      const msg = extractExactMessage(trimmed);
      if (msg && !/All items completed/i.test(msg)) {
        issues.push({
          title: `Ansible reported failure: ${msg.slice(0, 90)}`,
          exactMessage: msg,
          line: i + 1,
          category: 'Ansible task failure',
          categoryId: 'ansible',
          excerpt: trimmed.slice(0, 400),
          investigation: [
            'Inspect the Ansible task result JSON for module stderr/stdout',
            'Re-run the play with --start-at-task targeting the failing task',
          ],
        });
      }
    }
  });

  const recapMatches = [...text.matchAll(PATTERNS.ansibleRecapFailed)];
  for (const m of recapMatches) {
    const count = Number(m[1]);
    if (count > 0) {
      const recapLine = lines.findIndex((l) => /PLAY RECAP|failed=\d+/i.test(l)) + 1;
      issues.push({
        title: `Ansible PLAY RECAP shows ${count} failed task(s)`,
        exactMessage: `PLAY RECAP reports failed=${count}`,
        line: recapLine > 0 ? recapLine : null,
        category: 'Ansible recap',
        categoryId: 'ansible',
        excerpt: lines.find((l) => /failed=\d+/i.test(l))?.slice(0, 400) || '',
        investigation: [
          'Scroll to the first TASK [...] *** FAILED *** block above the recap',
          'Fix the failing task, then re-run the playbook',
        ],
      });
      break;
    }
  }

  return issues;
}

function dedupeIssues(issues) {
  const seen = new Set();
  return issues.filter((issue) => {
    const key = `${issue.title}|${issue.exactMessage}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildIssues({ text, lines, errors, summary, failedPhase, exitCode }) {
  const issues = [];

  issues.push(...parseAnsibleIssues(text, lines));

  for (const err of errors) {
    const exact = extractExactMessage(err.text);
    issues.push({
      title: `${err.category}: ${exact.slice(0, 100)}`,
      exactMessage: exact,
      line: err.line,
      category: err.category,
      categoryId: err.categoryId,
      excerpt: err.text,
      investigation: investigationForCategory(err.categoryId, exact),
    });
  }

  if (exitCode !== null && exitCode !== 0 && !issues.length) {
    issues.push({
      title: `Process exited with non-zero code ${exitCode}`,
      exactMessage: `exit_code: ${exitCode}`,
      line: lines.findIndex((l) => /exit[_ ]?code/i.test(l)) + 1 || null,
      category: 'Exit code',
      categoryId: 'exit',
      excerpt: lines.find((l) => /exit[_ ]?code/i.test(l)) || `Process terminated with exit code ${exitCode}`,
      investigation: ['Review the last command output before exit', 'Re-run the same command locally to reproduce'],
    });
  }

  if (failedPhase && !issues.some((i) => i.line === failedPhase.line)) {
    const nearError = errors.find((e) => e.line >= failedPhase.line - 5);
    if (nearError) {
      // already covered by error issue
    }
  }

  if (summary.vulnerabilityBreakdown?.high > 0 || summary.vulnerabilityBreakdown?.critical > 0) {
    const { high, critical, moderate, low } = summary.vulnerabilityBreakdown;
    issues.push({
      title: `npm audit: ${high + critical} high/critical vulnerabilities in dependencies`,
      exactMessage: `${high + critical} high/critical, ${moderate} moderate, ${low} low`,
      line: lines.findIndex((l) => /vulnerabilit/i.test(l)) + 1 || null,
      category: 'Security / npm audit',
      categoryId: 'security',
      excerpt: lines.find((l) => /vulnerabilit/i.test(l))?.slice(0, 400) || '',
      investigation: ['Run npm audit for package names', 'Upgrade or override affected dependencies', 'Re-run install and confirm audit is clean'],
    });
  }

  return dedupeIssues(issues);
}

function investigationForCategory(categoryId, message) {
  const map = {
    module: ['Run npm install / pnpm install from a clean node_modules', 'Verify the missing package is listed in package.json', 'Check CI cache is not stale'],
    network: ['Verify the target URL/host is reachable from the deploy environment', 'Check DNS, firewall, and proxy settings', 'Confirm the upstream service is running'],
    permission: ['Verify credentials and API tokens in CI/deploy secrets', 'Check file/folder permissions on the target path', 'Confirm the service account has required roles'],
    memory: ['Increase NODE_OPTIONS=--max-old-space-size', 'Reduce parallel build workers', 'Split the build or optimize bundle size'],
    build: ['Re-run the build locally with the same Node version', 'Inspect the first compile error above this line', 'Clear build cache (.next, dist, node_modules/.cache)'],
    database: ['Verify DB host, port, username, and password', 'Check migrations have been applied', 'Confirm network access from app server to DB'],
    port: ['Find and stop the process using the port (lsof -i :PORT)', 'Set a different PORT in environment config', 'Ensure only one app instance binds the port'],
    timeout: ['Increase timeout settings for the failing request/build step', 'Check if upstream service is slow or unavailable', 'Add retries for transient network failures'],
    docker: ['Inspect container logs (docker logs <id>)', 'Verify image tag and Dockerfile build args', 'Check volume mounts and entrypoint command'],
    ssl: ['Renew or reinstall the TLS certificate', 'Verify certificate chain and intermediate certs', 'Confirm system clock is correct'],
    ansible: ['Re-run ansible with -vvv on the failing task', 'Verify inventory host vars and become/sudo settings'],
  };
  return map[categoryId] || ['Review the exact log line and reproduce the failing command locally', 'Compare with the last successful deploy log'];
}

function buildBugReport({ verdict, verdictReason, summary, issues, failedPhase }) {
  const blocking = issues.filter((i) => !isAdvisoryIssue(i));

  if (!blocking.length) {
    if (verdict === 'success') {
      const advisory = issues.filter(isAdvisoryIssue);
      const note = advisory.length
        ? `Build/deploy succeeded. Advisory: ${advisory[0].title}`
        : 'Log analysis did not detect failed tasks, error lines, or a non-zero exit code.';
      return {
        summary: advisory.length ? advisory[0].title : 'No defect found — deploy/build completed successfully',
        body: note,
        copyText: advisory.length
          ? `${advisory[0].title}\n\nBuild/deploy succeeded (exit code ${summary.exitCode ?? 'n/a'}).\n\nAdvisory only — not a deploy failure:\n${advisory[0].exactMessage}\n\nRecommended: run npm audit and upgrade affected packages before production.`
          : 'No defect found — deploy/build completed successfully.\n\nLog analysis did not detect failed tasks, error lines, or a non-zero exit code.',
        hasIssue: false,
      };
    }
    return {
      summary: `Investigate: ${verdictReason}`,
      body: [
        '## Summary',
        verdictReason,
        '',
        '## Environment',
        `- Log source: ${summary.logSource}`,
        `- Environment: ${summary.environment}`,
        summary.framework !== 'unknown' ? `- Framework: ${summary.framework}` : null,
        summary.exitCode !== null ? `- Exit code: ${summary.exitCode}` : null,
        '',
        '## Note',
        'No exact failure message was extracted. Review the full log manually.',
      ].filter(Boolean).join('\n'),
      copyText: `Investigate: ${verdictReason}\n\nLog source: ${summary.logSource}\nEnvironment: ${summary.environment}\n\nNo exact failure message was extracted — review full log.`,
      hasIssue: verdict !== 'success',
    };
  }

  const primary = blocking[0] || issues[0];
  const summaryLine = primary.title;
  const envLines = [
    `- Log source: ${summary.logSource}`,
    `- Environment: ${summary.environment}`,
    summary.framework !== 'unknown' ? `- Framework: ${summary.framework}` : null,
    summary.packageManager !== 'unknown' ? `- Package manager: ${summary.packageManager}` : null,
    summary.nodeVersion ? `- Node: ${summary.nodeVersion}` : null,
    summary.exitCode !== null ? `- Exit code: ${summary.exitCode}` : null,
    failedPhase ? `- Failed phase: ${failedPhase.phase} (line ${failedPhase.line})` : null,
    primary.line ? `- Log line: ${primary.line}` : null,
  ].filter(Boolean);

  const body = [
    '## Summary',
    summaryLine,
    '',
    '## What happened',
    primary.exactMessage || primary.title,
    '',
    '## Environment',
    ...envLines,
    '',
    '## Log excerpt',
    '```',
    primary.excerpt || primary.exactMessage || '',
    '```',
    '',
    '## Steps to investigate',
    ...primary.investigation.map((step, i) => `${i + 1}. ${step}`),
  ];

  if (issues.length > 1) {
    body.push('', '## Additional issues');
    issues.slice(1, 4).forEach((issue, i) => {
      body.push(`${i + 1}. ${issue.title}${issue.line ? ` (line ${issue.line})` : ''}`);
      if (issue.exactMessage) body.push(`   ${issue.exactMessage}`);
    });
  }

  const copyText = body.join('\n');
  return { summary: summaryLine, body: copyText, copyText, hasIssue: true };
}

function parseVulnerabilityBreakdown(text) {
  const breakdown = { low: 0, moderate: 0, high: 0, critical: 0 };
  let match;
  const re = new RegExp(PATTERNS.vulnBreakdown.source, 'gi');
  while ((match = re.exec(text)) !== null) {
    const count = Number(match[1]);
    const level = match[2].toLowerCase();
    if (level in breakdown) breakdown[level] += count;
  }
  const total = breakdown.low + breakdown.moderate + breakdown.high + breakdown.critical;
  return total > 0 ? { ...breakdown, total } : null;
}

function isAdvisoryIssue(issue) {
  return issue.categoryId === 'security';
}

function hasBlockingIssues(issues) {
  return issues.some((issue) => !isAdvisoryIssue(issue));
}

function buildInsights({ verdict, summary, errorCategories, firstError, failedPhase, deprecations, issues }) {
  const insights = [];
  const blocking = (issues || []).filter((i) => !isAdvisoryIssue(i));

  if (blocking.length) {
    insights.push({ level: 'error', text: blocking[0].title });
    if (blocking[0].line) {
      insights.push({ level: 'error', text: `Exact message (line ${blocking[0].line}): ${blocking[0].exactMessage}` });
    }
  } else if (issues?.length && verdict !== 'success') {
    insights.push({ level: 'warn', text: issues[0].title });
  }

  if (verdict === 'failed' && failedPhase && !issues?.length) {
    insights.push({ level: 'error', text: `Deploy likely failed during "${failedPhase.phase}" (line ${failedPhase.line}). Start debugging there.` });
  }
  if (firstError && !issues?.length) {
    insights.push({ level: 'error', text: `First error at line ${firstError.line} (${firstError.category}): ${extractExactMessage(firstError.text)}` });
  }
  if (summary.vulnerabilityBreakdown?.high > 0 || summary.vulnerabilityBreakdown?.critical > 0) {
    const { high, critical } = summary.vulnerabilityBreakdown;
    insights.push({ level: 'warn', text: `${high + critical} high/critical npm vulnerability(ies) — run npm audit and upgrade affected packages before production.` });
  }
  if (deprecations.length > 0) {
    insights.push({ level: 'warn', text: `${deprecations.length} deprecated package(s) — plan upgrades to avoid future breakage.` });
  }
  if (errorCategories.find((c) => c.id === 'module')) {
    insights.push({ level: 'error', text: 'Missing module detected — verify package.json dependencies and run a clean install.' });
  }
  if (errorCategories.find((c) => c.id === 'port')) {
    insights.push({ level: 'error', text: 'Port already in use — stop the conflicting process or change PORT in .env.' });
  }
  if (errorCategories.find((c) => c.id === 'memory')) {
    insights.push({ level: 'error', text: 'Out-of-memory — increase Node heap (NODE_OPTIONS=--max-old-space-size) or optimize the build.' });
  }
  if (errorCategories.find((c) => c.id === 'network')) {
    insights.push({ level: 'warn', text: 'Network/connection errors — check service URLs, DNS, firewall, and upstream availability.' });
  }
  if (errorCategories.find((c) => c.id === 'database')) {
    insights.push({ level: 'error', text: 'Database errors — verify credentials, host reachability, and migration state.' });
  }
  if (verdict === 'success' && summary.warnings > 0) {
    insights.push({ level: 'info', text: 'Build succeeded with warnings — safe to deploy but review warnings before production.' });
  }
  if (verdict === 'success' && summary.errors === 0 && summary.warnings === 0) {
    insights.push({ level: 'info', text: 'Clean run — no errors or warnings detected.' });
  }
  if (summary.httpErrors?.length) {
    insights.push({ level: 'warn', text: `HTTP ${summary.httpErrors.join(', ')} responses found — check API/routing and upstream health.` });
  }

  return insights.slice(0, 8);
}

function analyzeLog(raw) {
  const text = String(raw || '');
  const lines = text.split(/\r?\n/);

  const errors = [];
  const warnings = [];
  const deprecations = new Set();
  const timestamps = [];
  const phases = [];
  const commands = [];
  const httpErrors = new Set();
  const categoryCounts = new Map();
  let stackTraceLines = 0;

  let exitCode = null;
  let vulnerabilities = null;
  let portDetected = null;
  let packagesAdded = null;
  let nodeVersion = null;
  let npmVersion = null;

  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    const ts = trimmed.match(PATTERNS.timestamp);
    if (ts) timestamps.push({ line: i + 1, raw: ts[1] });

    const ec = trimmed.match(PATTERNS.exitCode);
    if (ec) exitCode = Number(ec[1]);

    const dep = trimmed.match(PATTERNS.npmDeprecated);
    if (dep) deprecations.add(dep[1]);

    const vuln = trimmed.match(PATTERNS.vulnerabilities);
    if (vuln && vulnerabilities === null) vulnerabilities = Number(vuln[1]);

    const port = trimmed.match(PATTERNS.portDetected);
    if (port) portDetected = Number(port[1]);

    const pkgs = trimmed.match(PATTERNS.packagesAdded);
    if (pkgs) packagesAdded = Number(pkgs[1]);

    const nv = trimmed.match(PATTERNS.nodeVersion);
    if (nv && !nodeVersion) nodeVersion = nv[1];

    const npmv = trimmed.match(PATTERNS.npmVersion);
    if (npmv && !npmVersion) npmVersion = npmv[1];

    const cmd = trimmed.match(PATTERNS.command);
    if (cmd) commands.push({ line: i + 1, command: cmd[1].slice(0, 120) });

    const http = extractHttpStatus(trimmed);
    if (http) httpErrors.add(http);

    const phase = trimmed.match(PATTERNS.buildPhase);
    if (phase) {
      let phaseLabel = phase[1].trim();
      let phaseText = (phase[2] || '').trim();
      if (PATTERNS.timestamp.test(phaseLabel)) {
        phaseLabel = phaseText;
        phaseText = '';
      }
      if (phaseLabel && !/^\d/.test(phaseLabel) && !/^(exit[_ ]?code|status)\b/i.test(phaseLabel)) {
        phases.push({
          line: i + 1,
          phase: phaseLabel,
          text: phaseText,
          timestamp: ts ? ts[1] : (PATTERNS.timestamp.test(phase[1]) ? phase[1] : null),
        });
      }
    }

    if (PATTERNS.stackTrace.test(trimmed)) stackTraceLines += 1;

    const isDep = PATTERNS.warning.test(trimmed) && /deprecat/i.test(trimmed);
    if (PATTERNS.error.test(trimmed) && !isDep && !isFalsePositiveLine(trimmed)) {
      const category = categorizeError(trimmed);
      categoryCounts.set(category.id, (categoryCounts.get(category.id) || 0) + 1);
      errors.push({ line: i + 1, text: trimmed.slice(0, 300), category: category.label, categoryId: category.id });
    } else if (PATTERNS.warning.test(trimmed) && !isDep) {
      warnings.push({ line: i + 1, text: trimmed.slice(0, 300) });
    }
  });

  const vulnerabilityBreakdown = parseVulnerabilityBreakdown(text);
  const logSource = detectLogSource(text);
  const ansibleSuccess = logSource === 'Ansible' && PATTERNS.ansibleChangedOk.test(text)
    && ![...text.matchAll(PATTERNS.ansibleRecapFailed)].some((m) => Number(m[1]) > 0)
    && !/TASK\s+\[.+?\]\s+\*\*\*\s+FAILED/i.test(text);

  // Duration if 2+ timestamps
  let durationSec = null;
  if (timestamps.length >= 2) {
    const t0 = parseTimestamp(timestamps[0].raw);
    const t1 = parseTimestamp(timestamps[timestamps.length - 1].raw);
    if (!Number.isNaN(t0) && !Number.isNaN(t1) && t1 >= t0) durationSec = Math.round((t1 - t0) / 1000);
  }

  // Phase durations from consecutive timestamps
  const phasesWithDuration = phases.map((p, idx) => {
    const next = phases[idx + 1];
    let durationSec = null;
    if (p.timestamp && next?.timestamp) {
      const t0 = parseTimestamp(p.timestamp);
      const t1 = parseTimestamp(next.timestamp);
      if (!Number.isNaN(t0) && !Number.isNaN(t1) && t1 >= t0) durationSec = Math.round((t1 - t0) / 1000);
    }
    return { ...p, durationSec };
  });

  const firstError = errors[0] || null;

  // Failed phase: last phase before first error
  let failedPhase = null;
  if (firstError && phases.length) {
    failedPhase = [...phases].reverse().find((p) => p.line <= firstError.line) || phases[phases.length - 1];
  }

  const errorCategories = [...categoryCounts.entries()]
    .map(([id, count]) => ({
      id,
      label: ERROR_CATEGORIES.find((c) => c.id === id)?.label || 'General error',
      count,
    }))
    .sort((a, b) => b.count - a.count);

  const issues = buildIssues({
    text, lines, errors,
    summary: { vulnerabilityBreakdown, logSource },
    failedPhase,
    exitCode,
  });

  let verdict;
  let verdictReason;
  const buildSucceeded = exitCode === 0 || ansibleSuccess || PATTERNS.success.test(text);

  if (exitCode !== null && exitCode !== 0) {
    verdict = 'failed';
    verdictReason = issues[0]?.exactMessage || `Process exited with code ${exitCode}`;
  } else if (buildSucceeded) {
    verdict = 'success';
    if (ansibleSuccess) verdictReason = 'Ansible tasks completed successfully';
    else if (exitCode === 0) verdictReason = 'Process exited cleanly (exit code 0)';
    else verdictReason = 'Success markers found in log';
    if (issues.some(isAdvisoryIssue)) {
      verdictReason += ' (npm audit advisories present — review before production)';
    }
  } else if (hasBlockingIssues(issues)) {
    verdict = 'failed';
    verdictReason = issues.find((i) => !isAdvisoryIssue(i)).exactMessage || issues[0].title;
  } else if (errors.length > 0 && exitCode === null) {
    verdict = 'errors-found';
    verdictReason = `${errors.length} error-like line(s) detected, no explicit exit code`;
  } else if (PATTERNS.success.test(text)) {
    verdict = 'success';
    verdictReason = 'Success markers found, no exit code';
  } else {
    verdict = 'inconclusive';
    verdictReason = 'No clear success or failure signal';
  }

  const summary = {
    totalLines: lines.filter((l) => l.trim()).length,
    errors: errors.length,
    warnings: warnings.length,
    deprecations: deprecations.size,
    exitCode,
    vulnerabilities: vulnerabilityBreakdown?.total ?? vulnerabilities,
    vulnerabilityBreakdown,
    portDetected,
    packagesAdded,
    durationSec,
    packageManager: detectPackageManager(text),
    framework: detectFramework(text),
    logSource,
    environment: detectEnvironment(text),
    nodeVersion,
    npmVersion,
    httpErrors: [...httpErrors].sort(),
    commandsRun: commands.length,
    stackTraceLines,
    hasOom: PATTERNS.oom.test(text),
  };

  const insights = buildInsights({
    verdict,
    summary,
    errorCategories,
    firstError,
    failedPhase,
    deprecations: [...deprecations],
    issues,
  });

  const bugReport = buildBugReport({ verdict, verdictReason, summary, issues, failedPhase });

  return {
    verdict,
    verdictReason,
    summary,
    insights,
    issues,
    bugReport,
    firstError: (() => {
      const blocking = issues.filter((i) => !isAdvisoryIssue(i));
      if (blocking[0]) {
        return {
          line: blocking[0].line,
          text: blocking[0].excerpt || blocking[0].exactMessage,
          category: blocking[0].category,
        };
      }
      return verdict === 'success' ? null : firstError;
    })(),
    failedPhase: failedPhase ? { phase: failedPhase.phase, line: failedPhase.line } : null,
    errorCategories,
    errors: errors.slice(0, 50),
    warnings: warnings.slice(0, 50),
    deprecations: [...deprecations],
    phases: phasesWithDuration.slice(0, 50),
    commands: commands.slice(0, 20),
  };
}

module.exports = { analyzeLog };
