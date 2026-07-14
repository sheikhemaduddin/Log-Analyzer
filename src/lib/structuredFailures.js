// Structured failure parsers — turn noisy logs into actionable assessments.
// Each parser returns null or a rich issue with failureDetail.

function lineNo(lines, predicate) {
  const i = lines.findIndex(predicate);
  return i >= 0 ? i + 1 : null;
}

function findLine(lines, re) {
  return lines.find((l) => re.test(l)) || null;
}

function lastCommand(lines) {
  for (let i = lines.length - 1; i >= 0; i -= 1) {
    const m = lines[i].trim().match(/^\$\s+(.+)$/);
    if (m) return m[1].slice(0, 160);
  }
  return null;
}

function packageManager(text) {
  if (/\bpnpm\b/i.test(text)) return 'pnpm';
  if (/\byarn\b/i.test(text)) return 'yarn';
  if (/\bnpm\b/i.test(text)) return 'npm';
  return 'npm';
}

function makeIssue({
  type,
  categoryId,
  category,
  headline,
  description,
  line,
  excerpt,
  failedCommand,
  failedPhase,
  conflict,
  details,
  resolution,
  investigation,
}) {
  return {
    title: headline,
    exactMessage: description,
    line: line || null,
    category,
    categoryId,
    excerpt: (excerpt || headline).slice(0, 400),
    investigation: investigation || resolution || [],
    failureDetail: {
      type,
      headline,
      description,
      failedCommand: failedCommand || null,
      failedPhase: failedPhase || null,
      conflict: conflict || null,
      details: details || [],
      resolution: [...new Set(resolution || [])],
    },
  };
}

function noiseSuppressForStructured(text) {
  return /ERESOLVE|error code E\d+|yarn error|ERR_PNPM|FATAL:|Finished:\s*FAILURE|container exited|OCI runtime|PLAY RECAP|TASK \[.+\] \*\*\* FAILED/i.test(text);
}

// --- npm / yarn / pnpm ----------------------------------------------------

function parseNpmEresolve(text, lines) {
  if (!/ERESOLVE could not resolve|npm error code ERESOLVE/i.test(text)) return null;

  const eresolveLine = lineNo(lines, (l) => /npm error code ERESOLVE|ERESOLVE could not resolve/i.test(l));
  const whileResolving = findLine(lines, /While resolving:\s*(\S+)/i);
  const foundInstalled = findLine(lines, /Found:\s*(\S+@\S+)/i);
  const couldNotResolveIdx = lines.findIndex((l) => /Could not resolve dependency/i.test(l));
  const peerRequired = couldNotResolveIdx >= 0
    ? lines.slice(couldNotResolveIdx, couldNotResolveIdx + 6).find((l) => /peer(?:Optional)?\s/i.test(l))
    : findLine(lines, /peer(?:Optional)?\s+.+from\s+\S+/i);
  const conflicting = findLine(lines, /Conflicting peer dependency:\s*(\S+)/i);
  const fixLine = findLine(lines, /--legacy-peer-deps|--force/i);

  const pkgMatch = whileResolving?.match(/While resolving:\s*(\S+)/i);
  const installedMatch = foundInstalled?.match(/Found:\s*(\S+)/i);
  const rootDepMatch = findLine(lines, /(?:dev|peer)\s+(\S+@"[^"]+"|\S+@\^[^\s]+)\s+from the root project/i);
  const peerMatch = peerRequired?.match(/peer(?:Optional)?\s+(\S+@"[^"]+"|\S+@>=[^\s]+)\s+from\s+(\S+)/i);
  const conflictMatch = conflicting?.match(/Conflicting peer dependency:\s*(\S+)/i);

  const installedPkg = installedMatch?.[1] || null;
  const requiredBy = peerMatch?.[2] || pkgMatch?.[1] || null;
  const requiredRangeRaw = peerMatch?.[1] || null;
  const requiredRange = requiredRangeRaw?.includes('@')
    ? requiredRangeRaw.split('@').slice(1).join('@').replace(/"/g, '')
    : requiredRangeRaw;
  const wouldInstall = conflictMatch?.[1] || null;
  const installedName = installedPkg?.split('@')[0] || 'dependency';
  const requiredName = requiredRangeRaw?.split('@')[0] || installedName;

  let installedFrom = 'the project';
  if (rootDepMatch) {
    const m = rootDepMatch.match(/(?:dev|peer)\s+(\S+@"[^"]+"|\S+@\^[^\s]+)\s+from the root project/i);
    if (m) installedFrom = `root package.json (${m[1]})`;
  }

  const headline = requiredBy && installedPkg && requiredRange
    ? `npm install failed: ${requiredBy} requires ${requiredName} ${requiredRange}, but the project has ${installedPkg}`
    : 'npm install failed: dependency peer conflict (ERESOLVE)';

  const description = installedPkg && requiredBy
    ? `${requiredBy} expects ${requiredName} ${requiredRange || 'at a compatible version'}, but ${installedPkg} is pinned via ${installedFrom}. npm cannot satisfy both without updating package.json.`
    : 'npm could not resolve conflicting peer dependency versions during install.';

  const resolution = [];
  if (installedName && requiredRange) {
    resolution.push(`Upgrade ${installedName} in package.json to ${requiredRange} (or newer) to satisfy ${requiredBy || 'the peer requirement'}.`);
    resolution.push('Run npm install locally, verify the build, commit package-lock.json, then redeploy.');
  } else {
    resolution.push('Align peer dependency versions in package.json so install can resolve cleanly.');
  }
  if (wouldInstall && installedPkg && wouldInstall !== installedPkg) {
    resolution.push(`npm would pull in ${wouldInstall} — confirm that major upgrade is intended before deploying.`);
  }
  if (fixLine) {
    resolution.push('Temporary workaround only: npm install --legacy-peer-deps. Prefer fixing package.json versions.');
  }

  return makeIssue({
    type: 'npm-eresolve',
    categoryId: 'npm-peer-deps',
    category: 'npm peer dependency conflict',
    headline,
    description,
    line: eresolveLine,
    excerpt: lines[(eresolveLine || 1) - 1],
    failedCommand: lastCommand(lines) || 'npm install',
    failedPhase: findLine(lines, /Install Dependencies/i) ? 'Install Dependencies' : null,
    conflict: {
      package: pkgMatch?.[1] || requiredBy,
      installed: installedPkg,
      installedFrom,
      requiredBy,
      requiredRange: requiredRange || null,
      wouldInstall,
    },
    details: [
      installedPkg && { label: 'Installed', value: `${installedPkg} (${installedFrom})` },
      requiredBy && { label: 'Required by', value: `${requiredBy}${requiredRange ? ` needs ${requiredRange}` : ''}` },
      wouldInstall && { label: 'Would install', value: wouldInstall },
    ].filter(Boolean),
    resolution,
    investigation: [
      `Compare ${installedName} in package.json with ${requiredBy || 'peer'} requirements`,
      'Reproduce locally with the same Node version as the deploy server',
      'Commit lockfile after install succeeds',
    ],
  });
}

function parsePackageManagerError(text, lines) {
  const pm = packageManager(text);
  const cmd = lastCommand(lines) || `${pm} install`;

  // Yarn classic / berry
  const yarnPeer = text.match(/error\s+(.+?):?\s+The engine "node" is incompatible with this module|YN0000|YN0002|YN0060|YN0086/i);
  const yarnError = findLine(lines, /(?:error|YN\d{4})\s+.+/i);
  if (/\byarn\b/i.test(text) && (/YN0002|YN0060|doesn't provide|peer dependency/i.test(text))) {
    const peerLine = findLine(lines, /doesn't provide|peer dependency|YN0002|YN0060/i);
    const headline = `Yarn install failed: peer dependency / package resolution conflict`;
    return makeIssue({
      type: 'yarn-peer',
      categoryId: 'npm-peer-deps',
      category: 'Yarn peer dependency conflict',
      headline,
      description: (peerLine || 'Yarn could not satisfy peer dependency requirements.').slice(0, 300),
      line: lineNo(lines, (l) => /YN0002|YN0060|doesn't provide|peer dependency/i.test(l)),
      excerpt: peerLine || yarnError,
      failedCommand: cmd,
      failedPhase: 'Install Dependencies',
      details: [
        { label: 'Package manager', value: 'yarn' },
        peerLine && { label: 'Signal', value: peerLine.slice(0, 200) },
      ].filter(Boolean),
      resolution: [
        'Align package versions in package.json so peers match (preferred).',
        'For Yarn Berry: check packageExtensions in .yarnrc.yml if a package declares incorrect peers.',
        'Reproduce with yarn install locally, commit yarn.lock, redeploy.',
      ],
      investigation: ['Inspect the YN0002 / peer lines', 'Compare lockfile vs package.json ranges'],
    });
  }

  if (/\byarn\b/i.test(text) && (/error An unexpected error occurred|Couldn't find package|ENOENT|network timeout|ENOTFOUND/i.test(text) || yarnPeer)) {
    const errLine = findLine(lines, /error\s|ENOENT|Couldn't find package|ENOTFOUND|network timeout/i);
    const missing = errLine?.match(/Couldn't find package ["']?([^"'\s]+)/i)?.[1];
    return makeIssue({
      type: 'yarn-error',
      categoryId: missing ? 'module' : 'network',
      category: missing ? 'Yarn missing package' : 'Yarn install failure',
      headline: missing ? `Yarn failed: package "${missing}" could not be found` : 'Yarn install / script failed',
      description: (errLine || 'Yarn reported an error during install or script execution.').slice(0, 300),
      line: lineNo(lines, (l) => /error\s|Couldn't find package|ENOENT|ENOTFOUND/i.test(l)),
      excerpt: errLine,
      failedCommand: cmd,
      details: [
        { label: 'Package manager', value: 'yarn' },
        missing && { label: 'Missing package', value: missing },
      ].filter(Boolean),
      resolution: missing
        ? [`Add "${missing}" to package.json or fix the typo / registry scope.`, 'Clear yarn cache if a private package fails to resolve.', 'Verify registry auth (NPM_TOKEN) for private packages.']
        : ['Re-run yarn with the same Node version', 'Check network / registry access', 'Inspect the first yarn error line for the exact cause'],
      investigation: ['Reproduce with yarn install --check-cache', 'Compare with last successful CI run'],
    });
  }

  // pnpm
  if (/\bpnpm\b|ERR_PNPM/i.test(text)) {
    const pnpmLine = findLine(lines, /ERR_PNPM|ERESOLVE|peer dependency|does not satisfy/i);
    const code = text.match(/ERR_PNPM_[A-Z0-9_]+/)?.[0];
    const peer = /peer|ERESOLVE|does not satisfy/i.test(text);
    return makeIssue({
      type: 'pnpm-error',
      categoryId: peer ? 'npm-peer-deps' : 'module',
      category: peer ? 'pnpm peer dependency conflict' : 'pnpm install failure',
      headline: peer
        ? 'pnpm install failed: peer dependency resolution conflict'
        : `pnpm failed${code ? ` (${code})` : ''}`,
      description: (pnpmLine || 'pnpm could not complete install or script.').slice(0, 300),
      line: lineNo(lines, (l) => /ERR_PNPM|peer dependency|does not satisfy/i.test(l)),
      excerpt: pnpmLine,
      failedCommand: cmd,
      details: [
        { label: 'Package manager', value: 'pnpm' },
        code && { label: 'Error code', value: code },
      ].filter(Boolean),
      resolution: peer
        ? [
          'Update package.json so peer requirements match (preferred).',
          'Temporary: set packageManagerStrictPeerDependencies=false or use pnpm.peerDependencyRules — prefer fixing versions.',
          'Commit pnpm-lock.yaml after a clean install.',
        ]
        : [
          'Run pnpm install locally with the same Node version',
          'Verify store / cache is not corrupt (pnpm store prune)',
          'Confirm private registry credentials if packages fail to download',
        ],
      investigation: ['Read the first ERR_PNPM line', 'Compare lockfile with package.json'],
    });
  }

  // npm error codes (non-ERESOLVE)
  const npmCode = text.match(/npm error code\s+(E[A-Z0-9]+)/i)?.[1]
    || text.match(/\bnpm ERR! code\s+(E[A-Z0-9]+)/i)?.[1];
  if (!npmCode && !/npm error|npm ERR!/i.test(text)) return null;
  if (/ERESOLVE/i.test(text)) return null; // handled above

  const codeHandlers = {
    EACCES: {
      categoryId: 'permission',
      headline: 'npm failed: permission denied (EACCES)',
      description: 'npm could not write to a directory — usually node_modules, a global prefix, or cache ownership.',
      resolution: [
        'Do not use sudo with npm on deploy servers; fix directory ownership instead.',
        'Ensure the app user owns the project directory and npm cache.',
        'Clear npm cache if it is root-owned: npm cache clean --force (as the correct user).',
      ],
    },
    ENOENT: {
      categoryId: 'module',
      headline: 'npm failed: file or directory not found (ENOENT)',
      description: 'A required path (package, script, or lockfile) is missing.',
      resolution: [
        'Confirm package.json / lockfile exists in the deploy path',
        'Verify the failing path in the ENOENT line exists on the server',
        'Re-clone or re-sync the app files if the deploy tree is incomplete',
      ],
    },
    ENOTFOUND: {
      categoryId: 'network',
      headline: 'npm failed: host not found (ENOTFOUND)',
      description: 'DNS failed while reaching the registry or a package host.',
      resolution: [
        'Check DNS / outbound network from the server',
        'Verify registry URL in .npmrc',
        'Retry later if the registry had a transient outage',
      ],
    },
    ETIMEDOUT: {
      categoryId: 'timeout',
      headline: 'npm failed: network timeout (ETIMEDOUT)',
      description: 'Connecting to the package registry timed out.',
      resolution: [
        'Retry the install',
        'Check firewall / proxy settings for registry.npmjs.org',
        'Use a closer mirror or increase network timeout if corporate proxy is slow',
      ],
    },
    ECONNREFUSED: {
      categoryId: 'network',
      headline: 'npm failed: connection refused (ECONNREFUSED)',
      description: 'A network service (registry, proxy, or local cache) refused the connection.',
      resolution: [
        'Verify registry host is reachable',
        'Check proxy / VPN settings',
        'Confirm no local offline-mirror host is misconfigured',
      ],
    },
    E401: {
      categoryId: 'permission',
      headline: 'npm failed: unauthorized (E401)',
      description: 'Registry authentication failed — token missing, expired, or wrong scope.',
      resolution: [
        'Refresh NPM_TOKEN / registry credentials in CI or deploy secrets',
        'Confirm .npmrc auth lines for private scopes',
        'Re-login with npm login if using interactive auth',
      ],
    },
    E403: {
      categoryId: 'permission',
      headline: 'npm failed: forbidden (E403)',
      description: 'Registry rejected the request — package access or 2FA / publish rights.',
      resolution: [
        'Confirm the CI token has read access to private packages',
        'Check org package permissions',
        'Verify you are not blocked by 403 on a specific package name',
      ],
    },
    ETARGET: {
      categoryId: 'module',
      headline: 'npm failed: no matching version (ETARGET)',
      description: 'No package version matches the range in package.json.',
      resolution: [
        'Open package.json and fix the version range that cannot be satisfied',
        'Confirm the package still publishes that version on the registry',
        'Update lockfile after correcting the range',
      ],
    },
    ENGINE: {
      categoryId: 'build',
      headline: 'npm failed: Node engine requirement not met (ENGINE)',
      description: 'A dependency requires a different Node.js version than the runtime in use.',
      resolution: [
        'Align Cloudways / CI Node version with package.json engines.node',
        'Or loosen engines (only if the package truly supports your Node version)',
        'Re-run install after switching Node',
      ],
    },
    ELIFECYCLE: {
      categoryId: 'build',
      headline: 'npm failed: lifecycle script error (ELIFECYCLE)',
      description: 'A package.json script (install/build/postinstall) exited with an error.',
      resolution: [
        'Scroll to the script output above the ELIFECYCLE line — that is the real failure',
        'Run the failing script locally (e.g. npm run build)',
        'Fix the compile/runtime error, then redeploy',
      ],
    },
  };

  const handler = codeHandlers[npmCode] || {
    categoryId: 'module',
    headline: `npm failed${npmCode ? ` (${npmCode})` : ''}`,
    description: (findLine(lines, /npm error|npm ERR!/i) || 'npm reported an error.').slice(0, 300),
    resolution: [
      'Read the first npm error line for the concrete message',
      'Reproduce with the same Node/npm version locally',
      'Fix package.json / environment, commit lockfile, redeploy',
    ],
  };

  const errLine = findLine(lines, /npm error|npm ERR!/i);
  const missingMod = text.match(/Cannot find module ['"]([^'"]+)['"]/i)?.[1]
    || text.match(/missing script:\s*(\S+)/i)?.[1];

  if (/missing script/i.test(text)) {
    const script = text.match(/missing script:\s*(\S+)/i)?.[1];
    return makeIssue({
      type: 'npm-missing-script',
      categoryId: 'module',
      category: 'Missing npm script',
      headline: `npm failed: missing script "${script || 'unknown'}"`,
      description: `package.json has no "${script}" script, but the deploy/start command tried to run it.`,
      line: lineNo(lines, (l) => /missing script/i.test(l)),
      excerpt: errLine,
      failedCommand: cmd,
      details: [
        { label: 'Package manager', value: pm },
        { label: 'Missing script', value: script || 'unknown' },
      ],
      resolution: [
        `Add a "${script}" script to package.json, or change the deploy start/build command to an existing script.`,
        'Confirm Application Settings → Start / Build command on Cloudways match package.json.',
      ],
      investigation: ['List scripts: npm run', 'Compare deploy settings with package.json'],
    });
  }

  if (missingMod && /Cannot find module/i.test(text)) {
    return makeIssue({
      type: 'npm-missing-module',
      categoryId: 'module',
      category: 'Module not found',
      headline: `Runtime/build failed: cannot find module "${missingMod}"`,
      description: `Node tried to load "${missingMod}" but it is missing from node_modules or the import path is wrong.`,
      line: lineNo(lines, (l) => /Cannot find module/i.test(l)),
      excerpt: findLine(lines, /Cannot find module/i),
      failedCommand: cmd,
      details: [
        { label: 'Missing module', value: missingMod },
        { label: 'Package manager', value: pm },
      ],
      resolution: [
        `Install the dependency: ${pm} add ${missingMod} (or fix the import path if it is a local file).`,
        'Delete node_modules and reinstall if the lockfile is inconsistent.',
        'Ensure the package is listed under dependencies (not only devDependencies) if needed at runtime.',
      ],
      investigation: ['Verify package.json lists the module', 'Check NODE_PATH / imports'],
    });
  }

  return makeIssue({
    type: `npm-${(npmCode || 'error').toLowerCase()}`,
    categoryId: handler.categoryId,
    category: `npm ${npmCode || 'error'}`,
    headline: handler.headline,
    description: handler.description,
    line: lineNo(lines, (l) => /npm error code|npm ERR! code|npm error|npm ERR!/i.test(l)),
    excerpt: errLine,
    failedCommand: cmd,
    details: [
      { label: 'Package manager', value: pm },
      npmCode && { label: 'Error code', value: npmCode },
      errLine && { label: 'Log signal', value: errLine.slice(0, 200) },
    ].filter(Boolean),
    resolution: handler.resolution,
    investigation: investigationDefaults(handler.categoryId),
  });
}

function investigationDefaults(categoryId) {
  const map = {
    'npm-peer-deps': ['Align peer versions in package.json', 'Reinstall cleanly and commit lockfile'],
    module: ['Clean install node_modules', 'Verify package.json and lockfile'],
    network: ['Check DNS, firewall, and registry reachability'],
    permission: ['Verify credentials and file ownership'],
    memory: ['Raise Node heap or reduce parallel workers'],
    build: ['Reproduce the build locally with the same Node version'],
    database: ['Verify DB credentials and connectivity'],
    port: ['Free the port or change PORT'],
    timeout: ['Increase timeouts or check upstream latency'],
    docker: ['Inspect docker logs / Dockerfile steps'],
    ssl: ['Check certificate validity and chain'],
    ansible: ['Re-run failing task with -vvv'],
    jenkins: ['Open the failing stage console log'],
    ci: ['Compare with last green pipeline'],
  };
  return map[categoryId] || ['Reproduce the failing command locally', 'Compare with the last successful run'];
}

// --- Ansible --------------------------------------------------------------

function parseAnsibleStructured(text, lines) {
  if (!/ansible|PLAY \[|TASK \[|PLAY RECAP/i.test(text)) return null;

  const failedTask = findLine(lines, /TASK\s+\[.+?\]\s+\*\*\*\s+FAILED/i);
  const fatal = findLine(lines, /fatal:\s*\[[^\]]+\]:\s*FAILED/i);
  const recap = findLine(lines, /failed=[1-9]\d*/i);
  const unreachable = findLine(lines, /unreachable=[1-9]\d*/i);

  if (!failedTask && !fatal && !recap && !unreachable) return null;

  const taskName = failedTask?.match(/TASK\s+\[(.+?)\]/)?.[1]
    || findLine(lines, /TASK\s+\[.+?\]/)?.match(/TASK\s+\[(.+?)\]/)?.[1]
    || 'unknown task';
  const host = fatal?.match(/fatal:\s*\[([^\]]+)\]/)?.[1] || null;

  let msg = '';
  if (fatal) {
    const raw = fatal.match(/FAILED!?\s*=>\s*(.+)/i)?.[1] || '';
    try {
      const parsed = JSON.parse(raw);
      msg = parsed.msg || parsed.stderr || parsed.stdout || raw;
    } catch {
      const msgM = raw.match(/['"]msg['"]\s*:\s*['"]([^'"]+)['"]/);
      msg = msgM?.[1] || raw;
    }
  }
  if (!msg) {
    const msgLine = findLine(lines, /['"]msg['"]\s*:\s*['"]/);
    msg = msgLine?.match(/['"]msg['"]\s*:\s*['"]([^'"]+)/)?.[1] || '';
  }

  const failedCount = [...text.matchAll(/failed=(\d+)/gi)].map((m) => Number(m[1])).find((n) => n > 0);
  const unreachableCount = [...text.matchAll(/unreachable=(\d+)/gi)].map((m) => Number(m[1])).find((n) => n > 0);

  const headline = unreachableCount
    ? `Ansible failed: ${unreachableCount} host(s) unreachable${host ? ` (e.g. ${host})` : ''}`
    : `Ansible failed: task "${taskName}"${host ? ` on ${host}` : ''}`;

  const description = msg
    ? `Task "${taskName}" failed${host ? ` on host ${host}` : ''}: ${String(msg).slice(0, 280)}`
    : `Playbook failed${failedCount ? ` with failed=${failedCount}` : ''}. Open the TASK [...] *** FAILED block for module output.`;

  return makeIssue({
    type: 'ansible-task',
    categoryId: 'ansible',
    category: 'Ansible task failure',
    headline,
    description,
    line: lineNo(lines, (l) => /TASK\s+\[.+?\]\s+\*\*\*\s+FAILED|fatal:\s*\[/i.test(l)),
    excerpt: fatal || failedTask || recap,
    failedPhase: taskName,
    failedCommand: 'ansible-playbook',
    details: [
      { label: 'Failed task', value: taskName },
      host && { label: 'Host', value: host },
      failedCount && { label: 'PLAY RECAP failed', value: String(failedCount) },
      unreachableCount && { label: 'Unreachable', value: String(unreachableCount) },
      msg && { label: 'Module message', value: String(msg).slice(0, 240) },
    ].filter(Boolean),
    resolution: unreachableCount
      ? [
        'Verify SSH connectivity, inventory hostnames, and network access to the target',
        'Confirm ansible_user / SSH keys / become passwords',
        'Re-run with -vvv targeting the unreachable host',
      ]
      : [
        `Inspect playbook task "${taskName}" arguments and module response`,
        'Re-run ansible-playbook with -vvv --start-at-task for this task',
        'Validate target paths, packages, and sudo/become permissions on the host',
      ],
    investigation: [
      'Scroll to the first TASK [...] *** FAILED *** above PLAY RECAP',
      'Check host facts and variables used by the task',
    ],
  });
}

// --- Docker ---------------------------------------------------------------

function parseDockerStructured(text, lines) {
  if (!/docker|Dockerfile|containerd|OCI runtime|container exited|ERROR \[.*\]/i.test(text)) return null;

  const pullFail = findLine(lines, /pull access denied|manifest unknown|not found: manifest|unauthorized: authentication required/i);
  const buildFail = findLine(lines, /ERROR \[.*\]|failed to solve|failed to compute cache key|executor failed/i);
  const copyFail = findLine(lines, /COPY failed|failed to calculate checksum|"\/[^"]+": not found/i);
  const exited = findLine(lines, /container .+ exited with code|Exited \([1-9]\d*\)|OCI runtime.*error/i);
  const noSpace = findLine(lines, /no space left on device|ENOSPC/i);

  if (!pullFail && !buildFail && !copyFail && !exited && !noSpace) {
    // docker mentioned but no clear failure signature — let generic handle
    if (!/error|failed|FATAL/i.test(text)) return null;
  }

  if (noSpace) {
    return makeIssue({
      type: 'docker-disk',
      categoryId: 'docker',
      category: 'Docker disk space',
      headline: 'Docker failed: no space left on device',
      description: 'The host disk (or Docker volume) is full, so image build/pull/run cannot continue.',
      line: lineNo(lines, (l) => /no space left|ENOSPC/i.test(l)),
      excerpt: noSpace,
      details: [{ label: 'Signal', value: noSpace.slice(0, 200) }],
      resolution: [
        'Free disk: docker system prune -a (careful on shared hosts)',
        'Remove unused images/volumes',
        'Increase host disk or move Docker root if needed',
      ],
      investigation: ['df -h', 'docker system df'],
    });
  }

  if (pullFail) {
    const image = text.match(/(?:pulling|from)\s+(\S+\/\S+:\S+|\S+:\S+)/i)?.[1];
    return makeIssue({
      type: 'docker-pull',
      categoryId: 'docker',
      category: 'Docker image pull failure',
      headline: image ? `Docker failed to pull image "${image}"` : 'Docker failed to pull an image',
      description: pullFail.slice(0, 300),
      line: lineNo(lines, (l) => /pull access denied|manifest unknown|unauthorized/i.test(l)),
      excerpt: pullFail,
      details: [
        image && { label: 'Image', value: image },
        { label: 'Signal', value: pullFail.slice(0, 200) },
      ].filter(Boolean),
      resolution: [
        'Verify image name and tag exist in the registry',
        'Login to the private registry (docker login) with valid credentials',
        'Confirm CI secrets for registry auth are set',
      ],
      investigation: ['docker pull <image> manually', 'Check registry permissions'],
    });
  }

  if (copyFail || /COPY failed|failed to calculate checksum/i.test(text)) {
    return makeIssue({
      type: 'docker-copy',
      categoryId: 'docker',
      category: 'Docker COPY failure',
      headline: 'Docker build failed: COPY could not find a source file',
      description: (copyFail || 'A COPY/ADD instruction referenced a path that is not in the build context.').slice(0, 300),
      line: lineNo(lines, (l) => /COPY failed|failed to calculate checksum|not found/i.test(l)),
      excerpt: copyFail || buildFail,
      details: [{ label: 'Signal', value: (copyFail || buildFail || '').slice(0, 200) }],
      resolution: [
        'Confirm the file exists relative to the Docker build context',
        'Check .dockerignore is not excluding the needed path',
        'Fix the COPY path in the Dockerfile and rebuild',
      ],
      investigation: ['Inspect Dockerfile COPY lines', 'List build context files'],
    });
  }

  if (exited) {
    const code = exited.match(/exited with code[^\d]*(\d+)|Exited \((\d+)\)/i);
    const exit = code?.[1] || code?.[2] || null;
    return makeIssue({
      type: 'docker-exit',
      categoryId: 'docker',
      category: 'Container exit',
      headline: exit ? `Container exited with code ${exit}` : 'Container exited with a non-zero status',
      description: 'The container process stopped unexpectedly. Application logs inside the container usually show the real error.',
      line: lineNo(lines, (l) => /exited with code|Exited \(|OCI runtime/i.test(l)),
      excerpt: exited,
      details: [
        exit && { label: 'Exit code', value: exit },
        { label: 'Signal', value: exited.slice(0, 200) },
      ].filter(Boolean),
      resolution: [
        'Run docker logs <container> (or kubectl logs) for the app error',
        'Verify CMD/ENTRYPOINT, env vars, and mounted config',
        'Reproduce locally with the same image tag',
      ],
      investigation: ['docker inspect for OOMKilled / State', 'Check healthcheck failures'],
    });
  }

  if (buildFail) {
    const step = buildFail.match(/ERROR\s+\[([^\]]+)\]/)?.[1];
    return makeIssue({
      type: 'docker-build',
      categoryId: 'docker',
      category: 'Docker build failure',
      headline: step ? `Docker build failed at step [${step}]` : 'Docker build failed',
      description: buildFail.slice(0, 300),
      line: lineNo(lines, (l) => /ERROR \[|failed to solve|executor failed/i.test(l)),
      excerpt: buildFail,
      failedPhase: step || 'docker build',
      details: [
        step && { label: 'Build step', value: step },
        { label: 'Signal', value: buildFail.slice(0, 200) },
      ].filter(Boolean),
      resolution: [
        'Open the Dockerfile instruction for the failing step',
        'Reproduce: docker build --progress=plain .',
        'Fix the RUN/COPY command that exited non-zero',
      ],
      investigation: ['Scroll to the first ERROR [stage] line', 'Check base image and build args'],
    });
  }

  return null;
}

// --- Jenkins / CI ---------------------------------------------------------

function parseJenkinsStructured(text, lines) {
  const isJenkins = /jenkins|hudson\.|Finished:\s*(FAILURE|ABORTED|UNSTABLE)|Started by|Building in workspace|\[Pipeline\]/i.test(text);
  const isGha = /##\[error\]|Error: Process completed with exit code|github actions/i.test(text);
  const isGitlab = /ERROR: Job failed|section_end:|CI_JOB_|Uploading artifacts.*failed/i.test(text);

  if (!isJenkins && !isGha && !isGitlab) return null;

  if (isJenkins) {
    const finished = findLine(lines, /Finished:\s*(FAILURE|ABORTED|UNSTABLE)/i);
    const status = finished?.match(/Finished:\s*(\w+)/i)?.[1] || 'FAILURE';
    const stage = findLine(lines, /stage\s*\(\s*['"]([^'"]+)['"]/i)
      || findLine(lines, /\( ([A-Za-z][^)]*) \)/);
    let stageName = text.match(/stage\s*\(\s*['"]([^'"]+)['"]/i)?.[1] || null;
    if (!stageName) {
      const paren = findLine(lines, /\{\s*\(\s*([A-Za-z][^)]*)\s*\)/);
      stageName = paren?.match(/\{\s*\(\s*([A-Za-z][^)]*)\s*\)/)?.[1]?.trim() || null;
    }
    const err = findLine(lines, /ERROR:|error:|Exception:|script returned exit code|Build step .* marked build as failure/i);
    const exit = text.match(/script returned exit code\s+(\d+)/i)?.[1]
      || text.match(/exit code\s+(\d+)/i)?.[1];

    if (!finished && !err && status === 'FAILURE' && !/FAILURE|failed/i.test(text)) return null;

    return makeIssue({
      type: 'jenkins-failure',
      categoryId: 'jenkins',
      category: 'Jenkins build failure',
      headline: stageName
        ? `Jenkins ${status}: stage "${stageName}" failed`
        : `Jenkins build ${status}`,
      description: (err || finished || `Pipeline finished with ${status}.`).slice(0, 300),
      line: lineNo(lines, (l) => /ERROR:|Finished:\s*FAILURE|script returned exit code/i.test(l)),
      excerpt: err || finished,
      failedPhase: stageName || 'Jenkins pipeline',
      details: [
        { label: 'Result', value: status },
        stageName && { label: 'Stage', value: stageName },
        exit && { label: 'Exit code', value: exit },
        err && { label: 'Error signal', value: err.slice(0, 200) },
      ].filter(Boolean),
      resolution: [
        'Open the failing stage console output and fix the command that returned non-zero',
        'Reproduce the stage command on an agent with the same tools/Node/Docker versions',
        'Check Jenkins credentials / agent labels if the stage never started',
      ],
      investigation: [
        'Identify the first ERROR: line above Finished: FAILURE',
        'Compare with the last green build for the same branch',
      ],
    });
  }

  if (isGha) {
    const err = findLine(lines, /##\[error\]|Process completed with exit code/i);
    const code = text.match(/exit code\s+(\d+)/i)?.[1];
    const step = findLine(lines, /##\[group\]|Run .+/)?.replace(/##\[group\]\s*/, '');
    return makeIssue({
      type: 'gha-failure',
      categoryId: 'ci',
      category: 'GitHub Actions failure',
      headline: code ? `GitHub Actions failed (exit code ${code})` : 'GitHub Actions job failed',
      description: (err || 'A workflow step exited with a non-zero status.').slice(0, 300),
      line: lineNo(lines, (l) => /##\[error\]|Process completed with exit code/i.test(l)),
      excerpt: err,
      failedPhase: step || 'workflow step',
      details: [
        code && { label: 'Exit code', value: code },
        step && { label: 'Near step', value: step.slice(0, 120) },
      ].filter(Boolean),
      resolution: [
        'Open the failed step log in the Actions UI',
        'Reproduce the step command locally',
        'Fix secrets, versions, or the failing script',
      ],
      investigation: ['Search for ##[error]', 'Check matrix OS / Node version'],
    });
  }

  // GitLab CI
  const err = findLine(lines, /ERROR: Job failed|script_failure|exit code/i);
  const code = text.match(/exit code\s+(\d+)/i)?.[1];
  return makeIssue({
    type: 'gitlab-failure',
    categoryId: 'ci',
    category: 'GitLab CI failure',
    headline: code ? `GitLab CI job failed (exit code ${code})` : 'GitLab CI job failed',
    description: (err || 'The CI job script exited unsuccessfully.').slice(0, 300),
    line: lineNo(lines, (l) => /ERROR: Job failed|script_failure/i.test(l)),
    excerpt: err,
    details: [
      code && { label: 'Exit code', value: code },
      err && { label: 'Signal', value: err.slice(0, 200) },
    ].filter(Boolean),
    resolution: [
      'Inspect the job log around the first error',
      'Reproduce the job script locally',
      'Verify CI variables and runner tags',
    ],
    investigation: ['Check before_script / script sections', 'Compare with last green pipeline'],
  });
}

// --- Runtime / generic structured ----------------------------------------

function parseRuntimeStructured(text, lines) {
  const oom = findLine(lines, /heap out of memory|JavaScript heap|ENOMEM|out of memory|Killed/i);
  if (oom) {
    return makeIssue({
      type: 'oom',
      categoryId: 'memory',
      category: 'Out of memory',
      headline: 'Process ran out of memory (OOM)',
      description: 'The Node/process heap or host RAM was exhausted during install, build, or runtime.',
      line: lineNo(lines, (l) => /heap out of memory|ENOMEM|out of memory|Killed/i.test(l)),
      excerpt: oom,
      details: [{ label: 'Signal', value: oom.slice(0, 200) }],
      resolution: [
        'Increase heap: NODE_OPTIONS=--max-old-space-size=4096 (or higher)',
        'Reduce parallel build workers',
        'Upgrade server RAM if host OOM-killer sent SIGKILL',
      ],
      investigation: ['Check if exit was 137 (SIGKILL)', 'Profile peak memory on local build'],
    });
  }

  const port = findLine(lines, /EADDRINUSE|address already in use/i);
  if (port) {
    const p = text.match(/:(\d{2,5})\b/)?.[1];
    return makeIssue({
      type: 'port-in-use',
      categoryId: 'port',
      category: 'Port already in use',
      headline: p ? `Port ${p} is already in use` : 'Application port is already in use',
      description: 'Another process is bound to the same port, so the app cannot listen.',
      line: lineNo(lines, (l) => /EADDRINUSE|address already in use/i.test(l)),
      excerpt: port,
      details: [
        p && { label: 'Port', value: p },
        { label: 'Signal', value: port.slice(0, 200) },
      ].filter(Boolean),
      resolution: [
        p ? `Find and stop the process: lsof -i :${p}` : 'Find the process holding the port (lsof / ss)',
        'Or set a different PORT in environment config',
        'Ensure only one PM2/app instance is started',
      ],
      investigation: ['pm2 list / systemctl status', 'Check leftover node processes'],
    });
  }

  const ssl = findLine(lines, /CERT_HAS_EXPIRED|UNABLE_TO_VERIFY|self signed certificate|SSL routines|certificate verify failed/i);
  if (ssl) {
    return makeIssue({
      type: 'ssl',
      categoryId: 'ssl',
      category: 'SSL / TLS failure',
      headline: 'SSL/TLS certificate or verification failed',
      description: ssl.slice(0, 300),
      line: lineNo(lines, (l) => /CERT_HAS_EXPIRED|UNABLE_TO_VERIFY|self signed|certificate/i.test(l)),
      excerpt: ssl,
      details: [{ label: 'Signal', value: ssl.slice(0, 200) }],
      resolution: [
        'Renew or reinstall the TLS certificate',
        'Verify full chain / intermediate certs are installed',
        'Confirm system clock is correct (skew breaks TLS)',
      ],
      investigation: ['openssl s_client -connect host:443', 'Check CA bundle'],
    });
  }

  const db = findLine(lines, /ECONNREFUSED.*(?:5432|3306|27017)|SequelizeConnectionError|MongoNetworkError|password authentication failed|SQLSTATE|Too many connections/i);
  if (db) {
    return makeIssue({
      type: 'database',
      categoryId: 'database',
      category: 'Database connection failure',
      headline: 'Database connection / query failed',
      description: db.slice(0, 300),
      line: lineNo(lines, (l) => /ECONNREFUSED|Sequelize|MongoNetwork|authentication failed|SQLSTATE|Too many connections/i.test(l)),
      excerpt: db,
      details: [{ label: 'Signal', value: db.slice(0, 200) }],
      resolution: [
        'Verify DB host, port, username, password, and database name',
        'Confirm the app server can reach the DB (firewall / security group)',
        'Check migrations and connection pool limits',
      ],
      investigation: ['Test connectivity with psql/mysql client', 'Review recent DB config changes'],
    });
  }

  const mod = findLine(lines, /Cannot find module|ERR_MODULE_NOT_FOUND|Module not found/i);
  if (mod) {
    const name = mod.match(/Cannot find module ['"]([^'"]+)['"]/i)?.[1]
      || mod.match(/Module not found:.*(Error: )?Can't resolve ['"]([^'"]+)['"]/i)?.[2];
    return makeIssue({
      type: 'module-not-found',
      categoryId: 'module',
      category: 'Module not found',
      headline: name ? `Cannot find module "${name}"` : 'Required module/file was not found',
      description: mod.slice(0, 300),
      line: lineNo(lines, (l) => /Cannot find module|ERR_MODULE_NOT_FOUND|Module not found/i.test(l)),
      excerpt: mod,
      details: [
        name && { label: 'Missing', value: name },
        { label: 'Signal', value: mod.slice(0, 200) },
      ].filter(Boolean),
      resolution: [
        name ? `Install or fix import for "${name}"` : 'Fix the missing import / file path',
        'Clean reinstall node_modules if dependency should already exist',
        'Ensure production install includes required dependencies',
      ],
      investigation: ['Check package.json and import path', 'Verify deploy sync includes the file'],
    });
  }

  return null;
}

function parseGenericStructured(text, lines, ctx = {}) {
  const { errors = [], exitCode = null, failedPhase = null } = ctx;
  const first = errors[0];
  if (!first && (exitCode === null || exitCode === 0) && !failedPhase) return null;

  const signal = first?.text || findLine(lines, /\b(error|failed|fatal|exception)\b/i);
  if (!signal && exitCode === null) return null;

  const category = first?.category || 'General failure';
  const categoryId = first?.categoryId || 'unknown';
  const exact = (signal || '').replace(/^\[stderr\]\s*/i, '').slice(0, 240);
  const phase = failedPhase?.phase || null;
  const cmd = lastCommand(lines);

  const headline = phase
    ? `Failure during "${phase}": ${exact.slice(0, 120) || `exit code ${exitCode}`}`
    : (exact ? exact.slice(0, 140) : `Process failed with exit code ${exitCode}`);

  const description = [
    exact && `Primary signal: ${exact}`,
    exitCode !== null && exitCode !== 0 && `Process exited with code ${exitCode}.`,
    phase && `Likely failed in phase "${phase}".`,
    cmd && `Last command seen: ${cmd}.`,
  ].filter(Boolean).join(' ') || 'A failure was detected but no specialized pattern matched. Use the log excerpt and recommended steps below.';

  return makeIssue({
    type: 'generic-failure',
    categoryId,
    category,
    headline,
    description,
    line: first?.line || lineNo(lines, (l) => /\b(error|failed|fatal)\b/i.test(l)),
    excerpt: signal,
    failedCommand: cmd,
    failedPhase: phase,
    details: [
      category && category !== 'General error' && { label: 'Category', value: category },
      exitCode !== null && { label: 'Exit code', value: String(exitCode) },
      phase && { label: 'Phase', value: phase },
      cmd && { label: 'Last command', value: cmd },
      exact && { label: 'Primary signal', value: exact },
    ].filter(Boolean),
    resolution: [
      'Start at the first error line (shown above) — later “error” lines are often noise',
      cmd ? `Reproduce: run \`${cmd}\` locally with the same runtime versions` : 'Reproduce the failing command locally',
      'Compare this log with the last successful deploy/build',
      'Fix the root cause, then re-run until exit code is 0',
    ],
    investigation: investigationDefaults(categoryId),
  });
}

/**
 * Try specialized parsers first; fall back to generic structured assessment.
 * Returns the primary structured issue (or null).
 */
function parseStructuredFailure(text, lines, ctx = {}) {
  const parsers = [
    parseNpmEresolve,
    parsePackageManagerError,
    parseAnsibleStructured,
    parseDockerStructured,
    parseJenkinsStructured,
    parseRuntimeStructured,
  ];

  for (const parse of parsers) {
    const issue = parse(text, lines);
    if (issue) return issue;
  }

  return parseGenericStructured(text, lines, ctx);
}

module.exports = {
  parseStructuredFailure,
  parseNpmEresolve,
  noiseSuppressForStructured,
  makeIssue,
};
