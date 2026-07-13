// QA Knowledge Hub — Cloudways KB + competitor hosting trends grouped by company.

const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const ITEMS_PER_COMPANY = 6;

const KNOWLEDGE_HUB_HOME = 'https://support.cloudways.com/en/';

const KNOWLEDGE_HUB_ARTICLES = [
  'https://support.cloudways.com/en/articles/5119539-getting-started-with-cloudways',
  'https://support.cloudways.com/en/articles/5124126-how-to-launch-server-and-add-an-application-on-the-cloudways-platform',
  'https://support.cloudways.com/en/articles/4805075-how-do-i-take-my-website-live-from-cloudways',
  'https://support.cloudways.com/en/articles/8743665-how-to-change-the-domain-name-of-your-application',
  'https://support.cloudways.com/en/articles/5128800-how-to-activate-the-dns-made-easy-add-on',
  'https://support.cloudways.com/en/articles/5120743-how-to-deploy-code-to-your-application-using-git-on-cloudways',
  'https://support.cloudways.com/en/articles/5136065-how-to-use-the-cloudways-api',
  'https://support.cloudways.com/en/articles/5126470-how-to-install-and-configure-breeze-wordpress-cache-plugin',
];

const QA_FEEDS = [
  {
    id: 'mot',
    name: 'Ministry of Testing',
    url: 'https://feeds.feedburner.com/MinistryOfTesting',
  },
];

// Competitors and peers — grouped by company with a quality angle for triage context.
const HOSTING_COMPANIES = [
  {
    id: 'cloudways',
    name: 'Cloudways',
    website: 'https://www.cloudways.com',
    category: 'Managed cloud',
    qualityFocus: 'Managed PHP/WordPress on AWS, GCP & DigitalOcean — staging, Breeze cache, monitoring, and Git deploy.',
    feedUrl: 'https://www.cloudways.com/blog/feed/',
    feedType: 'rss',
  },
  {
    id: 'vercel',
    name: 'Vercel',
    website: 'https://vercel.com',
    category: 'Frontend PaaS',
    qualityFocus: 'Edge deployments, Speed Insights, preview URLs, and zero-downtime rollouts for Jamstack apps.',
    feedUrl: 'https://vercel.com/atom',
    feedType: 'atom',
  },
  {
    id: 'hostinger',
    name: 'Hostinger',
    website: 'https://www.hostinger.com',
    category: 'Shared & cloud hosting',
    qualityFocus: 'LiteSpeed cache, hPanel UX, affordable cloud VPS, and performance tuning for SMB sites.',
    feedUrl: 'https://www.hostinger.com/tutorials/feed',
    feedType: 'rss',
  },
  {
    id: 'digitalocean',
    name: 'DigitalOcean',
    website: 'https://www.digitalocean.com',
    category: 'Cloud IaaS / PaaS',
    qualityFocus: 'App Platform, managed DBs, droplet reliability, and developer-first deploy workflows.',
    feedUrl: 'https://www.digitalocean.com/blog/rss/',
    feedType: 'atom',
  },
  {
    id: 'kinsta',
    name: 'Kinsta',
    website: 'https://kinsta.com',
    category: 'Managed WordPress',
    qualityFocus: 'Premium WP on Google Cloud — uptime SLAs, staging, CDN, and security hardening.',
    feedUrl: 'https://kinsta.com/blog/feed/',
    feedType: 'rss',
  },
  {
    id: 'wpengine',
    name: 'WP Engine',
    website: 'https://wpengine.com',
    category: 'Enterprise WordPress',
    qualityFocus: 'Enterprise WP platform — global CDN, security patches, and performance at scale.',
    feedUrl: 'https://wpengine.com/feed/',
    feedType: 'rss',
  },
  {
    id: 'railway',
    name: 'Railway',
    website: 'https://railway.app',
    category: 'App PaaS',
    qualityFocus: 'One-click deploys, built-in observability, and infra-as-code for fast iteration.',
    feedUrl: 'https://blog.railway.app/rss.xml',
    feedType: 'rss',
  },
  {
    id: 'render',
    name: 'Render',
    website: 'https://render.com',
    category: 'App PaaS',
    qualityFocus: 'Managed web services, health checks, auto-deploy from Git, and zero-downtime updates.',
    feedUrl: 'https://render.com/blog/feed.xml',
    feedType: 'atom',
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    website: 'https://www.cloudflare.com',
    category: 'CDN & edge',
    qualityFocus: 'Global CDN, DDoS protection, Workers edge compute, and web performance optimization.',
    feedUrl: 'https://blog.cloudflare.com/rss/',
    feedType: 'rss',
  },
  {
    id: 'linode',
    name: 'Akamai / Linode',
    website: 'https://www.linode.com',
    category: 'Cloud IaaS',
    qualityFocus: 'Predictable cloud VMs, network reliability, and Akamai-backed edge performance.',
    feedUrl: 'https://www.linode.com/blog/feed/',
    feedType: 'rss',
  },
  {
    id: 'aws',
    name: 'AWS',
    website: 'https://aws.amazon.com',
    category: 'Hyperscaler',
    qualityFocus: 'Scale, multi-AZ reliability, observability suite, and broad managed services.',
    feedUrl: 'https://aws.amazon.com/blogs/aws/feed/',
    feedType: 'rss',
  },
  {
    id: 'google-cloud',
    name: 'Google Cloud',
    website: 'https://cloud.google.com',
    category: 'Hyperscaler',
    qualityFocus: 'Global network, AI/ML tooling, GKE, and Cloud Run for resilient workloads.',
    feedUrl: 'https://cloudblog.withgoogle.com/rss/',
    feedType: 'rss',
  },
  {
    id: 'azure',
    name: 'Microsoft Azure',
    website: 'https://azure.microsoft.com',
    category: 'Hyperscaler',
    qualityFocus: 'Enterprise hybrid cloud, compliance, and high-availability regional pairs.',
    feedUrl: 'https://azure.microsoft.com/en-us/blog/feed/',
    feedType: 'rss',
  },
  {
    id: 'bluehost',
    name: 'Bluehost',
    website: 'https://www.bluehost.com',
    category: 'WordPress hosting',
    qualityFocus: 'Beginner-friendly WP hosting, onboarding, and bundled performance plugins.',
    feedUrl: 'https://www.bluehost.com/blog/feed/',
    feedType: 'rss',
  },
  {
    id: 'dreamhost',
    name: 'DreamHost',
    website: 'https://www.dreamhost.com',
    category: 'WordPress hosting',
    qualityFocus: 'Open-source ethos, managed WP, and SSD-backed performance for creators.',
    feedUrl: 'https://www.dreamhost.com/blog/feed/',
    feedType: 'rss',
  },
  {
    id: 'pantheon',
    name: 'Pantheon',
    website: 'https://pantheon.io',
    category: 'WebOps / WordPress',
    qualityFocus: 'Multidev workflows, Git-based deploys, and performance tooling for agency WP.',
    feedUrl: 'https://pantheon.io/blog/feed',
    feedType: 'rss',
  },
];

const QUALITY_KEYWORDS = [
  { tag: 'Performance', words: ['performance', 'speed', 'fast', 'latency', 'lighthouse', 'core web vitals', 'cache', 'cdn', 'optimize', 'lcp', 'ttfb'] },
  { tag: 'Reliability', words: ['uptime', 'sla', 'reliability', 'availability', 'resilien', 'failover', 'redundan', 'downtime', 'outage'] },
  { tag: 'Security', words: ['security', 'ssl', 'ddos', 'waf', 'vulnerab', 'patch', 'firewall', 'compliance', 'malware', 'zero trust'] },
  { tag: 'DevOps', words: ['deploy', 'ci/cd', 'pipeline', 'git', 'staging', 'rollback', 'terraform', 'kubernetes', 'docker', 'release'] },
  { tag: 'Monitoring', words: ['monitor', 'observab', 'alert', 'log', 'metric', 'apm', 'insight', 'tracing', 'dashboard'] },
  { tag: 'Testing', words: ['test', 'qa', 'quality', 'automation', 'e2e', 'regression', 'triage', 'bug'] },
];

let cache = { fetchedAt: 0, data: null };

function decodeEntities(text) {
  return String(text || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#039;/g, "'")
    .replace(/&apos;/g, "'")
    .trim();
}

function stripHtml(html) {
  return decodeEntities(html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function extractQualityTags(title, excerpt) {
  const hay = `${title} ${excerpt}`.toLowerCase();
  return QUALITY_KEYWORDS.filter((k) => k.words.some((w) => hay.includes(w))).map((k) => k.tag);
}

function limitFeedXml(xml, feedType, maxEntries = 15) {
  const tag = feedType === 'atom' ? 'entry' : 'item';
  const parts = String(xml).split(new RegExp(`(?=<${tag}[\\s>])`, 'i'));
  if (parts.length <= maxEntries + 1) return xml;
  return parts[0] + parts.slice(1, maxEntries + 1).join('');
}

function parseRssItems(xml, meta) {
  const items = [];
  const blocks = String(xml).match(/<item[\s\S]*?<\/item>/gi) || [];
  for (const block of blocks) {
    const title = decodeEntities((block.match(/<title>([\s\S]*?)<\/title>/i) || [])[1]);
    const link = decodeEntities((block.match(/<link>([\s\S]*?)<\/link>/i) || [])[1]);
    const pubDate = decodeEntities((block.match(/<pubDate>([\s\S]*?)<\/pubDate>/i) || [])[1]);
    const description = stripHtml((block.match(/<description>([\s\S]*?)<\/description>/i) || [])[1]).slice(0, 240);
    if (!title || !link) continue;
    const qualityTags = extractQualityTags(title, description);
    items.push({
      title,
      url: link,
      excerpt: description,
      publishedAt: pubDate ? new Date(pubDate).toISOString() : null,
      source: meta.name,
      companyId: meta.id,
      type: 'article',
      qualityTags,
    });
  }
  return items;
}

function parseAtomItems(xml, meta) {
  const items = [];
  const blocks = String(xml).match(/<entry[\s\S]*?<\/entry>/gi) || [];
  for (const block of blocks) {
    const title = decodeEntities((block.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]);
    let link = decodeEntities((block.match(/<link[^>]*href="([^"]+)"/i) || [])[1]);
    if (!link) link = decodeEntities((block.match(/<link>([\s\S]*?)<\/link>/i) || [])[1]);
    const pubDate = decodeEntities((block.match(/<(?:published|updated)>([\s\S]*?)<\/(?:published|updated)>/i) || [])[1]);
    const summary = stripHtml((block.match(/<(?:summary|content)[^>]*>([\s\S]*?)<\/(?:summary|content)>/i) || [])[1]).slice(0, 240);
    if (!title || !link) continue;
    const qualityTags = extractQualityTags(title, summary);
    items.push({
      title,
      url: link,
      excerpt: summary,
      publishedAt: pubDate ? new Date(pubDate).toISOString() : null,
      source: meta.name,
      companyId: meta.id,
      type: 'article',
      qualityTags,
    });
  }
  return items;
}

async function fetchText(url, timeoutMs = 14000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'LogTriage-QADigest/1.0',
        Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, text/html',
      },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

async function fetchCompanyFeed(company, attempt = 1) {
  try {
    const raw = await fetchText(company.feedUrl);
    const xml = limitFeedXml(raw, company.feedType);
    const parse = company.feedType === 'atom' ? parseAtomItems : parseRssItems;
    const items = parse(xml, company).slice(0, ITEMS_PER_COMPANY);
    if (!items.length) throw new Error('No items parsed from feed');
    return { company, items, error: null };
  } catch (err) {
    if (attempt < 2) return fetchCompanyFeed(company, attempt + 1);
    return { company, items: [], error: err.message };
  }
}

async function fetchQaFeeds() {
  const results = await Promise.all(
    QA_FEEDS.map(async (feed) => {
      try {
        const xml = await fetchText(feed.url);
        return parseRssItems(xml, feed).slice(0, 8);
      } catch (err) {
        return [{ error: true, source: feed.name, message: err.message }];
      }
    }),
  );
  return results.flat();
}

async function fetchKbArticle(url) {
  try {
    const html = await fetchText(url);
    const ogTitle = (html.match(/<meta property="og:title" content="([^"]+)"/i) || [])[1];
    const ogDesc = (html.match(/<meta property="og:description" content="([^"]+)"/i) || [])[1];
    const title = decodeEntities(ogTitle || '').replace(/\s*\|\s*Cloudways Help Center$/i, '').trim();
    if (!title) throw new Error('No title');
    const excerpt = decodeEntities(ogDesc || '').slice(0, 240);
    return {
      title,
      url,
      excerpt,
      publishedAt: null,
      source: 'Cloudways Knowledge Hub',
      type: 'kb',
      qualityTags: extractQualityTags(title, excerpt),
    };
  } catch {
    const slug = url.split('/').pop().replace(/-/g, ' ');
    return {
      title: slug,
      url,
      excerpt: 'Cloudways Help Center article',
      publishedAt: null,
      source: 'Cloudways Knowledge Hub',
      type: 'kb',
      qualityTags: [],
      fallback: true,
    };
  }
}

async function fetchKnowledgeHub() {
  const results = await Promise.all(KNOWLEDGE_HUB_ARTICLES.map((url) => fetchKbArticle(url)));
  return results.filter((r) => r.title);
}

function buildCompanySection(result) {
  const { company, items, error } = result;
  return {
    id: `company-${company.id}`,
    kind: 'company',
    title: company.name,
    category: company.category,
    website: company.website,
    qualityFocus: company.qualityFocus,
    description: company.qualityFocus,
    items,
    error,
  };
}

async function buildDigest() {
  const [companyResults, knowledgeHub, qaRaw] = await Promise.all([
    Promise.all(HOSTING_COMPANIES.map(fetchCompanyFeed)),
    fetchKnowledgeHub(),
    fetchQaFeeds(),
  ]);

  const qaItems = qaRaw.filter((i) => !i.error);
  const feedErrors = companyResults
    .filter((r) => r.error)
    .map((r) => `${r.company.name}: ${r.error}`)
    .concat(qaRaw.filter((i) => i.error).map((e) => `${e.source}: ${e.message}`));

  const companySections = companyResults
    .map(buildCompanySection)
    .sort((a, b) => {
      if (a.id === 'company-cloudways') return -1;
      if (b.id === 'company-cloudways') return 1;
      const aQ = a.items.filter((i) => i.qualityTags?.length).length;
      const bQ = b.items.filter((i) => i.qualityTags?.length).length;
      if (bQ !== aQ) return bQ - aQ;
      return a.title.localeCompare(b.title);
    });

  const companiesWithItems = companySections.filter((s) => s.items.length).length;
  const qualityTagged = companySections.reduce(
    (n, s) => n + s.items.filter((i) => i.qualityTags?.length).length,
    0,
  );

  return {
    fetchedAt: new Date().toISOString(),
    knowledgeHubHome: KNOWLEDGE_HUB_HOME,
    stats: {
      companies: HOSTING_COMPANIES.length,
      companiesWithItems,
      totalArticles: companySections.reduce((n, s) => n + s.items.length, 0),
      qualityTagged,
    },
    sections: [
      {
        id: 'competitor-trends',
        kind: 'competitor-group',
        title: 'Hosting & cloud competitor trends',
        description: 'What rivals are shipping to improve performance, reliability, security, and deploy quality — grouped by company.',
        companies: companySections,
      },
      {
        id: 'cloudways-kb',
        kind: 'kb',
        title: 'Cloudways Knowledge Hub',
        description: 'Official guides for deploy, monitoring, Git, DNS, and troubleshooting on Cloudways.',
        hubUrl: KNOWLEDGE_HUB_HOME,
        items: knowledgeHub,
      },
      {
        id: 'qa',
        kind: 'qa',
        title: 'QA & testing community',
        description: 'Broader quality engineering news and testing practice trends.',
        items: qaItems,
      },
    ],
    errors: feedErrors,
  };
}

async function getDigest({ refresh = false } = {}) {
  const now = Date.now();
  if (!refresh && cache.data && now - cache.fetchedAt < CACHE_TTL_MS) {
    return { ...cache.data, cached: true };
  }
  const data = await buildDigest();
  cache = { fetchedAt: now, data };
  return { ...data, cached: false };
}

async function warmDigestCache() {
  try {
    await getDigest({ refresh: true });
    console.log('[log-triage] digest cache warmed');
  } catch (e) {
    console.warn('[log-triage] digest warmup failed:', e.message);
  }
}

module.exports = { getDigest, buildDigest, warmDigestCache };
