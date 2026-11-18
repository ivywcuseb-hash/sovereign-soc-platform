import crypto from 'node:crypto';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';

type LiveFeedFormat = 'json' | 'rss';
type LiveFeedCategory = 'CVE / Vulnerability' | 'Botnet C2 IP' | 'Security Advisory' | 'Threat Intel RSS';

interface LiveThreatFeedItem {
  id: string;
  sourceId: string;
  sourceName: string;
  category: LiveFeedCategory;
  title: string;
  indicator: string;
  indicatorKind: 'cve' | 'ip' | 'advisory' | 'domain';
  severity: 'critical' | 'high' | 'medium' | 'low';
  severityAr: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض';
  cvssScore?: number;
  publishedAt: string;
  summary: string;
  link: string;
  tags: string[];
}

const BUILTIN_THREAT_FEEDS = [
  {
    id: 'cisa_kev',
    name: 'CISA Known Exploited Vulnerabilities (KEV)',
    provider: 'U.S. CISA',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    format: 'json' as const,
    category: 'CVE / Vulnerability' as const,
  },
  {
    id: 'feodo_c2',
    name: 'Abuse.ch Feodo Tracker Botnet C2',
    provider: 'Abuse.ch',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    format: 'json' as const,
    category: 'Botnet C2 IP' as const,
  },
  {
    id: 'circl_cve',
    name: 'CIRCL Latest CVE & Advisories API',
    provider: 'CIRCL.lu',
    url: 'https://cve.circl.lu/api/last/15',
    format: 'json' as const,
    category: 'CVE / Vulnerability' as const,
  },
  {
    id: 'cisa_advisories',
    name: 'CISA Cybersecurity Advisories RSS',
    provider: 'U.S. CISA',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    format: 'rss' as const,
    category: 'Security Advisory' as const,
  },
  {
    id: 'sans_isc',
    name: 'SANS Internet Storm Center Diary RSS',
    provider: 'SANS ISC',
    url: 'https://isc.sans.edu/rssfeed_full.xml',
    format: 'rss' as const,
    category: 'Threat Intel RSS' as const,
  },
  {
    id: 'hacker_news',
    name: 'The Hacker News Threat Feed RSS',
    provider: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    format: 'rss' as const,
    category: 'Threat Intel RSS' as const,
  },
];

function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.replace(/^::ffff:/i, '');
  if (!net.isIP(clean)) return true;
  if (clean === '::1' || clean === '::' || clean.startsWith('fe80:') || clean.startsWith('fc') || clean.startsWith('fd')) {
    return true;
  }
  const parts = clean.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 10 || a === 127 || a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

async function assertSafePublicUrl(rawUrl: string): Promise<void> {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only HTTP/HTTPS URLs are permitted.');
  }
  const host = parsed.hostname.toLowerCase();
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Blocked internal hostname.');
  }
  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) throw new Error('Blocked private IP.');
    return;
  }
  const resolved = await dns.lookup(host, { all: true });
  if (!resolved.length || resolved.some((r) => isPrivateOrReservedIp(r.address))) {
    throw new Error('Blocked private DNS target.');
  }
}

function sanitizePublicUrl(raw: unknown): string {
  const str = String(raw || '').trim();
  if (!str) return '';
  try {
    const parsed = new URL(str);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.toString() : '';
  } catch {
    return '';
  }
}

function makeItemId(sourceId: string, uniqueKey: string): string {
  return crypto.createHash('sha256').update(`${sourceId}::${uniqueKey}`).digest('hex').slice(0, 16);
}

function severityToArabic(sev: LiveThreatFeedItem['severity']): LiveThreatFeedItem['severityAr'] {
  if (sev === 'critical') return 'حرج';
  if (sev === 'high') return 'مرتفع';
  if (sev === 'medium') return 'متوسط';
  return 'منخفض';
}

function normalizeIsoDate(dateStr?: string): string {
  if (!dateStr) return new Date().toISOString();
  const parsed = new Date(dateStr);
  return Number.isNaN(parsed.getTime()) ? new Date().toISOString() : parsed.toISOString();
}

function stripHtmlAndDecode(raw: string): string {
  return raw
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractXmlTag(block: string, tagName: string): string {
  const re = new RegExp(`<${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tagName}>`, 'i');
  const m = block.match(re);
  if (m) return stripHtmlAndDecode(m[1]);
  if (tagName === 'link') {
    const atomLink = block.match(/<link[^>]+href=["']([^"']+)["'][^>]*\/?>/i);
    if (atomLink) return atomLink[1].trim();
  }
  return '';
}

function inferSeverityFromText(text: string): LiveThreatFeedItem['severity'] {
  const lower = text.toLowerCase();
  if (/(zero[- ]day|0[- ]day|rce|remote code execution|actively exploited|ransomware|critical|cvss\s*9\.|cvss\s*10)/i.test(lower)) {
    return 'critical';
  }
  if (/(exploit|privilege escalation|authentication bypass|botnet|c2|backdoor|malware|apt|high severity|vulnerability)/i.test(lower)) {
    return 'high';
  }
  return 'medium';
}

async function fetchFeedText(url: string, timeoutMs = 7500): Promise<string> {
  await assertSafePublicUrl(url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'SovereignForensicEngine/2.5 (LiveThreatFeeds)',
        Accept: 'application/json, application/xml, application/rss+xml, text/xml, */*',
      },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (text.length > 4 * 1024 * 1024) return text.slice(0, 4 * 1024 * 1024);
    return text;
  } finally {
    clearTimeout(timer);
  }
}

function parseCisaKevJson(rawText: string, limit: number): LiveThreatFeedItem[] {
  const json = JSON.parse(rawText);
  const vulns: any[] = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
  const sorted = [...vulns].sort((a, b) => String(b.dateAdded || '').localeCompare(String(a.dateAdded || '')));
  return sorted.slice(0, limit).map((v) => {
    const cve = String(v.cveID || 'CVE-UNKNOWN');
    const isRansom = String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known';
    const sev: LiveThreatFeedItem['severity'] = isRansom ? 'critical' : 'high';
    return {
      id: makeItemId('cisa_kev', cve),
      sourceId: 'cisa_kev',
      sourceName: 'CISA KEV Catalog',
      category: 'CVE / Vulnerability',
      title: `${cve}: ${v.vendorProject || ''} ${v.product || ''} — ${v.vulnerabilityName || 'Known Exploited Vulnerability'}`.trim(),
      indicator: cve,
      indicatorKind: 'cve',
      severity: sev,
      severityAr: severityToArabic(sev),
      publishedAt: normalizeIsoDate(v.dateAdded),
      summary: `${v.shortDescription || ''} | إجراء المعالجة المطلوب: ${v.requiredAction || 'تحديث فوري'}`,
      link: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
      tags: [v.vendorProject || 'Vendor', v.product || 'Product', isRansom ? 'Ransomware Campaign' : 'Active Exploitation'].filter(Boolean),
    };
  });
}

function parseFeodoC2Json(rawText: string, limit: number): LiveThreatFeedItem[] {
  const arr = JSON.parse(rawText);
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, limit).map((entry: any) => {
    const ip = String(entry.ip_address || '').trim();
    const port = entry.port ? `:${entry.port}` : '';
    const malware = String(entry.malware || 'Botnet C2');
    const isOnline = String(entry.status || '').toLowerCase() === 'online';
    const sev: LiveThreatFeedItem['severity'] = isOnline ? 'critical' : 'high';
    return {
      id: makeItemId('feodo_c2', `${ip}:${entry.port || ''}`),
      sourceId: 'feodo_c2',
      sourceName: 'Abuse.ch Feodo C2',
      category: 'Botnet C2 IP',
      title: `Botnet C2 Server (${malware}): ${ip}${port}`,
      indicator: ip,
      indicatorKind: 'ip',
      severity: sev,
      severityAr: severityToArabic(sev),
      publishedAt: normalizeIsoDate(entry.last_online || entry.first_seen),
      summary: `خادم تحكم وسيطرة (C2) نشط مرتبط بعائلة ${malware} | الحالة: ${entry.status || 'online'} | الدولة: ${entry.country || 'N/A'}`,
      link: `https://feodotracker.abuse.ch/browse/host/${encodeURIComponent(ip)}/`,
      tags: [malware, entry.country || 'Unknown', `Port ${entry.port || '—'}`],
    };
  });
}

function parseCirclCveJson(rawText: string, limit: number): LiveThreatFeedItem[] {
  const arr = JSON.parse(rawText);
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, limit).map((entry: any) => {
    const cveId = String(entry.id || entry.cveMetadata?.cveId || entry.aliases?.[0] || 'CVE-ADVISORY');
    const title = String(entry.containers?.cna?.title || entry.summary?.slice(0, 120) || entry.details?.slice(0, 120) || cveId);
    const summaryText = String(entry.summary || entry.details || entry.containers?.cna?.descriptions?.[0]?.value || 'ثغرة أمنية حديثة مسجلة في CIRCL.');
    const cvssRaw =
      Number(entry.cvss) ||
      Number(entry.containers?.cna?.metrics?.[0]?.cvssV3_1?.baseScore) ||
      Number(entry.containers?.cna?.metrics?.[0]?.cvssV3_0?.baseScore) ||
      undefined;
    let sev: LiveThreatFeedItem['severity'] = inferSeverityFromText(`${title} ${summaryText}`);
    if (cvssRaw !== undefined && Number.isFinite(cvssRaw)) {
      sev = cvssRaw >= 9.0 ? 'critical' : cvssRaw >= 7.0 ? 'high' : cvssRaw >= 4.0 ? 'medium' : 'low';
    }
    return {
      id: makeItemId('circl_cve', cveId),
      sourceId: 'circl_cve',
      sourceName: 'CIRCL CVE Feed',
      category: 'CVE / Vulnerability',
      title: `${cveId}: ${title}`.slice(0, 180),
      indicator: cveId,
      indicatorKind: 'cve',
      severity: sev,
      severityAr: severityToArabic(sev),
      cvssScore: cvssRaw && Number.isFinite(cvssRaw) ? cvssRaw : undefined,
      publishedAt: normalizeIsoDate(entry.Published || entry.published || entry.modified || entry.cveMetadata?.datePublished),
      summary: summaryText.slice(0, 320),
      link: cveId.startsWith('CVE-')
        ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`
        : `https://cve.circl.lu/vuln/${encodeURIComponent(cveId)}`,
      tags: [cveId.split('-')[0] || 'CVE', cvssRaw ? `CVSS ${cvssRaw}` : 'Advisory'],
    };
  });
}

function parseRssOrAtomXml(
  rawXml: string,
  sourceId: string,
  sourceName: string,
  category: LiveFeedCategory,
  limit: number
): LiveThreatFeedItem[] {
  const headChunk = rawXml.slice(0, 320000);
  const itemMatches = headChunk.match(/<(?:item|entry)(?:\s[^>]*)?>[\s\S]*?<\/(?:item|entry)>/gi) || [];
  const items: LiveThreatFeedItem[] = [];
  for (const block of itemMatches.slice(0, limit)) {
    const title = extractXmlTag(block, 'title');
    if (!title) continue;
    const link = sanitizePublicUrl(extractXmlTag(block, 'link') || extractXmlTag(block, 'id') || '');
    const pubDate = extractXmlTag(block, 'pubDate') || extractXmlTag(block, 'published') || extractXmlTag(block, 'updated') || extractXmlTag(block, 'dc:date');
    const desc = extractXmlTag(block, 'description') || extractXmlTag(block, 'summary') || extractXmlTag(block, 'content');
    const cveMatch = `${title} ${desc}`.match(/CVE-\d{4}-\d{4,7}/i);
    const ipMatch = `${title} ${desc}`.match(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/);
    let domainHint = '';
    try {
      if (link) domainHint = new URL(link).hostname;
    } catch {
      domainHint = '';
    }
    const indicator = cveMatch ? cveMatch[0].toUpperCase() : ipMatch ? ipMatch[0] : domainHint || title.slice(0, 48);
    const sev = inferSeverityFromText(`${title} ${desc}`);
    items.push({
      id: makeItemId(sourceId, link || title),
      sourceId,
      sourceName,
      category,
      title: title.slice(0, 200),
      indicator,
      indicatorKind: cveMatch ? 'cve' : ipMatch ? 'ip' : 'advisory',
      severity: sev,
      severityAr: severityToArabic(sev),
      publishedAt: normalizeIsoDate(pubDate),
      summary: (desc || title).slice(0, 320),
      link,
      tags: [sourceName, cveMatch ? cveMatch[0].toUpperCase() : category],
    });
  }
  return items;
}

function parseGenericJsonFeed(rawText: string, sourceId: string, sourceName: string, category: LiveFeedCategory, limit: number): LiveThreatFeedItem[] {
  const parsed = JSON.parse(rawText);
  const rows: any[] = Array.isArray(parsed)
    ? parsed
    : Array.isArray(parsed?.items)
    ? parsed.items
    : Array.isArray(parsed?.vulnerabilities)
    ? parsed.vulnerabilities
    : Array.isArray(parsed?.data)
    ? parsed.data
    : [];
  return rows.slice(0, limit).map((row, idx) => {
    const title = String(row.title || row.name || row.cveID || row.id || `Feed Entry #${idx + 1}`);
    const summary = String(row.summary || row.description || row.shortDescription || JSON.stringify(row).slice(0, 220));
    const link = sanitizePublicUrl(row.url || row.link || '');
    const cveMatch = `${title} ${summary}`.match(/CVE-\d{4}-\d{4,7}/i);
    const ipVal = row.ip_address || row.ip || '';
    const indicator = String(cveMatch?.[0] || ipVal || row.indicator || title.slice(0, 48));
    const sev = inferSeverityFromText(`${title} ${summary}`);
    return {
      id: makeItemId(sourceId, `${indicator}-${idx}`),
      sourceId,
      sourceName,
      category,
      title: title.slice(0, 200),
      indicator,
      indicatorKind: cveMatch ? 'cve' : ipVal ? 'ip' : 'advisory',
      severity: sev,
      severityAr: severityToArabic(sev),
      publishedAt: normalizeIsoDate(row.publishedAt || row.published || row.dateAdded || row.created_at),
      summary: summary.slice(0, 320),
      link,
      tags: [sourceName, 'Custom JSON API'],
    };
  });
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const { enabledSources, customFeedUrls, limitPerSource } = bodyObj;
    const limit = Math.min(25, Math.max(3, typeof limitPerSource === 'number' ? limitPerSource : 10));
    const requestedIds =
      Array.isArray(enabledSources) && enabledSources.length
        ? new Set(enabledSources.slice(0, 12).map(String))
        : new Set(BUILTIN_THREAT_FEEDS.map((f) => f.id));

    const targets: Array<{
      id: string;
      name: string;
      provider: string;
      url: string;
      format: LiveFeedFormat | 'auto';
      category: LiveFeedCategory;
    }> = BUILTIN_THREAT_FEEDS.filter((f) => requestedIds.has(f.id)).map((f) => ({ ...f }));

    if (Array.isArray(customFeedUrls)) {
      for (const custom of customFeedUrls.slice(0, 5)) {
        const cleanUrl = String(custom?.url || '').trim().slice(0, 500);
        if (!cleanUrl) continue;
        let host = 'Custom Feed';
        try {
          host = new URL(cleanUrl).hostname || 'Custom Feed';
        } catch {
          continue;
        }
        targets.push({
          id: `custom_${makeItemId('custom', cleanUrl).slice(0, 8)}`,
          name: String(custom?.name || '').trim().slice(0, 80) || host,
          provider: 'Custom Feed',
          url: cleanUrl,
          format: 'auto',
          category: 'Threat Intel RSS',
        });
      }
    }

    const allItems: LiveThreatFeedItem[] = [];
    const sourceStatuses: any[] = [];

    await Promise.allSettled(
      targets.map(async (feed) => {
        const t0 = Date.now();
        const fetchedAt = new Date().toISOString();
        try {
          const rawBody = await fetchFeedText(feed.url, 7500);
          let parsedItems: LiveThreatFeedItem[] = [];
          if (feed.id === 'cisa_kev') parsedItems = parseCisaKevJson(rawBody, limit);
          else if (feed.id === 'feodo_c2') parsedItems = parseFeodoC2Json(rawBody, limit);
          else if (feed.id === 'circl_cve') parsedItems = parseCirclCveJson(rawBody, limit);
          else if (feed.format === 'rss' || rawBody.trimStart().startsWith('<')) {
            parsedItems = parseRssOrAtomXml(rawBody, feed.id, feed.name, feed.category, limit);
          } else {
            parsedItems = parseGenericJsonFeed(rawBody, feed.id, feed.name, feed.category, limit);
          }
          allItems.push(...parsedItems);
          sourceStatuses.push({
            id: feed.id,
            name: feed.name,
            provider: feed.provider,
            url: feed.url,
            format: rawBody.trimStart().startsWith('<') ? 'rss' : 'json',
            category: feed.category,
            status: 'ok',
            itemCount: parsedItems.length,
            latencyMs: Date.now() - t0,
            fetchedAt,
          });
        } catch (err: any) {
          sourceStatuses.push({
            id: feed.id,
            name: feed.name,
            provider: feed.provider,
            url: feed.url,
            format: feed.format === 'auto' ? 'rss' : feed.format,
            category: feed.category,
            status: 'error',
            itemCount: 0,
            latencyMs: Date.now() - t0,
            fetchedAt,
            error: err?.message || 'تعذر الاتصال بالمصدر.',
          });
        }
      })
    );

    const deduped = new Map<string, LiveThreatFeedItem>();
    for (const item of allItems) {
      if (!deduped.has(item.id)) deduped.set(item.id, item);
    }
    const sortedItems = Array.from(deduped.values()).sort(
      (a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime()
    );

    return res.status(200).json({
      items: sortedItems,
      sourceStatuses,
      stats: {
        totalItems: sortedItems.length,
        criticalCount: sortedItems.filter((i) => i.severity === 'critical').length,
        highCount: sortedItems.filter((i) => i.severity === 'high').length,
        cveCount: sortedItems.filter((i) => i.indicatorKind === 'cve').length,
        c2Count: sortedItems.filter((i) => i.category === 'Botnet C2 IP').length,
        advisoryCount: sortedItems.filter((i) => i.category === 'Security Advisory' || i.category === 'Threat Intel RSS').length,
        activeSourcesOk: sourceStatuses.filter((s) => s.status === 'ok').length,
        activeSourcesTotal: sourceStatuses.length,
      },
      syncedAt: new Date().toISOString(),
    });
  } catch {
    return res.status(500).json({ error: 'فشل مزامنة تغذيات التهديدات المفتوحة.' });
  }
}
