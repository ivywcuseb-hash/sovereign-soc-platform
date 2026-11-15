import crypto from 'node:crypto';

export type LiveFeedFormat = 'json' | 'rss';
export type LiveFeedCategory = 'CVE / Vulnerability' | 'Botnet C2 IP' | 'Security Advisory' | 'Threat Intel RSS';

export interface BuiltinFeedDefinition {
  id: string;
  name: string;
  provider: string;
  url: string;
  format: LiveFeedFormat;
  category: LiveFeedCategory;
  description: string;
}

export interface LiveThreatFeedItem {
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

export interface LiveFeedSourceStatus {
  id: string;
  name: string;
  provider: string;
  url: string;
  format: LiveFeedFormat;
  category: LiveFeedCategory;
  status: 'ok' | 'error';
  itemCount: number;
  latencyMs: number;
  fetchedAt: string;
  error?: string;
}

export interface LiveFeedsSyncResponse {
  items: LiveThreatFeedItem[];
  sourceStatuses: LiveFeedSourceStatus[];
  stats: {
    totalItems: number;
    criticalCount: number;
    highCount: number;
    cveCount: number;
    c2Count: number;
    advisoryCount: number;
    activeSourcesOk: number;
    activeSourcesTotal: number;
  };
  syncedAt: string;
}

export const BUILTIN_THREAT_FEEDS: BuiltinFeedDefinition[] = [
  {
    id: 'cisa_kev',
    name: 'CISA Known Exploited Vulnerabilities (KEV)',
    provider: 'U.S. CISA',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    format: 'json',
    category: 'CVE / Vulnerability',
    description: 'الكتالوج الرسمي للثغرات الأمنية المستغلة فعلياً في الهجمات النشطة',
  },
  {
    id: 'feodo_c2',
    name: 'Abuse.ch Feodo Tracker Botnet C2',
    provider: 'Abuse.ch',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    format: 'json',
    category: 'Botnet C2 IP',
    description: 'قائمة عناوين IP النشطة لخوادم التحكم والسيطرة (Botnet C2)',
  },
  {
    id: 'circl_cve',
    name: 'CIRCL Latest CVE & Advisories API',
    provider: 'CIRCL.lu',
    url: 'https://cve.circl.lu/api/last/15',
    format: 'json',
    category: 'CVE / Vulnerability',
    description: 'أحدث الثغرات الأمنية المنشورة عالمياً مع التوصيف والدرجات',
  },
  {
    id: 'cisa_advisories',
    name: 'CISA Cybersecurity Advisories RSS',
    provider: 'U.S. CISA',
    url: 'https://www.cisa.gov/cybersecurity-advisories/all.xml',
    format: 'rss',
    category: 'Security Advisory',
    description: 'التنبيهات والتحذيرات السيبرانية الرسمية الصادرة عن وكالة CISA',
  },
  {
    id: 'sans_isc',
    name: 'SANS Internet Storm Center Diary RSS',
    provider: 'SANS ISC',
    url: 'https://isc.sans.edu/rssfeed_full.xml',
    format: 'rss',
    category: 'Threat Intel RSS',
    description: 'تقارير الرصد اليومي للحوادث والهجمات من مركز عواصف الإنترنت',
  },
  {
    id: 'hacker_news',
    name: 'The Hacker News Threat Feed RSS',
    provider: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    format: 'rss',
    category: 'Threat Intel RSS',
    description: 'تغذية الأخبار والتحليلات الأمنية الفورية لأحدث الثغرات والاختراقات',
  },
];

function makeItemId(sourceId: string, uniqueKey: string): string {
  return crypto.createHash('sha256').update(`${sourceId}::${uniqueKey}`).digest('hex').slice(0, 16);
}

function severityToArabic(sev: LiveThreatFeedItem['severity']): LiveThreatFeedItem['severityAr'] {
  if (sev === 'critical') return 'حرج';
  if (sev === 'high') return 'مرتفع';
  if (sev === 'medium') return 'متوسط';
  return 'منخفض';
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
  // Atom self-closing link href="..."
  if (tagName === 'link') {
    const atomLink = block.match(/<link[^>]+href=["']([^"']+)["'][^>]*\/?>/i);
    if (atomLink) return atomLink[1].trim();
  }
  return '';
}

function normalizeIsoDate(dateStr?: string): string {
  if (!dateStr) return new Date().toISOString();
  const parsed = new Date(dateStr);
  if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  return new Date().toISOString();
}

function inferSeverityFromText(text: string): LiveThreatFeedItem['severity'] {
  const lower = text.toLowerCase();
  if (/(zero[- ]day|0[- ]day|rce|remote code execution|actively exploited|ransomware|critical|cvss\s*9\.|cvss\s*10)/i.test(lower)) {
    return 'critical';
  }
  if (/(exploit|privilege escalation|authentication bypass|botnet|c2|backdoor|malware|apt|high severity|vulnerability)/i.test(lower)) {
    return 'high';
  }
  if (/(patch|update|advisory|phishing|spoofing)/i.test(lower)) {
    return 'medium';
  }
  return 'medium';
}

function isBlockedPrivateUrl(rawUrl: string): boolean {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return true;
    const host = parsed.hostname.toLowerCase();
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '::1' ||
      host === '0.0.0.0' ||
      host.endsWith('.local') ||
      host.startsWith('10.') ||
      host.startsWith('192.168.') ||
      host.startsWith('169.254.') ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host)
    ) {
      return true;
    }
    return false;
  } catch {
    return true;
  }
}

async function fetchWithTimeout(url: string, timeoutMs = 8000): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal,
      headers: {
        'User-Agent': 'SovereignForensicEngine/2.5 (LiveThreatFeeds)',
        Accept: 'application/json, application/xml, application/rss+xml, text/xml, */*',
      },
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

function parseCisaKevJson(rawText: string, limit: number): LiveThreatFeedItem[] {
  const json = JSON.parse(rawText);
  const vulns: any[] = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
  // Sort newest dateAdded descending
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
      summary: `${v.shortDescription || ''} | إجراء المعالجة المطلوب: ${v.requiredAction || 'تحديث فوري'} (الموعد النهائي: ${v.dueDate || '—'})`,
      link: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
      tags: [
        v.vendorProject || 'Vendor',
        v.product || 'Product',
        isRansom ? 'Ransomware Campaign' : 'Active Exploitation',
      ].filter(Boolean),
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
      summary: `خادم تحكم وسيطرة (C2) نشط مرتبط بعائلة ${malware} | الحالة: ${entry.status || 'online'} | الدولة: ${entry.country || 'N/A'} | AS: ${entry.as_number || ''} (${entry.as_name || ''})`,
      link: `https://feodotracker.abuse.ch/browse/host/${encodeURIComponent(ip)}/`,
      tags: [malware, entry.country || 'Unknown', `Port ${entry.port || '—'}`, isOnline ? 'Online C2' : 'Tracked C2'],
    };
  });
}

function parseCirclCveJson(rawText: string, limit: number): LiveThreatFeedItem[] {
  const arr = JSON.parse(rawText);
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, limit).map((entry: any) => {
    // Support both legacy CIRCL format (id, summary, cvss, Published) and CVE 5.1/OSV format
    const cveId = String(
      entry.id ||
        entry.cveMetadata?.cveId ||
        entry.aliases?.[0] ||
        'CVE-ADVISORY'
    );
    const title = String(
      entry.containers?.cna?.title ||
        entry.summary?.slice(0, 120) ||
        entry.details?.slice(0, 120) ||
        cveId
    );
    const summaryText = String(
      entry.summary ||
        entry.details ||
        entry.containers?.cna?.descriptions?.[0]?.value ||
        'ثغرة أمنية حديثة مسجلة في قاعدة بيانات CIRCL.'
    );
    const cvssRaw =
      Number(entry.cvss) ||
      Number(entry.containers?.cna?.metrics?.[0]?.cvssV3_1?.baseScore) ||
      Number(entry.containers?.cna?.metrics?.[0]?.cvssV3_0?.baseScore) ||
      undefined;
    let sev: LiveThreatFeedItem['severity'] = inferSeverityFromText(`${title} ${summaryText}`);
    if (cvssRaw !== undefined && Number.isFinite(cvssRaw)) {
      if (cvssRaw >= 9.0) sev = 'critical';
      else if (cvssRaw >= 7.0) sev = 'high';
      else if (cvssRaw >= 4.0) sev = 'medium';
      else sev = 'low';
    }
    const published = entry.Published || entry.published || entry.modified || entry.cveMetadata?.datePublished;
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
      publishedAt: normalizeIsoDate(published),
      summary: summaryText.slice(0, 320),
      link: cveId.startsWith('CVE-')
        ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`
        : `https://cve.circl.lu/vuln/${encodeURIComponent(cveId)}`,
      tags: [
        cveId.split('-')[0] || 'CVE',
        cvssRaw ? `CVSS ${cvssRaw}` : 'Advisory',
      ],
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
  // Slice first ~300KB so massive XML archives like CISA all.xml parse in milliseconds
  const headChunk = rawXml.slice(0, 320000);
  const itemMatches = headChunk.match(/<(?:item|entry)(?:\s[^>]*)?>[\s\S]*?<\/(?:item|entry)>/gi) || [];
  const items: LiveThreatFeedItem[] = [];

  for (const block of itemMatches.slice(0, limit)) {
    const title = extractXmlTag(block, 'title');
    if (!title) continue;
    const link = extractXmlTag(block, 'link') || extractXmlTag(block, 'id') || '';
    const pubDate =
      extractXmlTag(block, 'pubDate') ||
      extractXmlTag(block, 'published') ||
      extractXmlTag(block, 'updated') ||
      extractXmlTag(block, 'dc:date');
    const desc =
      extractXmlTag(block, 'description') ||
      extractXmlTag(block, 'summary') ||
      extractXmlTag(block, 'content');

    const cveMatch = `${title} ${desc}`.match(/CVE-\d{4}-\d{4,7}/i);
    const ipMatch = `${title} ${desc}`.match(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/);
    let domainHint = '';
    try {
      if (link) domainHint = new URL(link).hostname;
    } catch {
      domainHint = '';
    }

    const indicator = cveMatch ? cveMatch[0].toUpperCase() : ipMatch ? ipMatch[0] : domainHint || title.slice(0, 48);
    const indicatorKind: LiveThreatFeedItem['indicatorKind'] = cveMatch
      ? 'cve'
      : ipMatch
      ? 'ip'
      : domainHint
      ? 'advisory'
      : 'advisory';

    const sev = inferSeverityFromText(`${title} ${desc}`);
    items.push({
      id: makeItemId(sourceId, link || title),
      sourceId,
      sourceName,
      category,
      title: title.slice(0, 200),
      indicator,
      indicatorKind,
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

function parseGenericJsonFeed(
  rawText: string,
  sourceId: string,
  sourceName: string,
  category: LiveFeedCategory,
  limit: number
): LiveThreatFeedItem[] {
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
    const link = String(row.url || row.link || '');
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

export async function syncLiveThreatFeeds(options?: {
  enabledSources?: string[];
  customFeedUrls?: { name: string; url: string }[];
  limitPerSource?: number;
}): Promise<LiveFeedsSyncResponse> {
  const limit = Math.min(25, Math.max(3, options?.limitPerSource ?? 10));
  const requestedIds = options?.enabledSources?.length
    ? new Set(options.enabledSources)
    : new Set(BUILTIN_THREAT_FEEDS.map((f) => f.id));

  const targets: {
    id: string;
    name: string;
    provider: string;
    url: string;
    format: LiveFeedFormat | 'auto';
    category: LiveFeedCategory;
  }[] = BUILTIN_THREAT_FEEDS.filter((f) => requestedIds.has(f.id)).map((f) => ({ ...f }));

  // Append custom user feeds if safe
  for (const custom of options?.customFeedUrls || []) {
    const cleanUrl = (custom.url || '').trim();
    if (!cleanUrl) continue;
    const cid = `custom_${makeItemId('custom', cleanUrl).slice(0, 8)}`;
    targets.push({
      id: cid,
      name: custom.name?.trim() || new URL(cleanUrl).hostname,
      provider: 'Custom Feed',
      url: cleanUrl,
      format: 'auto',
      category: 'Threat Intel RSS',
    });
  }

  const allItems: LiveThreatFeedItem[] = [];
  const sourceStatuses: LiveFeedSourceStatus[] = [];

  await Promise.allSettled(
    targets.map(async (feed) => {
      const t0 = Date.now();
      const fetchedAt = new Date().toISOString();
      try {
        if (isBlockedPrivateUrl(feed.url)) {
          throw new Error('الرابط مرفوض أمنياً (يجب أن يكون HTTP/HTTPS عاماً وليس شبكة داخلية).');
        }
        const body = await fetchWithTimeout(feed.url, 8000);
        let parsedItems: LiveThreatFeedItem[] = [];

        if (feed.id === 'cisa_kev') {
          parsedItems = parseCisaKevJson(body, limit);
        } else if (feed.id === 'feodo_c2') {
          parsedItems = parseFeodoC2Json(body, limit);
        } else if (feed.id === 'circl_cve') {
          parsedItems = parseCirclCveJson(body, limit);
        } else if (feed.format === 'rss' || body.trimStart().startsWith('<')) {
          parsedItems = parseRssOrAtomXml(body, feed.id, feed.name, feed.category, limit);
        } else {
          parsedItems = parseGenericJsonFeed(body, feed.id, feed.name, feed.category, limit);
        }

        allItems.push(...parsedItems);
        sourceStatuses.push({
          id: feed.id,
          name: feed.name,
          provider: feed.provider,
          url: feed.url,
          format: body.trimStart().startsWith('<') ? 'rss' : 'json',
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

  // Deduplicate and sort newest first
  const dedupedMap = new Map<string, LiveThreatFeedItem>();
  for (const item of allItems) {
    if (!dedupedMap.has(item.id)) dedupedMap.set(item.id, item);
  }
  const sortedItems = Array.from(dedupedMap.values()).sort(
    (a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime()
  );

  return {
    items: sortedItems,
    sourceStatuses,
    stats: {
      totalItems: sortedItems.length,
      criticalCount: sortedItems.filter((i) => i.severity === 'critical').length,
      highCount: sortedItems.filter((i) => i.severity === 'high').length,
      cveCount: sortedItems.filter((i) => i.indicatorKind === 'cve').length,
      c2Count: sortedItems.filter((i) => i.category === 'Botnet C2 IP').length,
      advisoryCount: sortedItems.filter(
        (i) => i.category === 'Security Advisory' || i.category === 'Threat Intel RSS'
      ).length,
      activeSourcesOk: sourceStatuses.filter((s) => s.status === 'ok').length,
      activeSourcesTotal: sourceStatuses.length,
    },
    syncedAt: new Date().toISOString(),
  };
}
