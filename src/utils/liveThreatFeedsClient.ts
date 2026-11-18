export interface ClientBuiltinFeedDefinition {
  id: string;
  name: string;
  provider: string;
  url: string;
  format: 'json' | 'rss';
  category: 'CVE / Vulnerability' | 'Botnet C2 IP' | 'Security Advisory' | 'Threat Intel RSS';
  description: string;
}

export interface ClientLiveThreatFeedItem {
  id: string;
  sourceId: string;
  sourceName: string;
  category: 'CVE / Vulnerability' | 'Botnet C2 IP' | 'Security Advisory' | 'Threat Intel RSS';
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

export interface ClientLiveFeedSourceStatus {
  id: string;
  name: string;
  provider: string;
  url: string;
  format: 'json' | 'rss';
  category: 'CVE / Vulnerability' | 'Botnet C2 IP' | 'Security Advisory' | 'Threat Intel RSS';
  status: 'ok' | 'error';
  itemCount: number;
  latencyMs: number;
  fetchedAt: string;
  error?: string;
}

export interface ClientLiveFeedsSyncResponse {
  items: ClientLiveThreatFeedItem[];
  sourceStatuses: ClientLiveFeedSourceStatus[];
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

export const BUILTIN_THREAT_FEEDS_CLIENT: ClientBuiltinFeedDefinition[] = [
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

function severityAr(sev: ClientLiveThreatFeedItem['severity']): ClientLiveThreatFeedItem['severityAr'] {
  if (sev === 'critical') return 'حرج';
  if (sev === 'high') return 'مرتفع';
  if (sev === 'medium') return 'متوسط';
  return 'منخفض';
}

function normalizeIso(raw?: string): string {
  if (!raw) return new Date().toISOString();
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? new Date().toISOString() : d.toISOString();
}

function stableId(prefix: string, key: string): string {
  let h1 = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h1 ^= key.charCodeAt(i);
    h1 = Math.imul(h1, 0x01000193);
  }
  return `${prefix}_${(h1 >>> 0).toString(16).padStart(8, '0')}${key.length.toString(16)}`;
}

async function fetchJsonWithTimeout(url: string, timeoutMs = 8000): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    if (!text.trim()) throw new Error('Empty response body');
    return JSON.parse(text);
  } finally {
    clearTimeout(timer);
  }
}

export async function syncLiveThreatFeedsClientFallback(options?: {
  enabledSources?: string[];
  limitPerSource?: number;
}): Promise<ClientLiveFeedsSyncResponse> {
  const limit = Math.min(20, Math.max(4, options?.limitPerSource ?? 10));
  const items: ClientLiveThreatFeedItem[] = [];
  const sourceStatuses: ClientLiveFeedSourceStatus[] = [];

  const browserSources = [
    {
      id: 'github_advisories',
      name: 'GitHub Global Security Advisories (Reviewed CVEs)',
      provider: 'GitHub Security',
      url: `https://api.github.com/advisories?per_page=${limit}&type=reviewed`,
      category: 'Security Advisory' as const,
      run: async (): Promise<ClientLiveThreatFeedItem[]> => {
        const data = await fetchJsonWithTimeout(
          `https://api.github.com/advisories?per_page=${limit}&type=reviewed`
        );
        if (!Array.isArray(data)) return [];
        return data.slice(0, limit).map((adv: any) => {
          const cve = String(adv.cve_id || adv.ghsa_id || 'ADVISORY');
          const rawSev = String(adv.severity || 'medium').toLowerCase();
          const sev: ClientLiveThreatFeedItem['severity'] =
            rawSev === 'critical' ? 'critical' : rawSev === 'high' ? 'high' : rawSev === 'low' ? 'low' : 'medium';
          const cvss = typeof adv.cvss?.score === 'number' ? adv.cvss.score : undefined;
          return {
            id: stableId('ghsa', cve),
            sourceId: 'cisa_advisories',
            sourceName: 'GitHub Security Advisories',
            category: 'Security Advisory',
            title: `${cve}: ${adv.summary || 'Security Advisory'}`.slice(0, 190),
            indicator: cve,
            indicatorKind: cve.startsWith('CVE-') ? 'cve' : 'advisory',
            severity: sev,
            severityAr: severityAr(sev),
            cvssScore: cvss,
            publishedAt: normalizeIso(adv.published_at || adv.updated_at),
            summary: String(adv.description || adv.summary || '').slice(0, 320),
            link: String(adv.html_url || `https://github.com/advisories/${encodeURIComponent(adv.ghsa_id || '')}`),
            tags: ['GitHub Advisory', adv.ghsa_id || 'GHSA', cvss ? `CVSS ${cvss}` : sev.toUpperCase()],
          };
        });
      },
    },
    {
      id: 'circl_cve',
      name: 'CIRCL Latest CVE & Advisories API',
      provider: 'CIRCL.lu',
      url: `https://cve.circl.lu/api/last/${limit}`,
      category: 'CVE / Vulnerability' as const,
      run: async (): Promise<ClientLiveThreatFeedItem[]> => {
        const data = await fetchJsonWithTimeout(`https://cve.circl.lu/api/last/${limit}`);
        if (!Array.isArray(data)) return [];
        return data.slice(0, limit).map((entry: any) => {
          const cveId = String(entry.id || entry.cveMetadata?.cveId || entry.aliases?.[0] || 'CVE-ADVISORY');
          const title = String(entry.containers?.cna?.title || entry.summary?.slice(0, 120) || entry.details?.slice(0, 120) || cveId);
          const summary = String(entry.summary || entry.details || entry.containers?.cna?.descriptions?.[0]?.value || title);
          const cvssRaw =
            Number(entry.cvss) ||
            Number(entry.containers?.cna?.metrics?.[0]?.cvssV3_1?.baseScore) ||
            Number(entry.containers?.cna?.metrics?.[0]?.cvssV3_0?.baseScore) ||
            undefined;
          let sev: ClientLiveThreatFeedItem['severity'] = 'medium';
          if (cvssRaw !== undefined && Number.isFinite(cvssRaw)) {
            sev = cvssRaw >= 9 ? 'critical' : cvssRaw >= 7 ? 'high' : cvssRaw >= 4 ? 'medium' : 'low';
          }
          return {
            id: stableId('circl', cveId),
            sourceId: 'circl_cve',
            sourceName: 'CIRCL CVE Feed',
            category: 'CVE / Vulnerability',
            title: `${cveId}: ${title}`.slice(0, 180),
            indicator: cveId,
            indicatorKind: 'cve',
            severity: sev,
            severityAr: severityAr(sev),
            cvssScore: cvssRaw && Number.isFinite(cvssRaw) ? cvssRaw : undefined,
            publishedAt: normalizeIso(entry.Published || entry.published || entry.modified || entry.cveMetadata?.datePublished),
            summary: summary.slice(0, 320),
            link: cveId.startsWith('CVE-')
              ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}`
              : `https://cve.circl.lu/vuln/${encodeURIComponent(cveId)}`,
            tags: ['CIRCL', cvssRaw ? `CVSS ${cvssRaw}` : 'CVE'],
          };
        });
      },
    },
    {
      id: 'first_epss',
      name: 'FIRST.org High-Probability Exploited CVEs (EPSS)',
      provider: 'FIRST.org',
      url: `https://api.first.org/data/v1/epss?limit=${limit}&epss-gt=0.5`,
      category: 'CVE / Vulnerability' as const,
      run: async (): Promise<ClientLiveThreatFeedItem[]> => {
        const res = await fetchJsonWithTimeout(`https://api.first.org/data/v1/epss?limit=${limit}&epss-gt=0.5`);
        const rows = Array.isArray(res?.data) ? res.data : [];
        return rows.slice(0, limit).map((row: any) => {
          const cve = String(row.cve || 'CVE-UNKNOWN');
          const epssPct = Math.round((Number(row.epss) || 0) * 100);
          const sev: ClientLiveThreatFeedItem['severity'] = epssPct >= 80 ? 'critical' : 'high';
          return {
            id: stableId('epss', cve),
            sourceId: 'cisa_kev',
            sourceName: 'FIRST EPSS Exploit Predictor',
            category: 'CVE / Vulnerability',
            title: `${cve}: احتمالية استغلال نشط بنسبة ${epssPct}% (EPSS)`,
            indicator: cve,
            indicatorKind: 'cve',
            severity: sev,
            severityAr: severityAr(sev),
            publishedAt: normalizeIso(row.date),
            summary: `مؤشر FIRST EPSS يرصد ارتفاع احتمالية الاستغلال الفعلي للثغرة ${cve} بنسبة ${epssPct}% (Percentile: ${Math.round((Number(row.percentile) || 0) * 100)}%).`,
            link: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`,
            tags: ['FIRST EPSS', `Exploit ${epssPct}%`],
          };
        });
      },
    },
  ];

  await Promise.allSettled(
    browserSources.map(async (src) => {
      const t0 = Date.now();
      const fetchedAt = new Date().toISOString();
      try {
        const list = await src.run();
        items.push(...list);
        sourceStatuses.push({
          id: src.id,
          name: src.name,
          provider: src.provider,
          url: src.url,
          format: 'json',
          category: src.category,
          status: 'ok',
          itemCount: list.length,
          latencyMs: Date.now() - t0,
          fetchedAt,
        });
      } catch (err: any) {
        sourceStatuses.push({
          id: src.id,
          name: src.name,
          provider: src.provider,
          url: src.url,
          format: 'json',
          category: src.category,
          status: 'error',
          itemCount: 0,
          latencyMs: Date.now() - t0,
          fetchedAt,
          error: err?.message || 'CORS / Network Error',
        });
      }
    })
  );

  const deduped = new Map<string, ClientLiveThreatFeedItem>();
  for (const item of items) {
    if (!deduped.has(item.id)) deduped.set(item.id, item);
  }
  const sortedItems = Array.from(deduped.values()).sort(
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

export function buildLocalLiveFeedsBriefing(items: ClientLiveThreatFeedItem[]) {
  const critical = items.filter((i) => i.severity === 'critical');
  const high = items.filter((i) => i.severity === 'high');
  const alertCondition =
    critical.length >= 3
      ? 'تأهب حرج (CRITICAL)'
      : critical.length >= 1 || high.length >= 4
      ? 'تأهب مرتفع (HIGH)'
      : 'مراقبة اعتيادية (ELEVATED)';

  const topItems = [...critical, ...high, ...items].slice(0, 5);
  const tagSet = new Set<string>();
  topItems.forEach((it) => it.tags.slice(0, 2).forEach((t) => tagSet.add(t)));

  return {
    alertCondition,
    executiveBriefing: `تم تحليل ${items.length} مؤشر تهديد حيّ مباشرة من التغذيات المفتوحة، منها ${critical.length} مؤشر حرج و${high.length} مؤشر مرتفع الخطورة. يُنصح بمراجعة الثغرات الحرجة وتطبيق التحديثات الأمنية وحظر عناوين C2 المرصودة فوراً.`,
    topPriorityThreats: topItems.map((it) => `[${it.severityAr}] ${it.indicator} — ${it.title.slice(0, 110)}`),
    affectedTechnologies: Array.from(tagSet).slice(0, 6),
    actionablePlaybook: [
      'مراجعة الثغرات الحرجة (Critical CVEs) والتحقق من عدم وجود الأنظمة المتأثرة ضمن بيئة العمل.',
      'تحديث قواعد الجدار الناري (Firewall / IDS) لحظر مؤشرات C2 والعناوين عالية الخطورة.',
      'توثيق المؤشرات الحرجة في سلسلة الحيازة الرقمية وتصعيدها لسجل العمليات للمتابعة الدورية.',
    ],
  };
}
