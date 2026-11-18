import { GoogleGenAI, Modality } from '@google/genai';

export interface SiteDataSnapshot {
  userName?: string;
  userEmail?: string;
  userRole?: string;
  activeTab?: string;
  counts?: {
    investigations: number;
    evidence: number;
    auditLogs: number;
    custody: number;
    savedReports: number;
    liveFeeds: number;
    telemetry: number;
    criticalAlerts: number;
  };
  investigations?: Array<{
    title: string;
    caseNumber?: string;
    status?: string;
    createdAt?: string;
  }>;
  evidence?: Array<{
    fileName: string;
    fileSize?: number;
    sha256: string;
    riskLevel?: string;
    verdict?: string;
    authenticityScore?: number;
    detectedFileType?: string;
    isMasqueraded?: boolean;
    createdAt?: string;
  }>;
  auditLogs?: Array<{
    fileName: string;
    verdict?: string;
    risk?: string;
    score?: number;
    type?: string;
    sha256?: string;
    timestamp?: string;
  }>;
  liveFeeds?: Array<{
    title: string;
    sourceName?: string;
    category?: string;
    indicator?: string;
    severity?: string;
    severityAr?: string;
    cvssScore?: number;
    publishedAt?: string;
  }>;
  telemetry?: Array<{
    subsystem?: string;
    level?: string;
    message?: string;
    timestamp?: string;
  }>;
  currentAnalysis?: {
    fileName: string;
    verdict: string;
    riskLevel: string;
    authenticityScore: number;
    sha256: string;
    detectedFileType: string;
    entropy?: number;
    isMasqueraded?: boolean;
  } | null;
  apkResult?: {
    fileName: string;
    packageName?: string;
    permissionsCount?: number;
    riskHint?: string;
  } | null;
  browserResult?: {
    fileName: string;
    totalUrlsCount?: number;
    flaggedUrlsCount?: number;
  } | null;
  threatIntelResult?: {
    indicator: string;
    verdict?: string;
    threatScore?: number;
  } | null;
}

async function fetchJsonWithTimeout(url: string, options: RequestInit = {}, timeoutMs = 4500): Promise<any | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'SovereignForensicEngine/2.5.2',
        ...(options.headers || {}),
      },
    });
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

async function lookupLiveOsintFromPrompt(prompt: string): Promise<string[]> {
  const findings: string[] = [];

  // 1. CVE lookup via CIRCL + CISA KEV check
  const cveMatch = prompt.match(/\bCVE-\d{4}-\d{4,7}\b/i);
  if (cveMatch) {
    const cveId = cveMatch[0].toUpperCase();
    const [cveData, kevData] = await Promise.all([
      fetchJsonWithTimeout(`https://cve.circl.lu/api/cve/${encodeURIComponent(cveId)}`),
      fetchJsonWithTimeout('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', {}, 4000),
    ]);
    if (cveData && (cveData.summary || cveData.cveMetadata || cveData.containers)) {
      const summary =
        cveData.summary ||
        cveData.containers?.cna?.descriptions?.[0]?.value ||
        'تم العثور على سجل الثغرة في قاعدة CIRCL.';
      const cvss =
        cveData.cvss ||
        cveData.containers?.cna?.metrics?.[0]?.cvssV3_1?.baseScore ||
        cveData.containers?.adp?.[0]?.metrics?.[0]?.cvssV3_1?.baseScore ||
        'غير محدد';
      findings.push(
        `• سجل الثغرة ${cveId} (CIRCL CVE): درجة CVSS = ${cvss}. التفاصيل: ${String(summary).slice(0, 320)}`
      );
    }
    if (kevData && Array.isArray(kevData.vulnerabilities)) {
      const hit = kevData.vulnerabilities.find((v: any) => String(v.cveID).toUpperCase() === cveId);
      if (hit) {
        findings.push(
          `• تنبيه CISA KEV: الثغرة ${cveId} مُستغلة فعلياً في هجمات نشطة! المنتج: ${hit.vendorProject} ${hit.product}، تاريخ الإضافة: ${hit.dateAdded}، الإجراء المطلوب: ${hit.requiredAction}.`
        );
      }
    }
  }

  // 2. IPv4 lookup via ipwho.is + RDAP
  const ipMatch = prompt.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/);
  if (ipMatch) {
    const ip = ipMatch[0];
    const ipData = await fetchJsonWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (ipData && ipData.success !== false) {
      findings.push(
        `• معلومات IP الحية (${ip}): الدولة ${ipData.country || 'غير معروفة'} (${ipData.city || '—'})، المزود ISP: ${ipData.connection?.isp || ipData.connection?.org || '—'}، ASN: ${ipData.connection?.asn || '—'}، النطاق: ${ipData.connection?.domain || '—'}.`
      );
    }
  }

  // 3. Domain / URL DNS-over-HTTPS + MX/TXT lookup
  const domainMatch = prompt.match(/\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|app|gov|edu|ru|cn|ir|iq|sa|ae|uk|de|xyz|info|biz|me|co|top|dev))\b/i);
  if (domainMatch && !ipMatch) {
    const domain = domainMatch[1].toLowerCase();
    const [aData, mxData, txtData] = await Promise.all([
      fetchJsonWithTimeout(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
        headers: { Accept: 'application/dns-json' },
      }),
      fetchJsonWithTimeout(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=MX`, {
        headers: { Accept: 'application/dns-json' },
      }),
      fetchJsonWithTimeout(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=TXT`, {
        headers: { Accept: 'application/dns-json' },
      }),
    ]);
    const ips = Array.isArray(aData?.Answer)
      ? aData.Answer.filter((a: any) => a.type === 1).map((a: any) => a.data).slice(0, 4)
      : [];
    const mxs = Array.isArray(mxData?.Answer)
      ? mxData.Answer.map((m: any) => String(m.data)).slice(0, 2)
      : [];
    const hasSpf = Array.isArray(txtData?.Answer)
      ? txtData.Answer.some((t: any) => String(t.data).toLowerCase().includes('v=spf1'))
      : false;
    if (ips.length > 0 || mxs.length > 0) {
      findings.push(
        `• فحص النطاق الحي (${domain}): عناوين A = (${ips.join('، ') || 'غير متوفر'})، خوادم البريد MX = (${mxs.join('، ') || 'لا يوجد'})، سجل الحماية SPF = ${hasSpf ? 'مُفعّل' : 'غير مرصود'}.`
      );
    }
  }

  // 4. SHA-256 / MD5 / SHA-1 lookup via MalwareBazaar + CIRCL Hashlookup
  const hashMatch = prompt.match(/\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/i);
  if (hashMatch) {
    const hash = hashMatch[0].toLowerCase();
    const algo = hash.length === 64 ? 'sha256' : hash.length === 40 ? 'sha1' : 'md5';
    const form = new URLSearchParams({ query: 'get_info', hash });
    const [mb, circl] = await Promise.all([
      fetchJsonWithTimeout('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: form.toString(),
      }),
      fetchJsonWithTimeout(`https://hashlookup.circl.lu/lookup/${algo}/${encodeURIComponent(hash)}`),
    ]);
    if (mb?.query_status === 'ok' && Array.isArray(mb.data) && mb.data[0]) {
      const sample = mb.data[0];
      findings.push(
        `• تحذير MalwareBazaar: البصمة ${hash.slice(0, 16)}... مطابقة لبرمجية خبيثة معروفة (${sample.signature || sample.file_type || 'Malware'}) تم رصدها بتاريخ ${sample.first_seen || 'غير محدد'}.`
      );
    } else if (circl && (circl.FileName || circl.ProductName)) {
      findings.push(
        `• قاعدة CIRCL NSRL: البصمة ${hash.slice(0, 16)}... مطابقة لملف برمجي رسمي سليم (${circl.FileName || circl.ProductName}).`
      );
    } else if (mb?.query_status === 'hash_not_found') {
      findings.push(`• فحص MalwareBazaar للبصمة ${hash.slice(0, 16)}...: غير مسجلة في عينات البرمجيات الخبيثة المعروفة.`);
    }
  }

  return findings;
}

async function lookupLiveWebKnowledge(query: string): Promise<string | null> {
  const cleanTopic = query
    .replace(/^(?:شنو|ما هو|ما هي|من هو|من هي|ما معنى|عرف|اشرح|اشرحلي|تكلم عن|اعطني معلومات عن|قولي عن|وضح|كيف يعمل|what is|who is|explain|define|tell me about)\s+/gi, '')
    .replace(/[؟?]/g, '')
    .trim();

  if (!cleanTopic || cleanTopic.length < 2) return null;

  const isArabic = /[\u0600-\u06FF]/.test(cleanTopic);
  const wikiHost = isArabic ? 'ar.wikipedia.org' : 'en.wikipedia.org';

  // 1. Wikipedia Search -> Summary API
  const searchRes = await fetchJsonWithTimeout(
    `https://${wikiHost}/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(cleanTopic)}&format=json&srlimit=2`,
    {},
    4000
  );
  const topTitle: string | undefined = searchRes?.query?.search?.[0]?.title;
  if (topTitle) {
    const summaryRes = await fetchJsonWithTimeout(
      `https://${wikiHost}/api/rest_v1/page/summary/${encodeURIComponent(topTitle)}`,
      {},
      4000
    );
    if (summaryRes?.extract) {
      return `${summaryRes.title}: ${String(summaryRes.extract).slice(0, 750)}`;
    }
  }

  // 2. DuckDuckGo Instant Answer API + English Wikipedia fallback
  const [ddg, enSearch] = await Promise.all([
    fetchJsonWithTimeout(
      `https://api.duckduckgo.com/?q=${encodeURIComponent(cleanTopic)}&format=json&no_html=1&skip_disambig=1`,
      {},
      3500
    ),
    isArabic
      ? fetchJsonWithTimeout(
          `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(cleanTopic)}&format=json&srlimit=1`,
          {},
          3500
        )
      : Promise.resolve(null),
  ]);

  if (ddg?.AbstractText) {
    return `${ddg.Heading || cleanTopic}: ${String(ddg.AbstractText).slice(0, 700)}`;
  }

  const enTitle: string | undefined = enSearch?.query?.search?.[0]?.title;
  if (enTitle) {
    const enSummary = await fetchJsonWithTimeout(
      `https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(enTitle)}`,
      {},
      3500
    );
    if (enSummary?.extract) {
      return `${enSummary.title}: ${String(enSummary.extract).slice(0, 700)}`;
    }
  }

  return null;
}

function trySafeArithmeticEval(query: string): string | null {
  const mathMatch = query.match(/(?:احسب|كم يساوي|ناتج|calculate)?\s*([-+*/().\d\s]{3,60})\s*[=؟?]?$/i);
  if (!mathMatch) return null;
  const expr = mathMatch[1].trim();
  if (!/[+\-*/]/.test(expr) || !/^[0-9+\-*/().\s]+$/.test(expr)) return null;
  try {
    const fn = new Function(`"use strict"; return (${expr});`);
    const result = fn();
    if (typeof result === 'number' && Number.isFinite(result)) {
      return `نتيجة العملية الحسابية (${expr}) هي: ${result}`;
    }
  } catch {
    return null;
  }
  return null;
}

function normalizeArabicText(s: string): string {
  return s
    .toLowerCase()
    .replace(/[\u064B-\u065F\u0670]/g, '')
    .replace(/[أإآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .trim();
}

function buildDeepSiteDataAnalysis(
  userQuery: string,
  siteData: SiteDataSnapshot | null,
  osintFindings: string[]
): string | null {
  const norm = normalizeArabicText(userQuery);
  const counts = siteData?.counts || {
    investigations: 0,
    evidence: 0,
    auditLogs: 0,
    custody: 0,
    savedReports: 0,
    liveFeeds: 0,
    telemetry: 0,
    criticalAlerts: 0,
  };
  const evidence = siteData?.evidence || [];
  const auditLogs = siteData?.auditLogs || [];
  const feeds = siteData?.liveFeeds || [];
  const investigations = siteData?.investigations || [];

  // Search for any specific filename / hash / feed keyword mentioned directly in userQuery
  const matchingEvidence = evidence.filter(
    (e) =>
      (e.fileName && norm.includes(normalizeArabicText(e.fileName))) ||
      (e.sha256 && norm.includes(e.sha256.toLowerCase().slice(0, 12)))
  );
  if (matchingEvidence.length > 0) {
    const details = matchingEvidence
      .slice(0, 3)
      .map(
        (e) =>
          `الملف «${e.fileName}» (${e.detectedFileType || 'ملف'}): الحكم الجنائي = ${e.verdict || 'مفحوص'}، مستوى الخطورة = ${e.riskLevel || '—'}، درجة الأصالة = ${e.authenticityScore ?? '—'}%، البصمة SHA-256 = ${e.sha256}.`
      )
      .join('\n');
    return [...osintFindings, details].join('\n');
  }

  if (osintFindings.length > 0) {
    return osintFindings.join('\n');
  }

  // Conversational greeting / identity
  if (/^(هلو|مرحبا|اهلا|السلام عليكم|سلام|صباح الخير|مساء الخير|شلونك|كيفك|hi|hello|hey)\b/.test(norm)) {
    const who = siteData?.userName ? `يا ${siteData.userName}` : '';
    return `أهلاً بك ${who}! أنا جاهز الآن ومرتبط ببيانات موقعك الفعلية (${counts.evidence} دليل، ${counts.auditLogs} عملية فحص، ${counts.liveFeeds} تغذية تهديد حية، و${counts.criticalAlerts} تنبيه حرج/مرتفع). اسألني عن أي ملف رفعته، أو أخطر تهديد مسجل، أو أي ثغرة CVE أو عنوان IP أو موضوع سيبراني وتقني.`;
  }

  // Ranking riskiest / fake / suspicious files in evidence
  if (/(اخطر|خطر|مزيف|تزييف|ملف مشبوه|مشبوهه|اسوا|اقل اصاله)/.test(norm) && evidence.length > 0) {
    const ranked = [...evidence].sort(
      (a, b) => (a.authenticityScore ?? 100) - (b.authenticityScore ?? 100)
    );
    const risky = ranked.filter(
      (e) =>
        e.riskLevel === 'حرج' ||
        e.riskLevel === 'مرتفع' ||
        e.isMasqueraded ||
        (e.authenticityScore ?? 100) < 70
    );
    const list = (risky.length > 0 ? risky : ranked)
      .slice(0, 5)
      .map(
        (e, i) =>
          `${i + 1}) ${e.fileName} — التقييم: ${e.verdict || 'مفحوص'} (خطر: ${e.riskLevel || '—'} | أصالة: ${e.authenticityScore ?? '—'}% | SHA256: ${e.sha256.slice(0, 10)}...)`
      )
      .join('\n');
    return `بناءً على فحص ${evidence.length} دليل محفوظ في خزنتك الفعلية، إليك أكثر الملفات خطورة أو انخفاضاً في درجة الأصالة:\n${list}`;
  }

  // Detailed evidence list request
  if (/(الادله|ادله|ملفاتي|الملفات|المرفوعه|الخزنه|اخر ملف|احدث ملف|sha)/.test(norm)) {
    if (evidence.length === 0 && !siteData?.currentAnalysis) {
      return 'خزنتك السحابية لا تحتوي حالياً على ملفات أدلة محفوظة؛ ارفع صورة أو حزمة APK أو مستند PDF من وحدة التحليل ليتم تحليلها وحفظ بصمتها فوراً.';
    }
    const itemsText = evidence
      .slice(0, 6)
      .map(
        (e, i) =>
          `${i + 1}) ${e.fileName} (${e.riskLevel || '—'} • أصالة ${e.authenticityScore ?? '—'}% • ${e.verdict || 'موثق'})`
      )
      .join('\n');
    const activeNote = siteData?.currentAnalysis
      ? `\n• الملف النشط في الفاحص الآن: ${siteData.currentAnalysis.fileName} (${siteData.currentAnalysis.verdict} - ${siteData.currentAnalysis.authenticityScore}%).`
      : '';
    return `إجمالي الأدلة الموثقة في حسابك هو ${counts.evidence} دليل.${activeNote}\nأحدث الأدلة المسجلة:\n${itemsText}`;
  }

  // Threat feeds / CVEs / KEV
  if (/(التغذيات|تغذيه|ثغره|ثغرات|التهديدات|cve|kev|سي تو|c2|بوت نت)/.test(norm)) {
    if (feeds.length === 0) {
      return `لديك ${counts.auditLogs} سجل فحص و${counts.criticalAlerts} تنبيه حرج؛ لكن جدول التغذيات الحية لم يُزامَن في هذه الجلسة بعد. يمكنك تشغيل «حدث التغذيات» لجلب آخر الثغرات وخوادم C2 الحية.`;
    }
    const criticalFeeds = feeds.filter((f) => f.severity === 'critical' || f.severity === 'high');
    const summary = (criticalFeeds.length > 0 ? criticalFeeds : feeds)
      .slice(0, 6)
      .map(
        (f, i) =>
          `${i + 1}) [${f.severityAr || f.severity || 'تنبيه'}] ${f.title}${f.indicator ? ` — المؤشر: ${f.indicator}` : ''}${f.sourceName ? ` (${f.sourceName})` : ''}`
      )
      .join('\n');
    return `تقرير التغذيات الحية الفعلي (${feeds.length} مؤشر، منها ${criticalFeeds.length} حرج/مرتفع):\n${summary}`;
  }

  // Full stats / audit logs / investigations / cases
  if (/(احصائيات|ملخص|حاله الموقع|العمليات|السجل|القضايا|قضيه|تحقيق|حيازه|تيليمتري|بيانات موقعي)/.test(norm)) {
    const invText =
      investigations.length > 0
        ? `\n• القضايا المفتوحة (${investigations.length}): ${investigations.slice(0, 4).map((i) => `${i.title} [${i.status || 'نشط'}]`).join('، ')}`
        : '';
    const logText =
      auditLogs.length > 0
        ? `\n• آخر العمليات (${auditLogs.length}):\n${auditLogs
            .slice(0, 5)
            .map((l, idx) => `${idx + 1}) ${l.fileName} -> ${l.verdict || l.risk || 'مكتمل'}`)
            .join('\n')}`
        : '';
    return `ملخص البيانات الحقيقية المباشرة لمنصتك الآن:\n• الأدلة الرقمية: ${counts.evidence} | سجلات العمليات: ${counts.auditLogs} | القضايا: ${counts.investigations} | سلسلة الحيازة: ${counts.custody}\n• التغذيات الحية: ${counts.liveFeeds} | التنبيهات الحرجة/المرتفعة: ${counts.criticalAlerts} | التقارير الموثقة: ${counts.savedReports}${invText}${logText}`;
  }

  return null;
}

async function queryOpenLlmFallback(
  systemPrompt: string,
  history: Array<{ role: string; text: string }>,
  userMessage: string
): Promise<string | null> {
  try {
    const messages = [
      { role: 'system', content: systemPrompt },
      ...history.slice(-6).map((h) => ({
        role: h.role === 'assistant' ? 'assistant' : 'user',
        content: String(h.text || '').slice(0, 800),
      })),
      { role: 'user', content: userMessage },
    ];

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 9000);
    const res = await fetch('https://text.pollinations.ai/openai', {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'SovereignForensicEngine/2.5.2',
      },
      body: JSON.stringify({
        model: 'openai',
        messages,
      }),
    });
    clearTimeout(timer);

    if (!res.ok) return null;
    const data = await res.json();
    const content = data?.choices?.[0]?.message?.content;
    return typeof content === 'string' && content.trim() ? content.trim() : null;
  } catch {
    return null;
  }
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
    const audioBase64 = typeof bodyObj.audioBase64 === 'string' ? bodyObj.audioBase64 : '';
    const audioMimeType = typeof bodyObj.audioMimeType === 'string' ? bodyObj.audioMimeType : 'audio/webm';
    const textPrompt = typeof bodyObj.text === 'string' ? bodyObj.text.trim().slice(0, 3500) : '';
    const transcript = typeof bodyObj.transcript === 'string' ? bodyObj.transcript.trim().slice(0, 3500) : '';
    const voiceName = ['Zephyr', 'Puck', 'Charon', 'Kore', 'Fenrir'].includes(bodyObj.voiceName)
      ? bodyObj.voiceName
      : 'Zephyr';
    const forensicContext = typeof bodyObj.forensicContext === 'string' ? bodyObj.forensicContext.slice(0, 6000) : '';
    const siteData: SiteDataSnapshot | null =
      bodyObj.siteData && typeof bodyObj.siteData === 'object' ? bodyObj.siteData : null;
    const history: Array<{ role: string; text: string }> = Array.isArray(bodyObj.history)
      ? bodyObj.history.slice(-10)
      : [];

    const effectiveQuery = textPrompt || transcript;

    if (!audioBase64 && !effectiveQuery) {
      return res.status(400).json({ error: 'يرجى التحدث أو كتابة رسالة للمساعد.' });
    }

    // Always gather live real-time OSINT facts for any indicator mentioned in the prompt
    const osintFindings = effectiveQuery ? await lookupLiveOsintFromPrompt(effectiveQuery) : [];

    const structuredSnapshotText = siteData
      ? JSON.stringify(
          {
            user: siteData.userName || siteData.userEmail || 'Analyst',
            activeTab: siteData.activeTab,
            counts: siteData.counts,
            evidence: (siteData.evidence || []).slice(0, 30),
            auditLogs: (siteData.auditLogs || []).slice(0, 30),
            investigations: (siteData.investigations || []).slice(0, 15),
            liveFeeds: (siteData.liveFeeds || []).slice(0, 30),
            currentAnalysis: siteData.currentAnalysis,
            apkResult: siteData.apkResult,
            browserResult: siteData.browserResult,
            threatIntelResult: siteData.threatIntelResult,
            telemetry: (siteData.telemetry || []).slice(0, 12),
          },
          null,
          2
        ).slice(0, 18000)
      : '';

    const historyBlock =
      history.length > 0
        ? `\nسجل المحادثة السابقة:\n${history
            .map((h) => `${h.role === 'user' ? 'المستخدم' : 'المساعد'}: ${String(h.text || '').slice(0, 450)}`)
            .join('\n')}`
        : '';

    const systemInstruction = `أنت المساعد الذكي الشامل (AI Assistant & Forensic Analyst) داخل منصة SOVEREIGN FORENSIC ENGINE.
قواعدك:
1. أجب على جميع أسئلة المستخدم بذكاء ودقة وشمولية (سواء كانت عن ملفات وأدلة وتهديدات موقعه الحقيقية، أو أسئلة تقنية وبرمجية وسيبرانية، أو أسئلة عامة في أي مجال).
2. عندما يسأل المستخدم عن موقعه أو ملفاته أو ثغراته أو سجلاته، استخرج الإجابة من البيانات الحقيقية المرفقة أدناه بالأسماء والأرقام والبصمات الفعلية دون أي اختلاق.
3. تحدث بالعربية الطبيعية الواضحة (أو باللهجة التي يخاطبك بها المستخدم أو بالإنجليزية إذا سأل بالإنجليزية).
4. اجعل ردودك مباشرة ووافية ومناسبة للقراءة وللنطق الصوتي.
${forensicContext ? `\nملخص حالة المنصة:\n${forensicContext}` : ''}
${structuredSnapshotText ? `\nقاعدة بيانات الموقع الحية الكاملة للمستخدم الآن:\n${structuredSnapshotText}` : ''}
${osintFindings.length > 0 ? `\nبيانات فحص OSINT الحية للمؤشرات المذكورة:\n${osintFindings.join('\n')}` : ''}
${historyBlock}`;

    // TIER 1: Full Gemini SDK (GEMINI_API_KEY / GOOGLE_API_KEY) with Google Search Grounding + Audio TTS
    const apiKey =
      process.env.GEMINI_API_KEY ||
      process.env.GOOGLE_GENERATIVE_AI_API_KEY ||
      process.env.GOOGLE_API_KEY;

    if (apiKey && apiKey !== 'dummy-key') {
      const ai = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });

      const parts: any[] = [];
      if (audioBase64) {
        parts.push({
          inlineData: {
            mimeType: audioMimeType,
            data: audioBase64,
          },
        });
      }
      parts.push({
        text:
          effectiveQuery ||
          'استمع إلى رسالة المستخدم الصوتية وأجب عليها بدقة شاملة بالاعتماد على البيانات الحقيقية ومعرفتك الكاملة.',
      });

      for (const modelName of ['gemini-4-hydrogen', 'gemini-2.5-flash']) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: { parts },
            config: {
              systemInstruction,
              tools: [{ googleSearch: {} }],
            },
          });

          const replyText = (response.text || '').trim();
          if (replyText) {
            let audioPcmBase64: string | null = null;
            try {
              const ttsResponse = await ai.models.generateContent({
                model: 'gemini-3.8-flash-lite-tts',
                contents: replyText,
                config: {
                  responseModalities: [Modality.AUDIO],
                  speechConfig: {
                    voiceConfig: {
                      prebuiltVoiceConfig: { voiceName },
                    },
                  },
                },
              });
              const audioPart = ttsResponse.candidates?.[0]?.content?.parts?.find((p: any) => p.inlineData?.data);
              if (audioPart?.inlineData?.data) {
                audioPcmBase64 = audioPart.inlineData.data;
              }
            } catch {
              // Client automatically falls back to browser speech synthesis if PCM audio isn't returned
            }

            return res.status(200).json({
              success: true,
              engine: `${modelName}+grounding`,
              replyText,
              recognizedText: effectiveQuery || undefined,
              audioPcmBase64,
              sampleRate: 24000,
              useBrowserTts: !audioPcmBase64,
            });
          }
        } catch {
          // Try next Gemini model or fall through
        }
      }
    }

    // TIER 2: Check deterministic real-data / math / live OSINT queries on the user's site data FIRST if specifically about site records or indicators
    const mathAnswer = effectiveQuery ? trySafeArithmeticEval(effectiveQuery) : null;
    if (mathAnswer) {
      return res.status(200).json({
        success: true,
        engine: 'sovereign-compute-core',
        replyText: mathAnswer,
        recognizedText: effectiveQuery,
        audioPcmBase64: null,
        sampleRate: 24000,
        useBrowserTts: true,
      });
    }

    // TIER 3: Open Generative LLM Gateway (answers ANY general, coding, cyber, or site-data question conversationally)
    if (effectiveQuery) {
      const openAiReply = await queryOpenLlmFallback(systemInstruction, history, effectiveQuery);
      if (openAiReply) {
        return res.status(200).json({
          success: true,
          engine: 'sovereign-open-ai-core',
          replyText: openAiReply,
          recognizedText: effectiveQuery,
          audioPcmBase64: null,
          sampleRate: 24000,
          useBrowserTts: true,
        });
      }
    }

    // TIER 4: Deep Real-Site Data Query + Live Wikipedia/DuckDuckGo Knowledge Synthesis (Never rate-limited, always real!)
    const deepSiteReply = effectiveQuery
      ? buildDeepSiteDataAnalysis(effectiveQuery, siteData, osintFindings)
      : null;
    if (deepSiteReply) {
      return res.status(200).json({
        success: true,
        engine: 'sovereign-live-data-core',
        replyText: deepSiteReply,
        recognizedText: effectiveQuery,
        audioPcmBase64: null,
        sampleRate: 24000,
        useBrowserTts: true,
      });
    }

    const webKnowledge = effectiveQuery ? await lookupLiveWebKnowledge(effectiveQuery) : null;
    if (webKnowledge) {
      return res.status(200).json({
        success: true,
        engine: 'sovereign-live-knowledge-core',
        replyText: webKnowledge,
        recognizedText: effectiveQuery,
        audioPcmBase64: null,
        sampleRate: 24000,
        useBrowserTts: true,
      });
    }

    const finalFallback =
      buildDeepSiteDataAnalysis('ملخص النظام', siteData, osintFindings) ||
      'لم أتمكن من التقاط نص واضح من سؤالك؛ اكتب سؤالك أو انطق به بوضوح وسأبحث فوراً في بيانات موقعك أو المصادر الحية للإجابة عليك.';

    return res.status(200).json({
      success: true,
      engine: 'sovereign-live-data-core',
      replyText: finalFallback,
      recognizedText: effectiveQuery || undefined,
      audioPcmBase64: null,
      sampleRate: 24000,
      useBrowserTts: true,
    });
  } catch (err: any) {
    return res.status(500).json({
      error: err?.message || 'تعذر معالجة جولة المحادثة الصوتية.',
    });
  }
}
