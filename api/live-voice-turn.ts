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

  // 1. CVE lookup via CIRCL + CISA KEV
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

  // 2. IPv4 lookup via ipwho.is
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

  // 3. Domain / URL DNS-over-HTTPS lookup
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

function normalizeArabicText(s: string): string {
  return s
    .toLowerCase()
    .replace(/[\u064B-\u065F\u0670]/g, '')
    .replace(/[أإآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .trim();
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

function buildConversationalAndSiteDataReply(
  userQuery: string,
  siteData: SiteDataSnapshot | null,
  osintFindings: string[]
): string {
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

  // 1. Matching evidence file or SHA-256 directly
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
          `الملف «${e.fileName}» (${e.detectedFileType || 'ملف'}): التقييم = ${e.verdict || 'مفحوص'}، الخطورة = ${e.riskLevel || '—'}، درجة الأصالة = ${e.authenticityScore ?? '—'}%، البصمة SHA-256 = ${e.sha256}.`
      )
      .join('\n');
    return [...osintFindings, details].join('\n');
  }

  if (osintFindings.length > 0) {
    return osintFindings.join('\n');
  }

  // 2. Natural conversational greetings & small talk (NO Wikipedia/dictionary lookups!)
  if (/^(هلو|مرحبا|اهلا|السلام عليكم|سلام|صباح الخير|مساء الخير|شلونك|شخبارك|كيفك|هلا|حياك|hi|hello|hey)\b/.test(norm)) {
    const who = siteData?.userName ? `يا ${siteData.userName}` : 'بك';
    return `أهلاً وسهلاً ${who}! أنا جاهز وموجود لخدمتك. كيف أقدر أساعدك اليوم؟ تقدر تسألني عن الأدلة والقضايا والتهديدات الحالية في منصتك (عندك الآن ${counts.evidence} دليل، ${counts.investigations} قضية، و${counts.liveFeeds} مؤشر تهديد حي) أو تطرح أي استفسار أمني وتقني مباشر.`;
  }

  if (/(من انت|شنو شغلك|ماذا تفعل|كيف تساعدني|شنو تكدر تسوي|وش تقدر تسوي)/.test(norm)) {
    return `أنا الخبير السيبراني والمساعد الجنائي الذكي لمنصة Sovereign. أقدر أراجع معك ملفات الأدلة والبصمات، أحلل أخطر التهديدات والثغرات، أفحص عناوين IP والنطاقات وبصمات SHA-256 مباشرة، وأجاوب على أي سؤال تقني أو جنائي رقمي بكل وضوح.`;
  }

  if (/(شكرا|مشكور|تسلم|يعطيك العافيه|ممتاز|احسنت)/.test(norm)) {
    return 'على الرحب والسعة! تحت أمرك في أي وقت، إذا احتجت فحص أي دليل أو استشارة أمنية أنا موجود.';
  }

  // 3. Riskiest / suspicious evidence
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
          `${i + 1}) ${e.fileName} — ${e.verdict || 'مفحوص'} (الخطر: ${e.riskLevel || '—'} | الأصالة: ${e.authenticityScore ?? '—'}%)`
      )
      .join('\n');
    return `من واقع فحص ${evidence.length} دليل في خزنتك الحقيقية، هذه أبرز الملفات التي تحتاج انتباهك:\n${list}`;
  }

  // 4. Evidence list & active scan
  if (/(الادله|ادله|ملفاتي|الملفات|المرفوعه|الخزنه|اخر ملف|احدث ملف|sha)/.test(norm)) {
    if (evidence.length === 0 && !siteData?.currentAnalysis) {
      return 'لا توجد ملفات أدلة محفوظة حالياً في الخزنة؛ يمكنك رفع أي صورة أو مستند أو حزمة APK في قسم التحليل وسأقوم بقراءة نتائجها معك فوراً.';
    }
    const itemsText = evidence
      .slice(0, 6)
      .map(
        (e, i) =>
          `${i + 1}) ${e.fileName} (${e.riskLevel || '—'} • أصالة ${e.authenticityScore ?? '—'}% • ${e.verdict || 'موثق'})`
      )
      .join('\n');
    const activeNote = siteData?.currentAnalysis
      ? `\nالملف النشط حالياً في الفاحص: ${siteData.currentAnalysis.fileName} (${siteData.currentAnalysis.verdict} بنسبة أصالة ${siteData.currentAnalysis.authenticityScore}%).`
      : '';
    return `إجمالي الأدلة المسجلة لديك هو ${counts.evidence} دليل.${activeNote}\nأحدثها:\n${itemsText}`;
  }

  // 5. Threat feeds & CVEs
  if (/(التغذيات|تغذيه|ثغره|ثغرات|التهديدات|cve|kev|سي تو|c2|بوت نت)/.test(norm)) {
    if (feeds.length === 0) {
      return `لديك ${counts.auditLogs} سجل فحص و${counts.criticalAlerts} تنبيه حرج أو مرتفع، لكن التغذيات الحية لم تُحدَّث في هذه الجلسة بعد؛ يمكنك الضغط على مزامنة التغذيات لجلب أحدث المؤشرات.`;
    }
    const criticalFeeds = feeds.filter((f) => f.severity === 'critical' || f.severity === 'high');
    const summary = (criticalFeeds.length > 0 ? criticalFeeds : feeds)
      .slice(0, 6)
      .map(
        (f, i) =>
          `${i + 1}) [${f.severityAr || f.severity || 'تنبيه'}] ${f.title}${f.indicator ? ` (${f.indicator})` : ''}`
      )
      .join('\n');
    return `آخر بيانات التغذيات الحية (${feeds.length} مؤشر، منها ${criticalFeeds.length} بمستوى حرج أو مرتفع):\n${summary}`;
  }

  // 6. Site stats, cases, audit logs
  if (/(احصائيات|ملخص|حاله الموقع|العمليات|السجل|القضايا|قضيه|تحقيق|حيازه|تيليمتري|بيانات موقعي)/.test(norm)) {
    const invText =
      investigations.length > 0
        ? `\n• القضايا (${investigations.length}): ${investigations.slice(0, 4).map((i) => `${i.title} [${i.status || 'نشط'}]`).join('، ')}`
        : '';
    const logText =
      auditLogs.length > 0
        ? `\n• آخر العمليات:\n${auditLogs
            .slice(0, 4)
            .map((l, idx) => `${idx + 1}) ${l.fileName} — ${l.verdict || l.risk || 'مكتمل'}`)
            .join('\n')}`
        : '';
    return `إحصائيات منصتك الحقيقية الآن:\n• الأدلة: ${counts.evidence} | القضايا: ${counts.investigations} | العمليات: ${counts.auditLogs} | التنبيهات الحرجة: ${counts.criticalAlerts} | التغذيات الحية: ${counts.liveFeeds}${invText}${logText}`;
  }

  // 7. Honest prompt when GEMINI_API_KEY isn't configured on serverless host for open-ended questions
  return `وصلتني رسالتك (${userQuery}). بيانات موقعك المتاحة لدي الآن تشمل ${counts.evidence} دليل، ${counts.investigations} قضية، و${counts.liveFeeds} تهديد حي — ولإتاحة إجابات الذكاء الاصطناعي التوليدية الحرة لكل الأسئلة العامة من خادم Vercel، تأكد من ضبط متغير البيئة GEMINI_API_KEY في إعدادات المشروع على Vercel.`;
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
    const timer = setTimeout(() => controller.abort(), 8000);
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

    // Gather live OSINT facts only if user explicitly mentioned an IP, CVE, domain, or hash
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
        ? `\nسجل الحوار السابق:\n${history
            .map((h) => `${h.role === 'user' ? 'المستخدم' : 'المساعد'}: ${String(h.text || '').slice(0, 450)}`)
            .join('\n')}`
        : '';

    const systemInstruction = `أنت خبير تحقيق جنائي رقمي وأمن سيبراني ومساعد ذكاء اصطناعي حقيقي لمنصة SOVEREIGN FORENSIC ENGINE.
أسلوبك وشخصيتك:
- تتحدث بلهجة عربية طبيعية، ذكية، ودودة، ومباشرة (وتجيد اللهجة العراقية والفصحى المبسطة والإنجليزية إذا سُئلت بها).
- ترد على التحيات (مثل مرحبا، هلو، السلام عليكم) والأسئلة العامة والبرمجية والأمنية بطلاقة كأي خبير بشري، ولا تذكر إحصائيات الموقع إلا إذا سألك المستخدم عنها أو ارتبطت بسؤاله.
- لديك وصول مباشر إلى بيانات موقع المستخدم الحقيقية (عدد الأدلة، القضايا، التهديدات، سجلات العمليات، والتغذيات الحية)؛ وعند سؤالك عنها أجب بدقة تامة بالأرقام والأسماء والبصمات الفعلية دون أي اختلاق.
- صِغ ردودك بشكل واضح وسلس يناسب القراءة والنطق الصوتي المباشر.
${forensicContext ? `\nملخص حالة المنصة:\n${forensicContext}` : ''}
${structuredSnapshotText ? `\nالبيانات الحقيقية المباشرة لمنصة المستخدم الآن:\n${structuredSnapshotText}` : ''}
${osintFindings.length > 0 ? `\nنتائج فحص OSINT الحية للمؤشرات المذكورة:\n${osintFindings.join('\n')}` : ''}
${historyBlock}`;

    // Direct Gemini API Integration (AI Studio & Vercel GEMINI_API_KEY)
    const apiKey =
      process.env.GEMINI_API_KEY ||
      process.env.GOOGLE_GENERATIVE_AI_API_KEY ||
      process.env.GOOGLE_API_KEY ||
      process.env.VITE_GEMINI_API_KEY;

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
          'استمع إلى رسالة المستخدم الصوتية وتفاعل معها بذكاء وطلاقة كخبير تحقيق رقمي وأمن سيبراني.',
      });

      for (const modelName of ['gemini-4-hydrogen', 'gemini-2.5-flash', 'gemini-2.0-flash']) {
        try {
          const response = await ai.models.generateContent({
            model: modelName,
            contents: { parts },
            config: {
              systemInstruction,
            },
          });

          const replyText = (response.text || '').trim();
          if (replyText) {
            let audioPcmBase64: string | null = null;
            for (const ttsModel of ['gemini-3.8-flash-lite-tts', 'gemini-2.5-flash-preview-tts']) {
              try {
                const ttsResponse = await ai.models.generateContent({
                  model: ttsModel,
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
                  break;
                }
              } catch {
                // try next TTS model or let browser speech synthesis read replyText
              }
            }

            return res.status(200).json({
              success: true,
              engine: modelName,
              replyText,
              recognizedText: effectiveQuery || undefined,
              audioPcmBase64,
              sampleRate: 24000,
              useBrowserTts: !audioPcmBase64,
            });
          }
        } catch {
          // Try next Gemini model
        }
      }
    }

    // Safe arithmetic check
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

    // Open Generative LLM when GEMINI_API_KEY is absent on external Vercel deployment
    if (effectiveQuery) {
      const openAiReply = await queryOpenLlmFallback(systemInstruction, history, effectiveQuery);
      if (openAiReply) {
        return res.status(200).json({
          success: true,
          engine: 'sovereign-ai-gateway',
          replyText: openAiReply,
          recognizedText: effectiveQuery,
          audioPcmBase64: null,
          sampleRate: 24000,
          useBrowserTts: true,
        });
      }
    }

    // Conversational + Real Site Data response (NO Wikipedia or dictionary lookups!)
    const finalReply = buildConversationalAndSiteDataReply(
      effectiveQuery || 'مرحبا',
      siteData,
      osintFindings
    );

    return res.status(200).json({
      success: true,
      engine: 'sovereign-forensic-core',
      replyText: finalReply,
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
