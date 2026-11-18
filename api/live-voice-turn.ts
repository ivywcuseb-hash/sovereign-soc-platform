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
    const res = await fetch(url, { ...options, signal: controller.signal });
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
    const cveData = await fetchJsonWithTimeout(`https://cve.circl.lu/api/cve/${encodeURIComponent(cveId)}`);
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
        `فحص ثغرة ${cveId} (بيانات CIRCL CVE الحية): درجة الخطورة CVSS = ${cvss}. الوصف: ${String(summary).slice(0, 260)}`
      );
    }
  }

  // 2. IPv4 lookup via ipwho.is
  const ipMatch = prompt.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/);
  if (ipMatch) {
    const ip = ipMatch[0];
    const ipData = await fetchJsonWithTimeout(`https://ipwho.is/${encodeURIComponent(ip)}`);
    if (ipData && ipData.success !== false) {
      findings.push(
        `فحص عنوان IP الحي (${ip}): الدولة ${ipData.country || 'غير معروفة'} (${ipData.city || '—'})، المزود ISP: ${ipData.connection?.isp || ipData.connection?.org || '—'}، رقم ASN: ${ipData.connection?.asn || '—'}.`
      );
    }
  }

  // 3. Domain DNS-over-HTTPS lookup
  const domainMatch = prompt.match(/\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:com|net|org|io|app|gov|edu|ru|cn|ir|iq|sa|ae|uk|de|xyz|info|biz|me|co))\b/i);
  if (domainMatch && !ipMatch) {
    const domain = domainMatch[1].toLowerCase();
    const dnsData = await fetchJsonWithTimeout(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { Accept: 'application/dns-json' } }
    );
    if (dnsData && Array.isArray(dnsData.Answer)) {
      const ips = dnsData.Answer.filter((a: any) => a.type === 1).map((a: any) => a.data).slice(0, 4);
      if (ips.length > 0) {
        findings.push(`سجلات DNS الحية للنطاق ${domain}: يشير إلى عناوين IP التالية (${ips.join('، ')}).`);
      }
    }
  }

  // 4. SHA-256 MalwareBazaar lookup
  const shaMatch = prompt.match(/\b[a-f0-9]{64}\b/i);
  if (shaMatch) {
    const hash = shaMatch[0].toLowerCase();
    const form = new URLSearchParams({ query: 'get_info', hash });
    const mb = await fetchJsonWithTimeout('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    if (mb) {
      if (mb.query_status === 'ok' && Array.isArray(mb.data) && mb.data[0]) {
        const sample = mb.data[0];
        findings.push(
          `تنبيه خطير! البصمة ${hash.slice(0, 14)}... مسجلة في قاعدة MalwareBazaar كبرمجية خبيثة (${sample.signature || sample.file_type || 'Malware'}).`
        );
      } else if (mb.query_status === 'hash_not_found') {
        findings.push(`فحص MalwareBazaar للبصمة ${hash.slice(0, 14)}...: غير مدرجة في قوائم البرمجيات الخبيثة المعروفة.`);
      }
    }
  }

  return findings;
}

function buildLiveDataReply(
  userQuery: string,
  siteData: SiteDataSnapshot | null,
  osintFindings: string[],
  forensicContext: string
): string {
  const q = (userQuery || '').trim().toLowerCase();
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
  const telemetry = siteData?.telemetry || [];

  // If live OSINT results matched an indicator in the query, lead with those!
  if (osintFindings.length > 0) {
    const localMatches = evidence
      .filter((e) => q.includes(e.fileName.toLowerCase()) || (e.sha256 && q.includes(e.sha256.toLowerCase())))
      .map((e) => `ملف مطابق في أدلتك: ${e.fileName} (${e.verdict || 'مفحوص'}، الخطر: ${e.riskLevel || '—'}).`);
    return [...osintFindings, ...localMatches].join(' ');
  }

  // Greeting / intro
  if (
    !q ||
    /^(هلو|مرحبا|اهلا|أهلا|السلام|سلام|صباح|مساء|hi|hello|hey|test|اختبار)\b/i.test(q) ||
    q.length <= 4
  ) {
    const userTitle = siteData?.userName ? ` ${siteData.userName}` : '';
    const latestFile = evidence[0]?.fileName || auditLogs[0]?.fileName;
    const latestFeed = feeds[0]?.title;
    return [
      `أهلاً بك${userTitle} في المساعد الصوتي الجنائي لمنصة Sovereign.`,
      `حالة موقعك الحقيقية الآن: لديك ${counts.evidence} دليل رقمي محفوظ، ${counts.auditLogs} سجل عمليات، ${counts.investigations} ملف قضية، و${counts.liveFeeds} مؤشر تغذية تهديدات حية (${counts.criticalAlerts} تنبيه حرج أو مرتفع).`,
      latestFile ? `آخر ملف تم فحصه: ${latestFile}.` : '',
      latestFeed ? `أحدث تهديد مرصود بالتغذيات الحية: ${latestFeed}.` : '',
      `اسألني مباشرة عن الأدلة أو الثغرات أو أي عنوان IP أو رابط أو بصمة SHA-256 وسأجيبك صوتياً من البيانات الفعلية.`,
    ]
      .filter(Boolean)
      .join(' ');
  }

  // Evidence & uploaded files
  if (/(دليل|الأدلة|ادلة|ملف|ملفات|فحص|بصمة|hash|sha|ela|apk|متصفح)/i.test(q)) {
    const parts: string[] = [];
    if (siteData?.currentAnalysis) {
      const cur = siteData.currentAnalysis;
      parts.push(
        `التحليل النشط حالياً هو للملف ${cur.fileName} (النوع الحقيقي: ${cur.detectedFileType})، النتيجة: ${cur.verdict}، مستوى الخطورة: ${cur.riskLevel}، درجة الأصالة: ${cur.authenticityScore}%، بصمة SHA-256 تبدأ بـ ${cur.sha256.slice(0, 12)}.`
      );
    }
    if (siteData?.apkResult) {
      parts.push(
        `آخر حزمة APK محللة: ${siteData.apkResult.fileName} (الحزمة: ${siteData.apkResult.packageName || '—'}، عدد الأذونات: ${siteData.apkResult.permissionsCount ?? 0}).`
      );
    }
    if (siteData?.browserResult) {
      parts.push(
        `آخر قاعدة متصفح مفحوصة: ${siteData.browserResult.fileName} بإجمالي ${siteData.browserResult.totalUrlsCount ?? 0} رابط منها ${siteData.browserResult.flaggedUrlsCount ?? 0} رابط مشبوه.`
      );
    }
    if (evidence.length > 0) {
      const topEv = evidence
        .slice(0, 4)
        .map((e, idx) => `${idx + 1}: ${e.fileName} (${e.riskLevel || 'غير مصنف'} - ${e.verdict || 'محفوظ'})`)
        .join('، ');
      parts.push(`إجمالي الأدلة المحفوظة ${evidence.length}. أحدثها: ${topEv}.`);
    } else {
      parts.push('لا توجد أدلة مرفوعة في الخزنة السحابية حالياً؛ يمكنك رفع صورة أو مستند أو حزمة APK من قسم التحليل ليتم توثيقها فوراً.');
    }
    return parts.join(' ');
  }

  // Threat feeds & CVEs & vulnerabilities
  if (/(تهديد|ثغرة|ثغرات|cve|kev|تغذية|تغذيات|هجوم|اختراق|مخاطر|أخطر|اخطر)/i.test(q)) {
    if (feeds.length > 0) {
      const critical = feeds.filter((f) => f.severity === 'critical' || f.severity === 'high');
      const list = (critical.length > 0 ? critical : feeds)
        .slice(0, 4)
        .map((f, i) => `${i + 1}: ${f.title}${f.indicator ? ` (${f.indicator})` : ''} بدرجة ${f.severityAr || f.severity}`)
        .join('؛ ');
      return `يوجد حالياً ${feeds.length} مؤشر تهديد حي من المصادر المفتوحة، منها ${critical.length} بمستوى حرج أو مرتفع. أبرزها: ${list}.`;
    }
    if (auditLogs.length > 0) {
      const riskyLogs = auditLogs.filter((l) => l.risk === 'حرج' || l.risk === 'مرتفع');
      return `من واقع سجلات موقعك، تم تسجيل ${auditLogs.length} عملية فحص، من بينها ${riskyLogs.length} تنبيهات عالية الخطورة. يمكنك مزامنة التغذيات الحية من قسم التغذيات أو لوحة KEV لجلب أحدث ثغرات اليوم.`;
    }
    return 'لا توجد مؤشرات تغذية محملة في هذه اللحظة؛ افتح قسم التغذيات الحية أو لوحة ثغرات KEV واضغط مزامنة فورية لجلب البيانات الحقيقية.';
  }

  // Audit logs & telemetry & investigations
  if (/(سجل|السجل|العمليات|قضية|قضايا|تحقيق|حيازة|تقرير|تقارير|تيليمتري|نظام|حالة|ملخص|احصائيات|إحصائيات|كلشي|كل شيء|بيانات|موقعي)/i.test(q)) {
    const parts: string[] = [
      `ملخص البيانات الحقيقية في موقعك الآن: ${counts.investigations} قضية تحقيق، ${counts.evidence} دليل رقمي، ${counts.auditLogs} سجل فحص، ${counts.custody} قيد سلسلة حيازة، ${counts.savedReports} تقرير موثق، و${counts.liveFeeds} تغذية تهديدات حية.`,
    ];
    if (investigations.length > 0) {
      parts.push(`أحدث القضايا: ${investigations.slice(0, 3).map((i) => i.title).join('، ')}.`);
    }
    if (auditLogs.length > 0) {
      const topLogs = auditLogs
        .slice(0, 3)
        .map((l) => `${l.fileName} (${l.verdict || l.risk || 'مكتمل'})`)
        .join('، ');
      parts.push(`آخر العمليات المسجلة: ${topLogs}.`);
    }
    if (telemetry.length > 0 && telemetry[0]?.message) {
      parts.push(`آخر حدث تقني بالمنصة: ${telemetry[0].message}.`);
    }
    if (siteData?.threatIntelResult?.indicator) {
      parts.push(
        `آخر فحص استخباراتي كان للمؤشر ${siteData.threatIntelResult.indicator} بنتيجة: ${siteData.threatIntelResult.verdict || 'مكتمل'}.`
      );
    }
    return parts.join(' ');
  }

  // General real-data grounded answer
  const fallbackContextLine = forensicContext ? `ملخص حالتك الحالية: ${forensicContext}.` : '';
  return [
    `تم استلام استفسارك: "${userQuery}".`,
    fallbackContextLine,
    `البيانات النشطة الآن في موقعك تتضمن ${counts.evidence} دليل محفوظ و${counts.auditLogs} عملية فحص و${counts.liveFeeds} مؤشر تهديد حي.`,
    `لتحليل محدد بالصوت أو النص، يمكنك سؤالي عن: الأدلة والملفات، أخطر التهديدات والثغرات، سجل العمليات، أو كتابة أي عنوان IP أو CVE أو نطاق أو بصمة SHA-256 لفحصه فوراً.`,
  ]
    .filter(Boolean)
    .join(' ');
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
    const textPrompt = typeof bodyObj.text === 'string' ? bodyObj.text.trim().slice(0, 3000) : '';
    const transcript = typeof bodyObj.transcript === 'string' ? bodyObj.transcript.trim().slice(0, 3000) : '';
    const voiceName = ['Zephyr', 'Puck', 'Charon', 'Kore', 'Fenrir'].includes(bodyObj.voiceName)
      ? bodyObj.voiceName
      : 'Zephyr';
    const forensicContext = typeof bodyObj.forensicContext === 'string' ? bodyObj.forensicContext.slice(0, 5000) : '';
    const siteData: SiteDataSnapshot | null =
      bodyObj.siteData && typeof bodyObj.siteData === 'object' ? bodyObj.siteData : null;
    const history: Array<{ role: string; text: string }> = Array.isArray(bodyObj.history)
      ? bodyObj.history.slice(-8)
      : [];

    const effectiveQuery = textPrompt || transcript;

    if (!audioBase64 && !effectiveQuery) {
      return res.status(400).json({ error: 'يرجى التحدث أو كتابة رسالة للمساعد.' });
    }

    // Run real-time open-source indicator enrichment if the user mentioned IP / CVE / Domain / SHA256
    const osintFindings = effectiveQuery ? await lookupLiveOsintFromPrompt(effectiveQuery) : [];

    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && apiKey !== 'dummy-key') {
      try {
        const ai = new GoogleGenAI({
          apiKey,
          httpOptions: {
            headers: {
              'User-Agent': 'aistudio-build',
            },
          },
        });

        const structuredSnapshotText = siteData
          ? JSON.stringify(
              {
                user: siteData.userName || siteData.userEmail || 'Analyst',
                counts: siteData.counts,
                recentEvidence: (siteData.evidence || []).slice(0, 8),
                recentAuditLogs: (siteData.auditLogs || []).slice(0, 10),
                recentInvestigations: (siteData.investigations || []).slice(0, 6),
                recentLiveFeeds: (siteData.liveFeeds || []).slice(0, 10),
                currentAnalysis: siteData.currentAnalysis,
                apkResult: siteData.apkResult,
                browserResult: siteData.browserResult,
                threatIntelResult: siteData.threatIntelResult,
                recentTelemetry: (siteData.telemetry || []).slice(0, 6),
              },
              null,
              2
            ).slice(0, 9000)
          : '';

        const historyBlock =
          history.length > 0
            ? `\nالمحادثة السابقة:\n${history
                .map((h) => `${h.role === 'user' ? 'المستخدم' : 'المساعد'}: ${String(h.text || '').slice(0, 350)}`)
                .join('\n')}`
            : '';

        const systemInstruction = `أنت المساعد الصوتي الجنائي الذكي لمنصة SOVEREIGN FORENSIC ENGINE.
تتحدث العربية بطلاقة واحترافية (ويمكنك الرد بالإنجليزية إذا خاطبك المستخدم بها).
أجب دائماً استناداً إلى البيانات الحقيقية المرفقة من موقع المستخدم وأدواته وقاعدة بياناته، ولا تختلق أبداً ملفات أو ثغرات غير موجودة.
اجعل ردودك واضحة، طبيعية، ومناسبة للقراءة والاستماع الصوتي المباشر.
${forensicContext ? `\nملخص السياق الحي للمنصة:\n${forensicContext}` : ''}
${structuredSnapshotText ? `\nالبيانات الحقيقية الكاملة الحالية في حساب وموقع المستخدم:\n${structuredSnapshotText}` : ''}
${osintFindings.length > 0 ? `\nنتائج الفحص الخارجي الحي للمؤشرات المذكورة في السؤال:\n${osintFindings.join('\n')}` : ''}
${historyBlock}`;

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
            'استمع إلى رسالة المستخدم الصوتية وأجب عليها مباشرة بوضوح وبالاعتماد على البيانات الحقيقية المتوفرة للمنصة.',
        });

        const response = await ai.models.generateContent({
          model: 'gemini-4-hydrogen',
          contents: { parts },
          config: { systemInstruction },
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
            // Client falls back to Web Speech Synthesis automatically when audioPcmBase64 is null
          }

          return res.status(200).json({
            success: true,
            engine: 'gemini-4-hydrogen+tts',
            replyText,
            recognizedText: effectiveQuery || undefined,
            audioPcmBase64,
            sampleRate: 24000,
            useBrowserTts: !audioPcmBase64,
          });
        }
      } catch {
        // Fall through cleanly to real-data Sovereign Intelligence Core
      }
    }

    // Real-Data Sovereign Intelligence Core fallback (works on Vercel without GEMINI_API_KEY)
    const replyText = buildLiveDataReply(effectiveQuery, siteData, osintFindings, forensicContext);
    return res.status(200).json({
      success: true,
      engine: 'sovereign-live-data-core',
      replyText,
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
