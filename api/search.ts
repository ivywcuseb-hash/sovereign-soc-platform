import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import { GoogleGenAI } from '@google/genai';

function sanitizeControlChars(input: unknown, maxLen = 1000): string {
  return String(input || '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .slice(0, maxLen);
}

function wrapUntrustedBlock(label: string, content: unknown, maxLen = 1000): string {
  return `<<<BEGIN_${label}>>>\n${sanitizeControlChars(content, maxLen)}\n<<<END_${label}>>>`;
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

function isPrivateOrReservedIp(ip: string): boolean {
  const clean = ip.replace(/^::ffff:/i, '');
  if (!net.isIP(clean)) return true;
  if (
    clean === '::1' ||
    clean === '::' ||
    clean.startsWith('fe80:') ||
    clean.startsWith('fc') ||
    clean.startsWith('fd')
  ) {
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

function assertNoSsrfInQuery(rawQuery: string): void {
  const trimmed = rawQuery.trim();
  if (/(?:file:\/\/|gopher:\/\/|ftp:\/\/|169\.254\.169\.254|metadata\.google\.internal)/i.test(trimmed)) {
    throw new Error('تم حجب الاستعلام أمنياً: يحتوي على بروتوكول أو عنوان بيانات وصفية محظور (SSRF Protection).');
  }

  const ipsInQuery =
    trimmed.match(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g) || [];
  for (const ip of ipsInQuery) {
    if (isPrivateOrReservedIp(ip)) {
      throw new Error(`تم حجب الاستعلام أمنياً: عنوان IP الداخلي أو المحجوز (${ip}) مرفوض (SSRF Protection).`);
    }
  }

  const urls = trimmed.match(/https?:\/\/[^\s]+/gi) || [];
  for (const u of urls) {
    try {
      const host = new URL(u).hostname.toLowerCase();
      if (
        host === 'localhost' ||
        host.endsWith('.local') ||
        host.endsWith('.internal') ||
        host.endsWith('.localhost') ||
        (net.isIP(host) && isPrivateOrReservedIp(host))
      ) {
        throw new Error(`تم حجب الاستعلام أمنياً: النطاق الداخلي (${host}) محظور (SSRF Protection).`);
      }
    } catch (e: any) {
      if (e?.message?.includes('SSRF')) throw e;
    }
  }

  if (/\b(?:localhost|127\.0\.0\.1|::1)\b/i.test(trimmed) || /\.[a-z0-9-]+\.(?:local|internal)\b/i.test(trimmed)) {
    throw new Error('تم حجب الاستعلام أمنياً: الاستعلام عن المضيفات المحلية والداخلية مرفوض (SSRF Protection).');
  }
}

async function fetchJsonWithTimeout(url: string, timeoutMs = 5500): Promise<any> {
  const res = await fetch(url, {
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      Accept: 'application/json',
      'User-Agent': 'SovereignForensicEngine/2.5 (OSINT Search)',
    },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return await res.json();
}

async function runLivePublicOsintSearch(queryText: string): Promise<{
  result: string;
  sources: Array<{ title: string; uri: string }>;
}> {
  const sources: Array<{ title: string; uri: string }> = [];
  const blocks: string[] = [];
  let anyUpstreamAttempted = false;
  let anyUpstreamSuccess = false;

  const cveMatch = queryText.match(/CVE-\d{4}-\d{4,7}/i);
  if (cveMatch) {
    const cveId = cveMatch[0].toUpperCase();
    anyUpstreamAttempted = true;
    const [circlRes, epssRes] = await Promise.allSettled([
      fetchJsonWithTimeout(`https://cve.circl.lu/api/cve/${encodeURIComponent(cveId)}`),
      fetchJsonWithTimeout(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`),
    ]);
    if (circlRes.status === 'fulfilled' && circlRes.value) {
      anyUpstreamSuccess = true;
      const d = circlRes.value;
      const desc =
        d.summary ||
        d.containers?.cna?.descriptions?.[0]?.value ||
        d.descriptions?.[0]?.value ||
        'مسجل في قاعدة CIRCL CVE.';
      const cvss =
        d.cvss ||
        d.containers?.cna?.metrics?.[0]?.cvssV3_1?.baseScore ||
        d.containers?.cna?.metrics?.[0]?.cvssV3_0?.baseScore ||
        'غير محدد';
      blocks.push(`• الثغرة ${cveId} (CVSS: ${cvss}): ${String(desc).slice(0, 420)}`);
      sources.push({ title: `CIRCL CVE ${cveId}`, uri: `https://cve.circl.lu/vuln/${encodeURIComponent(cveId)}` });
      sources.push({ title: `NVD ${cveId}`, uri: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` });
    }
    if (epssRes.status === 'fulfilled' && Array.isArray(epssRes.value?.data) && epssRes.value.data[0]) {
      anyUpstreamSuccess = true;
      const e = epssRes.value.data[0];
      blocks.push(
        `• احتمالية الاستغلال (FIRST EPSS): ${(Number(e.epss) * 100).toFixed(2)}% (Percentile: ${(Number(e.percentile) * 100).toFixed(1)}%)`
      );
      sources.push({ title: 'FIRST EPSS API', uri: `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}` });
    }
  }

  const trimmed = queryText.trim();
  const bareTarget = /^https?:\/\//i.test(trimmed)
    ? (() => {
        try {
          return new URL(trimmed).hostname;
        } catch {
          return '';
        }
      })()
    : trimmed;

  if (net.isIP(bareTarget) && !isPrivateOrReservedIp(bareTarget)) {
    anyUpstreamAttempted = true;
    const [geoRes, ptrRes] = await Promise.allSettled([
      fetchJsonWithTimeout(`https://ipwho.is/${encodeURIComponent(bareTarget)}`),
      dns.reverse(bareTarget),
    ]);
    if (geoRes.status === 'fulfilled' && geoRes.value?.success) {
      anyUpstreamSuccess = true;
      const g = geoRes.value;
      blocks.push(
        `• بيانات IP الحية (${bareTarget}): الدولة ${g.country || '—'} (${g.city || '—'}) | المزود: ${g.connection?.isp || '—'} | ASN: ${g.connection?.asn ? `AS${g.connection.asn}` : '—'}`
      );
      sources.push({ title: 'IP Geolocation Registry', uri: `https://ipwho.is/${encodeURIComponent(bareTarget)}` });
    }
    if (ptrRes.status === 'fulfilled' && ptrRes.value.length > 0) {
      anyUpstreamSuccess = true;
      blocks.push(`• السجل العكسي PTR: ${ptrRes.value.join(', ')}`);
    }
  } else if (/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(bareTarget)) {
    anyUpstreamAttempted = true;
    const [aRes, mxRes, rdapRes] = await Promise.allSettled([
      dns.resolve4(bareTarget),
      dns.resolveMx(bareTarget),
      fetchJsonWithTimeout(`https://rdap.org/domain/${encodeURIComponent(bareTarget)}`),
    ]);
    if (aRes.status === 'fulfilled' && aRes.value.length > 0) {
      anyUpstreamSuccess = true;
      blocks.push(`• سجلات A الحية للنطاق ${bareTarget}: ${aRes.value.slice(0, 6).join(', ')}`);
    }
    if (mxRes.status === 'fulfilled' && mxRes.value.length > 0) {
      anyUpstreamSuccess = true;
      blocks.push(`• خوادم البريد MX: ${mxRes.value.slice(0, 4).map((m) => m.exchange).join(', ')}`);
    }
    if (rdapRes.status === 'fulfilled' && rdapRes.value) {
      anyUpstreamSuccess = true;
      const reg = rdapRes.value.ldhName || bareTarget;
      blocks.push(`• سجل RDAP الرسمي للنطاق: ${reg} (الحالة: ${(rdapRes.value.status || []).slice(0, 3).join(', ') || 'مسجل'})`);
      sources.push({ title: `RDAP ${bareTarget}`, uri: `https://rdap.org/domain/${encodeURIComponent(bareTarget)}` });
    }
  }

  // General keyword CVE / Threat Advisory search via NVD v2 + GitHub Advisories
  if (blocks.length === 0) {
    anyUpstreamAttempted = true;
    const [nvdRes, ghRes] = await Promise.allSettled([
      fetchJsonWithTimeout(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(trimmed)}&resultsPerPage=5`,
        6500
      ),
      fetchJsonWithTimeout('https://api.github.com/advisories?per_page=15', 5500),
    ]);

    if (nvdRes.status === 'fulfilled' && Array.isArray(nvdRes.value?.vulnerabilities)) {
      anyUpstreamSuccess = true;
      for (const v of nvdRes.value.vulnerabilities.slice(0, 5)) {
        const cve = v.cve;
        if (!cve?.id) continue;
        const desc =
          cve.descriptions?.find((d: any) => d.lang === 'en')?.value ||
          cve.descriptions?.[0]?.value ||
          '';
        blocks.push(`• ${cve.id}: ${String(desc).slice(0, 220)}`);
        sources.push({ title: `NVD ${cve.id}`, uri: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}` });
      }
    }

    if (ghRes.status === 'fulfilled' && Array.isArray(ghRes.value)) {
      anyUpstreamSuccess = true;
      const kw = trimmed.toLowerCase();
      const matched = ghRes.value
        .filter((a: any) => `${a.summary || ''} ${a.description || ''} ${a.cve_id || ''}`.toLowerCase().includes(kw))
        .slice(0, 4);
      for (const adv of matched) {
        blocks.push(`• [GitHub Advisory ${adv.ghsa_id || ''}] ${adv.summary || adv.cve_id}`);
        if (adv.html_url) {
          sources.push({ title: adv.ghsa_id || 'GitHub Advisory', uri: sanitizePublicUrl(adv.html_url) });
        }
      }
    }
  }

  if (anyUpstreamAttempted && !anyUpstreamSuccess) {
    throw new Error('UPSTREAM_SEARCH_UNAVAILABLE');
  }

  if (blocks.length === 0) {
    return {
      result: `تم تنفيذ الاستعلام الحي في قواعد الثغرات والمصادر المفتوحة لعبارة "${trimmed}"، ولم يُعثر على نتائج مطابقة.`,
      sources: [],
    };
  }

  return {
    result: `نتائج الاستعلام الحي من المصادر المفتوحة:\n\n${blocks.join('\n')}`,
    sources: sources.filter((s) => Boolean(s.uri)).slice(0, 10),
  };
}

export default async function handler(req: any, res: any) {
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  let bodyObj: Record<string, any> = {};
  try {
    bodyObj = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {};
  } catch {
    return res.status(400).json({ error: 'صيغة JSON المرسلة غير صالحة.' });
  }

  const rawQuery = bodyObj.query;
  if (typeof rawQuery !== 'string' || !rawQuery.trim() || rawQuery.trim().length > 1000) {
    return res.status(400).json({ error: 'يرجى إدخال نص بحث صالح (بحد أقصى 1000 حرف).' });
  }

  const queryText = rawQuery.trim();

  try {
    assertNoSsrfInQuery(queryText);
  } catch (ssrfErr: any) {
    return res.status(400).json({ error: ssrfErr?.message || 'تم حجب الاستعلام أمنياً (SSRF Protection).' });
  }

  const apiKey =
    process.env.GEMINI_API_KEY ||
    process.env.GOOGLE_GENERATIVE_AI_API_KEY ||
    process.env.GOOGLE_API_KEY;

  if (apiKey && apiKey !== 'dummy-key') {
    try {
      const genaiClient = new GoogleGenAI({
        apiKey,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
      const response = await genaiClient.models.generateContent({
        model: 'gemini-4-hydrogen',
        contents: wrapUntrustedBlock('SEARCH_QUERY', queryText, 1000),
        config: { tools: [{ googleSearch: {} }] },
      });
      const text = (response.text || '').trim();
      if (!text) {
        return res.status(502).json({ error: 'لم يُرجع محرك البحث الموجه أي محتوى.' });
      }
      const sources = (response.candidates?.[0]?.groundingMetadata?.groundingChunks || [])
        .map((chunk: any) => ({
          title: sanitizeControlChars(chunk?.web?.title || 'مصدر', 180),
          uri: sanitizePublicUrl(chunk?.web?.uri),
        }))
        .filter((s: { title: string; uri: string }) => Boolean(s.uri));

      return res.status(200).json({ result: text, sources });
    } catch (gemErr: any) {
      const msg = String(gemErr?.message || '');
      const status = gemErr?.status && typeof gemErr.status === 'number' ? gemErr.status : 502;
      return res.status(status >= 400 ? status : 502).json({
        error: /API_KEY_INVALID|PERMISSION_DENIED/i.test(msg)
          ? 'مفتاح التشغيل التشغيلي لخدمة البحث غير صالح (GEMINI_API_KEY).'
          : 'تعذر إتمام البحث الموجه عبر محرك البحث الخلفي.',
      });
    }
  }

  // Real live open-source search when GEMINI_API_KEY is not configured on Vercel
  try {
    const liveResult = await runLivePublicOsintSearch(queryText);
    return res.status(200).json(liveResult);
  } catch (err: any) {
    return res.status(503).json({
      error:
        err?.message === 'UPSTREAM_SEARCH_UNAVAILABLE'
          ? 'تعذر الاتصال بمصادر الاستخبارات والبحث المفتوحة حالياً؛ يرجى المحاولة مجدداً أو ضبط GEMINI_API_KEY.'
          : 'تعذر تنفيذ الاستعلام الحي في المصادر المفتوحة.',
    });
  }
}
