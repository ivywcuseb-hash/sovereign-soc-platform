import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Search,
  Copy,
  Check,
  RotateCcw,
  AlertTriangle,
  RefreshCw,
  FileJson,
  Globe,
  Link2,
  Server,
  CheckCircle2,
  XCircle,
  Lock,
  Unlock,
} from 'lucide-react';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface PhishingUrlDeepInspectorLabProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

export type DohProviderId = 'cloudflare' | 'google';

interface DohJsonAnswer {
  name?: string;
  type?: number;
  TTL?: number;
  data?: string;
}

interface DohJsonResponse {
  Status?: number;
  AD?: boolean;
  Answer?: DohJsonAnswer[];
}

interface ParsedDnsEntry {
  type: string;
  name: string;
  ttl: number;
  data: string;
}

interface TechnicalIndicatorItem {
  key: string;
  label: string;
  triggered: boolean;
  severity: 'risk' | 'warn' | 'ok';
  detail: string;
}

interface UrlStructureBreakdown {
  originalInput: string;
  normalizedUrl: string;
  protocol: string;
  protocolExplicit: boolean;
  username: string;
  passwordPresent: boolean;
  hostname: string;
  asciiHostname: string;
  registrableDomain: string | null;
  subdomains: string[];
  port: string;
  portIsDefault: boolean;
  pathname: string;
  queryString: string;
  queryParams: Array<{ key: string; value: string }>;
  hashFragment: string;
  isDirectIpHost: boolean;
}

interface DnsResolutionSummary {
  skippedReason?: string;
  provider: DohProviderId;
  providerLabel: string;
  queriedHostForA: string;
  queriedDomainForNs: string;
  aStatusCode: string;
  nsStatusCode: string;
  aRecords: ParsedDnsEntry[];
  nsRecords: ParsedDnsEntry[];
  domainActive: boolean;
  dnsError?: string;
  durationMs: number;
  rawA: DohJsonResponse | null;
  rawNs: DohJsonResponse | null;
}

interface PhishingUrlAuditReport {
  structure: UrlStructureBreakdown;
  indicators: TechnicalIndicatorItem[];
  dns: DnsResolutionSummary;
  inspectedAtIso: string;
}

const MULTI_PART_SUFFIXES = new Set([
  'gov.iq',
  'edu.iq',
  'com.iq',
  'org.iq',
  'net.iq',
  'mil.iq',
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.au',
  'net.au',
  'org.au',
  'edu.au',
  'gov.au',
  'com.sa',
  'gov.sa',
  'edu.sa',
  'org.sa',
  'com.ae',
  'gov.ae',
  'ac.ae',
  'com.eg',
  'edu.eg',
  'gov.eg',
  'com.jo',
  'gov.jo',
  'edu.jo',
  'com.tr',
  'gov.tr',
  'edu.tr',
  'co.jp',
  'ne.jp',
  'or.jp',
]);

const DNS_TYPE_CODES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
};

const DNS_RCODE_LABELS: Record<number, string> = {
  0: 'NOERROR',
  1: 'FORMERR',
  2: 'SERVFAIL',
  3: 'NXDOMAIN',
  4: 'NOTIMP',
  5: 'REFUSED',
};

function isLiteralIpHostname(hostname: string): boolean {
  const clean = hostname.replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return true;
  if (/^0x[0-9a-f]+$/i.test(clean) || /^\d+$/.test(clean)) return true; // integer/hex IP form
  if (clean.includes(':')) return true; // IPv6
  return false;
}

function extractDomainParts(hostname: string): {
  registrableDomain: string | null;
  subdomains: string[];
} {
  const clean = hostname.replace(/\.+$/, '').toLowerCase();
  if (!clean || isLiteralIpHostname(clean)) {
    return { registrableDomain: null, subdomains: [] };
  }
  const labels = clean.split('.').filter(Boolean);
  if (labels.length < 2) {
    return { registrableDomain: clean, subdomains: [] };
  }
  const lastTwo = `${labels[labels.length - 2]}.${labels[labels.length - 1]}`;
  const registrableCount = MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3 ? 3 : 2;
  const registrableDomain = labels.slice(-registrableCount).join('.');
  const subdomains = labels.slice(0, labels.length - registrableCount);
  return { registrableDomain, subdomains };
}

function parseAndValidateUrl(rawInput: string): {
  valid: boolean;
  structure?: UrlStructureBreakdown;
  error?: string;
} {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { valid: false, error: 'يرجى إدخال رابط (URL) صالح للفحص.' };
  }
  if (/\s/.test(trimmed)) {
    return { valid: false, error: 'الرابط يحتوي على مسافات غير صالحة. يرجى إدخال رابط متصل بدون فراغات.' };
  }

  // Reject dangerous or unsupported URI schemes explicitly
  const schemeMatch = trimmed.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):/);
  const hasExplicitDoubleSlash = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed);
  if (schemeMatch && !hasExplicitDoubleSlash) {
    const schemeLower = schemeMatch[1].toLowerCase();
    if (schemeLower !== 'http' && schemeLower !== 'https') {
      return {
        valid: false,
        error: `تم رفض المخطط غير الآمن أو غير المدعوم "${schemeLower}:". تدعم الأداة روابط http:// و https:// فقط.`,
      };
    }
  }
  if (hasExplicitDoubleSlash) {
    const scheme = trimmed.split('://')[0].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        valid: false,
        error: `البروتوكول "${scheme}://" غير مدعوم. أدخل رابطاً يبدأ بـ http:// أو https://.`,
      };
    }
  }

  const candidate = hasExplicitDoubleSlash ? trimmed : `http://${trimmed}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      valid: false,
      error: 'صيغة الرابط غير صالحة ولا يمكن تفكيكها. تأكد من كتابة رابط صحيح مثل https://example.com/login.',
    };
  }

  const hostname = parsed.hostname;
  if (!hostname) {
    return { valid: false, error: 'الرابط لا يحتوي على اسم مضيف (Hostname) صالح.' };
  }

  const directIp = isLiteralIpHostname(hostname);
  if (!directIp && !hostname.includes('.') && hostname !== 'localhost') {
    return {
      valid: false,
      error: `اسم المضيف "${hostname}" غير مكتمل ولا يحتوي على نطاق أعلى صالح (TLD).`,
    };
  }

  const { registrableDomain, subdomains } = extractDomainParts(hostname);
  const queryParams: Array<{ key: string; value: string }> = [];
  parsed.searchParams.forEach((value, key) => {
    queryParams.push({ key, value });
  });

  const effectivePort = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');

  return {
    valid: true,
    structure: {
      originalInput: trimmed,
      normalizedUrl: parsed.toString(),
      protocol: parsed.protocol.replace(':', '').toUpperCase(),
      protocolExplicit: hasExplicitDoubleSlash,
      username: parsed.username ? decodeURIComponentSafe(parsed.username) : '',
      passwordPresent: Boolean(parsed.password),
      hostname,
      asciiHostname: parsed.hostname,
      registrableDomain,
      subdomains,
      port: effectivePort,
      portIsDefault: !parsed.port,
      pathname: parsed.pathname || '/',
      queryString: parsed.search || '',
      queryParams,
      hashFragment: parsed.hash || '',
      isDirectIpHost: directIp,
    },
  };
}

function decodeURIComponentSafe(val: string): string {
  try {
    return decodeURIComponent(val);
  } catch {
    return val;
  }
}

function buildTechnicalIndicators(s: UrlStructureBreakdown): TechnicalIndicatorItem[] {
  const isUnencryptedHttp = s.protocol === 'HTTP';
  const hasAtObfuscation =
    Boolean(s.username) ||
    s.passwordPresent ||
    /^https?:\/\/[^/?#]*@/i.test(s.originalInput);
  const hasPunycode =
    s.hostname.toLowerCase().includes('xn--') || /[^\x00-\x7f]/.test(s.originalInput);
  const excessiveSubdomains = s.subdomains.length >= 3;
  const nonStandardPort = !s.portIsDefault && s.port !== '80' && s.port !== '443';

  return [
    {
      key: 'http_unencrypted',
      label: 'بروتوكول HTTP غير مشفر',
      triggered: isUnencryptedHttp,
      severity: isUnencryptedHttp ? 'risk' : 'ok',
      detail: isUnencryptedHttp
        ? s.protocolExplicit
          ? 'الرابط يستخدم http:// غير المشفر ولا يوفر تشفير TLS.'
          : 'لم يُذكر بروتوكول HTTPS في الرابط المدخل (يفتقر للتشفير الصريح).'
        : 'الرابط يستخدم HTTPS المشفر.',
    },
    {
      key: 'direct_ip_host',
      label: 'استخدام عنوان IP مباشر بدل اسم نطاق',
      triggered: s.isDirectIpHost,
      severity: s.isDirectIpHost ? 'risk' : 'ok',
      detail: s.isDirectIpHost
        ? `المضيف عبارة عن عنوان IP مباشر (${s.hostname}) وهي تقنية شائعة لتجاوز فلاتر السمعة.`
        : `يستخدم اسم نطاق نصي (${s.hostname}) وليس عنوان IP مباشر.`,
    },
    {
      key: 'punycode_idn',
      label: 'ترميز Punycode (xn--) أو أحرف دولية مموهة',
      triggered: hasPunycode,
      severity: hasPunycode ? 'risk' : 'ok',
      detail: hasPunycode
        ? `تم رصد ترميز Punycode (xn--) أو أحرف غير لاتينية في المضيف (${s.hostname}) قد تُستخدم في هجمات التشابه البصري (IDN Homograph).`
        : 'لا يحتوي المضيف على بادئة xn-- أو أحرف تمويه دولية.',
    },
    {
      key: 'at_symbol_obfuscation',
      label: 'استخدام رمز @ للتمويه في جزء العنوان',
      triggered: hasAtObfuscation,
      severity: hasAtObfuscation ? 'risk' : 'ok',
      detail: hasAtObfuscation
        ? `يحتوي جزء السلطة (Authority) على رمز @ (${s.username || 'userinfo'}@${s.hostname}) لإيهام المستخدم بنطاق مزيف قبل الرمز.`
        : 'لا يوجد تمويه برمز @ قبل اسم المضيف الحقيقي.',
    },
    {
      key: 'excessive_subdomains',
      label: 'تعدد النطاقات الفرعية المفرط',
      triggered: excessiveSubdomains,
      severity: excessiveSubdomains ? 'warn' : 'ok',
      detail: excessiveSubdomains
        ? `تم رصد ${s.subdomains.length} مستويات من النطاقات الفرعية (${s.subdomains.join('.')}) قبل النطاق المسجل (${s.registrableDomain}).`
        : s.subdomains.length > 0
        ? `عدد النطاقات الفرعية طبيعي (${s.subdomains.length}): ${s.subdomains.join('.')}.`
        : 'لا توجد نطاقات فرعية إضافية.',
    },
    {
      key: 'non_standard_port',
      label: 'استخدام منفذ غير قياسي',
      triggered: nonStandardPort,
      severity: nonStandardPort ? 'warn' : 'ok',
      detail: nonStandardPort
        ? `الرابط يستهدف منفذاً غير قياسي (${s.port}) بدلاً من 80/443.`
        : `المنفذ قياسي (${s.port}).`,
    },
  ];
}

async function queryDoh(
  qname: string,
  qtype: 'A' | 'NS',
  provider: DohProviderId,
  signal: AbortSignal
): Promise<DohJsonResponse> {
  const url =
    provider === 'cloudflare'
      ? `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(qname)}&type=${qtype}`
      : `https://dns.google/resolve?name=${encodeURIComponent(qname)}&type=${qtype}`;
  const res = await fetch(url, {
    method: 'GET',
    headers: { Accept: provider === 'cloudflare' ? 'application/dns-json' : 'application/json' },
    signal,
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} من خادم DoH (${provider})`);
  }
  const json = (await res.json()) as DohJsonResponse;
  if (!json || typeof json !== 'object') {
    throw new Error('استجابة DoH غير صالحة.');
  }
  return json;
}

function parseAnswers(json: DohJsonResponse | null): ParsedDnsEntry[] {
  if (!json || !Array.isArray(json.Answer)) return [];
  return json.Answer.map((ans) => {
    const t = Number(ans.type || 0);
    return {
      type: DNS_TYPE_CODES[t] || `TYPE${t}`,
      name: String(ans.name || '').replace(/\.$/, ''),
      ttl: typeof ans.TTL === 'number' ? ans.TTL : 0,
      data: String(ans.data || '').trim().replace(/\.$/, ''),
    };
  });
}

async function computeSha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export const PhishingUrlDeepInspectorLab: React.FC<PhishingUrlDeepInspectorLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [provider, setProvider] = useState<DohProviderId>('cloudflare');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [report, setReport] = useState<PhishingUrlAuditReport | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = async (text: string, key: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 1800);
      onNotify(`تم نسخ ${label} إلى الحافظة.`, 'success');
    } catch {
      onNotify('تعذر النسخ إلى الحافظة في هذا المتصفح.', 'warning');
    }
  };

  const handleReset = () => {
    setUrlInput('');
    setReport(null);
    setErrorMsg(null);
  };

  const runDeepInspect = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (loading) return;

    const parsedCheck = parseAndValidateUrl(urlInput);
    if (!parsedCheck.valid || !parsedCheck.structure) {
      setErrorMsg(parsedCheck.error || 'الرابط المدخل غير صالح.');
      setReport(null);
      onNotify(parsedCheck.error || 'الرابط المدخل غير صالح.', 'warning');
      return;
    }

    const structure = parsedCheck.structure;
    const indicators = buildTechnicalIndicators(structure);

    setLoading(true);
    setErrorMsg(null);
    setReport(null);

    const providerLabel =
      provider === 'cloudflare' ? 'Cloudflare DoH (1.1.1.1)' : 'Google Public DNS DoH (8.8.8.8)';

    // If literal IP or localhost, DNS query isn't applicable to domain names
    if (structure.isDirectIpHost || structure.hostname === 'localhost') {
      const dnsSummary: DnsResolutionSummary = {
        skippedReason: structure.isDirectIpHost
          ? `المضيف عنوان IP مباشر (${structure.hostname}) ولا يملك سجل نطاق A/NS في DNS.`
          : 'المضيف localhost محلي ولا يُستعلم عنه في DNS العام.',
        provider,
        providerLabel,
        queriedHostForA: structure.hostname,
        queriedDomainForNs: structure.registrableDomain || structure.hostname,
        aStatusCode: 'SKIPPED',
        nsStatusCode: 'SKIPPED',
        aRecords: [],
        nsRecords: [],
        domainActive: false,
        durationMs: 0,
        rawA: null,
        rawNs: null,
      };
      const finalReport: PhishingUrlAuditReport = {
        structure,
        indicators,
        dns: dnsSummary,
        inspectedAtIso: new Date().toISOString(),
      };
      setReport(finalReport);
      setLoading(false);

      const sha256 = await computeSha256Hex(JSON.stringify(finalReport));
      const riskHits = indicators.filter((i) => i.triggered && i.severity === 'risk').length;
      onRecordAudit({
        id: `url-deep-${Date.now()}`,
        fileName: `URL Deep Audit: ${structure.hostname}`,
        fileSize: `${indicators.filter((i) => i.triggered).length} flags`,
        verdict: `فحص بنية الرابط (${structure.hostname}): رصد ${riskHits} مؤشر خطورة`,
        score: riskHits > 0 ? 35 : 85,
        risk: riskHits > 0 ? 'مرتفع' : 'منخفض',
        sha256,
      });
      onNotify(`تم تفكيك الرابط واكتشاف ${riskHits} مؤشر خطورة تقني.`, 'warning');
      return;
    }

    const hostForA = structure.hostname;
    const domainForNs = structure.registrableDomain || structure.hostname;
    const startedAt = performance.now();
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 12000);

    try {
      const [resA, resNs] = await Promise.allSettled([
        queryDoh(hostForA, 'A', provider, controller.signal),
        queryDoh(domainForNs, 'NS', provider, controller.signal),
      ]);
      window.clearTimeout(timeoutId);
      const durationMs = Math.max(1, Math.round(performance.now() - startedAt));

      if (resA.status === 'rejected' && resNs.status === 'rejected') {
        const reason =
          resA.reason?.name === 'AbortError'
            ? 'انتهت مهلة الاتصال بخادم DoH.'
            : String(resA.reason?.message || 'فشل الاتصال بخادم DNS over HTTPS.');
        const errText = `تم تفكيك بنية الرابط لكن فشل استعلام DNS عبر ${providerLabel}: ${reason}`;
        setErrorMsg(errText);
        onNotify(errText, 'error');
        return;
      }

      const rawA = resA.status === 'fulfilled' ? resA.value : null;
      const rawNs = resNs.status === 'fulfilled' ? resNs.value : null;

      const aStatus = rawA && typeof rawA.Status === 'number' ? rawA.Status : -1;
      const nsStatus = rawNs && typeof rawNs.Status === 'number' ? rawNs.Status : -1;
      const aStatusCode = aStatus === -1 ? 'ERROR' : DNS_RCODE_LABELS[aStatus] || `RCODE_${aStatus}`;
      const nsStatusCode = nsStatus === -1 ? 'ERROR' : DNS_RCODE_LABELS[nsStatus] || `RCODE_${nsStatus}`;

      const aRecords = parseAnswers(rawA);
      const nsRecords = parseAnswers(rawNs);

      let dnsError: string | undefined;
      if (aStatus === 3 && nsStatus === 3) {
        dnsError = `النطاق "${domainForNs}" غير مسجل أو منتهٍ في نظام DNS العام (NXDOMAIN).`;
      } else if (resA.status === 'rejected') {
        dnsError = `تعذر جلب سجل A للمضيف ${hostForA}: ${resA.reason?.message || 'خطأ شبكة'}`;
      } else if (resNs.status === 'rejected') {
        dnsError = `تعذر جلب سجل NS للنطاق ${domainForNs}: ${resNs.reason?.message || 'خطأ شبكة'}`;
      } else if (aStatus !== 0 && aStatus !== 3) {
        dnsError = `أرجع استعلام A حالة خطأ: ${aStatusCode}`;
      }

      const domainActive = aRecords.length > 0 || nsRecords.length > 0;

      const finalReport: PhishingUrlAuditReport = {
        structure,
        indicators,
        dns: {
          provider,
          providerLabel,
          queriedHostForA: hostForA,
          queriedDomainForNs: domainForNs,
          aStatusCode,
          nsStatusCode,
          aRecords,
          nsRecords,
          domainActive,
          dnsError,
          durationMs,
          rawA,
          rawNs,
        },
        inspectedAtIso: new Date().toISOString(),
      };

      setReport(finalReport);

      const sha256 = await computeSha256Hex(JSON.stringify(finalReport));
      const riskHits = indicators.filter((i) => i.triggered && i.severity === 'risk').length;
      const warnHits = indicators.filter((i) => i.triggered && i.severity === 'warn').length;

      onRecordAudit({
        id: `url-deep-${Date.now()}`,
        fileName: `URL Deep Audit: ${hostForA}`,
        fileSize: `${aRecords.length} A · ${nsRecords.length} NS`,
        verdict: `${structure.protocol}://${hostForA} | مؤشرات الخطورة: ${riskHits} | DNS: ${
          domainActive ? 'نشط' : aStatusCode
        }`,
        score: riskHits > 0 ? 40 : warnHits > 0 ? 75 : 100,
        risk: riskHits > 0 ? 'مرتفع' : warnHits > 0 ? 'متوسط' : 'منخفض',
        sha256,
      });

      if (dnsError) {
        onNotify(dnsError, 'warning');
      } else {
        onNotify(
          `اكتمل الفحص التقني للرابط واستعلام DoH (${aRecords.length} سجل A · ${nsRecords.length} سجل NS).`,
          riskHits > 0 ? 'warning' : 'success'
        );
      }
    } catch (err: any) {
      window.clearTimeout(timeoutId);
      const errText =
        err?.name === 'AbortError'
          ? 'انتهت مهلة الاتصال بخادم DNS over HTTPS.'
          : err?.message || 'حدث خطأ أثناء فحص الرابط.';
      setErrorMsg(errText);
      onNotify(errText, 'error');
    } finally {
      setLoading(false);
    }
  };

  const copyFullReport = async () => {
    if (!report) return;
    const { structure, indicators, dns } = report;
    const lines = [
      `Phishing & URL Deep Inspector Technical Report`,
      `Inspected URL: ${structure.normalizedUrl}`,
      `Protocol: ${structure.protocol}${structure.protocolExplicit ? '' : ' (implicit in input)'}`,
      `Hostname: ${structure.hostname}`,
      `Registrable Domain: ${structure.registrableDomain || 'None (Direct IP)'}`,
      `Subdomains: ${structure.subdomains.length > 0 ? structure.subdomains.join('.') : 'None'}`,
      `Port: ${structure.port}${structure.portIsDefault ? ' (default)' : ''}`,
      `Path: ${structure.pathname}`,
      `Query Params (${structure.queryParams.length}): ${
        structure.queryParams.length > 0
          ? structure.queryParams.map((p) => `${p.key}=${p.value}`).join('&')
          : 'None'
      }`,
      '',
      '--- Technical Indicators ---',
      ...indicators.map((ind) => `[${ind.triggered ? 'TRIGGERED' : 'CLEAN'}] ${ind.label}: ${ind.detail}`),
      '',
      `--- Live DNS Resolution (${dns.providerLabel}) ---`,
      dns.skippedReason
        ? `Skipped: ${dns.skippedReason}`
        : `A (${dns.queriedHostForA}) [${dns.aStatusCode}]: ${
            dns.aRecords.length > 0 ? dns.aRecords.map((r) => `${r.type}=${r.data} (TTL ${r.ttl}s)`).join(', ') : 'None'
          }`,
      dns.skippedReason
        ? ''
        : `NS (${dns.queriedDomainForNs}) [${dns.nsStatusCode}]: ${
            dns.nsRecords.length > 0 ? dns.nsRecords.map((r) => `${r.data} (TTL ${r.ttl}s)`).join(', ') : 'None'
          }`,
    ].filter(Boolean);

    await handleCopy(lines.join('\n'), 'full-url-report', 'التقرير التقني الكامل');
  };

  const exportJson = () => {
    if (!report) return;
    const payload = {
      inspectedAt: report.inspectedAtIso,
      structure: report.structure,
      technicalIndicators: report.indicators,
      dnsResolution: {
        provider: report.dns.providerLabel,
        queriedHostForA: report.dns.queriedHostForA,
        queriedDomainForNs: report.dns.queriedDomainForNs,
        domainActive: report.dns.domainActive,
        aStatusCode: report.dns.aStatusCode,
        nsStatusCode: report.dns.nsStatusCode,
        aRecords: report.dns.aRecords,
        nsRecords: report.dns.nsRecords,
        durationMs: report.dns.durationMs,
        skippedReason: report.dns.skippedReason,
        dnsError: report.dns.dnsError,
        rawResponses: {
          A: report.dns.rawA,
          NS: report.dns.rawNs,
        },
      },
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `url-deep-report-${report.structure.hostname.replace(/[:[\]]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير التقرير التقني بصيغة JSON.`, 'success');
  };

  return (
    <div className="space-y-6">
      {/* Input & Controls */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-gray-800">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-[#D4AF37]" />
              <span>كاشف الروابط الاحتيالية ومحلل البنية (Phishing & URL Deep Inspector)</span>
            </h2>
            <p className="text-xs text-gray-400">
              تفكيك تقني لبنية أي رابط، ورصد مؤشرات التمويه (<span className="font-mono text-gray-200">HTTP · IP Host · Punycode xn-- · @ · Subdomains</span>)، والتحقق الحي من خوادم <span className="font-mono text-gray-200">A / NS</span> عبر DoH.
            </p>
          </div>

          <div className="flex items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800 shrink-0 self-start lg:self-auto">
            <button
              type="button"
              onClick={() => setProvider('cloudflare')}
              className={`px-3 py-1.5 rounded text-xs font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                provider === 'cloudflare'
                  ? 'bg-[#D4AF37] text-gray-950'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Cloudflare DoH
            </button>
            <button
              type="button"
              onClick={() => setProvider('google')}
              className={`px-3 py-1.5 rounded text-xs font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                provider === 'google'
                  ? 'bg-[#D4AF37] text-gray-950'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              Google DoH
            </button>
          </div>
        </div>

        <form onSubmit={runDeepInspect} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Link2 className="w-4 h-4 text-gray-500 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="ألصق الرابط الكامل للفحص (مثال: https://accounts.example.com:443/login?redirect=home)"
              dir="ltr"
              className="w-full bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl pr-10 pl-4 py-3 text-sm font-mono text-white placeholder-gray-500 outline-none transition"
            />
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="submit"
              disabled={loading}
              className="px-5 py-3 rounded-xl bg-[#D4AF37] hover:opacity-90 text-gray-950 font-bold text-xs inline-flex items-center justify-center gap-2 transition cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>جاري التحليل...</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  <span>فحص الرابط</span>
                </>
              )}
            </button>

            {(report || errorMsg || urlInput) && (
              <button
                type="button"
                onClick={handleReset}
                disabled={loading}
                className="px-4 py-3 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-300 font-bold text-xs inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>مسح</span>
              </button>
            )}
          </div>
        </form>

        {errorMsg && (
          <div className="rounded-xl bg-red-950/30 border border-red-500/40 p-4 flex items-start gap-3 text-xs text-red-200">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-red-300">خطأ في الفحص</div>
              <p className="text-red-200/90 leading-relaxed">{errorMsg}</p>
            </div>
          </div>
        )}
      </div>

      {/* Empty State */}
      {!loading && !report && !errorMsg && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-xl bg-gray-950 border border-gray-800 flex items-center justify-center mx-auto text-[#D4AF37]">
            <Link2 className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-bold text-white">في انتظار إدخال رابط للفحص التقني العميق</h3>
          <p className="text-xs text-gray-400 max-w-xl mx-auto leading-relaxed">
            أدخل أي رابط <span className="font-mono text-gray-200">http://</span> أو <span className="font-mono text-gray-200">https://</span> لتفكيك بنيته، وفحص مؤشرات التصيد والتمويه، والاستعلام المباشر عن سجلات DNS الحية للنطاق بدون فتح الرابط أو إرسال أي طلبات إليه.
          </p>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-xs text-[#D4AF37] font-bold">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>جاري تفكيك الرابط والاستعلام الحي عن سجلات A و NS عبر DoH...</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {[1, 2, 3].map((i) => (
              <div key={i} className="h-24 rounded-xl bg-gray-950 border border-gray-800 animate-pulse" />
            ))}
          </div>
        </div>
      )}

      {/* Real Inspection Report */}
      {report && !loading && (
        <div className="space-y-6">
          {/* Header Bar + Export */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-gray-800">
              <div className="space-y-1.5 min-w-0">
                <div className="flex flex-wrap items-center gap-2 text-sm font-bold text-white">
                  {report.structure.protocol === 'HTTPS' ? (
                    <Lock className="w-4 h-4 text-emerald-400 shrink-0" />
                  ) : (
                    <Unlock className="w-4 h-4 text-red-400 shrink-0" />
                  )}
                  <span className="font-mono text-[#D4AF37] break-all" dir="ltr">
                    {report.structure.hostname}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                  <span>
                    المؤشرات المرصودة:{' '}
                    <span className="font-mono tabular-nums text-white font-bold">
                      {report.indicators.filter((i) => i.triggered).length}
                    </span>
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>
                    حالة DNS:{' '}
                    <span
                      className={`font-bold ${
                        report.dns.domainActive
                          ? 'text-emerald-400'
                          : report.dns.skippedReason
                          ? 'text-amber-300'
                          : 'text-red-400'
                      }`}
                    >
                      {report.dns.domainActive
                        ? 'نطاق فعال ومربوط بخوادم حقيقية'
                        : report.dns.skippedReason
                        ? 'مستثنى (IP/محلي)'
                        : `غير فعال (${report.dns.aStatusCode})`}
                    </span>
                  </span>
                  <span aria-hidden="true">·</span>
                  <span>
                    زمن DoH: <span className="font-mono tabular-nums text-gray-200">{report.dns.durationMs} ms</span>
                  </span>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => void copyFullReport()}
                  className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
                >
                  {copiedKey === 'full-url-report' ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5 text-[#D4AF37]" />
                  )}
                  <span>نسخ التقرير</span>
                </button>

                <button
                  type="button"
                  onClick={exportJson}
                  className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
                >
                  <FileJson className="w-3.5 h-3.5 text-[#D4AF37]" />
                  <span>تصدير JSON</span>
                </button>
              </div>
            </div>

            {/* 1. URL Structural Dissection */}
            <div className="space-y-3">
              <h3 className="text-xs font-bold text-white flex items-center gap-2">
                <Link2 className="w-4 h-4 text-[#D4AF37]" />
                <span>التفكيك الكامل لبنية الرابط</span>
              </h3>

              <div className="overflow-x-auto border border-gray-800 rounded-xl">
                <table className="w-full text-xs text-right">
                  <tbody className="divide-y divide-gray-800">
                    <tr className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-4 text-gray-400 font-bold w-48 whitespace-nowrap">البروتوكول (Protocol)</td>
                      <td className="py-2.5 px-4 font-mono text-white" dir="ltr">
                        {report.structure.protocol}
                        {!report.structure.protocolExplicit && (
                          <span className="text-amber-300 text-[11px] ml-2">(implicit in input)</span>
                        )}
                      </td>
                    </tr>
                    <tr className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">النطاق الحقيقي المسجل</td>
                      <td className="py-2.5 px-4 font-mono text-[#D4AF37] font-bold" dir="ltr">
                        {report.structure.registrableDomain || 'غير موجود (عنوان IP مباشر)'}
                      </td>
                    </tr>
                    <tr className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">النطاقات الفرعية (Subdomains)</td>
                      <td className="py-2.5 px-4 font-mono text-white" dir="ltr">
                        {report.structure.subdomains.length > 0
                          ? `${report.structure.subdomains.join('.')} (${report.structure.subdomains.length})`
                          : 'لا يوجد'}
                      </td>
                    </tr>
                    <tr className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">المضيف الكامل (Hostname)</td>
                      <td className="py-2.5 px-4 font-mono text-gray-200 break-all" dir="ltr">
                        {report.structure.hostname}
                      </td>
                    </tr>
                    <tr className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">المنفذ (Port)</td>
                      <td className="py-2.5 px-4 font-mono tabular-nums text-white" dir="ltr">
                        {report.structure.port} {report.structure.portIsDefault ? '(افتراضي)' : '(محدد صراحةً)'}
                      </td>
                    </tr>
                    <tr className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">المسار (Path)</td>
                      <td className="py-2.5 px-4 font-mono text-gray-200 break-all" dir="ltr">
                        {report.structure.pathname}
                      </td>
                    </tr>
                    <tr className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">
                        معاملات الاستعلام ({report.structure.queryParams.length})
                      </td>
                      <td className="py-2.5 px-4 font-mono text-gray-200 break-all" dir="ltr">
                        {report.structure.queryParams.length === 0 ? (
                          <span className="text-gray-500">لا توجد معاملات استعلام</span>
                        ) : (
                          <div className="space-y-1">
                            {report.structure.queryParams.map((p, idx) => (
                              <div key={`${p.key}-${idx}`} className="text-[11px]">
                                <span className="text-[#D4AF37]">{p.key}</span>
                                <span className="text-gray-500"> = </span>
                                <span className="text-white">{p.value || '(empty)'}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </td>
                    </tr>
                    {report.structure.hashFragment && (
                      <tr className="hover:bg-gray-950/60">
                        <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">الجزء المرجعي (Hash)</td>
                        <td className="py-2.5 px-4 font-mono text-gray-300 break-all" dir="ltr">
                          {report.structure.hashFragment}
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* 2. Technical Phishing Indicators */}
            <div className="space-y-3">
              <h3 className="text-xs font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#D4AF37]" />
                <span>فحص المؤشرات التقنية الحقيقية</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {report.indicators.map((ind) => (
                  <div
                    key={ind.key}
                    className={`rounded-xl p-4 border space-y-1.5 ${
                      ind.severity === 'risk'
                        ? 'bg-red-950/20 border-red-500/40'
                        : ind.severity === 'warn'
                        ? 'bg-amber-950/20 border-amber-500/40'
                        : 'bg-gray-950 border-gray-800'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 text-xs font-bold">
                      <span className="text-white">{ind.label}</span>
                      {ind.triggered ? (
                        <span
                          className={`inline-flex items-center gap-1 shrink-0 ${
                            ind.severity === 'risk' ? 'text-red-400' : 'text-amber-400'
                          }`}
                        >
                          <XCircle className="w-3.5 h-3.5" />
                          <span>مرصود</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-emerald-400 shrink-0">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>سليم</span>
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-gray-300 leading-relaxed">{ind.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 3. Live DoH DNS Verification (A & NS) */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-gray-800">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Server className="w-4 h-4 text-[#D4AF37]" />
                <span>التحقق الحي عبر DNS over HTTPS (سجلات A و NS)</span>
              </h3>
              <span className="text-xs font-mono text-gray-400">{report.dns.providerLabel}</span>
            </div>

            {report.dns.skippedReason ? (
              <div className="rounded-xl bg-amber-950/25 border border-amber-500/30 p-4 text-xs text-amber-200">
                {report.dns.skippedReason}
              </div>
            ) : (
              <div className="space-y-4">
                {report.dns.dnsError && (
                  <div className="rounded-xl bg-red-950/30 border border-red-500/40 p-4 flex items-start gap-2.5 text-xs text-red-200">
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <span>{report.dns.dnsError}</span>
                  </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* A Records */}
                  <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-white flex items-center gap-1.5">
                        <Globe className="w-3.5 h-3.5 text-[#D4AF37]" />
                        <span>سجلات A ({report.dns.queriedHostForA})</span>
                      </span>
                      <span className="font-mono text-[11px] text-gray-400">
                        {report.dns.aStatusCode} · {report.dns.aRecords.length} سجل
                      </span>
                    </div>

                    {report.dns.aRecords.length === 0 ? (
                      <div className="text-xs text-gray-500 py-2">
                        لم تُرجع سجلات A لهذا المضيف.
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        {report.dns.aRecords.map((rec, i) => (
                          <div
                            key={`${rec.data}-${i}`}
                            className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 font-mono text-xs"
                            dir="ltr"
                          >
                            <span className="text-white truncate">
                              <span className="text-[#D4AF37] mr-2">{rec.type}</span>
                              {rec.data}
                            </span>
                            <span className="text-gray-500 text-[11px] tabular-nums shrink-0">
                              TTL {rec.ttl}s
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* NS Records */}
                  <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-3">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-white flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-[#D4AF37]" />
                        <span>سجلات NS ({report.dns.queriedDomainForNs})</span>
                      </span>
                      <span className="font-mono text-[11px] text-gray-400">
                        {report.dns.nsStatusCode} · {report.dns.nsRecords.length} سجل
                      </span>
                    </div>

                    {report.dns.nsRecords.length === 0 ? (
                      <div className="text-xs text-gray-500 py-2">
                        لم تُرجع سجلات NS لهذا النطاق.
                      </div>
                    ) : (
                      <div className="space-y-1.5">
                        {report.dns.nsRecords.map((rec, i) => (
                          <div
                            key={`${rec.data}-${i}`}
                            className="flex items-center justify-between gap-2 px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 font-mono text-xs"
                            dir="ltr"
                          >
                            <span className="text-white truncate">{rec.data}</span>
                            <span className="text-gray-500 text-[11px] tabular-nums shrink-0">
                              TTL {rec.ttl}s
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
