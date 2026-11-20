import React, { useMemo, useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  Search,
  Copy,
  Check,
  RotateCcw,
  AlertTriangle,
  RefreshCw,
  FileJson,
  FileSpreadsheet,
  Globe,
  Mail,
  Server,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface IqDomainSecurityAuditorLabProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

export type DohProviderId = 'cloudflare' | 'google';
export type IqQueryType = 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' | '_dmarc';

const DNS_TYPE_CODES: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
};

const DNS_RCODE_LABELS: Record<number, { code: string; descAr: string }> = {
  0: { code: 'NOERROR', descAr: 'استجابة ناجحة' },
  1: { code: 'FORMERR', descAr: 'خطأ في صيغة الاستعلام' },
  2: { code: 'SERVFAIL', descAr: 'فشل الخادم المرجعي في الرد (SERVFAIL)' },
  3: { code: 'NXDOMAIN', descAr: 'النطاق غير موجود في نظام DNS (NXDOMAIN)' },
  4: { code: 'NOTIMP', descAr: 'العملية غير مدعومة' },
  5: { code: 'REFUSED', descAr: 'رفض خادم DNS الاستعلام (REFUSED)' },
};

interface DohJsonAnswer {
  name?: string;
  type?: number;
  TTL?: number;
  data?: string;
}

interface DohJsonResponse {
  Status?: number;
  TC?: boolean;
  RD?: boolean;
  RA?: boolean;
  AD?: boolean;
  CD?: boolean;
  Question?: Array<{ name?: string; type?: number }>;
  Answer?: DohJsonAnswer[];
  Authority?: DohJsonAnswer[];
  Comment?: string;
}

interface ParsedRecordItem {
  id: string;
  queryGroup: IqQueryType;
  returnedType: string;
  name: string;
  ttl: number;
  data: string;
  priority?: number;
}

interface SpfSummary {
  present: boolean;
  rawRecords: string[];
  qualifier: string | null;
  qualifierSeverity: 'strict' | 'soft' | 'neutral' | 'dangerous' | 'unknown' | 'missing';
  includes: string[];
  hasMultipleSpf: boolean;
}

interface DmarcSummary {
  present: boolean;
  rawRecord: string | null;
  statusCode: string;
  policy: string | null;
  subdomainPolicy: string | null;
  pct: string | null;
  rua: string[];
  ruf: string[];
  adkim: string | null;
  aspf: string | null;
}

interface IqDomainAuditReport {
  domain: string;
  domainClassification: {
    isIq: boolean;
    suffix: string;
    labelAr: string;
  };
  provider: DohProviderId;
  providerLabel: string;
  resolverEndpoint: string;
  queriedAtIso: string;
  durationMs: number;
  dnssecValidated: boolean;
  aRecords: ParsedRecordItem[];
  aaaaRecords: ParsedRecordItem[];
  mxRecords: ParsedRecordItem[];
  nsRecords: ParsedRecordItem[];
  txtRecords: ParsedRecordItem[];
  dmarcRecords: ParsedRecordItem[];
  allRecords: ParsedRecordItem[];
  spf: SpfSummary;
  dmarc: DmarcSummary;
  queryStatuses: Record<IqQueryType, { status: number; statusCode: string; error?: string }>;
  findings: Array<{ level: 'ok' | 'warn' | 'risk'; text: string }>;
  rawResponses: Record<IqQueryType, DohJsonResponse | null>;
}

function classifyDomain(domain: string): { isIq: boolean; suffix: string; labelAr: string } {
  if (domain.endsWith('.gov.iq')) {
    return { isIq: true, suffix: '.gov.iq', labelAr: 'نطاق حكومي عراقي (.gov.iq)' };
  }
  if (domain.endsWith('.edu.iq')) {
    return { isIq: true, suffix: '.edu.iq', labelAr: 'نطاق تعليمي/أكاديمي عراقي (.edu.iq)' };
  }
  if (domain.endsWith('.com.iq')) {
    return { isIq: true, suffix: '.com.iq', labelAr: 'نطاق تجاري عراقي (.com.iq)' };
  }
  if (domain.endsWith('.org.iq')) {
    return { isIq: true, suffix: '.org.iq', labelAr: 'نطاق منظمات عراقي (.org.iq)' };
  }
  if (domain.endsWith('.net.iq')) {
    return { isIq: true, suffix: '.net.iq', labelAr: 'نطاق شبكات عراقي (.net.iq)' };
  }
  if (domain.endsWith('.mil.iq')) {
    return { isIq: true, suffix: '.mil.iq', labelAr: 'نطاق عسكري عراقي (.mil.iq)' };
  }
  if (domain.endsWith('.iq')) {
    return { isIq: true, suffix: '.iq', labelAr: 'نطاق عراقي مباشر (.iq)' };
  }
  const tld = domain.split('.').pop() || '';
  return { isIq: false, suffix: `.${tld}`, labelAr: `نطاق غير عراقي (.${tld})` };
}

function normalizeAndValidateDomain(raw: string): { valid: boolean; domain: string; error?: string } {
  let cleaned = raw.trim().toLowerCase();
  if (!cleaned) {
    return { valid: false, domain: '', error: 'يرجى إدخال اسم النطاق المراد فحصه (مثل example.gov.iq).' };
  }

  cleaned = cleaned.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0];
  cleaned = cleaned.replace(/^[^@]+@/, '');
  cleaned = cleaned.replace(/:\d+$/, '');
  cleaned = cleaned.replace(/\.+$/, '').trim();

  if (!cleaned) {
    return { valid: false, domain: '', error: 'النطاق المدخل فارغ بعد إزالة لاحقات الرابط.' };
  }
  if (cleaned.length > 253) {
    return { valid: false, domain: cleaned, error: 'اسم النطاق يتجاوز الحد الأقصى المسموح (253 حرفاً).' };
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleaned) || cleaned.includes(':')) {
    return {
      valid: false,
      domain: cleaned,
      error: 'يرجى إدخال اسم نطاق صالح (مثل ministry.gov.iq) وليس عنوان IP.',
    };
  }
  if (
    cleaned === 'localhost' ||
    cleaned.endsWith('.local') ||
    cleaned.endsWith('.internal') ||
    cleaned.endsWith('.localhost')
  ) {
    return {
      valid: false,
      domain: cleaned,
      error: 'لا يمكن الاستعلام عن نطاقات محلية أو داخلية عبر نظام DNS العام.',
    };
  }

  const fqdnRegex = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  if (!fqdnRegex.test(cleaned)) {
    return {
      valid: false,
      domain: cleaned,
      error: 'صيغة اسم النطاق غير صالحة. أدخل نطاقاً صحيحاً مثل example.gov.iq أو university.edu.iq.',
    };
  }

  return { valid: true, domain: cleaned };
}

function cleanTxtValue(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/"\s+"/g, '');
  }
  return trimmed;
}

function parseSpfFromTxt(txtStrings: string[]): SpfSummary {
  const spfRecords = txtStrings.filter((t) => /^v=spf1(\s|$)/i.test(t.trim()));
  if (spfRecords.length === 0) {
    return {
      present: false,
      rawRecords: [],
      qualifier: null,
      qualifierSeverity: 'missing',
      includes: [],
      hasMultipleSpf: false,
    };
  }

  const primary = spfRecords[0];
  const tokens = primary.split(/\s+/);
  const includes = tokens
    .filter((tok) => /^include:/i.test(tok))
    .map((tok) => tok.replace(/^include:/i, ''));

  let qualifier: string | null = null;
  let qualifierSeverity: SpfSummary['qualifierSeverity'] = 'unknown';

  if (tokens.includes('-all')) {
    qualifier = '-all (HardFail — حظر صارم للمرسلين غير المصرح لهم)';
    qualifierSeverity = 'strict';
  } else if (tokens.includes('~all')) {
    qualifier = '~all (SoftFail — وسم المرسلين غير المصرح لهم كمشبوهين)';
    qualifierSeverity = 'soft';
  } else if (tokens.includes('?all')) {
    qualifier = '?all (Neutral — محايد بدون حظر فعلي)';
    qualifierSeverity = 'neutral';
  } else if (tokens.includes('+all') || tokens.includes('all')) {
    qualifier = '+all (Allow-All — يسمح لأي جهة بالإرسال باسم النطاق)';
    qualifierSeverity = 'dangerous';
  } else {
    const redirectTok = tokens.find((tok) => /^redirect=/i.test(tok));
    if (redirectTok) {
      qualifier = `${redirectTok} (إعادة توجيه لسياسة نطاق آخر)`;
      qualifierSeverity = 'unknown';
    }
  }

  return {
    present: true,
    rawRecords: spfRecords,
    qualifier,
    qualifierSeverity,
    includes,
    hasMultipleSpf: spfRecords.length > 1,
  };
}

function parseDmarcFromTxt(dmarcTxtStrings: string[], statusCode: string): DmarcSummary {
  const dmarcRecord = dmarcTxtStrings.find((t) => /^v=DMARC1(\s*;|\s|$)/i.test(t.trim())) || null;
  if (!dmarcRecord) {
    return {
      present: false,
      rawRecord: null,
      statusCode,
      policy: null,
      subdomainPolicy: null,
      pct: null,
      rua: [],
      ruf: [],
      adkim: null,
      aspf: null,
    };
  }

  const kv: Record<string, string> = {};
  for (const part of dmarcRecord.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      const k = part.slice(0, idx).trim().toLowerCase();
      const v = part.slice(idx + 1).trim();
      if (k) kv[k] = v;
    }
  }

  const splitMailto = (val?: string) =>
    val
      ? val
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      : [];

  return {
    present: true,
    rawRecord: dmarcRecord,
    statusCode,
    policy: kv.p || null,
    subdomainPolicy: kv.sp || null,
    pct: kv.pct || null,
    rua: splitMailto(kv.rua),
    ruf: splitMailto(kv.ruf),
    adkim: kv.adkim || null,
    aspf: kv.aspf || null,
  };
}

async function computeSha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function sanitizeCsvCell(val: string | number | undefined): string {
  const s = String(val ?? '');
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
}

async function queryDoh(
  qname: string,
  qtype: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT',
  provider: DohProviderId,
  signal: AbortSignal
): Promise<DohJsonResponse> {
  const url =
    provider === 'cloudflare'
      ? `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(qname)}&type=${encodeURIComponent(qtype)}`
      : `https://dns.google/resolve?name=${encodeURIComponent(qname)}&type=${encodeURIComponent(qtype)}`;

  const res = await fetch(url, {
    method: 'GET',
    headers: { Accept: provider === 'cloudflare' ? 'application/dns-json' : 'application/json' },
    signal,
  });

  if (!res.ok) {
    throw new Error(`HTTP ${res.status} من خادم DoH (${provider})`);
  }
  const json = (await res.json()) as DohJsonResponse;
  if (typeof json !== 'object' || json === null) {
    throw new Error('استجابة DoH غير صالحة.');
  }
  return json;
}

function parseDohAnswers(
  json: DohJsonResponse,
  queryGroup: IqQueryType,
  fallbackName: string
): ParsedRecordItem[] {
  const answers = Array.isArray(json.Answer) ? json.Answer : [];
  const items: ParsedRecordItem[] = answers.map((ans, idx) => {
    const typeNum = Number(ans.type || 0);
    const returnedType = DNS_TYPE_CODES[typeNum] || `TYPE${typeNum}`;
    const rawData = String(ans.data || '').trim();
    let displayData = rawData;
    let priority: number | undefined;

    if (returnedType === 'MX') {
      const m = rawData.match(/^(\d+)\s+(.+)$/);
      if (m) {
        priority = Number(m[1]);
        displayData = m[2].replace(/\.$/, '');
      }
    } else if (returnedType === 'TXT') {
      displayData = cleanTxtValue(rawData);
    } else if (returnedType === 'NS' || returnedType === 'CNAME') {
      displayData = rawData.replace(/\.$/, '');
    }

    return {
      id: `${queryGroup}-${idx}-${returnedType}-${displayData}`,
      queryGroup,
      returnedType,
      name: String(ans.name || fallbackName).replace(/\.$/, ''),
      ttl: typeof ans.TTL === 'number' ? ans.TTL : 0,
      data: displayData,
      priority,
    };
  });

  if (queryGroup === 'MX') {
    items.sort((a, b) => (a.priority ?? 9999) - (b.priority ?? 9999));
  }
  return items;
}

export const IqDomainSecurityAuditorLab: React.FC<IqDomainSecurityAuditorLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [domainInput, setDomainInput] = useState('');
  const [provider, setProvider] = useState<DohProviderId>('cloudflare');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [report, setReport] = useState<IqDomainAuditReport | null>(null);
  const [filterGroup, setFilterGroup] = useState<'ALL' | IqQueryType>('ALL');
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
    setDomainInput('');
    setReport(null);
    setErrorMsg(null);
    setFilterGroup('ALL');
  };

  const runAudit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (loading) return;

    const validation = normalizeAndValidateDomain(domainInput);
    if (!validation.valid) {
      setErrorMsg(validation.error || 'اسم النطاق غير صالح.');
      setReport(null);
      onNotify(validation.error || 'اسم النطاق غير صالح.', 'warning');
      return;
    }

    const domain = validation.domain;
    setDomainInput(domain);
    setLoading(true);
    setErrorMsg(null);
    setReport(null);
    setFilterGroup('ALL');

    const startedAt = performance.now();
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 14000);

    const queryPlan: Array<{ key: IqQueryType; qname: string; qtype: 'A' | 'AAAA' | 'MX' | 'NS' | 'TXT' }> = [
      { key: 'A', qname: domain, qtype: 'A' },
      { key: 'AAAA', qname: domain, qtype: 'AAAA' },
      { key: 'MX', qname: domain, qtype: 'MX' },
      { key: 'NS', qname: domain, qtype: 'NS' },
      { key: 'TXT', qname: domain, qtype: 'TXT' },
      { key: '_dmarc', qname: `_dmarc.${domain}`, qtype: 'TXT' },
    ];

    try {
      const settled = await Promise.allSettled(
        queryPlan.map((item) => queryDoh(item.qname, item.qtype, provider, controller.signal))
      );
      window.clearTimeout(timeoutId);
      const durationMs = Math.max(1, Math.round(performance.now() - startedAt));

      const rawResponses = {} as Record<IqQueryType, DohJsonResponse | null>;
      const queryStatuses = {} as Record<IqQueryType, { status: number; statusCode: string; error?: string }>;
      const parsedMap: Record<IqQueryType, ParsedRecordItem[]> = {
        A: [],
        AAAA: [],
        MX: [],
        NS: [],
        TXT: [],
        _dmarc: [],
      };

      let networkErrors = 0;
      let firstNetError = '';
      let rootNxdomainCount = 0;
      let anyAd = false;

      queryPlan.forEach((item, idx) => {
        const res = settled[idx];
        if (res.status === 'rejected') {
          networkErrors += 1;
          const msg =
            res.reason?.name === 'AbortError'
              ? 'انتهت مهلة الاتصال بخادم DoH.'
              : String(res.reason?.message || 'فشل الاتصال بخادم DoH.');
          if (!firstNetError) firstNetError = msg;
          rawResponses[item.key] = null;
          queryStatuses[item.key] = { status: -1, statusCode: 'NETWORK_ERROR', error: msg };
          return;
        }

        const json = res.value;
        rawResponses[item.key] = json;
        const status = typeof json.Status === 'number' ? json.Status : 0;
        const rcodeInfo = DNS_RCODE_LABELS[status] || {
          code: `RCODE_${status}`,
          descAr: `رمز DNS: ${status}`,
        };
        if (json.AD) anyAd = true;
        if (item.key !== '_dmarc' && status === 3) {
          rootNxdomainCount += 1;
        }

        queryStatuses[item.key] = {
          status,
          statusCode: rcodeInfo.code,
          error: status !== 0 ? rcodeInfo.descAr : undefined,
        };
        parsedMap[item.key] = parseDohAnswers(json, item.key, item.qname);
      });

      if (networkErrors === queryPlan.length) {
        const errText = `فشل تنفيذ استعلامات DNS over HTTPS عبر ${
          provider === 'cloudflare' ? 'Cloudflare DoH' : 'Google DoH'
        }: ${firstNetError}`;
        setErrorMsg(errText);
        onNotify(errText, 'error');
        return;
      }

      // If all root domain queries returned NXDOMAIN (domain doesn't exist)
      if (rootNxdomainCount === 5) {
        const nxErr = `النطاق "${domain}" غير موجود في نظام DNS العام (NXDOMAIN).`;
        setErrorMsg(nxErr);
        onNotify(nxErr, 'warning');
        return;
      }

      const aRecords = parsedMap.A;
      const aaaaRecords = parsedMap.AAAA;
      const mxRecords = parsedMap.MX;
      const nsRecords = parsedMap.NS;
      const txtRecords = parsedMap.TXT;
      const dmarcRecords = parsedMap._dmarc;

      const spf = parseSpfFromTxt(
        txtRecords.filter((r) => r.returnedType === 'TXT').map((r) => r.data)
      );
      const dmarc = parseDmarcFromTxt(
        dmarcRecords.filter((r) => r.returnedType === 'TXT').map((r) => r.data),
        queryStatuses._dmarc.statusCode
      );

      // Factual observations derived strictly from real returned DNS records
      const findings: Array<{ level: 'ok' | 'warn' | 'risk'; text: string }> = [];

      if (nsRecords.length > 0) {
        findings.push({
          level: 'ok',
          text: `خوادم الأسماء (NS) مسجلة وتُرجع ${nsRecords.length} خادم/خوادم أسماء فعلية.`,
        });
      } else {
        findings.push({
          level: 'warn',
          text: 'لم تُرجع سجلات NS من الاستعلام المباشر لهذا النطاق (قد يكون نطاقاً فرعياً يعتمد على نطاق أعلى أو غير مهيأ).',
        });
      }

      if (mxRecords.length > 0) {
        findings.push({
          level: 'ok',
          text: `تم رصد ${mxRecords.length} سجل MX لاستقبال البريد الإلكتروني على هذا النطاق.`,
        });
      } else {
        findings.push({
          level: 'warn',
          text: 'لا توجد سجلات MX مسجلة لهذا النطاق في الاستعلام الحالي.',
        });
      }

      if (!spf.present) {
        findings.push({
          level: mxRecords.length > 0 ? 'risk' : 'warn',
          text: 'لا يوجد سجل SPF (v=spf1) في سجلات TXT المسترجعة، مما يضعف الحماية من انتحال هوية المرسل.',
        });
      } else {
        if (spf.hasMultipleSpf) {
          findings.push({
            level: 'risk',
            text: `تم العثور على أكثر من سجل SPF (${spf.rawRecords.length} سجلات) — وجود أكثر من سجل SPF يُسبب فشل التحقق PermError وفق RFC 7208.`,
          });
        }
        if (spf.qualifierSeverity === 'strict') {
          findings.push({ level: 'ok', text: 'سجل SPF موجود ومضبوط بسياسة حظر صارمة (-all).' });
        } else if (spf.qualifierSeverity === 'soft') {
          findings.push({ level: 'warn', text: 'سجل SPF موجود لكنه يستخدم (~all) SoftFail بدلاً من (-all).' });
        } else if (spf.qualifierSeverity === 'dangerous') {
          findings.push({ level: 'risk', text: 'سجل SPF يستخدم (+all) مما يسمح لأي خادم على الإنترنت بالإرسال باسم النطاق.' });
        } else if (spf.qualifierSeverity === 'neutral') {
          findings.push({ level: 'warn', text: 'سجل SPF يستخدم (?all) وهي سياسة محايدة لا توفر حماية حقيقية.' });
        } else {
          findings.push({ level: 'ok', text: 'سجل SPF موجود في سجلات TXT.' });
        }
      }

      if (!dmarc.present) {
        findings.push({
          level: mxRecords.length > 0 ? 'risk' : 'warn',
          text: `لا يوجد سجل DMARC في _dmarc.${domain} (${dmarc.statusCode}).`,
        });
      } else {
        const pol = (dmarc.policy || '').toLowerCase();
        if (pol === 'reject') {
          findings.push({ level: 'ok', text: 'سجل DMARC موجود ومضبوط بأقوى سياسة حماية (p=reject).' });
        } else if (pol === 'quarantine') {
          findings.push({ level: 'ok', text: 'سجل DMARC موجود ومضبوط بسياسة الحجر (p=quarantine).' });
        } else if (pol === 'none') {
          findings.push({ level: 'warn', text: 'سجل DMARC موجود لكنه في وضع المراقبة فقط (p=none) ولا يمنع الرسائل المنتحلة.' });
        } else {
          findings.push({ level: 'warn', text: 'سجل DMARC موجود في _dmarc لكن بدون سياسة p= واضحة.' });
        }
      }

      const allRecords = [
        ...aRecords,
        ...aaaaRecords,
        ...mxRecords,
        ...nsRecords,
        ...txtRecords,
        ...dmarcRecords,
      ];

      const providerLabel =
        provider === 'cloudflare' ? 'Cloudflare DoH (1.1.1.1)' : 'Google Public DNS DoH (8.8.8.8)';
      const resolverEndpoint =
        provider === 'cloudflare'
          ? 'https://cloudflare-dns.com/dns-query'
          : 'https://dns.google/resolve';

      const finalReport: IqDomainAuditReport = {
        domain,
        domainClassification: classifyDomain(domain),
        provider,
        providerLabel,
        resolverEndpoint,
        queriedAtIso: new Date().toISOString(),
        durationMs,
        dnssecValidated: anyAd,
        aRecords,
        aaaaRecords,
        mxRecords,
        nsRecords,
        txtRecords,
        dmarcRecords,
        allRecords,
        spf,
        dmarc,
        queryStatuses,
        findings,
        rawResponses,
      };

      setReport(finalReport);

      const sha256 = await computeSha256Hex(JSON.stringify(finalReport.allRecords));
      const riskCount = findings.filter((f) => f.level === 'risk').length;
      const warnCount = findings.filter((f) => f.level === 'warn').length;
      onRecordAudit({
        id: `iq-dns-${Date.now()}`,
        fileName: `IQ Domain Audit: ${domain}`,
        fileSize: `${allRecords.length} records`,
        verdict: `فحص ${domain}: SPF=${spf.present ? 'موجود' : 'مفقود'} · DMARC=${dmarc.present ? (dmarc.policy || 'موجود') : 'مفقود'} · MX=${mxRecords.length} · NS=${nsRecords.length}`,
        score: riskCount > 0 ? 45 : warnCount > 0 ? 75 : 100,
        risk: riskCount > 0 ? 'مرتفع' : warnCount > 0 ? 'متوسط' : 'منخفض',
        sha256,
      });

      if (allRecords.length === 0) {
        onNotify(`تم الاستعلام عن ${domain} عبر ${providerLabel} ولم يتم العثور على سجلات DNS.`, 'warning');
      } else {
        onNotify(`اكتمل فحص ${domain} الحقيقي (${allRecords.length} سجل في ${durationMs} ms).`, 'success');
      }
    } catch (err: any) {
      window.clearTimeout(timeoutId);
      const errText =
        err?.name === 'AbortError'
          ? 'انتهت مهلة الاتصال بخادم DNS over HTTPS.'
          : err?.message || 'حدث خطأ أثناء تنفيذ الفحص.';
      setErrorMsg(errText);
      onNotify(errText, 'error');
    } finally {
      setLoading(false);
    }
  };

  const filteredRecords = useMemo(() => {
    if (!report) return [];
    if (filterGroup === 'ALL') return report.allRecords;
    return report.allRecords.filter((r) => r.queryGroup === filterGroup);
  }, [report, filterGroup]);

  const copyFullReport = async () => {
    if (!report) return;
    const lines = [
      `IQ Domain Security Audit Report`,
      `Domain: ${report.domain} (${report.domainClassification.labelAr})`,
      `Resolver: ${report.providerLabel}`,
      `Queried At: ${report.queriedAtIso} (${report.durationMs} ms)`,
      `DNSSEC (AD): ${report.dnssecValidated ? 'Verified' : 'Unsigned / Unverified'}`,
      `SPF: ${report.spf.present ? report.spf.rawRecords.join(' | ') : 'MISSING'}`,
      `DMARC (_dmarc.${report.domain}): ${report.dmarc.present ? report.dmarc.rawRecord : `MISSING (${report.dmarc.statusCode})`}`,
      `MX Count: ${report.mxRecords.length}`,
      `NS Count: ${report.nsRecords.length}`,
      `A Count: ${report.aRecords.length} | AAAA Count: ${report.aaaaRecords.length}`,
      '',
      '--- Findings ---',
      ...report.findings.map((f) => `[${f.level.toUpperCase()}] ${f.text}`),
      '',
      '--- Returned DNS Records ---',
      ...report.allRecords.map(
        (r) =>
          `[${r.queryGroup}] ${r.returnedType} | ${r.name} | TTL=${r.ttl}s | ${
            r.priority !== undefined ? `prio=${r.priority} ` : ''
          }${r.data}`
      ),
    ];
    await handleCopy(lines.join('\n'), 'full-iq-report', 'التقرير الكامل');
  };

  const exportCsv = () => {
    if (!report) return;
    const headers = [
      'Domain',
      'Classification',
      'QueryGroup',
      'ReturnedType',
      'Name',
      'TTL',
      'Priority',
      'Data',
      'SPF_Present',
      'DMARC_Present',
      'DMARC_Policy',
      'Resolver',
      'QueriedAt',
    ];
    const rows = report.allRecords.map((r) => [
      sanitizeCsvCell(report.domain),
      sanitizeCsvCell(report.domainClassification.suffix),
      sanitizeCsvCell(r.queryGroup),
      sanitizeCsvCell(r.returnedType),
      sanitizeCsvCell(r.name),
      sanitizeCsvCell(r.ttl),
      sanitizeCsvCell(r.priority ?? ''),
      sanitizeCsvCell(r.data),
      sanitizeCsvCell(report.spf.present ? 'YES' : 'NO'),
      sanitizeCsvCell(report.dmarc.present ? 'YES' : 'NO'),
      sanitizeCsvCell(report.dmarc.policy || ''),
      sanitizeCsvCell(report.providerLabel),
      sanitizeCsvCell(report.queriedAtIso),
    ]);
    const csv = '\uFEFF' + [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iq-domain-audit-${report.domain}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير تقرير فحص ${report.domain} بصيغة CSV.`, 'success');
  };

  const exportJson = () => {
    if (!report) return;
    const payload = {
      domain: report.domain,
      classification: report.domainClassification,
      resolver: report.providerLabel,
      endpoint: report.resolverEndpoint,
      queriedAt: report.queriedAtIso,
      durationMs: report.durationMs,
      dnssecValidated: report.dnssecValidated,
      spf: report.spf,
      dmarc: report.dmarc,
      records: {
        A: report.aRecords,
        AAAA: report.aaaaRecords,
        MX: report.mxRecords,
        NS: report.nsRecords,
        TXT: report.txtRecords,
        _dmarc: report.dmarcRecords,
      },
      findings: report.findings,
      queryStatuses: report.queryStatuses,
      rawDohResponses: report.rawResponses,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `iq-domain-audit-${report.domain}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير تقرير فحص ${report.domain} بصيغة JSON.`, 'success');
  };

  return (
    <div className="space-y-6">
      {/* Query Panel */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-gray-800">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldCheck className="w-5 h-5 text-[#D4AF37]" />
              <span>فاحص أمان النطاقات العراقية (IQ Domain Security Auditor)</span>
            </h2>
            <p className="text-xs text-gray-400">
              فحص مباشر لنطاقات <span className="font-mono text-gray-200">.iq · .gov.iq · .edu.iq · .com.iq</span> عبر استعلامات DoH حقيقية لسجلات{' '}
              <span className="font-mono text-gray-200">A · AAAA · MX · NS · TXT · _dmarc</span> وتقييم SPF و DMARC بناءً على الردود الفعلية فقط.
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

        <form onSubmit={runAudit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-gray-500 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="أدخل اسم النطاق للفحص (مثال: domain.gov.iq أو university.edu.iq أو company.iq)"
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
                  <span>جاري الفحص المباشر...</span>
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" />
                  <span>فحص أمان النطاق</span>
                </>
              )}
            </button>

            {(report || errorMsg || domainInput) && (
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
              <div className="font-bold text-red-300">تعذر إتمام الفحص</div>
              <p className="text-red-200/90 leading-relaxed">{errorMsg}</p>
            </div>
          </div>
        )}
      </div>

      {/* Empty State */}
      {!loading && !report && !errorMsg && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-xl bg-gray-950 border border-gray-800 flex items-center justify-center mx-auto text-[#D4AF37]">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-bold text-white">في انتظار إدخال نطاق للفحص الأمني المباشر</h3>
          <p className="text-xs text-gray-400 max-w-xl mx-auto leading-relaxed">
            أدخل أي نطاق عراقي (<span className="font-mono text-gray-200">.iq / .gov.iq / .edu.iq / .com.iq</span>) أو نطاق دولي ثم اضغط <span className="text-gray-200 font-semibold">فحص أمان النطاق</span> للاستعلام الفعلي عن سجلات A و AAAA و MX و NS و TXT و _dmarc وتدقيق حالة SPF و DMARC دون أي بيانات افتراضية.
          </p>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-xs text-[#D4AF37] font-bold">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>جاري تنفيذ 6 استعلامات DoH حية (A, AAAA, MX, NS, TXT, _dmarc)...</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="h-24 rounded-xl bg-gray-950 border border-gray-800 animate-pulse" />
            ))}
          </div>
        </div>
      )}

      {/* Real Audit Report */}
      {report && !loading && (
        <div className="space-y-6">
          {/* Header Summary + Export */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-gray-800">
              <div className="space-y-1.5">
                <div className="flex flex-wrap items-center gap-2 text-sm font-bold text-white">
                  <span className="font-mono text-[#D4AF37]" dir="ltr">
                    {report.domain}
                  </span>
                  <span className="text-gray-600" aria-hidden="true">·</span>
                  <span className="text-xs font-normal text-gray-300">
                    {report.domainClassification.labelAr}
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                  <span>المزود: <span className="font-mono text-gray-200">{report.providerLabel}</span></span>
                  <span aria-hidden="true">·</span>
                  <span>إجمالي السجلات: <span className="font-mono tabular-nums text-white font-bold">{report.allRecords.length}</span></span>
                  <span aria-hidden="true">·</span>
                  <span>زمن الفحص: <span className="font-mono tabular-nums text-gray-200">{report.durationMs} ms</span></span>
                  <span aria-hidden="true">·</span>
                  <span>DNSSEC: <span className="font-mono text-gray-200">{report.dnssecValidated ? 'Verified (AD)' : 'Unsigned / Unverified'}</span></span>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                <button
                  type="button"
                  onClick={() => void copyFullReport()}
                  className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
                >
                  {copiedKey === 'full-iq-report' ? (
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <Copy className="w-3.5 h-3.5 text-[#D4AF37]" />
                  )}
                  <span>نسخ التقرير</span>
                </button>

                <button
                  type="button"
                  onClick={exportCsv}
                  disabled={report.allRecords.length === 0}
                  className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer disabled:opacity-40 whitespace-nowrap shrink-0"
                >
                  <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                  <span>تصدير CSV</span>
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

            {!report.domainClassification.isIq && (
              <div className="rounded-lg bg-amber-950/25 border border-amber-500/30 px-4 py-2.5 text-xs text-amber-200">
                ملاحظة: النطاق المدخل ({report.domain}) لا ينتهي بلاحقة <span className="font-mono">.iq</span> العراقية؛ النتائج المعروضة أدناه حقيقية ومسترجعة مباشرة من DNS لنفس النطاق.
              </div>
            )}

            {/* 4 Core Security Posture Cards: SPF, DMARC, MX, NS */}
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
              {/* SPF Card */}
              <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-gray-300">حالة SPF (TXT)</span>
                  {report.spf.present ? (
                    <span className="inline-flex items-center gap-1 text-emerald-400 font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>موجود</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-red-400 font-bold">
                      <XCircle className="w-3.5 h-3.5" />
                      <span>غير موجود</span>
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-gray-400 leading-relaxed font-mono break-all" dir="ltr">
                  {report.spf.present
                    ? report.spf.rawRecords[0]
                    : 'لم يتم العثور على سجل v=spf1'}
                </div>
                {report.spf.qualifier && (
                  <div className="text-[11px] text-[#D4AF37] pt-1 border-t border-gray-800">
                    {report.spf.qualifier}
                  </div>
                )}
              </div>

              {/* DMARC Card */}
              <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-gray-300">حالة DMARC (_dmarc)</span>
                  {report.dmarc.present ? (
                    <span className="inline-flex items-center gap-1 text-emerald-400 font-bold">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>موجود</span>
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-red-400 font-bold">
                      <XCircle className="w-3.5 h-3.5" />
                      <span>غير موجود</span>
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-gray-400 leading-relaxed font-mono break-all" dir="ltr">
                  {report.dmarc.present
                    ? report.dmarc.rawRecord
                    : `لا يوجد سجل في _dmarc.${report.domain} (${report.dmarc.statusCode})`}
                </div>
                {report.dmarc.present && (
                  <div className="text-[11px] text-gray-300 pt-1 border-t border-gray-800 font-mono" dir="ltr">
                    p={report.dmarc.policy || '—'} · pct={report.dmarc.pct || '100'}%
                    {report.dmarc.rua.length > 0 ? ` · rua=${report.dmarc.rua.length}` : ''}
                  </div>
                )}
              </div>

              {/* MX Card */}
              <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-gray-300 flex items-center gap-1.5">
                    <Mail className="w-3.5 h-3.5 text-[#D4AF37]" />
                    <span>خوادم البريد (MX)</span>
                  </span>
                  <span className="font-mono tabular-nums font-bold text-white">
                    {report.mxRecords.length}
                  </span>
                </div>
                {report.mxRecords.length === 0 ? (
                  <div className="text-[11px] text-amber-300">
                    لا توجد سجلات MX ({report.queryStatuses.MX.statusCode})
                  </div>
                ) : (
                  <ul className="space-y-1 text-[11px] font-mono text-gray-300" dir="ltr">
                    {report.mxRecords.slice(0, 3).map((mx, i) => (
                      <li key={i} className="truncate">
                        [{mx.priority ?? '—'}] {mx.data}
                      </li>
                    ))}
                    {report.mxRecords.length > 3 && (
                      <li className="text-gray-500">+{report.mxRecords.length - 3} more</li>
                    )}
                  </ul>
                )}
              </div>

              {/* NS Card */}
              <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold text-gray-300 flex items-center gap-1.5">
                    <Server className="w-3.5 h-3.5 text-[#D4AF37]" />
                    <span>خوادم الأسماء (NS)</span>
                  </span>
                  <span className="font-mono tabular-nums font-bold text-white">
                    {report.nsRecords.length}
                  </span>
                </div>
                {report.nsRecords.length === 0 ? (
                  <div className="text-[11px] text-amber-300">
                    لم تُرجع سجلات NS ({report.queryStatuses.NS.statusCode})
                  </div>
                ) : (
                  <ul className="space-y-1 text-[11px] font-mono text-gray-300" dir="ltr">
                    {report.nsRecords.slice(0, 3).map((ns, i) => (
                      <li key={i} className="truncate">
                        {ns.data}
                      </li>
                    ))}
                    {report.nsRecords.length > 3 && (
                      <li className="text-gray-500">+{report.nsRecords.length - 3} more</li>
                    )}
                  </ul>
                )}
              </div>
            </div>

            {/* Real Findings List */}
            <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-2">
              <h3 className="text-xs font-bold text-white">الملاحظات المستخلصة من السجلات الحقيقية</h3>
              <ul className="space-y-1.5 text-xs">
                {report.findings.map((f, i) => (
                  <li key={i} className="flex items-start gap-2">
                    {f.level === 'ok' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : f.level === 'warn' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    )}
                    <span
                      className={
                        f.level === 'ok'
                          ? 'text-emerald-200'
                          : f.level === 'warn'
                          ? 'text-amber-200'
                          : 'text-red-200'
                      }
                    >
                      {f.text}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {/* Full DNS Records Table (A, AAAA, MX, NS, TXT, _dmarc) */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#D4AF37]" />
                <span>السجلات الفعلية المسترجعة ({report.allRecords.length})</span>
              </h3>

              <div className="flex flex-wrap items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
                <button
                  type="button"
                  onClick={() => setFilterGroup('ALL')}
                  className={`px-2.5 py-1 rounded text-xs font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                    filterGroup === 'ALL'
                      ? 'bg-[#D4AF37] text-gray-950'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  الكل ({report.allRecords.length})
                </button>
                {(['A', 'AAAA', 'MX', 'NS', 'TXT', '_dmarc'] as const).map((grp) => {
                  const cnt = report.allRecords.filter((r) => r.queryGroup === grp).length;
                  return (
                    <button
                      key={grp}
                      type="button"
                      onClick={() => setFilterGroup(grp)}
                      className={`px-2.5 py-1 rounded text-xs font-mono font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                        filterGroup === grp
                          ? 'bg-[#D4AF37] text-gray-950'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      {grp} ({cnt})
                    </button>
                  );
                })}
              </div>
            </div>

            {filteredRecords.length === 0 ? (
              <div className="rounded-xl bg-gray-950 border border-gray-800 p-8 text-center text-xs text-gray-400">
                لم يتم إرجاع أي سجلات في هذه الفئة من استعلام DoH.
              </div>
            ) : (
              <div className="overflow-x-auto border border-gray-800 rounded-xl">
                <table className="w-full text-xs text-right">
                  <thead className="bg-gray-950 text-gray-400 border-b border-gray-800 font-mono">
                    <tr>
                      <th className="py-3 px-4 whitespace-nowrap">الاستعلام</th>
                      <th className="py-3 px-4 whitespace-nowrap">النوع</th>
                      <th className="py-3 px-4 whitespace-nowrap">الاسم (Name)</th>
                      <th className="py-3 px-4 whitespace-nowrap">TTL</th>
                      <th className="py-3 px-4 whitespace-nowrap">القيمة الحقيقية</th>
                      <th className="py-3 px-4 whitespace-nowrap text-center">نسخ</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 font-mono text-[12px]">
                    {filteredRecords.map((rec, idx) => (
                      <tr key={`${rec.id}-${idx}`} className="hover:bg-gray-950/60">
                        <td className="py-3 px-4 text-[#D4AF37] font-bold whitespace-nowrap">
                          {rec.queryGroup}
                        </td>
                        <td className="py-3 px-4 text-gray-300 whitespace-nowrap">
                          {rec.returnedType}
                          {rec.priority !== undefined ? ` (${rec.priority})` : ''}
                        </td>
                        <td className="py-3 px-4 text-gray-300 max-w-[200px] truncate" dir="ltr">
                          {rec.name}
                        </td>
                        <td className="py-3 px-4 text-gray-400 tabular-nums whitespace-nowrap">
                          {rec.ttl}s
                        </td>
                        <td className="py-3 px-4 text-white break-all min-w-[240px]" dir="ltr">
                          {rec.data}
                        </td>
                        <td className="py-3 px-4 text-center whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => void handleCopy(rec.data, `${rec.id}-${idx}`, `سجل ${rec.returnedType}`)}
                            title="نسخ القيمة"
                            className="p-1.5 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-800 text-gray-300 hover:text-white inline-flex items-center justify-center transition cursor-pointer"
                          >
                            {copiedKey === `${rec.id}-${idx}` ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
