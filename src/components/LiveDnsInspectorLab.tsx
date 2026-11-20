import React, { useMemo, useState } from 'react';
import {
  Globe,
  Search,
  Copy,
  Check,
  RotateCcw,
  AlertTriangle,
  RefreshCw,
  FileJson,
  FileSpreadsheet,
  Server,
} from 'lucide-react';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface LiveDnsInspectorLabProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

export type DnsRecordType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'NS';
export type DohProviderId = 'cloudflare' | 'google';

const TARGET_RECORD_TYPES: readonly DnsRecordType[] = ['A', 'AAAA', 'MX', 'TXT', 'NS'];

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

export interface ParsedDnsRecord {
  id: string;
  queriedType: DnsRecordType;
  returnedType: string;
  name: string;
  ttl: number;
  data: string;
  priority?: number;
}

export interface DnsTypeQueryOutcome {
  type: DnsRecordType;
  status: number;
  statusCode: string;
  ad: boolean;
  records: ParsedDnsRecord[];
  error?: string;
}

export interface LiveDnsInspectionReport {
  domain: string;
  provider: DohProviderId;
  providerLabel: string;
  resolverEndpoint: string;
  queriedAtIso: string;
  durationMs: number;
  overallStatusCode: string;
  dnssecValidated: boolean;
  byType: Record<DnsRecordType, DnsTypeQueryOutcome>;
  allRecords: ParsedDnsRecord[];
  rawResponses: Record<DnsRecordType, DohJsonResponse | null>;
}

function normalizeAndValidateDomain(raw: string): { valid: boolean; domain: string; error?: string } {
  let cleaned = raw.trim().toLowerCase();
  if (!cleaned) {
    return { valid: false, domain: '', error: 'يرجى إدخال اسم النطاق (Domain) المراد فحصه.' };
  }

  // Strip protocol, path, query, fragment, credentials, or port if pasted as URL
  cleaned = cleaned.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  cleaned = cleaned.split('/')[0].split('?')[0].split('#')[0];
  cleaned = cleaned.replace(/^[^@]+@/, '');
  cleaned = cleaned.replace(/:\d+$/, '');
  cleaned = cleaned.replace(/\.+$/, '').trim();

  if (!cleaned) {
    return { valid: false, domain: '', error: 'النطاق المدخل فارغ بعد تنظيف الرابط.' };
  }

  if (cleaned.length > 253) {
    return { valid: false, domain: cleaned, error: 'اسم النطاق يتجاوز الحد الأقصى المسموح (253 حرفاً).' };
  }

  // Reject IP addresses explicitly because A/AAAA/MX/TXT/NS queries expect a domain name
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(cleaned) || cleaned.includes(':')) {
    return {
      valid: false,
      domain: cleaned,
      error: 'يرجى إدخال اسم نطاق صالح (مثل example.com) وليس عنوان IP.',
    };
  }

  // Reject local/internal hostnames
  if (
    cleaned === 'localhost' ||
    cleaned.endsWith('.local') ||
    cleaned.endsWith('.internal') ||
    cleaned.endsWith('.localhost')
  ) {
    return {
      valid: false,
      domain: cleaned,
      error: 'لا يمكن الاستعلام عن نطاقات محلية أو داخلية عبر DNS العام.',
    };
  }

  // Strict RFC-compliant FQDN check (supports punycode xn-- labels)
  const fqdnRegex =
    /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
  if (!fqdnRegex.test(cleaned)) {
    return {
      valid: false,
      domain: cleaned,
      error: 'صيغة اسم النطاق غير صالحة. أدخل نطاقاً صحيحاً مثل example.com أو sub.domain.org.',
    };
  }

  return { valid: true, domain: cleaned };
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

function cleanTxtValue(raw: string): string {
  // Cloudflare/Google DoH wraps TXT segments in quotes; preserve readable value cleanly
  const trimmed = raw.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/"\s+"/g, '');
  }
  return trimmed;
}

async function fetchDohRecordType(
  domain: string,
  recordType: DnsRecordType,
  provider: DohProviderId,
  signal: AbortSignal
): Promise<{ json: DohJsonResponse; usedProvider: DohProviderId }> {
  const buildRequest = (targetProvider: DohProviderId) => {
    if (targetProvider === 'cloudflare') {
      return {
        url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(recordType)}`,
        init: {
          method: 'GET',
          headers: { Accept: 'application/dns-json' },
          signal,
        } as RequestInit,
      };
    }
    return {
      url: `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(recordType)}`,
      init: {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal,
      } as RequestInit,
    };
  };

  const primary = buildRequest(provider);
  const res = await fetch(primary.url, primary.init);
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} من خادم DoH (${provider})`);
  }
  const json = (await res.json()) as DohJsonResponse;
  if (typeof json !== 'object' || json === null) {
    throw new Error('استجابة DoH غير صالحة.');
  }
  return { json, usedProvider: provider };
}

export const LiveDnsInspectorLab: React.FC<LiveDnsInspectorLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [domainInput, setDomainInput] = useState('');
  const [provider, setProvider] = useState<DohProviderId>('cloudflare');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [report, setReport] = useState<LiveDnsInspectionReport | null>(null);
  const [typeFilter, setTypeFilter] = useState<'ALL' | DnsRecordType>('ALL');
  const [recordSearch, setRecordSearch] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopyText = async (text: string, id: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800);
      onNotify(`تم نسخ ${label} إلى الحافظة.`, 'success');
    } catch {
      onNotify('تعذر النسخ إلى الحافظة في هذا المتصفح.', 'warning');
    }
  };

  const handleReset = () => {
    setDomainInput('');
    setReport(null);
    setErrorMsg(null);
    setTypeFilter('ALL');
    setRecordSearch('');
  };

  const runLiveDnsLookup = async (e?: React.FormEvent) => {
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
    setTypeFilter('ALL');
    setRecordSearch('');

    const startedAt = performance.now();
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 12000);

    try {
      const results = await Promise.allSettled(
        TARGET_RECORD_TYPES.map((t) => fetchDohRecordType(domain, t, provider, controller.signal))
      );

      const byType = {} as Record<DnsRecordType, DnsTypeQueryOutcome>;
      const rawResponses = {} as Record<DnsRecordType, DohJsonResponse | null>;
      const allRecords: ParsedDnsRecord[] = [];
      let networkFailureCount = 0;
      let firstNetworkError = '';
      let nxdomainCount = 0;
      let anyAd = false;

      TARGET_RECORD_TYPES.forEach((rtype, idx) => {
        const outcome = results[idx];
        if (outcome.status === 'rejected') {
          networkFailureCount += 1;
          const reason =
            outcome.reason?.name === 'AbortError'
              ? 'انتهت مهلة الاتصال بخادم DoH (Timeout).'
              : String(outcome.reason?.message || 'فشل الاتصال بخادم DoH.');
          if (!firstNetworkError) firstNetworkError = reason;
          rawResponses[rtype] = null;
          byType[rtype] = {
            type: rtype,
            status: -1,
            statusCode: 'NETWORK_ERROR',
            ad: false,
            records: [],
            error: reason,
          };
          return;
        }

        const json = outcome.value.json;
        rawResponses[rtype] = json;
        const status = typeof json.Status === 'number' ? json.Status : 0;
        const rcodeInfo = DNS_RCODE_LABELS[status] || {
          code: `RCODE_${status}`,
          descAr: `رمز استجابة DNS: ${status}`,
        };
        if (status === 3) nxdomainCount += 1;
        if (json.AD) anyAd = true;

        const answers = Array.isArray(json.Answer) ? json.Answer : [];
        const parsed: ParsedDnsRecord[] = answers.map((ans, aIdx) => {
          const typeNum = Number(ans.type || 0);
          const returnedType = DNS_TYPE_CODES[typeNum] || `TYPE${typeNum}`;
          const rawData = String(ans.data || '').trim();
          let displayData = rawData;
          let priority: number | undefined;

          if (returnedType === 'MX') {
            const mxMatch = rawData.match(/^(\d+)\s+(.+)$/);
            if (mxMatch) {
              priority = Number(mxMatch[1]);
              displayData = mxMatch[2].replace(/\.$/, '');
            }
          } else if (returnedType === 'TXT') {
            displayData = cleanTxtValue(rawData);
          } else if (returnedType === 'NS' || returnedType === 'CNAME') {
            displayData = rawData.replace(/\.$/, '');
          }

          const rec: ParsedDnsRecord = {
            id: `${rtype}-${aIdx}-${returnedType}-${displayData}`,
            queriedType: rtype,
            returnedType,
            name: String(ans.name || domain).replace(/\.$/, ''),
            ttl: typeof ans.TTL === 'number' ? ans.TTL : 0,
            data: displayData,
            priority,
          };
          return rec;
        });

        // Sort MX records by priority ascending
        if (rtype === 'MX') {
          parsed.sort((a, b) => (a.priority ?? 9999) - (b.priority ?? 9999));
        }

        allRecords.push(...parsed);
        byType[rtype] = {
          type: rtype,
          status,
          statusCode: rcodeInfo.code,
          ad: Boolean(json.AD),
          records: parsed,
          error: status !== 0 ? `${rcodeInfo.descAr}` : undefined,
        };
      });

      window.clearTimeout(timeoutId);
      const durationMs = Math.max(1, Math.round(performance.now() - startedAt));

      if (networkFailureCount === TARGET_RECORD_TYPES.length) {
        const errText = `تعذر إتمام استعلام DNS over HTTPS عبر ${
          provider === 'cloudflare' ? 'Cloudflare DoH' : 'Google DoH'
        }: ${firstNetworkError}`;
        setErrorMsg(errText);
        onNotify(errText, 'error');
        return;
      }

      if (nxdomainCount === TARGET_RECORD_TYPES.length) {
        const nxMsg = `النطاق "${domain}" غير مسجل في نظام DNS العام (NXDOMAIN — لا وجود لهذا النطاق).`;
        setErrorMsg(nxMsg);
        onNotify(nxMsg, 'warning');
        return;
      }

      const providerLabel =
        provider === 'cloudflare' ? 'Cloudflare DoH (1.1.1.1)' : 'Google Public DNS DoH (8.8.8.8)';
      const resolverEndpoint =
        provider === 'cloudflare'
          ? 'https://cloudflare-dns.com/dns-query'
          : 'https://dns.google/resolve';

      const finalReport: LiveDnsInspectionReport = {
        domain,
        provider,
        providerLabel,
        resolverEndpoint,
        queriedAtIso: new Date().toISOString(),
        durationMs,
        overallStatusCode:
          networkFailureCount > 0
            ? 'PARTIAL'
            : nxdomainCount > 0
            ? 'NXDOMAIN'
            : 'NOERROR',
        dnssecValidated: anyAd,
        byType,
        allRecords,
        rawResponses,
      };

      setReport(finalReport);

      const sha256 = await computeSha256Hex(JSON.stringify(finalReport.allRecords));
      onRecordAudit({
        id: `dns-${Date.now()}`,
        fileName: `DNS Lookup: ${domain}`,
        fileSize: `${allRecords.length} records`,
        verdict:
          allRecords.length > 0
            ? `استعلام DoH مباشر ناجح (${allRecords.length} سجل عبر ${providerLabel})`
            : `استعلام DoH مباشر للنطاق ${domain}: لم يتم العثور على سجلات A/AAAA/MX/TXT/NS`,
        score: allRecords.length > 0 ? 100 : 75,
        risk: allRecords.length > 0 ? 'منخفض' : 'متوسط',
        sha256,
      });

      if (allRecords.length === 0) {
        onNotify(`تم الاستعلام عن ${domain} عبر ${providerLabel} ولم تُرجع أي سجلات.`, 'warning');
      } else {
        onNotify(`تم جلب ${allRecords.length} سجل DNS فعلي للنطاق ${domain} (${durationMs} ms).`, 'success');
      }
    } catch (err: any) {
      window.clearTimeout(timeoutId);
      const errText =
        err?.name === 'AbortError'
          ? 'انتهت مهلة الاتصال بخادم DNS over HTTPS.'
          : err?.message || 'حدث خطأ أثناء تنفيذ استعلام DNS.';
      setErrorMsg(errText);
      onNotify(errText, 'error');
    } finally {
      setLoading(false);
    }
  };

  const filteredRecords = useMemo(() => {
    if (!report) return [];
    const term = recordSearch.trim().toLowerCase();
    return report.allRecords.filter((rec) => {
      if (typeFilter !== 'ALL' && rec.queriedType !== typeFilter) return false;
      if (!term) return true;
      return (
        rec.name.toLowerCase().includes(term) ||
        rec.data.toLowerCase().includes(term) ||
        rec.returnedType.toLowerCase().includes(term) ||
        rec.queriedType.toLowerCase().includes(term)
      );
    });
  }, [report, typeFilter, recordSearch]);

  const exportCsv = () => {
    if (!report) return;
    const headers = ['Domain', 'QueriedType', 'ReturnedType', 'Name', 'TTL', 'Priority', 'Value', 'Resolver', 'QueriedAt'];
    const rows = report.allRecords.map((r) => [
      sanitizeCsvCell(report.domain),
      sanitizeCsvCell(r.queriedType),
      sanitizeCsvCell(r.returnedType),
      sanitizeCsvCell(r.name),
      sanitizeCsvCell(r.ttl),
      sanitizeCsvCell(r.priority ?? ''),
      sanitizeCsvCell(r.data),
      sanitizeCsvCell(report.providerLabel),
      sanitizeCsvCell(report.queriedAtIso),
    ]);
    const csv = '\uFEFF' + [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns-records-${report.domain}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير سجلات DNS للنطاق ${report.domain} بصيغة CSV.`, 'success');
  };

  const exportJson = () => {
    if (!report) return;
    const payload = {
      domain: report.domain,
      resolver: report.providerLabel,
      endpoint: report.resolverEndpoint,
      queriedAt: report.queriedAtIso,
      durationMs: report.durationMs,
      dnssecValidated: report.dnssecValidated,
      summary: Object.fromEntries(
        TARGET_RECORD_TYPES.map((t) => [
          t,
          {
            statusCode: report.byType[t].statusCode,
            count: report.byType[t].records.length,
            records: report.byType[t].records,
          },
        ])
      ),
      rawDohResponses: report.rawResponses,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `dns-report-${report.domain}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير تقرير DNS للنطاق ${report.domain} بصيغة JSON.`, 'success');
  };

  const copyFullSummary = async () => {
    if (!report) return;
    const lines: string[] = [
      `Domain: ${report.domain}`,
      `Resolver: ${report.providerLabel} (${report.resolverEndpoint})`,
      `Queried At: ${report.queriedAtIso}`,
      `Duration: ${report.durationMs} ms`,
      `DNSSEC (AD): ${report.dnssecValidated ? 'Verified' : 'Not Validated / Unsigned'}`,
      '',
    ];
    for (const t of TARGET_RECORD_TYPES) {
      const group = report.byType[t];
      lines.push(`[${t}] (${group.statusCode}) - ${group.records.length} record(s)`);
      if (group.records.length === 0) {
        lines.push('  (none)');
      } else {
        for (const r of group.records) {
          const prio = r.priority !== undefined ? `prio=${r.priority} ` : '';
          lines.push(`  ${r.returnedType} | TTL=${r.ttl}s | ${prio}${r.data}`);
        }
      }
      lines.push('');
    }
    await handleCopyText(lines.join('\n'), 'full-report', 'التقرير الكامل');
  };

  return (
    <div className="space-y-6">
      {/* Main Header & Query Bar */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-gray-800">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Globe className="w-5 h-5 text-[#D4AF37]" />
              <span>فاحص سجلات DNS المباشر (Live DNS Inspector)</span>
            </h2>
            <p className="text-xs text-gray-400">
              استعلام مباشر وفوري عن سجلات <span className="font-mono text-gray-200">A · AAAA · MX · TXT · NS</span> عبر بروتوكول DNS over HTTPS (DoH) دون أي بيانات وهمية.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <div className="flex items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
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
        </div>

        <form onSubmit={runLiveDnsLookup} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-gray-500 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="أدخل اسم النطاق للفحص (مثال: google.com أو cloudflare.com)"
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
                  <span>جاري الاستعلام...</span>
                </>
              ) : (
                <>
                  <Server className="w-4 h-4" />
                  <span>فحص سجلات DNS</span>
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

        {/* Error State */}
        {errorMsg && (
          <div className="rounded-xl bg-red-950/30 border border-red-500/40 p-4 flex items-start gap-3 text-xs text-red-200">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <div className="font-bold text-red-300">تعذر إتمام الاستعلام</div>
              <p className="text-red-200/90 leading-relaxed">{errorMsg}</p>
            </div>
          </div>
        )}
      </div>

      {/* Empty State (before any query) */}
      {!loading && !report && !errorMsg && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-xl bg-gray-950 border border-gray-800 flex items-center justify-center mx-auto text-[#D4AF37]">
            <Globe className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-bold text-white">في انتظار إدخال نطاق للفحص المباشر</h3>
          <p className="text-xs text-gray-400 max-w-lg mx-auto leading-relaxed">
            اكتب أي اسم نطاق صالح في الحقل أعلاه واضغط على <span className="text-gray-200 font-semibold">فحص سجلات DNS</span> لجلب سجلات A و AAAA و MX و TXT و NS الحقيقية مباشرةً عبر DNS over HTTPS. لا يتم عرض أي بيانات افتراضية أو محاكاة.
          </p>
        </div>
      )}

      {/* Loading Skeleton State */}
      {loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-xs text-[#D4AF37] font-bold">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>جاري تنفيذ استعلامات DoH الحية لسجلات A و AAAA و MX و TXT و NS...</span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {TARGET_RECORD_TYPES.map((t) => (
              <div key={t} className="h-16 rounded-lg bg-gray-950 border border-gray-800 animate-pulse" />
            ))}
          </div>
        </div>
      )}

      {/* Populated Live DNS Report */}
      {report && !loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-6">
          {/* Summary & Export Controls */}
          <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-gray-800">
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2 text-sm font-bold text-white">
                <span className="font-mono text-[#D4AF37]" dir="ltr">
                  {report.domain}
                </span>
                <span className="text-gray-600" aria-hidden="true">·</span>
                <span className="text-xs font-normal text-gray-300">
                  الحالة: <span className="font-mono text-emerald-400">{report.overallStatusCode}</span>
                </span>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                <span>المزود: <span className="font-mono text-gray-200">{report.providerLabel}</span></span>
                <span aria-hidden="true">·</span>
                <span>إجمالي السجلات: <span className="font-mono tabular-nums text-white font-bold">{report.allRecords.length}</span></span>
                <span aria-hidden="true">·</span>
                <span>زمن الاستجابة: <span className="font-mono tabular-nums text-gray-200">{report.durationMs} ms</span></span>
                <span aria-hidden="true">·</span>
                <span>DNSSEC: <span className="font-mono text-gray-200">{report.dnssecValidated ? 'Verified (AD)' : 'Unsigned / Unverified'}</span></span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => void copyFullSummary()}
                className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
              >
                {copiedId === 'full-report' ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5 text-[#D4AF37]" />
                )}
                <span>نسخ النتيجة</span>
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

          {/* Per-Type Status Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            {TARGET_RECORD_TYPES.map((t) => {
              const bucket = report.byType[t];
              const isSelected = typeFilter === t;
              return (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTypeFilter((prev) => (prev === t ? 'ALL' : t))}
                  className={`p-3.5 rounded-xl border text-right transition cursor-pointer ${
                    isSelected
                      ? 'bg-[#D4AF37]/10 border-[#D4AF37]'
                      : 'bg-gray-950 border-gray-800 hover:border-gray-700'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-bold text-[#D4AF37]">{t}</span>
                    <span className="font-mono text-[11px] text-gray-500">{bucket.statusCode}</span>
                  </div>
                  <div className="mt-1.5 text-xl font-bold font-mono tabular-nums text-white">
                    {bucket.records.length}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-0.5">
                    {bucket.error
                      ? bucket.error
                      : bucket.records.length === 0
                      ? 'لا توجد سجلات'
                      : 'سجل حقيقي'}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Filter Toolbar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
              <button
                type="button"
                onClick={() => setTypeFilter('ALL')}
                className={`px-3 py-1.5 rounded text-xs font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                  typeFilter === 'ALL'
                    ? 'bg-[#D4AF37] text-gray-950'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                الكل ({report.allRecords.length})
              </button>
              {TARGET_RECORD_TYPES.map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setTypeFilter(t)}
                  className={`px-3 py-1.5 rounded text-xs font-mono font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                    typeFilter === t
                      ? 'bg-[#D4AF37] text-gray-950'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {t} ({report.byType[t].records.length})
                </button>
              ))}
            </div>

            <div className="relative w-full sm:w-72">
              <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={recordSearch}
                onChange={(e) => setRecordSearch(e.target.value)}
                placeholder="تصفية القيم المسترجعة..."
                className="w-full bg-gray-950 border border-gray-800 focus:border-[#D4AF37] rounded-lg pr-9 pl-3 py-2 text-xs text-white placeholder-gray-500 outline-none"
              />
            </div>
          </div>

          {/* Results Table */}
          {filteredRecords.length === 0 ? (
            <div className="rounded-xl bg-gray-950 border border-gray-800 p-8 text-center text-xs text-gray-400">
              {report.allRecords.length === 0
                ? `لم يتم إرجاع أي سجلات من نوع A أو AAAA أو MX أو TXT أو NS للنطاق "${report.domain}".`
                : 'لا توجد سجلات تطابق عامل التصفية الحالي.'}
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
                    <th className="py-3 px-4 whitespace-nowrap">القيمة الحقيقية (Value / Data)</th>
                    <th className="py-3 px-4 whitespace-nowrap text-center">نسخ</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono text-[12px]">
                  {filteredRecords.map((rec, idx) => (
                    <tr key={`${rec.id}-${idx}`} className="hover:bg-gray-950/60">
                      <td className="py-3 px-4 text-[#D4AF37] font-bold whitespace-nowrap">
                        {rec.queriedType}
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
                          onClick={() => void handleCopyText(rec.data, `${rec.id}-${idx}`, `سجل ${rec.returnedType}`)}
                          title="نسخ القيمة"
                          className="p-1.5 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-800 text-gray-300 hover:text-white inline-flex items-center justify-center transition cursor-pointer"
                        >
                          {copiedId === `${rec.id}-${idx}` ? (
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
      )}
    </div>
  );
};
