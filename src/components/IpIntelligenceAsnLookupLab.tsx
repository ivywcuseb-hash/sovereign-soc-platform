import React, { useState } from 'react';
import {
  Network,
  Search,
  Copy,
  Check,
  RotateCcw,
  AlertTriangle,
  RefreshCw,
  FileJson,
  Globe,
  Building2,
  MapPin,
  Cpu,
  Radio,
} from 'lucide-react';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface IpIntelligenceAsnLookupLabProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

interface IpWhoisResponse {
  ip?: string;
  success?: boolean;
  message?: string;
  type?: string;
  continent?: string;
  continent_code?: string;
  country?: string;
  country_code?: string;
  region?: string;
  region_code?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  is_eu?: boolean;
  postal?: string;
  calling_code?: string;
  capital?: string;
  connection?: {
    asn?: number;
    org?: string;
    isp?: string;
    domain?: string;
  };
  timezone?: {
    id?: string;
    abbr?: string;
    is_dst?: boolean;
    offset?: number;
    utc?: string;
    current_time?: string;
  };
}

interface IpIntelligenceReport {
  ip: string;
  ipType: string;
  continent: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  isp: string;
  org: string;
  asn: string;
  asnDomain: string;
  timezone: string;
  latitude: number | null;
  longitude: number | null;
  isSelfLookup: boolean;
  durationMs: number;
  queriedAtIso: string;
  rawResponse: IpWhoisResponse;
}

function isValidIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    if (p.length > 1 && p.startsWith('0')) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function isValidIPv6(ip: string): boolean {
  if (!ip.includes(':')) return false;
  // Strip optional zone ID check -> reject zone IDs for public lookup
  if (ip.includes('%')) return false;
  const halves = ip.split('::');
  if (halves.length > 2) return false;

  const parseSide = (side: string): string[] | null => {
    if (side === '') return [];
    const groups = side.split(':');
    for (let i = 0; i < groups.length; i++) {
      const g = groups[i];
      if (i === groups.length - 1 && g.includes('.') && halves.length <= 2) {
        if (!isValidIPv4(g)) return null;
      } else if (!/^[0-9a-fA-F]{1,4}$/.test(g)) {
        return null;
      }
    }
    return groups;
  };

  const left = parseSide(halves[0]);
  if (!left) return false;
  if (halves.length === 1) {
    const hasEmbeddedV4 = left[left.length - 1]?.includes('.');
    return hasEmbeddedV4 ? left.length === 7 : left.length === 8;
  }
  const right = parseSide(halves[1]);
  if (!right) return false;
  const hasEmbeddedV4 = right[right.length - 1]?.includes('.');
  const maxGroups = hasEmbeddedV4 ? 6 : 7;
  return left.length + right.length <= maxGroups;
}

function isPrivateOrReservedIp(ip: string): string | null {
  if (isValidIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    if (a === 10) return 'عنوان شبكة خاصة (RFC 1918: 10.0.0.0/8).';
    if (a === 172 && b >= 16 && b <= 31) return 'عنوان شبكة خاصة (RFC 1918: 172.16.0.0/12).';
    if (a === 192 && b === 168) return 'عنوان شبكة خاصة (RFC 1918: 192.168.0.0/16).';
    if (a === 127) return 'عنوان Loopback محلي (127.0.0.0/8).';
    if (a === 169 && b === 254) return 'عنوان Link-Local محلي (169.254.0.0/16).';
    if (a === 0) return 'عنوان غير صالح للتوجيه العام (0.0.0.0/8).';
    if (a >= 224) return 'عنوان Multicast أو محجوز (224.0.0.0+).';
    return null;
  }

  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') {
    return 'عنوان IPv6 محلي (Loopback / Unspecified).';
  }
  if (/^(fe80|fc|fd)/i.test(lower)) {
    return 'عنوان IPv6 خاص أو محلي (Link-Local / ULA).';
  }
  return null;
}

function validateIpInput(raw: string): { valid: boolean; ip: string; error?: string } {
  const cleaned = raw.trim();
  if (!cleaned) {
    return { valid: false, ip: '', error: 'يرجى إدخال عنوان IPv4 أو IPv6 صالح أو الضغط على "فحص عنوان IP الحالي الخاص بي".' };
  }
  if (!isValidIPv4(cleaned) && !isValidIPv6(cleaned)) {
    return {
      valid: false,
      ip: cleaned,
      error: 'صيغة عنوان IP غير صالحة. يرجى إدخال عنوان IPv4 صحيح (مثل 8.8.8.8) أو IPv6 صحيح (مثل 2001:4860:4860::8888).',
    };
  }
  const reservedReason = isPrivateOrReservedIp(cleaned);
  if (reservedReason) {
    return {
      valid: false,
      ip: cleaned,
      error: `لا يمكن فحص هذا العنوان عبر قاعدة بيانات الشبكات العامة: ${reservedReason}`,
    };
  }
  return { valid: true, ip: cleaned };
}

async function computeSha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export const IpIntelligenceAsnLookupLab: React.FC<IpIntelligenceAsnLookupLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [ipInput, setIpInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [report, setReport] = useState<IpIntelligenceReport | null>(null);
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
    setIpInput('');
    setReport(null);
    setErrorMsg(null);
  };

  const executeLookup = async (targetIp: string | null) => {
    if (loading) return;

    const isSelf = targetIp === null;
    let verifiedIp = '';

    if (!isSelf) {
      const check = validateIpInput(targetIp);
      if (!check.valid) {
        setErrorMsg(check.error || 'عنوان IP غير صالح.');
        setReport(null);
        onNotify(check.error || 'عنوان IP غير صالح.', 'warning');
        return;
      }
      verifiedIp = check.ip;
      setIpInput(verifiedIp);
    }

    setLoading(true);
    setErrorMsg(null);
    setReport(null);

    const startedAt = performance.now();
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 12000);

    try {
      const endpoint = isSelf
        ? 'https://ipwho.is/'
        : `https://ipwho.is/${encodeURIComponent(verifiedIp)}`;

      const res = await fetch(endpoint, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });

      window.clearTimeout(timeoutId);
      const durationMs = Math.max(1, Math.round(performance.now() - startedAt));

      if (!res.ok) {
        throw new Error(`فشل الاتصال بخدمة ipwho.is (HTTP ${res.status}).`);
      }

      const data = (await res.json()) as IpWhoisResponse;
      if (!data || typeof data !== 'object') {
        throw new Error('استجابة غير صالحة من خدمة فحص الـ IP.');
      }

      if (data.success === false || !data.ip) {
        const apiErr = data.message
          ? `رفضت خدمة الفحص الاستعلام: ${data.message}`
          : 'تعذر استرجاع بيانات لهذا العنوان من الخدمة.';
        setErrorMsg(apiErr);
        onNotify(apiErr, 'warning');
        return;
      }

      if (isSelf) {
        setIpInput(data.ip);
      }

      const asnNum = data.connection?.asn;
      const asnFormatted =
        typeof asnNum === 'number' && asnNum > 0 ? `AS${asnNum}` : 'غير متوفر في الاستجابة';

      const tzLabel = data.timezone?.id
        ? `${data.timezone.id}${data.timezone.utc ? ` (UTC${data.timezone.utc})` : ''}`
        : 'غير متوفر في الاستجابة';

      const parsedReport: IpIntelligenceReport = {
        ip: data.ip,
        ipType: data.type || (data.ip.includes(':') ? 'IPv6' : 'IPv4'),
        continent: data.continent || 'غير متوفر',
        country: data.country || 'غير متوفر في الاستجابة',
        countryCode: data.country_code || '',
        region: data.region || 'غير متوفر',
        city: data.city || 'غير متوفر في الاستجابة',
        isp: data.connection?.isp || 'غير متوفر في الاستجابة',
        org: data.connection?.org || 'غير متوفر في الاستجابة',
        asn: asnFormatted,
        asnDomain: data.connection?.domain || 'غير متوفر',
        timezone: tzLabel,
        latitude: typeof data.latitude === 'number' ? data.latitude : null,
        longitude: typeof data.longitude === 'number' ? data.longitude : null,
        isSelfLookup: isSelf,
        durationMs,
        queriedAtIso: new Date().toISOString(),
        rawResponse: data,
      };

      setReport(parsedReport);

      const sha256 = await computeSha256Hex(JSON.stringify(data));
      onRecordAudit({
        id: `ip-asn-${Date.now()}`,
        fileName: `IP Lookup: ${parsedReport.ip}`,
        fileSize: parsedReport.asn,
        verdict: `${parsedReport.ip} (${parsedReport.ipType}) · ${parsedReport.country} / ${parsedReport.city} · ISP: ${parsedReport.isp}`,
        score: 100,
        risk: 'منخفض',
        sha256,
      });

      onNotify(
        `تم استرجاع بيانات ${parsedReport.ip} الحقيقية (${parsedReport.country} · ${parsedReport.asn}) في ${durationMs} ms.`,
        'success'
      );
    } catch (err: any) {
      window.clearTimeout(timeoutId);
      const errText =
        err?.name === 'AbortError'
          ? 'انتهت مهلة الاتصال بخدمة ipwho.is دون استجابة.'
          : err?.message || 'فشل الاتصال بخدمة فحص عناوين الـ IP.';
      setErrorMsg(errText);
      onNotify(errText, 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleManualSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    void executeLookup(ipInput);
  };

  const copyFullReport = async () => {
    if (!report) return;
    const text = [
      `IP Intelligence & ISP/ASN Report`,
      `IP Address: ${report.ip}`,
      `Type: ${report.ipType}`,
      `Country: ${report.country}${report.countryCode ? ` (${report.countryCode})` : ''}`,
      `Region / City: ${report.region} / ${report.city}`,
      `ISP: ${report.isp}`,
      `Organization: ${report.org}`,
      `ASN: ${report.asn}`,
      `ASN Domain: ${report.asnDomain}`,
      `Timezone: ${report.timezone}`,
      `Coordinates: ${
        report.latitude !== null && report.longitude !== null
          ? `${report.latitude}, ${report.longitude}`
          : 'Not provided'
      }`,
      `Source: ipwho.is (Real-time CORS API)`,
      `Queried At: ${report.queriedAtIso} (${report.durationMs} ms)`,
    ].join('\n');
    await handleCopy(text, 'full-ip-report', 'التقرير الكامل');
  };

  const exportJson = () => {
    if (!report) return;
    const payload = {
      queriedAt: report.queriedAtIso,
      durationMs: report.durationMs,
      source: 'https://ipwho.is/',
      summary: {
        ip: report.ip,
        type: report.ipType,
        country: report.country,
        countryCode: report.countryCode,
        region: report.region,
        city: report.city,
        isp: report.isp,
        organization: report.org,
        asn: report.asn,
        asnDomain: report.asnDomain,
        timezone: report.timezone,
        latitude: report.latitude,
        longitude: report.longitude,
      },
      rawApiResponse: report.rawResponse,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ip-intelligence-${report.ip.replace(/:/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير تقرير ${report.ip} بصيغة JSON.`, 'success');
  };

  return (
    <div className="space-y-6">
      {/* Query Panel */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-gray-800">
          <div className="space-y-1">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Network className="w-5 h-5 text-[#D4AF37]" />
              <span>فاحص IP ومزود الخدمة (IP Intelligence & ISP/ASN Lookup)</span>
            </h2>
            <p className="text-xs text-gray-400">
              استعلام مباشر وحقيقي عن عناوين <span className="font-mono text-gray-200">IPv4 / IPv6</span> ومعلومات الدولة والمدينة ومزود الخدمة (<span className="font-mono text-gray-200">ISP</span>) والمؤسسة ورقم الشبكة (<span className="font-mono text-gray-200">ASN</span>) عبر واجهة <span className="font-mono text-gray-200">ipwho.is</span> دون بيانات وهمية.
            </p>
          </div>

          <button
            type="button"
            disabled={loading}
            onClick={() => void executeLookup(null)}
            className="px-4 py-2.5 rounded-xl bg-gray-950 hover:bg-gray-800 border border-[#D4AF37]/50 text-[#D4AF37] font-bold text-xs inline-flex items-center justify-center gap-2 transition cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0 self-start lg:self-auto"
          >
            <Radio className="w-4 h-4" />
            <span>فحص عنوان IP الحالي الخاص بي</span>
          </button>
        </div>

        <form onSubmit={handleManualSubmit} className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-gray-500 absolute right-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={ipInput}
              onChange={(e) => setIpInput(e.target.value)}
              placeholder="أدخل عنوان IPv4 أو IPv6 للفحص (مثال: 8.8.8.8 أو 2606:4700:4700::1111)"
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
                  <span>جاري الفحص...</span>
                </>
              ) : (
                <>
                  <Network className="w-4 h-4" />
                  <span>فحص عنوان IP</span>
                </>
              )}
            </button>

            {(report || errorMsg || ipInput) && (
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
            <Network className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-bold text-white">في انتظار عنوان IP للفحص المباشر</h3>
          <p className="text-xs text-gray-400 max-w-xl mx-auto leading-relaxed">
            اضغط على <span className="text-[#D4AF37] font-semibold">فحص عنوان IP الحالي الخاص بي</span> لجلب بيانات اتصالك الحقيقية فوراً، أو أدخل أي عنوان IPv4 أو IPv6 عام في الحقل أعلاه. لا يتم عرض أي بيانات افتراضية أو محاكاة.
          </p>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-xs text-[#D4AF37] font-bold">
            <RefreshCw className="w-4 h-4 animate-spin" />
            <span>جاري الاستعلام الحي من واجهة ipwho.is...</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <div key={i} className="h-20 rounded-xl bg-gray-950 border border-gray-800 animate-pulse" />
            ))}
          </div>
        </div>
      )}

      {/* Populated Real IP Intelligence Report */}
      {report && !loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-6">
          <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-gray-800">
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2 text-base font-bold text-white">
                <span className="font-mono text-[#D4AF37]" dir="ltr">
                  {report.ip}
                </span>
                <span className="text-gray-600" aria-hidden="true">·</span>
                <span className="font-mono text-xs text-emerald-400">{report.ipType}</span>
                {report.isSelfLookup && (
                  <>
                    <span className="text-gray-600" aria-hidden="true">·</span>
                    <span className="text-xs font-normal text-gray-300">عنوان اتصالك الحالي</span>
                  </>
                )}
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-gray-400">
                <span>المصدر: <span className="font-mono text-gray-200">ipwho.is</span></span>
                <span aria-hidden="true">·</span>
                <span>زمن الاستجابة: <span className="font-mono tabular-nums text-gray-200">{report.durationMs} ms</span></span>
                <span aria-hidden="true">·</span>
                <span>الوقت: <span className="font-mono tabular-nums text-gray-200">{new Date(report.queriedAtIso).toLocaleTimeString('ar-SA')}</span></span>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => void copyFullReport()}
                className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
              >
                {copiedKey === 'full-ip-report' ? (
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

          {/* Structured Real Data Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-1.5">
              <div className="flex items-center justify-between text-xs text-gray-400">
                <span className="flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-[#D4AF37]" />
                  <span>عنوان IP والنوع</span>
                </span>
                <button
                  type="button"
                  onClick={() => void handleCopy(report.ip, 'ip', 'عنوان IP')}
                  className="text-gray-400 hover:text-white cursor-pointer"
                  title="نسخ IP"
                >
                  {copiedKey === 'ip' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-sm font-mono font-bold text-white break-all" dir="ltr">
                {report.ip}
              </div>
              <div className="text-xs font-mono text-emerald-400">{report.ipType}</div>
            </div>

            <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs text-gray-400">
                <MapPin className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>الدولة والمدينة</span>
              </div>
              <div className="text-sm font-bold text-white">
                {report.country} {report.countryCode ? `(${report.countryCode})` : ''}
              </div>
              <div className="text-xs text-gray-300">
                المدينة: <span className="text-white">{report.city}</span> · الإقليم: {report.region}
              </div>
            </div>

            <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-1.5">
              <div className="flex items-center justify-between text-xs text-gray-400">
                <span className="flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-[#D4AF37]" />
                  <span>رقم الشبكة المستقلة (ASN)</span>
                </span>
                <button
                  type="button"
                  onClick={() => void handleCopy(report.asn, 'asn', 'رقم ASN')}
                  className="text-gray-400 hover:text-white cursor-pointer"
                  title="نسخ ASN"
                >
                  {copiedKey === 'asn' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-sm font-mono font-bold text-[#D4AF37]" dir="ltr">
                {report.asn}
              </div>
              <div className="text-xs font-mono text-gray-400 truncate" dir="ltr">
                Domain: {report.asnDomain}
              </div>
            </div>

            <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-1.5">
              <div className="flex items-center justify-between text-xs text-gray-400">
                <span className="flex items-center gap-1.5">
                  <Network className="w-3.5 h-3.5 text-[#D4AF37]" />
                  <span>مزود الخدمة (ISP)</span>
                </span>
                <button
                  type="button"
                  onClick={() => void handleCopy(report.isp, 'isp', 'اسم ISP')}
                  className="text-gray-400 hover:text-white cursor-pointer"
                  title="نسخ ISP"
                >
                  {copiedKey === 'isp' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-sm font-bold text-white break-words" dir="ltr">
                {report.isp}
              </div>
            </div>

            <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs text-gray-400">
                <Building2 className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>المؤسسة (Organization)</span>
              </div>
              <div className="text-sm font-bold text-white break-words" dir="ltr">
                {report.org}
              </div>
            </div>

            <div className="rounded-xl bg-gray-950 border border-gray-800 p-4 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs text-gray-400">
                <Globe className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>المنطقة الزمنية والإحداثيات</span>
              </div>
              <div className="text-xs font-mono text-white truncate" dir="ltr">
                {report.timezone}
              </div>
              <div className="text-xs font-mono tabular-nums text-gray-400" dir="ltr">
                {report.latitude !== null && report.longitude !== null
                  ? `${report.latitude}, ${report.longitude}`
                  : 'الإحداثيات غير متوفرة'}
              </div>
            </div>
          </div>

          {/* Complete Raw Returned Fields Table */}
          <div className="overflow-x-auto border border-gray-800 rounded-xl">
            <table className="w-full text-xs text-right">
              <thead className="bg-gray-950 text-gray-400 border-b border-gray-800 font-mono">
                <tr>
                  <th className="py-3 px-4 whitespace-nowrap">الحقل</th>
                  <th className="py-3 px-4 whitespace-nowrap">القيمة الحقيقية المسترجعة</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800 text-[12px]">
                <tr className="hover:bg-gray-950/60">
                  <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">عنوان IP</td>
                  <td className="py-2.5 px-4 font-mono text-white" dir="ltr">{report.ip}</td>
                </tr>
                <tr className="hover:bg-gray-950/60">
                  <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">نوع العنوان</td>
                  <td className="py-2.5 px-4 font-mono text-emerald-400">{report.ipType}</td>
                </tr>
                <tr className="hover:bg-gray-950/60">
                  <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">القارة / الدولة / المدينة</td>
                  <td className="py-2.5 px-4 text-white">
                    {report.continent} · {report.country} {report.countryCode ? `(${report.countryCode})` : ''} · {report.city}
                  </td>
                </tr>
                <tr className="hover:bg-gray-950/60">
                  <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">مزود الخدمة (ISP)</td>
                  <td className="py-2.5 px-4 font-mono text-white" dir="ltr">{report.isp}</td>
                </tr>
                <tr className="hover:bg-gray-950/60">
                  <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">المؤسسة (Organization)</td>
                  <td className="py-2.5 px-4 font-mono text-white" dir="ltr">{report.org}</td>
                </tr>
                <tr className="hover:bg-gray-950/60">
                  <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">رقم الشبكة المستقلة (ASN)</td>
                  <td className="py-2.5 px-4 font-mono text-[#D4AF37]" dir="ltr">{report.asn}</td>
                </tr>
                <tr className="hover:bg-gray-950/60">
                  <td className="py-2.5 px-4 text-gray-400 font-bold whitespace-nowrap">نطاق الشبكة (ASN Domain)</td>
                  <td className="py-2.5 px-4 font-mono text-gray-300" dir="ltr">{report.asnDomain}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
