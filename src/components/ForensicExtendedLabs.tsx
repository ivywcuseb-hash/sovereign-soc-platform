import React, { useMemo, useState } from 'react';
import SparkMD5 from 'spark-md5';
import {
  MailCheck,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  RefreshCw,
  FileCode2,
  Upload,
  KeyRound,
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  Network,
  Download,
  Copy,
  Check,
  Hash,
  Clock,
  Globe,
  Filter,
  Eye,
  Plus,
  FileText,
  Trash2,
} from 'lucide-react';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface ExtendedLabProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

async function digestHex(algo: 'SHA-256' | 'SHA-1', input: ArrayBuffer | Uint8Array): Promise<string> {
  const src = input instanceof Uint8Array ? input : new Uint8Array(input);
  const copy = new Uint8Array(src.byteLength);
  copy.set(src);
  const hashBuf = await crypto.subtle.digest(algo, copy.buffer);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

// ============================================================================
// 1. Email Security & DNS Auditor (Google DNS-over-HTTPS: SPF, DMARC, MX, DKIM)
// ============================================================================
interface DnsAnswerRecord {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface EmailDnsAuditReport {
  domain: string;
  checkedAt: string;
  mxRecords: Array<{ priority: number; host: string; ttl: number }>;
  mailProviderHint: string;
  spfRecords: string[];
  spfAssessment: {
    present: boolean;
    qualifier: 'hardfail (-all)' | 'softfail (~all)' | 'neutral (?all)' | 'allow-all (+all)' | 'missing';
    includes: string[];
    ip4s: string[];
    lookupEstimate: number;
    issues: string[];
  };
  dmarcRecord: string | null;
  dmarcAssessment: {
    present: boolean;
    policy: string;
    subdomainPolicy: string | null;
    pct: number;
    rua: string[];
    ruf: string[];
    adkim: string;
    aspf: string;
    issues: string[];
  };
  dkimSelectorsFound: Array<{ selector: string; record: string }>;
  aRecords: string[];
  caaRecords: string[];
  nsRecords: string[];
  spoofingScore: number;
  riskLevel: 'آمن' | 'متوسط' | 'مرتفع' | 'حرج';
  recommendations: string[];
}

async function queryGoogleDoh(name: string, type: string): Promise<DnsAnswerRecord[]> {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      { headers: { Accept: 'application/dns-json' } }
    );
    if (!res.ok) return [];
    const data = await res.json();
    if (!Array.isArray(data?.Answer)) return [];
    return data.Answer as DnsAnswerRecord[];
  } catch {
    return [];
  }
}

function unquoteTxtData(raw: string): string {
  // Google DoH returns TXT strings enclosed in quotes, sometimes concatenated `"part1" "part2"`
  return String(raw || '')
    .replace(/"\s+"/g, '')
    .replace(/^"|"$/g, '')
    .trim();
}

export const EmailSecurityDnsAuditorLab: React.FC<ExtendedLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [domainInput, setDomainInput] = useState('');
  const [customDkimSelector, setCustomDkimSelector] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<EmailDnsAuditReport | null>(null);

  const runAudit = async (e?: React.FormEvent, overrideDomain?: string) => {
    e?.preventDefault();
    const raw = (overrideDomain ?? domainInput).trim();
    if (!raw) {
      setError('يرجى إدخال اسم النطاق أو البريد الإلكتروني (مثال: google.com أو user@domain.com).');
      return;
    }

    let domain = raw.toLowerCase();
    if (domain.includes('@')) domain = domain.split('@').pop() || '';
    if (/^https?:\/\//i.test(domain)) {
      try {
        domain = new URL(domain).hostname.toLowerCase();
      } catch {
        // ignore
      }
    }
    domain = domain.replace(/^www\./, '').replace(/\/.*$/, '').trim();

    if (!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) {
      setError('صيغة النطاق غير صالحة.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const selectors = Array.from(
        new Set(
          [
            customDkimSelector.trim().toLowerCase(),
            'google',
            'selector1',
            'selector2',
            'default',
            'k1',
            's1',
            's2',
            'dkim',
            'mail',
          ].filter(Boolean)
        )
      );

      const [mxAns, txtAns, dmarcAns, aAns, caaAns, nsAns, ...dkimResults] = await Promise.all([
        queryGoogleDoh(domain, 'MX'),
        queryGoogleDoh(domain, 'TXT'),
        queryGoogleDoh(`_dmarc.${domain}`, 'TXT'),
        queryGoogleDoh(domain, 'A'),
        queryGoogleDoh(domain, 'CAA'),
        queryGoogleDoh(domain, 'NS'),
        ...selectors.map(async (sel) => ({
          selector: sel,
          answers: await queryGoogleDoh(`${sel}._domainkey.${domain}`, 'TXT'),
        })),
      ]);

      // Parse MX
      const mxRecords = mxAns
        .filter((a) => a.type === 15)
        .map((a) => {
          const parts = String(a.data || '').trim().split(/\s+/);
          const priority = Number(parts[0]) || 10;
          const host = (parts[1] || parts[0] || '').replace(/\.$/, '').toLowerCase();
          return { priority, host, ttl: a.TTL };
        })
        .sort((a, b) => a.priority - b.priority);

      const joinedMx = mxRecords.map((m) => m.host).join(' ');
      let mailProviderHint = mxRecords.length ? 'خادم بريد مخصص / خاص' : 'لا توجد سجلات MX';
      if (/google\.com|googlemail\.com/i.test(joinedMx)) mailProviderHint = 'Google Workspace';
      else if (/outlook\.com|protection\.outlook\.com/i.test(joinedMx)) mailProviderHint = 'Microsoft 365 / Exchange Online';
      else if (/protonmail|proton\.ch/i.test(joinedMx)) mailProviderHint = 'Proton Mail';
      else if (/zoho\./i.test(joinedMx)) mailProviderHint = 'Zoho Mail';
      else if (/mimecast|proofpoint|barracuda/i.test(joinedMx)) mailProviderHint = 'Secure Email Gateway (Enterprise)';
      else if (/mx\d*\.cloudflare/i.test(joinedMx)) mailProviderHint = 'Cloudflare Email Routing';

      // Parse SPF
      const allTxts = txtAns.filter((a) => a.type === 16).map((a) => unquoteTxtData(a.data));
      const spfRecords = allTxts.filter((t) => /^v=spf1\b/i.test(t));
      const spfIssues: string[] = [];
      let qualifier: EmailDnsAuditReport['spfAssessment']['qualifier'] = 'missing';
      const includes: string[] = [];
      const ip4s: string[] = [];
      let lookupEstimate = 0;

      if (spfRecords.length === 0) {
        spfIssues.push('لا يوجد سجل SPF، مما يسمح بانتحال النطاق بسهولة في رسائل البريد.');
      } else {
        if (spfRecords.length > 1) {
          spfIssues.push('تحذير RFC 7208: يوجد أكثر من سجل SPF واحد مما قد يؤدي لفشل التحقق (PermError).');
        }
        const primarySpf = spfRecords[0];
        const tokens = primarySpf.split(/\s+/);
        for (const tok of tokens) {
          const lower = tok.toLowerCase();
          if (lower.startsWith('include:')) {
            includes.push(tok.slice(8));
            lookupEstimate++;
          } else if (lower.startsWith('ip4:')) {
            ip4s.push(tok.slice(4));
          } else if (lower === 'a' || lower.startsWith('a:') || lower === 'mx' || lower.startsWith('mx:') || lower.startsWith('exists:') || lower.startsWith('redirect=')) {
            lookupEstimate++;
          }
        }
        if (/\s-all(?:\s|$)/i.test(primarySpf)) qualifier = 'hardfail (-all)';
        else if (/\s~all(?:\s|$)/i.test(primarySpf)) {
          qualifier = 'softfail (~all)';
          spfIssues.push('سياسة SPF تستخدم SoftFail (~all)؛ يُفضّل تشديدها إلى (-all) بعد التأكد من كافة المرسلين.');
        } else if (/\s\?all(?:\s|$)/i.test(primarySpf)) {
          qualifier = 'neutral (?all)';
          spfIssues.push('سياسة SPF محايدة (?all) ولا تمنع الانتحال.');
        } else if (/\s\+?all(?:\s|$)/i.test(primarySpf)) {
          qualifier = 'allow-all (+all)';
          spfIssues.push('ثغرة حرجة: سجل SPF يحتوي على (+all) مما يسمح لأي خادم على الإنترنت بالإرسال باسم النطاق!');
        }
        if (lookupEstimate > 10) {
          spfIssues.push(`تجاوز حد استعلامات DNS (${lookupEstimate} / 10)، قد يؤدي إلى كسر مصادقة SPF.`);
        }
      }

      // Parse DMARC
      const dmarcTxts = dmarcAns
        .filter((a) => a.type === 16)
        .map((a) => unquoteTxtData(a.data))
        .filter((t) => /^v=DMARC1\b/i.test(t));
      const dmarcRecord = dmarcTxts[0] || null;
      const dmarcIssues: string[] = [];
      let policy = 'missing';
      let subdomainPolicy: string | null = null;
      let pct = 100;
      const rua: string[] = [];
      const ruf: string[] = [];
      let adkim = 'r';
      let aspf = 'r';

      if (!dmarcRecord) {
        dmarcIssues.push('لا يوجد سجل DMARC (_dmarc) — النطاق مكشوف لهجمات انتحال هوية البريد (Email Spoofing).');
      } else {
        const tagPairs = dmarcRecord.split(';').map((s) => s.trim()).filter(Boolean);
        for (const pair of tagPairs) {
          const [kRaw, ...vParts] = pair.split('=');
          const k = (kRaw || '').trim().toLowerCase();
          const v = vParts.join('=').trim();
          if (k === 'p') policy = v.toLowerCase();
          else if (k === 'sp') subdomainPolicy = v.toLowerCase();
          else if (k === 'pct') pct = Number(v) || 100;
          else if (k === 'rua') rua.push(...v.split(',').map((x) => x.trim()).filter(Boolean));
          else if (k === 'ruf') ruf.push(...v.split(',').map((x) => x.trim()).filter(Boolean));
          else if (k === 'adkim') adkim = v.toLowerCase();
          else if (k === 'aspf') aspf = v.toLowerCase();
        }
        if (policy === 'none') {
          dmarcIssues.push('سياسة DMARC مضبوطة على المراقبة فقط (p=none) ولا تمنع وصول الرسائل المنتحلة.');
        } else if (policy === 'quarantine') {
          dmarcIssues.push('سياسة DMARC تحجر الرسائل المشبوهة (p=quarantine)؛ المستوى الأعلى أماناً هو (p=reject).');
        }
        if (pct < 100) {
          dmarcIssues.push(`نسبة تطبيق السياسة pct=${pct}% أقل من 100%.`);
        }
        if (rua.length === 0) {
          dmarcIssues.push('لا يوجد عنوان تقارير تجميعية (rua=) لمتابعة محاولات الانتحال.');
        }
      }

      // DKIM Hits
      const dkimSelectorsFound = dkimResults
        .map((item) => {
          const hit = item.answers
            .filter((a) => a.type === 16)
            .map((a) => unquoteTxtData(a.data))
            .find((t) => /v=DKIM1|p=/i.test(t));
          return hit ? { selector: item.selector, record: hit } : null;
        })
        .filter((x): x is { selector: string; record: string } => Boolean(x));

      const aRecords = aAns.filter((a) => a.type === 1).map((a) => a.data);
      const caaRecords = caaAns.filter((a) => a.type === 257).map((a) => unquoteTxtData(a.data));
      const nsRecords = nsAns.filter((a) => a.type === 2).map((a) => String(a.data).replace(/\.$/, ''));

      // Score calculation (100 = strongest anti-spoofing posture)
      let score = 0;
      if (mxRecords.length > 0) score += 10;
      if (qualifier === 'hardfail (-all)') score += 30;
      else if (qualifier === 'softfail (~all)') score += 20;
      else if (qualifier === 'neutral (?all)') score += 8;
      else if (qualifier === 'allow-all (+all)') score += 0;

      if (dmarcRecord) {
        if (policy === 'reject') score += 40;
        else if (policy === 'quarantine') score += 30;
        else if (policy === 'none') score += 12;
        if (rua.length > 0) score += 5;
      }
      if (dkimSelectorsFound.length > 0) score += 15;
      if (spfRecords.length > 1) score = Math.max(0, score - 15);
      score = Math.min(100, Math.max(0, score));

      const riskLevel: EmailDnsAuditReport['riskLevel'] =
        score >= 80 ? 'آمن' : score >= 55 ? 'متوسط' : score >= 30 ? 'مرتفع' : 'حرج';

      const recommendations: string[] = [...spfIssues, ...dmarcIssues];
      if (dkimSelectorsFound.length === 0) {
        recommendations.push('لم يُعثر على مفتاح DKIM ضمن المحددات القياسية؛ تأكد من تفعيل توقيع DKIM في مزود البريد.');
      }
      if (caaRecords.length === 0) {
        recommendations.push('يُنصح بإضافة سجل CAA لتقييد الجهات المصرّح لها بإصدار شهادات SSL للنطاق.');
      }
      if (recommendations.length === 0) {
        recommendations.push('إعدادات حماية البريد الإلكتروني قوية ومحصّنة ضد هجمات الانتحال (Spoofing).');
      }

      const finalReport: EmailDnsAuditReport = {
        domain,
        checkedAt: new Date().toISOString(),
        mxRecords,
        mailProviderHint,
        spfRecords,
        spfAssessment: {
          present: spfRecords.length > 0,
          qualifier,
          includes,
          ip4s,
          lookupEstimate,
          issues: spfIssues,
        },
        dmarcRecord,
        dmarcAssessment: {
          present: Boolean(dmarcRecord),
          policy,
          subdomainPolicy,
          pct,
          rua,
          ruf,
          adkim,
          aspf,
          issues: dmarcIssues,
        },
        dkimSelectorsFound,
        aRecords,
        caaRecords,
        nsRecords,
        spoofingScore: score,
        riskLevel,
        recommendations,
      };

      setReport(finalReport);
      onNotify(`تم إتمام تدقيق أمان البريد والـ DNS للنطاق ${domain} (التقييم: ${score}/100)`, 'success');
      onRecordAudit({
        id: `dns-email-${Date.now()}`,
        fileName: `تدقيق DNS/البريد: ${domain}`,
        fileSize: `${mxRecords.length} MX`,
        verdict: `حماية الانتحال: ${score}/100 (DMARC: ${policy})`,
        score,
        risk: riskLevel === 'آمن' ? 'منخفض' : riskLevel,
        sha256: `DOH-GOOGLE-${domain.toUpperCase()}`,
      });
    } catch (err: any) {
      setError(err?.message || 'تعذر الاتصال بخدمة Google DNS-over-HTTPS؛ تحقق من اتصال الإنترنت واسم النطاق وأعد المحاولة.');
      onNotify('فشل تدقيق سجلات DNS', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6" dir="rtl">
      <div className="rounded-2xl bg-gray-900/95 border border-gray-800 p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-[#D4AF37]">
              DNS-over-HTTPS · SPF / DMARC / MX / DKIM
            </div>
            <h2 className="text-xl font-bold text-white">
              فحص أمان النطاقات والبريد (DNS / SPF)
            </h2>
            <p className="text-xs text-gray-400">
              استعلام مباشر عبر Google DoH لسجلات MX وSPF وDMARC وDKIM وتقييم الحماية من انتحال البريد.
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {['google.com', 'microsoft.com', 'cloudflare.com'].map((sample) => (
              <button
                key={sample}
                type="button"
                onClick={() => {
                  setDomainInput(sample);
                  void runAudit(undefined, sample);
                }}
                className="px-3 py-1.5 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-800 text-[11px] font-mono text-gray-300 cursor-pointer"
              >
                {sample}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={(e) => void runAudit(e)} className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <input
            type="text"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            placeholder="أدخل النطاق أو البريد الإلكتروني (مثال: company.com أو admin@company.com)"
            className="md:col-span-7 px-4 py-3 rounded-xl bg-gray-950 border border-gray-800 focus:border-[#D4AF37] text-xs text-white font-mono outline-none"
          />
          <input
            type="text"
            value={customDkimSelector}
            onChange={(e) => setCustomDkimSelector(e.target.value)}
            placeholder="محدد DKIM إضافي (اختياري)"
            className="md:col-span-3 px-4 py-3 rounded-xl bg-gray-950 border border-gray-800 focus:border-[#D4AF37] text-xs text-white font-mono outline-none"
          />
          <button
            type="submit"
            disabled={loading}
            className="md:col-span-2 py-3 px-4 rounded-xl bg-[#D4AF37] hover:opacity-90 disabled:opacity-60 text-gray-950 font-bold text-xs flex items-center justify-center gap-2 cursor-pointer"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{loading ? 'جاري الفحص...' : 'فحص النطاق'}</span>
          </button>
        </form>

        {error && (
          <div className="p-3.5 rounded-2xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {report && (
        <div className="space-y-6">
          {/* Score & Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-5 rounded-2xl bg-gray-900 border border-gray-800 space-y-2">
              <div className="text-[11px] text-gray-400">درجة الحماية ضد الانتحال</div>
              <div className="flex items-baseline justify-between">
                <span className="text-3xl font-bold font-mono text-[#D4AF37]">
                  {report.spoofingScore}/100
                </span>
                <span
                  className={`px-2.5 py-0.5 rounded-lg text-[11px] font-bold ${
                    report.riskLevel === 'آمن'
                      ? 'bg-emerald-500/15 text-emerald-300'
                      : report.riskLevel === 'متوسط'
                      ? 'bg-amber-500/15 text-amber-300'
                      : 'bg-red-500/15 text-red-300'
                  }`}
                >
                  {report.riskLevel}
                </span>
              </div>
              <div className="text-[11px] text-gray-400 font-mono truncate">{report.mailProviderHint}</div>
            </div>

            <div className="p-5 rounded-2xl bg-gray-900 border border-gray-800 space-y-2">
              <div className="text-[11px] text-gray-400">سياسة SPF</div>
              <div className="text-base font-bold text-white font-mono">
                {report.spfAssessment.qualifier}
              </div>
              <div className="text-[11px] text-gray-400">
                استعلامات DNS المقدرة: <strong className="text-white">{report.spfAssessment.lookupEstimate}</strong> / 10
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-gray-900 border border-gray-800 space-y-2">
              <div className="text-[11px] text-gray-400">سياسة DMARC (_dmarc)</div>
              <div className="text-base font-bold text-white font-mono">
                {report.dmarcAssessment.present ? `p=${report.dmarcAssessment.policy}` : 'غير موجود'}
              </div>
              <div className="text-[11px] text-gray-400">
                نسبة التطبيق: <strong className="text-white">{report.dmarcAssessment.pct}%</strong> • تقارير RUA:{' '}
                <strong className="text-white">{report.dmarcAssessment.rua.length}</strong>
              </div>
            </div>

            <div className="p-5 rounded-2xl bg-gray-900 border border-gray-800 space-y-2">
              <div className="text-[11px] text-gray-400">خوادم البريد (MX) ومفاتيح DKIM</div>
              <div className="text-base font-bold text-white font-mono">
                {report.mxRecords.length} MX • {report.dkimSelectorsFound.length} DKIM
              </div>
              <div className="text-[11px] text-gray-400">
                سجلات CAA: <strong className="text-white">{report.caaRecords.length}</strong>
              </div>
            </div>
          </div>

          {/* Detailed Records Breakdown */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="rounded-3xl bg-gray-900 border border-gray-800 p-5 space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Globe className="w-4 h-4 text-[#D4AF37]" />
                <span>خوادم البريد المستقبلة (MX Records)</span>
              </h3>
              {report.mxRecords.length === 0 ? (
                <div className="text-xs text-gray-400">لا توجد سجلات MX مسجلة لهذا النطاق.</div>
              ) : (
                <div className="space-y-2">
                  {report.mxRecords.map((mx, idx) => (
                    <div
                      key={`${mx.host}-${idx}`}
                      className="px-3.5 py-2.5 rounded-xl bg-gray-950 border border-gray-800 flex items-center justify-between text-xs font-mono"
                    >
                      <span className="text-white">{mx.host}</span>
                      <span className="text-[#D4AF37]">Priority {mx.priority} • TTL {mx.ttl}s</span>
                    </div>
                  ))}
                </div>
              )}

              <div className="pt-2 border-t border-gray-800 space-y-2">
                <div className="text-xs font-bold text-white">سجل SPF الخام:</div>
                <div className="p-3 rounded-xl bg-gray-950 border border-gray-800 text-[11px] font-mono text-emerald-300 break-all">
                  {report.spfRecords[0] || 'لم يتم العثور على سجل SPF'}
                </div>
              </div>

              <div className="space-y-2">
                <div className="text-xs font-bold text-white">سجل DMARC الخام:</div>
                <div className="p-3 rounded-xl bg-gray-950 border border-gray-800 text-[11px] font-mono text-sky-300 break-all">
                  {report.dmarcRecord || 'لم يتم العثور على سجل _dmarc'}
                </div>
              </div>
            </div>

            <div className="rounded-3xl bg-gray-900 border border-gray-800 p-5 space-y-4">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span>التوصيات الأمنية ومفاتيح DKIM المرصودة</span>
              </h3>

              <div className="space-y-2">
                {report.recommendations.map((rec, i) => (
                  <div
                    key={i}
                    className="p-3 rounded-xl bg-gray-950 border border-gray-800 text-xs text-gray-200 flex items-start gap-2"
                  >
                    {report.spoofingScore >= 80 && i === 0 ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    )}
                    <span>{rec}</span>
                  </div>
                ))}
              </div>

              {report.dkimSelectorsFound.length > 0 && (
                <div className="space-y-2 pt-2 border-t border-gray-800">
                  <div className="text-xs font-bold text-white">مفاتيح DKIM النشطة:</div>
                  {report.dkimSelectorsFound.map((dk) => (
                    <div
                      key={dk.selector}
                      className="p-3 rounded-xl bg-gray-950 border border-emerald-500/30 text-[11px] font-mono space-y-1"
                    >
                      <div className="text-emerald-400 font-bold">Selector: {dk.selector}._domainkey</div>
                      <div className="text-gray-400 break-all line-clamp-3">{dk.record}</div>
                    </div>
                  ))}
                </div>
              )}

              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-gray-800 text-[11px]">
                <div className="p-3 rounded-xl bg-gray-950 border border-gray-800">
                  <div className="text-gray-400 mb-1">عناوين A:</div>
                  <div className="font-mono text-white break-all">
                    {report.aRecords.join(', ') || '—'}
                  </div>
                </div>
                <div className="p-3 rounded-xl bg-gray-950 border border-gray-800">
                  <div className="text-gray-400 mb-1">خوادم الأسماء NS:</div>
                  <div className="font-mono text-white break-all">
                    {report.nsRecords.slice(0, 3).join(', ') || '—'}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 2. YARA Pattern Scanner (Real .yar Database + Multi-File Byte/Hex/Regex Engine)
// ============================================================================
interface ParsedYaraStringDef {
  id: string;
  kind: 'text' | 'hex' | 'regex';
  raw: string;
  nocase: boolean;
  ascii: boolean;
  wide: boolean;
  hexTokens?: Array<number | null>;
  regex?: RegExp;
}

interface ParsedYaraRule {
  name: string;
  tags: string[];
  meta: Record<string, string>;
  condition: string;
  strings: ParsedYaraStringDef[];
}

interface YaraMatchHit {
  ruleName: string;
  stringId: string;
  kind: 'text' | 'hex' | 'regex';
  offset: number;
  offsetHex: string;
  matchedHex: string;
  previewAscii: string;
}

interface YaraMatchedRuleSummary {
  ruleName: string;
  tags: string[];
  severity: string;
  description: string;
  condition: string;
  hitCount: number;
  hits: YaraMatchHit[];
}

interface YaraFileScanResult {
  fileName: string;
  fileSize: number;
  sha256: string;
  md5: string;
  rulesEvaluated: number;
  matchedRules: YaraMatchedRuleSummary[];
  totalHits: number;
  scannedMs: number;
}

interface LoadedYarFileInfo {
  name: string;
  size: number;
  ruleCount: number;
}

const YARA_PRESETS: Array<{ label: string; ruleText: string }> = [
  {
    label: 'Windows PE & API Hooks',
    ruleText: `rule Suspicious_PE_Or_API_Hooks : executable injection
{
  meta:
    description = "Detects Windows PE binaries referencing process injection APIs"
    severity = "high"
  strings:
    $mz_header = { 4D 5A ?? ?? }
    $pe_sig = { 50 45 00 00 }
    $api_alloc = "VirtualAlloc" nocase ascii wide
    $api_thread = "CreateRemoteThread" nocase ascii wide
    $api_write = "WriteProcessMemory" nocase ascii wide
  condition:
    ($mz_header and $pe_sig) or any of ($api_*)
}`,
  },
  {
    label: 'PowerShell & Dropper',
    ruleText: `rule Obfuscated_Script_Dropper : script powershell
{
  meta:
    description = "Detects obfuscated PowerShell or script dropper indicators"
    severity = "critical"
  strings:
    $ps = "powershell" nocase
    $enc = "-EncodedCommand" nocase
    $iex = "Invoke-Expression" nocase
    $b64 = "FromBase64String" nocase
    $wsh = "WScript.Shell" nocase
    $url = /https?:\\/\\/[a-zA-Z0-9._-]+\\.[a-z]{2,}/i
  condition:
    2 of them
}`,
  },
  {
    label: 'Embedded Payload / PDF JS',
    ruleText: `rule Embedded_Payload_Or_PDF_JS : document archive
{
  meta:
    description = "Detects ZIP headers or active JavaScript triggers in documents"
    severity = "medium"
  strings:
    $zip_magic = { 50 4B 03 04 }
    $pdf_js = "/JavaScript" nocase
    $pdf_open = "/OpenAction" nocase
    $script_tag = "<script" nocase
  condition:
    any of them
}`,
  },
];

function stripYaraComments(src: string): string {
  let out = '';
  let i = 0;
  let inDoubleQuote = false;
  let inRegex = false;
  while (i < src.length) {
    const ch = src[i];
    const next = src[i + 1];
    if (inDoubleQuote) {
      out += ch;
      if (ch === '\\' && i + 1 < src.length) {
        out += src[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inDoubleQuote = false;
      i++;
      continue;
    }
    if (inRegex) {
      out += ch;
      if (ch === '\\' && i + 1 < src.length) {
        out += src[i + 1];
        i += 2;
        continue;
      }
      if (ch === '/') inRegex = false;
      i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      i = end === -1 ? src.length : end + 2;
      continue;
    }
    if (ch === '/' && next === '/') {
      const nl = src.indexOf('\n', i + 2);
      i = nl === -1 ? src.length : nl;
      continue;
    }
    if (ch === '"') {
      inDoubleQuote = true;
    } else if (ch === '/' && (i === 0 || /[\s=:(,]/.test(src[i - 1]))) {
      inRegex = true;
    }
    out += ch;
    i++;
  }
  return out;
}

function parseHexPatternTokens(rawHex: string): Array<number | null> {
  // Expand simple byte jumps like [2] into wildcards, strip ranges [2-4] cleanly
  const expanded = rawHex
    .replace(/\[\s*(\d+)\s*\]/g, (_m, n) => ' ?? '.repeat(Math.min(16, Number(n))))
    .replace(/\[\s*\d*\s*-\s*\d*\s*\]/g, ' ?? ');

  return expanded
    .replace(/[{}()|]/g, ' ')
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((tok) => {
      if (tok.includes('?')) return null;
      const val = parseInt(tok, 16);
      return Number.isNaN(val) ? null : val & 0xff;
    });
}

function splitYaraRuleSections(body: string): { metaSec: string; stringsSec: string; conditionSec: string } {
  const sectionRegex = /(?:^|\n)\s*(meta|strings|condition)\s*:/gi;
  const markers: Array<{ key: 'meta' | 'strings' | 'condition'; start: number; endOfLabel: number }> = [];
  let m: RegExpExecArray | null;
  while ((m = sectionRegex.exec(body)) !== null) {
    markers.push({
      key: m[1].toLowerCase() as 'meta' | 'strings' | 'condition',
      start: m.index,
      endOfLabel: m.index + m[0].length,
    });
  }
  let metaSec = '';
  let stringsSec = '';
  let conditionSec = '';
  for (let i = 0; i < markers.length; i++) {
    const cur = markers[i];
    const nextStart = i + 1 < markers.length ? markers[i + 1].start : body.length;
    const content = body.slice(cur.endOfLabel, nextStart).trim();
    if (cur.key === 'meta') metaSec = content;
    else if (cur.key === 'strings') stringsSec = content;
    else if (cur.key === 'condition') conditionSec = content;
  }
  return { metaSec, stringsSec, conditionSec };
}

function parseYaraRulesInput(rawInput: string): ParsedYaraRule[] {
  const cleaned = stripYaraComments(rawInput).trim();
  if (!cleaned) return [];

  const ruleBlocks: ParsedYaraRule[] = [];
  const headerRegex = /\b(?:private\s+|global\s+)*rule\s+([A-Za-z0-9_]+)(?:\s*:\s*([^{]+))?\s*\{/g;
  let match: RegExpExecArray | null;

  while ((match = headerRegex.exec(cleaned)) !== null) {
    const name = match[1];
    const tags = (match[2] || '')
      .trim()
      .split(/\s+/)
      .filter(Boolean);

    // Brace-balanced scan from opening '{'
    let idx = headerRegex.lastIndex;
    let depth = 1;
    let inQuote = false;
    while (idx < cleaned.length && depth > 0) {
      const ch = cleaned[idx];
      if (inQuote) {
        if (ch === '\\' && idx + 1 < cleaned.length) {
          idx += 2;
          continue;
        }
        if (ch === '"') inQuote = false;
      } else {
        if (ch === '"') inQuote = true;
        else if (ch === '{') depth++;
        else if (ch === '}') depth--;
      }
      idx++;
    }

    if (depth !== 0) continue;
    const body = cleaned.slice(headerRegex.lastIndex, idx - 1);
    headerRegex.lastIndex = idx;

    const { metaSec, stringsSec, conditionSec } = splitYaraRuleSections(body);
    const meta: Record<string, string> = {};
    for (const line of metaSec.split(/\r?\n/)) {
      const mm = line.trim().match(/^([A-Za-z0-9_]+)\s*=\s*(?:"([^"]*)"|([^\s]+))/);
      if (mm) {
        meta[mm[1].toLowerCase()] = (mm[2] ?? mm[3] ?? '').trim();
      }
    }

    const defs: ParsedYaraStringDef[] = [];
    for (const line of stringsSec.split(/\r?\n/)) {
      const l = line.trim();
      if (!l) continue;
      const mText = l.match(/^(\$[A-Za-z0-9_*]+)\s*=\s*"((?:[^"\\]|\\.)*)"(.*)$/);
      if (mText) {
        const mods = mText[3] || '';
        const nocase = /\bnocase\b/i.test(mods);
        const hasWide = /\bwide\b/i.test(mods);
        const hasAscii = /\bascii\b/i.test(mods) || !hasWide;
        defs.push({
          id: mText[1],
          kind: 'text',
          raw: mText[2]
            .replace(/\\"/g, '"')
            .replace(/\\n/g, '\n')
            .replace(/\\r/g, '\r')
            .replace(/\\t/g, '\t')
            .replace(/\\\\/g, '\\'),
          nocase,
          ascii: hasAscii,
          wide: hasWide,
        });
        continue;
      }
      const mHex = l.match(/^(\$[A-Za-z0-9_*]+)\s*=\s*\{([^}]+)\}/);
      if (mHex) {
        defs.push({
          id: mHex[1],
          kind: 'hex',
          raw: mHex[2].trim(),
          nocase: false,
          ascii: false,
          wide: false,
          hexTokens: parseHexPatternTokens(mHex[2]),
        });
        continue;
      }
      const mRe = l.match(/^(\$[A-Za-z0-9_*]+)\s*=\s*\/(.+?)\/([gimsuy]*)(.*)$/);
      if (mRe) {
        try {
          const flags = mRe[3].includes('g') ? mRe[3] : `${mRe[3]}g`;
          defs.push({
            id: mRe[1],
            kind: 'regex',
            raw: mRe[2],
            nocase: flags.includes('i'),
            ascii: true,
            wide: false,
            regex: new RegExp(mRe[2], flags),
          });
        } catch {
          // ignore malformed regex
        }
      }
    }

    if (defs.length > 0) {
      ruleBlocks.push({
        name,
        tags,
        meta,
        condition: (conditionSec || 'any of them').trim(),
        strings: defs,
      });
    }
  }

  // Fallback: simple line-by-line pattern mode if plain IOCs/patterns pasted without `rule ... { }`
  if (ruleBlocks.length === 0) {
    const simpleDefs: ParsedYaraStringDef[] = [];
    const lines = cleaned.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    lines.forEach((line, idx) => {
      const id = `$p${idx + 1}`;
      if (/^\{[0-9A-Fa-f?\s]+\}$/.test(line) || /^hex:/i.test(line)) {
        const cleanedHex = line.replace(/^hex:/i, '').trim();
        simpleDefs.push({
          id,
          kind: 'hex',
          raw: cleanedHex,
          nocase: false,
          ascii: false,
          wide: false,
          hexTokens: parseHexPatternTokens(cleanedHex),
        });
      } else if (/^\/.+\/[gimsuy]*$/.test(line)) {
        const m = line.match(/^\/(.+)\/([gimsuy]*)$/);
        if (m) {
          try {
            const flags = m[2].includes('g') ? m[2] : `${m[2]}g`;
            simpleDefs.push({
              id,
              kind: 'regex',
              raw: m[1],
              nocase: flags.includes('i'),
              ascii: true,
              wide: false,
              regex: new RegExp(m[1], flags),
            });
          } catch {}
        }
      } else {
        simpleDefs.push({
          id,
          kind: 'text',
          raw: line.replace(/^"|"$/g, ''),
          nocase: true,
          ascii: true,
          wide: false,
        });
      }
    });
    if (simpleDefs.length > 0) {
      ruleBlocks.push({
        name: 'Custom_Pattern_Rule',
        tags: ['custom'],
        meta: { description: 'قواعد أنماط نصية أو بايتية مخصصة', severity: 'medium' },
        condition: 'any of them',
        strings: simpleDefs,
      });
    }
  }

  return ruleBlocks;
}

function evalSafeBooleanExpr(expr: string): boolean {
  const tokens = expr.match(/\(|\)|&&|\|\||!|true|false/g) || [];
  let pos = 0;

  function parseOr(): boolean {
    let left = parseAnd();
    while (tokens[pos] === '||') {
      pos++;
      const right = parseAnd();
      left = left || right;
    }
    return left;
  }

  function parseAnd(): boolean {
    let left = parseUnary();
    while (tokens[pos] === '&&') {
      pos++;
      const right = parseUnary();
      left = left && right;
    }
    return left;
  }

  function parseUnary(): boolean {
    if (tokens[pos] === '!') {
      pos++;
      return !parseUnary();
    }
    if (tokens[pos] === '(') {
      pos++;
      const val = parseOr();
      if (tokens[pos] === ')') pos++;
      return val;
    }
    const tok = tokens[pos++];
    return tok === 'true';
  }

  return parseOr();
}

function evaluateYaraCondition(
  condition: string,
  matchedIds: Set<string>,
  allStringIds: string[],
  bytes: Uint8Array
): boolean {
  const totalStrings = allStringIds.length;
  let norm = condition.toLowerCase().trim();
  if (!norm || norm === 'any of them') return matchedIds.size > 0;
  if (norm === 'all of them') return matchedIds.size >= totalStrings && totalStrings > 0;

  // Evaluate uint16(offset) == value / uint32(offset) == value
  norm = norm.replace(
    /\buint(16|32)(be)?\s*\(\s*(0x[0-9a-f]+|\d+)\s*\)\s*(==|!=)\s*(0x[0-9a-f]+|\d+)/gi,
    (_m, bits, be, offStr, op, valStr) => {
      const off = offStr.startsWith('0x') ? parseInt(offStr, 16) : Number(offStr);
      const expected = valStr.startsWith('0x') ? parseInt(valStr, 16) : Number(valStr);
      const byteLen = bits === '32' ? 4 : 2;
      if (off < 0 || off + byteLen > bytes.length) return op === '!=' ? 'true' : 'false';
      const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
      const actual = bits === '32' ? dv.getUint32(off, !be) : dv.getUint16(off, !be);
      const eq = actual === expected;
      return (op === '==' ? eq : !eq) ? 'true' : 'false';
    }
  );

  // Evaluate filesize comparisons like `filesize < 5MB` or `filesize > 100`
  norm = norm.replace(
    /\bfilesize\s*(<=|>=|==|!=|<|>)\s*(\d+)\s*(kb|mb)?\b/gi,
    (_m, op, numStr, unit) => {
      const mult = unit?.toLowerCase() === 'mb' ? 1024 * 1024 : unit?.toLowerCase() === 'kb' ? 1024 : 1;
      const rhs = Number(numStr) * mult;
      const lhs = bytes.length;
      const ok =
        op === '<'
          ? lhs < rhs
          : op === '<='
          ? lhs <= rhs
          : op === '>'
          ? lhs > rhs
          : op === '>='
          ? lhs >= rhs
          : op === '=='
          ? lhs === rhs
          : lhs !== rhs;
      return ok ? 'true' : 'false';
    }
  );

  // Evaluate `N of ($prefix*)` / `any of ($prefix*)` / `all of ($prefix*)`
  norm = norm.replace(
    /\b(any|all|\d+)\s+of\s+\((\$[a-z0-9_]+)\*\)/gi,
    (_m, qty, prefix) => {
      const prefLower = prefix.toLowerCase();
      const totalWithPrefix = allStringIds.filter((id) => id.toLowerCase().startsWith(prefLower)).length;
      const matchedWithPrefix = Array.from(matchedIds).filter((id) => id.toLowerCase().startsWith(prefLower)).length;
      if (qty === 'any') return matchedWithPrefix > 0 ? 'true' : 'false';
      if (qty === 'all') return totalWithPrefix > 0 && matchedWithPrefix >= totalWithPrefix ? 'true' : 'false';
      return matchedWithPrefix >= Number(qty) ? 'true' : 'false';
    }
  );

  // Evaluate `N of them` / `any of them` / `all of them`
  norm = norm.replace(/\b(\d+)\s+of\s+them\b/gi, (_m, n) =>
    matchedIds.size >= Number(n) ? 'true' : 'false'
  );
  norm = norm
    .replace(/\bany\s+of\s+them\b/gi, matchedIds.size > 0 ? 'true' : 'false')
    .replace(/\ball\s+of\s+them\b/gi, totalStrings > 0 && matchedIds.size >= totalStrings ? 'true' : 'false');

  // Replace $vars
  const vars = Array.from(new Set(norm.match(/\$[a-z0-9_]+/g) || []));
  for (const v of vars) {
    const hit = Array.from(matchedIds).some((id) => id.toLowerCase() === v);
    norm = norm.replace(new RegExp(`\\${v}\\b`, 'g'), hit ? 'true' : 'false');
  }

  norm = norm
    .replace(/\band\b/g, '&&')
    .replace(/\bor\b/g, '||')
    .replace(/\bnot\b/g, '!');

  if (/^[truefals\s&|!()]+$/.test(norm)) {
    try {
      return evalSafeBooleanExpr(norm);
    } catch {
      return matchedIds.size > 0;
    }
  }

  return matchedIds.size > 0;
}

function toUtf16LeLatin1(str: string): string {
  let res = '';
  for (let i = 0; i < str.length; i++) {
    res += str[i] + '\u0000';
  }
  return res;
}

function sanitizeCsvValue(val: string | number): string {
  const s = String(val ?? '');
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
}

export const YaraPatternScannerLab: React.FC<ExtendedLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [ruleText, setRuleText] = useState(YARA_PRESETS[0].ruleText);
  const [loadedYarFiles, setLoadedYarFiles] = useState<LoadedYarFileInfo[]>([]);
  const [targetFiles, setTargetFiles] = useState<File[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanResults, setScanResults] = useState<YaraFileScanResult[]>([]);
  const [tableSearch, setTableSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'matched' | 'clean'>('all');
  const [selectedHitDetail, setSelectedHitDetail] = useState<{
    fileName: string;
    ruleName: string;
    hit: YaraMatchHit;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const parsedRuleSummary = useMemo(() => parseYaraRulesInput(ruleText), [ruleText]);

  const handleYarDatabaseUpload = async (fileList: FileList | null, appendMode: boolean) => {
    if (!fileList || fileList.length === 0) return;
    setError(null);
    const files = Array.from(fileList);
    const sections: string[] = [];
    const metaInfos: LoadedYarFileInfo[] = [];

    for (const f of files) {
      const text = await f.text();
      if (!text.trim()) continue;
      const parsed = parseYaraRulesInput(text);
      sections.push(`/* Source: ${f.name} */\n${text.trim()}`);
      metaInfos.push({ name: f.name, size: f.size, ruleCount: parsed.length });
    }

    if (sections.length === 0) {
      setError('ملف القواعد المرفوع فارغ ولا يحتوي على قواعد YARA صالحة.');
      onNotify('ملف .yar المرفوع فارغ.', 'warning');
      return;
    }

    const combined = sections.join('\n\n');
    if (appendMode && ruleText.trim()) {
      setRuleText((prev) => `${prev.trim()}\n\n${combined}`);
      setLoadedYarFiles((prev) => [...prev, ...metaInfos]);
    } else {
      setRuleText(combined);
      setLoadedYarFiles(metaInfos);
    }

    const totalAddedRules = metaInfos.reduce((sum, x) => sum + x.ruleCount, 0);
    onNotify(`تم تحميل ${metaInfos.length} ملف قاعدة YARA (${totalAddedRules} قاعدة).`, 'success');
  };

  const scanSingleTargetFile = async (file: File, rules: ParsedYaraRule[]): Promise<YaraFileScanResult> => {
    const t0 = performance.now();
    const buffer = await file.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const sha256 = await digestHex('SHA-256', bytes);
    const md5 = SparkMD5.ArrayBuffer.hash(buffer);

    let latin1 = '';
    const chunkSz = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSz) {
      latin1 += String.fromCharCode(...bytes.subarray(i, Math.min(bytes.length, i + chunkSz)));
    }
    const lowerLatin1 = latin1.toLowerCase();

    const matchedRules: YaraMatchedRuleSummary[] = [];
    let totalHits = 0;

    for (const rule of rules) {
      const ruleHits: YaraMatchHit[] = [];
      const matchedIds = new Set<string>();

      for (const sDef of rule.strings) {
        if (sDef.kind === 'hex' && sDef.hexTokens && sDef.hexTokens.length > 0) {
          const pat = sDef.hexTokens;
          const limit = Math.min(bytes.length - pat.length, 4_000_000);
          for (let i = 0; i <= limit; i++) {
            let ok = true;
            for (let j = 0; j < pat.length; j++) {
              if (pat[j] !== null && bytes[i + j] !== pat[j]) {
                ok = false;
                break;
              }
            }
            if (ok) {
              matchedIds.add(sDef.id);
              const slice = bytes.subarray(i, Math.min(bytes.length, i + Math.max(pat.length, 16)));
              ruleHits.push({
                ruleName: rule.name,
                stringId: sDef.id,
                kind: 'hex',
                offset: i,
                offsetHex: `0x${i.toString(16).toUpperCase().padStart(8, '0')}`,
                matchedHex: Array.from(slice).map((b) => b.toString(16).padStart(2, '0')).join(' '),
                previewAscii: Array.from(slice).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join(''),
              });
              if (ruleHits.length >= 40) break;
              i += Math.max(0, pat.length - 1);
            }
          }
        } else if (sDef.kind === 'text' && sDef.raw) {
          const searchVariants: string[] = [];
          if (sDef.ascii) searchVariants.push(sDef.raw);
          if (sDef.wide) searchVariants.push(toUtf16LeLatin1(sDef.raw));

          for (const variant of searchVariants) {
            const hay = sDef.nocase ? lowerLatin1 : latin1;
            const needle = sDef.nocase ? variant.toLowerCase() : variant;
            let pos = 0;
            while (pos < hay.length) {
              const foundIdx = hay.indexOf(needle, pos);
              if (foundIdx === -1) break;
              matchedIds.add(sDef.id);
              const ctxStart = Math.max(0, foundIdx - 4);
              const ctxEnd = Math.min(bytes.length, foundIdx + needle.length + 12);
              const slice = bytes.subarray(ctxStart, ctxEnd);
              ruleHits.push({
                ruleName: rule.name,
                stringId: sDef.id,
                kind: 'text',
                offset: foundIdx,
                offsetHex: `0x${foundIdx.toString(16).toUpperCase().padStart(8, '0')}`,
                matchedHex: Array.from(slice.subarray(0, 16)).map((b) => b.toString(16).padStart(2, '0')).join(' '),
                previewAscii: Array.from(slice).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join(''),
              });
              if (ruleHits.length >= 40) break;
              pos = foundIdx + needle.length;
            }
          }
        } else if (sDef.kind === 'regex' && sDef.regex) {
          sDef.regex.lastIndex = 0;
          let m: RegExpExecArray | null;
          let guard = 0;
          while ((m = sDef.regex.exec(latin1)) !== null && guard < 40) {
            guard++;
            matchedIds.add(sDef.id);
            const idx = m.index;
            const slice = bytes.subarray(idx, Math.min(bytes.length, idx + Math.min(24, m[0].length)));
            ruleHits.push({
              ruleName: rule.name,
              stringId: sDef.id,
              kind: 'regex',
              offset: idx,
              offsetHex: `0x${idx.toString(16).toUpperCase().padStart(8, '0')}`,
              matchedHex: Array.from(slice).map((b) => b.toString(16).padStart(2, '0')).join(' '),
              previewAscii: m[0].slice(0, 60),
            });
            if (m[0].length === 0) sDef.regex.lastIndex++;
          }
        }
      }

      const allStringIds = rule.strings.map((s) => s.id);
      if (evaluateYaraCondition(rule.condition, matchedIds, allStringIds, bytes)) {
        matchedRules.push({
          ruleName: rule.name,
          tags: rule.tags,
          severity: rule.meta.severity || rule.meta.threat_level || 'medium',
          description: rule.meta.description || '',
          condition: rule.condition,
          hitCount: ruleHits.length,
          hits: ruleHits,
        });
        totalHits += ruleHits.length;
      }
    }

    return {
      fileName: file.name,
      fileSize: file.size,
      sha256,
      md5,
      rulesEvaluated: rules.length,
      matchedRules,
      totalHits,
      scannedMs: Math.round(performance.now() - t0),
    };
  };

  const runYaraScan = async (overrideFiles?: File[]) => {
    const filesToScan = overrideFiles || targetFiles;
    if (filesToScan.length === 0) {
      setError('يرجى رفع ملف واحد أو أكثر لفحصه بقواعد YARA.');
      return;
    }
    const rules = parseYaraRulesInput(ruleText);
    if (rules.length === 0) {
      setError('لا توجد قواعد YARA صالحة. قم برفع ملف .yar أو كتابة قاعدة صالحة في المحرر.');
      return;
    }

    setScanning(true);
    setError(null);
    setSelectedHitDetail(null);

    try {
      const results: YaraFileScanResult[] = [];
      for (const f of filesToScan.slice(0, 50)) {
        const res = await scanSingleTargetFile(f, rules);
        results.push(res);
      }

      setScanResults(results);

      const matchedFileCount = results.filter((r) => r.matchedRules.length > 0).length;
      const totalMatchedRules = results.reduce((sum, r) => sum + r.matchedRules.length, 0);
      const totalHitsAll = results.reduce((sum, r) => sum + r.totalHits, 0);
      const primary = results[0];

      const verdict =
        matchedFileCount > 0
          ? `فحص YARA: رصد ${totalMatchedRules} قاعدة متطابقة في ${matchedFileCount} من ${results.length} ملف (${totalHitsAll} مؤشر)`
          : `فحص YARA: نظيف — 0 تطابقات عبر ${results.length} ملف (${rules.length} قاعدة)`;

      onNotify(verdict, matchedFileCount > 0 ? 'warning' : 'success');
      if (primary) {
        onRecordAudit({
          id: `yara-${Date.now()}`,
          fileName: results.length > 1 ? `مسح YARA (${results.length} ملفات)` : `مسح YARA: ${primary.fileName}`,
          fileSize: formatBytes(results.reduce((s, r) => s + r.fileSize, 0)),
          verdict,
          score: matchedFileCount > 0 ? Math.max(15, 90 - matchedFileCount * 20) : 98,
          risk: matchedFileCount > 0 ? 'مرتفع' : 'منخفض',
          sha256: primary.sha256,
        });
      }
    } catch (err: any) {
      setError(err?.message || 'تعذر قراءة الملفات أو تطبيق قواعد YARA؛ تأكد من صحة ملف .yar والملفات المرفوعة.');
    } finally {
      setScanning(false);
    }
  };

  // Flatten scan results into visual table rows (matched hits + clean files)
  const unifiedTableRows = useMemo(() => {
    const q = tableSearch.trim().toLowerCase();
    const rows: Array<{
      rowKey: string;
      fileName: string;
      fileSize: number;
      sha256: string;
      status: 'matched' | 'clean';
      ruleName: string;
      severity: string;
      stringId: string;
      kind: string;
      offsetHex: string;
      previewAscii: string;
      hit: YaraMatchHit | null;
    }> = [];

    for (const fileRes of scanResults) {
      if (fileRes.matchedRules.length === 0) {
        rows.push({
          rowKey: `${fileRes.sha256}-clean`,
          fileName: fileRes.fileName,
          fileSize: fileRes.fileSize,
          sha256: fileRes.sha256,
          status: 'clean',
          ruleName: '—',
          severity: 'نظيف',
          stringId: '—',
          kind: '—',
          offsetHex: '—',
          previewAscii: `تم فحص ${fileRes.rulesEvaluated} قاعدة بدون أي تطابق ضار`,
          hit: null,
        });
      } else {
        for (const mr of fileRes.matchedRules) {
          if (mr.hits.length === 0) {
            rows.push({
              rowKey: `${fileRes.sha256}-${mr.ruleName}-cond`,
              fileName: fileRes.fileName,
              fileSize: fileRes.fileSize,
              sha256: fileRes.sha256,
              status: 'matched',
              ruleName: mr.ruleName,
              severity: mr.severity,
              stringId: 'condition',
              kind: 'rule',
              offsetHex: '—',
              previewAscii: mr.condition,
              hit: null,
            });
          } else {
            mr.hits.forEach((hit, idx) => {
              rows.push({
                rowKey: `${fileRes.sha256}-${mr.ruleName}-${hit.stringId}-${idx}`,
                fileName: fileRes.fileName,
                fileSize: fileRes.fileSize,
                sha256: fileRes.sha256,
                status: 'matched',
                ruleName: mr.ruleName,
                severity: mr.severity,
                stringId: hit.stringId,
                kind: hit.kind,
                offsetHex: hit.offsetHex,
                previewAscii: hit.previewAscii,
                hit,
              });
            });
          }
        }
      }
    }

    return rows.filter((r) => {
      if (statusFilter === 'matched' && r.status !== 'matched') return false;
      if (statusFilter === 'clean' && r.status !== 'clean') return false;
      if (q) {
        const hay = `${r.fileName} ${r.ruleName} ${r.stringId} ${r.offsetHex} ${r.previewAscii} ${r.sha256}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [scanResults, tableSearch, statusFilter]);

  const ruleDistributionStats = useMemo(() => {
    const counts = new Map<string, { ruleName: string; fileCount: number; hitCount: number; severity: string }>();
    for (const fileRes of scanResults) {
      for (const mr of fileRes.matchedRules) {
        const prev = counts.get(mr.ruleName) || {
          ruleName: mr.ruleName,
          fileCount: 0,
          hitCount: 0,
          severity: mr.severity,
        };
        prev.fileCount += 1;
        prev.hitCount += mr.hitCount;
        counts.set(mr.ruleName, prev);
      }
    }
    return Array.from(counts.values()).sort((a, b) => b.hitCount - a.hitCount);
  }, [scanResults]);

  const exportReportCsv = () => {
    if (scanResults.length === 0) return;
    const headers = ['FileName', 'FileSizeBytes', 'SHA256', 'MD5', 'Status', 'RuleName', 'Severity', 'StringID', 'MatchKind', 'OffsetHex', 'MatchedPreview'];
    const lines = unifiedTableRows.map((r) => {
      const fileMeta = scanResults.find((f) => f.sha256 === r.sha256);
      return [
        sanitizeCsvValue(r.fileName),
        sanitizeCsvValue(r.fileSize),
        sanitizeCsvValue(r.sha256),
        sanitizeCsvValue(fileMeta?.md5 || ''),
        sanitizeCsvValue(r.status === 'matched' ? 'DETECTED' : 'CLEAN'),
        sanitizeCsvValue(r.ruleName),
        sanitizeCsvValue(r.severity),
        sanitizeCsvValue(r.stringId),
        sanitizeCsvValue(r.kind),
        sanitizeCsvValue(r.offsetHex),
        sanitizeCsvValue(r.previewAscii),
      ].join(',');
    });
    const csv = '\uFEFF' + [headers.join(','), ...lines].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `yara-scan-report-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير تقرير فحص YARA بصيغة CSV (${unifiedTableRows.length} صف).`, 'success');
  };

  const exportReportJson = () => {
    if (scanResults.length === 0) return;
    const reportPayload = {
      generatedAt: new Date().toISOString(),
      scanner: 'YARA Pattern Scanner',
      loadedYarDatabases: loadedYarFiles,
      rulesEvaluatedCount: parsedRuleSummary.length,
      filesScannedCount: scanResults.length,
      filesMatchedCount: scanResults.filter((r) => r.matchedRules.length > 0).length,
      results: scanResults,
    };
    const blob = new Blob([JSON.stringify(reportPayload, null, 2)], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `yara-scan-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify('تم تصدير تقرير فحص YARA الكامل بصيغة JSON.', 'success');
  };

  const totalFilesScanned = scanResults.length;
  const matchedFilesTotal = scanResults.filter((r) => r.matchedRules.length > 0).length;
  const totalHitsAll = scanResults.reduce((s, r) => s + r.totalHits, 0);
  const maxRuleHits = Math.max(1, ...ruleDistributionStats.map((x) => x.hitCount));

  return (
    <div className="space-y-6" dir="rtl">
      <div className="rounded-xl bg-gray-900 border border-gray-800 p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-lg font-bold text-white">
              ماسح قواعد YARA (YARA Pattern Scanner)
            </h2>
            <p className="text-xs text-gray-400">
              ارفع ملفات قواعد بيانات YARA (<span className="font-mono text-gray-300">.yar / .yara</span>) وافحص ملفاً واحداً أو عدة ملفات لاكتشاف الأنماط الضارة المعروفة (Hex، نصوص ASCII/Wide، وتعابير Regex) مع جدول نتائج مرئي وتصدير التقرير.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {YARA_PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setRuleText(preset.ruleText);
                  setLoadedYarFiles([]);
                }}
                className="px-3 py-1.5 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-800 text-xs text-gray-200 cursor-pointer whitespace-nowrap shrink-0"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left/Primary: .yar Rule Database Upload + Editor */}
          <div className="lg:col-span-7 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs font-bold text-gray-300">
                قاعدة بيانات قواعد YARA ({parsedRuleSummary.length} قاعدة نشطة)
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <label className="px-3 py-1.5 rounded-lg bg-[#D4AF37] hover:opacity-90 text-gray-950 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0">
                  <Upload className="w-3.5 h-3.5" />
                  <span>رفع ملفات .yar</span>
                  <input
                    type="file"
                    accept=".yar,.yara,.txt"
                    multiple
                    className="hidden"
                    onChange={(e) => {
                      void handleYarDatabaseUpload(e.target.files, false);
                      e.target.value = '';
                    }}
                  />
                </label>
                <label className="px-3 py-1.5 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0">
                  <Plus className="w-3.5 h-3.5 text-[#D4AF37]" />
                  <span>دمج ملف .yar إضافي</span>
                  <input
                    type="file"
                    accept=".yar,.yara,.txt"
                    multiple
                    className="hidden"
                    onChange={(e) => {
                      void handleYarDatabaseUpload(e.target.files, true);
                      e.target.value = '';
                    }}
                  />
                </label>
              </div>
            </div>

            {loadedYarFiles.length > 0 && (
              <div className="px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 flex flex-wrap items-center justify-between gap-2 text-[11px] text-gray-300">
                <div className="flex flex-wrap items-center gap-2 font-mono">
                  <FileText className="w-3.5 h-3.5 text-[#D4AF37] shrink-0" />
                  <span>
                    ملفات القواعد المحملة: {loadedYarFiles.map((f) => `${f.name} (${f.ruleCount})`).join(' · ')}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    setLoadedYarFiles([]);
                    setRuleText('');
                  }}
                  className="text-red-400 hover:underline cursor-pointer inline-flex items-center gap-1 shrink-0"
                >
                  <Trash2 className="w-3 h-3" />
                  <span>تفريغ</span>
                </button>
              </div>
            )}

            <textarea
              dir="ltr"
              rows={11}
              value={ruleText}
              onChange={(e) => setRuleText(e.target.value)}
              placeholder="ارفع ملف قواعد .yar من الأعلى أو الصق قواعد YARA هنا..."
              className="w-full p-4 rounded-xl bg-gray-950 border border-gray-800 focus:border-[#D4AF37] text-xs font-mono text-emerald-300 outline-none leading-relaxed"
            />
          </div>

          {/* Right: Target Files Upload + Scan Trigger */}
          <div className="lg:col-span-5 flex flex-col justify-between gap-4 p-5 rounded-xl bg-gray-950 border border-gray-800">
            <div className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="text-xs font-bold text-white">الملفات المستهدفة للفحص</div>
                {targetFiles.length > 0 && (
                  <button
                    type="button"
                    onClick={() => {
                      setTargetFiles([]);
                      setScanResults([]);
                    }}
                    className="text-[11px] text-gray-400 hover:text-white cursor-pointer"
                  >
                    مسح القائمة ({targetFiles.length})
                  </button>
                )}
              </div>

              <label className="flex flex-col items-center justify-center p-6 rounded-xl border-2 border-dashed border-gray-700 hover:border-[#D4AF37] bg-gray-900/60 cursor-pointer text-center transition">
                <Upload className="w-7 h-7 text-[#D4AF37] mb-2" />
                <span className="text-xs font-bold text-white">
                  {targetFiles.length === 0
                    ? 'ارفع ملفاً أو عدة ملفات للفحص (EXE, DLL, PDF, PS1, ZIP...)'
                    : `تم اختيار ${targetFiles.length} ملف (${formatBytes(targetFiles.reduce((s, f) => s + f.size, 0))})`}
                </span>
                <span className="text-[11px] text-gray-400 mt-1">
                  يدعم الفحص الدفعي حتى 50 ملفاً داخل المتصفح مباشرة
                </span>
                <input
                  type="file"
                  multiple
                  className="hidden"
                  onChange={(e) => {
                    const picked = e.target.files ? Array.from(e.target.files) : [];
                    if (picked.length > 0) {
                      setTargetFiles(picked);
                      void runYaraScan(picked);
                    }
                    e.target.value = '';
                  }}
                />
              </label>

              {targetFiles.length > 0 && (
                <div className="max-h-32 overflow-y-auto divide-y divide-gray-800 border border-gray-800 rounded-lg bg-gray-900/50">
                  {targetFiles.map((f, idx) => (
                    <div key={`${f.name}-${idx}`} className="px-3 py-1.5 flex items-center justify-between text-[11px] font-mono">
                      <span className="text-gray-200 truncate" dir="ltr">{f.name}</span>
                      <span className="text-gray-400 tabular-nums shrink-0">{formatBytes(f.size)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <button
              type="button"
              disabled={scanning || targetFiles.length === 0 || parsedRuleSummary.length === 0}
              onClick={() => void runYaraScan()}
              className="w-full py-2.5 px-4 rounded-lg bg-[#D4AF37] hover:opacity-90 disabled:opacity-50 text-gray-950 font-bold text-xs flex items-center justify-center gap-2 cursor-pointer"
            >
              {scanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              <span>{scanning ? 'جاري فحص الملفات بقواعد YARA...' : 'تشغيل فحص YARA الآن'}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Visual Results & Structured Table */}
      {scanResults.length > 0 && (
        <div className="space-y-5">
          {/* KPI Strip + Export Actions */}
          <div className="rounded-xl bg-gray-900 border border-gray-800 p-5 space-y-5">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-gray-800">
              <div>
                <h3 className="text-sm font-bold text-white">ملخص نتائج مسح YARA</h3>
                <div className="text-xs font-mono text-gray-400 mt-0.5 tabular-nums">
                  {totalFilesScanned} ملف مفحوص · {parsedRuleSummary.length} قاعدة مقيّمة · {totalHitsAll} تطابق
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={exportReportCsv}
                  className="px-4 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5 text-[#D4AF37]" />
                  <span>تصدير التقرير (CSV)</span>
                </button>
                <button
                  type="button"
                  onClick={exportReportJson}
                  className="px-4 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0"
                >
                  <Download className="w-3.5 h-3.5 text-emerald-400" />
                  <span>تصدير التقرير (JSON)</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-xs text-gray-400">الملفات المفحوصة</div>
                <div className="text-2xl font-bold font-mono tabular-nums text-white">{totalFilesScanned}</div>
              </div>
              <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-xs text-gray-400">ملفات مطابقة لقواعد ضارة</div>
                <div className={`text-2xl font-bold font-mono tabular-nums ${matchedFilesTotal > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {matchedFilesTotal}
                </div>
              </div>
              <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-xs text-gray-400">ملفات نظيفة</div>
                <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
                  {totalFilesScanned - matchedFilesTotal}
                </div>
              </div>
              <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-xs text-gray-400">إجمالي المواضع المكتشفة</div>
                <div className="text-2xl font-bold font-mono tabular-nums text-[#D4AF37]">{totalHitsAll}</div>
              </div>
            </div>

            {/* Visual Distribution Bar Chart of Matched Rules */}
            {ruleDistributionStats.length > 0 && (
              <div className="space-y-2.5 pt-2">
                <div className="text-xs font-bold text-gray-300">التوزيع المرئي للقواعد المكتشفة</div>
                <div className="space-y-2">
                  {ruleDistributionStats.map((stat) => {
                    const widthPct = Math.max(8, Math.round((stat.hitCount / maxRuleHits) * 100));
                    return (
                      <div key={stat.ruleName} className="space-y-1">
                        <div className="flex items-center justify-between text-xs font-mono">
                          <span className="text-red-300 font-bold">{stat.ruleName}</span>
                          <span className="text-gray-400 tabular-nums">
                            {stat.fileCount} ملف · {stat.hitCount} موضع
                          </span>
                        </div>
                        <div className="w-full h-2 rounded-full bg-gray-950 border border-gray-800 overflow-hidden">
                          <div
                            className="h-full bg-red-500/80"
                            style={{ width: `${widthPct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Structured Visual Results Table */}
          <div className="rounded-xl bg-gray-900 border border-gray-800 p-5 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Filter className="w-4 h-4 text-[#D4AF37]" />
                <span>جدول نتائج الفحص ({unifiedTableRows.length} سجل)</span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[220px]">
                  <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={tableSearch}
                    onChange={(e) => setTableSearch(e.target.value)}
                    placeholder="تصفية بالملف أو اسم القاعدة أو Offset..."
                    className="w-full pr-9 pl-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-white focus:border-[#D4AF37] outline-none"
                  />
                </div>
                <div className="flex items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
                  {(
                    [
                      { id: 'all', label: 'الكل' },
                      { id: 'matched', label: 'تطابقات ضارة' },
                      { id: 'clean', label: 'نظيف' },
                    ] as const
                  ).map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => setStatusFilter(f.id)}
                      className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer whitespace-nowrap shrink-0 ${
                        statusFilter === f.id ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <div className="overflow-x-auto border border-gray-800 rounded-xl">
              <table className="w-full text-xs text-right">
                <thead className="bg-gray-950 text-gray-400 border-b border-gray-800 font-mono">
                  <tr>
                    <th className="py-2.5 px-3">الملف</th>
                    <th className="py-2.5 px-3">الحالة</th>
                    <th className="py-2.5 px-3">القاعدة</th>
                    <th className="py-2.5 px-3">المعرّف</th>
                    <th className="py-2.5 px-3">الإزاحة Offset</th>
                    <th className="py-2.5 px-3">المعاينة</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono text-[11px]">
                  {unifiedTableRows.map((row) => (
                    <tr
                      key={row.rowKey}
                      onClick={() => {
                        if (row.hit) {
                          setSelectedHitDetail({
                            fileName: row.fileName,
                            ruleName: row.ruleName,
                            hit: row.hit,
                          });
                        }
                      }}
                      className={`transition ${row.hit ? 'cursor-pointer hover:bg-gray-950/70' : ''}`}
                    >
                      <td className="py-2.5 px-3 text-white max-w-[180px] truncate" dir="ltr">
                        {row.fileName}
                      </td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {row.status === 'matched' ? (
                          <span className="inline-flex items-center gap-1 text-red-400 font-bold">
                            <ShieldAlert className="w-3.5 h-3.5" />
                            <span>متطابق</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-bold">
                            <ShieldCheck className="w-3.5 h-3.5" />
                            <span>نظيف</span>
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-red-300 font-bold">{row.ruleName}</td>
                      <td className="py-2.5 px-3 text-[#D4AF37]">{row.stringId}</td>
                      <td className="py-2.5 px-3 text-emerald-300 tabular-nums">{row.offsetHex}</td>
                      <td className="py-2.5 px-3 text-gray-300 max-w-xs truncate" dir="ltr">
                        {row.previewAscii}
                      </td>
                    </tr>
                  ))}
                  {unifiedTableRows.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-gray-500 font-sans text-xs">
                        لا توجد نتائج مطابقة لعوامل التصفية الحالية.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {selectedHitDetail && (
              <div className="p-4 rounded-xl bg-gray-950 border border-[#D4AF37]/40 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-[#D4AF37] font-bold">
                  <span>
                    {selectedHitDetail.fileName} · {selectedHitDetail.ruleName} ({selectedHitDetail.hit.stringId}) @ {selectedHitDetail.hit.offsetHex}
                  </span>
                  <button
                    type="button"
                    onClick={() => setSelectedHitDetail(null)}
                    className="text-gray-400 hover:text-white cursor-pointer"
                  >
                    إغلاق
                  </button>
                </div>
                <div className="text-[11px] text-gray-300 break-all" dir="ltr">
                  HEX: {selectedHitDetail.hit.matchedHex}
                </div>
                <div className="text-[11px] text-emerald-300 break-all" dir="ltr">
                  ASCII: {selectedHitDetail.hit.previewAscii}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 3. JWT & Token Forensic Inspector (Header/Payload Decode, Expiry, Security Audit)
// ============================================================================
function decodeBase64UrlUtf8(segment: string): string {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(segment.length / 4) * 4, '=');
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

interface JwtInspectionResult {
  tokenFormat: 'JWT (JWS)' | 'Base64 / Base64URL';
  header: Record<string, any> | null;
  payload: Record<string, any> | null;
  rawDecodedText?: string;
  signatureSegment: string;
  signatureByteLength: number;
  expiryStatus: 'ساري الصلاحية' | 'منتهي الصلاحية' | 'لا يحتوي على تاريخ انتهاء (exp)';
  expiryDetail: string;
  issuedAtFormatted: string | null;
  expiresAtFormatted: string | null;
  vulnerabilities: Array<{ severity: 'حرج' | 'مرتفع' | 'متوسط'; title: string; detail: string }>;
  securityScore: number;
  hmacVerified?: boolean | null;
}

export const JwtTokenForensicInspectorLab: React.FC<ExtendedLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [tokenInput, setTokenInput] = useState('');
  const [hmacSecret, setHmacSecret] = useState('');
  const [result, setResult] = useState<JwtInspectionResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const inspectToken = async (e?: React.FormEvent, overrideToken?: string) => {
    e?.preventDefault();
    const raw = (overrideToken ?? tokenInput).trim().replace(/^Bearer\s+/i, '');
    if (!raw) {
      setError('يرجى لصق رمز JWT أو سلسلة Base64 للتحليل.');
      return;
    }
    setError(null);

    try {
      const parts = raw.split('.');
      if (parts.length === 3) {
        const headerJson = JSON.parse(decodeBase64UrlUtf8(parts[0]));
        const payloadJson = JSON.parse(decodeBase64UrlUtf8(parts[1]));
        const sigSeg = parts[2] || '';
        const sigBytesLen = sigSeg ? Math.floor((sigSeg.length * 3) / 4) : 0;

        const nowSec = Math.floor(Date.now() / 1000);
        const vulnerabilities: JwtInspectionResult['vulnerabilities'] = [];
        const alg = String(headerJson.alg || '');

        if (!alg || alg.toLowerCase() === 'none') {
          vulnerabilities.push({
            severity: 'حرج',
            title: 'ثغرة الخوارزمية الصفرية (alg: none)',
            detail: 'التوكن يستخدم alg=none مما يسمح للمهاجم بتزوير الصلاحيات دون توقيع صحيح!',
          });
        }
        if (!sigSeg && alg.toLowerCase() !== 'none') {
          vulnerabilities.push({
            severity: 'حرج',
            title: 'توقيع مفقود في التوكن',
            detail: 'المقطع الثالث (Signature) فارغ، ما يشير لتوكن غير موقع أو مقطوع.',
          });
        }
        if (headerJson.jku || headerJson.x5u) {
          vulnerabilities.push({
            severity: 'مرتفع',
            title: 'وجود ترويسة جلب مفاتيح خارجية (jku / x5u)',
            detail: 'قد تستغل في هجمات SSRF أو حقن مفتاح توقيع مزور إذا لم يكن الخادم يتحقق من القائمة البيضاء.',
          });
        }
        if (typeof headerJson.kid === 'string' && /(\.\.|\/|'|;|\\)/.test(headerJson.kid)) {
          vulnerabilities.push({
            severity: 'مرتفع',
            title: 'أنماط مشبوهة في معرف المفتاح (kid Injection)',
            detail: `المعرف kid="${headerJson.kid}" يحتوي على محارف اجتياز مسار أو حقن أوامر.`,
          });
        }

        let expiryStatus: JwtInspectionResult['expiryStatus'] = 'لا يحتوي على تاريخ انتهاء (exp)';
        let expiryDetail = 'لا توجد مطالبة exp؛ التوكن قد يبقى صالحاً للأبد ما لم يُلغَ من الخادم.';
        let expiresAtFormatted: string | null = null;
        let issuedAtFormatted: string | null = null;

        if (typeof payloadJson.iat === 'number') {
          issuedAtFormatted = new Date(payloadJson.iat * 1000).toLocaleString('ar-EG');
        }
        if (typeof payloadJson.exp === 'number') {
          expiresAtFormatted = new Date(payloadJson.exp * 1000).toLocaleString('ar-EG');
          const diffSec = payloadJson.exp - nowSec;
          if (diffSec <= 0) {
            expiryStatus = 'منتهي الصلاحية';
            const hrs = Math.abs(Math.round(diffSec / 3600));
            expiryDetail = `انتهت صلاحية التوكن منذ ${hrs >= 24 ? `${Math.round(hrs / 24)} يوم` : `${hrs} ساعة`}.`;
          } else {
            expiryStatus = 'ساري الصلاحية';
            const mins = Math.round(diffSec / 60);
            expiryDetail = `متبقٍ على الانتهاء ${mins >= 60 ? `${Math.round(mins / 60)} ساعة` : `${mins} دقيقة`}.`;
          }
        } else {
          vulnerabilities.push({
            severity: 'متوسط',
            title: 'غياب حقل انتهاء الصلاحية (Missing exp)',
            detail: 'غياب المطالبة exp يمنع انتهاء صلاحية التوكن تلقائياً.',
          });
        }

        // Sensitive data leak check in unencrypted payload
        const sensitiveKeys = Object.keys(payloadJson).filter((k) =>
          /(password|passwd|secret|pin|cvv|ssn|privatekey|apikey)/i.test(k)
        );
        if (sensitiveKeys.length > 0) {
          vulnerabilities.push({
            severity: 'مرتفع',
            title: 'كشف بيانات حساسة داخل Payload غير المشفر',
            detail: `تذكر أن JWT مُرمّز بـ Base64 فقط؛ الحقول الحساسة المرصودة: ${sensitiveKeys.join(', ')}`,
          });
        }

        // Optional local WebCrypto HMAC verification
        let hmacVerified: boolean | null = null;
        if (hmacSecret.trim() && /^HS(256|384|512)$/i.test(alg)) {
          const hashName = alg.toUpperCase() === 'HS512' ? 'SHA-512' : alg.toUpperCase() === 'HS384' ? 'SHA-384' : 'SHA-256';
          const key = await crypto.subtle.importKey(
            'raw',
            new TextEncoder().encode(hmacSecret),
            { name: 'HMAC', hash: hashName },
            false,
            ['verify']
          );
          const paddedSig = sigSeg.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(sigSeg.length / 4) * 4, '=');
          const sigBin = atob(paddedSig);
          const sigBytes = new Uint8Array(sigBin.length);
          for (let i = 0; i < sigBin.length; i++) sigBytes[i] = sigBin.charCodeAt(i);
          hmacVerified = await crypto.subtle.verify(
            'HMAC',
            key,
            sigBytes,
            new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
          );
        }

        const penalty = vulnerabilities.reduce(
          (sum, v) => sum + (v.severity === 'حرج' ? 45 : v.severity === 'مرتفع' ? 25 : 12),
          0
        );
        const securityScore = Math.max(0, 100 - penalty);

        const parsedRes: JwtInspectionResult = {
          tokenFormat: 'JWT (JWS)',
          header: headerJson,
          payload: payloadJson,
          signatureSegment: sigSeg,
          signatureByteLength: sigBytesLen,
          expiryStatus,
          expiryDetail,
          issuedAtFormatted,
          expiresAtFormatted,
          vulnerabilities,
          securityScore,
          hmacVerified,
        };
        setResult(parsedRes);
        onNotify(`تم تفكيك وتحليل توكن JWT (الخوارزمية: ${alg || 'غير محددة'})`, vulnerabilities.length ? 'warning' : 'success');
        onRecordAudit({
          id: `jwt-${Date.now()}`,
          fileName: `فحص توكن JWT (${alg || 'unknown'})`,
          fileSize: `${raw.length} حرف`,
          verdict: `${expiryStatus} • ثغرات: ${vulnerabilities.length}`,
          score: securityScore,
          risk: vulnerabilities.some((v) => v.severity === 'حرج') ? 'حرج' : vulnerabilities.length > 0 ? 'متوسط' : 'منخفض',
          sha256: await digestHex('SHA-256', new TextEncoder().encode(raw)),
        });
        return;
      }

      // Base64 / Base64URL generic token decode
      const decodedText = decodeBase64UrlUtf8(raw);
      let maybeJson: Record<string, any> | null = null;
      try {
        maybeJson = JSON.parse(decodedText);
      } catch {}

      setResult({
        tokenFormat: 'Base64 / Base64URL',
        header: null,
        payload: maybeJson,
        rawDecodedText: decodedText,
        signatureSegment: '',
        signatureByteLength: 0,
        expiryStatus: 'لا يحتوي على تاريخ انتهاء (exp)',
        expiryDetail: 'سلسلة Base64 قياسية مفكوكة محلياً داخل المتصفح.',
        issuedAtFormatted: null,
        expiresAtFormatted: null,
        vulnerabilities: [],
        securityScore: 80,
      });
      onNotify('تم فك ترميز Base64 بنجاح.', 'success');
    } catch {
      setError('تعذر فك الترميز؛ تأكد من إدخال توكن JWT ثلاثي المقاطع (header.payload.sig) أو نص Base64 سليم دون فراغات.');
    }
  };

  return (
    <div className="space-y-6" dir="rtl">
      <div className="rounded-2xl bg-gray-900/95 border border-gray-800 p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-[#D4AF37]">
              Client-Side Token Forensics · JWT / Base64
            </div>
            <h2 className="text-xl font-bold text-white">
              محلل رموز التوثيق (JWT)
            </h2>
            <p className="text-xs text-gray-400">
              فك الترميز محلياً وعرض Header وPayload وفحص الصلاحية والثغرات والتحقق من توقيع HMAC.
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              // Synthetic real RFC-compliant sample with alg:none vulnerability purely for quick format demo if clicked
              const sample =
                'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhbmFseXN0LTAxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzAwMDAwMDAwLCJleHAiOjE3MDAwMDM2MDB9.';
              setTokenInput(sample);
              void inspectToken(undefined, sample);
            }}
            className="px-3.5 py-2 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-800 text-[11px] text-gray-300 cursor-pointer shrink-0"
          >
            تجربة توكن ضعيف (alg:none)
          </button>
        </div>

        <form onSubmit={(e) => void inspectToken(e)} className="space-y-3">
          <textarea
            dir="ltr"
            rows={4}
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature..."
            className="w-full p-4 rounded-2xl bg-gray-950 border border-gray-800 focus:border-[#D4AF37] text-xs font-mono text-amber-200 outline-none"
          />
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3">
            <input
              type="text"
              value={hmacSecret}
              onChange={(e) => setHmacSecret(e.target.value)}
              placeholder="مفتاح سري للتحقق من توقيع HS256/HS512 محلياً (اختياري)"
              className="md:col-span-9 px-4 py-2.5 rounded-xl bg-gray-950 border border-gray-800 focus:border-[#D4AF37] text-xs font-mono text-white outline-none"
            />
            <button
              type="submit"
              className="md:col-span-3 py-2.5 px-4 rounded-xl bg-[#D4AF37] hover:opacity-90 text-gray-950 font-bold text-xs flex items-center justify-center gap-2 cursor-pointer"
            >
              <Search className="w-4 h-4" />
              <span>تفكيك وتحليل التوكن</span>
            </button>
          </div>
        </form>

        {error && (
          <div className="p-3.5 rounded-2xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-[11px] text-gray-400">درجة السلامة والتوقيع</div>
              <div className="text-2xl font-bold font-mono text-[#D4AF37]">{result.securityScore}/100</div>
              <div className="text-[11px] text-gray-400 font-mono">{result.tokenFormat}</div>
            </div>

            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-[11px] text-gray-400">حالة الصلاحية الزمنية</div>
              <div
                className={`text-sm font-bold ${
                  result.expiryStatus === 'ساري الصلاحية'
                    ? 'text-emerald-400'
                    : result.expiryStatus === 'منتهي الصلاحية'
                    ? 'text-red-400'
                    : 'text-amber-300'
                }`}
              >
                {result.expiryStatus}
              </div>
              <div className="text-[11px] text-gray-400">{result.expiryDetail}</div>
            </div>

            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-[11px] text-gray-400">حالة التوقيع (Signature)</div>
              <div className="text-sm font-bold text-white font-mono">
                {result.hmacVerified === true
                  ? 'HMAC VALID ✓'
                  : result.hmacVerified === false
                  ? 'HMAC INVALID ✗'
                  : result.signatureByteLength > 0
                  ? `${result.signatureByteLength} Bytes`
                  : 'بدون توقيع'}
              </div>
              <div className="text-[11px] text-gray-400">
                {result.expiresAtFormatted ? `ينتهي: ${result.expiresAtFormatted}` : 'لا يوجد تاريخ exp'}
              </div>
            </div>
          </div>

          {result.vulnerabilities.length > 0 && (
            <div className="rounded-3xl bg-gray-900 border border-red-500/35 p-5 space-y-3">
              <h3 className="text-sm font-bold text-red-300 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" />
                <span>ثغرات ومخاطر مكتشفة في التوكن ({result.vulnerabilities.length})</span>
              </h3>
              <div className="space-y-2">
                {result.vulnerabilities.map((v, i) => (
                  <div key={i} className="p-3.5 rounded-2xl bg-gray-950 border border-red-500/30 text-xs space-y-1">
                    <div className="font-bold text-white flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 text-[10px]">{v.severity}</span>
                      <span>{v.title}</span>
                    </div>
                    <div className="text-gray-400">{v.detail}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {result.header && (
              <div className="rounded-3xl bg-gray-900 border border-gray-800 p-5 space-y-2">
                <div className="text-xs font-bold text-[#D4AF37] font-mono">DECODED HEADER</div>
                <pre dir="ltr" className="p-4 rounded-2xl bg-gray-950 border border-gray-800 text-xs font-mono text-rose-300 overflow-x-auto">
                  {JSON.stringify(result.header, null, 2)}
                </pre>
              </div>
            )}
            <div className={`rounded-3xl bg-gray-900 border border-gray-800 p-5 space-y-2 ${!result.header ? 'lg:col-span-2' : ''}`}>
              <div className="text-xs font-bold text-emerald-400 font-mono">DECODED PAYLOAD</div>
              <pre dir="ltr" className="p-4 rounded-2xl bg-gray-950 border border-gray-800 text-xs font-mono text-emerald-300 overflow-x-auto">
                {result.payload ? JSON.stringify(result.payload, null, 2) : result.rawDecodedText}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 4. PCAP Packet Inspector (Real Binary .pcap / .pcapng ArrayBuffer Parser)
// ============================================================================
interface ParsedPcapPacket {
  index: number;
  timestampIso: string;
  inclLen: number;
  origLen: number;
  protocol: string;
  srcIp: string;
  dstIp: string;
  srcPort: number | null;
  dstPort: number | null;
  flags: string;
  info: string;
  rawSliceHex: string;
  rawSliceAscii: string;
}

interface PcapAnalysisSummary {
  fileName: string;
  fileSize: number;
  sha256: string;
  format: 'libpcap' | 'pcapng';
  endianness: 'Little-Endian' | 'Big-Endian';
  linkType: number;
  linkTypeLabel: string;
  packetCount: number;
  packets: ParsedPcapPacket[];
  protocolCounts: Record<string, number>;
  topSrcIps: Array<{ ip: string; count: number }>;
  topDstIps: Array<{ ip: string; count: number }>;
  dnsQueries: string[];
  httpHosts: string[];
}

function formatMac(bytes: Uint8Array, offset: number): string {
  if (offset + 6 > bytes.length) return '—';
  return Array.from(bytes.subarray(offset, offset + 6))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join(':');
}

function formatIpv4(bytes: Uint8Array, offset: number): string {
  if (offset + 4 > bytes.length) return '—';
  return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
}

function decodeDnsQname(bytes: Uint8Array, startOffset: number): string | null {
  try {
    let idx = startOffset;
    const labels: string[] = [];
    let guard = 0;
    while (idx < bytes.length && guard < 30) {
      guard++;
      const len = bytes[idx];
      if (len === 0) break;
      if (len > 63 || idx + 1 + len > bytes.length) return null;
      labels.push(String.fromCharCode(...bytes.subarray(idx + 1, idx + 1 + len)));
      idx += 1 + len;
    }
    const domain = labels.join('.');
    return domain.includes('.') ? domain : null;
  } catch {
    return null;
  }
}

function parseSinglePacketFrame(
  bytes: Uint8Array,
  linkType: number,
  index: number,
  timestampIso: string,
  origLen: number
): { packet: ParsedPcapPacket; dnsQuery?: string; httpHost?: string } {
  let l3Offset = 0;
  let etherType = 0x0800;

  if (linkType === 1) {
    // Ethernet II
    if (bytes.length < 14) {
      return {
        packet: {
          index,
          timestampIso,
          inclLen: bytes.length,
          origLen,
          protocol: 'ETH-SHORT',
          srcIp: formatMac(bytes, 6),
          dstIp: formatMac(bytes, 0),
          srcPort: null,
          dstPort: null,
          flags: '',
          info: 'Truncated Ethernet frame',
          rawSliceHex: Array.from(bytes.subarray(0, 64)).map((b) => b.toString(16).padStart(2, '0')).join(' '),
          rawSliceAscii: Array.from(bytes.subarray(0, 64)).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join(''),
        },
      };
    }
    etherType = (bytes[12] << 8) | bytes[13];
    l3Offset = 14;
    // Handle 802.1Q VLAN tag
    if (etherType === 0x8100 && bytes.length >= 18) {
      etherType = (bytes[16] << 8) | bytes[17];
      l3Offset = 18;
    }
  } else if (linkType === 113) {
    // Linux Cooked Capture (SLL)
    etherType = bytes.length >= 16 ? (bytes[14] << 8) | bytes[15] : 0x0800;
    l3Offset = 16;
  } else if (linkType === 101 || linkType === 12) {
    // Raw IP
    l3Offset = 0;
    etherType = (bytes[0] >> 4) === 6 ? 0x86dd : 0x0800;
  }

  let protocol = 'RAW';
  let srcIp = formatMac(bytes, 6);
  let dstIp = formatMac(bytes, 0);
  let srcPort: number | null = null;
  let dstPort: number | null = null;
  let flags = '';
  let info = `EtherType 0x${etherType.toString(16)}`;
  let dnsQuery: string | undefined;
  let httpHost: string | undefined;

  if (etherType === 0x0806 && bytes.length >= l3Offset + 28) {
    protocol = 'ARP';
    const op = (bytes[l3Offset + 6] << 8) | bytes[l3Offset + 7];
    srcIp = formatIpv4(bytes, l3Offset + 14);
    dstIp = formatIpv4(bytes, l3Offset + 24);
    info = op === 1 ? `Who has ${dstIp}? Tell ${srcIp}` : `ARP Reply ${srcIp}`;
  } else if (etherType === 0x0800 && bytes.length >= l3Offset + 20) {
    const ihl = (bytes[l3Offset] & 0x0f) * 4;
    const ipProto = bytes[l3Offset + 9];
    srcIp = formatIpv4(bytes, l3Offset + 12);
    dstIp = formatIpv4(bytes, l3Offset + 16);
    const l4Offset = l3Offset + Math.max(20, ihl);

    if (ipProto === 6 && bytes.length >= l4Offset + 20) {
      protocol = 'TCP';
      srcPort = (bytes[l4Offset] << 8) | bytes[l4Offset + 1];
      dstPort = (bytes[l4Offset + 2] << 8) | bytes[l4Offset + 3];
      const dataOff = ((bytes[l4Offset + 12] >> 4) & 0x0f) * 4;
      const tcpFlags = bytes[l4Offset + 13];
      const flagNames: string[] = [];
      if (tcpFlags & 0x02) flagNames.push('SYN');
      if (tcpFlags & 0x10) flagNames.push('ACK');
      if (tcpFlags & 0x08) flagNames.push('PSH');
      if (tcpFlags & 0x01) flagNames.push('FIN');
      if (tcpFlags & 0x04) flagNames.push('RST');
      flags = flagNames.join(',');

      const appOffset = l4Offset + Math.max(20, dataOff);
      if (appOffset < bytes.length) {
        const appStr = String.fromCharCode(...bytes.subarray(appOffset, Math.min(bytes.length, appOffset + 200)));
        if (/^(GET|POST|PUT|DELETE|HEAD|HTTP\/)/i.test(appStr)) {
          protocol = 'HTTP';
          const hostM = appStr.match(/Host:\s*([^\r\n]+)/i);
          if (hostM?.[1]) httpHost = hostM[1].trim();
          info = appStr.split(/\r?\n/)[0].slice(0, 70);
        } else if (srcPort === 443 || dstPort === 443) {
          protocol = 'TLS/HTTPS';
          info = `TLS ${srcPort} → ${dstPort} [${flags || 'DATA'}]`;
        } else {
          info = `${srcPort} → ${dstPort} [${flags || 'DATA'}]`;
        }
      } else {
        if (srcPort === 443 || dstPort === 443) protocol = 'TLS/HTTPS';
        info = `${srcPort} → ${dstPort} [${flags || 'CTRL'}]`;
      }
    } else if (ipProto === 17 && bytes.length >= l4Offset + 8) {
      protocol = 'UDP';
      srcPort = (bytes[l4Offset] << 8) | bytes[l4Offset + 1];
      dstPort = (bytes[l4Offset + 2] << 8) | bytes[l4Offset + 3];
      const appOffset = l4Offset + 8;
      if ((srcPort === 53 || dstPort === 53) && bytes.length > appOffset + 12) {
        protocol = 'DNS';
        const qname = decodeDnsQname(bytes, appOffset + 12);
        if (qname) {
          dnsQuery = qname;
          info = `DNS Query/Resp: ${qname}`;
        } else {
          info = `DNS ${srcPort} → ${dstPort}`;
        }
      } else {
        info = `UDP ${srcPort} → ${dstPort}`;
      }
    } else if (ipProto === 1) {
      protocol = 'ICMP';
      const icmpType = bytes[l4Offset];
      info = icmpType === 8 ? 'Echo (ping) request' : icmpType === 0 ? 'Echo (ping) reply' : `ICMP Type ${icmpType}`;
    } else {
      protocol = `IP(${ipProto})`;
      info = `IPv4 Protocol ${ipProto}`;
    }
  } else if (etherType === 0x86dd && bytes.length >= l3Offset + 40) {
    protocol = 'IPv6';
    const nextHdr = bytes[l3Offset + 6];
    srcIp = 'IPv6-Src';
    dstIp = 'IPv6-Dst';
    info = `IPv6 NextHdr=${nextHdr}`;
  }

  const previewSlice = bytes.subarray(0, Math.min(bytes.length, 96));
  return {
    packet: {
      index,
      timestampIso,
      inclLen: bytes.length,
      origLen,
      protocol,
      srcIp,
      dstIp,
      srcPort,
      dstPort,
      flags,
      info,
      rawSliceHex: Array.from(previewSlice).map((b) => b.toString(16).padStart(2, '0')).join(' '),
      rawSliceAscii: Array.from(previewSlice).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join(''),
    },
    dnsQuery,
    httpHost,
  };
}

export const PcapPacketInspectorLab: React.FC<ExtendedLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<PcapAnalysisSummary | null>(null);
  const [filterText, setFilterText] = useState('');
  const [selectedPacket, setSelectedPacket] = useState<ParsedPcapPacket | null>(null);

  const handlePcapUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    setSelectedPacket(null);

    try {
      const buffer = await file.arrayBuffer();
      if (buffer.byteLength < 24) {
        throw new Error('حجم الملف أصغر من ترويسة PCAP القياسية.');
      }

      const view = new DataView(buffer);
      const bytes = new Uint8Array(buffer);
      const sha256 = await digestHex('SHA-256', bytes);

      const magicBE = view.getUint32(0, false);
      const packets: ParsedPcapPacket[] = [];
      const protocolCounts: Record<string, number> = {};
      const srcCounts = new Map<string, number>();
      const dstCounts = new Map<string, number>();
      const dnsSet = new Set<string>();
      const httpSet = new Set<string>();

      let format: 'libpcap' | 'pcapng' = 'libpcap';
      let endianness: 'Little-Endian' | 'Big-Endian' = 'Little-Endian';
      let linkType = 1;

      if (magicBE === 0x0a0d0d0a) {
        // PCAPNG parser
        format = 'pcapng';
        let offset = 0;
        let le = true;
        while (offset + 12 <= buffer.byteLength && packets.length < 2500) {
          const blockType = view.getUint32(offset, le);
          if (blockType === 0x0a0d0d0a && offset + 12 <= buffer.byteLength) {
            const bom = view.getUint32(offset + 8, true);
            le = bom === 0x1a2b3c4d;
            endianness = le ? 'Little-Endian' : 'Big-Endian';
          }
          const blockLen = view.getUint32(offset + 4, le);
          if (blockLen < 12 || offset + blockLen > buffer.byteLength) break;

          if (blockType === 0x00000001 && offset + 10 <= buffer.byteLength) {
            // IDB Interface Description Block
            linkType = view.getUint16(offset + 8, le);
          } else if (blockType === 0x00000006 && offset + 28 <= buffer.byteLength) {
            // EPB Enhanced Packet Block
            const capLen = view.getUint32(offset + 20, le);
            const origLen = view.getUint32(offset + 24, le);
            const dataStart = offset + 28;
            if (dataStart + capLen <= offset + blockLen) {
              const pktBytes = bytes.subarray(dataStart, dataStart + capLen);
              const parsed = parseSinglePacketFrame(
                pktBytes,
                linkType,
                packets.length + 1,
                new Date().toISOString(),
                origLen
              );
              packets.push(parsed.packet);
              protocolCounts[parsed.packet.protocol] = (protocolCounts[parsed.packet.protocol] || 0) + 1;
              srcCounts.set(parsed.packet.srcIp, (srcCounts.get(parsed.packet.srcIp) || 0) + 1);
              dstCounts.set(parsed.packet.dstIp, (dstCounts.get(parsed.packet.dstIp) || 0) + 1);
              if (parsed.dnsQuery) dnsSet.add(parsed.dnsQuery);
              if (parsed.httpHost) httpSet.add(parsed.httpHost);
            }
          }
          offset += blockLen;
        }
      } else {
        // Classic libpcap
        let le: boolean | null = null;
        let nano = false;
        if (magicBE === 0xd4c3b2a1 || magicBE === 0x4d3cb2a1) {
          le = true;
          nano = magicBE === 0x4d3cb2a1;
        } else if (magicBE === 0xa1b2c3d4 || magicBE === 0xa1b23c4d) {
          le = false;
          nano = magicBE === 0xa1b23c4d;
        }
        if (le === null) {
          throw new Error('توقيع الملف لا يطابق صيغة PCAP أو PCAPNG القياسية (Magic Bytes غير صالحة).');
        }
        endianness = le ? 'Little-Endian' : 'Big-Endian';
        linkType = view.getUint32(20, le);

        let offset = 24;
        while (offset + 16 <= buffer.byteLength && packets.length < 2500) {
          const tsSec = view.getUint32(offset, le);
          const tsSub = view.getUint32(offset + 4, le);
          const inclLen = view.getUint32(offset + 8, le);
          const origLen = view.getUint32(offset + 12, le);
          offset += 16;
          if (inclLen > 65535 || offset + inclLen > buffer.byteLength) break;

          const ms = tsSec * 1000 + Math.floor(tsSub / (nano ? 1_000_000 : 1_000));
          const tsIso = new Date(ms).toISOString();
          const pktBytes = bytes.subarray(offset, offset + inclLen);
          const parsed = parseSinglePacketFrame(pktBytes, linkType, packets.length + 1, tsIso, origLen);
          packets.push(parsed.packet);
          protocolCounts[parsed.packet.protocol] = (protocolCounts[parsed.packet.protocol] || 0) + 1;
          srcCounts.set(parsed.packet.srcIp, (srcCounts.get(parsed.packet.srcIp) || 0) + 1);
          dstCounts.set(parsed.packet.dstIp, (dstCounts.get(parsed.packet.dstIp) || 0) + 1);
          if (parsed.dnsQuery) dnsSet.add(parsed.dnsQuery);
          if (parsed.httpHost) httpSet.add(parsed.httpHost);

          offset += inclLen;
        }
      }

      const topSrcIps = Array.from(srcCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([ip, count]) => ({ ip, count }));
      const topDstIps = Array.from(dstCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6)
        .map(([ip, count]) => ({ ip, count }));

      const linkTypeLabel =
        linkType === 1
          ? 'Ethernet II (DLT_EN10MB)'
          : linkType === 113
          ? 'Linux Cooked Capture (DLT_LINUX_SLL)'
          : linkType === 101 || linkType === 12
          ? 'Raw IP (DLT_RAW)'
          : `Link-Type ${linkType}`;

      setSummary({
        fileName: file.name,
        fileSize: file.size,
        sha256,
        format,
        endianness,
        linkType,
        linkTypeLabel,
        packetCount: packets.length,
        packets,
        protocolCounts,
        topSrcIps,
        topDstIps,
        dnsQueries: Array.from(dnsSet).slice(0, 20),
        httpHosts: Array.from(httpSet).slice(0, 20),
      });

      onNotify(`تم تحليل ${packets.length} حزمة شبكة حقيقية من ${file.name}.`, 'success');
      onRecordAudit({
        id: `pcap-${Date.now()}`,
        fileName: `تحليل PCAP: ${file.name}`,
        fileSize: formatBytes(file.size),
        verdict: `${packets.length} حزمة (${format.toUpperCase()}) • ${Object.keys(protocolCounts).join(', ')}`,
        score: 92,
        risk: 'منخفض',
        sha256,
      });
    } catch (err: any) {
      setError(err?.message || 'تعذر تحليل الملف؛ تأكد من أنه ملف التقاط شبكة بصيغة .pcap أو .pcapng سليمة.');
    } finally {
      setLoading(false);
    }
  };

  const filteredPackets = useMemo(() => {
    if (!summary) return [];
    const q = filterText.trim().toLowerCase();
    if (!q) return summary.packets.slice(0, 250);
    return summary.packets
      .filter(
        (p) =>
          p.srcIp.toLowerCase().includes(q) ||
          p.dstIp.toLowerCase().includes(q) ||
          p.protocol.toLowerCase().includes(q) ||
          p.info.toLowerCase().includes(q) ||
          String(p.srcPort || '').includes(q) ||
          String(p.dstPort || '').includes(q)
      )
      .slice(0, 250);
  }, [summary, filterText]);

  return (
    <div className="space-y-6" dir="rtl">
      <div className="rounded-2xl bg-gray-900/95 border border-gray-800 p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-[#D4AF37]">
              Packet Dissector · libpcap / pcapng
            </div>
            <h2 className="text-xl font-bold text-white">
              محلل حزم الشبكة (PCAP)
            </h2>
            <p className="text-xs text-gray-400">
              قراءة ملفات .pcap و.pcapng محلياً لاستخراج الحزم والبروتوكولات وعناوين IP وطلبات DNS وHTTP.
            </p>
          </div>
        </div>

        <label className="flex flex-col items-center justify-center p-8 rounded-2xl border-2 border-dashed border-gray-700 hover:border-[#D4AF37] bg-gray-950/70 cursor-pointer text-center transition">
          <Upload className="w-8 h-8 text-[#D4AF37] mb-2" />
          <span className="text-sm font-bold text-white">
            {loading ? 'جاري تفكيك الحزم...' : 'ارفع ملف التقاط شبكة (.pcap أو .pcapng) للفحص الفوري'}
          </span>
          <span className="text-[11px] text-gray-400 mt-1">
            تتم المعالجة بالكامل داخل المتصفح مع استخراج طبقات L2 / L3 / L4
          </span>
          <input
            type="file"
            accept=".pcap,.pcapng,.cap"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handlePcapUpload(f);
            }}
          />
        </label>

        {error && (
          <div className="p-3.5 rounded-2xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {summary && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-[11px] text-gray-400">إجمالي الحزم المستخرجة</div>
              <div className="text-2xl font-bold font-mono text-[#D4AF37]">{summary.packetCount}</div>
              <div className="text-[11px] text-gray-400 font-mono">
                {summary.format.toUpperCase()} • {summary.endianness}
              </div>
            </div>
            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-[11px] text-gray-400">طبقة الربط (Link Layer)</div>
              <div className="text-sm font-bold text-white font-mono">{summary.linkTypeLabel}</div>
              <div className="text-[11px] text-gray-400 font-mono">{formatBytes(summary.fileSize)}</div>
            </div>
            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-[11px] text-gray-400">توزيع البروتوكولات</div>
              <div className="flex flex-wrap gap-1 pt-1">
                {Object.entries(summary.protocolCounts).map(([proto, count]) => (
                  <span
                    key={proto}
                    className="px-2 py-0.5 rounded bg-gray-950 border border-gray-800 text-[10px] font-mono text-emerald-300"
                  >
                    {proto}: {count}
                  </span>
                ))}
              </div>
            </div>
            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-[11px] text-gray-400">نطاقات DNS / HTTP المرصودة</div>
              <div className="text-sm font-bold text-white font-mono">
                {summary.dnsQueries.length} DNS • {summary.httpHosts.length} HTTP
              </div>
              <div className="text-[11px] text-gray-400 font-mono truncate">
                SHA256: {summary.sha256.slice(0, 14)}...
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-2">
              <div className="text-xs font-bold text-white">أكثر عناوين المصدر (Top Source IPs)</div>
              <div className="space-y-1.5 font-mono text-[11px]">
                {summary.topSrcIps.map((item) => (
                  <div key={item.ip} className="flex justify-between px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800">
                    <span className="text-emerald-300">{item.ip}</span>
                    <span className="text-gray-400">{item.count} حزمة</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="p-4 rounded-2xl bg-gray-900 border border-gray-800 space-y-2">
              <div className="text-xs font-bold text-white">أكثر عناوين الوجهة (Top Destination IPs)</div>
              <div className="space-y-1.5 font-mono text-[11px]">
                {summary.topDstIps.map((item) => (
                  <div key={item.ip} className="flex justify-between px-3 py-1.5 rounded-lg bg-gray-950 border border-gray-800">
                    <span className="text-sky-300">{item.ip}</span>
                    <span className="text-gray-400">{item.count} حزمة</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Filterable Packet Table */}
          <div className="rounded-3xl bg-gray-900 border border-gray-800 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="text-xs font-bold text-white">جدول الحزم التفصيلي (اضغط على أي حزمة لمعاينة البايتات)</div>
              <input
                type="text"
                value={filterText}
                onChange={(e) => setFilterText(e.target.value)}
                placeholder="تصفية بـ IP أو المنفذ أو البروتوكول (مثال: DNS, 443, 192.168)..."
                className="sm:w-80 px-3.5 py-2 rounded-xl bg-gray-950 border border-gray-800 text-xs text-white font-mono outline-none focus:border-[#D4AF37]"
              />
            </div>

            <div className="overflow-x-auto max-h-96 overflow-y-auto">
              <table className="w-full text-xs text-right">
                <thead className="text-[10px] font-mono text-gray-400 border-b border-gray-800 sticky top-0 bg-gray-900">
                  <tr>
                    <th className="py-2 px-2">#</th>
                    <th className="py-2 px-2">البروتوكول</th>
                    <th className="py-2 px-2">المصدر</th>
                    <th className="py-2 px-2">الوجهة</th>
                    <th className="py-2 px-2">الطول</th>
                    <th className="py-2 px-2">التفاصيل</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/70 font-mono text-[11px]">
                  {filteredPackets.map((pkt) => (
                    <tr
                      key={pkt.index}
                      onClick={() => setSelectedPacket(pkt)}
                      className={`cursor-pointer transition ${
                        selectedPacket?.index === pkt.index
                          ? 'bg-[#D4AF37]/15'
                          : 'hover:bg-gray-950'
                      }`}
                    >
                      <td className="py-2 px-2 text-gray-400">{pkt.index}</td>
                      <td className="py-2 px-2 text-[#D4AF37] font-bold">{pkt.protocol}</td>
                      <td className="py-2 px-2 text-emerald-300">
                        {pkt.srcIp}
                        {pkt.srcPort ? `:${pkt.srcPort}` : ''}
                      </td>
                      <td className="py-2 px-2 text-sky-300">
                        {pkt.dstIp}
                        {pkt.dstPort ? `:${pkt.dstPort}` : ''}
                      </td>
                      <td className="py-2 px-2 text-gray-300">{pkt.inclLen} B</td>
                      <td className="py-2 px-2 text-gray-200 truncate max-w-xs">{pkt.info}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selectedPacket && (
              <div className="p-4 rounded-2xl bg-gray-950 border border-[#D4AF37]/40 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between text-[#D4AF37] font-bold">
                  <span>Packet #{selectedPacket.index} • {selectedPacket.protocol}</span>
                  <span>{selectedPacket.timestampIso}</span>
                </div>
                <div className="text-[11px] text-gray-300 break-all">
                  HEX: {selectedPacket.rawSliceHex}
                </div>
                <div className="text-[11px] text-emerald-300 break-all">
                  ASCII: {selectedPacket.rawSliceAscii}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
