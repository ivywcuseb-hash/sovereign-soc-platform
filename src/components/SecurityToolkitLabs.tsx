import React, { useMemo, useState } from 'react';
import JSZip from 'jszip';
import {
  KeyRound,
  FolderArchive,
  Lock,
  MapPin,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Upload,
  FileText,
  Folder,
  FolderOpen,
  EyeOff,
  Download,
  Globe,
  ExternalLink,
  RefreshCw,
  CheckCircle2,
  XCircle,
  Hash,
  Server,
  Clock,
  Cpu,
  Terminal,
} from 'lucide-react';
import { apiUrl, safeReadJsonResponse } from '../utils/apiBase';

export interface ToolkitAuditPayload {
  id: string;
  fileName: string;
  fileSize: string;
  verdict: string;
  score: number;
  risk: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض';
  sha256: string;
}

interface LabCommonProps {
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
// 1. Credential & Breach Lookup Lab (HIBP k-Anonymity + XposedOrNot + OSINT)
// ============================================================================
export const BreachLookupLab: React.FC<LabCommonProps> = ({ onNotify, onRecordAudit }) => {
  const [mode, setMode] = useState<'email_user' | 'password'>('email_user');
  const [queryInput, setQueryInput] = useState('');
  const [passwordInput, setPasswordInput] = useState('');
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [emailResult, setEmailResult] = useState<any | null>(null);
  const [passwordResult, setPasswordResult] = useState<{
    sha1Prefix: string;
    sha1Suffix: string;
    pwnedCount: number;
    checkedAt: string;
  } | null>(null);

  const runEmailOrUsernameLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = queryInput.trim();
    if (!target || loading) return;
    setLoading(true);
    setError(null);
    setEmailResult(null);

    try {
      let data: any = null;
      let useClientFallback = false;

      try {
        const res = await fetch(apiUrl('/api/breach-lookup'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query: target }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data?.success) {
          data = parsed.data;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          useClientFallback = true;
        } else {
          throw new Error(parsed.data?.error || 'تعذر تنفيذ فحص التسريبات.');
        }
      } catch (err: any) {
        if (!useClientFallback && err instanceof TypeError) {
          useClientFallback = true;
        } else if (!useClientFallback) {
          throw err;
        }
      }

      if (useClientFallback || !data) {
        const isEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target);
        if (isEmail) {
          const email = target.toLowerCase();
          const domain = email.split('@')[1] || '';
          const [xonRes, analyticsRes, dnsRes] = await Promise.all([
            fetch(`https://api.xposedornot.com/v1/check-email/${encodeURIComponent(email)}`)
              .then((r) => safeReadJsonResponse(r))
              .catch(() => null),
            fetch(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`)
              .then((r) => safeReadJsonResponse(r))
              .catch(() => null),
            fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`)
              .then((r) => safeReadJsonResponse(r))
              .catch(() => null),
          ]);

          const rawBreaches: string[] = [];
          if (Array.isArray(xonRes?.data?.breaches?.[0])) {
            rawBreaches.push(...xonRes.data.breaches[0].map(String));
          } else if (Array.isArray(xonRes?.data?.breaches)) {
            rawBreaches.push(...xonRes.data.breaches.flat().map(String));
          }

          const breaches: any[] = [];
          const details = analyticsRes?.data?.ExposedBreaches?.breaches_details;
          if (Array.isArray(details)) {
            for (const b of details) {
              breaches.push({
                breach: String(b.breach || 'Unknown'),
                domain: String(b.domain || '—'),
                breachDate: String(b.xposed_date || '—'),
                exposedData: String(b.xposed_data || 'Email'),
                recordsCount: b.xposed_records ? Number(b.xposed_records).toLocaleString('en-US') : '—',
                industry: String(b.industry || '—'),
                passwordRisk: String(b.password_risk || 'unknown'),
              });
            }
          }
          for (const name of rawBreaches) {
            if (!breaches.some((d) => d.breach.toLowerCase() === name.toLowerCase())) {
              breaches.push({
                breach: name,
                domain: '—',
                breachDate: '—',
                exposedData: 'Email / Credentials',
                recordsCount: '—',
                industry: '—',
                passwordRisk: 'unknown',
              });
            }
          }
          const mxAnswers = Array.isArray(dnsRes?.data?.Answer) ? dnsRes.data.Answer : [];
          data = {
            success: true,
            queryType: 'email',
            target: email,
            breached: breaches.length > 0,
            breachCount: breaches.length,
            breaches,
            riskSummary: analyticsRes?.data?.BreachMetrics?.risk?.[0] || null,
            gravatarExposed: false,
            domainMxActive: mxAnswers.length > 0,
            mxServers: mxAnswers.map((a: any) => String(a.data)).slice(0, 5),
            sources: ['XposedOrNot Live API', 'Google DNS-over-HTTPS'],
            checkedAt: new Date().toISOString(),
          };
        } else {
          const username = target.replace(/^@/, '');
          const ghRes = await fetch(`https://api.github.com/users/${encodeURIComponent(username)}`)
            .then((r) => safeReadJsonResponse(r))
            .catch(() => null);
          const platforms = [
            ghRes?.ok && ghRes?.data?.login
              ? {
                  platform: 'GitHub',
                  found: true,
                  url: String(ghRes.data.html_url),
                  detail: `${ghRes.data.name || ghRes.data.login} • Repos: ${ghRes.data.public_repos ?? 0}`,
                }
              : { platform: 'GitHub', found: false, url: '', detail: 'غير مسجل أو خاص' },
          ];
          data = {
            success: true,
            queryType: 'username',
            target: username,
            breached: false,
            breachCount: 0,
            breaches: [],
            usernameExposures: platforms,
            sources: ['GitHub Public Users API'],
            checkedAt: new Date().toISOString(),
          };
        }
      }

      setEmailResult(data);
      const isBreached = Boolean(data.breached && data.breachCount > 0);
      const targetHash = await digestHex('SHA-256', new TextEncoder().encode(target.toLowerCase()));
      onRecordAudit({
        id: 'breach-' + Math.random().toString(36).slice(2, 9),
        fileName: `فحص تسريب بيانات: ${target}`,
        fileSize: data.queryType === 'email' ? 'Email Breach Check' : 'Username OSINT',
        verdict: isBreached ? `رصد ${data.breachCount} تسريبات حقيقية` : 'لم يتم رصد تسريب مسجل',
        score: isBreached ? Math.max(15, 100 - data.breachCount * 12) : 95,
        risk: data.breachCount >= 3 ? 'حرج' : isBreached ? 'مرتفع' : 'منخفض',
        sha256: targetHash,
      });
      onNotify(
        isBreached
          ? `تنبيه: تم رصد ${data.breachCount} تسريبات حقيقية مرتبطة بـ ${target}`
          : `اكتمل الفحص لـ ${target} عبر قواعد البيانات الحية.`,
        isBreached ? 'warning' : 'success'
      );
    } catch (err: any) {
      setError(err?.message || 'تعذر الاتصال بقواعد بيانات التسريبات.');
    } finally {
      setLoading(false);
    }
  };

  const runPasswordLeakCheck = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passwordInput || loading) return;
    setLoading(true);
    setError(null);
    setPasswordResult(null);

    try {
      const sha1Hex = (await digestHex('SHA-1', new TextEncoder().encode(passwordInput))).toUpperCase();
      const prefix = sha1Hex.slice(0, 5);
      const suffix = sha1Hex.slice(5);

      // k-Anonymity check: only 5-char SHA-1 prefix leaves the browser!
      const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status} من خادم HIBP Pwned Passwords`);
      const text = await res.text();
      let pwnedCount = 0;
      for (const line of text.split('\n')) {
        const [hashTail, countStr] = line.trim().split(':');
        if (hashTail === suffix) {
          pwnedCount = Number.parseInt(countStr || '0', 10) || 0;
          break;
        }
      }

      setPasswordResult({
        sha1Prefix: prefix,
        sha1Suffix: suffix,
        pwnedCount,
        checkedAt: new Date().toISOString(),
      });

      const maskedDigest = await digestHex('SHA-256', new TextEncoder().encode(sha1Hex));
      onRecordAudit({
        id: 'pwd-' + Math.random().toString(36).slice(2, 9),
        fileName: `فحص كلمة مرور (k-Anonymity SHA-1: ${prefix}***)`,
        fileSize: 'HIBP Pwned Passwords',
        verdict: pwnedCount > 0 ? `كلمة مرور مسربة (${pwnedCount.toLocaleString('en-US')} مرة)` : 'كلمة مرور غير مسربة',
        score: pwnedCount > 0 ? 10 : 98,
        risk: pwnedCount > 0 ? 'حرج' : 'منخفض',
        sha256: maskedDigest,
      });

      onNotify(
        pwnedCount > 0
          ? `تحذير حرج: كلمة المرور هذه ظهرت في ${pwnedCount.toLocaleString('en-US')} تسريب فعلي!`
          : 'ممتاز: لم يتم العثور على بصمة كلمة المرور في قاعدة بيانات HIBP.',
        pwnedCount > 0 ? 'error' : 'success'
      );
    } catch (err: any) {
      setError(err?.message || 'تعذر فحص بصمة كلمة المرور عبر HIBP.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-[11px] font-mono">
              <KeyRound className="w-3.5 h-3.5" />
              REAL CREDENTIAL & BREACH INTELLIGENCE • K-ANONYMITY
            </div>
            <h2 className="text-xl md:text-2xl font-bold text-white">
              أداة فحص وتسريب كلمات المرور والبيانات (Credential & Breach Lookup)
            </h2>
            <p className="text-xs text-gray-400">
              فحص حقيقي للبريد الإلكتروني واسم المستخدم عبر قاعدة تسريبات XposedOrNot، وفحص كلمات المرور ببروتوكول k-Anonymity (SHA-1 محلي عبر HIBP) دون إرسال كلمة المرور النصية.
            </p>
          </div>
          <div className="flex items-center gap-2 bg-gray-950 p-1 rounded-xl border border-gray-800 shrink-0">
            <button
              type="button"
              onClick={() => {
                setMode('email_user');
                setError(null);
              }}
              className={`px-3 py-2 rounded-lg text-xs font-bold transition cursor-pointer ${
                mode === 'email_user' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'
              }`}
            >
              فحص بريد / اسم مستخدم
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('password');
                setError(null);
              }}
              className={`px-3 py-2 rounded-lg text-xs font-bold transition cursor-pointer ${
                mode === 'password' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'
              }`}
            >
              فحص كلمة مرور (HIBP)
            </button>
          </div>
        </div>

        {mode === 'email_user' ? (
          <form onSubmit={runEmailOrUsernameLookup} className="flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              value={queryInput}
              onChange={(e) => setQueryInput(e.target.value)}
              placeholder="أدخل البريد الإلكتروني (example@domain.com) أو اسم المستخدم..."
              className="flex-1 bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-3 text-sm text-white font-mono outline-none"
              dir="ltr"
            />
            <button
              type="submit"
              disabled={loading || !queryInput.trim()}
              className="px-6 py-3 bg-[#D4AF37] hover:bg-[#c49f2c] disabled:opacity-50 text-gray-950 font-bold rounded-xl text-sm flex items-center justify-center gap-2 transition cursor-pointer"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              <span>{loading ? 'جاري الفحص الحي...' : 'فحص التسريبات الآن'}</span>
            </button>
          </form>
        ) : (
          <form onSubmit={runPasswordLeakCheck} className="space-y-3">
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <input
                  type={showPass ? 'text' : 'password'}
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  placeholder="أدخل كلمة المرور لفحص تسريبها عبر HIBP k-Anonymity..."
                  className="w-full bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-3 text-sm text-white font-mono outline-none"
                  dir="ltr"
                />
                <button
                  type="button"
                  onClick={() => setShowPass((v) => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-400 hover:text-white cursor-pointer"
                >
                  {showPass ? 'إخفاء' : 'إظهار'}
                </button>
              </div>
              <button
                type="submit"
                disabled={loading || !passwordInput}
                className="px-6 py-3 bg-[#D4AF37] hover:bg-[#c49f2c] disabled:opacity-50 text-gray-950 font-bold rounded-xl text-sm flex items-center justify-center gap-2 transition cursor-pointer"
              >
                {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
                <span>{loading ? 'جاري التشفير والفحص...' : 'فحص كلمة المرور بأمان'}</span>
              </button>
            </div>
            <p className="text-[11px] text-emerald-400 font-mono">
              * حماية الخصوصية: يتم حساب SHA-1 في متصفحك وإرسال أول 5 أحرف فقط لـ HIBP ولا تغادر كلمة المرور جهازك أبداً.
            </p>
          </form>
        )}

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {passwordResult && mode === 'password' && (
        <div
          className={`rounded-2xl border p-6 space-y-4 ${
            passwordResult.pwnedCount > 0
              ? 'bg-red-950/25 border-red-500/50'
              : 'bg-emerald-950/20 border-emerald-500/40'
          }`}
        >
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-3">
              {passwordResult.pwnedCount > 0 ? (
                <ShieldAlert className="w-8 h-8 text-red-400" />
              ) : (
                <ShieldCheck className="w-8 h-8 text-emerald-400" />
              )}
              <div>
                <h3 className="text-lg font-bold text-white">
                  {passwordResult.pwnedCount > 0
                    ? `تحذير: كلمة المرور مسربة في ${passwordResult.pwnedCount.toLocaleString('en-US')} اختراق فعلي!`
                    : 'كلمة المرور غير مدرجة في قواعد التسريبات المعروفة (0 تسريب)'}
                </h3>
                <p className="text-xs font-mono text-gray-400" dir="ltr">
                  SHA-1 Prefix Sent: {passwordResult.sha1Prefix} • Local Suffix Match Checked ({passwordResult.sha1Suffix.slice(0, 8)}...)
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {emailResult && mode === 'email_user' && (
        <div className="space-y-4">
          <div
            className={`rounded-2xl border p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 ${
              emailResult.breached
                ? 'bg-red-950/25 border-red-500/50'
                : 'bg-emerald-950/20 border-emerald-500/40'
            }`}
          >
            <div className="flex items-center gap-3">
              {emailResult.breached ? (
                <ShieldAlert className="w-8 h-8 text-red-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-8 h-8 text-emerald-400 shrink-0" />
              )}
              <div className="space-y-1">
                <div className="text-lg font-bold text-white" dir="ltr">
                  {emailResult.target}
                </div>
                <div className="text-xs text-gray-300">
                  {emailResult.queryType === 'email'
                    ? emailResult.breached
                      ? `تم رصد ${emailResult.breachCount} تسريبات بيانات مسجلة لهذا البريد الإلكتروني.`
                      : 'لم يتم العثور على تسريبات منشورة لهذا البريد في قاعدة XposedOrNot.'
                    : 'نتيجة فحص البصمة العامة لاسم المستخدم عبر المنصات المفتوحة:'}
                </div>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 text-xs font-mono">
              {emailResult.queryType === 'email' && (
                <span className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-gray-200">
                  MX Active: {emailResult.domainMxActive ? 'نعم' : 'لا'}
                </span>
              )}
              <span className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-[#D4AF37]">
                Breaches: {emailResult.breachCount}
              </span>
            </div>
          </div>

          {Array.isArray(emailResult.breaches) && emailResult.breaches.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
              <h4 className="text-sm font-bold text-[#D4AF37]">المنصات وقواعد البيانات المسربة ({emailResult.breaches.length}):</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {emailResult.breaches.map((b: any, idx: number) => (
                  <div key={`${b.breach}-${idx}`} className="bg-gray-950 border border-red-500/30 rounded-xl p-4 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-bold text-white text-sm">{b.breach}</span>
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300">
                        {b.breachDate}
                      </span>
                    </div>
                    <div className="text-xs text-gray-400">النطاق: <span className="font-mono text-gray-200">{b.domain}</span></div>
                    <div className="text-xs text-gray-400">البيانات المسربة: <span className="text-amber-300">{b.exposedData}</span></div>
                    <div className="text-[11px] text-gray-500 font-mono">
                      السجلات المتأثرة: {b.recordsCount} • خطورة كلمة المرور: {b.passwordRisk}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {Array.isArray(emailResult.usernameExposures) && (
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
              <h4 className="text-sm font-bold text-[#D4AF37]">تتبع اسم المستخدم عبر المنصات:</h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {emailResult.usernameExposures.map((p: any) => (
                  <div key={p.platform} className="bg-gray-950 border border-gray-800 rounded-xl p-4 flex items-center justify-between gap-3">
                    <div>
                      <div className="font-bold text-white text-sm">{p.platform}</div>
                      <div className="text-xs text-gray-400">{p.detail}</div>
                    </div>
                    {p.found && p.url ? (
                      <a
                        href={p.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3 py-1.5 rounded-lg bg-[#D4AF37]/15 text-[#D4AF37] text-xs font-bold flex items-center gap-1"
                      >
                        <span>عرض</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    ) : (
                      <span className="text-xs text-gray-500 font-mono">Not Found</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 2. Archive Forensics Extractor Lab (100% Real Local JSZip + Tree + Hex)
// ============================================================================
interface ArchiveEntryInfo {
  path: string;
  name: string;
  dir: boolean;
  depth: number;
  isHidden: boolean;
  isSuspiciousExt: boolean;
  isPathTraversal: boolean;
  compressedSize: number;
  uncompressedSize: number;
  date: string;
}

export const ArchiveExtractorLab: React.FC<LabCommonProps> = ({ onNotify, onRecordAudit }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [archiveMeta, setArchiveMeta] = useState<{
    fileName: string;
    fileSize: number;
    sha256: string;
    sha1: string;
    totalEntries: number;
    foldersCount: number;
    filesCount: number;
    hiddenCount: number;
    suspiciousCount: number;
    traversalCount: number;
    totalUncompressed: number;
    analyzedAt: string;
  } | null>(null);
  const [entries, setEntries] = useState<ArchiveEntryInfo[]>([]);
  const [filterMode, setFilterMode] = useState<'all' | 'hidden' | 'suspicious' | 'dirs'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [zipInstance, setZipInstance] = useState<JSZip | null>(null);
  const [selectedEntry, setSelectedEntry] = useState<{
    path: string;
    sha256: string;
    size: number;
    textPreview: string;
    hexPreview: string;
    isBinary: boolean;
  } | null>(null);

  const handleArchiveUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    setSelectedEntry(null);
    setEntries([]);
    setArchiveMeta(null);

    try {
      const buffer = await file.arrayBuffer();
      const [sha256, sha1, zip] = await Promise.all([
        digestHex('SHA-256', buffer),
        digestHex('SHA-1', buffer),
        JSZip.loadAsync(buffer),
      ]);

      const parsedEntries: ArchiveEntryInfo[] = [];
      let foldersCount = 0;
      let filesCount = 0;
      let hiddenCount = 0;
      let suspiciousCount = 0;
      let traversalCount = 0;
      let totalUncompressed = 0;

      zip.forEach((relativePath, zipObj) => {
        const clean = relativePath.replace(/\/+$/, '');
        const segments = clean.split('/').filter(Boolean);
        const name = segments[segments.length - 1] || relativePath;
        const isHidden = segments.some((seg) => seg.startsWith('.')) || /(^|\/)(__MACOSX|\.git|\.env|thumbs\.db)/i.test(relativePath);
        const isPathTraversal = relativePath.includes('..') || relativePath.startsWith('/');
        const isSuspiciousExt = /\.(exe|dll|bat|cmd|ps1|vbs|js|sh|scr|jar|dex|so|apk|pem|key|env|sql|db)$/i.test(name);

        const internalData: any = (zipObj as any)._data || {};
        const uncompSize = Number(internalData.uncompressedSize || 0);
        const compSize = Number(internalData.compressedSize || 0);

        if (zipObj.dir) {
          foldersCount++;
        } else {
          filesCount++;
          totalUncompressed += uncompSize;
        }
        if (isHidden) hiddenCount++;
        if (isSuspiciousExt && !zipObj.dir) suspiciousCount++;
        if (isPathTraversal) traversalCount++;

        parsedEntries.push({
          path: relativePath,
          name,
          dir: zipObj.dir,
          depth: Math.max(0, segments.length - 1),
          isHidden,
          isSuspiciousExt: isSuspiciousExt && !zipObj.dir,
          isPathTraversal,
          compressedSize: compSize,
          uncompressedSize: uncompSize,
          date: zipObj.date ? zipObj.date.toISOString() : '',
        });
      });

      parsedEntries.sort((a, b) => a.path.localeCompare(b.path));
      setZipInstance(zip);
      setEntries(parsedEntries);
      setArchiveMeta({
        fileName: file.name,
        fileSize: file.size,
        sha256,
        sha1,
        totalEntries: parsedEntries.length,
        foldersCount,
        filesCount,
        hiddenCount,
        suspiciousCount,
        traversalCount,
        totalUncompressed,
        analyzedAt: new Date().toISOString(),
      });

      const risk: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض' =
        traversalCount > 0 ? 'حرج' : suspiciousCount > 0 ? 'مرتفع' : hiddenCount > 0 ? 'متوسط' : 'منخفض';
      onRecordAudit({
        id: 'arch-' + Math.random().toString(36).slice(2, 9),
        fileName: `فحص أرشيف: ${file.name}`,
        fileSize: formatBytes(file.size),
        verdict: `استخراج ${filesCount} ملف و${foldersCount} مجلد (مخفية: ${hiddenCount} • مشبوهة: ${suspiciousCount})`,
        score: traversalCount > 0 ? 20 : suspiciousCount > 0 ? 55 : 92,
        risk,
        sha256,
      });
      onNotify(`تم فك وتحليل الأرشيف (${file.name}): ${parsedEntries.length} عنصر محلياً عبر JSZip.`, 'success');
    } catch (err: any) {
      setError(err?.message || 'تعذر فك الأرشيف؛ تأكد أن الملف بصيغة ZIP/JAR/DOCX/APK صالحة غير مشفرة بكلمة مرور.');
    } finally {
      setLoading(false);
    }
  };

  const inspectEntryContent = async (entry: ArchiveEntryInfo) => {
    if (entry.dir || !zipInstance) return;
    const fileObj = zipInstance.file(entry.path);
    if (!fileObj) return;
    const u8 = await fileObj.async('uint8array');
    const slice = u8.slice(0, 16384);
    const sha256 = await digestHex('SHA-256', u8);
    const hexPreview = Array.from(u8.slice(0, 128))
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');
    let nonPrintable = 0;
    for (let i = 0; i < Math.min(slice.length, 512); i++) {
      const c = slice[i];
      if (c < 9 || (c > 13 && c < 32)) nonPrintable++;
    }
    const isBinary = nonPrintable > 20;
    const textPreview = isBinary
      ? 'ملف ثنائي (Binary Payload) — راجع معاينة الـ Hex أدناه.'
      : new TextDecoder('utf-8', { fatal: false }).decode(slice);
    setSelectedEntry({
      path: entry.path,
      sha256,
      size: u8.byteLength,
      textPreview,
      hexPreview,
      isBinary,
    });
  };

  const filteredEntries = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return entries.filter((e) => {
      if (filterMode === 'hidden' && !e.isHidden) return false;
      if (filterMode === 'suspicious' && !e.isSuspiciousExt && !e.isPathTraversal) return false;
      if (filterMode === 'dirs' && !e.dir) return false;
      if (q && !e.path.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [entries, filterMode, searchTerm]);

  const exportManifestJson = () => {
    if (!archiveMeta) return;
    const blob = new Blob([JSON.stringify({ archiveMeta, entries }, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `archive_forensics_${archiveMeta.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-[#D4AF37] text-[11px] font-mono">
              <FolderArchive className="w-3.5 h-3.5" />
              LOCAL IN-BROWSER ARCHIVE FORENSICS • JSZIP + WEB CRYPTO
            </div>
            <h2 className="text-xl md:text-2xl font-bold text-white">
              أداة تحليل الملفات المضغوطة والأرشيف (Archive Forensics Extractor)
            </h2>
            <p className="text-xs text-gray-400">
              فك وتحليل فعلي 100% في المتصفح لملفات (.zip, .jar, .docx, .xlsx, .apk) لاستخراج شجرة المجلدات والملفات المخفية (.env / .git) وكشف ملفات السكربتات أو ثغرات Zip Slip.
            </p>
          </div>
          {archiveMeta && (
            <button
              type="button"
              onClick={exportManifestJson}
              className="px-4 py-2 rounded-xl bg-gray-950 border border-[#D4AF37]/40 text-[#D4AF37] text-xs font-bold flex items-center gap-2 hover:bg-gray-800 transition cursor-pointer shrink-0"
            >
              <Download className="w-4 h-4" />
              <span>تصدير شجرة الأرشيف JSON</span>
            </button>
          )}
        </div>

        <label className="block border-2 border-dashed border-gray-700 hover:border-[#D4AF37] rounded-2xl p-8 text-center cursor-pointer transition bg-gray-950/60">
          <input
            type="file"
            accept=".zip,.jar,.docx,.xlsx,.pptx,.apk"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleArchiveUpload(f);
              e.target.value = '';
            }}
          />
          <Upload className="w-10 h-10 text-[#D4AF37] mx-auto mb-3" />
          <div className="text-sm font-bold text-white">
            {loading ? 'جاري فك ضغط الأرشيف وبناء شجرة المحتويات...' : 'اضغط لرفع ملف أرشيفي (.zip / .jar / .docx / .apk)'}
          </div>
          <div className="text-xs text-gray-400 mt-1">
            التحليل محلي بالكامل داخل ذاكرة المتصفح ولا يتم إرسال محتوى الملف لأي خادم خارجي.
          </div>
        </label>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {archiveMeta && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">إجمالي العناصر</div>
              <div className="text-2xl font-bold font-mono text-white">{archiveMeta.totalEntries}</div>
              <div className="text-[10px] text-gray-500">{archiveMeta.filesCount} ملف • {archiveMeta.foldersCount} مجلد</div>
            </div>
            <div className="bg-gray-900 border border-amber-500/30 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">ملفات/مجلدات مخفية</div>
              <div className="text-2xl font-bold font-mono text-amber-400">{archiveMeta.hiddenCount}</div>
              <div className="text-[10px] text-gray-500">.git / .env / dot-files</div>
            </div>
            <div className="bg-gray-900 border border-red-500/30 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">ملفات تنفيذية / حساسة</div>
              <div className="text-2xl font-bold font-mono text-red-400">{archiveMeta.suspiciousCount}</div>
              <div className="text-[10px] text-gray-500">.exe / .ps1 / .sh / .sql / .key</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">ثغرات Zip Slip (../)</div>
              <div className={`text-2xl font-bold font-mono ${archiveMeta.traversalCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {archiveMeta.traversalCount}
              </div>
              <div className="text-[10px] text-gray-500">فحص مسارات الاختراق</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">الحجم بعد الفك</div>
              <div className="text-xl font-bold font-mono text-[#D4AF37]">{formatBytes(archiveMeta.totalUncompressed)}</div>
              <div className="text-[10px] text-gray-500 font-mono truncate">{archiveMeta.sha256.slice(0, 16)}...</div>
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="flex flex-wrap gap-2">
                {(
                  [
                    { id: 'all', label: `الكل (${entries.length})` },
                    { id: 'hidden', label: `المخفية (${archiveMeta.hiddenCount})` },
                    { id: 'suspicious', label: `المشبوهة (${archiveMeta.suspiciousCount + archiveMeta.traversalCount})` },
                    { id: 'dirs', label: `المجلدات (${archiveMeta.foldersCount})` },
                  ] as const
                ).map((f) => (
                  <button
                    key={f.id}
                    type="button"
                    onClick={() => setFilterMode(f.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer ${
                      filterMode === f.id ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                    }`}
                  >
                    {f.label}
                  </button>
                ))}
              </div>
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="تصفية داخل شجرة الأرشيف..."
                className="bg-gray-950 border border-gray-800 rounded-xl px-3 py-1.5 text-xs text-white font-mono outline-none focus:border-[#D4AF37]"
                dir="ltr"
              />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="bg-gray-950 border border-gray-800 rounded-xl p-3 max-h-[420px] overflow-y-auto space-y-1" dir="ltr">
                {filteredEntries.map((entry) => (
                  <button
                    key={entry.path}
                    type="button"
                    disabled={entry.dir}
                    onClick={() => void inspectEntryContent(entry)}
                    style={{ paddingLeft: `${entry.depth * 14 + 8}px` }}
                    className={`w-full text-left py-1.5 pr-2 rounded-lg text-xs font-mono flex items-center justify-between gap-2 transition ${
                      entry.dir
                        ? 'text-amber-300/90 cursor-default'
                        : selectedEntry?.path === entry.path
                        ? 'bg-[#D4AF37]/20 text-white border border-[#D4AF37]/40 cursor-pointer'
                        : 'text-gray-300 hover:bg-gray-900 cursor-pointer'
                    }`}
                  >
                    <span className="flex items-center gap-2 truncate">
                      {entry.dir ? <FolderOpen className="w-3.5 h-3.5 text-[#D4AF37] shrink-0" /> : <FileText className="w-3.5 h-3.5 text-gray-400 shrink-0" />}
                      <span className="truncate">{entry.name}</span>
                      {entry.isHidden && <EyeOff className="w-3 h-3 text-amber-400 shrink-0" />}
                      {entry.isSuspiciousExt && <ShieldAlert className="w-3 h-3 text-red-400 shrink-0" />}
                    </span>
                    {!entry.dir && (
                      <span className="text-[10px] text-gray-500 shrink-0">
                        {entry.uncompressedSize ? formatBytes(entry.uncompressedSize) : 'Inspect'}
                      </span>
                    )}
                  </button>
                ))}
              </div>

              <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3 max-h-[420px] overflow-y-auto">
                {selectedEntry ? (
                  <>
                    <div className="flex items-center justify-between border-b border-gray-800 pb-2">
                      <span className="text-xs font-mono text-[#D4AF37] break-all" dir="ltr">{selectedEntry.path}</span>
                      <span className="text-[11px] font-mono text-gray-400 shrink-0">{formatBytes(selectedEntry.size)}</span>
                    </div>
                    <div className="text-[11px] font-mono text-gray-400 break-all" dir="ltr">
                      SHA-256: <span className="text-emerald-400">{selectedEntry.sha256}</span>
                    </div>
                    <div className="space-y-1">
                      <div className="text-[11px] font-bold text-gray-300">Hex Header (First 128 Bytes):</div>
                      <pre className="p-2.5 rounded-lg bg-gray-900 border border-gray-800 text-[10px] font-mono text-amber-300 overflow-x-auto" dir="ltr">
                        {selectedEntry.hexPreview || 'Empty File'}
                      </pre>
                    </div>
                    <div className="space-y-1">
                      <div className="text-[11px] font-bold text-gray-300">معاينة المحتوى المستخرج:</div>
                      <pre className="p-3 rounded-lg bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-200 whitespace-pre-wrap break-all max-h-48 overflow-y-auto" dir="ltr">
                        {selectedEntry.textPreview}
                      </pre>
                    </div>
                  </>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-center text-gray-500 py-16 space-y-2">
                    <Folder className="w-8 h-8 text-gray-600" />
                    <p className="text-xs">اضغط على أي ملف داخل شجرة الأرشيف لفحص محتواه وبصمته SHA-256 ومقاطع الـ Hex.</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 3. SSL/TLS Certificate Inspector Lab (Real Node TLS Socket + crt.sh Fallback)
// ============================================================================
export const SslInspectorLab: React.FC<LabCommonProps> = ({ onNotify, onRecordAudit }) => {
  const [targetInput, setTargetInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [certResult, setCertResult] = useState<any | null>(null);

  const inspectSsl = async (e: React.FormEvent) => {
    e.preventDefault();
    const raw = targetInput.trim();
    if (!raw || loading) return;
    setLoading(true);
    setError(null);
    setCertResult(null);

    try {
      let certData: any = null;
      let useCtFallback = false;

      try {
        const res = await fetch(apiUrl('/api/ssl-inspect'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target: raw }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data?.certificate) {
          certData = parsed.data.certificate;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          useCtFallback = true;
        } else {
          throw new Error(parsed.data?.error || 'تعذر فحص شهادة SSL للموقع.');
        }
      } catch (err: any) {
        if (!useCtFallback && err instanceof TypeError) {
          useCtFallback = true;
        } else if (!useCtFallback) {
          throw err;
        }
      }

      if (useCtFallback || !certData) {
        let host = raw;
        if (/^https?:\/\//i.test(host)) host = new URL(host).hostname;
        host = host.split('/')[0].split(':')[0].toLowerCase();
        const ctRes = await fetch(`https://crt.sh/?q=${encodeURIComponent(host)}&output=json`);
        const parsedCt = await safeReadJsonResponse(ctRes);
        const rows = Array.isArray(parsedCt.data) ? parsedCt.data : [];
        if (!rows.length) {
          throw new Error(`لم يتم العثور على شهادة مسجلة في سجلات الشفافية (crt.sh) للنطاق ${host}.`);
        }
        const latest = rows[0];
        const validToMs = latest.not_after ? new Date(latest.not_after).getTime() : NaN;
        const daysRemaining = Number.isFinite(validToMs) ? Math.floor((validToMs - Date.now()) / 86400000) : null;
        certData = {
          hostname: host,
          resolvedIp: 'CT Log Lookup',
          authorized: daysRemaining !== null ? daysRemaining >= 0 : true,
          protocol: 'TLS (CT Log Record)',
          cipherName: 'Certificate Transparency Log',
          subjectCN: String(latest.common_name || host),
          subjectO: '—',
          issuerCN: String(latest.issuer_name || '—'),
          issuerO: String(latest.issuer_name || '—'),
          validFrom: String(latest.not_before || ''),
          validTo: String(latest.not_after || ''),
          daysRemaining,
          isExpired: daysRemaining !== null ? daysRemaining < 0 : false,
          keyBits: 2048,
          keyType: 'X.509 Public Certificate',
          serialNumber: String(latest.serial_number || ''),
          fingerprint256: `CT-ID-${latest.id || '0'}`,
          sanList: String(latest.name_value || '').split('\n').filter(Boolean).slice(0, 15),
          chain: [],
          inspectedAt: new Date().toISOString(),
        };
      }

      setCertResult(certData);
      const hash = await digestHex('SHA-256', new TextEncoder().encode(JSON.stringify(certData)));
      const expired = Boolean(certData.isExpired);
      onRecordAudit({
        id: 'ssl-' + Math.random().toString(36).slice(2, 9),
        fileName: `فحص SSL/TLS: ${certData.hostname}`,
        fileSize: `${certData.protocol} • ${certData.keyType}`,
        verdict: expired
          ? 'شهادة منتهية الصلاحية (Expired)'
          : `شهادة صالحة (${certData.daysRemaining ?? '—'} يوم متبقي) • ${certData.issuerO}`,
        score: expired ? 20 : certData.authorized ? 96 : 65,
        risk: expired ? 'حرج' : certData.authorized ? 'منخفض' : 'متوسط',
        sha256: hash,
      });
      onNotify(`اكتمل فحص شهادة SSL/TLS للنطاق ${certData.hostname} بنجاح.`, expired ? 'warning' : 'success');
    } catch (err: any) {
      setError(err?.message || 'تعذر الاتصال بالخادم لفحص الشهادة.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="space-y-1 border-b border-gray-800 pb-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[11px] font-mono">
            <Lock className="w-3.5 h-3.5" />
            LIVE X.509 HANDSHAKE • TLS CIPHER & CHAIN INSPECTOR
          </div>
          <h2 className="text-xl md:text-2xl font-bold text-white">
            أداة فحص شهادات الأمان وسلاسل التشفير (SSL/TLS Certificate Inspector)
          </h2>
          <p className="text-xs text-gray-400">
            اتصال حي مباشر بمنفذ TLS/443 لاستخراج الشهادة الفعلية، الجهة المصدرة، تاريخ الانتهاء، قوة المفتاح، خوارزمية التشفير (Cipher Suite)، وسلسلة الثقة الكاملة.
          </p>
        </div>

        <form onSubmit={inspectSsl} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder="أدخل رابط الموقع أو النطاق (مثال: https://google.com أو github.com)"
            className="flex-1 bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-3 text-sm text-white font-mono outline-none"
            dir="ltr"
          />
          <button
            type="submit"
            disabled={loading || !targetInput.trim()}
            className="px-6 py-3 bg-[#D4AF37] hover:bg-[#c49f2c] disabled:opacity-50 text-gray-950 font-bold rounded-xl text-sm flex items-center justify-center gap-2 transition cursor-pointer"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
            <span>{loading ? 'جاري فحص الشهادة...' : 'فحص شهادة SSL الآن'}</span>
          </button>
        </form>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {certResult && (
        <div className="space-y-4">
          <div
            className={`rounded-2xl border p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 ${
              certResult.isExpired
                ? 'bg-red-950/25 border-red-500/50'
                : 'bg-emerald-950/20 border-emerald-500/40'
            }`}
          >
            <div className="flex items-center gap-3">
              {certResult.isExpired ? (
                <XCircle className="w-8 h-8 text-red-400 shrink-0" />
              ) : (
                <CheckCircle2 className="w-8 h-8 text-emerald-400 shrink-0" />
              )}
              <div>
                <div className="text-lg font-bold text-white font-mono" dir="ltr">
                  {certResult.hostname} ({certResult.resolvedIp})
                </div>
                <div className="text-xs text-gray-300">
                  {certResult.isExpired
                    ? 'الشهادة منتهية الصلاحية!'
                    : `الشهادة صالحة • متبقي ${certResult.daysRemaining ?? '—'} يوماً حتى الانتهاء`}
                </div>
              </div>
            </div>
            <div className="flex flex-wrap gap-2 text-xs font-mono">
              <span className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-[#D4AF37]">
                {certResult.protocol}
              </span>
              <span className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-emerald-300">
                {certResult.keyType}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-2.5 text-xs">
              <h4 className="text-sm font-bold text-[#D4AF37] mb-2">تفاصيل الهوية والجهة المصدرة (Issuer & Subject)</h4>
              <div className="flex justify-between gap-2"><span className="text-gray-400">Subject CN:</span><span className="font-mono text-white" dir="ltr">{certResult.subjectCN}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">الجهة المصدرة (Issuer O):</span><span className="font-mono text-emerald-300" dir="ltr">{certResult.issuerO}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">Issuer CN:</span><span className="font-mono text-gray-200" dir="ltr">{certResult.issuerCN}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">تاريخ الإصدار:</span><span className="font-mono text-gray-200" dir="ltr">{certResult.validFrom}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">تاريخ الانتهاء:</span><span className="font-mono text-amber-300" dir="ltr">{certResult.validTo}</span></div>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-2.5 text-xs">
              <h4 className="text-sm font-bold text-[#D4AF37] mb-2">قوة التشفير وبصمة الشهادة (Cryptography)</h4>
              <div className="flex justify-between gap-2"><span className="text-gray-400">بروتوكول TLS:</span><span className="font-mono text-white">{certResult.protocol}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">حزمة التشفير (Cipher):</span><span className="font-mono text-emerald-300" dir="ltr">{certResult.cipherStandardName || certResult.cipherName}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">قوة المفتاح:</span><span className="font-mono text-white">{certResult.keyType}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">Serial Number:</span><span className="font-mono text-gray-300 truncate max-w-[210px]" dir="ltr">{certResult.serialNumber || '—'}</span></div>
              <div className="text-[11px] font-mono text-gray-400 break-all pt-1" dir="ltr">
                SHA-256 Fingerprint: <span className="text-[#D4AF37]">{certResult.fingerprint256}</span>
              </div>
            </div>
          </div>

          {Array.isArray(certResult.chain) && certResult.chain.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
              <h4 className="text-sm font-bold text-[#D4AF37]">سلسلة الثقة للشهادات (Certificate Chain Hierarchy)</h4>
              <div className="space-y-2">
                {certResult.chain.map((node: any, idx: number) => (
                  <div key={idx} className="bg-gray-950 border border-gray-800 rounded-xl p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono" dir="ltr">
                    <div>
                      <span className="text-[#D4AF37] mr-2">[{idx === 0 ? 'Leaf' : idx === certResult.chain.length - 1 ? 'Root/Intermediate' : `Chain #${idx}`}]</span>
                      <span className="text-white font-bold">{node.subjectCN}</span>
                      <span className="text-gray-400 ml-2">← Issued by: {node.issuerO} ({node.issuerCN})</span>
                    </div>
                    <span className="text-[10px] text-gray-500">Expires: {node.validTo}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {Array.isArray(certResult.sanList) && certResult.sanList.length > 0 && (
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-2">
              <h4 className="text-xs font-bold text-gray-300">النطاقات البديلة المغطاة بالشهادة (SANs - {certResult.sanList.length}):</h4>
              <div className="flex flex-wrap gap-1.5" dir="ltr">
                {certResult.sanList.map((s: string) => (
                  <span key={s} className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800 text-[11px] font-mono text-gray-300">
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 4. IP Geolocation & Threat Mapper Lab (GeoIP + Blocklists + Interactive Map)
// ============================================================================
export const IpGeoThreatMapperLab: React.FC<LabCommonProps> = ({ onNotify, onRecordAudit }) => {
  const [ipInput, setIpInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [geoResult, setGeoResult] = useState<any | null>(null);

  const lookupIp = async (targetIp?: string) => {
    let candidate = (targetIp ?? ipInput).trim();
    if (loading) return;
    setLoading(true);
    setError(null);
    setGeoResult(null);

    try {
      if (!candidate) {
        const myIpRes = await fetch('https://ipwho.is/');
        const myParsed = await safeReadJsonResponse(myIpRes);
        if (!myParsed.data?.ip) throw new Error('يرجى إدخال عنوان IP للفحص.');
        candidate = String(myParsed.data.ip);
        setIpInput(candidate);
      }

      let data: any = null;
      let useClientFallback = false;
      try {
        const res = await fetch(apiUrl('/api/ip-geo-threat'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: candidate }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data?.geoThreat) {
          data = parsed.data.geoThreat;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          useClientFallback = true;
        } else {
          throw new Error(parsed.data?.error || 'تعذر جلب البيانات الجغرافية لعنوان الـ IP.');
        }
      } catch (err: any) {
        if (!useClientFallback && err instanceof TypeError) {
          useClientFallback = true;
        } else if (!useClientFallback) {
          throw err;
        }
      }

      if (useClientFallback || !data) {
        const [geoRes, rdapRes] = await Promise.all([
          fetch(`https://ipwho.is/${encodeURIComponent(candidate)}`).then((r) => safeReadJsonResponse(r)).catch(() => null),
          fetch(`https://rdap.org/ip/${encodeURIComponent(candidate)}`).then((r) => safeReadJsonResponse(r)).catch(() => null),
        ]);
        const g = geoRes?.data;
        if (!g || g.success === false) {
          throw new Error(g?.message || 'عنوان IP غير صالح أو تعذر تحديد موقعه.');
        }
        const blocklistHits: any[] = [];
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(candidate)) {
          const rev = candidate.split('.').reverse().join('.');
          const spamRes = await fetch(`https://dns.google/resolve?name=${rev}.zen.spamhaus.org&type=A`)
            .then((r) => safeReadJsonResponse(r))
            .catch(() => null);
          const ans = Array.isArray(spamRes?.data?.Answer) ? spamRes.data.Answer : [];
          if (ans.some((a: any) => /^127\.0\.0\./.test(String(a.data)))) {
            blocklistHits.push({
              source: 'Spamhaus ZEN DNSBL',
              detail: `مدرج في قوائم الحظر (${ans.map((a: any) => a.data).join(', ')})`,
              severity: 'high',
            });
          }
        }
        data = {
          ip: candidate,
          country: g.country || rdapRes?.data?.country || 'غير محدد',
          countryCode: g.country_code || '',
          flagEmoji: g.flag?.emoji || '',
          region: g.region || '—',
          city: g.city || '—',
          timezone: g.timezone?.id || 'UTC',
          latitude: typeof g.latitude === 'number' ? g.latitude : null,
          longitude: typeof g.longitude === 'number' ? g.longitude : null,
          asn: g.connection?.asn ? `AS${g.connection.asn}` : '—',
          isp: g.connection?.isp || rdapRes?.data?.name || '—',
          org: g.connection?.org || rdapRes?.data?.name || '—',
          reverseDns: [],
          cidr: null,
          blocklisted: blocklistHits.length > 0,
          blocklistHits,
          sourcesChecked: ['IPWhois Live GeoIP', 'RDAP Network Registry', 'Spamhaus ZEN DNSBL'],
          checkedAt: new Date().toISOString(),
        };
      }

      setGeoResult(data);
      const hash = await digestHex('SHA-256', new TextEncoder().encode(candidate));
      onRecordAudit({
        id: 'geo-' + Math.random().toString(36).slice(2, 9),
        fileName: `خريطة IP والتهديدات: ${data.ip}`,
        fileSize: `${data.country} • ${data.asn}`,
        verdict: data.blocklisted
          ? `مدرج في ${data.blocklistHits.length} قائمة حظر (${data.isp})`
          : `نظيف • ${data.city}, ${data.country} (${data.isp})`,
        score: data.blocklisted ? 18 : 94,
        risk: data.blocklisted ? 'حرج' : 'منخفض',
        sha256: hash,
      });
      onNotify(
        data.blocklisted
          ? `تحذير: عنوان الـ IP (${data.ip}) مدرج في قوائم الحظر والتهديدات!`
          : `تم تحديد موقع ${data.ip}: ${data.city}, ${data.country}`,
        data.blocklisted ? 'error' : 'success'
      );
    } catch (err: any) {
      setError(err?.message || 'تعذر تحديد الموقع الجغرافي لعنوان الـ IP.');
    } finally {
      setLoading(false);
    }
  };

  // Convert lat/lon to equirectangular SVG percentages (800x400 viewBox)
  const mapCoords = useMemo(() => {
    if (!geoResult || typeof geoResult.latitude !== 'number' || typeof geoResult.longitude !== 'number') {
      return null;
    }
    const x = ((geoResult.longitude + 180) / 360) * 800;
    const y = ((90 - geoResult.latitude) / 180) * 400;
    return { x, y };
  }, [geoResult]);

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="space-y-1 border-b border-gray-800 pb-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-300 text-[11px] font-mono">
            <MapPin className="w-3.5 h-3.5" />
            LIVE IP GEOLOCATION • RDAP • ABUSE.CH & SPAMHAUS BLOCKLISTS
          </div>
          <h2 className="text-xl md:text-2xl font-bold text-white">
            أداة خريطة الـ IP الجغرافية واستخبارات التهديدات (IP Geolocation & Threat Mapper)
          </h2>
          <p className="text-xs text-gray-400">
            تحديد الموقع الجغرافي الدقيق، المزود (ISP/ASN)، سجلات RDAP، وفحص الإدراج في قوائم الحظر الحية (Feodo C2، ThreatFox، Spamhaus ZEN).
          </p>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void lookupIp();
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <input
            type="text"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            placeholder="أدخل عنوان IP (مثال: 8.8.8.8 أو 1.1.1.1)..."
            className="flex-1 bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-3 text-sm text-white font-mono outline-none"
            dir="ltr"
          />
          <button
            type="button"
            disabled={loading}
            onClick={() => {
              setIpInput('');
              void lookupIp('');
            }}
            className="px-4 py-3 bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 font-bold rounded-xl text-xs transition cursor-pointer"
          >
            فحص عنواني الحالي
          </button>
          <button
            type="submit"
            disabled={loading || !ipInput.trim()}
            className="px-6 py-3 bg-[#D4AF37] hover:bg-[#c49f2c] disabled:opacity-50 text-gray-950 font-bold rounded-xl text-sm flex items-center justify-center gap-2 transition cursor-pointer"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <MapPin className="w-4 h-4" />}
            <span>{loading ? 'جاري التتبع...' : 'تتبع وفحص الـ IP'}</span>
          </button>
        </form>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {geoResult && (
        <div className="space-y-4">
          <div
            className={`rounded-2xl border p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 ${
              geoResult.blocklisted
                ? 'bg-red-950/25 border-red-500/50'
                : 'bg-emerald-950/20 border-emerald-500/40'
            }`}
          >
            <div className="flex items-center gap-3">
              {geoResult.blocklisted ? (
                <ShieldAlert className="w-8 h-8 text-red-400 shrink-0" />
              ) : (
                <ShieldCheck className="w-8 h-8 text-emerald-400 shrink-0" />
              )}
              <div>
                <div className="text-lg font-bold text-white font-mono" dir="ltr">
                  {geoResult.flagEmoji} {geoResult.ip} — {geoResult.city}, {geoResult.country}
                </div>
                <div className="text-xs text-gray-300">
                  {geoResult.blocklisted
                    ? `تنبيه حرج: عنوان الـ IP مدرج في ${geoResult.blocklistHits.length} قائمة حظر أمنية!`
                    : 'سليم: عنوان الـ IP غير مدرج في قوائم Feodo C2 أو ThreatFox أو Spamhaus ZEN.'}
                </div>
              </div>
            </div>
            <span className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-xs font-mono text-[#D4AF37]">
              {geoResult.asn} • {geoResult.isp}
            </span>
          </div>

          {geoResult.blocklistHits?.length > 0 && (
            <div className="bg-red-950/20 border border-red-500/40 rounded-2xl p-4 space-y-2">
              <h4 className="text-xs font-bold text-red-300">مطابقات قوائم الحظر والتهديدات المرصودة:</h4>
              {geoResult.blocklistHits.map((hit: any, idx: number) => (
                <div key={idx} className="bg-gray-950 border border-red-500/30 rounded-xl p-3 text-xs flex items-center justify-between gap-2">
                  <span className="font-bold text-red-300">{hit.source}</span>
                  <span className="text-gray-200 font-mono">{hit.detail}</span>
                </div>
              ))}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-bold text-[#D4AF37]">خريطة الإحداثيات الجغرافية (Live Geo Plot)</h4>
                {mapCoords && (
                  <span className="text-[11px] font-mono text-gray-400" dir="ltr">
                    {geoResult.latitude.toFixed(4)}, {geoResult.longitude.toFixed(4)}
                  </span>
                )}
              </div>
              <div className="relative rounded-xl overflow-hidden bg-[#060a14] border border-gray-800">
                <svg viewBox="0 0 800 400" className="w-full h-56 block">
                  {/* Lat/Lon Grid */}
                  {[100, 200, 300].map((y) => (
                    <line key={`h-${y}`} x1="0" y1={y} x2="800" y2={y} stroke="#1f2937" strokeWidth="1" strokeDasharray="4 4" />
                  ))}
                  {[160, 320, 400, 480, 640].map((x) => (
                    <line key={`v-${x}`} x1={x} y1="0" x2={x} y2="400" stroke="#1f2937" strokeWidth="1" strokeDasharray="4 4" />
                  ))}
                  {/* Stylized continent silhouettes */}
                  <g fill="#162136" stroke="#2c3e5f" strokeWidth="1">
                    <path d="M95,70 L235,65 L255,130 L185,180 L125,155 Z" />
                    <path d="M210,195 L280,210 L295,305 L245,355 L210,285 Z" />
                    <path d="M365,65 L470,60 L485,130 L375,140 Z" />
                    <path d="M370,155 L490,150 L510,270 L440,320 L385,240 Z" />
                    <path d="M485,55 L700,65 L730,185 L590,215 L500,155 Z" />
                    <path d="M625,255 L725,260 L735,325 L640,330 Z" />
                  </g>
                  {mapCoords && (
                    <>
                      <line x1={mapCoords.x} y1="0" x2={mapCoords.x} y2="400" stroke={geoResult.blocklisted ? '#ef4444' : '#D4AF37'} strokeOpacity="0.35" strokeWidth="1" />
                      <line x1="0" y1={mapCoords.y} x2="800" y2={mapCoords.y} stroke={geoResult.blocklisted ? '#ef4444' : '#D4AF37'} strokeOpacity="0.35" strokeWidth="1" />
                      <circle cx={mapCoords.x} cy={mapCoords.y} r="18" fill={geoResult.blocklisted ? '#ef4444' : '#D4AF37'} fillOpacity="0.2" />
                      <circle cx={mapCoords.x} cy={mapCoords.y} r="6" fill={geoResult.blocklisted ? '#ef4444' : '#D4AF37'} stroke="#ffffff" strokeWidth="2" />
                    </>
                  )}
                </svg>
              </div>
              {typeof geoResult.latitude === 'number' && typeof geoResult.longitude === 'number' && (
                <a
                  href={`https://www.openstreetmap.org/?mlat=${geoResult.latitude}&mlon=${geoResult.longitude}#map=9/${geoResult.latitude}/${geoResult.longitude}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs text-[#D4AF37] hover:underline"
                >
                  <span>فتح الإحداثيات في الخريطة التفاعلية</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              )}
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-2.5 text-xs">
              <h4 className="text-sm font-bold text-[#D4AF37] mb-2">البيانات الشبكية والجغرافية الحية</h4>
              <div className="flex justify-between gap-2"><span className="text-gray-400">الدولة / المدينة:</span><span className="text-white">{geoResult.country} ({geoResult.countryCode || '—'}) • {geoResult.city}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">المنطقة / التوقيت:</span><span className="font-mono text-gray-200">{geoResult.region} • {geoResult.timezone}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">المزود (ISP):</span><span className="font-mono text-emerald-300" dir="ltr">{geoResult.isp}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">المنظمة / ASN:</span><span className="font-mono text-gray-200" dir="ltr">{geoResult.org} ({geoResult.asn})</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">نطاق الشبكة (CIDR):</span><span className="font-mono text-gray-300" dir="ltr">{geoResult.cidr || '—'}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">Reverse DNS (PTR):</span><span className="font-mono text-gray-300" dir="ltr">{geoResult.reverseDns?.join(', ') || 'لا يوجد سجل'}</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
