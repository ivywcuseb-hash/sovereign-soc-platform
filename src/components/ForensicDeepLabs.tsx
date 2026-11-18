import React, { useEffect, useMemo, useRef, useState } from 'react';
import SparkMD5 from 'spark-md5';
import {
  Bug,
  FileText,
  Route,
  ScanEye,
  Upload,
  Search,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ExternalLink,
  Download,
  Hash,
  Clock,
  Lock,
  Unlock,
  Link2,
  ArrowDown,
  CheckCircle2,
  FileCode,
  Copy,
  Check,
  Layers,
} from 'lucide-react';
import { apiUrl, safeReadJsonResponse } from '../utils/apiBase';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface DeepLabProps {
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
// 1. Malware Hash Lookup Lab (SHA-256 / MD5 + Abuse.ch MalwareBazaar + Cymru)
// ============================================================================
export const MalwareHashLookupLab: React.FC<DeepLabProps> = ({ onNotify, onRecordAudit }) => {
  const [hashInput, setHashInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [localFileHashes, setLocalFileHashes] = useState<{
    fileName: string;
    fileSize: number;
    sha256: string;
    sha1: string;
    md5: string;
    magicHex: string;
  } | null>(null);
  const [lookupResult, setLookupResult] = useState<any | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyText = (val: string, key: string) => {
    void navigator.clipboard?.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1500);
  };

  const executeHashLookup = async (
    primaryHash: string,
    opts?: { md5?: string; sha1?: string; fileName?: string; fileSize?: number }
  ) => {
    const cleanHash = primaryHash.trim().toLowerCase();
    if (!/^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(cleanHash)) {
      setError('يرجى إدخال بصمة صالحة (SHA-256 أو SHA-1 أو MD5).');
      return;
    }

    setLoading(true);
    setError(null);
    setLookupResult(null);

    try {
      let resultData: any = null;
      let useClientFallback = false;

      try {
        const res = await fetch(apiUrl('/api/malware-hash'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            hash: cleanHash,
            md5: opts?.md5 || '',
            sha1: opts?.sha1 || '',
            fileName: opts?.fileName || '',
          }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data?.result) {
          resultData = parsed.data.result;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          useClientFallback = true;
        } else {
          throw new Error(parsed.data?.error || 'تعذر فحص البصمة ضد قواعد الفيروسات.');
        }
      } catch (err: any) {
        if (!useClientFallback && err instanceof TypeError) {
          useClientFallback = true;
        } else if (!useClientFallback) {
          throw err;
        }
      }

      if (useClientFallback || !resultData) {
        // Real CORS-safe fallback via CIRCL Hashlookup & Team Cymru DNS-over-HTTPS
        const hashType = cleanHash.length === 64 ? 'sha256' : cleanHash.length === 40 ? 'sha1' : 'md5';
        const md5ForCymru = opts?.md5 || (hashType === 'md5' ? cleanHash : '');
        const [circlParsed, cymruDns] = await Promise.all([
          fetch(`https://hashlookup.circl.lu/lookup/${hashType}/${cleanHash}`)
            .then((r) => safeReadJsonResponse(r))
            .catch(() => null),
          md5ForCymru
            ? fetch(`https://dns.google/resolve?name=${md5ForCymru}.hash.cymru.com&type=TXT`)
                .then((r) => safeReadJsonResponse(r))
                .catch(() => null)
            : Promise.resolve(null),
        ]);

        const txtVal = String(cymruDns?.data?.Answer?.[0]?.data || '').replace(/"/g, '').trim();
        let cymruPct: number | null = null;
        if (/^\d+\s+\d+/.test(txtVal)) {
          cymruPct = Number.parseInt(txtVal.split(/\s+/)[1] || '0', 10) || null;
        }
        const detected = Boolean(cymruPct && cymruPct > 0);
        const isKnownClean = Boolean(circlParsed?.ok && (circlParsed.data?.FileName || circlParsed.data?.SHA256));

        resultData = {
          hash: cleanHash,
          hashType,
          md5: opts?.md5 || null,
          sha1: opts?.sha1 || null,
          fileName: opts?.fileName || circlParsed?.data?.FileName || null,
          detected,
          isKnownClean,
          verdict: detected
            ? `برمجية خبيثة مرصودة (Team Cymru MHR: ${cymruPct}%)`
            : isKnownClean
            ? `ملف موثوق وسليم (Known Good NSRL: ${circlParsed?.data?.FileName || 'Verified'})`
            : 'البصمة غير مسجلة في القوائم الخبيثة المفتوحة',
          signature: detected ? `Malware Hash Match (${cymruPct}% AV)` : null,
          cymruDetectionPct: cymruPct,
          circlProduct: circlParsed?.data?.ProductName || null,
          tags: [],
          sourcesChecked: [
            {
              name: 'CIRCL Hashlookup (NSRL)',
              status: isKnownClean ? 'KNOWN LEGITIMATE' : 'Not in NSRL',
              detail: isKnownClean ? `ملف نظامي معروف: ${circlParsed?.data?.FileName || 'Verified'}` : 'غير مدرج ضمن القاعدة القياسية',
            },
            ...(md5ForCymru
              ? [
                  {
                    name: 'Team Cymru MHR (DoH)',
                    status: detected ? `DETECTED (${cymruPct}% AV)` : 'Clean / Unknown',
                    detail: detected ? `نسبة رصد مضادات الفيروسات: ${cymruPct}%` : 'غير مدرج في سجل التهديدات الخبيثة',
                  },
                ]
              : []),
          ],
          checkedAt: new Date().toISOString(),
        };
      }

      setLookupResult(resultData);
      const isMalicious = Boolean(resultData.detected);
      const risk: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض' = isMalicious
        ? 'حرج'
        : resultData.isKnownClean
        ? 'منخفض'
        : 'متوسط';
      onRecordAudit({
        id: 'malhash-' + Math.random().toString(36).slice(2, 9),
        fileName: `فحص فيروسات (Hash): ${opts?.fileName || cleanHash.slice(0, 18) + '...'}`,
        fileSize: opts?.fileSize ? formatBytes(opts.fileSize) : cleanHash.length === 64 ? 'SHA-256' : 'Hash Lookup',
        verdict: resultData.verdict,
        score: isMalicious ? 5 : resultData.isKnownClean ? 99 : 80,
        risk,
        sha256: cleanHash.length === 64 ? cleanHash : await digestHex('SHA-256', new TextEncoder().encode(cleanHash)),
      });
      onNotify(
        isMalicious
          ? `تحذير حرج: تم تطابق بصمة الملف مع برمجية خبيثة (${resultData.signature || 'Malware'})!`
          : `اكتمل فحص البصمة: ${resultData.verdict}`,
        isMalicious ? 'error' : 'success'
      );
    } catch (err: any) {
      setError(err?.message || 'تعذر تنفيذ فحص بصمة الملف.');
    } finally {
      setLoading(false);
    }
  };

  const handleFileSelected = async (file: File) => {
    setError(null);
    setLoading(true);
    try {
      const buffer = await file.arrayBuffer();
      const [sha256, sha1] = await Promise.all([
        digestHex('SHA-256', buffer),
        digestHex('SHA-1', buffer),
      ]);
      const md5 = SparkMD5.ArrayBuffer.hash(buffer).toLowerCase();
      const head = new Uint8Array(buffer.slice(0, 12));
      const magicHex = Array.from(head)
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(' ');

      setLocalFileHashes({
        fileName: file.name,
        fileSize: file.size,
        sha256,
        sha1,
        md5,
        magicHex,
      });
      setHashInput(sha256);
      await executeHashLookup(sha256, {
        md5,
        sha1,
        fileName: file.name,
        fileSize: file.size,
      });
    } catch (err: any) {
      setError(err?.message || 'تعذر قراءة الملف أو حساب البصمات.');
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="space-y-1 border-b border-gray-800 pb-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-[11px] font-mono">
            <Bug className="w-3.5 h-3.5" />
            REAL MALWARE HASH LOOKUP • ABUSE.CH MALWAREBAZAAR & THREATFOX
          </div>
          <h2 className="text-xl md:text-2xl font-bold text-white">
            فاحص بصمات الملفات ضد الفيروسات (Malware Hash Lookup)
          </h2>
          <p className="text-xs text-gray-400">
            حساب بصمة SHA-256 و SHA-1 و MD5 الحقيقية لأي ملف ترفعه محلياً ومطابقتها فوراً مع قاعدة بيانات MalwareBazaar (Abuse.ch) و ThreatFox و Team Cymru MHR و CIRCL NSRL.
          </p>
        </div>

        <label className="block border-2 border-dashed border-gray-700 hover:border-[#D4AF37] rounded-2xl p-6 text-center cursor-pointer transition bg-gray-950/60">
          <input
            type="file"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleFileSelected(f);
              e.target.value = '';
            }}
          />
          <Upload className="w-9 h-9 text-[#D4AF37] mx-auto mb-2" />
          <div className="text-sm font-bold text-white">
            {loading ? 'جاري حساب البصمات والفحص ضد قواعد الفيروسات...' : 'اضغط لرفع أي ملف لفحص بصمته الحقيقية دون رفع الملف للخادم'}
          </div>
          <div className="text-xs text-gray-400 mt-1">
            يتم إرسال بصمة التشفير (SHA-256 / MD5) فقط إلى واجهات استخبارات التهديدات بينما يبقى ملفك في جهازك.
          </div>
        </label>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void executeHashLookup(hashInput, localFileHashes ? {
              md5: localFileHashes.md5,
              sha1: localFileHashes.sha1,
              fileName: localFileHashes.fileName,
              fileSize: localFileHashes.fileSize,
            } : undefined);
          }}
          className="flex flex-col sm:flex-row gap-3"
        >
          <input
            type="text"
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            placeholder="أو الصق بصمة SHA-256 / SHA-1 / MD5 مباشرة للفحص..."
            className="flex-1 bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-3 text-xs sm:text-sm text-white font-mono outline-none"
            dir="ltr"
          />
          <button
            type="submit"
            disabled={loading || !hashInput.trim()}
            className="px-6 py-3 bg-[#D4AF37] hover:bg-[#c49f2c] disabled:opacity-50 text-gray-950 font-bold rounded-xl text-sm flex items-center justify-center gap-2 transition cursor-pointer shrink-0"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            <span>{loading ? 'جاري المطابقة...' : 'فحص البصمة الآن'}</span>
          </button>
        </form>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {localFileHashes && (
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <span className="text-sm font-bold text-[#D4AF37] flex items-center gap-2">
              <Hash className="w-4 h-4" />
              البصمات المشفرة المحسوبة من الملف: {localFileHashes.fileName}
            </span>
            <span className="text-xs font-mono text-gray-400">
              {formatBytes(localFileHashes.fileSize)} • Header: {localFileHashes.magicHex}
            </span>
          </div>
          <div className="grid grid-cols-1 gap-2 text-xs font-mono" dir="ltr">
            {[
              { label: 'SHA-256', val: localFileHashes.sha256 },
              { label: 'SHA-1', val: localFileHashes.sha1 },
              { label: 'MD5', val: localFileHashes.md5 },
            ].map((item) => (
              <div key={item.label} className="bg-gray-950 border border-gray-800 rounded-xl px-3 py-2 flex items-center justify-between gap-2">
                <div className="truncate">
                  <span className="text-[#D4AF37] mr-2 font-bold">{item.label}:</span>
                  <span className="text-gray-200">{item.val}</span>
                </div>
                <button
                  type="button"
                  onClick={() => copyText(item.val, item.label)}
                  className="text-gray-400 hover:text-white shrink-0 cursor-pointer"
                  title="نسخ البصمة"
                >
                  {copiedKey === item.label ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {lookupResult && (
        <div className="space-y-4">
          <div
            className={`rounded-2xl border p-6 flex flex-col md:flex-row md:items-center justify-between gap-4 ${
              lookupResult.detected
                ? 'bg-red-950/30 border-red-500/60'
                : lookupResult.isKnownClean
                ? 'bg-emerald-950/25 border-emerald-500/50'
                : 'bg-amber-950/20 border-amber-500/40'
            }`}
          >
            <div className="flex items-center gap-3">
              {lookupResult.detected ? (
                <ShieldAlert className="w-9 h-9 text-red-400 shrink-0" />
              ) : (
                <ShieldCheck className={`w-9 h-9 shrink-0 ${lookupResult.isKnownClean ? 'text-emerald-400' : 'text-amber-400'}`} />
              )}
              <div className="space-y-1">
                <h3 className="text-lg font-bold text-white">{lookupResult.verdict}</h3>
                <p className="text-xs font-mono text-gray-300 break-all" dir="ltr">
                  {lookupResult.hashType.toUpperCase()}: {lookupResult.hash}
                </p>
              </div>
            </div>
            {lookupResult.malwareBazaarUrl && (
              <a
                href={lookupResult.malwareBazaarUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 rounded-xl bg-red-500/20 border border-red-400/50 text-red-200 text-xs font-bold flex items-center gap-2 shrink-0 hover:bg-red-500/30"
              >
                <span>عرض تقرير MalwareBazaar</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </a>
            )}
          </div>

          {lookupResult.detected && (
            <div className="bg-gray-900 border border-red-500/30 rounded-2xl p-5 grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              <div><span className="text-gray-400">العائلة الخبيثة / التوقيع: </span><span className="text-red-300 font-bold font-mono">{lookupResult.signature || '—'}</span></div>
              <div><span className="text-gray-400">نوع الملف الفعلي: </span><span className="text-white font-mono">{lookupResult.fileType || '—'}</span></div>
              <div><span className="text-gray-400">أول رصد (First Seen): </span><span className="text-amber-300 font-mono">{lookupResult.firstSeen || '—'}</span></div>
              <div><span className="text-gray-400">طريقة التسليم: </span><span className="text-gray-200 font-mono">{lookupResult.deliveryMethod || '—'}</span></div>
              {Array.isArray(lookupResult.tags) && lookupResult.tags.length > 0 && (
                <div className="md:col-span-2 flex flex-wrap gap-1.5 items-center pt-1">
                  <span className="text-gray-400 ml-2">الوسوم (Tags):</span>
                  {lookupResult.tags.map((t: string) => (
                    <span key={t} className="px-2 py-0.5 rounded bg-red-500/15 border border-red-500/30 text-red-200 font-mono text-[11px]">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
            <h4 className="text-sm font-bold text-[#D4AF37]">نتائج المطابقة عبر محركات الاستخبارات الحية:</h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {(lookupResult.sourcesChecked || []).map((src: any, idx: number) => (
                <div key={idx} className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-bold text-white">{src.name}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        String(src.status).includes('MALICIOUS') || String(src.status).includes('DETECTED')
                          ? 'bg-red-500/20 text-red-300'
                          : String(src.status).includes('KNOWN')
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : 'bg-gray-800 text-gray-300'
                      }`}
                    >
                      {src.status}
                    </span>
                  </div>
                  <p className="text-xs text-gray-400">{src.detail}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 2. PDF & Document Forensics Lab (100% Real Binary + Flate + XMP + IoCs)
// ============================================================================
function decodePdfStringValue(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('<') && trimmed.endsWith('>')) {
    const hex = trimmed.slice(1, -1).replace(/\s+/g, '');
    if (hex.toUpperCase().startsWith('FEFF')) {
      let out = '';
      for (let i = 4; i + 3 < hex.length; i += 4) {
        const code = Number.parseInt(hex.slice(i, i + 4), 16);
        if (code > 0) out += String.fromCharCode(code);
      }
      return out;
    }
    let ascii = '';
    for (let i = 0; i + 1 < hex.length; i += 2) {
      const code = Number.parseInt(hex.slice(i, i + 2), 16);
      if (code >= 32) ascii += String.fromCharCode(code);
    }
    return ascii;
  }
  if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
    let inner = trimmed.slice(1, -1);
    if (inner.startsWith('\xFE\xFF') || inner.startsWith('\u00fe\u00ff')) {
      let out = '';
      for (let i = 2; i + 1 < inner.length; i += 2) {
        out += String.fromCharCode((inner.charCodeAt(i) << 8) | inner.charCodeAt(i + 1));
      }
      return out;
    }
    inner = inner
      .replace(/\\n/g, '\n')
      .replace(/\\r/g, '\r')
      .replace(/\\t/g, '\t')
      .replace(/\\\(/g, '(')
      .replace(/\\\)/g, ')')
      .replace(/\\\\/g, '\\')
      .replace(/\\([0-7]{1,3})/g, (_m, oct) => String.fromCharCode(Number.parseInt(oct, 8)));
    return inner;
  }
  return trimmed;
}

function formatPdfDate(val: string): string {
  const m = val.match(/D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?([+-Z].*)?/);
  if (!m) return val;
  const [, y, mo = '01', d = '01', h = '00', mi = '00', s = '00', tz = ''] = m;
  return `${y}-${mo}-${d} ${h}:${mi}:${s}${tz ? ` (${tz.replace(/'/g, '')})` : ''}`;
}

async function decompressPdfFlateStreams(bytes: Uint8Array, maxStreams = 60): Promise<string[]> {
  if (typeof DecompressionStream === 'undefined') return [];
  const latin1 = new TextDecoder('latin1').decode(bytes);
  const outputs: string[] = [];
  let cursor = 0;
  let scanned = 0;

  while (scanned < maxStreams) {
    const streamIdx = latin1.indexOf('stream', cursor);
    if (streamIdx === -1) break;
    let start = streamIdx + 6;
    if (latin1[start] === '\r' && latin1[start + 1] === '\n') start += 2;
    else if (latin1[start] === '\n' || latin1[start] === '\r') start += 1;

    const endIdx = latin1.indexOf('endstream', start);
    if (endIdx === -1) break;

    cursor = endIdx + 9;
    const headerContext = latin1.slice(Math.max(0, streamIdx - 260), streamIdx);
    if (!/\/FlateDecode/i.test(headerContext)) continue;

    let sliceEnd = endIdx;
    while (sliceEnd > start && (latin1[sliceEnd - 1] === '\n' || latin1[sliceEnd - 1] === '\r')) {
      sliceEnd--;
    }
    const compressed = bytes.slice(start, sliceEnd);
    if (compressed.length < 4 || compressed.length > 2 * 1024 * 1024) continue;
    scanned++;

    try {
      const ds = new DecompressionStream('deflate');
      const writer = ds.writable.getWriter();
      const copy = new Uint8Array(compressed.byteLength);
      copy.set(compressed);
      void writer.write(copy).then(() => writer.close()).catch(() => {});
      const decompressedBuf = await new Response(ds.readable).arrayBuffer();
      outputs.push(new TextDecoder('utf-8', { fatal: false }).decode(decompressedBuf).slice(0, 65536));
    } catch {
      // Ignore individual corrupt/non-standard deflate stream
    }
  }

  return outputs;
}

export const PdfDocumentForensicsLab: React.FC<DeepLabProps> = ({ onNotify, onRecordAudit }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pdfReport, setPdfReport] = useState<any | null>(null);

  const handlePdfUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    setPdfReport(null);

    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const [sha256, sha1] = await Promise.all([
        digestHex('SHA-256', buffer),
        digestHex('SHA-1', buffer),
      ]);
      const md5 = SparkMD5.ArrayBuffer.hash(buffer).toLowerCase();

      const rawText = new TextDecoder('latin1').decode(bytes);
      const headerOffset = rawText.indexOf('%PDF-');
      if (headerOffset === -1) {
        throw new Error('الملف المرفوع لا يحتوي على ترويسة PDF حقيقية (%PDF-). يرجى رفع ملف PDF فعلي.');
      }

      const versionMatch = rawText.slice(headerOffset, headerOffset + 20).match(/%PDF-(\d+\.\d+)/);
      const pdfVersion = versionMatch ? versionMatch[1] : 'غير محدد';
      const eofCount = (rawText.match(/%%EOF/g) || []).length;
      const pageCount = (rawText.match(/\/Type\s*\/Page\b(?!s)/g) || []).length;
      const objCount = (rawText.match(/\b\d+\s+\d+\s+obj\b/g) || []).length;

      // Decompress FlateDecode streams inside the browser
      const decompressedChunks = await decompressPdfFlateStreams(bytes);
      const combinedCorpus = `${rawText}\n${decompressedChunks.join('\n')}`;

      // Extract Info Dictionary Fields
      const extractInfoField = (field: string): string => {
        const regex = new RegExp(`\\/${field}\\s*(\\((?:\\\\.|[^\\\\)])*\\)|<[0-9A-Fa-f\\s]+>)`, 'm');
        const match = combinedCorpus.match(regex);
        return match?.[1] ? decodePdfStringValue(match[1]) : '';
      };

      const xmpMatch = (tag: string): string => {
        const rx = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
        const m = combinedCorpus.match(rx);
        if (!m?.[1]) return '';
        return m[1].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      };

      const title = extractInfoField('Title') || xmpMatch('dc:title');
      const author = extractInfoField('Author') || xmpMatch('dc:creator');
      const creator = extractInfoField('Creator') || xmpMatch('xmp:CreatorTool');
      const producer = extractInfoField('Producer') || xmpMatch('pdf:Producer');
      const subject = extractInfoField('Subject') || xmpMatch('dc:description');
      const keywords = extractInfoField('Keywords') || xmpMatch('pdf:Keywords');
      const creationDateRaw = extractInfoField('CreationDate') || xmpMatch('xmp:CreateDate');
      const modDateRaw = extractInfoField('ModDate') || xmpMatch('xmp:ModifyDate');

      // Extract URLs from /URI(...) and raw links
      const urlSet = new Set<string>();
      const uriActionRegex = /\/URI\s*\(((?:\\.|[^\\)])+)\)/g;
      let uriMatch: RegExpExecArray | null;
      while ((uriMatch = uriActionRegex.exec(combinedCorpus)) !== null) {
        const decoded = decodePdfStringValue(`(${uriMatch[1]})`).trim();
        if (decoded) urlSet.add(decoded);
      }
      const genericUrlRegex = /\b(?:https?|ftp|file|smb):\/\/[^\s<>"')\]\\]{4,240}/gi;
      const genericMatches = combinedCorpus.match(genericUrlRegex) || [];
      for (const u of genericMatches) {
        if (!/ns\.adobe\.com|w3\.org\/1999|purl\.org/i.test(u)) {
          urlSet.add(u.replace(/[),.;]+$/, ''));
        }
      }

      // Active Threats / Scripts / Embedded Actions Scan
      const suspiciousTokens: Array<{ token: string; count: number; severity: 'critical' | 'high' | 'medium'; description: string }> = [];
      const checks: Array<{ token: string; rx: RegExp; severity: 'critical' | 'high' | 'medium'; description: string }> = [
        { token: '/JavaScript | /JS', rx: /\/(?:JavaScript|JS)\b/g, severity: 'critical', description: 'أكواد JavaScript مدمجة قابلة للتنفيذ داخل قارئ PDF' },
        { token: '/Launch', rx: /\/Launch\b/g, severity: 'critical', description: 'أمر تشغيل برامج أو أوامر خارجية على نظام الضحية' },
        { token: '/OpenAction | /AA', rx: /\/(?:OpenAction|AA)\b/g, severity: 'high', description: 'إجراء تلقائي (Auto-Run) يتم تنفيذه فور فتح المستند' },
        { token: '/EmbeddedFile | /Filespec', rx: /\/(?:EmbeddedFile|Filespec)\b/g, severity: 'high', description: 'ملفات أو مرفقات مخفية مضمنة داخل بنية الـ PDF' },
        { token: '/SubmitForm | /GoToR', rx: /\/(?:SubmitForm|GoToR)\b/g, severity: 'high', description: 'محاولة إرسال بيانات نموذجية أو القفز لملفات شبكة بعيدة' },
        { token: '/AcroForm | /XFA', rx: /\/(?:AcroForm|XFA)\b/g, severity: 'medium', description: 'نماذج تفاعلية XML/AcroForm قد تستغل ثغرات المحرك' },
        { token: '/Encrypt', rx: /\/Encrypt\b/g, severity: 'medium', description: 'محتوى أو كائنات مشفرة بكلمة مرور/صلاحيات' },
        { token: '/ObjStm', rx: /\/ObjStm\b/g, severity: 'medium', description: 'تضمين كائنات داخل تيارات مضغوطة (Object Streams)' },
      ];

      for (const c of checks) {
        const matches = combinedCorpus.match(c.rx);
        if (matches && matches.length > 0) {
          suspiciousTokens.push({
            token: c.token,
            count: matches.length,
            severity: c.severity,
            description: c.description,
          });
        }
      }

      // Extract embedded JavaScript snippet previews if present
      const jsSnippets: string[] = [];
      const jsRx = /\/JS\s*\(((?:\\.|[^\\)]){4,600})\)/g;
      let jm: RegExpExecArray | null;
      while ((jm = jsRx.exec(combinedCorpus)) !== null && jsSnippets.length < 5) {
        jsSnippets.push(decodePdfStringValue(`(${jm[1]})`));
      }

      const criticalCount = suspiciousTokens.filter((t) => t.severity === 'critical').length;
      const highCount = suspiciousTokens.filter((t) => t.severity === 'high').length;
      const riskScore = Math.min(100, criticalCount * 35 + highCount * 20 + (headerOffset > 0 ? 25 : 0) + (eofCount > 2 ? 10 : 0));
      const riskLevel: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض' =
        riskScore >= 60 ? 'حرج' : riskScore >= 35 ? 'مرتفع' : riskScore >= 15 ? 'متوسط' : 'منخفض';

      const report = {
        fileName: file.name,
        fileSize: file.size,
        sha256,
        sha1,
        md5,
        pdfVersion,
        headerOffset,
        eofCount,
        pageCount: Math.max(1, pageCount),
        objCount,
        decompressedStreamsCount: decompressedChunks.length,
        metadata: {
          title: title || 'غير محدد',
          author: author || 'غير محدد',
          creator: creator || 'غير محدد',
          producer: producer || 'غير محدد',
          subject: subject || 'غير محدد',
          keywords: keywords || 'غير محدد',
          creationDate: creationDateRaw ? formatPdfDate(creationDateRaw) : 'غير محدد',
          modDate: modDateRaw ? formatPdfDate(modDateRaw) : 'غير محدد',
        },
        urls: Array.from(urlSet).slice(0, 80),
        suspiciousTokens,
        jsSnippets,
        riskScore,
        riskLevel,
        analyzedAt: new Date().toISOString(),
      };

      setPdfReport(report);
      onRecordAudit({
        id: 'pdf-' + Math.random().toString(36).slice(2, 9),
        fileName: `تحليل مستند PDF: ${file.name}`,
        fileSize: `${formatBytes(file.size)} • PDF v${pdfVersion}`,
        verdict:
          criticalCount > 0
            ? `خطر: رُصدت أكواد تنفيذية (${suspiciousTokens.map((t) => t.token).join(', ')})`
            : `سليم / منخفض الخطورة • ${report.urls.length} رابط • ${eofCount} مراجعة EOF`,
        score: Math.max(10, 100 - riskScore),
        risk: riskLevel,
        sha256,
      });
      onNotify(
        criticalCount > 0
          ? `تنبيه حرج: مستند ${file.name} يحتوي على أوامر JavaScript أو Launch مدمجة!`
          : `اكتمل فحص المستند (${file.name}): استخراج الميتاداتا و ${report.urls.length} رابطاً.`,
        criticalCount > 0 ? 'error' : 'success'
      );
    } catch (err: any) {
      setError(err?.message || 'تعذر قراءة أو تحليل المستند.');
    } finally {
      setLoading(false);
    }
  };

  const exportPdfJson = () => {
    if (!pdfReport) return;
    const blob = new Blob([JSON.stringify(pdfReport, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pdf_forensics_${pdfReport.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/30 text-[#D4AF37] text-[11px] font-mono">
              <FileText className="w-3.5 h-3.5" />
              LOCAL PDF BINARY & XMP FORENSICS • FLATEDECODE INSPECTOR
            </div>
            <h2 className="text-xl md:text-2xl font-bold text-white">
              محلل المستندات والملفات الوثائقية (PDF & Document Forensics)
            </h2>
            <p className="text-xs text-gray-400">
              قراءة البايتات الحقيقية وفك تيارات الضغط (FlateDecode) محلياً لاستخراج المؤلف، البرنامج المنشئ، تواريخ التعديل، عدد المراجعات (EOF)، وكشف الأكواد المدمجة (/JS، /Launch، /OpenAction) والروابط المخفية.
            </p>
          </div>
          {pdfReport && (
            <button
              type="button"
              onClick={exportPdfJson}
              className="px-4 py-2 rounded-xl bg-gray-950 border border-[#D4AF37]/40 text-[#D4AF37] text-xs font-bold flex items-center gap-2 hover:bg-gray-800 transition cursor-pointer shrink-0"
            >
              <Download className="w-4 h-4" />
              <span>تصدير التقرير JSON</span>
            </button>
          )}
        </div>

        <label className="block border-2 border-dashed border-gray-700 hover:border-[#D4AF37] rounded-2xl p-8 text-center cursor-pointer transition bg-gray-950/60">
          <input
            type="file"
            accept=".pdf,application/pdf"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handlePdfUpload(f);
              e.target.value = '';
            }}
          />
          <Upload className="w-10 h-10 text-[#D4AF37] mx-auto mb-3" />
          <div className="text-sm font-bold text-white">
            {loading ? 'جاري تفكيك الكائنات وتيارات FlateDecode واستخراج الميتاداتا...' : 'اضغط لرفع ملف PDF حقيقي للتحليل الجنائي'}
          </div>
          <div className="text-xs text-gray-400 mt-1">
            تحليل عميق فوري في متصفحك (Header, XMP, Info Dictionary, Incremental Revisions, Scripts & URIs).
          </div>
        </label>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {pdfReport && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">إصدار PDF والصفحات</div>
              <div className="text-xl font-bold font-mono text-white">v{pdfReport.pdfVersion}</div>
              <div className="text-[10px] text-gray-500">{pdfReport.pageCount} صفحة • {pdfReport.objCount} كائن</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">تعديلات المستند (EOF)</div>
              <div className={`text-xl font-bold font-mono ${pdfReport.eofCount > 1 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {pdfReport.eofCount}
              </div>
              <div className="text-[10px] text-gray-500">
                {pdfReport.eofCount > 1 ? 'يحتوي على تعديلات لاحقة (Incremental)' : 'نسخة واحدة أصلية'}
              </div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">الروابط المستخرجة</div>
              <div className="text-xl font-bold font-mono text-[#D4AF37]">{pdfReport.urls.length}</div>
              <div className="text-[10px] text-gray-500">فحص تيارات الضغط ({pdfReport.decompressedStreamsCount})</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">إشارات خطورة مدمجة</div>
              <div className={`text-xl font-bold font-mono ${pdfReport.suspiciousTokens.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {pdfReport.suspiciousTokens.length}
              </div>
              <div className="text-[10px] text-gray-500">JS / Launch / OpenAction</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">تقييم الخطورة</div>
              <div className={`text-xl font-bold ${pdfReport.riskLevel === 'حرج' || pdfReport.riskLevel === 'مرتفع' ? 'text-red-400' : 'text-emerald-400'}`}>
                {pdfReport.riskLevel} ({pdfReport.riskScore}%)
              </div>
              <div className="text-[10px] text-gray-500 font-mono truncate">{pdfReport.sha256.slice(0, 14)}...</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-2.5 text-xs">
              <h4 className="text-sm font-bold text-[#D4AF37] mb-2">البيانات الوصفية الحقيقية (PDF Info & XMP Metadata)</h4>
              <div className="flex justify-between gap-2"><span className="text-gray-400">العنوان (Title):</span><span className="text-white text-left">{pdfReport.metadata.title}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">المؤلف (Author):</span><span className="text-emerald-300 font-bold text-left">{pdfReport.metadata.author}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">برنامج الإنشاء (Creator):</span><span className="font-mono text-gray-200 text-left" dir="ltr">{pdfReport.metadata.creator}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">محرك الإنتاج (Producer):</span><span className="font-mono text-amber-300 text-left" dir="ltr">{pdfReport.metadata.producer}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">تاريخ الإنشاء:</span><span className="font-mono text-gray-200" dir="ltr">{pdfReport.metadata.creationDate}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">تاريخ آخر تعديل:</span><span className="font-mono text-amber-300" dir="ltr">{pdfReport.metadata.modDate}</span></div>
              <div className="flex justify-between gap-2"><span className="text-gray-400">إزاحة الترويسة (Polyglot Check):</span><span className="font-mono text-gray-300">{pdfReport.headerOffset === 0 ? 'Offset 0 (سليم)' : `تحذير: Offset ${pdfReport.headerOffset} بايت قبل %PDF-`}</span></div>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
              <h4 className="text-sm font-bold text-[#D4AF37]">الأوامر والهياكل النشطة المكتشفة (Active Threats & Objects)</h4>
              {pdfReport.suspiciousTokens.length === 0 ? (
                <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 shrink-0" />
                  <span>لم يتم العثور على أوامر /JavaScript أو /Launch أو مرفقات تنفيذية مدمجة داخل هذا الـ PDF.</span>
                </div>
              ) : (
                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {pdfReport.suspiciousTokens.map((item: any, idx: number) => (
                    <div
                      key={idx}
                      className={`p-3 rounded-xl border text-xs space-y-1 ${
                        item.severity === 'critical'
                          ? 'bg-red-950/30 border-red-500/40 text-red-200'
                          : item.severity === 'high'
                          ? 'bg-amber-950/25 border-amber-500/40 text-amber-200'
                          : 'bg-gray-950 border-gray-800 text-gray-200'
                      }`}
                    >
                      <div className="flex items-center justify-between font-mono font-bold">
                        <span>{item.token}</span>
                        <span>التكرار: {item.count}</span>
                      </div>
                      <div className="text-[11px] opacity-90">{item.description}</div>
                    </div>
                  ))}
                </div>
              )}

              {pdfReport.jsSnippets?.length > 0 && (
                <div className="space-y-1 pt-2">
                  <div className="text-xs font-bold text-red-300 flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5" />
                    <span>مقتطف من كود JavaScript المستخرج:</span>
                  </div>
                  <pre className="p-2.5 rounded-lg bg-gray-950 border border-red-500/30 text-[11px] font-mono text-red-200 overflow-x-auto max-h-32" dir="ltr">
                    {pdfReport.jsSnippets.join('\n---\n')}
                  </pre>
                </div>
              )}
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
            <h4 className="text-sm font-bold text-[#D4AF37]">الروابط وعناوين الـ URI المدمجة داخل المستند ({pdfReport.urls.length}):</h4>
            {pdfReport.urls.length === 0 ? (
              <p className="text-xs text-gray-400">لا توجد روابط خارجية أو إجراءات /URI مدمجة داخل المستند.</p>
            ) : (
              <div className="max-h-56 overflow-y-auto space-y-1.5" dir="ltr">
                {pdfReport.urls.map((u: string, i: number) => (
                  <div key={i} className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-xs font-mono text-gray-200 break-all flex items-center justify-between gap-2">
                    <span>{u}</span>
                    {/^https?:\/\//i.test(u) && (
                      <a href={u} target="_blank" rel="noopener noreferrer" className="text-[#D4AF37] hover:underline shrink-0">
                        <ExternalLink className="w-3.5 h-3.5" />
                      </a>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 3. URL Redirect Tracer Lab (Real Hop-by-Hop Server Trace)
// ============================================================================
export const UrlRedirectTracerLab: React.FC<DeepLabProps> = ({ onNotify, onRecordAudit }) => {
  const [urlInput, setUrlInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [traceResult, setTraceResult] = useState<any | null>(null);

  const traceUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    const raw = urlInput.trim();
    if (!raw || loading) return;
    setLoading(true);
    setError(null);
    setTraceResult(null);

    try {
      const res = await fetch(apiUrl('/api/url-trace'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: raw }),
      });
      const parsed = await safeReadJsonResponse(res);
      if (!res.ok || !parsed.isJson || !parsed.data?.trace) {
        throw new Error(parsed.data?.error || 'تعذر الاتصال بخدمة تتبع الروابط الحيّة.');
      }

      const trace = parsed.data.trace;
      setTraceResult(trace);
      const hash = await digestHex('SHA-256', new TextEncoder().encode(trace.finalUrl));
      const risk: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض' =
        trace.hasHttpsDowngrade || trace.isIpLiteralFinal
          ? 'مرتفع'
          : trace.changedDomain || trace.redirectCount >= 2
          ? 'متوسط'
          : 'منخفض';

      onRecordAudit({
        id: 'trace-' + Math.random().toString(36).slice(2, 9),
        fileName: `تتبع رابط: ${trace.initialDomain} → ${trace.finalDomain}`,
        fileSize: `${trace.redirectCount} تحويلات • ${trace.totalLatencyMs}ms`,
        verdict: `الوجهة النهائية: ${trace.finalUrl}`,
        score: trace.hasHttpsDowngrade ? 45 : trace.changedDomain ? 78 : 95,
        risk,
        sha256: hash,
      });

      onNotify(
        `اكتمل تتبع الرابط (${trace.redirectCount} تحويلات) ← الوجهة النهائية: ${trace.finalDomain}`,
        trace.hasHttpsDowngrade ? 'warning' : 'success'
      );
    } catch (err: any) {
      setError(err?.message || 'تعذر تتبع مسار التحويلات للرابط المدخل.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="space-y-1 border-b border-gray-800 pb-4">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-300 text-[11px] font-mono">
            <Route className="w-3.5 h-3.5" />
            LIVE HTTP/META/JS REDIRECT TRACER • SSRF PROTECTED
          </div>
          <h2 className="text-xl md:text-2xl font-bold text-white">
            متتبع الروابط المختصرة ومسار التحويلات (URL Redirect Tracer)
          </h2>
          <p className="text-xs text-gray-400">
            تتبع حقيقي خطوة بخطوة لكل قفزات التوجيه (HTTP 301/302/307/308، Meta Refresh، و JS Redirects) لكشف الوجهة النهائية، النطاق المستهدف، عنوان الـ IP، وأي خفض للتشفير (HTTPS → HTTP) دون تنفيذ الرابط في متصفحك.
          </p>
        </div>

        <form onSubmit={traceUrl} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={urlInput}
            onChange={(e) => setUrlInput(e.target.value)}
            placeholder="أدخل الرابط المختصر أو المشبوه (مثال: https://bit.ly/... أو https://t.co/...)"
            className="flex-1 bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-3 text-sm text-white font-mono outline-none"
            dir="ltr"
          />
          <button
            type="submit"
            disabled={loading || !urlInput.trim()}
            className="px-6 py-3 bg-[#D4AF37] hover:bg-[#c49f2c] disabled:opacity-50 text-gray-950 font-bold rounded-xl text-sm flex items-center justify-center gap-2 transition cursor-pointer shrink-0"
          >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Route className="w-4 h-4" />}
            <span>{loading ? 'جاري تتبع المسار...' : 'كشف الوجهة النهائية'}</span>
          </button>
        </form>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {traceResult && (
        <div className="space-y-4">
          <div
            className={`rounded-2xl border p-6 space-y-3 ${
              traceResult.hasHttpsDowngrade || traceResult.isIpLiteralFinal
                ? 'bg-red-950/25 border-red-500/50'
                : 'bg-emerald-950/20 border-emerald-500/40'
            }`}
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="flex items-center gap-3 min-w-0">
                <Link2 className="w-7 h-7 text-[#D4AF37] shrink-0" />
                <div className="min-w-0">
                  <div className="text-xs text-gray-400">الوجهة النهائية الحقيقية المكتشفة:</div>
                  <div className="text-sm sm:text-base font-bold font-mono text-white break-all" dir="ltr">
                    {traceResult.finalUrl}
                  </div>
                </div>
              </div>
              <div className="flex flex-wrap gap-2 text-xs font-mono shrink-0">
                <span className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-[#D4AF37]">
                  Hops: {traceResult.totalHops} ({traceResult.redirectCount} redirects)
                </span>
                <span className="px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 text-emerald-300">
                  IP: {traceResult.finalIp}
                </span>
              </div>
            </div>

            <div className="flex flex-wrap gap-2 text-[11px]">
              {traceResult.changedDomain && (
                <span className="px-2.5 py-1 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300">
                  تحويل عابر للنطاقات ({traceResult.initialDomain} → {traceResult.finalDomain})
                </span>
              )}
              {traceResult.shortenerDetected && (
                <span className="px-2.5 py-1 rounded-lg bg-blue-500/15 border border-blue-500/30 text-blue-300">
                  خدمة اختصار روابط مرصودة
                </span>
              )}
              {traceResult.hasHttpsDowngrade && (
                <span className="px-2.5 py-1 rounded-lg bg-red-500/20 border border-red-500/40 text-red-300">
                  تحذير: الرابط النهائي أو أحد التحويلات يستخدم HTTP غير المشفر!
                </span>
              )}
              {traceResult.trackingParams?.length > 0 && (
                <span className="px-2.5 py-1 rounded-lg bg-gray-900 border border-gray-700 text-gray-300 font-mono">
                  معاملات تتبع: {traceResult.trackingParams.join(', ')}
                </span>
              )}
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
            <h4 className="text-sm font-bold text-[#D4AF37]">سلسلة القفزات والتحويلات خطوة بخطوة ({traceResult.hops.length}):</h4>
            <div className="space-y-3">
              {traceResult.hops.map((hop: any, idx: number) => (
                <React.Fragment key={hop.step}>
                  <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-2" dir="ltr">
                    <div className="flex items-center justify-between flex-wrap gap-2 text-xs font-mono">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-[#D4AF37]/20 text-[#D4AF37] font-bold">
                          HOP #{hop.step}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded font-bold ${
                            hop.status >= 300 && hop.status < 400
                              ? 'bg-amber-500/20 text-amber-300'
                              : hop.status >= 200 && hop.status < 300
                              ? 'bg-emerald-500/20 text-emerald-300'
                              : 'bg-red-500/20 text-red-300'
                          }`}
                        >
                          HTTP {hop.status}
                        </span>
                        <span className="text-gray-400">{hop.redirectType}</span>
                      </div>
                      <div className="flex items-center gap-3 text-[11px] text-gray-400">
                        <span className="flex items-center gap-1">
                          {hop.protocol === 'https:' ? <Lock className="w-3 h-3 text-emerald-400" /> : <Unlock className="w-3 h-3 text-red-400" />}
                          {hop.resolvedIp}
                        </span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {hop.latencyMs}ms
                        </span>
                      </div>
                    </div>
                    <div className="text-xs font-mono text-white break-all">{hop.url}</div>
                    <div className="text-[11px] font-mono text-gray-500">
                      Server: {hop.serverHeader}
                      {hop.locationHeader ? ` • Target → ${hop.locationHeader}` : ''}
                    </div>
                  </div>
                  {idx < traceResult.hops.length - 1 && (
                    <div className="flex justify-center">
                      <ArrowDown className="w-4 h-4 text-[#D4AF37]" />
                    </div>
                  )}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ============================================================================
// 4. Steganography LSB Inspector Lab (Canvas Pixel Bitplane + EOF Scanner)
// ============================================================================
type LsbExtractionMode = 'rgb' | 'red' | 'green' | 'blue' | 'alpha';

function extractLsbBytes(
  rgba: Uint8ClampedArray,
  mode: LsbExtractionMode,
  bitOrder: 'msb' | 'lsb',
  maxBytes = 32768
): { bytes: Uint8Array; totalBits: number; onesCount: number; firstQuarterOnesRatio: number; restOnesRatio: number } {
  const bytesOut: number[] = [];
  let currentByte = 0;
  let bitIdx = 0;
  let totalBits = 0;
  let onesCount = 0;
  const quarterSplit = Math.floor((rgba.length / 4) * 0.25);
  let firstQuarterBits = 0;
  let firstQuarterOnes = 0;
  let restBits = 0;
  let restOnes = 0;

  const pushBit = (bit: number, pixelIndex: number) => {
    totalBits++;
    if (bit === 1) onesCount++;
    if (pixelIndex < quarterSplit) {
      firstQuarterBits++;
      if (bit === 1) firstQuarterOnes++;
    } else {
      restBits++;
      if (bit === 1) restOnes++;
    }

    if (bytesOut.length < maxBytes) {
      if (bitOrder === 'msb') {
        currentByte = (currentByte << 1) | bit;
      } else {
        currentByte = currentByte | (bit << bitIdx);
      }
      bitIdx++;
      if (bitIdx === 8) {
        bytesOut.push(currentByte);
        currentByte = 0;
        bitIdx = 0;
      }
    }
  };

  const totalPixels = rgba.length / 4;
  for (let p = 0; p < totalPixels; p++) {
    const base = p * 4;
    if (mode === 'rgb') {
      pushBit(rgba[base] & 1, p);
      pushBit(rgba[base + 1] & 1, p);
      pushBit(rgba[base + 2] & 1, p);
    } else if (mode === 'red') {
      pushBit(rgba[base] & 1, p);
    } else if (mode === 'green') {
      pushBit(rgba[base + 1] & 1, p);
    } else if (mode === 'blue') {
      pushBit(rgba[base + 2] & 1, p);
    } else {
      pushBit(rgba[base + 3] & 1, p);
    }
  }

  return {
    bytes: new Uint8Array(bytesOut),
    totalBits,
    onesCount,
    firstQuarterOnesRatio: firstQuarterBits ? firstQuarterOnes / firstQuarterBits : 0.5,
    restOnesRatio: restBits ? restOnes / restBits : 0.5,
  };
}

function findPrintableStrings(bytes: Uint8Array, minLen = 6): string[] {
  const strings: string[] = [];
  let buf = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if ((b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9) {
      buf += String.fromCharCode(b);
    } else {
      if (buf.trim().length >= minLen) {
        strings.push(buf.trim());
        if (strings.length >= 30) break;
      }
      buf = '';
    }
  }
  if (buf.trim().length >= minLen && strings.length < 30) {
    strings.push(buf.trim());
  }
  return strings;
}

function detectMagicPayload(bytes: Uint8Array): string | null {
  if (bytes.length < 4) return null;
  if (bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) return 'ZIP / Office / APK Archive (PK)';
  if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'PDF Document (%PDF)';
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return 'Nested PNG Image';
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) return 'Windows Executable (PE/MZ)';
  return null;
}

function detectTrailingEofData(rawBytes: Uint8Array): { found: boolean; format: string; trailingBytes: number; magic: string | null; previewText: string; hexHead: string } {
  // Check PNG IEND chunk: 49 45 4E 44 AE 42 60 82
  if (rawBytes.length > 8 && rawBytes[0] === 0x89 && rawBytes[1] === 0x50 && rawBytes[2] === 0x4e && rawBytes[3] === 0x47) {
    for (let i = 8; i <= rawBytes.length - 8; i++) {
      if (
        rawBytes[i] === 0x49 &&
        rawBytes[i + 1] === 0x45 &&
        rawBytes[i + 2] === 0x4e &&
        rawBytes[i + 3] === 0x44 &&
        rawBytes[i + 4] === 0xae &&
        rawBytes[i + 5] === 0x42 &&
        rawBytes[i + 6] === 0x60 &&
        rawBytes[i + 7] === 0x82
      ) {
        const trailingStart = i + 8;
        const trailingBytes = rawBytes.length - trailingStart;
        if (trailingBytes > 0) {
          const slice = rawBytes.slice(trailingStart, trailingStart + 4096);
          return {
            found: true,
            format: 'PNG (Trailing after IEND)',
            trailingBytes,
            magic: detectMagicPayload(slice),
            previewText: new TextDecoder('utf-8', { fatal: false }).decode(slice.slice(0, 800)),
            hexHead: Array.from(slice.slice(0, 64)).map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(' '),
          };
        }
        break;
      }
    }
  }

  // Check JPEG EOI marker FF D9 from end backwards
  if (rawBytes.length > 4 && rawBytes[0] === 0xff && rawBytes[1] === 0xd8) {
    for (let i = rawBytes.length - 2; i >= 2; i--) {
      if (rawBytes[i] === 0xff && rawBytes[i + 1] === 0xd9) {
        const trailingStart = i + 2;
        const trailingBytes = rawBytes.length - trailingStart;
        if (trailingBytes > 16) {
          const slice = rawBytes.slice(trailingStart, trailingStart + 4096);
          return {
            found: true,
            format: 'JPEG (Trailing after EOI FF D9)',
            trailingBytes,
            magic: detectMagicPayload(slice),
            previewText: new TextDecoder('utf-8', { fatal: false }).decode(slice.slice(0, 800)),
            hexHead: Array.from(slice.slice(0, 64)).map((b) => b.toString(16).padStart(2, '0').toUpperCase()).join(' '),
          };
        }
        break;
      }
    }
  }

  return { found: false, format: 'None', trailingBytes: 0, magic: null, previewText: '', hexHead: '' };
}

export const StegLsbInspectorLab: React.FC<DeepLabProps> = ({ onNotify, onRecordAudit }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mode, setMode] = useState<LsbExtractionMode>('rgb');
  const [bitOrder, setBitOrder] = useState<'msb' | 'lsb'>('msb');
  const [pixelState, setPixelState] = useState<{
    fileName: string;
    fileSize: number;
    sha256: string;
    width: number;
    height: number;
    rgba: Uint8ClampedArray;
    imageUrl: string;
    eofInfo: ReturnType<typeof detectTrailingEofData>;
  } | null>(null);

  const lsbCanvasRef = useRef<HTMLCanvasElement | null>(null);

  const lsbAnalysis = useMemo(() => {
    if (!pixelState) return null;
    const extracted = extractLsbBytes(pixelState.rgba, mode, bitOrder);
    const printableRuns = findPrintableStrings(extracted.bytes, 6);
    const lsbMagic = detectMagicPayload(extracted.bytes);
    const onesPercent = extracted.totalBits ? (extracted.onesCount / extracted.totalBits) * 100 : 50;
    const spatialSkew = Math.abs(extracted.firstQuarterOnesRatio - extracted.restOnesRatio) * 100;
    const hasAlphaAnomaly = (() => {
      let nonOpaque = 0;
      let maxDiff = 0;
      for (let i = 3; i < pixelState.rgba.length; i += 4) {
        if (pixelState.rgba[i] < 255) {
          nonOpaque++;
          maxDiff = Math.max(maxDiff, 255 - pixelState.rgba[i]);
        }
      }
      return { nonOpaque, subtleAlphaSteg: nonOpaque > 0 && maxDiff <= 3 };
    })();

    const decodedLeadText = new TextDecoder('utf-8', { fatal: false })
      .decode(extracted.bytes.slice(0, 600))
      .replace(/[^\x20-\x7E\n\r\t\u0600-\u06FF]/g, '.');

    const hexHead = Array.from(extracted.bytes.slice(0, 64))
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ');

    return {
      ...extracted,
      onesPercent,
      spatialSkew,
      printableRuns,
      lsbMagic,
      hasAlphaAnomaly,
      decodedLeadText,
      hexHead,
    };
  }, [pixelState, mode, bitOrder]);

  // Render live amplified LSB Bitplane 0 visualization onto HTML5 Canvas
  useEffect(() => {
    if (!pixelState || !lsbCanvasRef.current) return;
    const canvas = lsbCanvasRef.current;
    canvas.width = pixelState.width;
    canvas.height = pixelState.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const outImg = ctx.createImageData(pixelState.width, pixelState.height);
    const src = pixelState.rgba;
    const dst = outImg.data;
    for (let i = 0; i < src.length; i += 4) {
      if (mode === 'rgb') {
        dst[i] = (src[i] & 1) * 255;
        dst[i + 1] = (src[i + 1] & 1) * 255;
        dst[i + 2] = (src[i + 2] & 1) * 255;
      } else if (mode === 'red') {
        const v = (src[i] & 1) * 255;
        dst[i] = v;
        dst[i + 1] = 0;
        dst[i + 2] = 0;
      } else if (mode === 'green') {
        const v = (src[i + 1] & 1) * 255;
        dst[i] = 0;
        dst[i + 1] = v;
        dst[i + 2] = 0;
      } else if (mode === 'blue') {
        const v = (src[i + 2] & 1) * 255;
        dst[i] = 0;
        dst[i + 1] = 0;
        dst[i + 2] = v;
      } else {
        const v = (src[i + 3] & 1) * 255;
        dst[i] = v;
        dst[i + 1] = v;
        dst[i + 2] = v;
      }
      dst[i + 3] = 255;
    }
    ctx.putImageData(outImg, 0, 0);
  }, [pixelState, mode]);

  const handleImageUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    if (pixelState?.imageUrl) {
      URL.revokeObjectURL(pixelState.imageUrl);
    }
    setPixelState(null);

    try {
      const buffer = await file.arrayBuffer();
      const rawBytes = new Uint8Array(buffer);
      const sha256 = await digestHex('SHA-256', buffer);
      const eofInfo = detectTrailingEofData(rawBytes);

      const imageUrl = URL.createObjectURL(file);
      const img = await new Promise<HTMLImageElement>((resolve, reject) => {
        const el = new Image();
        el.onload = () => resolve(el);
        el.onerror = () => reject(new Error('تعذر فك تشفير الصورة في المتصفح. تأكد من صحة ملف الصورة (PNG/BMP/JPG/WebP).'));
        el.src = imageUrl;
      });

      const canvas = document.createElement('canvas');
      canvas.width = img.naturalWidth || img.width;
      canvas.height = img.naturalHeight || img.height;
      const ctx = canvas.getContext('2d');
      if (!ctx) throw new Error('تعذر تهيئة محرك Canvas لتحليل البكسلات.');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      const initialLsb = extractLsbBytes(imageData.data, 'rgb', 'msb');
      const initialRuns = findPrintableStrings(initialLsb.bytes, 7);
      const initialMagic = detectMagicPayload(initialLsb.bytes);
      const skew = Math.abs(initialLsb.firstQuarterOnesRatio - initialLsb.restOnesRatio) * 100;

      setPixelState({
        fileName: file.name,
        fileSize: file.size,
        sha256,
        width: canvas.width,
        height: canvas.height,
        rgba: imageData.data,
        imageUrl,
        eofInfo,
      });

      const strongAnomaly = Boolean(eofInfo.found || initialMagic || skew > 8 || initialRuns.some((r) => r.length >= 14));
      onRecordAudit({
        id: 'steg-' + Math.random().toString(36).slice(2, 9),
        fileName: `فحص Steganography LSB: ${file.name}`,
        fileSize: `${canvas.width}×${canvas.height} px • ${formatBytes(file.size)}`,
        verdict: eofInfo.found
          ? `رصد بيانات محقونة بعد نهاية الملف (${eofInfo.trailingBytes} بايت)`
          : strongAnomaly
          ? `شذوذ أو نصوص في مصفوفة LSB (${initialRuns.length} سلاسل مقروءة)`
          : `فحص مصفوفة LSB مكتمل (${canvas.width * canvas.height} بكسل)`,
        score: eofInfo.found ? 20 : strongAnomaly ? 45 : 92,
        risk: eofInfo.found ? 'حرج' : strongAnomaly ? 'مرتفع' : 'منخفض',
        sha256,
      });
      onNotify(
        eofInfo.found
          ? `تنبيه: تم اكتشاف ${eofInfo.trailingBytes} بايت مخفية بعد نهاية ملف الصورة!`
          : `تم استخراج مصفوفة LSB (${canvas.width}×${canvas.height} بكسل) لـ ${file.name}.`,
        eofInfo.found || strongAnomaly ? 'warning' : 'success'
      );
    } catch (err: any) {
      setError(err?.message || 'فشل تحليل البكسلات عبر HTML5 Canvas.');
    } finally {
      setLoading(false);
    }
  };

  const downloadExtractedLsb = () => {
    if (!lsbAnalysis || !pixelState) return;
    const copy = new Uint8Array(lsbAnalysis.bytes.byteLength);
    copy.set(lsbAnalysis.bytes);
    const blob = new Blob([copy.buffer], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `lsb_${mode}_${bitOrder}_${pixelState.fileName}.bin`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 animate-fadeIn">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-4">
          <div className="space-y-1">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/10 border border-purple-500/30 text-purple-300 text-[11px] font-mono">
              <ScanEye className="w-3.5 h-3.5" />
              HTML5 CANVAS PIXEL MATRIX • LSB BITPLANE & EOF STEGANOGRAPHY
            </div>
            <h2 className="text-xl md:text-2xl font-bold text-white">
              كاشف البيانات المخفية في الصور (Steganography LSB Inspector)
            </h2>
            <p className="text-xs text-gray-400">
              تحليل فعلي لمصفوفة البكسلات (R,G,B,A) عبر HTML5 Canvas واستخراج البت الأقل أهمية (Least Significant Bit) بوضعي MSB/LSB، مع توليد خريطة التشتت البصرية وكشف البيانات المحقونة بعد علامة نهاية الملف (PNG IEND / JPEG EOI).
            </p>
          </div>
          {lsbAnalysis && (
            <button
              type="button"
              onClick={downloadExtractedLsb}
              className="px-4 py-2 rounded-xl bg-gray-950 border border-[#D4AF37]/40 text-[#D4AF37] text-xs font-bold flex items-center gap-2 hover:bg-gray-800 transition cursor-pointer shrink-0"
            >
              <Download className="w-4 h-4" />
              <span>تصدير بايتات LSB الخام</span>
            </button>
          )}
        </div>

        <label className="block border-2 border-dashed border-gray-700 hover:border-[#D4AF37] rounded-2xl p-8 text-center cursor-pointer transition bg-gray-950/60">
          <input
            type="file"
            accept="image/*"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleImageUpload(f);
              e.target.value = '';
            }}
          />
          <Upload className="w-10 h-10 text-[#D4AF37] mx-auto mb-3" />
          <div className="text-sm font-bold text-white">
            {loading ? 'جاري قراءة مصفوفة البكسلات وحساب مستويات البت...' : 'اضغط لرفع صورة (PNG / BMP / WebP / JPG) لفحص الإخفاء'}
          </div>
          <div className="text-xs text-gray-400 mt-1">
            ملاحظة جنائية: صيغ PNG و BMP تحافظ على بيانات LSB بدقة بينما يكشف الفحص أيضاً أي ملفات مدمجة بعد نهاية الـ JPEG.
          </div>
        </label>

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {pixelState && lsbAnalysis && (
        <div className="space-y-4">
          {/* Controls for LSB Bitplane Channel & Bit Order */}
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-wrap gap-2 items-center">
              <span className="text-xs font-bold text-gray-300 ml-1">قناة الفحص (Bitplane 0):</span>
              {(
                [
                  { id: 'rgb', label: 'RGB مدمج' },
                  { id: 'red', label: 'الأحمر (R)' },
                  { id: 'green', label: 'الأخضر (G)' },
                  { id: 'blue', label: 'الأزرق (B)' },
                  { id: 'alpha', label: 'الشفافية (Alpha)' },
                ] as const
              ).map((ch) => (
                <button
                  key={ch.id}
                  type="button"
                  onClick={() => setMode(ch.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer ${
                    mode === ch.id ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                  }`}
                >
                  {ch.label}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2 bg-gray-950 p-1 rounded-xl border border-gray-800">
              <button
                type="button"
                onClick={() => setBitOrder('msb')}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold cursor-pointer ${
                  bitOrder === 'msb' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400'
                }`}
              >
                MSB-first
              </button>
              <button
                type="button"
                onClick={() => setBitOrder('lsb')}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold cursor-pointer ${
                  bitOrder === 'lsb' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400'
                }`}
              >
                LSB-first
              </button>
            </div>
          </div>

          {/* Metrics Row */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">أبعاد الصورة والبكسلات</div>
              <div className="text-lg font-bold font-mono text-white">{pixelState.width} × {pixelState.height}</div>
              <div className="text-[10px] text-gray-500">{(pixelState.width * pixelState.height).toLocaleString('en-US')} بكسل</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">نسبة البت (1) في LSB</div>
              <div className="text-lg font-bold font-mono text-[#D4AF37]">{lsbAnalysis.onesPercent.toFixed(2)}%</div>
              <div className="text-[10px] text-gray-500">تباين الربع الأول: {lsbAnalysis.spatialSkew.toFixed(2)}%</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">نصوص قابلة للقراءة (LSB)</div>
              <div className={`text-lg font-bold font-mono ${lsbAnalysis.printableRuns.length > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                {lsbAnalysis.printableRuns.length}
              </div>
              <div className="text-[10px] text-gray-500">{lsbAnalysis.lsbMagic || 'توقيع: نصي / خام'}</div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
              <div className="text-[11px] text-gray-400">بيانات بعد نهاية الملف (EOF)</div>
              <div className={`text-lg font-bold font-mono ${pixelState.eofInfo.found ? 'text-red-400' : 'text-emerald-400'}`}>
                {pixelState.eofInfo.found ? `${pixelState.eofInfo.trailingBytes} B` : '0 بايت'}
              </div>
              <div className="text-[10px] text-gray-500">{pixelState.eofInfo.found ? pixelState.eofInfo.format : 'سليم بدون ذيل محقون'}</div>
            </div>
          </div>

          {pixelState.eofInfo.found && (
            <div className="bg-red-950/30 border border-red-500/50 rounded-2xl p-5 space-y-3">
              <div className="flex items-center gap-2 text-red-300 font-bold text-sm">
                <ShieldAlert className="w-5 h-5" />
                <span>تنبيه حرج: رُصدت بيانات محقونة بعد نهاية الصورة ({pixelState.eofInfo.trailingBytes} بايت — {pixelState.eofInfo.format})</span>
              </div>
              {pixelState.eofInfo.magic && (
                <div className="text-xs font-mono text-amber-300">النوع المكتشف داخل الذيل: {pixelState.eofInfo.magic}</div>
              )}
              <pre className="p-3 rounded-xl bg-gray-950 border border-red-500/30 text-[11px] font-mono text-gray-200 whitespace-pre-wrap break-all max-h-40 overflow-y-auto" dir="ltr">
                {pixelState.eofInfo.previewText}
              </pre>
            </div>
          )}

          {/* Side-by-Side Original vs Live LSB Bitplane Map */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-2">
              <div className="text-xs font-bold text-gray-300 flex items-center justify-between">
                <span>الصورة الأصلية المرفوعة</span>
                <span className="font-mono text-[10px] text-gray-500">{pixelState.fileName}</span>
              </div>
              <div className="bg-gray-950 rounded-xl border border-gray-800 p-2 flex items-center justify-center max-h-72 overflow-hidden">
                <img src={pixelState.imageUrl} alt={pixelState.fileName} className="max-h-64 object-contain rounded" />
              </div>
            </div>
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-2">
              <div className="text-xs font-bold text-[#D4AF37] flex items-center justify-between">
                <span className="flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5" />
                  خريطة Bitplane 0 المضخمة (LSB Visual Noise Map)
                </span>
                <span className="font-mono text-[10px] text-gray-400">({mode.toUpperCase()} & 1) × 255</span>
              </div>
              <div className="bg-gray-950 rounded-xl border border-gray-800 p-2 flex items-center justify-center max-h-72 overflow-hidden">
                <canvas ref={lsbCanvasRef} className="max-h-64 max-w-full object-contain rounded" />
              </div>
            </div>
          </div>

          {/* Extracted LSB Bitstream & Printable Strings */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
              <h4 className="text-sm font-bold text-[#D4AF37]">النصوص المقروءة المستخلصة من مصفوفة LSB ({lsbAnalysis.printableRuns.length}):</h4>
              {lsbAnalysis.printableRuns.length === 0 ? (
                <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 text-xs text-gray-400 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>لم يتم العثور على سلاسل نصية واضحة (6 أحرف فأكثر) في نمط {mode.toUpperCase()} / {bitOrder.toUpperCase()}.</span>
                </div>
              ) : (
                <div className="max-h-52 overflow-y-auto space-y-1.5" dir="ltr">
                  {lsbAnalysis.printableRuns.map((s, idx) => (
                    <div key={idx} className="bg-gray-950 border border-amber-500/30 rounded-lg px-3 py-1.5 text-xs font-mono text-amber-200 break-all">
                      {s}
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-3">
              <h4 className="text-sm font-bold text-[#D4AF37]">مقتطف البايتات الأولى المستخرجة من البكسلات:</h4>
              <div className="text-[11px] font-mono text-amber-300 bg-gray-950 border border-gray-800 rounded-lg p-2.5 overflow-x-auto" dir="ltr">
                HEX: {lsbAnalysis.hexHead}
              </div>
              <pre className="p-3 rounded-xl bg-gray-950 border border-gray-800 text-[11px] font-mono text-gray-200 whitespace-pre-wrap break-all max-h-36 overflow-y-auto" dir="ltr">
                {lsbAnalysis.decodedLeadText}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
