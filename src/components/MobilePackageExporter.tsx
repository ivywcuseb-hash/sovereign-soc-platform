import React, { useState, useEffect, useCallback } from 'react';
import JSZip from 'jszip';
import {
  PackageCheck,
  Download,
  FileArchive,
  Smartphone,
  Code2,
  CheckCircle2,
  Copy,
  Check,
  X,
  RefreshCw,
  ShieldCheck,
  FolderArchive,
  Link2,
  Globe
} from 'lucide-react';
import { APP_CURRENT_VERSION } from './UpdateNotification';

export type ExportPackageMode = 'github-pages' | 'pwa-dist' | 'full-source';

interface BuildInfoResponse {
  version: string;
  hasProductionBuild: boolean;
  buildSourceDir: string | null;
  distFileCount: number;
  distSizeBytes: number;
  sourceFileCount: number;
  sourceSizeBytes: number;
  directDownloadUrls: {
    githubPages?: string;
    pwaDist: string;
    fullSource: string;
  };
  filesPreview: string[];
  checkedAt: string;
}

interface ExportArtifactState {
  fileName: string;
  sizeBytes: number;
  sha256: string;
  blobUrl: string;
  source: 'server-api' | 'client-jszip';
  exportedAt: string;
}

function formatBytes(bytes: number): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, i);
  return `${value.toFixed(i === 0 ? 0 : 2)} ${units[i]}`;
}

async function computeSha256Hex(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildClientFallbackZip(mode: ExportPackageMode): Promise<Blob> {
  const zip = new JSZip();
  const basePaths = [
    './index.html',
    './404.html',
    './manifest.json',
    './sw.js',
    './pwa-192x192.png',
    './pwa-512x512.png',
    './pwa-maskable-512x512.png',
    './apple-touch-icon.png',
    './icon.svg',
    './favicon.ico',
    './sql-wasm.wasm'
  ];

  // Discover built JS/CSS assets from current index.html
  const discoveredAssets = new Set<string>(basePaths);
  try {
    const htmlRes = await fetch('./index.html', { cache: 'no-store' });
    if (htmlRes.ok) {
      const htmlText = await htmlRes.text();
      const assetMatches = htmlText.matchAll(/(?:src|href)=["'](\.?\/?assets\/[^"']+|workbox-[^"']+\.js)["']/g);
      for (const match of assetMatches) {
        if (match[1]) {
          const normalized = match[1].startsWith('./') || match[1].startsWith('/') ? match[1] : `./${match[1]}`;
          discoveredAssets.add(normalized);
        }
      }
    }
  } catch {
    // Continue with basePaths
  }

  for (const relPath of discoveredAssets) {
    try {
      const response = await fetch(relPath, { cache: 'no-store' });
      if (!response.ok) continue;
      const contentType = response.headers.get('content-type') || '';
      // Avoid saving HTML fallback inside asset files
      if (!relPath.endsWith('.html') && contentType.includes('text/html')) continue;

      const cleanPath = relPath.replace(/^\.\//, '').replace(/^\//, '');
      const buf = await response.arrayBuffer();
      zip.file(cleanPath, buf);
      if (mode !== 'github-pages') {
        zip.file(`www/${cleanPath}`, buf);
      }
    } catch {
      // Skip unreachable optional files
    }
  }

  if (mode === 'github-pages') {
    zip.file('.nojekyll', '');
  } else {
    const capacitorConfig = JSON.stringify(
      {
        appId: 'com.sovereign.forensic.engine',
        appName: 'Sovereign Forensic Engine',
        webDir: 'www',
        bundledWebRuntime: false,
        server: { androidScheme: 'https' },
        android: { allowMixedContent: false, backgroundColor: '#0b0f19' }
      },
      null,
      2
    );
    zip.file('capacitor.config.json', capacitorConfig);
    zip.file(
      'README-MOBILE-DEPLOY.md',
      `# Sovereign Forensic Engine v${APP_CURRENT_VERSION} (${mode})\n\nReady for static deploy (Vercel / GitHub Pages / Netlify) or Capacitor Android packaging (npx cap add android).\n`
    );
  }

  return zip.generateAsync({
    type: 'blob',
    compression: 'DEFLATE',
    compressionOptions: { level: 6 }
  });
}

export function MobilePackageExportModal({
  isOpen,
  onClose,
  onExportLogged
}: {
  isOpen: boolean;
  onClose: () => void;
  onExportLogged?: (detail: { fileName: string; sizeBytes: number; sha256: string; mode: ExportPackageMode }) => void;
}) {
  const [selectedMode, setSelectedMode] = useState<ExportPackageMode>('github-pages');
  const [buildInfo, setBuildInfo] = useState<BuildInfoResponse | null>(null);
  const [loadingInfo, setLoadingInfo] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [progressLabel, setProgressLabel] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [lastArtifact, setLastArtifact] = useState<ExportArtifactState | null>(null);
  const [copiedUrl, setCopiedUrl] = useState(false);

  const serverDirectPath = `/api/export/pwa-package?mode=${selectedMode}`;
  const fullServerDirectUrl =
    typeof window !== 'undefined' ? `${window.location.origin}${serverDirectPath}` : serverDirectPath;

  const fetchBuildInfo = useCallback(async () => {
    setLoadingInfo(true);
    try {
      const res = await fetch(`/api/export/build-info?t=${Date.now()}`, { cache: 'no-store' });
      if (res.ok) {
        const ct = res.headers.get('content-type') || '';
        if (ct.includes('application/json')) {
          const data: BuildInfoResponse = await res.json();
          setBuildInfo(data);
        }
      }
    } catch {
      // Static-only mode: buildInfo stays null and client fallback handles packaging cleanly
    } finally {
      setLoadingInfo(false);
    }
  }, []);

  useEffect(() => {
    if (isOpen) {
      fetchBuildInfo();
    }
  }, [isOpen, fetchBuildInfo]);

  useEffect(() => {
    return () => {
      if (lastArtifact?.blobUrl) {
        URL.revokeObjectURL(lastArtifact.blobUrl);
      }
    };
  }, [lastArtifact]);

  const triggerDownloadLink = (url: string, fileName: string) => {
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleExportNow = async () => {
    setIsExporting(true);
    setErrorMsg(null);
    setProgressLabel('جاري تجميع ملفات التطبيق وضغط الحزمة (ZIP)...');

    const expectedFileName =
      selectedMode === 'full-source'
        ? `sovereign-forensic-full-source-v${APP_CURRENT_VERSION}.zip`
        : selectedMode === 'github-pages'
        ? `sovereign-forensic-github-pages-v${APP_CURRENT_VERSION}.zip`
        : `sovereign-forensic-mobile-pwa-v${APP_CURRENT_VERSION}.zip`;

    try {
      let blob: Blob | null = null;
      let source: 'server-api' | 'client-jszip' = 'server-api';

      try {
        const res = await fetch(`${serverDirectPath}&t=${Date.now()}`, { cache: 'no-store' });
        const ct = res.headers.get('content-type') || '';
        if (res.ok && (ct.includes('application/zip') || ct.includes('application/octet-stream'))) {
          setProgressLabel('جاري استلام الحزمة المضغوطة وحساب بصمة التحقق SHA-256...');
          blob = await res.blob();
        }
      } catch {
        blob = null;
      }

      if (!blob) {
        source = 'client-jszip';
        setProgressLabel('جاري تجميع أصول PWA محلياً عبر JSZip...');
        blob = await buildClientFallbackZip(selectedMode);
      }

      const arrayBuffer = await blob.arrayBuffer();
      const sha256 = await computeSha256Hex(arrayBuffer);

      if (lastArtifact?.blobUrl) {
        URL.revokeObjectURL(lastArtifact.blobUrl);
      }
      const blobUrl = URL.createObjectURL(blob);

      const artifact: ExportArtifactState = {
        fileName: expectedFileName,
        sizeBytes: blob.size,
        sha256,
        blobUrl,
        source,
        exportedAt: new Date().toLocaleTimeString('ar-SA')
      };

      setLastArtifact(artifact);
      triggerDownloadLink(blobUrl, expectedFileName);
      onExportLogged?.({
        fileName: expectedFileName,
        sizeBytes: blob.size,
        sha256,
        mode: selectedMode
      });
      setProgressLabel('تم تجهيز الحزمة وبدء التحميل المباشر بنجاح.');
    } catch (err: any) {
      setErrorMsg(err?.message || 'تعذر توليد حزمة التصدير المضغوطة.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleCopyUrl = async () => {
    try {
      await navigator.clipboard.writeText(fullServerDirectUrl);
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2500);
    } catch {
      // Ignore clipboard errors
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div
        dir="rtl"
        className="relative w-full max-w-2xl rounded-3xl bg-gray-900 border border-[#D4AF37]/40 p-6 shadow-2xl text-right space-y-5 max-h-[90vh] overflow-y-auto"
      >
        <button
          type="button"
          onClick={onClose}
          className="absolute left-5 top-5 p-2 rounded-xl text-gray-400 hover:text-white hover:bg-gray-800 transition cursor-pointer"
          aria-label="إغلاق"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3.5">
          <div className="w-12 h-12 rounded-2xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37] shrink-0">
            <PackageCheck className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">تصدير وتحميل حزمة التطبيق (Export Mobile / PWA Package)</h3>
            <p className="text-xs text-gray-400">
              توليد وتحميل أرشيف ZIP حقيقي يضم ملفات المنصة والأيقونات وملف الخدمة `sw.js` وإعدادات Capacitor & Vercel.
            </p>
          </div>
        </div>

        {/* Live Build Stats Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 p-3.5 rounded-2xl bg-gray-950/70 border border-gray-800 text-xs">
          <div>
            <div className="text-[10px] text-gray-500 font-mono">BUILD VERSION</div>
            <div className="font-mono font-bold text-white mt-0.5">v{buildInfo?.version || APP_CURRENT_VERSION}</div>
          </div>
          <div>
            <div className="text-[10px] text-gray-500 font-mono">PRODUCTION DIST</div>
            <div className="font-mono font-bold text-emerald-400 mt-0.5">
              {loadingInfo
                ? '...'
                : buildInfo
                ? `${buildInfo.distFileCount} ملف (${formatBytes(buildInfo.distSizeBytes)})`
                : 'PWA Live Assets'}
            </div>
          </div>
          <div>
            <div className="text-[10px] text-gray-500 font-mono">SOURCE MODULES</div>
            <div className="font-mono font-bold text-[#D4AF37] mt-0.5">
              {loadingInfo
                ? '...'
                : buildInfo
                ? `${buildInfo.sourceFileCount} ملف (${formatBytes(buildInfo.sourceSizeBytes)})`
                : 'Browser Bundle'}
            </div>
          </div>
          <div>
            <div className="text-[10px] text-gray-500 font-mono">ANDROID TARGET</div>
            <div className="font-mono font-bold text-emerald-400 mt-0.5 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
              Standalone PWA
            </div>
          </div>
        </div>

        {/* Package Mode Selector */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <button
            type="button"
            onClick={() => setSelectedMode('github-pages')}
            className={`p-4 rounded-2xl border text-right transition cursor-pointer space-y-2 ${
              selectedMode === 'github-pages'
                ? 'bg-[#D4AF37]/10 border-[#D4AF37] shadow-lg shadow-[#D4AF37]/10'
                : 'bg-gray-950/50 border-gray-800 hover:border-gray-700'
            }`}
          >
            <div className="flex items-center justify-between gap-1">
              <span className="flex items-center gap-1.5 font-bold text-xs text-white">
                <Globe className="w-4 h-4 text-[#D4AF37] shrink-0" />
                حزمة GitHub Pages نظيفة
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-emerald-500/20 text-emerald-300 shrink-0">
                الأسهل للرفع
              </span>
            </div>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              ملفات التشغيل الجاهزة فقط (حوالي 15 ملف ~2MB بدون أي ملفات زائدة) مناسبة للسحب والإفلات المباشر في متصفح GitHub بدون أخطاء.
            </p>
          </button>

          <button
            type="button"
            onClick={() => setSelectedMode('pwa-dist')}
            className={`p-4 rounded-2xl border text-right transition cursor-pointer space-y-2 ${
              selectedMode === 'pwa-dist'
                ? 'bg-[#D4AF37]/10 border-[#D4AF37] shadow-lg shadow-[#D4AF37]/10'
                : 'bg-gray-950/50 border-gray-800 hover:border-gray-700'
            }`}
          >
            <div className="flex items-center justify-between gap-1">
              <span className="flex items-center gap-1.5 font-bold text-xs text-white">
                <Smartphone className="w-4 h-4 text-[#D4AF37] shrink-0" />
                حزمة الموبايل و Capacitor
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-[#D4AF37]/20 text-[#D4AF37] shrink-0">
                PWA + www
              </span>
            </div>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              تضم ملفات التطبيق المبنية + مجلد `www/` و `capacitor.config.json` و `vercel.json` لتوليد APK أو النشر على Vercel.
            </p>
          </button>

          <button
            type="button"
            onClick={() => setSelectedMode('full-source')}
            className={`p-4 rounded-2xl border text-right transition cursor-pointer space-y-2 ${
              selectedMode === 'full-source'
                ? 'bg-[#D4AF37]/10 border-[#D4AF37] shadow-lg shadow-[#D4AF37]/10'
                : 'bg-gray-950/50 border-gray-800 hover:border-gray-700'
            }`}
          >
            <div className="flex items-center justify-between gap-1">
              <span className="flex items-center gap-1.5 font-bold text-xs text-white">
                <Code2 className="w-4 h-4 text-[#D4AF37] shrink-0" />
                الأكواد المصدرية الكاملة
              </span>
              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-blue-500/15 text-blue-300 shrink-0">
                Git / Actions
              </span>
            </div>
            <p className="text-[11px] text-gray-400 leading-relaxed">
              كامل الشيفرة (`src/`، `public/`، `.github/workflows/deploy.yml`، `vercel.json`) نظيفة وخالية من `.env` لـ `git push`.
            </p>
          </button>
        </div>

        {/* Direct Server Endpoint URL Box */}
        <div className="p-3.5 rounded-2xl bg-gray-950 border border-gray-800 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-gray-300 flex items-center gap-1.5">
              <Link2 className="w-3.5 h-3.5 text-[#D4AF37]" />
              رابط التحميل المباشر من الخادم (Direct ZIP Endpoint):
            </span>
            <button
              type="button"
              onClick={handleCopyUrl}
              className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 text-[11px] transition cursor-pointer"
            >
              {copiedUrl ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              {copiedUrl ? 'تم النسخ' : 'نسخ الرابط'}
            </button>
          </div>
          <div
            dir="ltr"
            className="px-3 py-2 rounded-xl bg-gray-900 border border-gray-800 font-mono text-[11px] text-[#D4AF37] break-all select-all"
          >
            {fullServerDirectUrl}
          </div>
        </div>

        {/* Progress / Generated Artifact Feedback */}
        {progressLabel && !errorMsg && (
          <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center gap-2">
            {isExporting ? (
              <RefreshCw className="w-4 h-4 animate-spin shrink-0 text-[#D4AF37]" />
            ) : (
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
            )}
            <span>{progressLabel}</span>
          </div>
        )}

        {errorMsg && (
          <div className="p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-xs text-red-300">
            {errorMsg}
          </div>
        )}

        {lastArtifact && (
          <div className="p-4 rounded-2xl bg-gray-950/90 border border-[#D4AF37]/40 space-y-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <FolderArchive className="w-4 h-4 text-[#D4AF37]" />
                <span dir="ltr">{lastArtifact.fileName}</span>
              </div>
              <span className="text-[11px] font-mono text-emerald-400">
                {formatBytes(lastArtifact.sizeBytes)} • {lastArtifact.exportedAt}
              </span>
            </div>

            <div className="text-[11px] font-mono text-gray-400 break-all" dir="ltr">
              <span className="text-gray-500">SHA-256: </span>
              {lastArtifact.sha256}
            </div>

            <div className="flex flex-wrap items-center gap-2 pt-1">
              <a
                href={lastArtifact.blobUrl}
                download={lastArtifact.fileName}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs transition"
              >
                <Download className="w-3.5 h-3.5" />
                إعادة تنزيل الملف الجاهز (.zip)
              </a>
              <span className="text-[10px] text-gray-500 font-mono flex items-center gap-1">
                <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                {lastArtifact.source === 'server-api' ? 'Verified Express ZIP Stream' : 'Client JSZip Archive'}
              </span>
            </div>
          </div>
        )}

        {/* Action Footer */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-gray-800">
          <a
            href={serverDirectPath}
            download
            className="text-xs text-gray-400 hover:text-[#D4AF37] underline underline-offset-4 flex items-center gap-1.5"
          >
            <FileArchive className="w-3.5 h-3.5" />
            رابط تنزيل مباشر HTTP
          </a>

          <div className="flex items-center gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2.5 rounded-xl text-xs font-medium text-gray-400 hover:text-white hover:bg-gray-800 transition cursor-pointer"
            >
              إغلاق
            </button>
            <button
              type="button"
              onClick={handleExportNow}
              disabled={isExporting}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs shadow-lg shadow-[#D4AF37]/20 transition cursor-pointer disabled:opacity-50"
            >
              {isExporting ? (
                <RefreshCw className="w-4 h-4 animate-spin" />
              ) : (
                <Download className="w-4 h-4" />
              )}
              {isExporting ? 'جاري التوليد والضغط...' : 'توليد وتحميل حزمة التطبيق (ZIP)'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export function ExportMobilePackageButton({
  onClick,
  variant = 'primary'
}: {
  onClick: () => void;
  variant?: 'primary' | 'compact';
}) {
  if (variant === 'compact') {
    return (
      <button
        type="button"
        onClick={onClick}
        className="w-full py-2.5 px-3 bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 text-[#D4AF37] font-bold text-xs rounded-xl border border-[#D4AF37]/50 transition flex items-center justify-center gap-2 cursor-pointer"
      >
        <PackageCheck className="w-4 h-4 shrink-0" />
        <span>تحميل حزمة التطبيق (Export Mobile / PWA Package)</span>
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] hover:opacity-95 text-gray-950 font-bold text-xs rounded-xl shadow-lg shadow-[#D4AF37]/20 transition cursor-pointer shrink-0"
    >
      <PackageCheck className="w-4 h-4 shrink-0" />
      <span>تحميل حزمة التطبيق (Export Mobile / PWA Package)</span>
    </button>
  );
}
