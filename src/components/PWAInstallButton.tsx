import React, { useState } from 'react';
import { Download, Smartphone, Share, Plus, X, WifiOff, CheckCircle2 } from 'lucide-react';
import { usePWAInstall, useOnlineStatus } from '../hooks/usePWAInstall';

export function PWAInstallButton({ compact = false }: { compact?: boolean }) {
  const { isInstallable, isInstalled, isIOS, install } = usePWAInstall();
  const [showIOSModal, setShowIOSModal] = useState(false);

  if (isInstalled) {
    if (!compact) return null;
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">
        <CheckCircle2 className="w-3.5 h-3.5" />
        يعمل كتطبيق مستقل (Standalone)
      </span>
    );
  }

  if (isInstallable) {
    return (
      <button
        type="button"
        onClick={install}
        title="تثبيت المنصة كتطبيق أندرويد / سطح مكتب مستقل (PWA Standalone)"
        className="flex items-center gap-1.5 px-2.5 py-1.5 bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 text-[#D4AF37] border border-[#D4AF37]/50 rounded-xl text-[11px] font-bold transition cursor-pointer shadow-sm"
      >
        <Download className="w-3.5 h-3.5 shrink-0" />
        <span className={compact ? 'inline' : 'hidden xl:inline'}>تثبيت التطبيق (APK/PWA)</span>
      </button>
    );
  }

  if (isIOS) {
    return (
      <>
        <button
          type="button"
          onClick={() => setShowIOSModal(true)}
          title="تثبيت المنصة على الشاشة الرئيسية"
          className="flex items-center gap-1.5 px-2.5 py-1.5 bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 text-[#D4AF37] border border-[#D4AF37]/50 rounded-xl text-[11px] font-bold transition cursor-pointer shadow-sm"
        >
          <Smartphone className="w-3.5 h-3.5 shrink-0" />
          <span className={compact ? 'inline' : 'hidden xl:inline'}>تثبيت على iOS</span>
        </button>

        {showIOSModal && (
          <div className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
            <div
              dir="rtl"
              className="relative w-full max-w-sm rounded-2xl bg-gray-900 border border-[#D4AF37]/40 p-6 shadow-2xl text-right space-y-4"
            >
              <button
                type="button"
                onClick={() => setShowIOSModal(false)}
                className="absolute left-4 top-4 p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition cursor-pointer"
                aria-label="إغلاق"
              >
                <X className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-2.5">
                <div className="w-9 h-9 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37]">
                  <Smartphone className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-sm font-bold text-white">تثبيت Sovereign Forensic Engine</h3>
                  <p className="text-[11px] text-gray-400">تشغيل مستقل بدون شريط المتصفح</p>
                </div>
              </div>

              <ol className="space-y-3 text-xs text-gray-300">
                <li className="flex items-center gap-2.5 bg-gray-950/70 p-2.5 rounded-xl border border-gray-800">
                  <span className="w-6 h-6 rounded-full bg-[#D4AF37] text-gray-950 font-bold flex items-center justify-center shrink-0">
                    1
                  </span>
                  <span className="flex items-center gap-1.5 flex-wrap">
                    اضغط على أيقونة المشاركة <Share className="w-4 h-4 text-[#D4AF37] inline" /> في شريط Safari
                  </span>
                </li>
                <li className="flex items-center gap-2.5 bg-gray-950/70 p-2.5 rounded-xl border border-gray-800">
                  <span className="w-6 h-6 rounded-full bg-[#D4AF37] text-gray-950 font-bold flex items-center justify-center shrink-0">
                    2
                  </span>
                  <span className="flex items-center gap-1.5 flex-wrap">
                    اختر <Plus className="w-4 h-4 text-[#D4AF37] inline" /> إضافة إلى الشاشة الرئيسية
                  </span>
                </li>
                <li className="flex items-center gap-2.5 bg-gray-950/70 p-2.5 rounded-xl border border-gray-800">
                  <span className="w-6 h-6 rounded-full bg-[#D4AF37] text-gray-950 font-bold flex items-center justify-center shrink-0">
                    3
                  </span>
                  <span>اضغط «إضافة» للتشغيل بوضع Standalone</span>
                </li>
              </ol>
            </div>
          </div>
        )}
      </>
    );
  }

  return null;
}

export function OfflineIndicator() {
  const isOnline = useOnlineStatus();

  if (isOnline) return null;

  return (
    <div
      dir="rtl"
      role="status"
      aria-live="polite"
      className="fixed bottom-12 right-5 z-50 no-print flex items-center gap-2 px-3.5 py-2 rounded-xl bg-amber-950/95 border border-[#D4AF37]/70 text-[#D4AF37] text-xs font-bold shadow-2xl backdrop-blur-md"
    >
      <WifiOff className="w-4 h-4 shrink-0" />
      <span>وضع عدم الاتصال نشط — المختبرات المحلية تعمل بالكامل</span>
    </div>
  );
}
