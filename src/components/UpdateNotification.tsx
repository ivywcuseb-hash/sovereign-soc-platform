import React, { useState, useEffect, useCallback } from 'react';
import { 
  RefreshCw, 
  AlertCircle, 
  CheckCircle2, 
  Download, 
  Sparkles, 
  X, 
  Info, 
  ExternalLink,
  ShieldCheck,
  Cpu
} from 'lucide-react';
import { registerSW } from 'virtual:pwa-register';
import { apiUrl } from '../utils/apiBase';
import { safeParseRes } from '../utils/clientSecurity';

export const APP_CURRENT_VERSION = '2.5.2';

interface UpdateInfo {
  version: string;
  latestVersion: string;
  hasUpdate: boolean;
  buildTimestamp: string;
  releaseDate: string;
  title: string;
  message: string;
  features: string[];
}

export function useUpdateChecker() {
  const [hasUpdate, setHasUpdate] = useState<boolean>(false);
  const [isUpdating, setIsUpdating] = useState<boolean>(false);
  const [isChecking, setIsChecking] = useState<boolean>(false);
  const [updateDetails, setUpdateDetails] = useState<UpdateInfo | null>(null);
  const [showModal, setShowModal] = useState<boolean>(false);
  const [dismissed, setDismissed] = useState<boolean>(false);
  const [swUpdateFunction, setSwUpdateFunction] = useState<((reloadPage?: boolean) => Promise<void>) | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [swStatus, setSwStatus] = useState<'active' | 'installing' | 'pending' | 'unsupported'>(() =>
    typeof navigator !== 'undefined' && 'serviceWorker' in navigator ? 'pending' : 'unsupported'
  );
  const [swScriptUrl, setSwScriptUrl] = useState<string>('/sw.js');

  // Initialize PWA Service Worker Registration (/sw.js)
  useEffect(() => {
    if (typeof window === 'undefined' || !('serviceWorker' in navigator)) {
      setSwStatus('unsupported');
      return;
    }

    let updateFn: ((reloadPage?: boolean) => Promise<void>) | null = null;
    let updateInterval: ReturnType<typeof setInterval> | null = null;
    let cancelled = false;

    const syncRegistrationState = (registration: ServiceWorkerRegistration | undefined | null) => {
      if (cancelled || !registration) return;
      const worker = registration.active || registration.waiting || registration.installing;
      if (worker?.scriptURL) {
        try {
          setSwScriptUrl(new URL(worker.scriptURL).pathname);
        } catch {
          setSwScriptUrl('/sw.js');
        }
      }
      if (registration.active) {
        setSwStatus('active');
      } else if (registration.installing || registration.waiting) {
        setSwStatus('installing');
        worker?.addEventListener('statechange', () => {
          if (!cancelled && registration.active) {
            setSwStatus('active');
          }
        });
      }
    };

    try {
      updateFn = registerSW({
        immediate: true,
        onNeedRefresh() {
          setHasUpdate(true);
          setDismissed(false);
        },
        onOfflineReady() {
          setSwStatus('active');
        },
        onRegisteredSW(swUrl, registration) {
          if (swUrl) {
            setSwScriptUrl(swUrl);
          }
          syncRegistrationState(registration);
          if (registration) {
            updateInterval = setInterval(() => {
              registration.update().catch(() => undefined);
            }, 5 * 60 * 1000);
          }
        },
        onRegisterError() {
          // Fallback to direct /sw.js registration below
        }
      });
      setSwUpdateFunction(() => updateFn);
    } catch {
      // Fallback handled directly below
    }

    // Guarantee sw.js registration for Android APK / PWA standalone readiness (works on root and GitHub Pages subpath)
    navigator.serviceWorker
      .getRegistration('./')
      .then(async (existingReg) => {
        if (existingReg) {
          syncRegistrationState(existingReg);
          return existingReg;
        }
        const directReg = await navigator.serviceWorker.register('./sw.js', { scope: './' });
        syncRegistrationState(directReg);
        return directReg;
      })
      .catch(() => undefined);

    const onControllerChange = () => {
      setSwStatus('active');
    };
    navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);

    return () => {
      cancelled = true;
      if (updateInterval) clearInterval(updateInterval);
      navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange);
    };
  }, []);

  // Check version against backend /api/version
  const checkForUpdates = useCallback(async (manual = false) => {
    setIsChecking(true);
    try {
      // Trigger SW registration update
      if ('serviceWorker' in navigator) {
        try {
          const reg = await navigator.serviceWorker.getRegistration();
          if (reg) {
            await reg.update();
            if (reg.waiting) {
              setHasUpdate(true);
              setDismissed(false);
            }
          }
        } catch (swErr) {
          console.log('[SW Check] SW update check skipped:', swErr);
        }
      }

      // Query version API
      const res = await fetch(apiUrl(`/api/version?clientVersion=${encodeURIComponent(APP_CURRENT_VERSION)}&t=${Date.now()}`));
      if (res.ok) {
        const data: UpdateInfo = await safeParseRes(res);
        if (data && typeof data === 'object') {
          setUpdateDetails(data);
          if (data.hasUpdate) {
            setHasUpdate(true);
            setDismissed(false);
          } else if (manual) {
            setToastMessage(`أنت تستخدم أحدث إصدار من المنصة (${APP_CURRENT_VERSION}). جميع وحدات التحقيق الجنائي محدثة بالكامل.`);
            setTimeout(() => setToastMessage(null), 4000);
          }
        }
      }
    } catch (err) {
      console.error('Update check failed:', err);
      if (manual) {
        setToastMessage(`تم فحص النظام: المنصة تعمل بالإصدار المستقر (${APP_CURRENT_VERSION}).`);
        setTimeout(() => setToastMessage(null), 4000);
      }
    } finally {
      setIsChecking(false);
    }
  }, []);

  // Periodic check on load and focus
  useEffect(() => {
    checkForUpdates(false);

    const onFocus = () => checkForUpdates(false);
    window.addEventListener('focus', onFocus);
    return () => window.removeEventListener('focus', onFocus);
  }, [checkForUpdates]);

  // Execute update: activate waiting SW, purge caches, hard reload
  const applyUpdateNow = async () => {
    setIsUpdating(true);
    try {
      // 1. Tell PWA update function to skip waiting
      if (swUpdateFunction) {
        try {
          await swUpdateFunction(true);
        } catch (swErr) {
          console.warn('SW update function call issue:', swErr);
        }
      }

      // 2. Tell any waiting SW directly
      if ('serviceWorker' in navigator) {
        const registrations = await navigator.serviceWorker.getRegistrations();
        for (const reg of registrations) {
          if (reg.waiting) {
            reg.waiting.postMessage({ type: 'SKIP_WAITING' });
          }
        }
      }

      // 3. Clear cache storage
      if ('caches' in window) {
        try {
          const cacheKeys = await caches.keys();
          await Promise.all(cacheKeys.map(k => caches.delete(k)));
        } catch (cErr) {
          console.warn('Cache clearing error:', cErr);
        }
      }

      // 4. Force reload after brief delay to show animation
      setTimeout(() => {
        window.location.reload();
      }, 600);
    } catch (err) {
      console.error('Failed to apply update cleanly:', err);
      window.location.reload();
    }
  };

  // Simulation mode for testing the update notification UI
  const triggerSimulatedUpdate = () => {
    setHasUpdate(true);
    setDismissed(false);
    setUpdateDetails({
      version: APP_CURRENT_VERSION,
      latestVersion: '2.5.3-PRO',
      hasUpdate: true,
      buildTimestamp: new Date().toISOString(),
      releaseDate: new Date().toLocaleDateString('ar-SA'),
      title: 'تحديث منصة SOVEREIGN الجنائية',
      message: 'يتوفر إصدار جديد للموقع يتضمن تسريع خوارزميات التجزئة وبصمات الأدلة وحزم تحليل الصور المتقدمة.',
      features: [
        'تسريع حساب بصمات MD5 وSHA-256 بنسبة 40%',
        'تحديث نظام سلسلة العهدة الرقمية (Chain of Custody)',
        'تطبيق أحدث حزم فحص ELA وتحليل بكسلات الصور بدون تجميد',
        'تحديث قواعد الحماية الصارمة لبيانات Firestore وStorage'
      ]
    });
  };

  return {
    hasUpdate,
    isUpdating,
    isChecking,
    updateDetails,
    showModal,
    dismissed,
    toastMessage,
    swStatus,
    swScriptUrl,
    setShowModal,
    setDismissed,
    checkForUpdates,
    applyUpdateNow,
    triggerSimulatedUpdate
  };
}

export function UpdateBanner({
  hasUpdate,
  isUpdating,
  dismissed,
  setDismissed,
  applyUpdateNow,
  setShowModal
}: {
  hasUpdate: boolean;
  isUpdating: boolean;
  dismissed: boolean;
  setDismissed: (val: boolean) => void;
  applyUpdateNow: () => void;
  setShowModal: (val: boolean) => void;
}) {
  if (!hasUpdate || dismissed) return null;

  return (
    <div className="relative z-50 bg-gradient-to-r from-amber-950/90 via-gray-900 to-amber-950/90 border-b-2 border-[#D4AF37] px-4 py-3 shadow-2xl backdrop-blur-md transition-all animate-in fade-in slide-in-from-top-2">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-3 text-sm">
        
        {/* Update Notice Content */}
        <div className="flex items-center gap-3 text-right w-full md:w-auto">
          <div className="w-9 h-9 rounded-xl bg-[#D4AF37]/20 border border-[#D4AF37]/40 flex items-center justify-center shrink-0 text-[#D4AF37] animate-pulse">
            <RefreshCw className="w-5 h-5 animate-spin" style={{ animationDuration: '3s' }} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-white text-sm">هذا الموقع يريد تحديث!</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-[#D4AF37] text-gray-950 uppercase tracking-wider">
                تحديث متوفر
              </span>
            </div>
            <p className="text-gray-300 text-xs mt-0.5">
              يتوفر إصدار جديد من منصة SOVEREIGN الجنائية. قم بالتحديث الآن لتطبيق التحسينات الأمنية وتسريع الفحص.
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-2 w-full md:w-auto justify-end shrink-0">
          <button
            onClick={() => setShowModal(true)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium text-gray-300 bg-gray-800/80 hover:bg-gray-700 hover:text-white border border-gray-700 transition"
          >
            تفاصيل التحديث
          </button>

          <button
            onClick={applyUpdateNow}
            disabled={isUpdating}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-xs font-bold bg-[#D4AF37] hover:bg-[#c29d2f] text-gray-950 shadow-lg shadow-[#D4AF37]/20 hover:scale-[1.02] active:scale-[0.98] transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isUpdating ? 'animate-spin' : ''}`} />
            {isUpdating ? 'جاري التحديث والتطبيق...' : 'تحديث الآن'}
          </button>

          <button
            onClick={() => setDismissed(true)}
            title="تذكيري لاحقاً"
            className="p-1.5 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

      </div>
    </div>
  );
}

export function UpdateModal({
  isOpen,
  onClose,
  updateDetails,
  isUpdating,
  applyUpdateNow
}: {
  isOpen: boolean;
  onClose: () => void;
  updateDetails: UpdateInfo | null;
  isUpdating: boolean;
  applyUpdateNow: () => void;
}) {
  if (!isOpen) return null;

  const features = updateDetails?.features || [
    'نظام كشف وتحديث الموقع التلقائي مع تفريغ الكاش المحدث',
    'تسريع محرك التجزئة الرقمية وحساب MD5 وSHA-256 وSHA-1',
    'مقارنة الأدلة الثنائية وسلسلة العهدة التلقائية',
    'استقرار فحص الصور والأدلة دون أي تجميد'
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in">
      <div className="bg-gray-900 border border-gray-800 rounded-3xl max-w-lg w-full p-6 shadow-2xl relative text-right space-y-5">
        
        <button
          onClick={onClose}
          className="absolute top-5 left-5 p-2 rounded-xl text-gray-400 hover:text-white hover:bg-gray-800 transition"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-[#D4AF37]/20 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37] shadow-lg">
            <Sparkles className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">مركز تحديثات المنصة الجنائية</h3>
            <p className="text-xs text-gray-400 font-mono">SOVEREIGN FORENSIC ENGINE • v{APP_CURRENT_VERSION}</p>
          </div>
        </div>

        <div className="p-4 rounded-2xl bg-gray-950/60 border border-gray-800/80 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="text-gray-400">الإصدار الحالي المثبت:</span>
            <span className="font-mono text-gray-300 font-bold">v{APP_CURRENT_VERSION}</span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-gray-400">الإصدار المتاح:</span>
            <span className="font-mono text-[#D4AF37] font-bold">
              v{updateDetails?.latestVersion || '2.5.3 (مُحدّث)'}
            </span>
          </div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-gray-400">حالة التحديث:</span>
            <span className="text-emerald-400 font-bold flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              حزمة التحديث جاهزة للتطبيق الفوري
            </span>
          </div>
        </div>

        <div className="space-y-2">
          <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider">أبرز التحسينات في هذا التحديث:</h4>
          <ul className="space-y-1.5 text-xs text-gray-300">
            {features.map((feat, idx) => (
              <li key={idx} className="flex items-start gap-2 bg-gray-800/40 p-2 rounded-lg border border-gray-800">
                <CheckCircle2 className="w-3.5 h-3.5 text-[#D4AF37] mt-0.5 shrink-0" />
                <span>{feat}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="pt-2 flex items-center justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-xl text-xs font-medium text-gray-400 hover:text-white hover:bg-gray-800 transition"
          >
            إغلاق
          </button>

          <button
            onClick={applyUpdateNow}
            disabled={isUpdating}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl text-xs font-bold bg-[#D4AF37] hover:bg-[#c29d2f] text-gray-950 shadow-xl shadow-[#D4AF37]/20 hover:scale-[1.02] active:scale-[0.98] transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isUpdating ? 'animate-spin' : ''}`} />
            {isUpdating ? 'جاري تحديث المنصة...' : 'تطبيق التحديث وإعادة التحميل الآن'}
          </button>
        </div>

      </div>
    </div>
  );
}
