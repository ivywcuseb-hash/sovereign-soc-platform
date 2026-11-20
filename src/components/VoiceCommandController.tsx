import React, { useEffect, useRef, useState } from 'react';
import {
  Mic,
  MicOff,
  Volume2,
  VolumeX,
  X,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Terminal,
  Command,
  RefreshCw,
} from 'lucide-react';
import type { AppTabId } from './LayoutCustomizer';

export interface VoiceCommandHistoryItem {
  id: string;
  transcript: string;
  matchedLabel: string;
  status: 'executed' | 'unmatched' | 'error';
  confidence?: number;
  timestamp: string;
}

interface VoiceCommandControllerProps {
  isOpen: boolean;
  onToggleOpen: (open: boolean) => void;
  activeTab: AppTabId;
  onNavigateTab: (tab: AppTabId) => void;
  onInspectLatestFile: () => Promise<string>;
  onSyncLiveFeeds: () => Promise<string> | string;
  onInspectClipboard: () => Promise<string> | string;
  onGetStatusSummary: () => string;
  onOpenCustomizer: () => void;
  onRandomTheme: () => string;
  onLockSystem: () => void;
  onTriggerOsintQuery: (indicator: string) => void;
  onNotify: (msg: string, type?: 'success' | 'error' | 'warning') => void;
}

function normalizeArabicVoiceText(input: string): string {
  return input
    .toLowerCase()
    .replace(/[\u064B-\u065F\u0670]/g, '') // strip Arabic diacritics
    .replace(/[أإآٱ]/g, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .replace(/[^\p{L}\p{N}\s._:-]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

const TAB_VOICE_ROUTES: Array<{ tab: AppTabId; labelAr: string; keywords: string[] }> = [
  {
    tab: 'cyber_telemetry',
    labelAr: 'لوحة مراقبة تدفق الشبكة (SOC)',
    keywords: ['لوحه الشبكه', 'تدفق الشبكه', 'الشبكه', 'مراقبه الشبكه', 'ترافك', 'network dashboard', 'telemetry'],
  },
  {
    tab: 'vuln_kev_dashboard',
    labelAr: 'لوحة إدارة الثغرات (KEV & EPSS)',
    keywords: ['لوحه الثغرات', 'الثغرات', 'ثغرات kev', 'kev', 'epss', 'cve'],
  },
  {
    tab: 'asset_os_dashboard',
    labelAr: 'لوحة الأصول وأنظمة التشغيل',
    keywords: ['توزيع الاصول', 'لوحه الاصول', 'الاصول', 'انظمه التشغيل', 'الاجهزه', 'assets'],
  },
  {
    tab: 'live_voice',
    labelAr: 'المحادثة الصوتية الحية',
    keywords: ['المحادثه الصوتيه', 'الصوت الحي', 'المساعد الصوتي', 'محادثه صوتيه', 'voice chat'],
  },
  {
    tab: 'dashboard',
    labelAr: 'لوحة التحكم الرئيسية',
    keywords: ['لوحه التحكم', 'الرئيسيه', 'الصفحه الرئيسيه', 'dashboard', 'home'],
  },
  {
    tab: 'analyzer',
    labelAr: 'وحدة التحليل الرقمي',
    keywords: ['وحده التحليل', 'التحليل الرقمي', 'المحلل', 'التحليل', 'analyzer'],
  },
  {
    tab: 'evidence',
    labelAr: 'إدارة الأدلة الرقمية',
    keywords: ['اداره الادله', 'الادله', 'الخزنه', 'evidence'],
  },
  {
    tab: 'custody',
    labelAr: 'سلسلة الحيازة',
    keywords: ['سلسله الحيازه', 'الحيازه', 'العهدة', 'custody'],
  },
  {
    tab: 'live_feeds',
    labelAr: 'التغذيات الحية',
    keywords: ['التغذيات الحيه', 'التغذيات', 'اخبار التهديدات', 'live feeds'],
  },
  {
    tab: 'audit',
    labelAr: 'سجل العمليات',
    keywords: ['سجل العمليات', 'السجل', 'سجل الفحص', 'audit'],
  },
  {
    tab: 'reports',
    labelAr: 'التقارير الموثقة',
    keywords: ['التقارير الموثقه', 'التقارير', 'reports'],
  },
  {
    tab: 'hex',
    labelAr: 'عارض الهكس والبايتات (Hex)',
    keywords: ['عارض الهكس', 'الهكس', 'فحص البايتات', 'البايتات', 'hex'],
  },
  {
    tab: 'ela',
    labelAr: 'تحليل التلاعب بالصور (ELA)',
    keywords: ['تحليل التلاعب', 'تلاعب الصور', 'اي ال اي', 'ela'],
  },
  {
    tab: 'apk',
    labelAr: 'محلل تطبيقات أندرويد (APK)',
    keywords: ['تحليل apk', 'محلل apk', 'تطبيقات اندرويد', 'الاندرويد', 'apk'],
  },
  {
    tab: 'browser',
    labelAr: 'محلل سجل المتصفح (SQLite)',
    keywords: ['سجل المتصفح', 'المتصفح', 'sqlite', 'browser'],
  },
  {
    tab: 'threat_intel',
    labelAr: 'الاستخبارات العالمية للتهديدات',
    keywords: ['الاستخبارات العالميه', 'استخبارات التهديدات', 'threat intel'],
  },
  {
    tab: 'search',
    labelAr: 'البحث الجنائي (OSINT)',
    keywords: ['اوسنت', 'الاستخبارات', 'البحث الجنائي', 'osint'],
  },
  {
    tab: 'deobfuscator',
    labelAr: 'فك تشويه السكربتات',
    keywords: ['فك تشويه', 'السكربتات', 'deobfuscator'],
  },
  {
    tab: 'binary_lab',
    labelAr: 'تحليل الباينري (PE/ELF)',
    keywords: ['تحليل الباينري', 'الباينري', 'binary'],
  },
  {
    tab: 'parser',
    labelAr: 'محلل السجلات (IoC)',
    keywords: ['محلل السجلات', 'مؤشرات الاختراق', 'ioc', 'parser'],
  },
  {
    tab: 'breach_lookup',
    labelAr: 'فحص التسريبات',
    keywords: ['فحص التسريبات', 'التسريبات', 'كلمات المرور', 'breach'],
  },
  {
    tab: 'archive_extractor',
    labelAr: 'تحليل الأرشيف (ZIP)',
    keywords: ['تحليل الارشيف', 'الارشيف', 'الملفات المضغوطه', 'zip'],
  },
  {
    tab: 'ssl_inspector',
    labelAr: 'فحص شهادات SSL/TLS',
    keywords: ['شهادات الامان', 'شهاده ssl', 'شهادات ssl', 'التشفير', 'ssl'],
  },
  {
    tab: 'ip_mapper',
    labelAr: 'خريطة الـ IP والتهديدات',
    keywords: ['خريطه الاي بي', 'خريطه ip', 'خريطه العناوين', 'ip map'],
  },
  {
    tab: 'malware_hash',
    labelAr: 'فاحص بصمات الفيروسات',
    keywords: ['بصمات الفيروسات', 'فاحص الفيروسات', 'فحص البصمه', 'malware hash'],
  },
  {
    tab: 'pdf_forensics',
    labelAr: 'محلل مستندات PDF',
    keywords: ['محلل pdf', 'مستندات pdf', 'فحص pdf', 'المستندات'],
  },
  {
    tab: 'url_tracer',
    labelAr: 'متتبع الروابط المختصرة',
    keywords: ['متتبع الروابط', 'تتبع الروابط', 'الروابط المختصره', 'url tracer'],
  },
  {
    tab: 'steg_inspector',
    labelAr: 'كاشف الإخفاء في الصور (LSB)',
    keywords: ['كاشف الاخفاء', 'البيانات المخفيه', 'steganography', 'lsb'],
  },
  {
    tab: 'phishing_url_inspector',
    labelAr: 'كاشف الروابط الاحتيالية ومحلل البنية (Phishing & URL Deep Inspector)',
    keywords: ['كاشف الروابط الاحتياليه', 'محلل البنيه', 'روابط التصيد', 'phishing', 'url deep'],
  },
  {
    tab: 'ip_isp_asn_lookup',
    labelAr: 'فاحص IP ومزود الخدمة (IP Intelligence & ISP/ASN Lookup)',
    keywords: ['فاحص ip', 'مزود الخدمه', 'رقم الشبكه', 'isp', 'asn', 'ip intelligence'],
  },
  {
    tab: 'iq_domain_auditor',
    labelAr: 'فاحص أمان النطاقات العراقية (IQ Domain Security Auditor)',
    keywords: ['النطاقات العراقيه', 'فاحص النطاقات العراقيه', 'نطاق عراقي', 'iq domain', 'gov iq'],
  },
  {
    tab: 'live_dns_inspector',
    labelAr: 'فاحص سجلات DNS المباشر (Live DNS Inspector)',
    keywords: ['فاحص dns المباشر', 'فاحص سجلات dns', 'live dns', 'dns inspector', 'استعلام dns'],
  },
  {
    tab: 'dns_email_auditor',
    labelAr: 'فاحص أمان النطاقات والبريد (DNS/SPF/DMARC)',
    keywords: ['فاحص النطاقات', 'امان البريد', 'سجلات dns', 'spf', 'dmarc', 'dns'],
  },
  {
    tab: 'yara_scanner',
    labelAr: 'ماسح قواعد YARA للملفات',
    keywords: ['ماسح يارا', 'قواعد يارا', 'يارا', 'yara'],
  },
  {
    tab: 'jwt_inspector',
    labelAr: 'محلل رموز التوثيق (JWT / Token)',
    keywords: ['محلل التوكن', 'رموز التوثيق', 'التوكن', 'jwt', 'token'],
  },
  {
    tab: 'pcap_inspector',
    labelAr: 'محلل حزم الشبكة (PCAP)',
    keywords: ['حزم الشبكه', 'محلل الحزم', 'بيكاب', 'pcap'],
  },
  {
    tab: 'log_analyzer',
    labelAr: 'محلل السجلات الحقيقي (Real Log Analyzer)',
    keywords: ['محلل السجلات', 'تحليل السجلات', 'السجلات', 'access log', 'log analyzer'],
  },
  {
    tab: 'exif_inspector',
    labelAr: 'مستخرج البيانات الوصفية (EXIF & Metadata Inspector)',
    keywords: ['مستخرج البيانات', 'البيانات الوصفيه', 'exif', 'metadata'],
  },
  {
    tab: 'email',
    labelAr: 'تحليل البريد الإلكتروني',
    keywords: ['تحليل البريد', 'البريد', 'email'],
  },
  {
    tab: 'clipboard',
    labelAr: 'مختبر فحص الحافظة',
    keywords: ['الحافظه', 'مختبر الحافظه', 'clipboard'],
  },
  {
    tab: 'comparison',
    labelAr: 'مقارنة الأدلة',
    keywords: ['مقارنه الادله', 'المقارنه', 'comparison'],
  },
  {
    tab: 'profile',
    labelAr: 'الحساب والإعدادات',
    keywords: ['الحساب', 'الملف الشخصي', 'الاعدادات', 'profile'],
  },
];

export const VoiceCommandController: React.FC<VoiceCommandControllerProps> = ({
  isOpen,
  onToggleOpen,
  activeTab,
  onNavigateTab,
  onInspectLatestFile,
  onSyncLiveFeeds,
  onInspectClipboard,
  onGetStatusSummary,
  onOpenCustomizer,
  onRandomTheme,
  onLockSystem,
  onTriggerOsintQuery,
  onNotify,
}) => {
  const [speechSupported, setSpeechSupported] = useState<boolean>(true);
  const [isListening, setIsListening] = useState<boolean>(false);
  const [continuousMode, setContinuousMode] = useState<boolean>(false);
  const [speechLang, setSpeechLang] = useState<'ar-SA' | 'ar-IQ' | 'en-US'>('ar-SA');
  const [speakFeedback, setSpeakFeedback] = useState<boolean>(true);
  const [interimTranscript, setInterimTranscript] = useState<string>('');
  const [lastExecutedBanner, setLastExecutedBanner] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [history, setHistory] = useState<VoiceCommandHistoryItem[]>([]);

  const recognitionRef = useRef<any>(null);
  const continuousRef = useRef<boolean>(false);
  const speakFeedbackRef = useRef<boolean>(true);
  const isListeningRef = useRef<boolean>(false);
  const latestCallbacksRef = useRef({
    onNavigateTab,
    onInspectLatestFile,
    onSyncLiveFeeds,
    onInspectClipboard,
    onGetStatusSummary,
    onOpenCustomizer,
    onRandomTheme,
    onLockSystem,
    onTriggerOsintQuery,
    onNotify,
  });

  useEffect(() => {
    latestCallbacksRef.current = {
      onNavigateTab,
      onInspectLatestFile,
      onSyncLiveFeeds,
      onInspectClipboard,
      onGetStatusSummary,
      onOpenCustomizer,
      onRandomTheme,
      onLockSystem,
      onTriggerOsintQuery,
      onNotify,
    };
  }, [
    onNavigateTab,
    onInspectLatestFile,
    onSyncLiveFeeds,
    onInspectClipboard,
    onGetStatusSummary,
    onOpenCustomizer,
    onRandomTheme,
    onLockSystem,
    onTriggerOsintQuery,
    onNotify,
  ]);

  useEffect(() => {
    continuousRef.current = continuousMode;
  }, [continuousMode]);

  useEffect(() => {
    speakFeedbackRef.current = speakFeedback;
    if (!speakFeedback && typeof window !== 'undefined' && 'speechSynthesis' in window) {
      window.speechSynthesis.cancel();
    }
  }, [speakFeedback]);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const Rec = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
      setSpeechSupported(Boolean(Rec));
      if ('speechSynthesis' in window) {
        window.speechSynthesis.getVoices();
      }
    }
    return () => {
      continuousRef.current = false;
      if (recognitionRef.current) {
        try {
          recognitionRef.current.stop();
        } catch {}
      }
    };
  }, []);

  const speakResponse = (text: string) => {
    if (!speakFeedbackRef.current || !text.trim()) return;
    if (typeof window === 'undefined' || !('speechSynthesis' in window)) return;
    try {
      const synth = window.speechSynthesis;
      synth.cancel();
      const voices = synth.getVoices();
      const isArabic = /[\u0600-\u06FF]/.test(text);
      const preferred = isArabic
        ? voices.find((v) => v.lang.toLowerCase().startsWith('ar')) || null
        : voices.find((v) => v.lang.toLowerCase().startsWith('en')) || null;

      const utt = new SpeechSynthesisUtterance(text);
      if (preferred) utt.voice = preferred;
      utt.lang = preferred?.lang || (isArabic ? 'ar-SA' : 'en-US');
      utt.rate = 1.03;
      utt.pitch = 1.0;
      synth.speak(utt);
    } catch {
      // ignore TTS failures
    }
  };

  const executeVoiceCommand = async (rawTranscript: string, confidence?: number) => {
    const clean = rawTranscript.trim();
    if (!clean) return;

    const norm = normalizeArabicVoiceText(clean);
    const cb = latestCallbacksRef.current;

    const pushHistory = (
      matchedLabel: string,
      status: VoiceCommandHistoryItem['status']
    ) => {
      setHistory((prev) => [
        {
          id: `vcmd-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
          transcript: clean,
          matchedLabel,
          status,
          confidence,
          timestamp: new Date().toLocaleTimeString('ar-EG', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
          }),
        },
        ...prev.slice(0, 7),
      ]);
    };

    // 1. Inspect Latest File command ("افحص الملف الأخير")
    if (
      /(افحص|فحص|حلل|تحليل|اعد فحص).*(الملف الاخير|اخر ملف|ملف الاخير|اخر دليل|الملف الحالي)/.test(norm) ||
      /\b(inspect|scan|analyze)\s+(latest|last)\s+file\b/.test(norm)
    ) {
      const feedback = await cb.onInspectLatestFile();
      setLastExecutedBanner(feedback);
      pushHistory('فحص الملف الأخير', 'executed');
      cb.onNotify(feedback, 'success');
      speakResponse(feedback);
      return;
    }

    // 2. Sync Live Feeds command ("حدث التغذيات")
    if (
      /(حدث|مزامنه|تحديث|جلب).*(التغذيات|التهديدات|الفيد)/.test(norm) ||
      /\b(sync|refresh)\s+(feeds|threats)\b/.test(norm)
    ) {
      const msg = await cb.onSyncLiveFeeds();
      setLastExecutedBanner(msg);
      pushHistory('مزامنة التغذيات الحية', 'executed');
      cb.onNotify(msg, 'success');
      speakResponse(msg);
      return;
    }

    // 3. Inspect Clipboard command ("افحص الحافظة")
    if (/(افحص|فحص|حلل).*(الحافظه)/.test(norm)) {
      const msg = await cb.onInspectClipboard();
      setLastExecutedBanner(msg);
      pushHistory('فحص الحافظة الحية', 'executed');
      cb.onNotify(msg, 'success');
      speakResponse(msg);
      return;
    }

    // 4. Status Summary ("تقرير الحالة" / "ملخص النظام")
    if (
      /(ملخص النظام|تقرير الحاله|حاله النظام|حاله الموقع|كم دليل|احصائيات الموقع)/.test(norm) ||
      /\b(system status|summary)\b/.test(norm)
    ) {
      const summary = cb.onGetStatusSummary();
      setLastExecutedBanner(summary);
      pushHistory('تقرير حالة النظام الحية', 'executed');
      cb.onNotify(summary, 'success');
      speakResponse(summary);
      return;
    }

    // 5. UI Customizer / Random Theme / Lock System
    if (/(تخصيص الواجهه|تخصيص الهيكل|افتح التخصيص|اعدادات الواجهه)/.test(norm)) {
      cb.onOpenCustomizer();
      const msg = 'تم فتح لوحة تخصيص الهيكل والواجهة.';
      setLastExecutedBanner(msg);
      pushHistory('فتح تخصيص الواجهة', 'executed');
      speakResponse(msg);
      return;
    }

    if (/(غير الثيم|ثيم عشوائي|بدل الثيم)/.test(norm)) {
      const msg = cb.onRandomTheme();
      setLastExecutedBanner(msg);
      pushHistory('تطبيق ثيم إجرائي عشوائي', 'executed');
      speakResponse(msg);
      return;
    }

    if (/(اقفل النظام|قفل النظام|اغلق النظام|قفل الطوارئ)/.test(norm)) {
      const msg = 'جاري تنفيذ قفل النظام الفوري.';
      setLastExecutedBanner(msg);
      pushHistory('قفل النظام الأمني', 'executed');
      speakResponse(msg);
      cb.onLockSystem();
      return;
    }

    // 6. OSINT / Search Indicator Voice Command ("افحص الاي بي 8.8.8.8" or "ابحث عن ...")
    const searchMatch = clean.match(/(?:ابحث عن|افحص العنوان|افحص النطاق|فحص مؤشر)\s+(.+)/i);
    if (searchMatch && searchMatch[1]) {
      const target = searchMatch[1].trim();
      cb.onTriggerOsintQuery(target);
      const msg = `تم إرسال المؤشر ${target} إلى محرك الاستخبارات العالمية.`;
      setLastExecutedBanner(msg);
      pushHistory(`استخبارات OSINT: ${target}`, 'executed');
      cb.onNotify(msg, 'success');
      speakResponse(msg);
      return;
    }

    // 7. Open / Navigate Tab Matching ("افتح لوحة الشبكة", etc.)
    const strippedForTab = norm.replace(/^(افتح|فتح|شغل|اعرض|انتقل الي|اذهب الي|open|show|go to)\s+/g, '').trim();
    const matchedRoute = TAB_VOICE_ROUTES.find((route) =>
      route.keywords.some((kw) => strippedForTab.includes(kw) || norm.includes(kw))
    );

    if (matchedRoute) {
      cb.onNavigateTab(matchedRoute.tab);
      const msg = `تم فتح ${matchedRoute.labelAr}.`;
      setLastExecutedBanner(msg);
      pushHistory(`فتح: ${matchedRoute.labelAr}`, 'executed');
      cb.onNotify(msg, 'success');
      speakResponse(msg);
      return;
    }

    // 8. Unmatched speech
    const warn = `لم يتم التعرف على أمر مطابق لـ: "${clean}". جرب مثلاً: «افتح لوحة الشبكة» أو «افحص الملف الأخير».`;
    setLastExecutedBanner(warn);
    pushHistory('أمر غير معروف', 'unmatched');
    cb.onNotify(warn, 'warning');
  };

  const stopListening = () => {
    isListeningRef.current = false;
    setIsListening(false);
    setInterimTranscript('');
    if (recognitionRef.current) {
      try {
        recognitionRef.current.stop();
      } catch {}
    }
  };

  const startListening = () => {
    setErrorMsg(null);
    const Rec = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    if (!Rec) {
      setSpeechSupported(false);
      setErrorMsg('المتصفح الحالي لا يدعم واجهة Web Speech API (SpeechRecognition). استخدم Chrome أو Edge.');
      return;
    }

    // Unlock speechSynthesis cleanly on gesture
    try {
      if ('speechSynthesis' in window) {
        window.speechSynthesis.resume();
      }
    } catch {}

    if (isListeningRef.current) {
      stopListening();
      return;
    }

    try {
      const recognition = new Rec();
      recognition.lang = speechLang;
      recognition.interimResults = true;
      recognition.continuous = continuousMode;
      recognition.maxAlternatives = 2;

      recognition.onstart = () => {
        isListeningRef.current = true;
        setIsListening(true);
        setInterimTranscript('');
      };

      recognition.onresult = (event: any) => {
        let interim = '';
        for (let i = event.resultIndex; i < event.results.length; i++) {
          const res = event.results[i];
          const txt = res[0]?.transcript || '';
          if (res.isFinal) {
            setInterimTranscript('');
            void executeVoiceCommand(txt, res[0]?.confidence);
          } else {
            interim += txt;
          }
        }
        if (interim) setInterimTranscript(interim.trim());
      };

      recognition.onerror = (ev: any) => {
        if (ev?.error === 'not-allowed' || ev?.error === 'service-not-allowed') {
          setErrorMsg('تم رفض إذن الميكروفون؛ فعّل صلاحية الميكروفون من شريط العنوان.');
          continuousRef.current = false;
          setContinuousMode(false);
        } else if (ev?.error === 'no-speech') {
          setErrorMsg('لم يتم التقاط صوت واضح؛ اضغط وتحدث بصوت واضح.');
        } else if (ev?.error !== 'aborted') {
          setErrorMsg(`تنبيه التعرف الصوتي: ${ev?.error || 'غير معروف'}`);
        }
        isListeningRef.current = false;
        setIsListening(false);
      };

      recognition.onend = () => {
        isListeningRef.current = false;
        setIsListening(false);
        setInterimTranscript('');
        if (continuousRef.current) {
          window.setTimeout(() => {
            if (continuousRef.current && !isListeningRef.current) {
              startListening();
            }
          }, 250);
        }
      };

      recognitionRef.current = recognition;
      recognition.start();
    } catch (err: any) {
      isListeningRef.current = false;
      setIsListening(false);
      setErrorMsg(err?.message || 'تعذر بدء خدمة التعرف الصوتي Web Speech API.');
    }
  };

  if (!isOpen) return null;

  return (
    <div
      dir="rtl"
      className="fixed bottom-14 right-4 z-[65] w-[calc(100vw-2rem)] max-w-md rounded-3xl bg-gray-950/95 border border-[#D4AF37]/50 shadow-2xl shadow-black/80 backdrop-blur-xl overflow-hidden no-print"
    >
      {/* HUD Header */}
      <div className="px-4 py-3 bg-gray-900/90 border-b border-gray-800 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className={`w-8 h-8 rounded-xl flex items-center justify-center border shrink-0 ${
              isListening
                ? 'bg-emerald-500/20 border-emerald-400 text-emerald-300 animate-pulse'
                : 'bg-[#D4AF37]/15 border-[#D4AF37]/40 text-[#D4AF37]'
            }`}
          >
            <Command className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <h3 className="text-xs font-bold text-white truncate">
              التحكم الصوتي المباشر (Web Speech API)
            </h3>
            <p className="text-[10px] text-gray-400 font-mono truncate">
              {isListening ? `LISTENING (${speechLang})...` : `READY • TAB: ${activeTab.toUpperCase()}`}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <button
            type="button"
            onClick={() => setSpeakFeedback((v) => !v)}
            title={speakFeedback ? 'كتم الرد الصوتي للأوامر' : 'تفعيل الرد الصوتي للأوامر'}
            className="p-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-300 cursor-pointer"
          >
            {speakFeedback ? <Volume2 className="w-3.5 h-3.5 text-[#D4AF37]" /> : <VolumeX className="w-3.5 h-3.5 text-gray-500" />}
          </button>
          <button
            type="button"
            onClick={() => {
              stopListening();
              onToggleOpen(false);
            }}
            aria-label="إغلاق لوحة التحكم الصوتي"
            className="p-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-400 hover:text-white cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Main Controls Body */}
      <div className="p-4 space-y-3.5 max-h-[70vh] overflow-y-auto">
        {!speechSupported && (
          <div className="p-3 rounded-xl bg-amber-950/40 border border-amber-500/40 text-amber-200 text-[11px] flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <span>
              المتصفح الحالي لا يدعم واجهة SpeechRecognition؛ يمكنك استخدام أزرار الأوامر الفورية أدناه أو فتح المتصفح في Chrome.
            </span>
          </div>
        )}

        {/* Primary Listen Button + Language & Continuous Controls */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={startListening}
            disabled={!speechSupported}
            className={`flex-1 py-2.5 px-3 rounded-xl font-bold text-xs flex items-center justify-center gap-2 transition cursor-pointer disabled:opacity-40 ${
              isListening
                ? 'bg-red-600 hover:bg-red-500 text-white shadow-lg shadow-red-900/30'
                : 'bg-[#D4AF37] hover:opacity-90 text-gray-950 shadow-lg shadow-[#D4AF37]/20'
            }`}
          >
            {isListening ? <MicOff className="w-4 h-4" /> : <Mic className="w-4 h-4" />}
            <span>{isListening ? 'إيقاف الاستماع' : 'اضغط وأصدر أمراً صوتياً'}</span>
          </button>

          <select
            value={speechLang}
            onChange={(e) => setSpeechLang(e.target.value as 'ar-SA' | 'ar-IQ' | 'en-US')}
            aria-label="لغة التعرف الصوتي"
            className="px-2.5 py-2.5 rounded-xl bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-200 outline-none focus:border-[#D4AF37]"
          >
            <option value="ar-SA">AR-SA</option>
            <option value="ar-IQ">AR-IQ</option>
            <option value="en-US">EN-US</option>
          </select>
        </div>

        {/* Continuous mode switch */}
        <label className="flex items-center justify-between px-3 py-2 rounded-xl bg-gray-900/80 border border-gray-800 cursor-pointer text-[11px]">
          <span className="flex items-center gap-2 text-gray-300">
            <RefreshCw className={`w-3.5 h-3.5 text-emerald-400 ${continuousMode && isListening ? 'animate-spin' : ''}`} />
            <span>وضع الاستماع المستمر للأوامر المتتالية</span>
          </span>
          <input
            type="checkbox"
            checked={continuousMode}
            onChange={(e) => {
              const checked = e.target.checked;
              continuousRef.current = checked;
              setContinuousMode(checked);
            }}
            className="w-4 h-4 accent-[#D4AF37]"
          />
        </label>

        {/* Live Interim Recognition Box */}
        {(isListening || interimTranscript) && (
          <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/40 text-xs text-emerald-100">
            <div className="text-[10px] font-mono text-emerald-400 mb-1">LIVE SPEECH CAPTURE:</div>
            <div className="font-bold">
              {interimTranscript || 'تحدث الآن... (مثال: افتح لوحة الشبكة / افحص الملف الأخير)'}
            </div>
          </div>
        )}

        {/* Execution Status */}
        {lastExecutedBanner && (
          <div className="p-2.5 rounded-xl bg-gray-900 border border-[#D4AF37]/35 text-[11px] text-gray-200 flex items-start gap-2">
            <CheckCircle2 className="w-4 h-4 text-[#D4AF37] shrink-0 mt-0.5" />
            <span>{lastExecutedBanner}</span>
          </div>
        )}

        {errorMsg && (
          <div className="p-2.5 rounded-xl bg-red-950/35 border border-red-500/40 text-[11px] text-red-200 flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Interactive Voice Command Examples (Tap or Speak) */}
        <div className="space-y-2">
          <div className="text-[11px] font-bold text-gray-400 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#D4AF37]" />
            <span>أمثلة أوامر صوتية مدعومة (انطقها أو اضغط للتجربة):</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {[
              'افتح لوحة الشبكة',
              'افحص الملف الأخير',
              'افتح لوحة الثغرات',
              'افتح توزيع الأصول',
              'حدث التغذيات',
              'تقرير الحالة',
              'افحص الحافظة',
              'افتح المحادثة الصوتية',
            ].map((cmd) => (
              <button
                key={cmd}
                type="button"
                onClick={() => void executeVoiceCommand(cmd, 1)}
                className="px-2.5 py-1 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 hover:border-[#D4AF37]/60 text-[10px] text-gray-200 transition cursor-pointer"
              >
                «{cmd}»
              </button>
            ))}
          </div>
        </div>

        {/* Recent Recognized Commands History */}
        {history.length > 0 && (
          <div className="space-y-1.5 pt-1 border-t border-gray-800/80">
            <div className="text-[10px] font-mono text-gray-500 flex items-center gap-1">
              <Terminal className="w-3 h-3" />
              <span>سجل الأوامر الصوتية المنفذة</span>
            </div>
            <div className="space-y-1 max-h-32 overflow-y-auto">
              {history.map((item) => (
                <div
                  key={item.id}
                  className="px-2.5 py-1.5 rounded-lg bg-gray-900/70 border border-gray-800/80 flex items-center justify-between gap-2 text-[10px]"
                >
                  <div className="min-w-0">
                    <div className="text-white font-bold truncate">«{item.transcript}»</div>
                    <div
                      className={
                        item.status === 'executed' ? 'text-emerald-400' : 'text-amber-400'
                      }
                    >
                      {item.matchedLabel}
                      {typeof item.confidence === 'number' && item.confidence > 0
                        ? ` (${Math.round(item.confidence * 100)}%)`
                        : ''}
                    </div>
                  </div>
                  <span className="text-gray-500 font-mono shrink-0">{item.timestamp}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
