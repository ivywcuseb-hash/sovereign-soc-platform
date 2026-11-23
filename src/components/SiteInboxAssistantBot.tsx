import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bot,
  Check,
  Copy,
  Database,
  Inbox,
  Loader2,
  MessageSquare,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  Sparkles,
  Trash2,
  AlertTriangle,
  User as UserIcon,
} from 'lucide-react';
import { auth } from '../firebase';
import { apiUrl, safeReadJsonResponse } from '../utils/apiBase';
import type { SiteAssistantSnapshot } from '../../api/site-assistant';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface InboxMessage {
  id: string;
  role: 'user' | 'assistant';
  text: string;
  timestamp: string;
  model?: string;
  durationMs?: number;
}

interface InboxThread {
  id: string;
  subject: string;
  createdAt: string;
  updatedAt: string;
  messages: InboxMessage[];
  lastError?: {
    status: number;
    code?: string;
    message: string;
    failedUserText: string;
  } | null;
}

interface SiteInboxAssistantBotProps {
  siteSnapshot: SiteAssistantSnapshot;
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
  onNavigateToAuth?: () => void;
}

const STORAGE_KEY = 'sovereign_site_inbox_threads_v1';

const QUICK_PLATFORM_INQUIRIES: Array<{ label: string; prompt: string }> = [
  {
    label: 'خريطة أدوات المنصة',
    prompt: 'ما هي أبرز أدوات التحقيق الجنائي وأمن الشبكات المتوفرة فعلياً في المنصة وكيف أستخدمها؟',
  },
  {
    label: 'حالة جلستي الحالية',
    prompt: 'لخّص وضع الأدلة والقضايا والتغذيات الحية وسجل العمليات في جلستي الحالية بناءً على البيانات الفعلية فقط.',
  },
  {
    label: 'أمن الشبكات والتحليل الرقمي',
    prompt: 'اشرح كيف تسهم سجلات SPF وDMARC وفحص البصمات الرقمية SHA-256 في كشف التصيد والتلاعب بالملفات؟',
  },
  {
    label: 'تصدير التقارير الموثقة',
    prompt: 'ما هي خطوات إنشاء وتصدير التقرير الجنائي الموثق بصيغة PDF أو HTML مع ختم SHA-256؟',
  },
];

function readStoredThreads(): InboxThread[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (t): t is InboxThread =>
        Boolean(t && typeof t === 'object' && typeof t.id === 'string' && Array.isArray(t.messages))
    );
  } catch {
    return [];
  }
}

async function computeSha256Hex(text: string): Promise<string> {
  try {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  } catch {
    return '0'.repeat(64);
  }
}

export const SiteInboxAssistantBot: React.FC<SiteInboxAssistantBotProps> = ({
  siteSnapshot,
  onNotify,
  onRecordAudit,
  onNavigateToAuth,
}) => {
  const [threads, setThreads] = useState<InboxThread[]>(() => readStoredThreads());
  const [activeThreadId, setActiveThreadId] = useState<string | null>(() => {
    const initial = readStoredThreads();
    return initial[0]?.id ?? null;
  });
  const [draftMessage, setDraftMessage] = useState('');
  const [includeLiveContext, setIncludeLiveContext] = useState(true);
  const [isSending, setIsSending] = useState(false);
  const [inlineError, setInlineError] = useState<{
    status: number;
    code?: string;
    message: string;
    failedText?: string;
  } | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(threads.slice(0, 25)));
    } catch {
      // Ignore storage quota errors
    }
  }, [threads]);

  const activeThread = useMemo(
    () => threads.find((t) => t.id === activeThreadId) || null,
    [threads, activeThreadId]
  );

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeThread?.messages.length, inlineError]);

  const startNewThread = () => {
    setActiveThreadId(null);
    setInlineError(null);
  };

  const deleteThread = (threadId: string) => {
    setThreads((prev) => {
      const next = prev.filter((t) => t.id !== threadId);
      if (activeThreadId === threadId) {
        setActiveThreadId(next[0]?.id ?? null);
        setInlineError(null);
      }
      return next;
    });
  };

  const clearAllThreads = () => {
    setThreads([]);
    setActiveThreadId(null);
    setInlineError(null);
    onNotify('تم مسح سجل رسائل المساعد من هذه الجلسة.', 'success');
  };

  const handleCopyReply = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1800);
      onNotify('تم نسخ الرد إلى الحافظة.', 'success');
    } catch {
      onNotify('تعذر النسخ التلقائي إلى الحافظة.', 'warning');
    }
  };

  const sendMessageToAssistant = async (overrideText?: string, isRetry = false) => {
    if (isSending) return;
    const textToSend = (overrideText ?? draftMessage).trim();

    if (!textToSend) {
      setInlineError({
        status: 400,
        code: 'EMPTY_MESSAGE',
        message: 'يرجى إدخال رسالة أو استفسار صالح للمساعد قبل الإرسال.',
      });
      onNotify('يرجى كتابة رسالة قبل الإرسال.', 'warning');
      return;
    }

    if (textToSend.length > 2000) {
      setInlineError({
        status: 400,
        code: 'MESSAGE_TOO_LONG',
        message: 'طول الرسالة يتجاوز الحد الأقصى المسموح به (2000 حرف).',
      });
      return;
    }

    setInlineError(null);
    setIsSending(true);

    const nowIso = new Date().toISOString();
    const uidSuffix = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    let targetThreadId = activeThreadId;

    // Only append a new user bubble if this is not a retry of the already-visible last user message
    const existingThread = targetThreadId ? threads.find((t) => t.id === targetThreadId) : null;
    const rawPriorMessages = existingThread?.messages || [];
    const priorForHistory =
      isRetry &&
      rawPriorMessages.length > 0 &&
      rawPriorMessages[rawPriorMessages.length - 1].role === 'user' &&
      rawPriorMessages[rawPriorMessages.length - 1].text.trim() === textToSend
        ? rawPriorMessages.slice(0, -1)
        : rawPriorMessages;
    const historyForApi = priorForHistory
      .slice(-10)
      .map((m) => ({ role: m.role, text: m.text }));

    if (!existingThread) {
      targetThreadId = `inbox-${uidSuffix}`;
      const newThread: InboxThread = {
        id: targetThreadId,
        subject: textToSend.slice(0, 64) + (textToSend.length > 64 ? '...' : ''),
        createdAt: nowIso,
        updatedAt: nowIso,
        messages: [
          {
            id: `msg-u-${uidSuffix}`,
            role: 'user',
            text: textToSend,
            timestamp: nowIso,
          },
        ],
        lastError: null,
      };
      setThreads((prev) => [newThread, ...prev]);
      setActiveThreadId(targetThreadId);
    } else if (!isRetry) {
      const userMsg: InboxMessage = {
        id: `msg-u-${uidSuffix}`,
        role: 'user',
        text: textToSend,
        timestamp: nowIso,
      };
      setThreads((prev) =>
        prev.map((t) =>
          t.id === targetThreadId
            ? {
                ...t,
                updatedAt: nowIso,
                lastError: null,
                messages: [...t.messages, userMsg],
              }
            : t
        )
      );
    }

    if (!overrideText) {
      setDraftMessage('');
    }

    const resolveFreshIdToken = async (forceRefresh = false): Promise<string | null> => {
      try {
        if (typeof (auth as { authStateReady?: () => Promise<void> }).authStateReady === 'function') {
          await (auth as { authStateReady: () => Promise<void> }).authStateReady();
        }
        const currentUser = auth.currentUser;
        if (!currentUser) return null;

        let shouldForce = forceRefresh;
        if (!shouldForce && typeof currentUser.getIdTokenResult === 'function') {
          try {
            const tokenMeta = await currentUser.getIdTokenResult();
            const expMs = Date.parse(tokenMeta.expirationTime);
            if (Number.isFinite(expMs) && expMs - Date.now() < 60_000) {
              shouldForce = true;
            }
          } catch {
            // Fall back cleanly to standard getIdToken
          }
        }
        return await currentUser.getIdToken(shouldForce);
      } catch {
        return null;
      }
    };

    const callAssistantApi = async (bearerToken: string) => {
      const res = await fetch(apiUrl('/api/site-assistant'), {
        method: 'POST',
        cache: 'no-store',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Authorization: `Bearer ${bearerToken}`,
        },
        body: JSON.stringify({
          message: textToSend,
          history: historyForApi,
          siteSnapshot: includeLiveContext ? siteSnapshot : undefined,
        }),
      });
      const contentType = res.headers.get('content-type') || '';
      const parsed = await safeReadJsonResponse<{
        success?: boolean;
        reply?: string;
        model?: string;
        durationMs?: number;
        respondedAt?: string;
        error?: string;
        code?: string;
      }>(res);
      return { ...parsed, contentType };
    };

    try {
      const initialToken = await resolveFreshIdToken(isRetry);
      if (!initialToken) {
        const authErrMsg =
          'لا توجد جلسة مستخدم نشطة حالياً. يرجى تسجيل الدخول بحسابك أولاً أو تحديث الجلسة ثم إعادة المحاولة.';
        const errPayload = {
          status: 401,
          code: 'AUTH_REQUIRED',
          message: authErrMsg,
          failedUserText: textToSend,
        };
        setInlineError({
          status: 401,
          code: 'AUTH_REQUIRED',
          message: authErrMsg,
          failedText: textToSend,
        });
        setThreads((prev) =>
          prev.map((t) =>
            t.id === targetThreadId
              ? { ...t, updatedAt: new Date().toISOString(), lastError: errPayload }
              : t
          )
        );
        onNotify(authErrMsg, 'warning');
        return;
      }

      let parsed = await callAssistantApi(initialToken);

      // Self-heal stale service worker / transient proxy HTML response with a single automatic retry
      const isHtmlPayload = (p: typeof parsed) =>
        !p.isJson &&
        (p.contentType.toLowerCase().includes('text/html') ||
          /^<(?:!doctype|html)\b/i.test(p.rawText.trim()));

      if (isHtmlPayload(parsed)) {
        if (typeof navigator !== 'undefined' && 'serviceWorker' in navigator) {
          await navigator.serviceWorker
            .getRegistrations()
            .then((regs) => Promise.all(regs.map((r) => r.unregister().catch(() => false))))
            .catch(() => undefined);
        }
        await new Promise((resolve) => setTimeout(resolve, 450));
        parsed = await callAssistantApi(initialToken);
      }

      // Automatic refresh + single retry if the cached ID token expired in flight
      if (parsed.status === 401 && auth.currentUser) {
        const refreshedToken = await resolveFreshIdToken(true);
        if (refreshedToken) {
          parsed = await callAssistantApi(refreshedToken);
        }
      }

      const serverError =
        typeof parsed.data?.error === 'string' ? parsed.data.error.trim() : '';
      const replyText =
        typeof parsed.data?.reply === 'string' ? parsed.data.reply.trim() : '';

      if (serverError || !parsed.ok || !parsed.isJson || !replyText) {
        const status = parsed.status || 502;
        const trimmedRaw = parsed.rawText.trim();
        const looksLikeHtml =
          parsed.contentType.toLowerCase().includes('text/html') ||
          /^<(?:!doctype|html)\b/i.test(trimmedRaw);

        let errCode = parsed.data?.code;
        let errMsg = serverError;

        if (!errMsg) {
          if (status === 401) {
            errCode = errCode || 'INVALID_OR_EXPIRED_TOKEN';
            errMsg =
              'انتهت صلاحية رمز الجلسة أو تعذر التحقق منه. يرجى تحديث الجلسة أو تسجيل الدخول بحسابك مجدداً.';
          } else if (!parsed.isJson) {
            if (looksLikeHtml) {
              errCode = 'UNEXPECTED_HTML_RESPONSE';
              const titleMatch = trimmedRaw.match(/<title[^>]*>([^<]{1,100})<\/title>/i);
              const htmlTitle = titleMatch?.[1]?.trim();
              errMsg = `استجاب المسار /api/site-assistant بصفحة HTML بدلاً من JSON (HTTP ${status}${htmlTitle ? ` — ${htmlTitle}` : ''}). يرجى إعادة المحاولة أو تحديث الصفحة.`;
            } else if (!trimmedRaw) {
              errCode = 'EMPTY_RESPONSE_BODY';
              errMsg = `أعاد الخادم استجابة فارغة بدون بيانات JSON (HTTP ${status}). يرجى إعادة المحاولة.`;
            } else {
              errCode = 'NON_JSON_RESPONSE';
              errMsg = `أعاد الخادم استجابة غير صالحة وليست بصيغة JSON (HTTP ${status}): ${trimmedRaw.slice(0, 140)}`;
            }
          } else if (status === 404) {
            errCode = errCode || 'ENDPOINT_NOT_FOUND';
            errMsg = 'مسار مساعد المنصة (/api/site-assistant) غير متاح على هذا الخادم (HTTP 404).';
          } else if (parsed.ok && !replyText) {
            errCode = errCode || 'INVALID_REPLY_PAYLOAD';
            errMsg = `أعاد الخادم استجابة JSON صالحة (HTTP ${status}) لكنها لا تحتوي على نص رد من المساعد الذكي.`;
          } else if (status === 503) {
            errCode = errCode || 'SERVICE_UNAVAILABLE';
            errMsg = 'خدمة المساعد غير متاحة حالياً (503) — تحقق من إعداد GEMINI_API_KEY على الخادم.';
          } else if (status === 400) {
            errCode = errCode || 'BAD_REQUEST';
            errMsg = 'طلب غير صالح (400) — يرجى مراجعة نص الرسالة.';
          } else if (status === 429) {
            errCode = errCode || 'RATE_LIMITED';
            errMsg = 'تم تجاوز حد الطلبات المؤقت (429). يرجى الانتظار بضع لحظات ثم إعادة المحاولة.';
          } else {
            errCode = errCode || `HTTP_${status}`;
            errMsg = `تعذر الحصول على رد صالح من خادم المساعد الذكي (HTTP ${status}).`;
          }
        }

        const errPayload = {
          status,
          code: errCode,
          message: errMsg,
          failedUserText: textToSend,
        };

        setInlineError({
          status,
          code: errCode,
          message: errMsg,
          failedText: textToSend,
        });

        setThreads((prev) =>
          prev.map((t) =>
            t.id === targetThreadId
              ? { ...t, updatedAt: new Date().toISOString(), lastError: errPayload }
              : t
          )
        );
        onNotify(errMsg, status === 401 ? 'warning' : 'error');
        return;
      }

      const assistantMsg: InboxMessage = {
        id: `msg-a-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
        role: 'assistant',
        text: replyText,
        timestamp: parsed.data?.respondedAt || new Date().toISOString(),
        model: parsed.data?.model,
        durationMs: parsed.data?.durationMs,
      };

      setThreads((prev) =>
        prev.map((t) =>
          t.id === targetThreadId
            ? {
                ...t,
                updatedAt: assistantMsg.timestamp,
                lastError: null,
                messages: [...t.messages, assistantMsg],
              }
            : t
        )
      );

      const digest = await computeSha256Hex(`${textToSend}::${replyText}`);
      onRecordAudit({
        id: `site-bot-${Date.now()}`,
        fileName: `Site Assistant (${textToSend.slice(0, 28)})`,
        fileSize: `${replyText.length} chars`,
        verdict: `استجابة حقيقية (${parsed.data?.model || 'gemini-4-hydrogen'})`,
        score: 100,
        risk: 'منخفض',
        sha256: digest,
      });
    } catch {
      const networkErr = 'تعذر الوصول إلى مسار الخادم /api/site-assistant (خطأ شبكة 502).';
      setInlineError({
        status: 502,
        code: 'NETWORK_ERROR',
        message: networkErr,
        failedText: textToSend,
      });
      setThreads((prev) =>
        prev.map((t) =>
          t.id === targetThreadId
            ? {
                ...t,
                updatedAt: new Date().toISOString(),
                lastError: {
                  status: 502,
                  code: 'NETWORK_ERROR',
                  message: networkErr,
                  failedUserText: textToSend,
                },
              }
            : t
        )
      );
      onNotify(networkErr, 'error');
    } finally {
      setIsSending(false);
    }
  };

  const activeErrorBanner =
    inlineError ||
    (activeThread?.lastError
      ? {
          status: activeThread.lastError.status,
          code: activeThread.lastError.code,
          message: activeThread.lastError.message,
          failedText: activeThread.lastError.failedUserText,
        }
      : null);

  return (
    <div dir="rtl" className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="w-11 h-11 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37] shrink-0">
              <MessageSquare className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">
                مساعد ورسائل المنصة الذكي (Site &amp; Inbox Assistant Bot)
              </h2>
              <p className="text-xs text-gray-400 mt-1">
                بوابة مراسلات ذكية متصلة بمسار{' '}
                <span className="font-mono text-emerald-400" dir="ltr">/api/site-assistant</span>{' '}
                للإجابة عن استفسارات المنصة وأدواتها وبيانات جلستك الحقيقية، وكذلك الأسئلة العامة والتقنية والبرمجية والأمنية عبر Gemini API بدون أي ردود وهمية.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex items-center gap-2 px-3 py-1.5 rounded-xl bg-gray-950 border border-gray-800 text-xs text-gray-300 cursor-pointer">
              <input
                type="checkbox"
                checked={includeLiveContext}
                onChange={(e) => setIncludeLiveContext(e.target.checked)}
                className="accent-[#D4AF37]"
              />
              <Database className="w-3.5 h-3.5 text-emerald-400" />
              <span>ربط سياق الجلسة الفعلي</span>
            </label>
          </div>
        </div>

        {/* Real Live Session Snapshot Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 pt-2 border-t border-gray-800/80 text-xs">
          <div className="rounded-xl bg-gray-950 border border-gray-800 px-3 py-2">
            <div className="text-[10px] text-gray-500">الأدلة الموثقة</div>
            <div className="font-bold text-white font-mono mt-0.5">{siteSnapshot.counts?.evidence ?? 0}</div>
          </div>
          <div className="rounded-xl bg-gray-950 border border-gray-800 px-3 py-2">
            <div className="text-[10px] text-gray-500">القضايا المفتوحة</div>
            <div className="font-bold text-white font-mono mt-0.5">{siteSnapshot.counts?.investigations ?? 0}</div>
          </div>
          <div className="rounded-xl bg-gray-950 border border-gray-800 px-3 py-2">
            <div className="text-[10px] text-gray-500">التغذيات الحية</div>
            <div className="font-bold text-emerald-400 font-mono mt-0.5">{siteSnapshot.counts?.liveFeeds ?? 0}</div>
          </div>
          <div className="rounded-xl bg-gray-950 border border-gray-800 px-3 py-2">
            <div className="text-[10px] text-gray-500">سجلات العمليات</div>
            <div className="font-bold text-white font-mono mt-0.5">{siteSnapshot.counts?.auditLogs ?? 0}</div>
          </div>
          <div className="rounded-xl bg-gray-950 border border-gray-800 px-3 py-2 col-span-2 sm:col-span-1">
            <div className="text-[10px] text-gray-500">الأدوات المتاحة لك</div>
            <div className="font-bold text-[#D4AF37] font-mono mt-0.5">
              {siteSnapshot.counts?.unlockedTools ?? siteSnapshot.availableTools?.length ?? 0}
            </div>
          </div>
        </div>
      </div>

      {/* Main Inbox & Chat Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Sidebar: Real Inbox Threads */}
        <div className="lg:col-span-4 rounded-2xl bg-gray-900 border border-gray-800 p-4 flex flex-col gap-3 max-h-[650px]">
          <div className="flex items-center justify-between gap-2 pb-3 border-b border-gray-800">
            <div className="flex items-center gap-2 text-sm font-bold text-white">
              <Inbox className="w-4 h-4 text-[#D4AF37]" />
              <span>صندوق الرسائل ({threads.length})</span>
            </div>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={startNewThread}
                className="px-2.5 py-1.5 rounded-lg bg-[#D4AF37] text-gray-950 text-[11px] font-bold hover:opacity-90 transition flex items-center gap-1 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>رسالة جديدة</span>
              </button>
              {threads.length > 0 && (
                <button
                  type="button"
                  onClick={clearAllThreads}
                  title="مسح جميع المحادثات"
                  className="p-1.5 rounded-lg bg-gray-950 border border-gray-800 text-gray-400 hover:text-red-400 transition cursor-pointer"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </div>

          {threads.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center text-center py-10 px-4 text-xs text-gray-500 space-y-2 border border-dashed border-gray-800 rounded-xl">
              <MessageSquare className="w-7 h-7 text-gray-700" />
              <p className="font-bold text-gray-400">صندوق الرسائل فارغ</p>
              <p>أرسل استفسارك الأول حول المنصة أو أي سؤال تقني أو عام لبدء محادثة جديدة.</p>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto space-y-2 pl-1">
              {threads.map((thread) => {
                const isActive = thread.id === activeThreadId;
                return (
                  <div
                    key={thread.id}
                    className={`rounded-xl border p-3 transition flex items-start justify-between gap-2 cursor-pointer ${
                      isActive
                        ? 'bg-[#D4AF37]/10 border-[#D4AF37]/50'
                        : 'bg-gray-950 border-gray-800 hover:border-gray-700'
                    }`}
                    onClick={() => {
                      setActiveThreadId(thread.id);
                      setInlineError(null);
                    }}
                  >
                    <div className="min-w-0 flex-1 space-y-1">
                      <div className="text-xs font-bold text-white truncate">{thread.subject}</div>
                      <div className="flex items-center gap-2 text-[10px] text-gray-400">
                        <span>{thread.messages.length} رسالة</span>
                        <span>•</span>
                        <span>{new Date(thread.updatedAt).toLocaleTimeString('ar-SA')}</span>
                        {thread.lastError && (
                          <span className="px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 font-mono">
                            HTTP {thread.lastError.status}
                          </span>
                        )}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        deleteThread(thread.id);
                      }}
                      title="حذف المحادثة"
                      className="p-1 rounded text-gray-500 hover:text-red-400 transition shrink-0"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Main Chat / Response Pane */}
        <div className="lg:col-span-8 rounded-2xl bg-gray-900 border border-gray-800 flex flex-col min-h-[540px] max-h-[650px] overflow-hidden">
          {/* Messages Scroll Area */}
          <div className="flex-1 overflow-y-auto p-5 space-y-4">
            {(!activeThread || activeThread.messages.length === 0) ? (
              <div className="h-full flex flex-col items-center justify-center text-center py-8 px-4 space-y-5">
                <div className="w-14 h-14 rounded-2xl bg-[#D4AF37]/10 border border-[#D4AF37]/30 flex items-center justify-center text-[#D4AF37]">
                  <Bot className="w-7 h-7" />
                </div>
                <div className="space-y-1.5 max-w-lg">
                  <h3 className="text-sm font-bold text-white">
                    مرحباً بك في مساعد ورسائل المنصة الذكي
                  </h3>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    اطرح أي سؤال حول أدوات المنصة وبيانات جلستك الحالية، أو اسأل في أي موضوع عام أو تقني أو برمجي أو في الأمن السيبراني والتحليل الجنائي الرقمي. سيتم إرسال استفسارك مباشرة إلى الخادم دون أي ردود افتراضية.
                  </p>
                </div>

                {/* Quick Real Prompt Shortcuts */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 w-full max-w-xl text-right">
                  {QUICK_PLATFORM_INQUIRIES.map((item) => (
                    <button
                      key={item.label}
                      type="button"
                      disabled={isSending}
                      onClick={() => void sendMessageToAssistant(item.prompt)}
                      className="p-3 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-800 hover:border-[#D4AF37]/40 transition text-right space-y-1 cursor-pointer disabled:opacity-50"
                    >
                      <div className="text-xs font-bold text-[#D4AF37] flex items-center gap-1.5">
                        <Sparkles className="w-3.5 h-3.5 shrink-0" />
                        <span>{item.label}</span>
                      </div>
                      <div className="text-[11px] text-gray-400 line-clamp-2">{item.prompt}</div>
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <>
                {activeThread.messages.map((msg) => {
                  const isUser = msg.role === 'user';
                  return (
                    <div
                      key={msg.id}
                      className={`flex items-start gap-3 ${isUser ? 'flex-row' : 'flex-row-reverse'}`}
                    >
                      <div
                        className={`w-8 h-8 rounded-xl border flex items-center justify-center shrink-0 ${
                          isUser
                            ? 'bg-[#D4AF37]/15 border-[#D4AF37]/40 text-[#D4AF37]'
                            : 'bg-emerald-500/15 border-emerald-500/35 text-emerald-400'
                        }`}
                      >
                        {isUser ? <UserIcon className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                      </div>

                      <div
                        className={`flex-1 max-w-[88%] rounded-2xl border p-3.5 space-y-2 ${
                          isUser
                            ? 'bg-gray-950 border-gray-800 text-gray-100'
                            : 'bg-emerald-950/20 border-emerald-500/25 text-gray-100'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 text-[10px] text-gray-400">
                          <span className="font-bold">
                            {isUser ? 'أنت' : 'مساعد المنصة الذكي'}
                          </span>
                          <div className="flex items-center gap-2">
                            {msg.model && (
                              <span className="px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 font-mono">
                                {msg.model}
                                {typeof msg.durationMs === 'number' ? ` • ${msg.durationMs}ms` : ''}
                              </span>
                            )}
                            <span>{new Date(msg.timestamp).toLocaleTimeString('ar-SA')}</span>
                            {!isUser && (
                              <button
                                type="button"
                                onClick={() => void handleCopyReply(msg.id, msg.text)}
                                className="text-gray-400 hover:text-[#D4AF37] transition"
                                title="نسخ الرد"
                              >
                                {copiedId === msg.id ? (
                                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3.5 h-3.5" />
                                )}
                              </button>
                            )}
                          </div>
                        </div>
                        <div className="text-xs leading-relaxed whitespace-pre-wrap break-words">
                          {msg.text}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </>
            )}

            {/* Explicit HTTP Error Banner (400 / 502 / 503) — Zero Fake Reply */}
            {activeErrorBanner && (
              <div className="rounded-xl bg-red-500/10 border border-red-500/35 p-4 text-xs text-red-200 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 font-bold text-red-300">
                    <AlertTriangle className="w-4 h-4 shrink-0" />
                    <span>تعذر إتمام الطلب من الخادم</span>
                  </div>
                  <span className="px-2 py-0.5 rounded bg-red-500/20 border border-red-500/40 font-mono text-[10px]" dir="ltr">
                    HTTP {activeErrorBanner.status}
                    {activeErrorBanner.code ? ` • ${activeErrorBanner.code}` : ''}
                  </span>
                </div>
                <p className="text-red-100 leading-relaxed">{activeErrorBanner.message}</p>
                <div className="flex flex-wrap items-center gap-2">
                  {activeErrorBanner.failedText && (
                    <button
                      type="button"
                      disabled={isSending}
                      onClick={() => void sendMessageToAssistant(activeErrorBanner.failedText, true)}
                      className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-200 text-[11px] font-bold inline-flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className="w-3.5 h-3.5" />
                      <span>
                        {activeErrorBanner.status === 401
                          ? 'تحديث الجلسة وإعادة الإرسال'
                          : 'إعادة إرسال الرسالة'}
                      </span>
                    </button>
                  )}
                  {activeErrorBanner.status === 401 && onNavigateToAuth && (
                    <button
                      type="button"
                      onClick={onNavigateToAuth}
                      className="px-3 py-1.5 rounded-lg bg-[#D4AF37]/20 hover:bg-[#D4AF37]/30 border border-[#D4AF37]/40 text-[#D4AF37] text-[11px] font-bold inline-flex items-center gap-1.5 transition cursor-pointer"
                    >
                      <UserIcon className="w-3.5 h-3.5" />
                      <span>الانتقال إلى تسجيل الدخول / الحساب</span>
                    </button>
                  )}
                </div>
              </div>
            )}

            {isSending && (
              <div className="flex items-center gap-2 text-xs text-[#D4AF37] bg-gray-950 border border-gray-800 rounded-xl px-4 py-3">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>جاري معالجة استفسارك عبر /api/site-assistant...</span>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Composer Footer */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void sendMessageToAssistant();
            }}
            className="p-4 border-t border-gray-800 bg-gray-950 space-y-2"
          >
            <div className="flex items-end gap-2.5">
              <textarea
                dir="rtl"
                rows={2}
                maxLength={2000}
                value={draftMessage}
                onChange={(e) => setDraftMessage(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    void sendMessageToAssistant();
                  }
                }}
                placeholder="اكتب رسالتك أو أي سؤال حول المنصة أو البرمجة أو الأمن السيبراني أو المواضيع العامة... (Enter للإرسال، Shift+Enter لسطر جديد)"
                className="flex-1 bg-gray-900 border border-gray-800 focus:border-[#D4AF37] rounded-xl px-3.5 py-2.5 text-xs text-white placeholder-gray-500 outline-none resize-none"
              />
              <button
                type="submit"
                disabled={isSending}
                className="px-4 py-3 rounded-xl bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold text-xs shadow hover:opacity-95 transition flex items-center gap-2 shrink-0 cursor-pointer disabled:opacity-50"
              >
                {isSending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
                <span>إرسال</span>
              </button>
            </div>
            <div className="flex items-center justify-between text-[10px] text-gray-500">
              <span className="flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-emerald-400" />
                <span>المسار السحابي: POST /api/site-assistant • استجابات حقيقية فقط</span>
              </span>
              <span className="font-mono" dir="ltr">
                {draftMessage.length} / 2000
              </span>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};
