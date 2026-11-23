import React, { useEffect, useState } from 'react';
import {
  Lock,
  Unlock,
  Crown,
  CheckCircle2,
  X,
  Copy,
  ShieldCheck,
  Users,
  RefreshCw,
  Ban,
  UserCheck,
  Search,
  SlidersHorizontal,
  RotateCcw,
  ExternalLink,
  Megaphone,
  Wrench,
  AlertTriangle,
  AlertOctagon,
  Info,
  Power,
  Send,
} from 'lucide-react';
import {
  collection,
  onSnapshot,
} from 'firebase/firestore';
import { db, handleFirestoreError, OperationType } from '../firebase';
import {
  NAV_TABS_META,
  NAV_GROUP_ORDER,
  renderTabIcon,
  type AppTabId,
  type NavGroupId,
} from './LayoutCustomizer';
import {
  DEFAULT_LOCKED_TOOLS,
  isSubscriptionActive,
  saveLockedToolsConfigToFirestore,
  writeLocalLockedToolsBackup,
  sanitizeLockedToolsList,
  readAllLocalUserSubscriptionsBackup,
  saveUserSubscriptionToFirestoreOrLocal,
  revokeUserSubscriptionInFirestoreOrLocal,
  OWNER_EMAILS,
  OWNER_UIDS,
  type SovereignAccessState,
  type SubscriptionPlanId,
  type UserSubscriptionRecord,
} from '../utils/subscriptionAccess';
import {
  ANNOUNCEMENT_TYPE_META,
  DEFAULT_PLATFORM_SITE_CONTROLS,
  GROUP_LABELS_BY_ID,
  MAX_ANNOUNCEMENT_LENGTH,
  MAX_MAINTENANCE_MESSAGE_LENGTH,
  savePlatformSiteControlsToFirestore,
  type AnnouncementType,
  type PlatformSiteControls,
  type TabMaintenanceStatus,
} from '../utils/platformControls';

interface SubscriptionPaywallModalProps {
  isOpen: boolean;
  isOwner?: boolean;
  isPro?: boolean;
  requestedTab: AppTabId | null;
  userUid: string;
  userEmail: string;
  subscription: UserSubscriptionRecord | null;
  onClose: () => void;
  onOpenProfile: () => void;
  onNotify: (msg: string, type?: 'success' | 'error' | 'warning') => void;
}

export const SubscriptionPaywallModal: React.FC<SubscriptionPaywallModalProps> = ({
  isOpen,
  isOwner,
  isPro,
  requestedTab,
  userUid,
  userEmail,
  subscription,
  onClose,
  onOpenProfile,
  onNotify,
}) => {
  const isExemptOwnerOrPro =
    Boolean(isOwner) ||
    Boolean(isPro) ||
    OWNER_UIDS.has((userUid || '').trim()) ||
    OWNER_EMAILS.has((userEmail || '').trim().toLowerCase());

  if (!isOpen || isExemptOwnerOrPro) return null;

  const tabMeta = requestedTab ? NAV_TABS_META.find((t) => t.id === requestedTab) : null;

  const copyUid = () => {
    navigator.clipboard?.writeText(userUid);
    onNotify('تم نسخ معرف المستخدم (UID) بنجاح.', 'success');
  };

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center p-4 bg-black/80 backdrop-blur-md no-print" dir="rtl">
      <div className="max-w-lg w-full bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5 shadow-2xl">
        <div className="flex items-start justify-between gap-3 pb-4 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-11 h-11 rounded-xl bg-amber-500/15 border border-amber-500/40 flex items-center justify-center text-amber-400 shrink-0">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">أداة مدفوعة — يتطلب تفعيل الاشتراك</h3>
              <p className="text-xs text-gray-400 mt-0.5">
                {tabMeta ? `${tabMeta.label} (${tabMeta.groupLabel})` : 'وحدة تحليل متقدمة'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="إغلاق"
            className="p-1.5 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-800 text-gray-400 hover:text-white transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 space-y-2.5 text-xs">
          <p className="text-gray-300 leading-relaxed">
            هذه الأداة متاحة للمشتركين في الباقات المدفوعة (<span className="text-[#D4AF37] font-bold">Pro / Enterprise</span>) أو لحسابات الإدارة المعتمدة فقط.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-1 text-[11px] text-gray-400">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>لوحات SOC والثغرات KEV</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>محلل الباينري و APK و PCAP</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>فاحص الفيروسات و OSINT و YARA</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>المساعد الذكي والصوتي الحي</span>
            </div>
          </div>
        </div>

        <div className="p-4 rounded-xl bg-gray-950/70 border border-gray-800 space-y-2 text-xs">
          <div className="flex items-center justify-between gap-2">
            <span className="text-gray-500">حالة الاشتراك الحالية:</span>
            <span className="px-2 py-0.5 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300 font-bold text-[11px]">
              {subscription?.status === 'expired'
                ? 'منتهي الصلاحية'
                : subscription?.status === 'revoked'
                ? 'موقوف'
                : 'غير مشترك (مجاني)'}
            </span>
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="text-gray-500">البريد المسجل:</span>
            <span className="text-gray-200 font-mono text-[11px] truncate" dir="ltr">{userEmail || '—'}</span>
          </div>
          <div className="flex items-center justify-between gap-2 pt-1">
            <span className="text-gray-500 shrink-0">معرّف الحساب (UID):</span>
            <div className="flex items-center gap-1.5 min-w-0">
              <code className="text-[11px] font-mono text-[#D4AF37] truncate" dir="ltr">{userUid}</code>
              <button
                type="button"
                onClick={copyUid}
                className="px-2 py-1 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-700 text-gray-300 text-[10px] font-bold flex items-center gap-1 shrink-0 cursor-pointer"
              >
                <Copy className="w-3 h-3" />
                نسخ
              </button>
            </div>
          </div>
        </div>

        <p className="text-[11px] text-gray-400 leading-relaxed">
          لتفعيل الاشتراك لحسابك، أرسل معرّف الـ <span className="font-mono text-gray-200">UID</span> أعلاه لمالك المنصة ليتم تفعيله مباشرة في Firestore، وسيتاح الوصول لك فوراً وبشكل تلقائي.
        </p>

        <div className="flex flex-wrap gap-2.5 pt-1">
          <button
            type="button"
            onClick={() => {
              onClose();
              onOpenProfile();
            }}
            className="flex-1 py-2.5 px-4 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition cursor-pointer flex items-center justify-center gap-1.5"
          >
            <Crown className="w-4 h-4" />
            عرض حالة الحساب والاشتراك
          </button>
          <button
            type="button"
            onClick={onClose}
            className="py-2.5 px-4 bg-gray-800 hover:bg-gray-700 text-gray-200 font-bold text-xs rounded-xl transition cursor-pointer"
          >
            إغلاق
          </button>
        </div>
      </div>
    </div>
  );
};

interface SubscriptionInlineGateProps {
  tabId: AppTabId;
  isOwner?: boolean;
  isPro?: boolean;
  onOpenSubscriptionModal: () => void;
  onBackToDashboard: () => void;
}

export const SubscriptionInlineGate: React.FC<SubscriptionInlineGateProps> = ({
  tabId,
  isOwner,
  isPro,
  onOpenSubscriptionModal,
  onBackToDashboard,
}) => {
  if (isOwner || isPro) return null;
  const tabMeta = NAV_TABS_META.find((t) => t.id === tabId);
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 text-center space-y-4">
      <div className="w-12 h-12 rounded-xl bg-amber-500/15 border border-amber-500/40 flex items-center justify-center text-amber-400 mx-auto">
        <Lock className="w-6 h-6" />
      </div>
      <div className="space-y-1.5">
        <h3 className="text-base font-bold text-white">
          {tabMeta?.label || 'أداة متقدمة'} — مقفلة (اشتراك مدفوع)
        </h3>
        <p className="text-xs text-gray-400 max-w-md mx-auto leading-relaxed">
          الوصول إلى هذه الوحدة يتطلب اشتراكاً فعالاً في Firestore أو صلاحية إدارة معتمدة.
        </p>
      </div>
      <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
        <button
          type="button"
          onClick={onOpenSubscriptionModal}
          className="px-5 py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition cursor-pointer inline-flex items-center gap-1.5"
        >
          <Crown className="w-4 h-4" />
          تفاصيل التفعيل والاشتراك
        </button>
        <button
          type="button"
          onClick={onBackToDashboard}
          className="px-4 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 font-bold text-xs rounded-xl transition cursor-pointer"
        >
          العودة للوحة الرئيسية
        </button>
      </div>
    </div>
  );
};

interface MaintenanceModeNoticeProps {
  status: TabMaintenanceStatus;
  isAdminPreview?: boolean;
  onExitAdminPreview?: () => void;
  onBackToSafeTab: () => void;
  backButtonLabel?: string;
}

export const MaintenanceModeNotice: React.FC<MaintenanceModeNoticeProps> = ({
  status,
  isAdminPreview,
  onExitAdminPreview,
  onBackToSafeTab,
  backButtonLabel = 'العودة للوحة الرئيسية',
}) => {
  return (
    <div className="bg-gray-900 border border-amber-500/40 rounded-2xl p-8 text-center space-y-5 shadow-2xl">
      <div className="w-14 h-14 rounded-2xl bg-amber-500/15 border border-amber-500/40 flex items-center justify-center text-amber-400 mx-auto">
        <Wrench className="w-7 h-7" />
      </div>
      <div className="space-y-2">
        <div className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg bg-amber-500/15 border border-amber-500/35 text-amber-300 text-[11px] font-bold">
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>تحت الصيانة المؤقتة</span>
        </div>
        <h3 className="text-lg font-bold text-white">
          {status.scope === 'group'
            ? `قسم "${status.groupLabel}" في وضع الصيانة المؤقت`
            : `أداة "${status.toolLabel}" في وضع الصيانة المؤقت`}
        </h3>
        {status.scope === 'group' && (
          <p className="text-xs text-gray-400">
            الوحدة المطلوبة: <span className="text-gray-200 font-bold">{status.toolLabel}</span>
          </p>
        )}
      </div>

      <div className="max-w-xl mx-auto p-4 rounded-xl bg-gray-950 border border-gray-800 text-xs text-gray-200 leading-relaxed whitespace-pre-wrap">
        {status.message}
      </div>

      {status.updatedAt && (
        <div className="text-[11px] font-mono text-gray-500" dir="ltr">
          Last Updated: {new Date(status.updatedAt).toLocaleString('ar-SA')}
        </div>
      )}

      <div className="flex flex-wrap items-center justify-center gap-3 pt-1">
        {isAdminPreview && onExitAdminPreview && (
          <button
            type="button"
            onClick={onExitAdminPreview}
            className="px-5 py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition cursor-pointer inline-flex items-center gap-1.5"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>إنهاء المعاينة ومتابعة عرض الأداة (صلاحية الأدمن)</span>
          </button>
        )}
        <button
          type="button"
          onClick={onBackToSafeTab}
          className="px-5 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-100 font-bold text-xs rounded-xl transition cursor-pointer"
        >
          {backButtonLabel}
        </button>
      </div>
    </div>
  );
};

interface AdminUserSummary {
  uid: string;
  email: string;
  displayName?: string;
  role?: string;
  createdAt?: string;
}

interface AdminSubscriptionManagerProps {
  currentUserUid: string;
  accessState: SovereignAccessState;
  siteControls?: PlatformSiteControls;
  siteControlsLoaded?: boolean;
  requestedAdminTab?: 'tools' | 'announcement' | 'maintenance' | 'users' | null;
  onPaidTabsSaved?: (nextLockedTools: AppTabId[]) => void;
  onLockedToolsSaved?: (nextLockedTools: AppTabId[]) => void;
  onSiteControlsSaved?: (nextControls: PlatformSiteControls) => void;
  onOpenTool?: (tabId: AppTabId) => void;
  onNotify: (msg: string, type?: 'success' | 'error' | 'warning') => void;
}

export const AdminSubscriptionManager: React.FC<AdminSubscriptionManagerProps> = ({
  currentUserUid,
  accessState,
  siteControls = DEFAULT_PLATFORM_SITE_CONTROLS,
  siteControlsLoaded = false,
  requestedAdminTab = null,
  onPaidTabsSaved,
  onLockedToolsSaved,
  onSiteControlsSaved,
  onOpenTool,
  onNotify,
}) => {
  const [ownerConsoleTab, setOwnerConsoleTab] = useState<
    'tools' | 'announcement' | 'maintenance' | 'users'
  >('tools');
  const [usersList, setUsersList] = useState<AdminUserSummary[]>([]);
  const [subsMap, setSubsMap] = useState<Record<string, UserSubscriptionRecord>>(() =>
    readAllLocalUserSubscriptionsBackup()
  );
  const [loading, setLoading] = useState(true);
  const [targetUid, setTargetUid] = useState('');
  const [targetEmail, setTargetEmail] = useState('');
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlanId>('pro');
  const [durationDays, setDurationDays] = useState<number>(0);
  const [searchTerm, setSearchTerm] = useState('');
  const [toolSearchTerm, setToolSearchTerm] = useState('');
  const [savingUid, setSavingUid] = useState<string | null>(null);
  const [savingToolId, setSavingToolId] = useState<string | null>(null);
  const [lastSavedInfo, setLastSavedInfo] = useState<{
    message: string;
    savedAt: string;
    syncedToCloud: boolean;
  } | null>(null);
  const [lastSubSavedInfo, setLastSubSavedInfo] = useState<{
    message: string;
    savedAt: string;
    syncedToCloud: boolean;
  } | null>(null);

  // Firestore-backed Announcement Banner & Maintenance Mode States
  const [draftAnnouncementEnabled, setDraftAnnouncementEnabled] = useState<boolean>(
    siteControls.announcementEnabled
  );
  const [draftAnnouncementText, setDraftAnnouncementText] = useState<string>(
    siteControls.announcementText
  );
  const [draftAnnouncementType, setDraftAnnouncementType] = useState<AnnouncementType>(
    siteControls.announcementType
  );
  const [savingAnnouncement, setSavingAnnouncement] = useState<boolean>(false);
  const [announcementFeedback, setAnnouncementFeedback] = useState<{
    ok: boolean;
    message: string;
    savedAt: string;
  } | null>(null);

  const [draftMaintenanceTools, setDraftMaintenanceTools] = useState<AppTabId[]>(
    siteControls.maintenanceTools
  );
  const [draftMaintenanceGroups, setDraftMaintenanceGroups] = useState<NavGroupId[]>(
    siteControls.maintenanceGroups
  );
  const [draftMaintenanceMessage, setDraftMaintenanceMessage] = useState<string>(
    siteControls.maintenanceMessage
  );
  const [maintenanceToolSearch, setMaintenanceToolSearch] = useState<string>('');
  const [savingMaintenanceKey, setSavingMaintenanceKey] = useState<string | null>(null);
  const [maintenanceFeedback, setMaintenanceFeedback] = useState<{
    ok: boolean;
    message: string;
    savedAt: string;
  } | null>(null);

  useEffect(() => {
    if (requestedAdminTab) {
      setOwnerConsoleTab(requestedAdminTab);
    }
  }, [requestedAdminTab]);

  useEffect(() => {
    setDraftAnnouncementEnabled(siteControls.announcementEnabled);
    setDraftAnnouncementText(siteControls.announcementText);
    setDraftAnnouncementType(siteControls.announcementType);
    setDraftMaintenanceTools(siteControls.maintenanceTools);
    setDraftMaintenanceGroups(siteControls.maintenanceGroups);
    setDraftMaintenanceMessage(siteControls.maintenanceMessage);
  }, [siteControls]);

  useEffect(() => {
    if (!accessState.isAdminOrOwner) return;

    const unsubUsers = onSnapshot(
      collection(db, 'users'),
      (snap) => {
        const list: AdminUserSummary[] = [];
        snap.forEach((d) => {
          const data = d.data();
          list.push({
            uid: data.uid || d.id,
            email: data.email || '',
            displayName: data.displayName || '',
            role: data.role || 'analyst',
            createdAt: data.createdAt || '',
          });
        });
        list.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
        setUsersList(list);
        setLoading(false);
      },
      (err) => {
        setLoading(false);
        console.warn('Admin users list error:', err);
        try {
          handleFirestoreError(err, OperationType.LIST, 'users');
        } catch {}
      }
    );

    const unsubSubs = onSnapshot(
      collection(db, 'subscriptions'),
      (snap) => {
        const nextMap: Record<string, UserSubscriptionRecord> = {
          ...readAllLocalUserSubscriptionsBackup(),
        };
        snap.forEach((d) => {
          nextMap[d.id] = d.data() as UserSubscriptionRecord;
        });
        setSubsMap(nextMap);
      },
      (err: any) => {
        const msg = String(err?.message || '');
        if (err?.code === 'permission-denied' || msg.toLowerCase().includes('permission')) {
          setSubsMap(readAllLocalUserSubscriptionsBackup());
          return;
        }
        console.warn('Admin subscriptions list error:', err);
      }
    );

    return () => {
      unsubUsers();
      unsubSubs();
    };
  }, [accessState.isAdminOrOwner]);

  if (!accessState.isAdminOrOwner) return null;

  const persistLockedTools = async (nextTabs: AppTabId[], actionKey: string, successMessage: string) => {
    setSavingToolId(actionKey);
    const sanitized = sanitizeLockedToolsList(nextTabs);
    const notifySavedState = onLockedToolsSaved || onPaidTabsSaved;
    const immediateTimestamp = new Date().toISOString();

    // 1. Apply immediately to localStorage + UI state so toggling works instantaneously
    writeLocalLockedToolsBackup(sanitized);
    notifySavedState?.(sanitized);
    setLastSavedInfo({
      message: successMessage,
      savedAt: immediateTimestamp,
      syncedToCloud: false,
    });

    try {
      // 2. Quietly sync with Firestore
      const result = await saveLockedToolsConfigToFirestore(sanitized, currentUserUid);
      if (result.syncedToCloud) {
        setLastSavedInfo({
          message: successMessage,
          savedAt: result.updatedAt,
          syncedToCloud: true,
        });
        onNotify(`${successMessage} (تم الحفظ في Firestore)`, 'success');
      } else {
        setLastSavedInfo({
          message: `${successMessage} — تم الحفظ محلياً لحين تحديث قواعد Firestore`,
          savedAt: result.updatedAt,
          syncedToCloud: false,
        });
        onNotify(`${successMessage} (تم الحفظ محلياً لحين تحديث قواعد Firestore)`, 'warning');
      }
    } finally {
      setSavingToolId(null);
    }
  };

  const toggleToolPaidStatus = (tabId: AppTabId, label: string) => {
    if (tabId === 'profile') return;
    const currentlyLocked = accessState.isToolInLockedList(tabId);
    const currentList = [...accessState.lockedTools];
    const nextList = currentlyLocked
      ? currentList.filter((id) => id !== tabId)
      : [...currentList, tabId];
    const message = currentlyLocked
      ? `تم فتح أداة "${label}" مجاناً لجميع المستخدمين.`
      : `تم قفل أداة "${label}" لغير المشتركين (تبقى مفتوحة لك مباشرة).`;
    void persistLockedTools(nextList, tabId, message);
  };

  const grantSubscription = async (
    uid: string,
    email: string,
    plan: SubscriptionPlanId,
    days: number
  ) => {
    const cleanUid = uid.trim();
    if (!cleanUid || !/^[a-zA-Z0-9_-]{1,128}$/.test(cleanUid)) {
      onNotify('يرجى إدخال معرّف UID صالح.', 'warning');
      return;
    }
    setSavingUid(cleanUid);
    try {
      const result = await saveUserSubscriptionToFirestoreOrLocal({
        uid: cleanUid,
        email,
        plan,
        durationDays: days,
        grantedByUid: currentUserUid,
        existingRecord: subsMap[cleanUid] || null,
      });

      setSubsMap((prev) => ({
        ...prev,
        [cleanUid]: result.record,
      }));

      const label = `تم تفعيل اشتراك (${plan.toUpperCase()}) للمعرّف ${cleanUid}`;
      if (result.syncedToCloud) {
        setLastSubSavedInfo({
          message: label,
          savedAt: result.record.updatedAt,
          syncedToCloud: true,
        });
        onNotify(`${label} (تم الحفظ في Firestore)`, 'success');
      } else {
        setLastSubSavedInfo({
          message: `${label} — تم الحفظ محلياً لحين تحديث قواعد Firestore`,
          savedAt: result.record.updatedAt,
          syncedToCloud: false,
        });
        onNotify(`${label} (تم الحفظ محلياً لحين تحديث قواعد Firestore)`, 'warning');
      }
    } finally {
      setSavingUid(null);
    }
  };

  const revokeSubscription = async (uid: string) => {
    const cleanUid = uid.trim();
    if (!cleanUid || !/^[a-zA-Z0-9_-]{1,128}$/.test(cleanUid)) {
      onNotify('يرجى إدخال معرّف UID صالح لإلغاء التفعيل.', 'warning');
      return;
    }
    setSavingUid(cleanUid);
    try {
      const result = await revokeUserSubscriptionInFirestoreOrLocal({
        uid: cleanUid,
        grantedByUid: currentUserUid,
        existingRecord: subsMap[cleanUid] || null,
      });

      setSubsMap((prev) => ({
        ...prev,
        [cleanUid]: result.record,
      }));

      const label = `تم إلغاء تفعيل الاشتراك للمعرّف ${cleanUid}`;
      if (result.syncedToCloud) {
        setLastSubSavedInfo({
          message: label,
          savedAt: result.record.updatedAt,
          syncedToCloud: true,
        });
        onNotify(`${label} (تم الحفظ في Firestore)`, 'warning');
      } else {
        setLastSubSavedInfo({
          message: `${label} — تم الحفظ محلياً لحين تحديث قواعد Firestore`,
          savedAt: result.record.updatedAt,
          syncedToCloud: false,
        });
        onNotify(`${label} (تم الحفظ محلياً لحين تحديث قواعد Firestore)`, 'warning');
      }
    } finally {
      setSavingUid(null);
    }
  };

  const mergedUsersList: AdminUserSummary[] = (() => {
    const byUid = new Map<string, AdminUserSummary>();
    for (const u of usersList) {
      byUid.set(u.uid, u);
    }
    for (const [subUid, sub] of Object.entries(subsMap)) {
      if (!byUid.has(subUid)) {
        byUid.set(subUid, {
          uid: subUid,
          email: sub.email || '',
          displayName: 'حساب مفعّل بالـ UID',
          role: 'analyst',
          createdAt: sub.createdAt || sub.updatedAt || '',
        });
      }
    }
    return Array.from(byUid.values());
  })();

  const filteredUsers = mergedUsersList.filter((u) => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return true;
    return (
      u.uid.toLowerCase().includes(q) ||
      u.email.toLowerCase().includes(q) ||
      (u.displayName || '').toLowerCase().includes(q)
    );
  });

  const handleSaveAnnouncement = async (forceEnabled?: boolean) => {
    const nextEnabled =
      typeof forceEnabled === 'boolean' ? forceEnabled : draftAnnouncementEnabled;
    const trimmedText = draftAnnouncementText.trim();

    if (nextEnabled && !trimmedText) {
      const msg = 'يرجى كتابة نص التنبيه قبل تفعيل الشريط في المنصة.';
      setAnnouncementFeedback({ ok: false, message: msg, savedAt: new Date().toISOString() });
      onNotify(msg, 'warning');
      return;
    }

    setSavingAnnouncement(true);
    setAnnouncementFeedback(null);
    const nowIso = new Date().toISOString();
    const nextPayload: PlatformSiteControls = {
      ...siteControls,
      announcementEnabled: nextEnabled,
      announcementText: trimmedText.slice(0, MAX_ANNOUNCEMENT_LENGTH),
      announcementType: draftAnnouncementType,
      announcementUpdatedAt: nowIso,
      maintenanceTools: draftMaintenanceTools,
      maintenanceGroups: draftMaintenanceGroups,
      maintenanceMessage: draftMaintenanceMessage.trim().slice(0, MAX_MAINTENANCE_MESSAGE_LENGTH),
      updatedBy: currentUserUid,
      updatedAt: nowIso,
    };

    try {
      const res = await savePlatformSiteControlsToFirestore(nextPayload, currentUserUid);
      if (res.syncedToCloud) {
        onSiteControlsSaved?.(res.controls);
        const msg = res.controls.announcementEnabled
          ? 'تم نشر شريط التنبيهات وتفعيله في Firestore بنجاح.'
          : 'تم تعطيل شريط التنبيهات وحفظ التغيير في Firestore.';
        setAnnouncementFeedback({ ok: true, message: msg, savedAt: res.controls.updatedAt });
        onNotify(msg, 'success');
      } else {
        const msg = res.permissionDenied
          ? 'تم رفض التعديل من قواعد أمان Firestore (الصلاحية محصورة للمالك والأدمن المعتمد فقط).'
          : `فشل حفظ التنبيه في Firestore: ${res.errorMessage || 'خطأ في الاتصال'}`;
        setAnnouncementFeedback({ ok: false, message: msg, savedAt: nowIso });
        onNotify(msg, 'error');
      }
    } finally {
      setSavingAnnouncement(false);
    }
  };

  const persistMaintenanceControls = async (
    nextTools: AppTabId[],
    nextGroups: NavGroupId[],
    nextMessage: string,
    actionKey: string,
    successMsg: string
  ) => {
    setSavingMaintenanceKey(actionKey);
    setMaintenanceFeedback(null);
    const nowIso = new Date().toISOString();
    const nextPayload: PlatformSiteControls = {
      ...siteControls,
      announcementEnabled: draftAnnouncementEnabled,
      announcementText: draftAnnouncementText.trim().slice(0, MAX_ANNOUNCEMENT_LENGTH),
      announcementType: draftAnnouncementType,
      maintenanceTools: nextTools.filter((id) => id !== 'profile'),
      maintenanceGroups: nextGroups,
      maintenanceMessage: nextMessage.trim().slice(0, MAX_MAINTENANCE_MESSAGE_LENGTH),
      maintenanceUpdatedAt: nowIso,
      updatedBy: currentUserUid,
      updatedAt: nowIso,
    };

    try {
      const res = await savePlatformSiteControlsToFirestore(nextPayload, currentUserUid);
      if (res.syncedToCloud) {
        setDraftMaintenanceTools(res.controls.maintenanceTools);
        setDraftMaintenanceGroups(res.controls.maintenanceGroups);
        setDraftMaintenanceMessage(res.controls.maintenanceMessage);
        onSiteControlsSaved?.(res.controls);
        setMaintenanceFeedback({
          ok: true,
          message: successMsg,
          savedAt: res.controls.updatedAt,
        });
        onNotify(`${successMsg} (تم التحديث في Firestore)`, 'success');
      } else {
        setDraftMaintenanceTools(siteControls.maintenanceTools);
        setDraftMaintenanceGroups(siteControls.maintenanceGroups);
        const msg = res.permissionDenied
          ? 'تم رفض تعديل وضع الصيانة من قواعد Firestore (الصلاحية محصورة للمالك والأدمن المعتمد فقط).'
          : `فشل حفظ وضع الصيانة في Firestore: ${res.errorMessage || 'خطأ غير متوقع'}`;
        setMaintenanceFeedback({ ok: false, message: msg, savedAt: nowIso });
        onNotify(msg, 'error');
      }
    } finally {
      setSavingMaintenanceKey(null);
    }
  };

  const toggleGroupMaintenance = (groupId: NavGroupId) => {
    const exists = draftMaintenanceGroups.includes(groupId);
    const nextGroups = exists
      ? draftMaintenanceGroups.filter((g) => g !== groupId)
      : [...draftMaintenanceGroups, groupId];
    const groupLabel = GROUP_LABELS_BY_ID[groupId] || groupId;
    const msg = exists
      ? `تم إخراج قسم "${groupLabel}" من وضع الصيانة المؤقت.`
      : `تم وضع قسم "${groupLabel}" تحت الصيانة المؤقتة.`;
    void persistMaintenanceControls(
      draftMaintenanceTools,
      nextGroups,
      draftMaintenanceMessage,
      `group:${groupId}`,
      msg
    );
  };

  const toggleToolMaintenance = (tabId: AppTabId, label: string) => {
    if (tabId === 'profile') return;
    const exists = draftMaintenanceTools.includes(tabId);
    const nextTools = exists
      ? draftMaintenanceTools.filter((id) => id !== tabId)
      : [...draftMaintenanceTools, tabId];
    const msg = exists
      ? `تم إخراج أداة "${label}" من وضع الصيانة.`
      : `تم وضع أداة "${label}" تحت الصيانة المؤقتة.`;
    void persistMaintenanceControls(
      nextTools,
      draftMaintenanceGroups,
      draftMaintenanceMessage,
      `tool:${tabId}`,
      msg
    );
  };

  const normalizedToolQuery = toolSearchTerm.trim().toLowerCase();
  const normalizedMaintQuery = maintenanceToolSearch.trim().toLowerCase();
  const paidToolsCount = NAV_TABS_META.filter((t) => accessState.isToolInLockedList(t.id)).length;
  const freeToolsCount = NAV_TABS_META.length - paidToolsCount;
  const activeMaintCount =
    siteControls.maintenanceTools.length + siteControls.maintenanceGroups.length;

  return (
    <div id="owner-management-console" className="bg-gray-950/70 border border-[#D4AF37]/40 rounded-2xl p-6 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37] shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">لوحة إدارة المالك والمطور</h3>
            <p className="text-[11px] text-gray-400">
              تحكم إداري مباشر مخزّن في Firestore: قفل الأدوات، شريط التنبيهات العام، وضع الصيانة المؤقت للأقسام والأدوات، وإدارة الاشتراكات.
            </p>
          </div>
        </div>
        <span className="px-3 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[11px] font-bold shrink-0 self-start sm:self-center">
          صلاحية المالك / الأدمن نشطة
        </span>
      </div>

      {/* Sub-navigation between Admin Control Tabs */}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => setOwnerConsoleTab('tools')}
          className={`px-4 py-2 rounded-xl text-xs font-bold border transition flex items-center gap-2 cursor-pointer ${
            ownerConsoleTab === 'tools'
              ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37]'
              : 'bg-gray-900 text-gray-300 border-gray-800 hover:border-gray-700'
          }`}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span>التحكم بقفل وفتح الأدوات ({NAV_TABS_META.length})</span>
        </button>
        <button
          type="button"
          onClick={() => setOwnerConsoleTab('announcement')}
          className={`px-4 py-2 rounded-xl text-xs font-bold border transition flex items-center gap-2 cursor-pointer ${
            ownerConsoleTab === 'announcement'
              ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37]'
              : 'bg-gray-900 text-gray-300 border-gray-800 hover:border-gray-700'
          }`}
        >
          <Megaphone className="w-3.5 h-3.5" />
          <span>شريط التنبيهات والإعلانات</span>
          {siteControls.announcementEnabled && (
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                ownerConsoleTab === 'announcement'
                  ? 'bg-gray-950/20 text-gray-950'
                  : 'bg-emerald-500/20 text-emerald-300'
              }`}
            >
              مفعّل
            </span>
          )}
        </button>
        <button
          type="button"
          onClick={() => setOwnerConsoleTab('maintenance')}
          className={`px-4 py-2 rounded-xl text-xs font-bold border transition flex items-center gap-2 cursor-pointer ${
            ownerConsoleTab === 'maintenance'
              ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37]'
              : 'bg-gray-900 text-gray-300 border-gray-800 hover:border-gray-700'
          }`}
        >
          <Wrench className="w-3.5 h-3.5" />
          <span>وضع الصيانة المؤقت</span>
          {activeMaintCount > 0 && (
            <span
              className={`px-1.5 py-0.5 rounded text-[10px] font-bold tabular-nums ${
                ownerConsoleTab === 'maintenance'
                  ? 'bg-gray-950/20 text-gray-950'
                  : 'bg-amber-500/20 text-amber-300'
              }`}
            >
              {activeMaintCount}
            </span>
          )}
        </button>
        <button
          type="button"
          onClick={() => setOwnerConsoleTab('users')}
          className={`px-4 py-2 rounded-xl text-xs font-bold border transition flex items-center gap-2 cursor-pointer ${
            ownerConsoleTab === 'users'
              ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37]'
              : 'bg-gray-900 text-gray-300 border-gray-800 hover:border-gray-700'
          }`}
        >
          <Users className="w-3.5 h-3.5" />
          <span>اشتراكات المستخدمين ({mergedUsersList.length})</span>
        </button>
      </div>

      {ownerConsoleTab === 'tools' ? (
        <div className="space-y-4">
          <div className="p-3.5 rounded-xl bg-gray-900/90 border border-gray-800 flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2 text-[11px]">
              <span className="px-2.5 py-1 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300 font-bold tabular-nums">
                مدفوعة لغير المشتركين: {paidToolsCount}
              </span>
              <span className="px-2.5 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-bold tabular-nums">
                مجانية للجميع: {freeToolsCount}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                disabled={Boolean(savingToolId)}
                onClick={() =>
                  void persistLockedTools(
                    DEFAULT_LOCKED_TOOLS,
                    '__reset__',
                    'تمت استعادة الإعداد الافتراضي (الأدوات المتقدمة مقفلة لغير المشتركين).'
                  )
                }
                className="px-3 py-1.5 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 text-[11px] font-bold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                <RotateCcw className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>الوضع الافتراضي</span>
              </button>
              <button
                type="button"
                disabled={Boolean(savingToolId)}
                onClick={() =>
                  void persistLockedTools(
                    [],
                    '__unlock_all__',
                    'تم فتح جميع أدوات المنصة مجاناً لكافة المستخدمين.'
                  )
                }
                className="px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-[11px] font-bold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                <Unlock className="w-3.5 h-3.5" />
                <span>فتح الكل مجاناً</span>
              </button>
            </div>
          </div>

          {lastSavedInfo && (
            <div
              className={`px-3.5 py-2.5 rounded-xl border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                lastSavedInfo.syncedToCloud
                  ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                  : 'bg-amber-500/10 border-amber-500/35 text-amber-300'
              }`}
            >
              <div className="flex items-center gap-2 font-bold">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{lastSavedInfo.message}</span>
              </div>
              <span className="text-[10px] font-mono opacity-80 shrink-0" dir="ltr">
                {lastSavedInfo.syncedToCloud ? 'Firestore + Local' : 'Local Backup'} • {new Date(lastSavedInfo.savedAt).toLocaleTimeString('ar-SA')}
              </span>
            </div>
          )}

          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={toolSearchTerm}
              onChange={(e) => setToolSearchTerm(e.target.value)}
              placeholder="تصفية الأدوات بالاسم أو المعرّف (مثل: YARA, PCAP, OSINT)..."
              className="w-full pr-9 pl-3 py-2 bg-gray-900 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
            />
          </div>

          <div className="space-y-4">
            {NAV_GROUP_ORDER.map((groupId) => {
              const groupTools = NAV_TABS_META.filter((t) => {
                if (t.group !== groupId) return false;
                if (!normalizedToolQuery) return true;
                return (
                  t.label.toLowerCase().includes(normalizedToolQuery) ||
                  t.shortLabel.toLowerCase().includes(normalizedToolQuery) ||
                  t.id.toLowerCase().includes(normalizedToolQuery)
                );
              });
              if (groupTools.length === 0) return null;

              return (
                <div key={groupId} className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden">
                  <div className="px-4 py-2.5 bg-gray-900 border-b border-gray-800 flex items-center justify-between text-xs font-bold text-gray-200">
                    <span>{groupTools[0].groupLabel}</span>
                    <span className="text-[11px] text-gray-500 tabular-nums">{groupTools.length} أداة</span>
                  </div>
                  <div className="divide-y divide-gray-800/80">
                    {groupTools.map((tool) => {
                      const isProfile = tool.id === 'profile';
                      const isPaid = accessState.isToolInLockedList(tool.id);
                      const isBusy = savingToolId === tool.id || savingToolId === '__reset__' || savingToolId === '__unlock_all__';

                      return (
                        <div
                          key={tool.id}
                          className="px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-gray-900/50 transition"
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            <div
                              className={`w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 ${
                                isPaid
                                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                                  : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                              }`}
                            >
                              {renderTabIcon(tool.id, 'w-4 h-4')}
                            </div>
                            <div className="min-w-0">
                              <div className="text-xs font-bold text-white truncate">{tool.label}</div>
                              <div className="text-[10px] font-mono text-gray-500" dir="ltr">{tool.id}</div>
                            </div>
                          </div>

                          <div className="flex items-center justify-between sm:justify-end gap-2.5 shrink-0">
                            {isProfile ? (
                              <span className="px-2.5 py-1 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 text-[10px] font-bold">
                                مفتوح دائماً لإدارة الحساب
                              </span>
                            ) : (
                              <>
                                <span
                                  className={`px-2.5 py-1 rounded-lg border text-[10px] font-bold inline-flex items-center gap-1 ${
                                    isPaid
                                      ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                                      : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                                  }`}
                                >
                                  {isPaid ? <Lock className="w-3 h-3" /> : <Unlock className="w-3 h-3" />}
                                  <span>{isPaid ? 'مقفلة للمستخدمين الآخرين (مفتوحة لك)' : 'مجانية (مفتوحة للجميع)'}</span>
                                </span>

                                {onOpenTool && (
                                  <button
                                    type="button"
                                    onClick={() => onOpenTool(tool.id)}
                                    title={`فتح أداة ${tool.label} مباشرة`}
                                    className="px-2.5 py-1.5 rounded-lg border border-gray-700 bg-gray-950 hover:bg-gray-800 text-gray-200 text-[11px] font-bold inline-flex items-center gap-1 transition cursor-pointer"
                                  >
                                    <ExternalLink className="w-3 h-3 text-[#D4AF37]" />
                                    <span>فتح</span>
                                  </button>
                                )}

                                <button
                                  type="button"
                                  disabled={Boolean(savingToolId)}
                                  onClick={() => toggleToolPaidStatus(tool.id, tool.label)}
                                  className={`px-3 py-1.5 rounded-lg border text-[11px] font-bold inline-flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 ${
                                    isPaid
                                      ? 'bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/40 text-emerald-300'
                                      : 'bg-amber-500/15 hover:bg-amber-500/25 border-amber-500/40 text-amber-300'
                                  }`}
                                >
                                  {isBusy ? (
                                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                  ) : isPaid ? (
                                    <Unlock className="w-3.5 h-3.5" />
                                  ) : (
                                    <Lock className="w-3.5 h-3.5" />
                                  )}
                                  <span>{isPaid ? 'فتح مجاناً' : 'قفل للآخرين'}</span>
                                </button>
                              </>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : ownerConsoleTab === 'announcement' ? (
        <div className="space-y-4">
          <div className="bg-gray-900 p-5 rounded-xl border border-gray-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-800">
              <div>
                <h4 className="text-xs font-bold text-white flex items-center gap-2">
                  <Megaphone className="w-4 h-4 text-[#D4AF37]" />
                  <span>شريط تنبيهات وإعلانات المنصة (Firestore: platform_config/site_controls)</span>
                </h4>
                <p className="text-[11px] text-gray-400 mt-1">
                  يظهر فوراً أعلى واجهة المنصة لجميع المستخدمين عند التفعيل، ويُدار حصراً من حسابات المالك والأدمن عبر قواعد أمان Firestore.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setDraftAnnouncementEnabled((v) => !v)}
                className={`px-3.5 py-2 rounded-xl text-xs font-bold border transition inline-flex items-center gap-2 cursor-pointer shrink-0 ${
                  draftAnnouncementEnabled
                    ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                    : 'bg-gray-950 border-gray-700 text-gray-300 hover:border-gray-600'
                }`}
              >
                <Power className="w-3.5 h-3.5" />
                <span>الحالة: {draftAnnouncementEnabled ? 'مفعّل' : 'معطّل'}</span>
              </button>
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-bold text-gray-300">نوع التنبيه / الإعلان</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
                {(['info', 'warning', 'critical', 'success'] as AnnouncementType[]).map((typeKey) => {
                  const meta = ANNOUNCEMENT_TYPE_META[typeKey];
                  const active = draftAnnouncementType === typeKey;
                  const icon =
                    typeKey === 'critical' ? (
                      <AlertOctagon className="w-4 h-4 text-red-400" />
                    ) : typeKey === 'warning' ? (
                      <AlertTriangle className="w-4 h-4 text-amber-400" />
                    ) : typeKey === 'success' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Info className="w-4 h-4 text-sky-400" />
                    );
                  return (
                    <button
                      key={typeKey}
                      type="button"
                      onClick={() => setDraftAnnouncementType(typeKey)}
                      className={`p-3 rounded-xl border text-right transition cursor-pointer space-y-1 ${
                        active
                          ? 'bg-[#D4AF37]/15 border-[#D4AF37] text-white'
                          : 'bg-gray-950 border-gray-800 text-gray-300 hover:border-gray-700'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold">{meta.labelAr}</span>
                        {icon}
                      </div>
                      <p className="text-[10px] text-gray-400">{meta.descriptionAr}</p>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <label className="font-bold text-gray-300">نص التنبيه أو الإعلان</label>
                <span className="text-[11px] font-mono text-gray-400 tabular-nums" dir="ltr">
                  {draftAnnouncementText.length} / {MAX_ANNOUNCEMENT_LENGTH}
                </span>
              </div>
              <textarea
                rows={3}
                maxLength={MAX_ANNOUNCEMENT_LENGTH}
                value={draftAnnouncementText}
                onChange={(e) => setDraftAnnouncementText(e.target.value)}
                placeholder="اكتب نص التنبيه أو الإعلان الرسمي الذي سيظهر في شريط المنصة..."
                className="w-full p-3 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none resize-y"
              />
            </div>

            {/* Live Preview of Banner */}
            {draftAnnouncementText.trim() && (
              <div className="space-y-1.5">
                <span className="text-[11px] text-gray-400 font-bold">معاينة مباشرة لشكل الشريط عند التفعيل:</span>
                <div
                  className={`p-3.5 rounded-xl border flex flex-wrap items-center justify-between gap-2 text-xs ${
                    draftAnnouncementType === 'critical'
                      ? 'bg-red-500/15 border-red-500/45 text-red-200'
                      : draftAnnouncementType === 'warning'
                      ? 'bg-amber-500/15 border-amber-500/45 text-amber-200'
                      : draftAnnouncementType === 'success'
                      ? 'bg-emerald-500/15 border-emerald-500/45 text-emerald-200'
                      : 'bg-sky-500/15 border-sky-500/45 text-sky-200'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="px-2 py-0.5 rounded-md bg-black/30 font-bold text-[10px] shrink-0">
                      {ANNOUNCEMENT_TYPE_META[draftAnnouncementType].badgeAr}
                    </span>
                    <span className="font-medium leading-relaxed break-words">
                      {draftAnnouncementText.trim()}
                    </span>
                  </div>
                </div>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={savingAnnouncement}
                  onClick={() => void handleSaveAnnouncement()}
                  className="px-4 py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition cursor-pointer disabled:opacity-50 inline-flex items-center gap-2"
                >
                  {savingAnnouncement ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Send className="w-3.5 h-3.5" />
                  )}
                  <span>حفظ الإعدادات في Firestore</span>
                </button>
                {siteControls.announcementEnabled && (
                  <button
                    type="button"
                    disabled={savingAnnouncement}
                    onClick={() => void handleSaveAnnouncement(false)}
                    className="px-4 py-2.5 bg-red-500/15 hover:bg-red-500/25 border border-red-500/35 text-red-300 font-bold text-xs rounded-xl transition cursor-pointer disabled:opacity-50 inline-flex items-center gap-1.5"
                  >
                    <Ban className="w-3.5 h-3.5" />
                    <span>تعطيل الشريط الآن</span>
                  </button>
                )}
              </div>
              <span className="text-[11px] font-mono text-gray-500" dir="ltr">
                {siteControlsLoaded
                  ? siteControls.announcementUpdatedAt
                    ? `Firestore Sync: ${new Date(siteControls.announcementUpdatedAt).toLocaleTimeString('ar-SA')}`
                    : 'Firestore Ready'
                  : 'Syncing Firestore...'}
              </span>
            </div>
          </div>

          {announcementFeedback && (
            <div
              className={`px-4 py-3 rounded-xl border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                announcementFeedback.ok
                  ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                  : 'bg-red-500/10 border-red-500/35 text-red-300'
              }`}
            >
              <div className="flex items-center gap-2 font-bold">
                {announcementFeedback.ok ? (
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                ) : (
                  <AlertOctagon className="w-4 h-4 shrink-0" />
                )}
                <span>{announcementFeedback.message}</span>
              </div>
              <span className="text-[10px] font-mono opacity-80 shrink-0" dir="ltr">
                {new Date(announcementFeedback.savedAt).toLocaleTimeString('ar-SA')}
              </span>
            </div>
          )}
        </div>
      ) : ownerConsoleTab === 'maintenance' ? (
        <div className="space-y-4">
          <div className="bg-gray-900 p-5 rounded-xl border border-gray-800 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-gray-800">
              <div>
                <h4 className="text-xs font-bold text-white flex items-center gap-2">
                  <Wrench className="w-4 h-4 text-amber-400" />
                  <span>وضع الصيانة المؤقت للأدوات أو الأقسام (Firestore)</span>
                </h4>
                <p className="text-[11px] text-gray-400 mt-1">
                  يمكنك وضع قسم كامل أو أداة محددة في حالة "تحت الصيانة" مع رسالة توضيحية تظهر للمستخدمين فوراً عند فتح الأداة أو القسم.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-2.5 py-1 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[11px] font-bold tabular-nums">
                  أقسام تحت الصيانة: {siteControls.maintenanceGroups.length} • أدوات: {siteControls.maintenanceTools.length}
                </span>
                {activeMaintCount > 0 && (
                  <button
                    type="button"
                    disabled={Boolean(savingMaintenanceKey)}
                    onClick={() =>
                      void persistMaintenanceControls(
                        [],
                        [],
                        draftMaintenanceMessage,
                        '__clear_all_maint__',
                        'تم رفع وضع الصيانة عن جميع الأقسام والأدوات.'
                      )
                    }
                    className="px-3 py-1.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-[11px] font-bold flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
                  >
                    <Unlock className="w-3.5 h-3.5" />
                    <span>إيقاف الصيانة عن الكل</span>
                  </button>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <label className="font-bold text-gray-300">الرسالة التوضيحية للمستخدمين أثناء الصيانة</label>
                <span className="text-[11px] font-mono text-gray-400 tabular-nums" dir="ltr">
                  {draftMaintenanceMessage.length} / {MAX_MAINTENANCE_MESSAGE_LENGTH}
                </span>
              </div>
              <textarea
                rows={2}
                maxLength={MAX_MAINTENANCE_MESSAGE_LENGTH}
                value={draftMaintenanceMessage}
                onChange={(e) => setDraftMaintenanceMessage(e.target.value)}
                placeholder="مثال: هذه الوحدة قيد التحديث الأمني المجدول وستعود للعمل خلال دقائق..."
                className="w-full p-3 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none resize-y"
              />
              <div className="flex flex-wrap items-center justify-between gap-2">
                <button
                  type="button"
                  disabled={Boolean(savingMaintenanceKey)}
                  onClick={() =>
                    void persistMaintenanceControls(
                      draftMaintenanceTools,
                      draftMaintenanceGroups,
                      draftMaintenanceMessage,
                      '__save_msg__',
                      'تم حفظ رسالة الصيانة التوضيحية في Firestore بنجاح.'
                    )
                  }
                  className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition cursor-pointer disabled:opacity-50 inline-flex items-center gap-1.5"
                >
                  {savingMaintenanceKey === '__save_msg__' ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Send className="w-3.5 h-3.5" />
                  )}
                  <span>حفظ رسالة الصيانة في Firestore</span>
                </button>
                {siteControls.maintenanceUpdatedAt && (
                  <span className="text-[10px] font-mono text-gray-500" dir="ltr">
                    Last Sync: {new Date(siteControls.maintenanceUpdatedAt).toLocaleTimeString('ar-SA')}
                  </span>
                )}
              </div>
            </div>
          </div>

          {maintenanceFeedback && (
            <div
              className={`px-4 py-3 rounded-xl border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                maintenanceFeedback.ok
                  ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                  : 'bg-red-500/10 border-red-500/35 text-red-300'
              }`}
            >
              <div className="flex items-center gap-2 font-bold">
                {maintenanceFeedback.ok ? (
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                ) : (
                  <AlertOctagon className="w-4 h-4 shrink-0" />
                )}
                <span>{maintenanceFeedback.message}</span>
              </div>
              <span className="text-[10px] font-mono opacity-80 shrink-0" dir="ltr">
                {new Date(maintenanceFeedback.savedAt).toLocaleTimeString('ar-SA')}
              </span>
            </div>
          )}

          {/* Section-level maintenance toggles */}
          <div className="bg-gray-900/70 border border-gray-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h5 className="text-xs font-bold text-white">1. وضع الصيانة على مستوى الأقسام الكاملة</h5>
              <span className="text-[10px] text-gray-400">يشمل جميع أدوات القسم فوراً (باستثناء صفحة الحساب والإدارة)</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
              {NAV_GROUP_ORDER.map((groupId) => {
                const isGroupMaint = draftMaintenanceGroups.includes(groupId);
                const groupCount = NAV_TABS_META.filter((t) => t.group === groupId).length;
                const isBusy = savingMaintenanceKey === `group:${groupId}` || savingMaintenanceKey === '__clear_all_maint__';
                return (
                  <div
                    key={groupId}
                    className={`p-3 rounded-xl border flex items-center justify-between gap-2.5 transition ${
                      isGroupMaint
                        ? 'bg-amber-500/10 border-amber-500/40'
                        : 'bg-gray-950 border-gray-800'
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="text-xs font-bold text-white truncate">
                        {GROUP_LABELS_BY_ID[groupId]}
                      </div>
                      <div className="text-[10px] text-gray-400">
                        {groupCount} أداة {groupId === 'system' ? '• الحساب مستثنى' : ''}
                      </div>
                    </div>
                    <button
                      type="button"
                      disabled={Boolean(savingMaintenanceKey)}
                      onClick={() => toggleGroupMaintenance(groupId)}
                      className={`px-3 py-1.5 rounded-lg border text-[11px] font-bold inline-flex items-center gap-1.5 transition cursor-pointer shrink-0 disabled:opacity-50 ${
                        isGroupMaint
                          ? 'bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/40 text-emerald-300'
                          : 'bg-amber-500/15 hover:bg-amber-500/25 border-amber-500/40 text-amber-300'
                      }`}
                    >
                      {isBusy ? (
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      ) : (
                        <Wrench className="w-3.5 h-3.5" />
                      )}
                      <span>{isGroupMaint ? 'إيقاف الصيانة' : 'تحت الصيانة'}</span>
                    </button>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Tool-level maintenance toggles */}
          <div className="space-y-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={maintenanceToolSearch}
                onChange={(e) => setMaintenanceToolSearch(e.target.value)}
                placeholder="تصفية الأدوات لوضع أداة محددة تحت الصيانة..."
                className="w-full pr-9 pl-3 py-2 bg-gray-900 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
              />
            </div>

            <div className="space-y-4">
              {NAV_GROUP_ORDER.map((groupId) => {
                const groupTools = NAV_TABS_META.filter((t) => {
                  if (t.group !== groupId) return false;
                  if (!normalizedMaintQuery) return true;
                  return (
                    t.label.toLowerCase().includes(normalizedMaintQuery) ||
                    t.shortLabel.toLowerCase().includes(normalizedMaintQuery) ||
                    t.id.toLowerCase().includes(normalizedMaintQuery)
                  );
                });
                if (groupTools.length === 0) return null;
                const isGroupMaint = draftMaintenanceGroups.includes(groupId);

                return (
                  <div key={`maint-${groupId}`} className="bg-gray-900/60 border border-gray-800 rounded-xl overflow-hidden">
                    <div className="px-4 py-2.5 bg-gray-900 border-b border-gray-800 flex items-center justify-between text-xs font-bold text-gray-200">
                      <span className="flex items-center gap-2">
                        <span>{groupTools[0].groupLabel}</span>
                        {isGroupMaint && (
                          <span className="px-2 py-0.5 rounded bg-amber-500/20 border border-amber-500/40 text-amber-300 text-[10px]">
                            القسم بالكامل تحت الصيانة
                          </span>
                        )}
                      </span>
                      <span className="text-[11px] text-gray-500 tabular-nums">{groupTools.length} أداة</span>
                    </div>
                    <div className="divide-y divide-gray-800/80">
                      {groupTools.map((tool) => {
                        const isProfile = tool.id === 'profile';
                        const isToolMaint = !isProfile && draftMaintenanceTools.includes(tool.id);
                        const effectiveMaint = !isProfile && (isToolMaint || isGroupMaint);
                        const isBusy =
                          savingMaintenanceKey === `tool:${tool.id}` ||
                          savingMaintenanceKey === '__clear_all_maint__';

                        return (
                          <div
                            key={`maint-tool-${tool.id}`}
                            className="px-4 py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-gray-900/50 transition"
                          >
                            <div className="flex items-center gap-3 min-w-0">
                              <div
                                className={`w-8 h-8 rounded-lg border flex items-center justify-center shrink-0 ${
                                  effectiveMaint
                                    ? 'bg-amber-500/15 border-amber-500/40 text-amber-400'
                                    : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                                }`}
                              >
                                {renderTabIcon(tool.id, 'w-4 h-4')}
                              </div>
                              <div className="min-w-0">
                                <div className="text-xs font-bold text-white truncate">{tool.label}</div>
                                <div className="text-[10px] font-mono text-gray-500" dir="ltr">{tool.id}</div>
                              </div>
                            </div>

                            <div className="flex items-center justify-between sm:justify-end gap-2.5 shrink-0">
                              {isProfile ? (
                                <span className="px-2.5 py-1 rounded-lg bg-gray-800 border border-gray-700 text-gray-400 text-[10px] font-bold">
                                  مستثنى دائماً لإدارة المنصة والحساب
                                </span>
                              ) : (
                                <>
                                  <span
                                    className={`px-2.5 py-1 rounded-lg border text-[10px] font-bold inline-flex items-center gap-1 ${
                                      effectiveMaint
                                        ? 'bg-amber-500/15 border-amber-500/35 text-amber-300'
                                        : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                                    }`}
                                  >
                                    {effectiveMaint ? <Wrench className="w-3 h-3" /> : <CheckCircle2 className="w-3 h-3" />}
                                    <span>
                                      {isToolMaint
                                        ? 'الأداة تحت الصيانة'
                                        : isGroupMaint
                                        ? 'مغطاة بصيانة القسم'
                                        : 'تعمل بشكل طبيعي'}
                                    </span>
                                  </span>

                                  <button
                                    type="button"
                                    disabled={Boolean(savingMaintenanceKey)}
                                    onClick={() => toggleToolMaintenance(tool.id, tool.label)}
                                    className={`px-3 py-1.5 rounded-lg border text-[11px] font-bold inline-flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 ${
                                      isToolMaint
                                        ? 'bg-emerald-500/15 hover:bg-emerald-500/25 border-emerald-500/40 text-emerald-300'
                                        : 'bg-amber-500/15 hover:bg-amber-500/25 border-amber-500/40 text-amber-300'
                                    }`}
                                  >
                                    {isBusy ? (
                                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                                    ) : (
                                      <Wrench className="w-3.5 h-3.5" />
                                    )}
                                    <span>{isToolMaint ? 'إنهاء صيانة الأداة' : 'تعيين تحت الصيانة'}</span>
                                  </button>
                                </>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Direct UID Subscription Activation & Revocation Panel */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void grantSubscription(targetUid, targetEmail, selectedPlan, durationDays);
            }}
            className="bg-gray-900 p-4 rounded-xl border border-gray-800 space-y-3"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-bold text-white">تفعيل أو إلغاء الاشتراك عبر UID</span>
              <span className="text-[10px] text-gray-400">
                يحفظ في Firestore (subscriptions) مع نسخة احتياطية محلية تلقائياً
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-12 gap-2.5">
              <input
                type="text"
                dir="ltr"
                value={targetUid}
                onChange={(e) => setTargetUid(e.target.value)}
                placeholder="أدخل معرّف المستخدم (UID)..."
                className="md:col-span-5 px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-white focus:border-[#D4AF37] outline-none"
                required
              />
              <input
                type="email"
                dir="ltr"
                value={targetEmail}
                onChange={(e) => setTargetEmail(e.target.value)}
                placeholder="البريد الإلكتروني (اختياري)"
                className="md:col-span-3 px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-white focus:border-[#D4AF37] outline-none"
              />
              <select
                value={selectedPlan}
                onChange={(e) => setSelectedPlan(e.target.value as SubscriptionPlanId)}
                className="md:col-span-2 px-2.5 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs text-white focus:border-[#D4AF37] outline-none"
              >
                <option value="pro">Pro</option>
                <option value="enterprise">Enterprise</option>
              </select>
              <select
                value={durationDays}
                onChange={(e) => setDurationDays(Number(e.target.value))}
                className="md:col-span-2 px-2 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs text-white focus:border-[#D4AF37] outline-none"
              >
                <option value={0}>دائم (مفتوح)</option>
                <option value={30}>30 يوم</option>
                <option value={90}>90 يوم</option>
                <option value={365}>سنة</option>
              </select>
            </div>

            <div className="flex flex-wrap items-center gap-2.5">
              <button
                type="submit"
                disabled={Boolean(savingUid) || !targetUid.trim()}
                className="py-2 px-4 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-lg transition cursor-pointer disabled:opacity-50 inline-flex items-center gap-1.5"
              >
                <UserCheck className="w-3.5 h-3.5" />
                <span>تفعيل الاشتراك (Pro)</span>
              </button>
              <button
                type="button"
                disabled={Boolean(savingUid) || !targetUid.trim()}
                onClick={() => void revokeSubscription(targetUid)}
                className="py-2 px-4 bg-red-500/15 hover:bg-red-500/25 border border-red-500/35 text-red-300 font-bold text-xs rounded-lg transition cursor-pointer disabled:opacity-50 inline-flex items-center gap-1.5"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>إلغاء التفعيل</span>
              </button>
            </div>
          </form>

          {lastSubSavedInfo && (
            <div
              className={`px-3.5 py-2.5 rounded-xl border text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                lastSubSavedInfo.syncedToCloud
                  ? 'bg-emerald-500/10 border-emerald-500/35 text-emerald-300'
                  : 'bg-amber-500/10 border-amber-500/35 text-amber-300'
              }`}
            >
              <div className="flex items-center gap-2 font-bold">
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                <span>{lastSubSavedInfo.message}</span>
              </div>
              <span className="text-[10px] font-mono opacity-80 shrink-0" dir="ltr">
                {lastSubSavedInfo.syncedToCloud ? 'Firestore + Local' : 'Local Backup'} • {new Date(lastSubSavedInfo.savedAt).toLocaleTimeString('ar-SA')}
              </span>
            </div>
          )}

          {/* Registered Users Table */}
          <div className="space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-xs font-bold text-gray-300">
                <Users className="w-4 h-4 text-[#D4AF37]" />
                <span>المستخدمون المسجلون والاشتراكات ({mergedUsersList.length})</span>
              </div>
              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="بحث بالبريد أو UID..."
                  className="w-full pr-8 pl-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-xs text-white focus:border-[#D4AF37] outline-none"
                />
              </div>
            </div>

            {loading ? (
              <div className="py-6 text-center text-xs text-gray-500 flex items-center justify-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin text-[#D4AF37]" />
                <span>جاري تحميل قائمة المستخدمين...</span>
              </div>
            ) : (
              <div className="overflow-x-auto border border-gray-800 rounded-xl">
                <table className="w-full text-right text-xs">
                  <thead className="bg-gray-900 text-gray-400 border-b border-gray-800">
                    <tr>
                      <th className="p-3">المستخدم</th>
                      <th className="p-3">UID</th>
                      <th className="p-3">الصلاحية / الاشتراك</th>
                      <th className="p-3">إجراء</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 bg-gray-950/60">
                    {filteredUsers.map((u) => {
                      const sub = subsMap[u.uid];
                      const isOwnerOrAdminRow =
                        u.role === 'admin' ||
                        OWNER_UIDS.has(u.uid) ||
                        OWNER_EMAILS.has((u.email || '').trim().toLowerCase());
                      const subActive = isSubscriptionActive(sub);

                      return (
                        <tr key={u.uid} className="hover:bg-gray-900/40">
                          <td className="p-3">
                            <div className="font-bold text-white">{u.displayName || 'مستخدم'}</div>
                            <div className="text-[11px] font-mono text-gray-400" dir="ltr">{u.email}</div>
                          </td>
                          <td className="p-3 font-mono text-[11px] text-gray-400" dir="ltr">
                            {u.uid.slice(0, 14)}...
                          </td>
                          <td className="p-3">
                            {isOwnerOrAdminRow ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-[#D4AF37]/15 border border-[#D4AF37]/40 text-[#D4AF37] text-[10px] font-bold">
                                <Crown className="w-3 h-3" />
                                مالك / Admin (معفى)
                              </span>
                            ) : subActive ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[10px] font-bold">
                                <CheckCircle2 className="w-3 h-3" />
                                نشط ({sub?.plan.toUpperCase()})
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-gray-800 text-gray-400 text-[10px] font-bold">
                                <Lock className="w-3 h-3" />
                                مجاني (مقيد)
                              </span>
                            )}
                          </td>
                          <td className="p-3">
                            {isOwnerOrAdminRow ? (
                              <span className="text-[11px] text-gray-500">وصول دائم</span>
                            ) : subActive ? (
                              <button
                                type="button"
                                disabled={savingUid === u.uid}
                                onClick={() => void revokeSubscription(u.uid)}
                                className="px-2.5 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-red-400 text-[11px] font-bold inline-flex items-center gap-1 cursor-pointer disabled:opacity-50"
                              >
                                <Ban className="w-3 h-3" />
                                إيقاف
                              </button>
                            ) : (
                              <button
                                type="button"
                                disabled={savingUid === u.uid}
                                onClick={() => void grantSubscription(u.uid, u.email, 'pro', 30)}
                                className="px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-500/30 text-emerald-300 text-[11px] font-bold inline-flex items-center gap-1 cursor-pointer disabled:opacity-50"
                              >
                                <UserCheck className="w-3 h-3" />
                                تفعيل Pro (30 يوم)
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                    {filteredUsers.length === 0 && (
                      <tr>
                        <td colSpan={4} className="p-6 text-center text-gray-500">
                          لا يوجد مستخدمون مطابقون للبحث.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
