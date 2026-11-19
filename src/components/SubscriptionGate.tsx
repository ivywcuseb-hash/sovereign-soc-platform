import React, { useEffect, useState } from 'react';
import {
  Lock,
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
} from 'lucide-react';
import {
  collection,
  doc,
  onSnapshot,
  setDoc,
  deleteDoc,
} from 'firebase/firestore';
import { db, handleFirestoreError, OperationType } from '../firebase';
import { NAV_TABS_META, type AppTabId } from './LayoutCustomizer';
import {
  isSubscriptionActive,
  OWNER_EMAILS,
  OWNER_UIDS,
  type SovereignAccessState,
  type SubscriptionPlanId,
  type UserSubscriptionRecord,
} from '../utils/subscriptionAccess';

interface SubscriptionPaywallModalProps {
  isOpen: boolean;
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
  requestedTab,
  userUid,
  userEmail,
  subscription,
  onClose,
  onOpenProfile,
  onNotify,
}) => {
  if (!isOpen) return null;

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
  onOpenSubscriptionModal: () => void;
  onBackToDashboard: () => void;
}

export const SubscriptionInlineGate: React.FC<SubscriptionInlineGateProps> = ({
  tabId,
  onOpenSubscriptionModal,
  onBackToDashboard,
}) => {
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
  onNotify: (msg: string, type?: 'success' | 'error' | 'warning') => void;
}

export const AdminSubscriptionManager: React.FC<AdminSubscriptionManagerProps> = ({
  currentUserUid,
  accessState,
  onNotify,
}) => {
  const [usersList, setUsersList] = useState<AdminUserSummary[]>([]);
  const [subsMap, setSubsMap] = useState<Record<string, UserSubscriptionRecord>>({});
  const [loading, setLoading] = useState(true);
  const [targetUid, setTargetUid] = useState('');
  const [targetEmail, setTargetEmail] = useState('');
  const [selectedPlan, setSelectedPlan] = useState<SubscriptionPlanId>('pro');
  const [durationDays, setDurationDays] = useState<number>(30);
  const [searchTerm, setSearchTerm] = useState('');
  const [savingUid, setSavingUid] = useState<string | null>(null);

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
        const nextMap: Record<string, UserSubscriptionRecord> = {};
        snap.forEach((d) => {
          nextMap[d.id] = d.data() as UserSubscriptionRecord;
        });
        setSubsMap(nextMap);
      },
      (err) => {
        console.warn('Admin subscriptions list error:', err);
        try {
          handleFirestoreError(err, OperationType.LIST, 'subscriptions');
        } catch {}
      }
    );

    return () => {
      unsubUsers();
      unsubSubs();
    };
  }, [accessState.isAdminOrOwner]);

  if (!accessState.isAdminOrOwner) return null;

  const grantSubscription = async (
    uid: string,
    email: string,
    plan: SubscriptionPlanId,
    days: number
  ) => {
    const cleanUid = uid.trim();
    if (!cleanUid || !/^[a-zA-Z0-9_-]{1,128}$/.test(cleanUid)) {
      onNotify('معرّف UID غير صالح.', 'error');
      return;
    }
    setSavingUid(cleanUid);
    try {
      const nowIso = new Date().toISOString();
      const existing = subsMap[cleanUid];
      const payload: Record<string, string> = {
        userId: cleanUid,
        plan,
        status: 'active',
        grantedBy: currentUserUid,
        createdAt: existing?.createdAt || nowIso,
        updatedAt: nowIso,
      };
      if (email.trim()) {
        payload.email = email.trim().slice(0, 320);
      }
      if (days > 0) {
        payload.expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
      }
      await setDoc(doc(db, 'subscriptions', cleanUid), payload);
      onNotify(`تم تفعيل اشتراك (${plan.toUpperCase()}) للمستخدم بنجاح في Firestore.`, 'success');
      if (cleanUid === targetUid.trim()) {
        setTargetUid('');
        setTargetEmail('');
      }
    } catch (err: any) {
      console.error('Grant subscription error:', err);
      onNotify(err?.message || 'تعذر تفعيل الاشتراك في Firestore.', 'error');
      try {
        handleFirestoreError(err, OperationType.WRITE, `subscriptions/${cleanUid}`);
      } catch {}
    } finally {
      setSavingUid(null);
    }
  };

  const revokeSubscription = async (uid: string) => {
    setSavingUid(uid);
    try {
      const existing = subsMap[uid];
      if (existing) {
        await setDoc(doc(db, 'subscriptions', uid), {
          userId: uid,
          email: existing.email || '',
          plan: 'free',
          status: 'revoked',
          grantedBy: currentUserUid,
          createdAt: existing.createdAt || new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });
      } else {
        await deleteDoc(doc(db, 'subscriptions', uid));
      }
      onNotify('تم إيقاف الاشتراك وتقييد الأدوات المدفوعة لهذا الحساب.', 'warning');
    } catch (err: any) {
      console.error('Revoke subscription error:', err);
      onNotify(err?.message || 'تعذر إيقاف الاشتراك.', 'error');
    } finally {
      setSavingUid(null);
    }
  };

  const filteredUsers = usersList.filter((u) => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return true;
    return (
      u.uid.toLowerCase().includes(q) ||
      u.email.toLowerCase().includes(q) ||
      (u.displayName || '').toLowerCase().includes(q)
    );
  });

  return (
    <div className="bg-gray-950/70 border border-[#D4AF37]/40 rounded-2xl p-6 space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37]">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">إدارة اشتراكات المستخدمين (لوحة المالك والأدمن)</h3>
            <p className="text-[11px] text-gray-400">
              تفعيل أو إيقاف الباقات المدفوعة في مجموعة <code className="text-[#D4AF37]">subscriptions</code> في Firestore. حسابك معفى تلقائياً بالكامل.
            </p>
          </div>
        </div>
        <span className="px-3 py-1 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[11px] font-bold shrink-0">
          وصول المالك مفتوح بالكامل
        </span>
      </div>

      {/* Quick Grant Form by UID */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void grantSubscription(targetUid, targetEmail, selectedPlan, durationDays);
        }}
        className="grid grid-cols-1 md:grid-cols-12 gap-2.5 bg-gray-900 p-4 rounded-xl border border-gray-800"
      >
        <input
          type="text"
          dir="ltr"
          value={targetUid}
          onChange={(e) => setTargetUid(e.target.value)}
          placeholder="Firebase User UID..."
          className="md:col-span-4 px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-white focus:border-[#D4AF37] outline-none"
          required
        />
        <input
          type="email"
          dir="ltr"
          value={targetEmail}
          onChange={(e) => setTargetEmail(e.target.value)}
          placeholder="البريد (اختياري)"
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
          className="md:col-span-1 px-2 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs text-white focus:border-[#D4AF37] outline-none"
        >
          <option value={30}>30 يوم</option>
          <option value={90}>90 يوم</option>
          <option value={365}>سنة</option>
          <option value={0}>دائم</option>
        </select>
        <button
          type="submit"
          disabled={Boolean(savingUid)}
          className="md:col-span-2 py-2 px-3 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-lg transition cursor-pointer disabled:opacity-50"
        >
          تفعيل الاشتراك
        </button>
      </form>

      {/* Registered Users Table */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-xs font-bold text-gray-300">
            <Users className="w-4 h-4 text-[#D4AF37]" />
            <span>المستخدمون المسجلون ({usersList.length})</span>
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
  );
};
