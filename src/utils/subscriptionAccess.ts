import type { User } from 'firebase/auth';
import { doc, getDocFromServer, onSnapshot, setDoc } from 'firebase/firestore';
import { db, handleFirestoreError, OperationType } from '../firebase';
import { NAV_TABS_META, type AppTabId } from '../components/LayoutCustomizer';

/**
 * Platform Owner / Developer / Administrator identities that are automatically
 * exempt from all subscription restrictions and receive unrestricted access to every tool.
 */
export const OWNER_EMAILS: ReadonlySet<string> = new Set([
  'ivywcusel@gmail.com',
  'ivywcuseb@gmail.com',
]);

export const OWNER_UIDS: ReadonlySet<string> = new Set<string>([
  'T1C6FEfH2CYtQm7mWElPY1L0x3I3',
]);

export type SubscriptionPlanId = 'free' | 'pro' | 'enterprise';
export type SubscriptionStatusId = 'active' | 'inactive' | 'expired' | 'revoked';

export interface UserSubscriptionRecord {
  userId: string;
  email?: string;
  plan: SubscriptionPlanId;
  status: SubscriptionStatusId;
  expiresAt?: string;
  grantedBy?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
}

export interface AccessUserProfileLike {
  uid?: string;
  email?: string;
  role?: 'analyst' | 'admin' | string;
}

export const TOOL_ACCESS_COLLECTION = 'platform_config';
export const TOOL_ACCESS_DOC_ID = 'tool_access';
export const TOOL_ACCESS_DOC_PATH = `${TOOL_ACCESS_COLLECTION}/${TOOL_ACCESS_DOC_ID}`;

export const VALID_TOOL_IDS: ReadonlySet<AppTabId> = new Set<AppTabId>(
  NAV_TABS_META.map((t) => t.id)
);

/**
 * Core free tools by default when no custom Firestore tool_access override exists.
 */
export const FREE_CORE_TABS: ReadonlySet<AppTabId> = new Set<AppTabId>([
  'dashboard',
  'analyzer',
  'evidence',
  'audit',
  'profile',
  'samples',
]);

/**
 * Canonical default list of locked tools (`lockedTools`) for non-subscribed users.
 * Owner can override this dynamically in Firestore (`platform_config/tool_access`).
 */
export const DEFAULT_LOCKED_TOOLS: AppTabId[] = NAV_TABS_META
  .map((t) => t.id)
  .filter((id) => !FREE_CORE_TABS.has(id));

export const DEFAULT_PAID_TABS: AppTabId[] = DEFAULT_LOCKED_TOOLS;

export const LOCKED_TOOLS_LOCAL_STORAGE_KEY = 'sovereign_locked_tools';
export const PAID_TABS_LOCAL_STORAGE_KEY = 'sovereign_paid_tabs_config';

export function sanitizeLockedToolsList(raw: unknown): AppTabId[] {
  if (!Array.isArray(raw)) return [];
  return Array.from(
    new Set(
      raw.filter(
        (id): id is AppTabId =>
          typeof id === 'string' &&
          VALID_TOOL_IDS.has(id as AppTabId) &&
          id !== 'profile'
      )
    )
  );
}

export function extractLockedToolsFromConfigData(
  data: Record<string, unknown> | null | undefined
): AppTabId[] | null {
  if (!data || typeof data !== 'object') return null;
  if (Array.isArray(data.lockedTools)) {
    return sanitizeLockedToolsList(data.lockedTools);
  }
  if (Array.isArray(data.paidTabs)) {
    return sanitizeLockedToolsList(data.paidTabs);
  }
  return null;
}

export function readLocalLockedToolsBackup(): AppTabId[] | null {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return null;
    const primaryRaw = window.localStorage.getItem(LOCKED_TOOLS_LOCAL_STORAGE_KEY);
    if (primaryRaw !== null) {
      const parsed = JSON.parse(primaryRaw);
      if (Array.isArray(parsed)) {
        return sanitizeLockedToolsList(parsed);
      }
    }
    const legacyRaw = window.localStorage.getItem(PAID_TABS_LOCAL_STORAGE_KEY);
    if (legacyRaw !== null) {
      const parsed = JSON.parse(legacyRaw);
      if (Array.isArray(parsed)) {
        const sanitized = sanitizeLockedToolsList(parsed);
        window.localStorage.setItem(LOCKED_TOOLS_LOCAL_STORAGE_KEY, JSON.stringify(sanitized));
        return sanitized;
      }
    }
    return null;
  } catch {
    return null;
  }
}

export function writeLocalLockedToolsBackup(lockedTools: readonly AppTabId[] | null): void {
  try {
    if (typeof window === 'undefined' || !window.localStorage) return;
    if (lockedTools === null) {
      window.localStorage.removeItem(LOCKED_TOOLS_LOCAL_STORAGE_KEY);
      window.localStorage.removeItem(PAID_TABS_LOCAL_STORAGE_KEY);
      return;
    }
    const sanitized = sanitizeLockedToolsList(lockedTools);
    const serialized = JSON.stringify(sanitized);
    window.localStorage.setItem(LOCKED_TOOLS_LOCAL_STORAGE_KEY, serialized);
    window.localStorage.setItem(PAID_TABS_LOCAL_STORAGE_KEY, serialized);
  } catch {}
}

export const readLocalPaidTabsBackup = readLocalLockedToolsBackup;
export const writeLocalPaidTabsBackup = writeLocalLockedToolsBackup;

export interface SaveLockedToolsResult {
  lockedTools: AppTabId[];
  updatedAt: string;
  syncedToCloud: boolean;
  permissionDenied?: boolean;
  errorCode?: string;
  errorMessage?: string;
}

/**
 * Subscribe to the single canonical `lockedTools` list in Firestore (`platform_config/tool_access`)
 * and perform an authoritative server read while preserving localStorage overrides if Firestore
 * has not been initialized yet or rejects access.
 */
export function subscribeToLockedToolsConfig(
  onConfigChange: (nextLockedTools: AppTabId[] | null) => void
): () => void {
  const configRef = doc(db, TOOL_ACCESS_COLLECTION, TOOL_ACCESS_DOC_ID);
  let disposed = false;

  const applyMissingCloudDocFallback = () => {
    const localBackup = readLocalLockedToolsBackup();
    if (localBackup !== null) {
      onConfigChange(localBackup);
    } else {
      onConfigChange(null);
    }
  };

  void getDocFromServer(configRef)
    .then((serverSnap) => {
      if (disposed) return;
      if (serverSnap.exists()) {
        const extracted = extractLockedToolsFromConfigData(serverSnap.data());
        if (extracted !== null) {
          writeLocalLockedToolsBackup(extracted);
          onConfigChange(extracted);
        }
      } else {
        applyMissingCloudDocFallback();
      }
    })
    .catch(() => {
      // Offline, permission-denied, or transient error — keep localStorage backup active silently
    });

  const unsub = onSnapshot(
    configRef,
    (cfgSnap) => {
      if (disposed) return;
      if (cfgSnap.exists()) {
        const extracted = extractLockedToolsFromConfigData(cfgSnap.data());
        if (extracted !== null) {
          writeLocalLockedToolsBackup(extracted);
          onConfigChange(extracted);
        }
      } else if (!cfgSnap.metadata.fromCache) {
        applyMissingCloudDocFallback();
      }
    },
    (error: any) => {
      const code = String(error?.code || '');
      const msg = String(error?.message || '');
      if (code === 'permission-denied' || msg.toLowerCase().includes('permission')) {
        applyMissingCloudDocFallback();
        return;
      }
      console.warn('Tool access config snapshot error:', error);
    }
  );

  return () => {
    disposed = true;
    unsub();
  };
}

/**
 * Save `lockedTools` directly to localStorage first so toggles work immediately,
 * then quietly attempt to synchronize with Firestore (`platform_config/tool_access`).
 * On `permission-denied`, keeps the local save without throwing a failure error.
 */
export async function saveLockedToolsConfigToFirestore(
  nextLockedTools: readonly AppTabId[],
  updatedByUid: string
): Promise<SaveLockedToolsResult> {
  const sanitized = sanitizeLockedToolsList(nextLockedTools);
  const updatedAt = new Date().toISOString();

  // 1. Always persist immediately to localStorage first
  writeLocalLockedToolsBackup(sanitized);

  // 2. Quietly sync with Firestore
  const configRef = doc(db, TOOL_ACCESS_COLLECTION, TOOL_ACCESS_DOC_ID);
  try {
    await setDoc(configRef, {
      lockedTools: sanitized,
      paidTabs: sanitized,
      updatedBy: (updatedByUid || 'owner').slice(0, 128),
      updatedAt,
    });
    return {
      lockedTools: sanitized,
      updatedAt,
      syncedToCloud: true,
    };
  } catch (error: any) {
    const errorCode = String(error?.code || '');
    const errorMessage = String(error?.message || '');
    const isPermissionDenied =
      errorCode === 'permission-denied' ||
      errorMessage.toLowerCase().includes('permission') ||
      errorMessage.toLowerCase().includes('insufficient permissions');

    if (isPermissionDenied) {
      console.info('[Sovereign Access] Firestore rules restricted write; lockedTools saved locally in localStorage.');
      return {
        lockedTools: sanitized,
        updatedAt,
        syncedToCloud: false,
        permissionDenied: true,
        errorCode,
        errorMessage,
      };
    }

    console.warn('[Sovereign Access] Cloud sync deferred; lockedTools saved locally:', errorMessage || error);
    try {
      handleFirestoreError(error, OperationType.WRITE, TOOL_ACCESS_DOC_PATH);
    } catch {
      // Structured diagnostics logged safely
    }
    return {
      lockedTools: sanitized,
      updatedAt,
      syncedToCloud: false,
      permissionDenied: false,
      errorCode,
      errorMessage,
    };
  }
}

export function resolveNormalizedUserEmail(user: User | null | undefined, profile?: AccessUserProfileLike | null): string {
  const candidates = [
    user?.email,
    ...(user?.providerData?.map((p) => p?.email) || []),
    profile?.email,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.trim()) {
      return candidate.trim().toLowerCase();
    }
  }
  return '';
}

export function isOwnerUidAccount(user: User | null | undefined, profile?: AccessUserProfileLike | null): boolean {
  const uidCandidates = [user?.uid, profile?.uid]
    .filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
    .map((v) => v.trim());
  return uidCandidates.some((uid) => OWNER_UIDS.has(uid));
}

export function isOwnerEmailAccount(user: User | null | undefined, profile?: AccessUserProfileLike | null): boolean {
  if (!user && !profile) return false;
  const emailCandidates = [
    user?.email,
    ...(user?.providerData?.map((p) => p?.email) || []),
    (user as unknown as { reloadUserInfo?: { email?: string } } | null | undefined)?.reloadUserInfo?.email,
    profile?.email,
  ]
    .filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
    .map((v) => v.trim().toLowerCase());

  return emailCandidates.some((em) => OWNER_EMAILS.has(em));
}

export function isPlatformAdminOrOwner(
  user: User | null | undefined,
  profile?: AccessUserProfileLike | null
): boolean {
  if (!user && !profile) return false;
  if (isOwnerUidAccount(user, profile)) return true;
  if (isOwnerEmailAccount(user, profile)) return true;
  if (profile?.role === 'admin') return true;
  return false;
}

export function isSubscriptionActive(sub: UserSubscriptionRecord | null | undefined): boolean {
  if (!sub) return false;
  if (sub.status !== 'active') return false;
  if (sub.plan !== 'pro' && sub.plan !== 'enterprise') return false;
  if (sub.expiresAt) {
    const expMs = new Date(sub.expiresAt).getTime();
    if (!Number.isNaN(expMs) && expMs <= Date.now()) {
      return false;
    }
  }
  return true;
}

export interface SovereignAccessState {
  isOwner: boolean;
  isDeveloper: boolean;
  isAdmin: boolean;
  isPro: boolean;
  hasAccess: boolean;
  isAdminOrOwner: boolean;
  isOwnerEmail: boolean;
  isOwnerUid: boolean;
  hasActiveSubscription: boolean;
  hasFullAccess: boolean;
  effectivePlanLabel: string;
  effectiveRoleLabel: string;
  subscription: UserSubscriptionRecord | null;
  subscriptionLoaded: boolean;
  lockedTools: readonly AppTabId[];
  lockedToolsSet: ReadonlySet<AppTabId>;
  activePaidTabs: ReadonlySet<AppTabId>;
  isToolInLockedList: (tabId: AppTabId) => boolean;
  isTabPaidForUsers: (tabId: AppTabId) => boolean;
  isTabLocked: (tabId: AppTabId) => boolean;
  canOpenTool: (tabId: AppTabId) => boolean;
}

export function hasOwnerOrSubscriptionAccess(
  user: User | null | undefined,
  profile: AccessUserProfileLike | null | undefined,
  subscription: UserSubscriptionRecord | null | undefined
): boolean {
  if (isPlatformAdminOrOwner(user, profile)) return true;
  return isSubscriptionActive(subscription);
}

export function computeSovereignAccessState(
  user: User | null | undefined,
  profile: AccessUserProfileLike | null | undefined,
  subscription: UserSubscriptionRecord | null | undefined,
  subscriptionLoaded: boolean,
  lockedToolsOverride?: readonly AppTabId[] | null
): SovereignAccessState {
  const isOwnerUid = isOwnerUidAccount(user, profile);
  const isOwnerEmail = isOwnerEmailAccount(user, profile);
  const isOwnerIdentity = isOwnerUid || isOwnerEmail;
  const isAdminOrOwner = isOwnerIdentity || isPlatformAdminOrOwner(user, profile);
  const subRecord = subscription || null;
  const hasActiveSub = isSubscriptionActive(subRecord);
  const hasFullAccess = isOwnerIdentity || isAdminOrOwner || hasActiveSub;

  const resolvedLockedTools = sanitizeLockedToolsList(
    lockedToolsOverride !== undefined && lockedToolsOverride !== null
      ? lockedToolsOverride
      : DEFAULT_LOCKED_TOOLS
  );
  const lockedToolsSet = new Set<AppTabId>(resolvedLockedTools);

  let effectivePlanLabel = 'الخطة المجانية (أدوات أساسية)';
  if (isOwnerIdentity) {
    effectivePlanLabel = 'مالك ومطور المنصة (Pro / Owner) — وصول كامل بدون قيود';
  } else if (isAdminOrOwner) {
    effectivePlanLabel = 'مسؤول النظام (Admin / Pro) — وصول كامل';
  } else if (hasActiveSub && subRecord) {
    effectivePlanLabel =
      subRecord.plan === 'enterprise'
        ? 'باقة المؤسسات (Enterprise — نشط)'
        : 'الباقة الاحترافية (Pro — نشط)';
  } else if (subRecord?.status === 'expired' || (subRecord?.expiresAt && new Date(subRecord.expiresAt).getTime() <= Date.now())) {
    effectivePlanLabel = 'الاشتراك منتهي الصلاحية';
  } else if (subRecord?.status === 'revoked') {
    effectivePlanLabel = 'تم إيقاف الاشتراك';
  }

  const effectiveRoleLabel = isOwnerIdentity
    ? 'OWNER / DEVELOPER'
    : isAdminOrOwner
    ? 'ADMIN'
    : (profile?.role || 'analyst').toUpperCase();

  const isToolInLockedList = (tabId: AppTabId): boolean =>
    tabId !== 'profile' && lockedToolsSet.has(tabId);

  const isTabLocked = (tabId: AppTabId): boolean => {
    if (isOwnerIdentity || isAdminOrOwner || hasFullAccess) return false;
    if (tabId === 'profile') return false;
    return lockedToolsSet.has(tabId);
  };

  return {
    isOwner: isOwnerIdentity,
    isDeveloper: isOwnerIdentity,
    isAdmin: isAdminOrOwner,
    isPro: hasFullAccess,
    hasAccess: hasFullAccess,
    isAdminOrOwner,
    isOwnerEmail,
    isOwnerUid,
    hasActiveSubscription: hasActiveSub || isOwnerIdentity,
    hasFullAccess,
    effectivePlanLabel,
    effectiveRoleLabel,
    subscription: subRecord,
    subscriptionLoaded,
    lockedTools: resolvedLockedTools,
    lockedToolsSet,
    activePaidTabs: lockedToolsSet,
    isToolInLockedList,
    isTabPaidForUsers: isToolInLockedList,
    isTabLocked,
    canOpenTool: (tabId: AppTabId) => !isTabLocked(tabId),
  };
}
