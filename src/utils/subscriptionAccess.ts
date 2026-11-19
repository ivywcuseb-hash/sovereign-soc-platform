import type { User } from 'firebase/auth';
import type { AppTabId } from '../components/LayoutCustomizer';

/**
 * Platform Owner / Administrator identities that are automatically exempt
 * from all subscription restrictions and receive unrestricted access to every lab.
 */
export const OWNER_EMAILS: ReadonlySet<string> = new Set([
  'ivywcuseb@gmail.com',
]);

export const OWNER_UIDS: ReadonlySet<string> = new Set<string>([
  // Add specific owner Firebase Auth UID(s) if needed in addition to email/role checks
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

/**
 * Core free tools accessible to any authenticated user without a paid subscription.
 * All specialized forensic labs, SOC dashboards, OSINT, and AI Voice Core require
 * an active Firestore subscription (unless the user is the Platform Owner or Admin).
 */
export const FREE_CORE_TABS: ReadonlySet<AppTabId> = new Set<AppTabId>([
  'dashboard',
  'analyzer',
  'evidence',
  'audit',
  'profile',
  'samples',
]);

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

export function isOwnerEmailAccount(user: User | null | undefined, profile?: AccessUserProfileLike | null): boolean {
  if (!user) return false;
  const emailCandidates = [
    user.email,
    ...(user.providerData?.map((p) => p?.email) || []),
  ]
    .filter((v): v is string => typeof v === 'string' && v.trim().length > 0)
    .map((v) => v.trim().toLowerCase());

  // Require Firebase Auth emailVerified (Google sign-in always sets emailVerified = true)
  if (user.emailVerified === false) return false;

  if (emailCandidates.some((em) => OWNER_EMAILS.has(em))) {
    return true;
  }

  // Fallback check if profile email matches owner while user object is Google-authenticated
  const profileEmail = profile?.email?.trim().toLowerCase();
  if (profileEmail && OWNER_EMAILS.has(profileEmail) && user.emailVerified) {
    return true;
  }
  return false;
}

export function isPlatformAdminOrOwner(
  user: User | null | undefined,
  profile?: AccessUserProfileLike | null
): boolean {
  if (!user) return false;
  if (profile?.role === 'admin') return true;
  if (OWNER_UIDS.has(user.uid)) return true;
  if (isOwnerEmailAccount(user, profile)) return true;
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
  isAdminOrOwner: boolean;
  isOwnerEmail: boolean;
  hasActiveSubscription: boolean;
  hasFullAccess: boolean;
  effectivePlanLabel: string;
  effectiveRoleLabel: string;
  subscription: UserSubscriptionRecord | null;
  subscriptionLoaded: boolean;
  isTabLocked: (tabId: AppTabId) => boolean;
}

export function computeSovereignAccessState(
  user: User | null | undefined,
  profile: AccessUserProfileLike | null | undefined,
  subscription: UserSubscriptionRecord | null | undefined,
  subscriptionLoaded: boolean
): SovereignAccessState {
  const isOwnerEmail = isOwnerEmailAccount(user, profile);
  const isAdminOrOwner = isPlatformAdminOrOwner(user, profile);
  const subRecord = subscription || null;
  const hasActiveSub = isSubscriptionActive(subRecord);
  const hasFullAccess = isAdminOrOwner || hasActiveSub;

  let effectivePlanLabel = 'الخطة المجانية (أدوات أساسية)';
  if (isOwnerEmail) {
    effectivePlanLabel = 'مالك المنصة — وصول كامل (معفى تلقائياً)';
  } else if (isAdminOrOwner) {
    effectivePlanLabel = 'مسؤول النظام (Admin) — وصول كامل';
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

  const effectiveRoleLabel = isOwnerEmail
    ? 'OWNER / ADMIN'
    : isAdminOrOwner
    ? 'ADMIN'
    : (profile?.role || 'analyst').toUpperCase();

  return {
    isAdminOrOwner,
    isOwnerEmail,
    hasActiveSubscription: hasActiveSub,
    hasFullAccess,
    effectivePlanLabel,
    effectiveRoleLabel,
    subscription: subRecord,
    subscriptionLoaded,
    isTabLocked: (tabId: AppTabId) => {
      if (hasFullAccess) return false;
      return !FREE_CORE_TABS.has(tabId);
    },
  };
}
