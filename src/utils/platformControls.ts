import { doc, getDocFromServer, onSnapshot, setDoc } from 'firebase/firestore';
import { db, handleFirestoreError, OperationType } from '../firebase';
import {
  NAV_GROUP_ORDER,
  NAV_TABS_META,
  type AppTabId,
  type NavGroupId,
} from '../components/LayoutCustomizer';

export const SITE_CONTROLS_COLLECTION = 'platform_config';
export const SITE_CONTROLS_DOC_ID = 'site_controls';
export const SITE_CONTROLS_DOC_PATH = `${SITE_CONTROLS_COLLECTION}/${SITE_CONTROLS_DOC_ID}`;

export const MAX_ANNOUNCEMENT_LENGTH = 500;
export const MAX_MAINTENANCE_MESSAGE_LENGTH = 500;

export type AnnouncementType = 'info' | 'warning' | 'critical' | 'success';

export const ANNOUNCEMENT_TYPE_META: Record<
  AnnouncementType,
  {
    labelAr: string;
    badgeAr: string;
    descriptionAr: string;
  }
> = {
  info: {
    labelAr: 'معلومات عامة',
    badgeAr: 'إعلان المنصة',
    descriptionAr: 'توجيه عام أو تحديث إرشادي للمستخدمين',
  },
  warning: {
    labelAr: 'تنبيه / تحذير',
    badgeAr: 'تنبيه إداري',
    descriptionAr: 'ملاحظة تشغيلية مهمة تتطلب الانتباه',
  },
  critical: {
    labelAr: 'تنبيه حرج / عاجل',
    badgeAr: 'تنبيه عاجل',
    descriptionAr: 'إشعار أمني أو تشغيلي عالي الأولوية',
  },
  success: {
    labelAr: 'إشعار إيجابي / تحديث مكتمل',
    badgeAr: 'تحديث المنصة',
    descriptionAr: 'إعلان إتاحة ميزة أو اكتمال ترقية',
  },
};

export interface PlatformSiteControls {
  announcementEnabled: boolean;
  announcementText: string;
  announcementType: AnnouncementType;
  announcementUpdatedAt: string;
  maintenanceTools: AppTabId[];
  maintenanceGroups: NavGroupId[];
  maintenanceMessage: string;
  maintenanceUpdatedAt: string;
  updatedBy: string;
  updatedAt: string;
}

export const DEFAULT_PLATFORM_SITE_CONTROLS: PlatformSiteControls = {
  announcementEnabled: false,
  announcementText: '',
  announcementType: 'info',
  announcementUpdatedAt: '',
  maintenanceTools: [],
  maintenanceGroups: [],
  maintenanceMessage: '',
  maintenanceUpdatedAt: '',
  updatedBy: '',
  updatedAt: '',
};

const VALID_TOOL_IDS: ReadonlySet<AppTabId> = new Set<AppTabId>(NAV_TABS_META.map((t) => t.id));
const VALID_GROUP_IDS: ReadonlySet<NavGroupId> = new Set<NavGroupId>(NAV_GROUP_ORDER);
const VALID_ANNOUNCEMENT_TYPES: ReadonlySet<AnnouncementType> = new Set<AnnouncementType>([
  'info',
  'warning',
  'critical',
  'success',
]);

export const GROUP_LABELS_BY_ID: Record<NavGroupId, string> = NAV_GROUP_ORDER.reduce(
  (acc, groupId) => {
    const first = NAV_TABS_META.find((t) => t.group === groupId);
    acc[groupId] = first?.groupLabel || groupId;
    return acc;
  },
  {} as Record<NavGroupId, string>
);

export function sanitizeAnnouncementType(raw: unknown): AnnouncementType {
  if (typeof raw === 'string' && VALID_ANNOUNCEMENT_TYPES.has(raw as AnnouncementType)) {
    return raw as AnnouncementType;
  }
  return 'info';
}

export function sanitizeBoundedString(raw: unknown, maxLen: number): string {
  if (typeof raw !== 'string') return '';
  return raw.slice(0, maxLen);
}

export function sanitizeMaintenanceTools(raw: unknown): AppTabId[] {
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
  ).slice(0, 100);
}

export function sanitizeMaintenanceGroups(raw: unknown): NavGroupId[] {
  if (!Array.isArray(raw)) return [];
  return Array.from(
    new Set(
      raw.filter(
        (id): id is NavGroupId =>
          typeof id === 'string' && VALID_GROUP_IDS.has(id as NavGroupId)
      )
    )
  ).slice(0, 10);
}

export function parsePlatformSiteControls(
  data: Record<string, unknown> | null | undefined
): PlatformSiteControls {
  if (!data || typeof data !== 'object') {
    return { ...DEFAULT_PLATFORM_SITE_CONTROLS };
  }
  return {
    announcementEnabled: Boolean(data.announcementEnabled),
    announcementText: sanitizeBoundedString(data.announcementText, MAX_ANNOUNCEMENT_LENGTH),
    announcementType: sanitizeAnnouncementType(data.announcementType),
    announcementUpdatedAt: sanitizeBoundedString(data.announcementUpdatedAt, 64),
    maintenanceTools: sanitizeMaintenanceTools(data.maintenanceTools),
    maintenanceGroups: sanitizeMaintenanceGroups(data.maintenanceGroups),
    maintenanceMessage: sanitizeBoundedString(
      data.maintenanceMessage,
      MAX_MAINTENANCE_MESSAGE_LENGTH
    ),
    maintenanceUpdatedAt: sanitizeBoundedString(data.maintenanceUpdatedAt, 64),
    updatedBy: sanitizeBoundedString(data.updatedBy, 128),
    updatedAt: sanitizeBoundedString(data.updatedAt, 64),
  };
}

export interface TabMaintenanceStatus {
  inMaintenance: boolean;
  scope: 'tool' | 'group' | null;
  groupId: NavGroupId | null;
  groupLabel: string;
  toolLabel: string;
  message: string;
  updatedAt: string;
}

export function getTabMaintenanceInfo(
  controls: PlatformSiteControls,
  tabId: AppTabId
): TabMaintenanceStatus {
  const meta = NAV_TABS_META.find((t) => t.id === tabId);
  const groupId = meta?.group || null;
  const groupLabel = meta?.groupLabel || '';
  const toolLabel = meta?.label || tabId;

  // Never place Account & Admin Settings ('profile') in maintenance lockout
  if (tabId === 'profile') {
    return {
      inMaintenance: false,
      scope: null,
      groupId,
      groupLabel,
      toolLabel,
      message: '',
      updatedAt: '',
    };
  }

  const groupInMaintenance = Boolean(groupId && controls.maintenanceGroups.includes(groupId));
  const toolInMaintenance = controls.maintenanceTools.includes(tabId);

  if (!groupInMaintenance && !toolInMaintenance) {
    return {
      inMaintenance: false,
      scope: null,
      groupId,
      groupLabel,
      toolLabel,
      message: '',
      updatedAt: '',
    };
  }

  const customMessage = controls.maintenanceMessage.trim();
  const scope: 'tool' | 'group' = groupInMaintenance ? 'group' : 'tool';

  return {
    inMaintenance: true,
    scope,
    groupId,
    groupLabel,
    toolLabel,
    message:
      customMessage ||
      (scope === 'group'
        ? `قسم "${groupLabel}" متوقف مؤقتاً لأعمال الصيانة والتحديث.`
        : `أداة "${toolLabel}" متوقفة مؤقتاً لأعمال الصيانة والتحديث.`),
    updatedAt: controls.maintenanceUpdatedAt || controls.updatedAt,
  };
}

export function subscribeToPlatformSiteControls(
  onUpdate: (
    controls: PlatformSiteControls,
    meta: { existsInCloud: boolean; fromCache: boolean }
  ) => void,
  onError?: (err: { permissionDenied: boolean; message: string }) => void
): () => void {
  const controlsRef = doc(db, SITE_CONTROLS_COLLECTION, SITE_CONTROLS_DOC_ID);
  let disposed = false;

  void getDocFromServer(controlsRef)
    .then((serverSnap) => {
      if (disposed) return;
      if (serverSnap.exists()) {
        onUpdate(parsePlatformSiteControls(serverSnap.data()), {
          existsInCloud: true,
          fromCache: false,
        });
      } else {
        onUpdate({ ...DEFAULT_PLATFORM_SITE_CONTROLS }, {
          existsInCloud: false,
          fromCache: false,
        });
      }
    })
    .catch(() => {
      // Snapshot listener below handles authoritative state and errors
    });

  const unsub = onSnapshot(
    controlsRef,
    (snap) => {
      if (disposed) return;
      if (snap.exists()) {
        onUpdate(parsePlatformSiteControls(snap.data()), {
          existsInCloud: true,
          fromCache: snap.metadata.fromCache,
        });
      } else if (!snap.metadata.fromCache) {
        onUpdate({ ...DEFAULT_PLATFORM_SITE_CONTROLS }, {
          existsInCloud: false,
          fromCache: false,
        });
      }
    },
    (error: any) => {
      if (disposed) return;
      const code = String(error?.code || '');
      const message = String(error?.message || 'Firestore read error');
      const permissionDenied =
        code === 'permission-denied' ||
        message.toLowerCase().includes('permission') ||
        message.toLowerCase().includes('insufficient permissions');
      onError?.({ permissionDenied, message });
      try {
        handleFirestoreError(error, OperationType.GET, SITE_CONTROLS_DOC_PATH);
      } catch {
        // Structured diagnostics logged safely
      }
    }
  );

  return () => {
    disposed = true;
    unsub();
  };
}

export interface SavePlatformSiteControlsResult {
  controls: PlatformSiteControls;
  syncedToCloud: boolean;
  permissionDenied: boolean;
  errorCode?: string;
  errorMessage?: string;
}

/**
 * Persist administrative controls strictly to Firestore (`platform_config/site_controls`).
 * Never uses local fake fallbacks: unauthorized writes are rejected by Firestore Security Rules.
 */
export async function savePlatformSiteControlsToFirestore(
  nextControls: PlatformSiteControls,
  updatedByUid: string
): Promise<SavePlatformSiteControlsResult> {
  const nowIso = new Date().toISOString().slice(0, 64);
  const sanitizedPayload: PlatformSiteControls = {
    announcementEnabled: Boolean(nextControls.announcementEnabled),
    announcementText: sanitizeBoundedString(
      nextControls.announcementText.trim(),
      MAX_ANNOUNCEMENT_LENGTH
    ),
    announcementType: sanitizeAnnouncementType(nextControls.announcementType),
    announcementUpdatedAt: (nextControls.announcementUpdatedAt || nowIso).slice(0, 64),
    maintenanceTools: sanitizeMaintenanceTools(nextControls.maintenanceTools),
    maintenanceGroups: sanitizeMaintenanceGroups(nextControls.maintenanceGroups),
    maintenanceMessage: sanitizeBoundedString(
      nextControls.maintenanceMessage.trim(),
      MAX_MAINTENANCE_MESSAGE_LENGTH
    ),
    maintenanceUpdatedAt: (nextControls.maintenanceUpdatedAt || nowIso).slice(0, 64),
    updatedBy: (updatedByUid || 'unknown').slice(0, 128),
    updatedAt: nowIso,
  };

  const controlsRef = doc(db, SITE_CONTROLS_COLLECTION, SITE_CONTROLS_DOC_ID);
  try {
    await setDoc(controlsRef, sanitizedPayload);
    return {
      controls: sanitizedPayload,
      syncedToCloud: true,
      permissionDenied: false,
    };
  } catch (error: any) {
    const errorCode = String(error?.code || '');
    const errorMessage = String(error?.message || 'Firestore write failed');
    const permissionDenied =
      errorCode === 'permission-denied' ||
      errorMessage.toLowerCase().includes('permission') ||
      errorMessage.toLowerCase().includes('insufficient permissions');

    try {
      handleFirestoreError(error, OperationType.WRITE, SITE_CONTROLS_DOC_PATH);
    } catch {
      // Structured diagnostics logged cleanly
    }

    return {
      controls: sanitizedPayload,
      syncedToCloud: false,
      permissionDenied,
      errorCode,
      errorMessage,
    };
  }
}
