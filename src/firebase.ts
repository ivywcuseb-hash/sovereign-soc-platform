import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  signOut,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updateProfile,
  GoogleAuthProvider,
  signInWithPopup,
  browserLocalPersistence,
  setPersistence
} from 'firebase/auth';
import { getFirestore, doc, getDocFromServer } from 'firebase/firestore';
import { getStorage, uploadBytesResumable, deleteObject } from 'firebase/storage';
import defaultFirebaseConfig from '../firebase-applet-config.json';

const CUSTOM_FIREBASE_STORAGE_KEY = 'sovereign_custom_firebase_config';

export const PRIMARY_VERCEL_DOMAIN = 'sovqs.vercel.app';
export const LEGACY_VERCEL_DOMAINS = [
  'sovsoc.vercel.app',
  'sovereign-soc-platform-9wwm.vercel.app',
] as const;

const DEPRECATED_FIREBASE_PROJECT_IDS = new Set<string>([
  'ai-studio-applet-webapp-6aff0',
  'remixed-project-id',
]);

export interface SovereignFirebaseConfig {
  projectId: string;
  appId: string;
  apiKey: string;
  authDomain: string;
  firestoreDatabaseId?: string;
  storageBucket?: string;
  messagingSenderId?: string;
}

export interface DomainVerificationStatus {
  hostname: string;
  isPrimaryVercelDomain: boolean;
  isLegacyVercelDomain: boolean;
  isAiStudioRuntime: boolean;
  isLocalhost: boolean;
  isRecognizedDomain: boolean;
  canonicalUrl: string;
  expectedAuthDomain: string;
}

function loadActiveFirebaseConfig(): { config: SovereignFirebaseConfig; isCustom: boolean } {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      const raw = window.localStorage.getItem(CUSTOM_FIREBASE_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (
          parsed &&
          parsed.apiKey &&
          parsed.authDomain &&
          parsed.projectId &&
          parsed.appId &&
          !DEPRECATED_FIREBASE_PROJECT_IDS.has(String(parsed.projectId).trim())
        ) {
          return { config: parsed as SovereignFirebaseConfig, isCustom: true };
        }
        // Automatically discard stale or deprecated Firebase config overrides
        window.localStorage.removeItem(CUSTOM_FIREBASE_STORAGE_KEY);
      }
    }
  } catch {
    // Fallback cleanly to active provisioned config
  }
  const baseConfig = defaultFirebaseConfig as SovereignFirebaseConfig;
  const resolvedAuthDomain = (
    (import.meta as any).env?.VITE_FIREBASE_AUTH_DOMAIN || 'sovqs.vercel.app'
  ).trim().toLowerCase();

  return {
    config: {
      ...baseConfig,
      authDomain: resolvedAuthDomain,
    },
    isCustom: false,
  };
}

const { config: firebaseConfig, isCustom: isUsingCustomFirebaseConfig } = loadActiveFirebaseConfig();

export function parseFirebaseConfigInput(rawInput: string): SovereignFirebaseConfig | null {
  const trimmed = rawInput.trim();
  if (!trimmed) return null;

  try {
    const direct = JSON.parse(trimmed);
    if (direct.apiKey && direct.authDomain && direct.projectId && direct.appId) {
      return direct as SovereignFirebaseConfig;
    }
  } catch {
    // Extract key/value pairs from JS snippet (e.g. const firebaseConfig = { apiKey: "...", ... })
  }

  const extractField = (field: string): string | undefined => {
    const regex = new RegExp(`["']?${field}["']?\\s*:\\s*["']([^"']+)["']`);
    const match = trimmed.match(regex);
    return match?.[1];
  };

  const apiKey = extractField('apiKey');
  const authDomain = extractField('authDomain');
  const projectId = extractField('projectId');
  const appId = extractField('appId');

  if (!apiKey || !authDomain || !projectId || !appId) {
    return null;
  }

  return {
    apiKey,
    authDomain,
    projectId,
    appId,
    storageBucket: extractField('storageBucket'),
    messagingSenderId: extractField('messagingSenderId'),
    firestoreDatabaseId: extractField('firestoreDatabaseId') || '(default)',
  };
}

export function saveCustomFirebaseConfig(cfg: SovereignFirebaseConfig) {
  window.localStorage.setItem(CUSTOM_FIREBASE_STORAGE_KEY, JSON.stringify(cfg));
  window.location.reload();
}

export function resetCustomFirebaseConfig() {
  window.localStorage.removeItem(CUSTOM_FIREBASE_STORAGE_KEY);
  window.location.reload();
}

const app = initializeApp(firebaseConfig);
export const db = firebaseConfig.firestoreDatabaseId && firebaseConfig.firestoreDatabaseId !== '(default)'
  ? getFirestore(app, firebaseConfig.firestoreDatabaseId)
  : getFirestore(app);
export const auth = getAuth(app);
auth.languageCode = 'ar';
if (typeof window !== 'undefined') {
  void setPersistence(auth, browserLocalPersistence).catch(() => {});
}
export const storage = getStorage(app);

export function createGoogleAuthProvider(): GoogleAuthProvider {
  const provider = new GoogleAuthProvider();
  provider.addScope('email');
  provider.addScope('profile');
  provider.setCustomParameters({
    prompt: 'select_account',
  });
  return provider;
}

export function verifyAppDomainForGoogleAuth(): DomainVerificationStatus {
  const hostname =
    typeof window !== 'undefined' ? window.location.hostname.toLowerCase() : PRIMARY_VERCEL_DOMAIN;
  const isPrimaryVercelDomain = hostname === PRIMARY_VERCEL_DOMAIN;
  const isLegacyVercelDomain = (LEGACY_VERCEL_DOMAINS as readonly string[]).includes(hostname);
  const isAiStudioRuntime =
    hostname.endsWith('.run.app') ||
    hostname.endsWith('.scf.usercontent.goog') ||
    hostname.endsWith('.googleusercontent.com');
  const isLocalhost =
    hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
  const isRecognizedDomain =
    isPrimaryVercelDomain || isAiStudioRuntime || isLocalhost;

  return {
    hostname,
    isPrimaryVercelDomain,
    isLegacyVercelDomain,
    isAiStudioRuntime,
    isLocalhost,
    isRecognizedDomain,
    canonicalUrl: `https://${PRIMARY_VERCEL_DOMAIN}/`,
    expectedAuthDomain: firebaseConfig.authDomain,
  };
}

export { 
  firebaseConfig,
  isUsingCustomFirebaseConfig,
  signOut,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updateProfile,
  uploadBytesResumable,
  deleteObject,
  GoogleAuthProvider,
  signInWithPopup
};

// Test connection
async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
testConnection();

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null) {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo: auth.currentUser?.providerData?.map(provider => ({
        providerId: provider.providerId,
        email: provider.email,
      })) || []
    },
    operationType,
    path
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}
