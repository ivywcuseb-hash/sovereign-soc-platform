// Client-Side Security Primitives: PBKDF2 PIN Hashing, Brute-Force Lockout, ReDoS Guard, URL XSS Sanitization
import { apiUrl } from './apiBase';

export function sanitizeSafeHref(rawUrl: unknown, allowBlobOrImageData = false): string {
  if (typeof rawUrl !== 'string') return '#';
  const trimmed = rawUrl.trim();
  if (!trimmed) return '#';

  // Reject control characters / hidden whitespace tricks like "java\tscript:"
  const normalized = trimmed.replace(/[\u0000-\u0020]/g, '').toLowerCase();
  if (
    normalized.startsWith('javascript:') ||
    normalized.startsWith('vbscript:') ||
    normalized.startsWith('file:')
  ) {
    return '#';
  }

  if (allowBlobOrImageData) {
    if (normalized.startsWith('blob:')) return trimmed;
    if (/^data:image\/(png|jpeg|jpg|webp|gif);base64,[a-z0-9+/=]+$/i.test(normalized)) {
      return trimmed;
    }
  }

  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      return parsed.toString();
    }
    return '#';
  } catch {
    return '#';
  }
}

export function isRegexSafe(pattern: string): { safe: boolean; reason?: string } {
  if (!pattern || typeof pattern !== 'string') {
    return { safe: false, reason: 'التعبير النمطي فارغ.' };
  }
  if (pattern.length > 256) {
    return { safe: false, reason: 'طول التعبير النمطي يتجاوز الحد الآمن (256 حرفاً).' };
  }
  // Detect nested quantifiers / catastrophic backtracking patterns (ReDoS)
  // e.g. (a+)+, (a*)*, (a+)*, ([a-z]+)+, (a|a?)+
  const nestedQuantifier =
    /\([^)]*(?:[+*]|\{\d+,\d*\})[^)]*\)\s*(?:[+*?]|\{\d+,\d*\})/;
  const overlappingAlternation =
    /\([^)|]+\|[^)]+\)\s*(?:[+*]|\{\d+,\d*\})/;
  const excessiveBackrefs = (pattern.match(/\\[1-9]/g) || []).length > 2;

  if (nestedQuantifier.test(pattern)) {
    return {
      safe: false,
      reason: 'تم رفض التعبير النمطي لمنع هجوم ReDoS (تداخل المكممات المتكررة Nested Quantifiers).',
    };
  }
  if (overlappingAlternation.test(pattern) && /[*+]{1}/.test(pattern)) {
    return {
      safe: false,
      reason: 'تم رفض التعبير النمطي لاحتمال استنزاف المعالج عبر التفرع المتداخل (ReDoS Protection).',
    };
  }
  if (excessiveBackrefs) {
    return {
      safe: false,
      reason: 'تم تجاوز الحد المسموح للمراجع الخلفية (Backreferences) حمايةً للأداء.',
    };
  }
  return { safe: true };
}

// Legacy compatibility hasher (used strictly for migrating pre-existing stored SHA-256 PINs on unlock)
async function legacySha256Pin(pin: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`sovereign_pin_secure_salt_${pin}`);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

const PBKDF2_ITERATIONS = 120000;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  const arr = new Uint8Array(clean.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return arr;
}

function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

export async function hashPinPbkdf2(pin: string, existingSaltHex?: string): Promise<string> {
  const encoder = new TextEncoder();
  const salt = existingSaltHex
    ? hexToBytes(existingSaltHex)
    : crypto.getRandomValues(new Uint8Array(16));
  const saltHex = bytesToHex(salt);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(pin),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const derivedHex = bytesToHex(new Uint8Array(derivedBits));
  return `pbkdf2$${PBKDF2_ITERATIONS}$${saltHex}$${derivedHex}`;
}

export async function verifyPinAgainstStoredHash(
  pin: string,
  storedHash: string
): Promise<{ valid: boolean; needsMigrationToPbkdf2: boolean }> {
  if (!storedHash || !pin) {
    return { valid: false, needsMigrationToPbkdf2: false };
  }
  if (storedHash.startsWith('pbkdf2$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 4) return { valid: false, needsMigrationToPbkdf2: false };
    const iterations = parseInt(parts[1], 10);
    const saltHex = parts[2];
    const expectedHex = parts[3];
    if (!Number.isFinite(iterations) || iterations < 10000 || !saltHex || !expectedHex) {
      return { valid: false, needsMigrationToPbkdf2: false };
    }
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(pin),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: hexToBytes(saltHex) as unknown as BufferSource,
        iterations,
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    );
    const actualHex = bytesToHex(new Uint8Array(derivedBits));
    return {
      valid: constantTimeEqualHex(actualHex, expectedHex),
      needsMigrationToPbkdf2: false,
    };
  }

  // Legacy SHA-256 verification for seamless backward compatibility
  const legacyHash = await legacySha256Pin(pin);
  const valid = constantTimeEqualHex(legacyHash, storedHash);
  return { valid, needsMigrationToPbkdf2: valid };
}

// ============================================================================
// Persistent PIN Brute-Force Lockout Manager
// ============================================================================
interface PinGuardState {
  failedAttempts: number;
  lockedUntilMs: number;
}

function getPinGuardKey(uid: string): string {
  return `sovereign_pin_guard_${uid || 'local'}`;
}

export function getPinLockoutRemainingSec(uid: string): number {
  try {
    const raw = localStorage.getItem(getPinGuardKey(uid));
    if (!raw) return 0;
    const state = JSON.parse(raw) as PinGuardState;
    if (state.lockedUntilMs && state.lockedUntilMs > Date.now()) {
      return Math.ceil((state.lockedUntilMs - Date.now()) / 1000);
    }
    return 0;
  } catch {
    return 0;
  }
}

export function recordFailedPinAttempt(uid: string): {
  failedAttempts: number;
  lockedSeconds: number;
} {
  let state: PinGuardState = { failedAttempts: 0, lockedUntilMs: 0 };
  try {
    const raw = localStorage.getItem(getPinGuardKey(uid));
    if (raw) state = JSON.parse(raw) as PinGuardState;
  } catch {
    state = { failedAttempts: 0, lockedUntilMs: 0 };
  }

  const nextAttempts = (state.failedAttempts || 0) + 1;
  let lockedSeconds = 0;
  if (nextAttempts >= 5) {
    // Exponential cooldown: 60s on 5th, 180s on 6th, 300s cap on 7th+
    const multiplier = Math.min(5, Math.pow(3, nextAttempts - 5));
    lockedSeconds = Math.min(300, 60 * multiplier);
  }
  const nextState: PinGuardState = {
    failedAttempts: nextAttempts,
    lockedUntilMs: lockedSeconds > 0 ? Date.now() + lockedSeconds * 1000 : 0,
  };
  try {
    localStorage.setItem(getPinGuardKey(uid), JSON.stringify(nextState));
  } catch {
    // Ignore storage quota errors
  }
  return { failedAttempts: nextAttempts, lockedSeconds };
}

export function clearPinFailureCounter(uid: string): void {
  try {
    localStorage.removeItem(getPinGuardKey(uid));
  } catch {
    // Ignore
  }
}

// ============================================================================
// Client Security Event Reporter (Redacted & Non-Blocking)
// ============================================================================
export async function reportClientSecurityEvent(params: {
  eventType: 'CLIENT_PIN_LOCKOUT' | 'CLIENT_SECURITY_ALERT' | 'SUSPICIOUS_INPUT' | 'AUTH_FAILURE';
  detail: string;
  idToken?: string | null;
}) {
  try {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (params.idToken && params.idToken !== 'mock-token') {
      headers['Authorization'] = `Bearer ${params.idToken}`;
    }
    await fetch(apiUrl('/api/security/client-event'), {
      method: 'POST',
      headers,
      body: JSON.stringify({
        eventType: params.eventType,
        detail: String(params.detail || '').slice(0, 240),
      }),
    });
  } catch {
    // Never interrupt forensic workflows if offline
  }
}

// ============================================================================
// Master Password Gate (SHA-256 Digest + Tab-Scoped sessionStorage Session)
// ============================================================================
export const MASTER_SESSION_STORAGE_KEY = 'sovereign_master_unlocked';
const MASTER_PASSWORD_SHA256 = '3033ac0cb6d25a9ee60e896ee1730f8bfafc90d8253a90840f2e71174fc02abc';

export async function computeSha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(hashBuffer));
}

export async function verifyMasterPasswordSha256(password: string): Promise<boolean> {
  if (!password || typeof password !== 'string') return false;
  const candidateHex = await computeSha256Hex(password);
  return constantTimeEqualHex(candidateHex, MASTER_PASSWORD_SHA256);
}

export function isMasterSessionUnlocked(): boolean {
  try {
    return typeof window !== 'undefined' && window.sessionStorage?.getItem(MASTER_SESSION_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

export function setMasterSessionUnlocked(unlocked: boolean): void {
  try {
    if (typeof window === 'undefined' || !window.sessionStorage) return;
    if (unlocked) {
      window.sessionStorage.setItem(MASTER_SESSION_STORAGE_KEY, '1');
    } else {
      window.sessionStorage.removeItem(MASTER_SESSION_STORAGE_KEY);
    }
  } catch {
    // Ignore storage restriction errors cleanly
  }
}


export function safeJsonParse<T>(value: string | null, fallback: T): T {
  if (!value || typeof value !== 'string') return fallback;
  const trimmed = value.trim();
  if (!trimmed || trimmed === 'undefined' || trimmed === 'null') return fallback;
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    return fallback;
  }
}

export async function safeParseRes(res: Response): Promise<any> {
  try {
    const text = await res.text();
    if (!text || !text.trim()) return {};
    return JSON.parse(text);
  } catch {
    return {};
  }
}


