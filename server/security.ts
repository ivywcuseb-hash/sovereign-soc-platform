import crypto from 'node:crypto';
import fs from 'node:fs';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import type { Request, Response, NextFunction } from 'express';
import type { Auth, DecodedIdToken } from 'firebase-admin/auth';
import type { Firestore } from 'firebase-admin/firestore';

export type SecuritySeverity = 'low' | 'medium' | 'high' | 'critical';
export type SecurityEventType =
  | 'AUTH_FAILURE'
  | 'ACCESS_DENIED'
  | 'RATE_LIMIT_EXCEEDED'
  | 'SSRF_BLOCKED'
  | 'CSRF_ORIGIN_BLOCKED'
  | 'SUSPICIOUS_INPUT'
  | 'CLIENT_PIN_LOCKOUT'
  | 'CLIENT_SECURITY_ALERT'
  | 'ADMIN_ACTION';

export interface SecurityEventRecord {
  id: string;
  timestamp: string;
  eventType: SecurityEventType;
  severity: SecuritySeverity;
  route: string;
  method: string;
  clientIpHash: string;
  userId: string | null;
  detail: string;
  blocked: boolean;
  prevHash: string;
  recordHash: string;
}

export interface AuthedRequest extends Request {
  user?: DecodedIdToken | null;
}

const SECRET_KEYS_RE =
  /(password|passwd|pin|pinhash|secret|token|apikey|api_key|authorization|cookie|privatekey|credential|idtoken)/i;

const SECRET_VALUE_PATTERNS: Array<[RegExp, string]> = [
  [/Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi, 'Bearer [REDACTED]'],
  [/AIza[0-9A-Za-z\-_]{20,}/g, '[REDACTED_GOOGLE_KEY]'],
  [/ya29\.[0-9A-Za-z\-_]+/g, '[REDACTED_OAUTH_TOKEN]'],
  [/sk-[A-Za-z0-9]{16,}/g, '[REDACTED_API_SECRET]'],
  [/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[REDACTED_JWT]'],
  [/github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]{20,}/g, '[REDACTED_GITHUB_TOKEN]'],
];

export function redactSecretsString(raw: string): string {
  let out = String(raw || '');
  for (const [pattern, replacement] of SECRET_VALUE_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

export function redactSecrets<T>(value: T, depth = 0): T {
  if (depth > 6 || value === null || value === undefined) return value;
  if (typeof value === 'string') {
    return redactSecretsString(value) as unknown as T;
  }
  if (Array.isArray(value)) {
    return value.slice(0, 100).map((item) => redactSecrets(item, depth + 1)) as unknown as T;
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_KEYS_RE.test(k)) {
        out[k] = '[REDACTED]';
      } else {
        out[k] = redactSecrets(v, depth + 1);
      }
    }
    return out as T;
  }
  return value;
}

export function getClientIp(req: Request): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.trim()) {
    return fwd.split(',')[0].trim();
  }
  return req.ip || req.socket?.remoteAddress || '0.0.0.0';
}

function hashIpForAudit(ip: string, salt: string): string {
  return crypto.createHmac('sha256', salt).update(ip).digest('hex').slice(0, 16);
}

// ============================================================================
// Tamper-Evident Security Defense & Monitoring System (Append-Only Hash Chain)
// ============================================================================
function resolveAuditHmacSecret(): {
  secret: string;
  source: 'secret-env' | 'secret-file' | 'ephemeral-runtime';
} {
  const envKey = String(process.env.SECURITY_AUDIT_HMAC_KEY || '').trim();
  if (envKey.length >= 32) {
    return { secret: envKey, source: 'secret-env' };
  }

  const keyFile = String(process.env.SECURITY_AUDIT_HMAC_KEY_FILE || '').trim();
  if (keyFile) {
    try {
      const fileSecret = fs.readFileSync(keyFile, 'utf8').trim();
      if (fileSecret.length >= 32) {
        return { secret: fileSecret, source: 'secret-file' };
      }
    } catch {
      // Fall through cleanly
    }
  }

  if (process.env.NODE_ENV === 'production') {
    console.warn(
      '[SECURITY_CONFIG_WARN] SECURITY_AUDIT_HMAC_KEY is not configured via Secret Manager/env (>=32 chars); using ephemeral runtime HMAC key.'
    );
  }
  return { secret: crypto.randomBytes(32).toString('hex'), source: 'ephemeral-runtime' };
}

export class SecurityMonitor {
  private readonly events: SecurityEventRecord[] = [];
  private readonly maxMemoryEvents = 500;
  private readonly hmacSecret: string;
  private readonly hmacKeySource: 'secret-env' | 'secret-file' | 'ephemeral-runtime';
  private readonly ipCounters = new Map<string, { score: number; windowStart: number }>();
  private lastHash = '0'.repeat(64);
  private adminDb: Firestore | null = null;
  private totalBlocked = 0;

  constructor() {
    const resolved = resolveAuditHmacSecret();
    this.hmacSecret = resolved.secret;
    this.hmacKeySource = resolved.source;
  }

  public attachFirestore(db: Firestore) {
    this.adminDb = db;
  }

  private computeRecordHash(
    prevHash: string,
    payload: Omit<SecurityEventRecord, 'recordHash'>
  ): string {
    const canonical = JSON.stringify({
      prevHash,
      id: payload.id,
      timestamp: payload.timestamp,
      eventType: payload.eventType,
      severity: payload.severity,
      route: payload.route,
      method: payload.method,
      clientIpHash: payload.clientIpHash,
      userId: payload.userId,
      detail: payload.detail,
      blocked: payload.blocked,
    });
    return crypto.createHmac('sha256', this.hmacSecret).update(canonical).digest('hex');
  }

  public record(params: {
    eventType: SecurityEventType;
    severity: SecuritySeverity;
    route: string;
    method?: string;
    clientIp?: string;
    userId?: string | null;
    detail: string;
    blocked?: boolean;
  }): SecurityEventRecord {
    const id = `sec-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const timestamp = new Date().toISOString();
    const clientIpHash = hashIpForAudit(params.clientIp || 'internal', this.hmacSecret);
    const cleanDetail = redactSecretsString(params.detail).replace(/[\u0000-\u001F\u007F]/g, ' ').slice(0, 400);
    const blocked = params.blocked ?? true;

    const base: Omit<SecurityEventRecord, 'recordHash'> = {
      id,
      timestamp,
      eventType: params.eventType,
      severity: params.severity,
      route: String(params.route || '/').slice(0, 128),
      method: String(params.method || 'GET').slice(0, 16),
      clientIpHash,
      userId: params.userId ? String(params.userId).slice(0, 128) : null,
      detail: cleanDetail,
      blocked,
      prevHash: this.lastHash,
    };

    const recordHash = this.computeRecordHash(this.lastHash, base);
    const entry: SecurityEventRecord = Object.freeze({ ...base, recordHash });

    this.lastHash = recordHash;
    if (blocked) this.totalBlocked++;

    this.events.unshift(entry);
    if (this.events.length > this.maxMemoryEvents) {
      this.events.length = this.maxMemoryEvents;
    }

    // Track IP threat accumulation over 15-minute window
    const now = Date.now();
    const weight =
      params.severity === 'critical'
        ? 40
        : params.severity === 'high'
        ? 20
        : params.severity === 'medium'
        ? 10
        : 2;
    const prevCounter = this.ipCounters.get(clientIpHash);
    if (!prevCounter || now - prevCounter.windowStart > 15 * 60 * 1000) {
      this.ipCounters.set(clientIpHash, { score: weight, windowStart: now });
    } else {
      prevCounter.score += weight;
    }

    if (params.severity === 'high' || params.severity === 'critical') {
      console.warn(
        `[SECURITY_ALERT][${params.severity.toUpperCase()}][${params.eventType}] ${entry.method} ${entry.route} :: ${cleanDetail}`
      );
    }

    // Persist medium+ security events to append-only Firestore collection (best-effort)
    if (this.adminDb && (params.severity === 'medium' || params.severity === 'high' || params.severity === 'critical')) {
      void this.adminDb
        .collection('security_events')
        .doc(entry.id)
        .set({ ...entry })
        .catch(() => {
          // Ignore when offline or without cloud ADC credentials; memory chain stays authoritative
        });
    }

    return entry;
  }

  public verifyChainIntegrity(): { valid: boolean; checkedCount: number } {
    if (this.events.length === 0) return { valid: true, checkedCount: 0 };
    // Events are stored newest-first; validate oldest -> newest links
    const chronological = [...this.events].reverse();
    for (let i = 0; i < chronological.length; i++) {
      const ev = chronological[i];
      if (i > 0 && ev.prevHash !== chronological[i - 1].recordHash) {
        return { valid: false, checkedCount: i + 1 };
      }
      const { recordHash, ...rest } = ev;
      const expected = this.computeRecordHash(ev.prevHash, rest);
      if (expected !== recordHash) {
        return { valid: false, checkedCount: i + 1 };
      }
    }
    return { valid: true, checkedCount: chronological.length };
  }

  public getStatusSummary() {
    const now = Date.now();
    const recent15m = this.events.filter(
      (e) => now - new Date(e.timestamp).getTime() <= 15 * 60 * 1000
    );
    const criticalRecent = recent15m.filter((e) => e.severity === 'critical').length;
    const highRecent = recent15m.filter((e) => e.severity === 'high').length;
    const mediumRecent = recent15m.filter((e) => e.severity === 'medium').length;

    let alertLevel: 'NORMAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL' = 'NORMAL';
    if (criticalRecent >= 1 || highRecent >= 5) alertLevel = 'CRITICAL';
    else if (highRecent >= 2 || recent15m.length >= 15) alertLevel = 'HIGH';
    else if (mediumRecent >= 3 || recent15m.length >= 5) alertLevel = 'ELEVATED';

    return {
      alertLevel,
      totalEventsBuffered: this.events.length,
      totalBlocked: this.totalBlocked,
      recent15mCount: recent15m.length,
      recentBySeverity: {
        critical: criticalRecent,
        high: highRecent,
        medium: mediumRecent,
        low: recent15m.filter((e) => e.severity === 'low').length,
      },
      chainIntegrity: this.verifyChainIntegrity(),
      hmacKeySource: this.hmacKeySource,
      environment: process.env.NODE_ENV || 'development',
      activeControls: [
        'CSP & Security Headers',
        'Sliding-Window Rate Limiting',
        'SSRF DNS + Redirect Guard',
        'CSRF & Allowlisted CORS Guard',
        'Server-Side Token & Admin RBAC',
        'Secret Redaction Filter',
      ],
      checkedAt: new Date().toISOString(),
    };
  }

  public getEventsForUser(uid: string, isAdmin: boolean, limitCount = 50): SecurityEventRecord[] {
    const filtered = isAdmin
      ? this.events
      : this.events.filter((e) => e.userId === uid);
    return filtered.slice(0, Math.min(100, Math.max(1, limitCount)));
  }
}

export const securityMonitor = new SecurityMonitor();

// ============================================================================
// SSRF & Private/Metadata Network Protection (IPv4 + IPv6 + DNS + Redirects)
// ============================================================================
function ipv4ToInt(ip: string): number {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return -1;
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr4(ipInt: number, baseStr: string, maskBits: number): boolean {
  const baseInt = ipv4ToInt(baseStr);
  if (ipInt < 0 || baseInt < 0) return true;
  const mask = maskBits === 0 ? 0 : (0xffffffff << (32 - maskBits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

export function isPrivateOrReservedIp(rawIp: string): boolean {
  const ip = rawIp.trim().toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  if (!ip) return true;

  if (net.isIPv4(ip)) {
    const n = ipv4ToInt(ip);
    if (n < 0) return true;
    return (
      inCidr4(n, '0.0.0.0', 8) || // Current network / unspecified
      inCidr4(n, '10.0.0.0', 8) || // RFC1918
      inCidr4(n, '100.64.0.0', 10) || // CGNAT / Alibaba metadata
      inCidr4(n, '127.0.0.0', 8) || // Loopback
      inCidr4(n, '169.254.0.0', 16) || // Link-local & AWS/GCP/Azure metadata
      inCidr4(n, '172.16.0.0', 12) || // RFC1918
      inCidr4(n, '192.0.0.0', 24) || // IETF protocol assignments
      inCidr4(n, '192.0.2.0', 24) || // TEST-NET-1
      inCidr4(n, '192.168.0.0', 16) || // RFC1918
      inCidr4(n, '198.18.0.0', 15) || // Benchmarking
      inCidr4(n, '198.51.100.0', 24) || // TEST-NET-2
      inCidr4(n, '203.0.113.0', 24) || // TEST-NET-3
      inCidr4(n, '224.0.0.0', 4) || // Multicast
      inCidr4(n, '240.0.0.0', 4) // Reserved / Broadcast
    );
  }

  if (net.isIPv6(ip)) {
    // Handle IPv4-mapped IPv6 addresses e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1
    if (ip.startsWith('::ffff:')) {
      const tail = ip.slice(7);
      if (net.isIPv4(tail)) return isPrivateOrReservedIp(tail);
      const hexMatch = tail.match(/^([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
      if (hexMatch) {
        const hi = parseInt(hexMatch[1], 16);
        const lo = parseInt(hexMatch[2], 16);
        const reconstructed = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isPrivateOrReservedIp(reconstructed);
      }
      return true;
    }

    if (ip === '::' || ip === '::1') return true;
    const firstWord = parseInt(ip.split(':')[0] || '0', 16);
    if ((firstWord & 0xfe00) === 0xfc00) return true; // fc00::/7 Unique local
    if ((firstWord & 0xffc0) === 0xfe80) return true; // fe80::/10 Link-local
    if ((firstWord & 0xff00) === 0xff00) return true; // ff00::/8 Multicast
    if (ip.startsWith('fd00:ec2:')) return true; // AWS IPv6 metadata
    return false;
  }

  return true;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'ip6-localhost',
  'ip6-loopback',
  'metadata.google.internal',
  'metadata',
  'instance-data',
]);

export async function assertHostnameResolvesPublic(hostname: string): Promise<string[]> {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (
    !host ||
    BLOCKED_HOSTNAMES.has(host) ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.localhost') ||
    host.endsWith('.arpa')
  ) {
    throw new Error('SSRF_BLOCKED: النطاق الداخلي أو المحلي محظور أمنياً.');
  }

  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) {
      throw new Error('SSRF_BLOCKED: عنوان IP الخاص أو المحلي محظور أمنياً.');
    }
    return [host];
  }

  const records = await dns.lookup(host, { all: true });
  if (!records || records.length === 0) {
    throw new Error('DNS_RESOLUTION_EMPTY: تعذر ترجمة اسم النطاق إلى عنوان عام.');
  }
  const publicIps: string[] = [];
  for (const rec of records) {
    if (isPrivateOrReservedIp(rec.address)) {
      throw new Error('SSRF_BLOCKED: النطاق يشير عبر DNS إلى شبكة داخلية أو محجوزة.');
    }
    publicIps.push(rec.address);
  }
  return publicIps;
}

export async function assertSafeExternalUrl(rawUrl: string): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error('INVALID_URL: رابط غير صالح.');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('SSRF_BLOCKED: يُسمح فقط ببروتوكول HTTP/HTTPS.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('SSRF_BLOCKED: الروابط التي تحتوي على بيانات اعتماد مدمجة مرفوضة.');
  }
  await assertHostnameResolvesPublic(parsed.hostname);
  return parsed;
}

export async function safeExternalFetch(
  rawUrl: string,
  options?: {
    method?: 'GET' | 'POST';
    headers?: Record<string, string>;
    body?: string;
    timeoutMs?: number;
    maxBytes?: number;
    maxRedirects?: number;
    clientIp?: string;
    route?: string;
  }
): Promise<{ status: number; ok: boolean; text: string; finalUrl: string }> {
  const timeoutMs = options?.timeoutMs ?? 8000;
  const maxBytes = options?.maxBytes ?? 4 * 1024 * 1024;
  const maxRedirects = options?.maxRedirects ?? 2;

  let currentUrl = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    let parsed: URL;
    try {
      parsed = await assertSafeExternalUrl(currentUrl);
    } catch (err: any) {
      securityMonitor.record({
        eventType: 'SSRF_BLOCKED',
        severity: 'high',
        route: options?.route || 'outbound-fetch',
        method: options?.method || 'GET',
        clientIp: options?.clientIp,
        detail: `Blocked outbound request to "${currentUrl}": ${err?.message || 'SSRF violation'}`,
      });
      throw err;
    }

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(parsed.toString(), {
        method: options?.method || 'GET',
        headers: options?.headers,
        body: options?.body,
        redirect: 'manual',
        signal: ctrl.signal,
      });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get('location');
        if (!location) {
          throw new Error(`HTTP ${res.status} redirect missing Location`);
        }
        if (hop === maxRedirects) {
          throw new Error('TOO_MANY_REDIRECTS');
        }
        currentUrl = new URL(location, parsed).toString();
        continue;
      }

      const contentLen = Number(res.headers.get('content-length') || '0');
      if (contentLen > maxBytes) {
        throw new Error('RESPONSE_TOO_LARGE');
      }

      const reader = res.body?.getReader();
      if (!reader) {
        const text = await res.text();
        if (Buffer.byteLength(text, 'utf8') > maxBytes) {
          throw new Error('RESPONSE_TOO_LARGE');
        }
        return { status: res.status, ok: res.ok, text, finalUrl: parsed.toString() };
      }

      const chunks: Uint8Array[] = [];
      let received = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          received += value.byteLength;
          if (received > maxBytes) {
            await reader.cancel().catch(() => undefined);
            throw new Error('RESPONSE_TOO_LARGE');
          }
          chunks.push(value);
        }
      }
      const fullBuf = Buffer.concat(chunks);
      return {
        status: res.status,
        ok: res.ok,
        text: fullBuf.toString('utf8'),
        finalUrl: parsed.toString(),
      };
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error('TOO_MANY_REDIRECTS');
}

// ============================================================================
// HTTP Security Headers, CSP & CSRF/Origin Middleware
// ============================================================================
export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(self), geolocation=(), payment=(), usb=()'
  );
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  if (req.path.startsWith('/api/')) {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    res.setHeader('Cache-Control', 'no-store');
  } else {
    // Same-origin-allow-popups preserves Google OAuth signInWithPopup while protecting main window
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin-allow-popups');
    res.setHeader(
      'Content-Security-Policy',
      [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://apis.google.com https://www.gstatic.com",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob: https:",
        "font-src 'self' data: https:",
        "connect-src 'self' ws: wss: https://*.googleapis.com https://*.firebaseio.com https://*.firebaseapp.com https://firestore.googleapis.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://firebasestorage.googleapis.com https://dns.google https://rdap.org https://ipwho.is",
        "frame-src 'self' https://*.firebaseapp.com https://accounts.google.com",
        "worker-src 'self' blob:",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'self' https://aistudio.google.com https://*.scf.usercontent.goog https://*.googleusercontent.com",
      ].join('; ')
    );
  }
  next();
}

function getExtraCorsOrigins(): Set<string> {
  const raw = String(process.env.ALLOWED_CORS_ORIGINS || '').trim();
  if (!raw) return new Set();
  return new Set(
    raw
      .split(',')
      .map((s) => s.trim().toLowerCase().replace(/\/+$/, ''))
      .filter(Boolean)
  );
}

export function isTrustedOrigin(originHeader: string, reqHost?: string): boolean {
  try {
    const parsed = new URL(originHeader);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;
    const originNormalized = `${parsed.protocol}//${parsed.host}`.toLowerCase();
    const host = parsed.host.toLowerCase();
    const hostname = parsed.hostname.toLowerCase();
    if (reqHost && host === reqHost.toLowerCase()) return true;
    if (getExtraCorsOrigins().has(originNormalized)) return true;
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]') return true;
    if (
      hostname.endsWith('.github.io') ||
      hostname.endsWith('.vercel.app') ||
      hostname.endsWith('.run.app') ||
      hostname.endsWith('.scf.usercontent.goog') ||
      hostname.endsWith('.googleusercontent.com')
    ) {
      return parsed.protocol === 'https:';
    }
    return false;
  } catch {
    return false;
  }
}

export function corsMiddleware(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.path.startsWith('/api/')) return next();

  const originHeader = typeof req.headers.origin === 'string' ? req.headers.origin : '';
  const reqHost = typeof req.headers.host === 'string' ? req.headers.host : undefined;

  if (originHeader) {
    if (isTrustedOrigin(originHeader, reqHost)) {
      res.setHeader('Access-Control-Allow-Origin', originHeader);
      res.setHeader('Vary', 'Origin');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      res.setHeader('Access-Control-Max-Age', '600');
    } else if (req.method.toUpperCase() === 'OPTIONS') {
      securityMonitor.record({
        eventType: 'CSRF_ORIGIN_BLOCKED',
        severity: 'high',
        route: req.path,
        method: 'OPTIONS',
        clientIp: getClientIp(req),
        detail: `Blocked untrusted CORS preflight Origin: ${originHeader}`,
      });
      return res.status(403).json({ error: 'CORS preflight origin rejected.' });
    }
  }

  if (req.method.toUpperCase() === 'OPTIONS') {
    return res.status(204).end();
  }
  next();
}

export function originAndContentTypeGuard(req: AuthedRequest, res: Response, next: NextFunction) {
  if (!req.path.startsWith('/api/')) return next();

  const method = req.method.toUpperCase();
  if (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE') {
    const ct = String(req.headers['content-type'] || '').toLowerCase();
    if (!ct.includes('application/json')) {
      securityMonitor.record({
        eventType: 'SUSPICIOUS_INPUT',
        severity: 'medium',
        route: req.path,
        method,
        clientIp: getClientIp(req),
        detail: `Rejected non-JSON Content-Type: "${ct || 'none'}"`,
      });
      return res.status(415).json({ error: 'Content-Type must be application/json.' });
    }

    const secFetchSite = String(req.headers['sec-fetch-site'] || '').toLowerCase();
    const originHeader = typeof req.headers.origin === 'string' ? req.headers.origin : '';
    const refererHeader = typeof req.headers.referer === 'string' ? req.headers.referer : '';
    const reqHost = typeof req.headers.host === 'string' ? req.headers.host : undefined;

    if (originHeader && !isTrustedOrigin(originHeader, reqHost)) {
      securityMonitor.record({
        eventType: 'CSRF_ORIGIN_BLOCKED',
        severity: 'high',
        route: req.path,
        method,
        clientIp: getClientIp(req),
        detail: `Blocked untrusted Origin header: ${originHeader}`,
      });
      return res.status(403).json({ error: 'Cross-origin request rejected by CSRF policy.' });
    }

    if (!originHeader && secFetchSite === 'cross-site') {
      const refOk = refererHeader ? isTrustedOrigin(refererHeader, reqHost) : false;
      if (!refOk) {
        securityMonitor.record({
          eventType: 'CSRF_ORIGIN_BLOCKED',
          severity: 'high',
          route: req.path,
          method,
          clientIp: getClientIp(req),
          detail: 'Blocked cross-site Sec-Fetch-Site request without trusted origin.',
        });
        return res.status(403).json({ error: 'Cross-site request rejected by CSRF policy.' });
      }
    }
  }
  next();
}

// ============================================================================
// Sliding-Window Rate Limiter
// ============================================================================
interface RateBucket {
  timestamps: number[];
}

export function createRateLimiter(options: {
  name: string;
  windowMs: number;
  maxRequests: number;
}) {
  const buckets = new Map<string, RateBucket>();

  // Periodic cleanup to avoid unbounded memory growth
  const cleanupInterval = setInterval(() => {
    const cutoff = Date.now() - options.windowMs;
    for (const [key, bucket] of buckets.entries()) {
      bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);
      if (bucket.timestamps.length === 0) buckets.delete(key);
    }
  }, Math.max(30_000, options.windowMs));
  cleanupInterval.unref?.();

  return (req: AuthedRequest, res: Response, next: NextFunction) => {
    const now = Date.now();
    const cutoff = now - options.windowMs;
    const ip = getClientIp(req);
    const uid = req.user?.uid ? `uid:${req.user.uid}` : `ip:${ip}`;
    const key = `${options.name}:${uid}`;

    const bucket = buckets.get(key) || { timestamps: [] };
    bucket.timestamps = bucket.timestamps.filter((t) => t > cutoff);

    if (bucket.timestamps.length >= options.maxRequests) {
      const oldest = bucket.timestamps[0] || now;
      const retryAfterSec = Math.max(1, Math.ceil((oldest + options.windowMs - now) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
      res.setHeader('X-RateLimit-Remaining', '0');

      securityMonitor.record({
        eventType: 'RATE_LIMIT_EXCEEDED',
        severity: 'high',
        route: req.path,
        method: req.method,
        clientIp: ip,
        userId: req.user?.uid || null,
        detail: `Rate limit bucket "${options.name}" exceeded (${bucket.timestamps.length}/${options.maxRequests} in ${options.windowMs}ms)`,
      });

      return res.status(429).json({
        error: 'تم تجاوز الحد الأقصى للطلبات المسموح به مؤقتاً (Rate Limit). يرجى الانتظار بضع لحظات.',
        retryAfterSec,
      });
    }

    bucket.timestamps.push(now);
    buckets.set(key, bucket);
    const oldestActive = bucket.timestamps[0] || now;
    const resetEpochSec = Math.ceil((oldestActive + options.windowMs) / 1000);
    res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
    res.setHeader(
      'X-RateLimit-Remaining',
      String(Math.max(0, options.maxRequests - bucket.timestamps.length))
    );
    res.setHeader('X-RateLimit-Reset', String(resetEpochSec));
    next();
  };
}

// ============================================================================
// Server-Side Auth, Token Revocation Verification & Admin RBAC
// ============================================================================
export function createAuthMiddleware(adminAuth: Auth, adminDb: Firestore) {
  const verifyTokenStrict = async (token: string): Promise<DecodedIdToken> => {
    // Reject obvious placeholder or malformed tokens immediately
    if (!token || token === 'mock-token' || token.split('.').length !== 3) {
      throw new Error('MALFORMED_TOKEN');
    }

    // 1. Always enforce cryptographic RSA signature, issuer, project audience, and expiry verification
    const decoded = await adminAuth.verifyIdToken(token, false);

    // 2. Best-effort revocation check when Admin ADC / service-account credentials are available
    try {
      return await adminAuth.verifyIdToken(token, true);
    } catch (err: any) {
      const codeAndMsg = `${String(err?.code || '')} ${String(err?.message || '')}`;
      if (
        /id-token-revoked|id-token-expired|user-disabled|user-not-found|argument-error|invalid-id-token/i.test(
          codeAndMsg
        )
      ) {
        throw err;
      }
      if (
        /invalid-credential|default credentials|insufficient-permission|ECONNREFUSED|ENOTFOUND|ETIMEDOUT|ENETUNREACH|EAI_AGAIN|fetch failed|metadata|internal-error/i.test(
          codeAndMsg
        )
      ) {
        return decoded;
      }
      throw err;
    }
  };

  const requireAuth = async (req: AuthedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    const ip = getClientIp(req);
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      securityMonitor.record({
        eventType: 'AUTH_FAILURE',
        severity: 'medium',
        route: req.path,
        method: req.method,
        clientIp: ip,
        detail: 'Missing or invalid Authorization Bearer header',
      });
      return res.status(401).json({ error: 'Unauthorized: Authentication token required.' });
    }

    const token = authHeader.slice('Bearer '.length).trim();
    try {
      const decodedToken = await verifyTokenStrict(token);
      req.user = decodedToken;
      next();
    } catch (error: any) {
      securityMonitor.record({
        eventType: 'AUTH_FAILURE',
        severity: 'high',
        route: req.path,
        method: req.method,
        clientIp: ip,
        detail: `Invalid/forged/revoked ID token rejected (${String(error?.code || error?.message || 'verify_failed').slice(0, 64)})`,
      });
      return res.status(401).json({ error: 'Unauthorized: Invalid or expired session token.' });
    }
  };

  // Used for dual-mode forensic endpoints (supports Local Isolated Mode while strictly verifying tokens if sent)
  const optionalVerifiedAuth = async (req: AuthedRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      req.user = null;
      return next();
    }
    if (!authHeader.startsWith('Bearer ')) {
      securityMonitor.record({
        eventType: 'AUTH_FAILURE',
        severity: 'medium',
        route: req.path,
        method: req.method,
        clientIp: getClientIp(req),
        detail: 'Malformed Authorization header scheme on forensic endpoint',
      });
      return res.status(401).json({ error: 'Unauthorized: Malformed Authorization header.' });
    }
    const token = authHeader.slice('Bearer '.length).trim();
    if (!token || token === 'mock-token') {
      req.user = null;
      return next();
    }
    try {
      req.user = await verifyTokenStrict(token);
      next();
    } catch (error: any) {
      securityMonitor.record({
        eventType: 'AUTH_FAILURE',
        severity: 'high',
        route: req.path,
        method: req.method,
        clientIp: getClientIp(req),
        detail: `Rejected invalid Bearer token on endpoint (${String(error?.code || 'invalid_token').slice(0, 48)})`,
      });
      return res.status(401).json({
        error: 'Unauthorized: Invalid or expired session token.',
        code: 'INVALID_OR_EXPIRED_TOKEN',
      });
    }
  };

  const checkIsAdminServerSide = async (uid: string): Promise<boolean> => {
    if (!uid) return false;
    try {
      const adminDoc = await adminDb.collection('admins').doc(uid).get();
      return adminDoc.exists && adminDoc.data()?.active !== false;
    } catch {
      return false;
    }
  };

  const requireAdmin = async (req: AuthedRequest, res: Response, next: NextFunction) => {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const isAdmin = await checkIsAdminServerSide(req.user.uid);
    if (!isAdmin) {
      securityMonitor.record({
        eventType: 'ACCESS_DENIED',
        severity: 'high',
        route: req.path,
        method: req.method,
        clientIp: getClientIp(req),
        userId: req.user.uid,
        detail: 'Privilege escalation / unauthorized admin endpoint access denied server-side',
      });
      return res.status(403).json({ error: 'Forbidden: Server-side Admin authorization required.' });
    }
    next();
  };

  return {
    requireAuth,
    optionalVerifiedAuth,
    requireAdmin,
    checkIsAdminServerSide,
  };
}

// ============================================================================
// Input Validation & Prompt Injection Sanitizers
// ============================================================================
export function sanitizeControlChars(input: unknown, maxLength = 512): string {
  return String(input ?? '')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u202A-\u202E\u2066-\u2069]/g, '')
    .trim()
    .slice(0, maxLength);
}

export function wrapUntrustedBlock(label: string, content: unknown, maxLength = 4000): string {
  const safe = redactSecretsString(String(content ?? ''))
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .slice(0, maxLength);
  return `<<<BEGIN_UNTRUSTED_${label}>>>\n${safe}\n<<<END_UNTRUSTED_${label}>>>`;
}

export function sanitizePublicUrl(raw: unknown): string {
  if (typeof raw !== 'string') return '';
  try {
    const u = new URL(raw.trim());
    if (u.protocol === 'https:' || u.protocol === 'http:') {
      return u.toString();
    }
    return '';
  } catch {
    return '';
  }
}

export function sanitizeCoreErrorMessage(err: any, fallbackMessage: string): string {
  const raw = redactSecretsString(String(err?.message || err || ''));
  if (raw.includes('429') || raw.toLowerCase().includes('quota') || raw.toLowerCase().includes('rate limit')) {
    return 'بوابة التحليل السيادي قيد معالجة مكثفة حالياً (Sovereign Core Throttle / 429). يُرجى المحاولة بعد لحظات.';
  }
  if (
    raw.toLowerCase().includes('api_key') ||
    raw.toLowerCase().includes('apikey') ||
    raw.toLowerCase().includes('key not valid')
  ) {
    return 'بوابة التحليل السيادي Core Gateway غير مهيأة أو تحتاج إلى ترقية التراخيص الأمنية.';
  }
  if (
    raw.toLowerCase().includes('gemini') ||
    raw.toLowerCase().includes('ai studio') ||
    raw.toLowerCase().includes('aistudio') ||
    raw.toLowerCase().includes('enoent') ||
    raw.toLowerCase().includes('econnrefused') ||
    raw.includes('/app/') ||
    raw.includes('stack')
  ) {
    return fallbackMessage;
  }
  return fallbackMessage;
}
