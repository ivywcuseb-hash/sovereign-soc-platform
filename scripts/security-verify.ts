import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import JSZip from 'jszip';

import {
  isPrivateOrReservedIp,
  assertSafeExternalUrl,
  redactSecrets,
  redactSecretsString,
  SecurityMonitor,
} from '../server/security.ts';
import {
  sanitizeSafeHref,
  isRegexSafe,
  hashPinPbkdf2,
  verifyPinAgainstStoredHash,
} from '../src/utils/clientSecurity.ts';
import {
  generateOfficialHtmlReport,
  generateOfficialCsvManifest,
  type ForensicDossierInput,
} from '../src/utils/reportGenerator.ts';

interface TestResult {
  category: string;
  name: string;
  passed: boolean;
  detail: string;
}

const results: TestResult[] = [];

async function runTest(category: string, name: string, fn: () => Promise<void> | void) {
  try {
    await fn();
    results.push({ category, name, passed: true, detail: 'PASS' });
    console.log(`[PASS] [${category}] ${name}`);
  } catch (err: any) {
    const detail = err?.message || String(err);
    results.push({ category, name, passed: false, detail });
    console.error(`[FAIL] [${category}] ${name}: ${detail}`);
  }
}

async function main() {
  const baseUrl = (process.env.PENTEST_BASE_URL || 'http://127.0.0.1:3000').replace(/\/+$/, '');

  // =========================================================================
  // 1. Unit & Cryptographic Primitives Verification
  // =========================================================================
  await runTest('SSRF-Unit', 'Block RFC1918, Loopback, AWS/GCP Metadata & IPv4-mapped IPv6', async () => {
    const blockedIps = [
      '127.0.0.1',
      '10.0.0.1',
      '172.16.0.5',
      '192.168.1.1',
      '169.254.169.254',
      '100.64.0.1',
      '0.0.0.0',
      '::1',
      'fe80::1',
      'fc00::1',
      '::ffff:127.0.0.1',
      '::ffff:7f00:1',
    ];
    for (const ip of blockedIps) {
      assert.equal(isPrivateOrReservedIp(ip), true, `Expected ${ip} to be blocked`);
    }
    assert.equal(isPrivateOrReservedIp('8.8.8.8'), false);
    assert.equal(isPrivateOrReservedIp('1.1.1.1'), false);

    await assert.rejects(() => assertSafeExternalUrl('http://169.254.169.254/latest/meta-data/'));
    await assert.rejects(() => assertSafeExternalUrl('http://metadata.google.internal/'));
    await assert.rejects(() => assertSafeExternalUrl('file:///etc/passwd'));
    await assert.rejects(() => assertSafeExternalUrl('http://user:pass@example.com/'));
  });

  await runTest('Secret-Redaction', 'Strip API keys, JWTs, Bearer tokens & PIN hashes from logs', () => {
    const sample = {
      password: 'my-secret-password',
      pinHash: 'abc123',
      authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.payload123.sig456',
      note: 'Leak AIzaSyD1234567890abcdefghijk1234567 and github_pat_1234567890abcdefghij',
    };
    const scrubbed = redactSecrets(sample);
    assert.equal(scrubbed.password, '[REDACTED]');
    assert.equal(scrubbed.pinHash, '[REDACTED]');
    assert.equal(scrubbed.authorization, '[REDACTED]');
    assert.equal(scrubbed.note.includes('AIzaSyD'), false);
    assert.equal(scrubbed.note.includes('github_pat_'), false);
    assert.equal(redactSecretsString('Bearer secretToken12345').includes('secretToken12345'), false);
  });

  await runTest('Tamper-Evident-Log', 'Verify HMAC hash chain and detect log tampering', () => {
    const mon = new SecurityMonitor();
    mon.record({ eventType: 'AUTH_FAILURE', severity: 'high', route: '/api/dashboard-stats', detail: 'Test 1' });
    mon.record({ eventType: 'SSRF_BLOCKED', severity: 'critical', route: '/api/dns-ip-lookup', detail: 'Test 2' });
    const ok = mon.verifyChainIntegrity();
    assert.equal(ok.valid, true);
    assert.equal(ok.checkedCount, 2);

    const eventsRef = (mon as any).events as Array<any>;
    const original = { ...eventsRef[0] };
    eventsRef[0] = { ...original, detail: 'TAMPERED_ENTRY' };
    const tampered = mon.verifyChainIntegrity();
    assert.equal(tampered.valid, false);
  });

  await runTest('Client-Security', 'Enforce XSS URL filter, ReDoS guard & PBKDF2 PIN verification', async () => {
    assert.equal(sanitizeSafeHref('javascript:alert(1)'), '#');
    assert.equal(sanitizeSafeHref('java\tscript:alert(1)'), '#');
    assert.equal(sanitizeSafeHref('data:text/html,<script>alert(1)</script>', true), '#');
    assert.equal(sanitizeSafeHref('https://example.com/report'), 'https://example.com/report');

    assert.equal(isRegexSafe('(a+)+$').safe, false);
    assert.equal(isRegexSafe('([a-z]+)*').safe, false);
    assert.equal(isRegexSafe('\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b').safe, true);

    const pbkdf2Hash = await hashPinPbkdf2('2580');
    assert.ok(pbkdf2Hash.startsWith('pbkdf2$120000$'));
    const okRes = await verifyPinAgainstStoredHash('2580', pbkdf2Hash);
    assert.equal(okRes.valid, true);
    assert.equal(okRes.needsMigrationToPbkdf2, false);
    const badRes = await verifyPinAgainstStoredHash('9999', pbkdf2Hash);
    assert.equal(badRes.valid, false);
  });

  await runTest('XSS-CSV-Reports', 'Escape <script> XSS, add script-none CSP, and neutralize CSV formulas', () => {
    const dossier: ForensicDossierInput = {
      caseNumber: 'CASE-001',
      title: '<script>alert(1)</script>',
      classification: 'TOP_SECRET',
      examinerName: '<img src=x onerror=alert(2)>',
      examinerEmail: 'test@example.com',
      department: 'Cyber SOC',
      investigationTitle: 'Test',
      summary: '<b>Summary</b>',
      generatedAt: new Date().toISOString(),
      evidenceItems: [
        {
          id: 'ev1',
          fileName: '=cmd|"/C calc"!A0',
          fileSize: 1024,
          mimeType: 'text/plain',
          sha256: 'a'.repeat(64),
          investigationId: 'inv1',
          createdAt: new Date().toISOString(),
        },
      ],
      custodyEntries: [],
      custodyChainVerified: true,
      iocs: [],
      includeEvidenceHashes: true,
      includeExifEla: false,
      includeCustodyChain: false,
      includeIoCs: false,
    };

    const html = generateOfficialHtmlReport(dossier, 'b'.repeat(64));
    assert.ok(html.includes("script-src 'none'"));
    assert.equal(html.includes('<script>alert(1)</script>'), false);
    assert.ok(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'));
    assert.equal(html.includes('<img src=x onerror=alert(2)>'), false);

    const csv = generateOfficialCsvManifest(dossier, 'b'.repeat(64));
    assert.ok(csv.includes('"\'=cmd'));
  });

  // =========================================================================
  // 2. Firebase Firestore, Storage Rules & Dependency Audit
  // =========================================================================
  await runTest('Firebase-Rules', 'Audit firestore.rules, storage.rules & firebase.json invariants', () => {
    const fsRules = fs.readFileSync(path.resolve('firestore.rules'), 'utf8');
    const stRules = fs.readFileSync(path.resolve('storage.rules'), 'utf8');
    const fbJson = JSON.parse(fs.readFileSync(path.resolve('firebase.json'), 'utf8'));

    assert.equal(fbJson.firestore?.rules, 'firestore.rules');
    assert.equal(fbJson.storage?.rules, 'storage.rules');
    assert.ok(fsRules.includes('allow read, write: if false;'));
    assert.ok(fsRules.includes('match /admins/{adminId}'));
    assert.ok(fsRules.includes('match /security_events/{eventId}'));
    assert.ok(fsRules.includes("data.role == 'analyst'"));
    assert.equal(fsRules.includes('allow read: if true'), false);

    const listLines = fsRules.split('\n').filter((l) => l.includes('allow list'));
    for (const line of listLines) {
      assert.equal(line.includes('get('), false, `Found get() inside allow list: ${line}`);
    }

    assert.equal(stRules.includes('allow read: if true'), false);
    assert.ok(stRules.includes('isValidUid(userId)'));
    assert.ok(stRules.includes('request.resource.size <= 5 * 1024 * 1024'));
    assert.ok(stRules.includes('request.resource.size <= 25 * 1024 * 1024'));
  });

  await runTest('Dependency-Patch', 'Verify @grpc/grpc-js patched >= 1.14.0 in node_modules', () => {
    const grpcPkg = JSON.parse(
      fs.readFileSync(path.resolve('node_modules/@grpc/grpc-js/package.json'), 'utf8')
    );
    const [major, minor] = String(grpcPkg.version || '0.0.0').split('.').map(Number);
    assert.ok(major > 1 || (major === 1 && minor >= 14), `Expected @grpc/grpc-js >= 1.14.0, got ${grpcPkg.version}`);
  });

  // =========================================================================
  // 3. Live Backend API & Security Penetration Tests
  // =========================================================================
  await runTest('Health-Headers', 'Verify /api/health, /api/version, Security Headers & removed X-Powered-By', async () => {
    const healthRes = await fetch(`${baseUrl}/api/health`);
    assert.equal(healthRes.status, 200);
    const healthJson = await healthRes.json();
    assert.equal(healthJson.ok, true);
    assert.equal(healthJson.chainValid, true);
    assert.equal(JSON.stringify(healthJson).includes('AIza'), false);

    const verRes = await fetch(`${baseUrl}/api/version?clientVersion=2.5.2`);
    assert.equal(verRes.status, 200);
    assert.equal(verRes.headers.get('x-powered-by'), null);
    assert.equal(verRes.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(verRes.headers.get('x-frame-options'), 'DENY');
    assert.ok((verRes.headers.get('content-security-policy') || '').includes("frame-ancestors 'none'"));
  });

  await runTest('CORS-GitHubPages', 'Verify allowlisted CORS preflight for GitHub Pages and block untrusted origins', async () => {
    const okPreflight = await fetch(`${baseUrl}/api/security/status`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://ivywcuseb-hash.github.io',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.equal(okPreflight.status, 204);
    assert.equal(
      okPreflight.headers.get('access-control-allow-origin'),
      'https://ivywcuseb-hash.github.io'
    );

    const badPreflight = await fetch(`${baseUrl}/api/security/status`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'https://evil-phishing-domain.example',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.equal(badPreflight.status, 403);
  });

  await runTest('Auth-RBAC-API', 'Reject unauthenticated, mock-token, and forged JWT requests with 401', async () => {
    const r1 = await fetch(`${baseUrl}/api/dashboard-stats`);
    assert.equal(r1.status, 401);

    const r2 = await fetch(`${baseUrl}/api/dashboard-stats`, {
      headers: { Authorization: 'Bearer mock-token' },
    });
    assert.equal(r2.status, 401);

    const r3 = await fetch(`${baseUrl}/api/security/events`, {
      headers: { Authorization: 'Bearer fake.forged.jwt123' },
    });
    assert.equal(r3.status, 401);

    const r4 = await fetch(`${baseUrl}/api/security/admin-audit`, {
      headers: { Authorization: 'Bearer fake.forged.jwt123' },
    });
    assert.equal(r4.status, 401);
  });

  await runTest('All-API-Validation', 'Validate input checks & malformed payload handling across all API routes', async () => {
    const endpointsToValidate: Array<{ path: string; body: Record<string, unknown> }> = [
      { path: '/api/analyze-image', body: {} },
      { path: '/api/analyze-apk', body: {} },
      { path: '/api/analyze-browser-history', body: {} },
      { path: '/api/threat-intel', body: {} },
      { path: '/api/dns-ip-lookup', body: {} },
      { path: '/api/analyze-script', body: {} },
      { path: '/api/analyze-binary', body: {} },
      { path: '/api/live-feeds/briefing', body: { items: [] } },
      { path: '/api/search', body: { query: '' } },
      { path: '/api/security/client-event', body: { eventType: 'INVALID_TYPE' } },
    ];

    for (const ep of endpointsToValidate) {
      const r = await fetch(`${baseUrl}${ep.path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ep.body),
      });
      assert.equal(r.status, 400, `Expected HTTP 400 validation error on ${ep.path}, got ${r.status}`);
    }

    const catRes = await fetch(`${baseUrl}/api/live-feeds/catalog`);
    assert.equal(catRes.status, 200);
    const catJson = await catRes.json();
    assert.ok(Array.isArray(catJson.feeds) && catJson.feeds.length >= 4);

    const buildRes = await fetch(`${baseUrl}/api/export/build-info`);
    assert.equal(buildRes.status, 200);
  });

  await runTest('CSRF-ContentType', 'Block untrusted cross-origin CSRF POST & non-JSON Content-Type', async () => {
    const csrfRes = await fetch(`${baseUrl}/api/dns-ip-lookup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'https://malicious-attacker.example',
      },
      body: JSON.stringify({ target: '8.8.8.8' }),
    });
    assert.equal(csrfRes.status, 403);

    const ctRes = await fetch(`${baseUrl}/api/dns-ip-lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: 'target=8.8.8.8',
    });
    assert.equal(ctRes.status, 415);

    const badJsonRes = await fetch(`${baseUrl}/api/dns-ip-lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{invalid-json',
    });
    assert.equal(badJsonRes.status, 400);
    const badJsonBody = await badJsonRes.json();
    assert.equal(JSON.stringify(badJsonBody).includes('SyntaxError'), false);
  });

  await runTest('SSRF-API', 'Block private/loopback/cloud-metadata probes across OSINT & Live Feeds APIs', async () => {
    for (const target of ['127.0.0.1', '169.254.169.254', '10.0.0.1', 'localhost']) {
      const res = await fetch(`${baseUrl}/api/dns-ip-lookup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target }),
      });
      assert.equal(res.status, 400, `Expected 400 for SSRF target ${target}`);
    }

    const feedRes = await fetch(`${baseUrl}/api/live-feeds/sync`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        enabledSources: [],
        customFeedUrls: [{ name: 'ssrf', url: 'http://169.254.169.254/latest/meta-data/' }],
      }),
    });
    assert.equal(feedRes.status, 200);
    const feedData = await feedRes.json();
    assert.equal(feedData.sourceStatuses?.[0]?.status, 'error');
  });

  await runTest('Export-Secrets', 'Verify exported full-source ZIP includes firebase.json & excludes .env/.git/node_modules', async () => {
    const zipRes = await fetch(`${baseUrl}/api/export/pwa-package?mode=full-source`);
    assert.equal(zipRes.status, 200);
    const buf = await zipRes.arrayBuffer();
    const zip = await JSZip.loadAsync(buf);
    const paths = Object.keys(zip.files);
    assert.ok(paths.includes('server/security.ts'), 'Expected server/security.ts in full-source export');
    assert.ok(paths.includes('firestore.rules'), 'Expected firestore.rules in full-source export');
    assert.ok(paths.includes('storage.rules'), 'Expected storage.rules in full-source export');
    assert.ok(paths.includes('firebase.json'), 'Expected firebase.json in full-source export');
    for (const p of paths) {
      assert.equal(p === '.env' || p === '.env.local', false, `Secret file leaked in ZIP: ${p}`);
      assert.equal(p.startsWith('node_modules/'), false, `node_modules leaked in ZIP: ${p}`);
      assert.equal(p.startsWith('.git/'), false, `.git leaked in ZIP: ${p}`);
    }
  });

  await runTest('Rate-Limit-Monitor', 'Verify Rate Limiter enforces 429 with Retry-After/X-RateLimit-Reset & Security Monitor logs', async () => {
    let hit429 = false;
    for (let i = 0; i < 15; i++) {
      const r = await fetch(`${baseUrl}/api/export/build-info`);
      assert.ok(r.headers.get('x-ratelimit-limit'), 'Expected X-RateLimit-Limit header');
      if (r.status === 429) {
        hit429 = true;
        assert.ok(r.headers.get('retry-after'), 'Expected Retry-After header on 429');
        break;
      }
    }
    assert.equal(hit429, true, 'Expected rate limiter to trigger HTTP 429 within 15 rapid bursts');

    const statusRes = await fetch(`${baseUrl}/api/security/status`);
    const statusJson = await statusRes.json();
    assert.ok(statusJson.totalBlocked >= 5, `Expected Security Monitor to count blocked attacks, got ${statusJson.totalBlocked}`);
    assert.equal(statusJson.chainIntegrity?.valid, true);
    assert.ok(['secret-env', 'secret-file', 'ephemeral-runtime'].includes(statusJson.hmacKeySource));
  });

  const passedCount = results.filter((r) => r.passed).length;
  console.log(`\nSECURITY VERIFICATION SUMMARY: ${passedCount}/${results.length} tests passed.`);
  if (passedCount !== results.length) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal pentest runner error:', err);
  process.exit(1);
});
