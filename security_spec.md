# Security Specification: Sovereign Forensic Engine (Full-Stack Invariants)

## 1. Data & Authorization Invariants
- **Strict Tenant Isolation**: Every document in `investigations`, `evidence`, `custody_ledger`, `forensic_reports`, and `audit_logs` MUST belong to `request.auth.uid` (or verified server-side Admin).
- **Privilege Escalation Prevention**: Client writes to `/users/{uid}` MUST NOT assign `role: 'admin'`, and `role`, `uid`, `createdAt` are immutable once created. `/admins/{uid}` is readable/writable strictly via Firebase Admin SDK (`allow read, write: if false;` in Rules).
- **Immutability**: `audit_logs`, `custody_ledger`, `forensic_reports`, `chain_of_custody`, and `security_events` disallow client `update` and `delete`.
- **Cryptographic Integrity**: `sha256`, `prevHash`, `recordHash`, and `reportSealSha256` MUST match `^[a-fA-F0-9]{64}$`.
- **Storage Isolation**: `/profiles/{userId}/**` prohibits unauthenticated reads; all uploads enforce strict byte limits (`5MB` profiles, `25MB` evidence) and MIME constraints where appropriate.

## 2. The "Dirty Dozen" Payloads (Adversarial Rule Matrix)
1. Create `audit_logs` entry without `sha256`. (MUST FAIL)
2. Create `audit_logs` entry with `sha256` longer than 64 chars or non-hex chars. (MUST FAIL)
3. Update or delete existing `audit_logs` / `custody_ledger` / `forensic_reports` document. (MUST FAIL)
4. Create `users/{uid}` with `role: 'admin'` or update `users/{uid}` changing `role` / `uid`. (MUST FAIL)
5. Write to `/admins/{uid}` or `/security_events/{id}` from client SDK. (MUST FAIL)
6. Cross-tenant `get`/`list`/`update`/`delete` on another user's `investigations`, `evidence`, `audit_logs`, or `users/{otherUid}`. (MUST FAIL)
7. Create `audit_logs` with `authenticityScore` > 100 or < 0. (MUST FAIL)
8. Create `evidence` without valid 64-char hex `sha256` or > 100MB `fileSize`. (MUST FAIL)
9. Unauthenticated Storage `read` on `/profiles/{userId}/avatar.png`. (MUST FAIL)
10. Storage upload > 5MB or `text/html` MIME on `/profiles/{userId}/avatar`. (MUST FAIL)
11. Unauthenticated `/api/dashboard-stats` or `/api/security/events` or forged `Bearer mock-token`. (MUST RETURN 401)
12. SSRF probe (`127.0.0.1`, `169.254.169.254`, `10.0.0.1`, `localhost`) via `/api/dns-ip-lookup` or `/api/live-feeds/sync`. (MUST BLOCK & LOG `SSRF_BLOCKED`)
