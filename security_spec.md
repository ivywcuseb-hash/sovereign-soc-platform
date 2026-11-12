# Security Specification: Audit Log SHA-256 Hash Field

## 1. Data Invariants
- Each `AuditLog` entry MUST have a unique `id` and belong to an authenticated user (`userId`).
- The `sha256` hash, once created, MUST be immutable.
- A user can only access their own audit logs.

## 2. The "Dirty Dozen" Payloads
1. Create log without `sha256`. (Should Fail)
2. Create log with `sha256` longer than 64 chars. (Should Fail)
3. Create log with `sha256` containing invalid hex characters. (Should Fail)
4. Create log with `userId` belonging to another user. (Should Fail)
5. Create log with an empty `sha256` string. (Should Fail)
6. Update existing `sha256` field. (Should Fail)
7. Update `userId` field to a different UID. (Should Fail)
8. Create log with `createdAt` set in the future. (Should Fail - implicitly covered by server time)
9. Create log with `authenticityScore` > 100 or < 0. (Should Fail)
10. Update `logId` path to something not matching document `id` field. (Should Fail)
11. List all logs not belonging to the authenticated user. (Should Fail)
12. Delete another user's log. (Should Fail)

## 3. Test Runner (firestore.rules.test.ts)
```typescript
// Conceptual Test Runner
assertFails(db.collection('audit_logs').add({ ...payloadWithoutSha256 }));
assertFails(db.collection('audit_logs').add({ ...payloadWithLongSha256 }));
assertFails(db.collection('audit_logs').add({ ...payloadWithInvalidHexSha256 }));
assertFails(db.collection('audit_logs').doc('log1').set({ ...payloadWithDifferentUserId }));
// ... etc
```
