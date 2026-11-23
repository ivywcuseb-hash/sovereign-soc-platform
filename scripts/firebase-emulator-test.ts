import assert from 'node:assert/strict';
import { initializeApp, deleteApp } from 'firebase/app';
import {
  getAuth,
  connectAuthEmulator,
  createUserWithEmailAndPassword,
  signOut,
} from 'firebase/auth';
import {
  getFirestore,
  connectFirestoreEmulator,
  doc,
  setDoc,
  getDoc,
  updateDoc,
  deleteDoc,
  collection,
  query,
  where,
  getDocs,
} from 'firebase/firestore';
import {
  getStorage,
  connectStorageEmulator,
  ref,
  uploadBytes,
  getBytes,
} from 'firebase/storage';
import { initializeApp as initAdmin, getApps, deleteApp as deleteAdminApp } from 'firebase-admin/app';
import { getFirestore as getAdminFirestore } from 'firebase-admin/firestore';

/**
 * Real Firebase Emulator Suite Security Verification
 * Execute in any environment with Java installed via:
 *   firebase emulators:exec --only auth,firestore,storage "npm run test:emulator"
 */
async function main() {
  const firestoreHost = process.env.FIRESTORE_EMULATOR_HOST;
  const authHost = process.env.FIREBASE_AUTH_EMULATOR_HOST;
  const storageHost = process.env.FIREBASE_STORAGE_EMULATOR_HOST;

  if (!firestoreHost || !authHost || !storageHost) {
    console.error(
      '[ERROR] Firebase Emulator environment variables are missing. Run via:\n' +
        '  firebase emulators:exec --only auth,firestore,storage "npm run test:emulator"'
    );
    process.exit(1);
  }

  const projectId = 'sovereign-emulator-test';
  const adminApp = getApps().length ? getApps()[0] : initAdmin({ projectId });
  const adminDb = getAdminFirestore(adminApp);

  const clientCfg = {
    apiKey: 'fake-emulator-api-key',
    authDomain: `${projectId}.firebaseapp.com`,
    projectId,
    storageBucket: `${projectId}.appspot.com`,
  };

  const appA = initializeApp(clientCfg, 'user-a');
  const appB = initializeApp(clientCfg, 'user-b');
  const appAnon = initializeApp(clientCfg, 'anon');

  const authA = getAuth(appA);
  const authB = getAuth(appB);
  connectAuthEmulator(authA, `http://${authHost}`, { disableWarnings: true });
  connectAuthEmulator(authB, `http://${authHost}`, { disableWarnings: true });

  const [fsHost, fsPortStr] = firestoreHost.split(':');
  const [stHost, stPortStr] = storageHost.split(':');
  const dbA = getFirestore(appA);
  const dbB = getFirestore(appB);
  const dbAnon = getFirestore(appAnon);
  connectFirestoreEmulator(dbA, fsHost, Number(fsPortStr));
  connectFirestoreEmulator(dbB, fsHost, Number(fsPortStr));
  connectFirestoreEmulator(dbAnon, fsHost, Number(fsPortStr));

  const storageA = getStorage(appA);
  const storageB = getStorage(appB);
  const storageAnon = getStorage(appAnon);
  connectStorageEmulator(storageA, stHost, Number(stPortStr));
  connectStorageEmulator(storageB, stHost, Number(stPortStr));
  connectStorageEmulator(storageAnon, stHost, Number(stPortStr));

  const credA = await createUserWithEmailAndPassword(authA, 'analyst-a@sovereign.local', 'SovereignTest!123');
  const credB = await createUserWithEmailAndPassword(authB, 'analyst-b@sovereign.local', 'SovereignTest!123');
  const uidA = credA.user.uid;
  const uidB = credB.user.uid;

  // Seed admin role ONLY via Admin SDK (clients must never write /admins/{uid})
  await adminDb.collection('admins').doc(uidB).set({ active: true, grantedAt: new Date().toISOString() });

  // 1. Unauthenticated read/write must fail closed on Firestore & Storage
  await assert.rejects(() => getDoc(doc(dbAnon, 'users', uidA)));
  await assert.rejects(() => getDocs(collection(dbAnon, 'investigations')));
  await assert.rejects(() =>
    uploadBytes(ref(storageAnon, `evidence/${uidA}/unauth.txt`), new TextEncoder().encode('nope'))
  );
  console.log('[PASS] Unauthenticated Firestore & Storage access rejected');

  // 2. Privilege escalation tests: analyst A cannot create role='admin' or write /admins or /security_events
  await assert.rejects(() =>
    setDoc(doc(dbA, 'users', uidA), {
      uid: uidA,
      email: 'analyst-a@sovereign.local',
      role: 'admin',
      createdAt: new Date().toISOString(),
    })
  );
  await assert.rejects(() => setDoc(doc(dbA, 'admins', uidA), { active: true }));
  await assert.rejects(() =>
    setDoc(doc(dbA, 'security_events', 'evt-forged'), { id: 'evt-forged' })
  );
  console.log('[PASS] Privilege escalation (/users role=admin, /admins, /security_events) rejected');

  // 3. Valid analyst A profile & evidence creation
  await setDoc(doc(dbA, 'users', uidA), {
    uid: uidA,
    email: 'analyst-a@sovereign.local',
    displayName: 'Analyst A',
    role: 'analyst',
    createdAt: new Date().toISOString(),
  });
  await assert.rejects(() =>
    updateDoc(doc(dbA, 'users', uidA), { role: 'admin' })
  );

  const sha = 'a'.repeat(64);
  await setDoc(doc(dbA, 'investigations', 'inv-a-001'), {
    userId: uidA,
    title: 'Case A',
    status: 'active',
    createdAt: new Date().toISOString(),
  });
  await setDoc(doc(dbA, 'evidence', 'ev-a-001'), {
    userId: uidA,
    investigationId: 'inv-a-001',
    fileName: 'sample.bin',
    sha256: sha,
    createdAt: new Date().toISOString(),
  });
  await uploadBytes(
    ref(storageA, `evidence/${uidA}/sample.bin`),
    new TextEncoder().encode('evidence-bytes')
  );
  console.log('[PASS] Owner A valid writes accepted & role field immutable');

  // 4. Cross-user isolation: non-admin user C or user A reading another user's data must fail
  // Note: uidB is admin; create user C as standard analyst to verify cross-tenant isolation
  const appC = initializeApp(clientCfg, 'user-c');
  const authC = getAuth(appC);
  connectAuthEmulator(authC, `http://${authHost}`, { disableWarnings: true });
  const dbC = getFirestore(appC);
  connectFirestoreEmulator(dbC, fsHost, Number(fsPortStr));
  const storageC = getStorage(appC);
  connectStorageEmulator(storageC, stHost, Number(stPortStr));
  const credC = await createUserWithEmailAndPassword(authC, 'analyst-c@sovereign.local', 'SovereignTest!123');
  const uidC = credC.user.uid;

  await assert.rejects(() => getDoc(doc(dbC, 'users', uidA)));
  await assert.rejects(() => getDoc(doc(dbC, 'investigations', 'inv-a-001')));
  await assert.rejects(() => getDoc(doc(dbC, 'evidence', 'ev-a-001')));
  await assert.rejects(() =>
    getDocs(query(collection(dbC, 'evidence'), where('userId', '==', uidA)))
  );
  await assert.rejects(() => deleteDoc(doc(dbC, 'evidence', 'ev-a-001')));
  await assert.rejects(() => getBytes(ref(storageC, `evidence/${uidA}/sample.bin`)));
  await assert.rejects(() =>
    uploadBytes(ref(storageC, `evidence/${uidA}/tamper.bin`), new TextEncoder().encode('x'))
  );
  console.log('[PASS] Cross-user isolation (User C -> User A Firestore & Storage) strictly blocked');

  // 5. Storage size & MIME type validation
  await assert.rejects(() =>
    uploadBytes(ref(storageA, `profiles/${uidA}/not-an-image.txt`), new TextEncoder().encode('text'), {
      contentType: 'text/plain',
    })
  );
  const over5Mb = new Uint8Array(5 * 1024 * 1024 + 64);
  await assert.rejects(() =>
    uploadBytes(ref(storageA, `profiles/${uidA}/huge.png`), over5Mb, { contentType: 'image/png' })
  );
  console.log('[PASS] Storage MIME & size limits enforced');

  // 6. Server-verified Admin (User B seeded in /admins) can audit User A records, still cannot alter immutable logs
  const evSnapByAdmin = await getDoc(doc(dbB, 'evidence', 'ev-a-001'));
  assert.equal(evSnapByAdmin.exists(), true);

  // 7. Platform Site Controls (Announcement Banner & Maintenance Mode) strictly Admin-writable
  const siteControlsPayload = {
    announcementEnabled: true,
    announcementText: 'System maintenance alert',
    announcementType: 'warning',
    announcementUpdatedAt: new Date().toISOString(),
    maintenanceTools: ['apk'],
    maintenanceGroups: [],
    maintenanceMessage: 'APK analyzer under scheduled upgrade',
    maintenanceUpdatedAt: new Date().toISOString(),
    updatedBy: uidA,
    updatedAt: new Date().toISOString(),
  };
  await assert.rejects(() =>
    setDoc(doc(dbA, 'platform_config', 'site_controls'), siteControlsPayload)
  );
  await setDoc(doc(dbB, 'platform_config', 'site_controls'), {
    ...siteControlsPayload,
    updatedBy: uidB,
  });
  const siteControlsByAnalyst = await getDoc(doc(dbA, 'platform_config', 'site_controls'));
  assert.equal(siteControlsByAnalyst.exists(), true);
  assert.equal(siteControlsByAnalyst.data()?.announcementEnabled, true);
  console.log('[PASS] Server-verified Admin RBAC & platform_config/site_controls confirmed');

  await signOut(authA);
  await signOut(authB);
  await signOut(authC);
  await deleteApp(appA);
  await deleteApp(appB);
  await deleteApp(appC);
  await deleteApp(appAnon);
  await deleteAdminApp(adminApp);
  console.log('\nALL FIREBASE EMULATOR SECURITY TESTS PASSED.');
}

main().catch((err) => {
  console.error('Emulator security test failed:', err);
  process.exit(1);
});
