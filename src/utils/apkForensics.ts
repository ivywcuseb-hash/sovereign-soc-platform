import JSZip from 'jszip';

export type PermissionSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface ApkPermissionRecord {
  name: string;
  shortName: string;
  severity: PermissionSeverity;
  category: string;
  description: string;
}

export interface ApkUrlRecord {
  url: string;
  domain: string;
  sourceFile: string;
  occurrences: number;
  isStandardSchema: boolean;
  riskTag: 'suspicious' | 'insecure_http' | 'https_endpoint' | 'schema_ref';
}

export interface ApkIpRecord {
  ip: string;
  sourceFile: string;
  occurrences: number;
  isPrivate: boolean;
  classification: string;
}

export interface ApkStaticForensicsResult {
  fileName: string;
  fileSize: number;
  packageName: string | null;
  versionName: string | null;
  minSdkVersion: string | null;
  targetSdkVersion: string | null;
  hasAndroidManifest: boolean;
  manifestFormat: 'axml_binary' | 'xml_plaintext' | 'missing';
  totalEntries: number;
  dexFiles: string[];
  nativeLibs: string[];
  certFiles: string[];
  permissions: ApkPermissionRecord[];
  sensitivePermissionsCount: number;
  criticalPermissionsCount: number;
  suspiciousTriggers: string[];
  urls: ApkUrlRecord[];
  endpointUrlsCount: number;
  ips: ApkIpRecord[];
  manifestRawStringsSample: string[];
  extractionTimestamp: string;
}

const SENSITIVE_PERMISSIONS_DB: Record<
  string,
  { severity: PermissionSeverity; category: string; description: string }
> = {
  'android.permission.READ_SMS': {
    severity: 'critical',
    category: 'الرسائل النصية (SMS)',
    description: 'قراءة كافة الرسائل النصية الواردة والصادرة بما في ذلك رموز التحقق (OTP).',
  },
  'android.permission.RECEIVE_SMS': {
    severity: 'critical',
    category: 'الرسائل النصية (SMS)',
    description: 'اعتراض الرسائل النصية الواردة فور وصولها في الخلفية.',
  },
  'android.permission.SEND_SMS': {
    severity: 'critical',
    category: 'الرسائل النصية (SMS)',
    description: 'إرسال رسائل نصية دون تدخل المستخدم (خطر الاحتيال أو تسريب البيانات).',
  },
  'android.permission.READ_CALL_LOG': {
    severity: 'critical',
    category: 'سجل المكالمات',
    description: 'الوصول الكامل لسجل المكالمات الصادرة والواردة والفائتة.',
  },
  'android.permission.WRITE_CALL_LOG': {
    severity: 'high',
    category: 'سجل المكالمات',
    description: 'تعديل أو حذف سجل المكالمات لإخفاء آثار النشاط.',
  },
  'android.permission.PROCESS_OUTGOING_CALLS': {
    severity: 'critical',
    category: 'المكالمات',
    description: 'مراقبة أو تعديل أو إعادة توجيه المكالمات الصادرة.',
  },
  'android.permission.RECORD_AUDIO': {
    severity: 'critical',
    category: 'التنصت والميكروفون',
    description: 'تسجيل الصوت من الميكروفون سراً أو أثناء المكالمات.',
  },
  'android.permission.CAMERA': {
    severity: 'critical',
    category: 'الكاميرا والتصوير',
    description: 'الوصول إلى الكاميرا والتقاط الصور أو الفيديو.',
  },
  'android.permission.ACCESS_BACKGROUND_LOCATION': {
    severity: 'critical',
    category: 'التتبع الجغرافي',
    description: 'تتبع الموقع الجغرافي الدقيق باستمرار في الخلفية حتى عند إغلاق التطبيق.',
  },
  'android.permission.ACCESS_FINE_LOCATION': {
    severity: 'high',
    category: 'التتبع الجغرافي',
    description: 'الحصول على إحداثيات GPS الدقيقة للمستخدم.',
  },
  'android.permission.ACCESS_COARSE_LOCATION': {
    severity: 'medium',
    category: 'التتبع الجغرافي',
    description: 'تحديد الموقع التقريبي عبر الشبكة والأبراج.',
  },
  'android.permission.READ_CONTACTS': {
    severity: 'high',
    category: 'جهات الاتصال',
    description: 'سحب قائمة جهات الاتصال وأرقام الهواتف والبريد الإلكتروني.',
  },
  'android.permission.WRITE_CONTACTS': {
    severity: 'medium',
    category: 'جهات الاتصال',
    description: 'تعديل أو إضافة جهات اتصال جديدة.',
  },
  'android.permission.BIND_ACCESSIBILITY_SERVICE': {
    severity: 'critical',
    category: 'إمكانية الوصول (Accessibility)',
    description: 'صلاحية خطيرة جداً تتيح قراءة محتوى الشاشة وتسجيل النقرات (Keylogging) والتحكم الكامل بالجهاز.',
  },
  'android.permission.BIND_DEVICE_ADMIN': {
    severity: 'critical',
    category: 'إدارة الجهاز (Device Admin)',
    description: 'منع المستخدم من إلغاء تثبيت التطبيق أو قفل الجهاز وتشفيره.',
  },
  'android.permission.SYSTEM_ALERT_WINDOW': {
    severity: 'high',
    category: 'التراكب على الشاشة (Overlay)',
    description: 'رسم نوافذ فوق التطبيقات الأخرى (يستخدم في هجمات التصيد وسرقة كلمات المرور).',
  },
  'android.permission.REQUEST_INSTALL_PACKAGES': {
    severity: 'high',
    category: 'تثبيت الحزم',
    description: 'تنزيل وتثبيت تطبيقات APK إضافية (Dropper / Payload Loader).',
  },
  'android.permission.MANAGE_EXTERNAL_STORAGE': {
    severity: 'high',
    category: 'التخزين الشامل',
    description: 'الوصول الكامل لجميع الملفات والمجلدات في ذاكرة الجهاز.',
  },
  'android.permission.READ_EXTERNAL_STORAGE': {
    severity: 'medium',
    category: 'التخزين',
    description: 'قراءة الصور والملفات من ذاكرة الهاتف.',
  },
  'android.permission.WRITE_EXTERNAL_STORAGE': {
    severity: 'medium',
    category: 'التخزين',
    description: 'كتابة أو تعديل الملفات في ذاكرة الهاتف.',
  },
  'android.permission.READ_PHONE_STATE': {
    severity: 'high',
    category: 'معرفات الجهاز',
    description: 'قراءة رقم الهاتف وIMEI ومعرف الشبكة وحالة الاتصال.',
  },
  'android.permission.READ_PHONE_NUMBERS': {
    severity: 'high',
    category: 'معرفات الجهاز',
    description: 'قراءة أرقام الهاتف المسجلة في الشرائح.',
  },
  'android.permission.QUERY_ALL_PACKAGES': {
    severity: 'high',
    category: 'جرد التطبيقات',
    description: 'استعراض قائمة جميع التطبيقات المثبتة على الجهاز.',
  },
  'android.permission.PACKAGE_USAGE_STATS': {
    severity: 'high',
    category: 'مراقبة الاستخدام',
    description: 'مراقبة التطبيقات التي يفتحها المستخدم ومدة استخدامها.',
  },
  'android.permission.RECEIVE_BOOT_COMPLETED': {
    severity: 'medium',
    category: 'الاستمرارية (Persistence)',
    description: 'التشغيل التلقائي في الخلفية فور إعادة تشغيل الهاتف.',
  },
  'android.permission.GET_ACCOUNTS': {
    severity: 'medium',
    category: 'الحسابات',
    description: 'معرفة الحسابات المسجلة على الجهاز (Google / Email).',
  },
  'android.permission.INTERNET': {
    severity: 'low',
    category: 'الشبكة',
    description: 'فتح اتصالات شبكة وإرسال/استقبال البيانات عبر الإنترنت.',
  },
  'android.permission.ACCESS_NETWORK_STATE': {
    severity: 'low',
    category: 'الشبكة',
    description: 'معرفة حالة اتصال الإنترنت.',
  },
  'android.permission.WAKE_LOCK': {
    severity: 'low',
    category: 'الطاقة والخلفية',
    description: 'منع المعالج من السكون للاستمرار في العمل بالخلفية.',
  },
  'android.permission.FOREGROUND_SERVICE': {
    severity: 'low',
    category: 'الخدمات',
    description: 'تشغيل خدمة مستمرة في الخلفية.',
  },
};

const STANDARD_SCHEMA_DOMAINS = new Set([
  'schemas.android.com',
  'www.w3.org',
  'ns.adobe.com',
  'www.apache.org',
  'apache.org',
  'opensource.org',
  'purl.org',
  'xml.org',
  'java.sun.com',
  'schemas.xmlsoap.org',
]);

function readUint16LE(u8: Uint8Array, offset: number): number {
  return u8[offset] | (u8[offset + 1] << 8);
}

function readUint32LE(u8: Uint8Array, offset: number): number {
  return (
    (u8[offset] |
      (u8[offset + 1] << 8) |
      (u8[offset + 2] << 16) |
      (u8[offset + 3] << 24)) >>>
    0
  );
}

/**
 * Parses Android Binary XML (AXML) StringPool and extracts all string entries.
 * Supports both UTF-8 (FLAG_UTF8 = 0x100) and UTF-16LE encodings per AOSP ResourceTypes.h.
 */
export function extractStringsFromAxml(buffer: Uint8Array): {
  isAxml: boolean;
  strings: string[];
} {
  if (buffer.length < 16) return { isAxml: false, strings: [] };

  const fileType = readUint16LE(buffer, 0);
  const headerSize = readUint16LE(buffer, 2);

  // RES_XML_TYPE = 0x0003
  if (fileType !== 0x0003 || headerSize < 8 || headerSize >= buffer.length) {
    return { isAxml: false, strings: [] };
  }

  const strings: string[] = [];
  const utf8Decoder = new TextDecoder('utf-8', { fatal: false });
  const utf16Decoder = new TextDecoder('utf-16le', { fatal: false });

  let pos = headerSize;
  while (pos + 8 <= buffer.length) {
    const chunkType = readUint16LE(buffer, pos);
    const chunkHeaderSize = readUint16LE(buffer, pos + 2);
    const chunkSize = readUint32LE(buffer, pos + 4);

    if (chunkSize < 8 || pos + chunkSize > buffer.length) break;

    // RES_STRING_POOL_TYPE = 0x0001
    if (chunkType === 0x0001 && pos + 28 <= buffer.length) {
      const stringCount = readUint32LE(buffer, pos + 8);
      const flags = readUint32LE(buffer, pos + 16);
      const stringsStart = readUint32LE(buffer, pos + 20);
      const isUtf8 = (flags & 0x0100) !== 0;

      const offsetsStart = pos + chunkHeaderSize;
      const poolDataStart = pos + stringsStart;

      const maxCount = Math.min(stringCount, 50000);
      for (let i = 0; i < maxCount; i++) {
        const offPos = offsetsStart + i * 4;
        if (offPos + 4 > buffer.length) break;
        const strOffset = readUint32LE(buffer, offPos);
        let sPos = poolDataStart + strOffset;
        if (sPos >= pos + chunkSize) continue;

        try {
          if (isUtf8) {
            // Length encoded in 1 or 2 bytes for UTF-16 length, then 1 or 2 bytes for UTF-8 byte length
            if (sPos >= buffer.length) continue;
            const u16Len1 = buffer[sPos++];
            if ((u16Len1 & 0x80) !== 0 && sPos < buffer.length) sPos++;

            if (sPos >= buffer.length) continue;
            let byteLen = buffer[sPos++];
            if ((byteLen & 0x80) !== 0 && sPos < buffer.length) {
              byteLen = ((byteLen & 0x7f) << 8) | buffer[sPos++];
            }

            if (byteLen > 0 && sPos + byteLen <= buffer.length) {
              const decoded = utf8Decoder.decode(buffer.subarray(sPos, sPos + byteLen)).replace(/\0+$/, '');
              if (decoded) strings.push(decoded);
            } else if (byteLen === 0) {
              strings.push('');
            }
          } else {
            if (sPos + 2 > buffer.length) continue;
            let charLen = readUint16LE(buffer, sPos);
            sPos += 2;
            if ((charLen & 0x8000) !== 0 && sPos + 2 <= buffer.length) {
              const low = readUint16LE(buffer, sPos);
              sPos += 2;
              charLen = ((charLen & 0x7fff) << 16) | low;
            }
            const byteLen = charLen * 2;
            if (byteLen > 0 && sPos + byteLen <= buffer.length) {
              const decoded = utf16Decoder.decode(buffer.subarray(sPos, sPos + byteLen)).replace(/\0+$/, '');
              if (decoded) strings.push(decoded);
            } else if (byteLen === 0) {
              strings.push('');
            }
          }
        } catch {
          // Ignore malformed pool string entry
        }
      }
      break;
    }

    pos += chunkSize;
  }

  return { isAxml: true, strings };
}

/**
 * Extracts printable ASCII & UTF-8 sequences from binary buffers (DEX, ARSC, SO, etc.)
 * in a fast, memory-safe linear pass.
 */
function extractPrintableStringsFromBinary(u8: Uint8Array, minLen: number = 6, maxBytes: number = 14 * 1024 * 1024): string {
  const limit = Math.min(u8.length, maxBytes);
  const chunks: string[] = [];
  let start = -1;

  for (let i = 0; i < limit; i++) {
    const c = u8[i];
    const isPrintable = c >= 0x20 && c <= 0x7e;
    if (isPrintable) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= minLen) {
        let str = '';
        for (let j = start; j < i; j++) {
          str += String.fromCharCode(u8[j]);
        }
        chunks.push(str);
      }
      start = -1;
    }
  }
  if (start !== -1 && limit - start >= minLen) {
    let str = '';
    for (let j = start; j < limit; j++) {
      str += String.fromCharCode(u8[j]);
    }
    chunks.push(str);
  }
  return chunks.join('\n');
}

function classifyPermission(permName: string): ApkPermissionRecord {
  const trimmed = permName.trim();
  const shortName = trimmed.includes('.') ? trimmed.split('.').pop() || trimmed : trimmed;
  const exact = SENSITIVE_PERMISSIONS_DB[trimmed];
  if (exact) {
    return {
      name: trimmed,
      shortName,
      severity: exact.severity,
      category: exact.category,
      description: exact.description,
    };
  }

  const upper = shortName.toUpperCase();
  if (
    upper.includes('SMS') ||
    upper.includes('CALL_LOG') ||
    upper.includes('ACCESSIBILITY') ||
    upper.includes('RECORD_AUDIO') ||
    upper.includes('CAMERA') ||
    upper.includes('DEVICE_ADMIN') ||
    upper.includes('SPY')
  ) {
    return {
      name: trimmed,
      shortName,
      severity: 'critical',
      category: 'صلاحية حرجة مخصصة/موسعة',
      description: 'صلاحية حساسة تمس خصوصية المكالمات أو الرسائل أو التحكم بالنظام.',
    };
  }

  if (
    upper.includes('LOCATION') ||
    upper.includes('CONTACTS') ||
    upper.includes('PHONE') ||
    upper.includes('INSTALL') ||
    upper.includes('OVERLAY') ||
    upper.includes('PACKAGE')
  ) {
    return {
      name: trimmed,
      shortName,
      severity: 'high',
      category: 'صلاحية وصول عالي',
      description: 'صلاحية تمنح وصولاً لبيانات المستخدم أو الحزم أو الموقع.',
    };
  }

  if (upper.includes('STORAGE') || upper.includes('BOOT') || upper.includes('ACCOUNT')) {
    return {
      name: trimmed,
      shortName,
      severity: 'medium',
      category: 'صلاحية نظام/تخزين',
      description: 'صلاحية مرتبطة بالملفات أو التشغيل التلقائي.',
    };
  }

  return {
    name: trimmed,
    shortName,
    severity: 'low',
    category: 'صلاحية تطبيق قياسية',
    description: 'صلاحية قياسية أو مخصصة للتطبيق.',
  };
}

function isPrivateIpAddress(ip: string): { isPrivate: boolean; label: string } {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) {
    return { isPrivate: false, label: 'غير معروف' };
  }
  const [a, b] = parts;
  if (a === 127) return { isPrivate: true, label: 'Loopback / Localhost (127.x)' };
  if (a === 0) return { isPrivate: true, label: 'Unspecified / Wildcard (0.0.0.0)' };
  if (a === 10) return { isPrivate: true, label: 'شبكة خاصة (Private RFC1918 10.x)' };
  if (a === 172 && b >= 16 && b <= 31) return { isPrivate: true, label: 'شبكة خاصة (Private RFC1918 172.16-31.x)' };
  if (a === 192 && b === 168) return { isPrivate: true, label: 'شبكة محلية (LAN 192.168.x)' };
  if (a === 169 && b === 254) return { isPrivate: true, label: 'Link-Local (169.254.x)' };
  if (a >= 224) return { isPrivate: true, label: 'Multicast / Reserved' };
  return { isPrivate: false, label: 'عنوان IP عام خارجي (Public Routable IP)' };
}

export async function analyzeApkBuffer(
  buffer: ArrayBuffer,
  fileName: string
): Promise<ApkStaticForensicsResult> {
  const zip = await JSZip.loadAsync(buffer);
  const allEntryNames = Object.keys(zip.files);

  const dexFiles = allEntryNames.filter((n) => /^classes\d*\.dex$/i.test(n) || n.endsWith('.dex'));
  const nativeLibs = allEntryNames.filter((n) => n.startsWith('lib/') && n.endsWith('.so'));
  const certFiles = allEntryNames.filter((n) => n.startsWith('META-INF/') && /\.(RSA|DSA|EC|SF|MF)$/i.test(n));

  let hasAndroidManifest = false;
  let manifestFormat: 'axml_binary' | 'xml_plaintext' | 'missing' = 'missing';
  let packageName: string | null = null;
  let versionName: string | null = null;
  let minSdkVersion: string | null = null;
  let targetSdkVersion: string | null = null;
  const manifestRawStringsSample: string[] = [];
  const permissionsSet = new Set<string>();
  const suspiciousTriggersSet = new Set<string>();

  const urlMap = new Map<string, ApkUrlRecord>();
  const ipMap = new Map<string, ApkIpRecord>();

  const collectUrlsAndIps = (text: string, sourceFile: string) => {
    // 1. Extract URLs
    const urlRegex = /https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g;
    const urlMatches = text.match(urlRegex) || [];
    for (const rawUrl of urlMatches) {
      const cleaned = rawUrl.replace(/[.,;:'")\]}>\\]+$/, '');
      if (cleaned.length < 10 || cleaned.length > 512) continue;
      let domain = '';
      try {
        domain = new URL(cleaned).hostname.toLowerCase();
      } catch {
        continue;
      }
      if (!domain || !domain.includes('.')) continue;

      const isStandardSchema = STANDARD_SCHEMA_DOMAINS.has(domain);
      const isSuspiciousUrl =
        !isStandardSchema &&
        (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain) ||
          /:\d{2,5}/.test(cleaned) ||
          /\.onion$|ngrok|duckdns|no-ip|pastebin|raw\.githubusercontent|discord\.com\/api\/webhooks|api\.telegram\.org|\/gate\.php|\/panel|\/upload/i.test(
            cleaned
          ));

      const riskTag: ApkUrlRecord['riskTag'] = isStandardSchema
        ? 'schema_ref'
        : isSuspiciousUrl
        ? 'suspicious'
        : cleaned.startsWith('http://')
        ? 'insecure_http'
        : 'https_endpoint';

      const existing = urlMap.get(cleaned);
      if (existing) {
        existing.occurrences += 1;
      } else {
        urlMap.set(cleaned, {
          url: cleaned,
          domain,
          sourceFile,
          occurrences: 1,
          isStandardSchema,
          riskTag,
        });
      }
    }

    // 2. Extract IPv4 addresses
    const ipRegex =
      /(?<![.\d])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![.\d])/g;
    const ipMatches = text.match(ipRegex) || [];
    for (const ip of ipMatches) {
      // Ignore obvious Android version/OID prefixes like 1.0.0.0 or 255.255.255.255 mask if repeated
      if (ip === '0.0.0.0' || ip === '255.255.255.255' || ip === '255.255.255.0') continue;
      const { isPrivate, label } = isPrivateIpAddress(ip);
      const existing = ipMap.get(ip);
      if (existing) {
        existing.occurrences += 1;
      } else {
        ipMap.set(ip, {
          ip,
          sourceFile,
          occurrences: 1,
          isPrivate,
          classification: label,
        });
      }
    }
  };

  // Step 1: Parse AndroidManifest.xml
  const manifestEntry = zip.file('AndroidManifest.xml');
  if (manifestEntry) {
    hasAndroidManifest = true;
    const manifestBytes = await manifestEntry.async('uint8array');
    const axml = extractStringsFromAxml(manifestBytes);

    if (axml.isAxml && axml.strings.length > 0) {
      manifestFormat = 'axml_binary';
      const filteredStrings = axml.strings.filter((s) => s.trim().length > 0);
      manifestRawStringsSample.push(...filteredStrings.slice(0, 60));

      for (const s of filteredStrings) {
        if (
          /^(android\.permission|com\.android\.|com\.google\.android\.|androidx\.|[a-zA-Z0-9_.]+\.permission)\.[A-Z0-9_]+$/.test(
            s
          )
        ) {
          permissionsSet.add(s);
        }
        if (
          /SMS_RECEIVED|BOOT_COMPLETED|AccessibilityService|DeviceAdminReceiver|PHONE_STATE|NEW_OUTGOING_CALL|OVERLAY/i.test(
            s
          )
        ) {
          suspiciousTriggersSet.add(s);
        }
        if (
          !packageName &&
          /^[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,6}$/.test(s) &&
          !s.startsWith('android.') &&
          !s.startsWith('http') &&
          !s.includes('.permission.') &&
          !s.endsWith('.xml')
        ) {
          packageName = s;
        }
      }
      collectUrlsAndIps(filteredStrings.join('\n'), 'AndroidManifest.xml');
    } else {
      // Plaintext XML or fallback text scan
      const text = new TextDecoder('utf-8', { fatal: false }).decode(manifestBytes);
      if (text.includes('<manifest') || text.includes('uses-permission')) {
        manifestFormat = 'xml_plaintext';
      } else {
        manifestFormat = 'axml_binary';
      }

      const pkgMatch = text.match(/package\s*=\s*["']([^"']+)["']/);
      if (pkgMatch) packageName = pkgMatch[1];

      const verMatch = text.match(/android:versionName\s*=\s*["']([^"']+)["']/);
      if (verMatch) versionName = verMatch[1];

      const minSdkMatch = text.match(/android:minSdkVersion\s*=\s*["']([^"']+)["']/);
      if (minSdkMatch) minSdkVersion = minSdkMatch[1];

      const targetSdkMatch = text.match(/android:targetSdkVersion\s*=\s*["']([^"']+)["']/);
      if (targetSdkMatch) targetSdkVersion = targetSdkMatch[1];

      const permRegex = /[a-zA-Z0-9_.]+\.permission\.[A-Z0-9_]+/g;
      const perms = text.match(permRegex) || [];
      for (const p of perms) permissionsSet.add(p);

      const triggerMatches =
        text.match(
          /[a-zA-Z0-9_.]*(?:SMS_RECEIVED|BOOT_COMPLETED|AccessibilityService|DeviceAdminReceiver|NEW_OUTGOING_CALL)[a-zA-Z0-9_.]*/gi
        ) || [];
      for (const t of triggerMatches) suspiciousTriggersSet.add(t);

      const fallbackPrintable = extractPrintableStringsFromBinary(manifestBytes, 6, 2 * 1024 * 1024);
      manifestRawStringsSample.push(
        ...fallbackPrintable
          .split('\n')
          .filter(Boolean)
          .slice(0, 40)
      );
      collectUrlsAndIps(text + '\n' + fallbackPrintable, 'AndroidManifest.xml');
    }
  }

  // Step 2: Scan DEX, resources, assets, and config files for URLs & IPs
  const scanTargets = allEntryNames.filter((name) => {
    const entry = zip.files[name];
    if (!entry || entry.dir) return false;
    if (name === 'AndroidManifest.xml') return false;
    if (/^classes\d*\.dex$/i.test(name) || name.endsWith('.dex')) return true;
    if (name === 'resources.arsc') return true;
    if (name.startsWith('assets/') && !/\.(png|jpg|jpeg|webp|ogg|mp3|mp4|ttf|otf|woff2?)$/i.test(name)) return true;
    if (/\.(json|xml|properties|js|html|txt|cfg|conf|ini|pem|crt|so)$/i.test(name)) return true;
    return false;
  });

  // Cap total scanned entries cleanly to guarantee snappy execution in browser
  for (const entryName of scanTargets.slice(0, 60)) {
    const fileObj = zip.file(entryName);
    if (!fileObj) continue;
    try {
      const bytes = await fileObj.async('uint8array');
      const isText = /\.(json|xml|properties|js|html|txt|cfg|conf|ini)$/i.test(entryName);
      if (isText) {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 2 * 1024 * 1024));
        collectUrlsAndIps(text, entryName);
      } else {
        const printable = extractPrintableStringsFromBinary(bytes, 7, 10 * 1024 * 1024);
        collectUrlsAndIps(printable, entryName);
      }
    } catch {
      // Skip unreadable zip entry
    }
  }

  const severityOrder: Record<PermissionSeverity, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
  };

  const permissions = Array.from(permissionsSet)
    .map(classifyPermission)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || a.shortName.localeCompare(b.shortName));

  const urls = Array.from(urlMap.values()).sort((a, b) => {
    const rank = { suspicious: 0, insecure_http: 1, https_endpoint: 2, schema_ref: 3 };
    return rank[a.riskTag] - rank[b.riskTag] || b.occurrences - a.occurrences;
  });

  const ips = Array.from(ipMap.values()).sort((a, b) => {
    if (a.isPrivate !== b.isPrivate) return a.isPrivate ? 1 : -1;
    return b.occurrences - a.occurrences;
  });

  const sensitivePermissionsCount = permissions.filter((p) => p.severity === 'critical' || p.severity === 'high').length;
  const criticalPermissionsCount = permissions.filter((p) => p.severity === 'critical').length;
  const endpointUrlsCount = urls.filter((u) => !u.isStandardSchema).length;

  return {
    fileName,
    fileSize: buffer.byteLength,
    packageName,
    versionName,
    minSdkVersion,
    targetSdkVersion,
    hasAndroidManifest,
    manifestFormat,
    totalEntries: allEntryNames.length,
    dexFiles,
    nativeLibs,
    certFiles,
    permissions,
    sensitivePermissionsCount,
    criticalPermissionsCount,
    suspiciousTriggers: Array.from(suspiciousTriggersSet),
    urls: urls.slice(0, 200),
    endpointUrlsCount,
    ips: ips.slice(0, 150),
    manifestRawStringsSample,
    extractionTimestamp: new Date().toISOString(),
  };
}
