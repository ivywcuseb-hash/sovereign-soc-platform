import SparkMD5 from 'spark-md5';

export interface BinaryInspectionResult {
  hexBytes: string[];
  extendedHexBytes?: string[];
  totalByteLength?: number;
  headerHex: string;
  headerAscii: string;
  detectedFileType: string;
  mimeTypeDetected: string;
  expectedExtensions: string[];
  matchedSignatureHex?: string;
  isExecOrDangerous: boolean;
  entropy: number;
  entropyClassification: string;
  isMasqueraded: boolean;
  masqueradeWarning: string | null;
  sha256: string;
  sha1: string;
  sha512: string;
  md5: string;
}

export interface GpsMetadata {
  latitude: number;
  longitude: number;
  latitudeRef: string;
  longitudeRef: string;
  latitudeDms: string;
  longitudeDms: string;
  altitude?: number;
  altitudeRef?: string;
  timeStamp?: string;
  dateStamp?: string;
}

export interface ExifTagEntry {
  tagId: string;
  ifd: 'IFD0' | 'ExifIFD' | 'GPS';
  name: string;
  value: string;
}

export interface FullExifData {
  hasExif: boolean;
  containerFormat?: string;
  make?: string;
  model?: string;
  dateTime?: string;
  dateTimeOriginal?: string;
  dateTimeDigitized?: string;
  software?: string;
  lensModel?: string;
  exposureTime?: string;
  fNumber?: string;
  iso?: string;
  focalLength?: string;
  gps?: GpsMetadata;
  rawTags?: ExifTagEntry[];
  message?: string;
}

export interface MagicSignatureInfo {
  signatureHex: string;
  format: string;
  extensions: string[];
  category: 'image' | 'document' | 'executable' | 'archive' | 'database' | 'media';
}

export const KNOWN_MAGIC_SIGNATURES: MagicSignatureInfo[] = [
  { signatureHex: 'FF D8 FF', format: 'JPEG Image (JFIF / EXIF)', extensions: ['jpg', 'jpeg'], category: 'image' },
  { signatureHex: '89 50 4E 47 0D 0A 1A 0A', format: 'PNG Image', extensions: ['png'], category: 'image' },
  { signatureHex: '47 49 46 38', format: 'GIF Image', extensions: ['gif'], category: 'image' },
  { signatureHex: '52 49 46 46 .. .. .. .. 57 45 42 50', format: 'WebP Image', extensions: ['webp'], category: 'image' },
  { signatureHex: '25 50 44 46', format: 'Adobe PDF Document', extensions: ['pdf'], category: 'document' },
  { signatureHex: '50 4B 03 04', format: 'ZIP / OOXML (DOCX, XLSX, APK, JAR)', extensions: ['zip', 'docx', 'xlsx', 'apk', 'jar'], category: 'archive' },
  { signatureHex: 'D0 CF 11 E0 A1 B1 1A E1', format: 'OLE2 Compound (DOC, XLS, MSI)', extensions: ['doc', 'xls', 'msi'], category: 'document' },
  { signatureHex: '4D 5A', format: 'Windows PE Executable / DLL (MZ)', extensions: ['exe', 'dll', 'sys'], category: 'executable' },
  { signatureHex: '7F 45 4C 46', format: 'Linux ELF Executable / SO', extensions: ['elf', 'so', 'bin'], category: 'executable' },
  { signatureHex: 'CF FA ED FE', format: 'macOS Mach-O 64-bit Binary', extensions: ['dylib', 'macho'], category: 'executable' },
  { signatureHex: '52 61 72 21', format: 'RAR Compressed Archive', extensions: ['rar'], category: 'archive' },
  { signatureHex: '37 7A BC AF 27 1C', format: '7-Zip Archive', extensions: ['7z'], category: 'archive' },
  { signatureHex: '1F 8B', format: 'GZIP Compressed Stream', extensions: ['gz', 'tgz'], category: 'archive' },
  { signatureHex: '53 51 4C 69 74 65', format: 'SQLite 3 Database', extensions: ['db', 'sqlite', 'sqlite3'], category: 'database' },
  { signatureHex: '23 21', format: 'Unix Shebang Script (#!)', extensions: ['sh', 'py', 'pl'], category: 'executable' },
];

export interface ChainOfCustodyRecord {
  id: string;
  evidenceId: string;
  userId: string;
  officerName?: string;
  action: string;
  location: string;
  notes: string;
  timestamp: string;
  prevHash?: string;
  recordHash?: string;
}

export interface ChainVerificationResult {
  verified: boolean;
  count: number;
  status: 'empty' | 'valid' | 'tampered';
  brokenAtIndex?: number;
  reason?: string;
}

export type IoCType =
  | 'ipv4'
  | 'ipv6'
  | 'domain'
  | 'url'
  | 'email'
  | 'sha256'
  | 'sha1'
  | 'md5'
  | 'cve'
  | 'exploit'
  | 'artifact';

export interface ExtractedIoCRecord {
  id: string;
  type: IoCType;
  value: string;
  details: string;
  isPrivateIp?: boolean;
  severity: 'critical' | 'high' | 'medium' | 'info';
  occurrences: number;
  lines: number[];
}

export interface IoCStatsSummary {
  total: number;
  critical: number;
  high: number;
  ipv4: number;
  ipv6: number;
  domain: number;
  url: number;
  email: number;
  hash: number;
  cve: number;
  exploit: number;
  artifact: number;
}

const MAGIC_GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export function formatFileSize(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }
  return `${(bytes / 1024).toFixed(2)} KB`;
}

export function calculateShannonEntropy(buffer: ArrayBuffer): { entropy: number; classification: string } {
  const bytes = new Uint8Array(buffer);
  if (bytes.length === 0) {
    return { entropy: 0, classification: 'منخفض (Zero Data)' };
  }
  const frequencies = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) {
    frequencies[bytes[i]]++;
  }
  let entropy = 0;
  const total = bytes.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / total;
      entropy -= p * Math.log2(p);
    }
  }
  const val = Number(entropy.toFixed(3));
  let classification = 'طبيعي (Normal Binary Data)';
  if (val >= 7.2) {
    classification = 'عالي جداً (High/Encrypted/Packed) - يشير لتشفير أو تغليف برمجيات (Packer/UPX)';
  } else if (val < 4.0) {
    classification = 'منخفض (Low/Sparse) - بيانات نصية أو فراغ بايتات متكرر';
  }
  return { entropy: val, classification };
}

function bytesMatch(u8: Uint8Array, offset: number, sig: number[]): boolean {
  if (u8.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) {
    if (u8[offset + i] !== sig[i]) return false;
  }
  return true;
}

function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function analyzeFileBinary(
  buffer: ArrayBuffer,
  fileName: string = '',
  declaredMimeType: string = ''
): Promise<BinaryInspectionResult> {
  const uint8 = new Uint8Array(buffer);
  const inspectLength = Math.min(uint8.length, 256);
  const extendedLength = Math.min(uint8.length, 4096);
  const hexBytes: string[] = [];
  const extendedHexBytes: string[] = [];
  for (let i = 0; i < extendedLength; i++) {
    const hex = uint8[i].toString(16).padStart(2, '0').toUpperCase();
    if (i < inspectLength) hexBytes.push(hex);
    extendedHexBytes.push(hex);
  }

  const headerHex = hexBytes.slice(0, 16).join(' ');
  let headerAscii = '';
  for (let i = 0; i < Math.min(uint8.length, 16); i++) {
    const code = uint8[i];
    headerAscii += code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
  }

  const { entropy, classification: entropyClassification } = calculateShannonEntropy(buffer);

  // Compute real cryptographic hashes via WebCrypto + SparkMD5
  const [sha256Buf, sha1Buf, sha512Buf] = await Promise.all([
    crypto.subtle.digest('SHA-256', buffer),
    crypto.subtle.digest('SHA-1', buffer),
    crypto.subtle.digest('SHA-512', buffer),
  ]);
  const sha256 = bufferToHex(sha256Buf);
  const sha1 = bufferToHex(sha1Buf);
  const sha512 = bufferToHex(sha512Buf);
  const spark = new SparkMD5.ArrayBuffer();
  spark.append(buffer);
  const md5 = spark.end();

  let detectedFileType = 'ملف بيانات ثنائي غير معروف (Unknown Binary Stream)';
  let mimeTypeDetected = declaredMimeType || 'application/octet-stream';
  let expectedExtensions: string[] = [];
  let isExecOrDangerous = false;

  // Comprehensive Magic Bytes Database
  if (bytesMatch(uint8, 0, [0xff, 0xd8, 0xff])) {
    detectedFileType = 'صورة JPEG أصلية (JPEG Baseline / JFIF / EXIF)';
    mimeTypeDetected = 'image/jpeg';
    expectedExtensions = ['jpg', 'jpeg', 'jpe', 'jif', 'jfif'];
  } else if (bytesMatch(uint8, 0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) {
    detectedFileType = 'صورة PNG أصلية (Portable Network Graphics)';
    mimeTypeDetected = 'image/png';
    expectedExtensions = ['png'];
  } else if (bytesMatch(uint8, 0, [0x47, 0x49, 0x46, 0x38])) {
    detectedFileType = 'صورة GIF متحركة/ثابتة (Graphics Interchange Format)';
    mimeTypeDetected = 'image/gif';
    expectedExtensions = ['gif'];
  } else if (
    bytesMatch(uint8, 0, [0x52, 0x49, 0x46, 0x46]) &&
    bytesMatch(uint8, 8, [0x57, 0x45, 0x42, 0x50])
  ) {
    detectedFileType = 'صورة WebP (Google RIFF WebP Container)';
    mimeTypeDetected = 'image/webp';
    expectedExtensions = ['webp'];
  } else if (bytesMatch(uint8, 0, [0x42, 0x4d])) {
    detectedFileType = 'صورة BMP حقيقية (Windows Bitmap)';
    mimeTypeDetected = 'image/bmp';
    expectedExtensions = ['bmp'];
  } else if (
    bytesMatch(uint8, 0, [0x49, 0x49, 0x2a, 0x00]) ||
    bytesMatch(uint8, 0, [0x4d, 0x4d, 0x00, 0x2a])
  ) {
    detectedFileType = 'صورة TIFF أصلية (Tagged Image File Format)';
    mimeTypeDetected = 'image/tiff';
    expectedExtensions = ['tif', 'tiff'];
  } else if (bytesMatch(uint8, 0, [0x00, 0x00, 0x01, 0x00])) {
    detectedFileType = 'أيقونة ويندوز (Windows ICO)';
    mimeTypeDetected = 'image/x-icon';
    expectedExtensions = ['ico'];
  } else if (bytesMatch(uint8, 0, [0x38, 0x42, 0x50, 0x53])) {
    detectedFileType = 'ملف فوتوشوب (Adobe Photoshop PSD)';
    mimeTypeDetected = 'image/vnd.adobe.photoshop';
    expectedExtensions = ['psd'];
  } else if (bytesMatch(uint8, 0, [0x4d, 0x5a])) {
    detectedFileType = 'ملف تنفيذي لنظام ويندوز (Windows PE Executable / DLL / MZ)';
    mimeTypeDetected = 'application/x-dosexec';
    expectedExtensions = ['exe', 'dll', 'sys', 'scr', 'cpl', 'ocx'];
    isExecOrDangerous = true;
  } else if (bytesMatch(uint8, 0, [0x7f, 0x45, 0x4c, 0x46])) {
    detectedFileType = 'ملف تنفيذي لأنظمة لينكس (Linux ELF Binary / Shared Object)';
    mimeTypeDetected = 'application/x-elf';
    expectedExtensions = ['elf', 'so', 'bin', 'out'];
    isExecOrDangerous = true;
  } else if (
    bytesMatch(uint8, 0, [0xfe, 0xed, 0xfa, 0xce]) ||
    bytesMatch(uint8, 0, [0xfe, 0xed, 0xfa, 0xcf]) ||
    bytesMatch(uint8, 0, [0xcf, 0xfa, 0xed, 0xfe]) ||
    bytesMatch(uint8, 0, [0xce, 0xfa, 0xed, 0xfe])
  ) {
    detectedFileType = 'ملف تنفيذي لماكنتوش (macOS Mach-O Binary)';
    mimeTypeDetected = 'application/x-mach-binary';
    expectedExtensions = ['dylib', 'macho', 'bin'];
    isExecOrDangerous = true;
  } else if (bytesMatch(uint8, 0, [0xca, 0xfe, 0xba, 0xbe])) {
    detectedFileType = 'ملف بايت كود جافا (Java Class / Mach-O Universal Binary)';
    mimeTypeDetected = 'application/java-vm';
    expectedExtensions = ['class', 'jar'];
    isExecOrDangerous = true;
  } else if (bytesMatch(uint8, 0, [0x00, 0x61, 0x73, 0x6d])) {
    detectedFileType = 'وحدة ويب أسمبلي (WebAssembly Binary / Wasm)';
    mimeTypeDetected = 'application/wasm';
    expectedExtensions = ['wasm'];
  } else if (bytesMatch(uint8, 0, [0x64, 0x65, 0x78, 0x0a])) {
    detectedFileType = 'كود تطبيقي لأندرويد (Android Dalvik Executable DEX)';
    mimeTypeDetected = 'application/vnd.android.dex';
    expectedExtensions = ['dex'];
    isExecOrDangerous = true;
  } else if (bytesMatch(uint8, 0, [0x25, 0x50, 0x44, 0x46])) {
    detectedFileType = 'مستند رقمي أدوبي PDF (Portable Document Format)';
    mimeTypeDetected = 'application/pdf';
    expectedExtensions = ['pdf'];
  } else if (bytesMatch(uint8, 0, [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])) {
    detectedFileType = 'ملف مركب أوفيس / حزمة تثبيت (OLE2 Compound / DOC / XLS / MSI)';
    mimeTypeDetected = 'application/x-ole-storage';
    expectedExtensions = ['doc', 'xls', 'ppt', 'msi', 'msg'];
  } else if (
    bytesMatch(uint8, 0, [0x50, 0x4b, 0x03, 0x04]) ||
    bytesMatch(uint8, 0, [0x50, 0x4b, 0x05, 0x06])
  ) {
    detectedFileType = 'أرشيف مضغوط ZIP أو حزمة أوفيس (ZIP / OOXML DOCX / XLSX / APK / JAR)';
    mimeTypeDetected = 'application/zip';
    expectedExtensions = ['zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odt'];
  } else if (bytesMatch(uint8, 0, [0x52, 0x61, 0x72, 0x21])) {
    detectedFileType = 'أرشيف رار مضغوط (RAR Archive)';
    mimeTypeDetected = 'application/x-rar-compressed';
    expectedExtensions = ['rar'];
  } else if (bytesMatch(uint8, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) {
    detectedFileType = 'أرشيف 7-Zip مضغوط (7-Zip Archive)';
    mimeTypeDetected = 'application/x-7z-compressed';
    expectedExtensions = ['7z'];
  } else if (bytesMatch(uint8, 0, [0x1f, 0x8b])) {
    detectedFileType = 'أرشيف GZIP مضغوط (Gzip Compressed)';
    mimeTypeDetected = 'application/gzip';
    expectedExtensions = ['gz', 'tgz'];
  } else if (bytesMatch(uint8, 0, [0x42, 0x5a, 0x68])) {
    detectedFileType = 'أرشيف BZip2 مضغوط (BZip2 Archive)';
    mimeTypeDetected = 'application/x-bzip2';
    expectedExtensions = ['bz2'];
  } else if (bytesMatch(uint8, 0, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) {
    detectedFileType = 'أرشيف XZ مضغوط (XZ Archive)';
    mimeTypeDetected = 'application/x-xz';
    expectedExtensions = ['xz'];
  } else if (bytesMatch(uint8, 257, [0x75, 0x73, 0x74, 0x61, 0x72])) {
    detectedFileType = 'أرشيف POSIX TAR (Tape Archive)';
    mimeTypeDetected = 'application/x-tar';
    expectedExtensions = ['tar'];
  } else if (bytesMatch(uint8, 0, [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65])) {
    detectedFileType = 'قاعدة بيانات محلية (SQLite 3 Database File)';
    mimeTypeDetected = 'application/vnd.sqlite3';
    expectedExtensions = ['db', 'sqlite', 'sqlite3', 'db3'];
  } else if (bytesMatch(uint8, 0, [0x23, 0x21])) {
    detectedFileType = 'سكربت تنفيذي يبدأ بـ Shebang (Shell / Python / Perl Script)';
    mimeTypeDetected = 'text/x-script';
    expectedExtensions = ['sh', 'bash', 'py', 'pl', 'rb'];
    isExecOrDangerous = true;
  } else if (bytesMatch(uint8, 0, [0x49, 0x44, 0x33]) || bytesMatch(uint8, 0, [0xff, 0xfb])) {
    detectedFileType = 'ملف صوتي MP3 (MPEG Audio Layer III)';
    mimeTypeDetected = 'audio/mpeg';
    expectedExtensions = ['mp3'];
  } else if (
    bytesMatch(uint8, 0, [0x52, 0x49, 0x46, 0x46]) &&
    bytesMatch(uint8, 8, [0x57, 0x41, 0x56, 0x45])
  ) {
    detectedFileType = 'ملف صوتي WAV (RIFF WAVE Audio)';
    mimeTypeDetected = 'audio/wav';
    expectedExtensions = ['wav'];
  } else if (bytesMatch(uint8, 4, [0x66, 0x74, 0x79, 0x70])) {
    detectedFileType = 'ملف وسائط ISO BMFF (MP4 / MOV / M4A)';
    mimeTypeDetected = 'video/mp4';
    expectedExtensions = ['mp4', 'mov', 'm4v', 'm4a', '3gp'];
  } else {
    // Inspect printable ASCII/UTF-8 text signatures (PEM, JSON, XML, HTML, SVG, Log)
    const headText = new TextDecoder('utf-8', { fatal: false }).decode(uint8.slice(0, 512)).trimStart();
    if (headText.startsWith('-----BEGIN ')) {
      detectedFileType = 'شهادة تشفير أو مفتاح خاص PEM (X.509 / RSA / EC Key)';
      mimeTypeDetected = 'application/x-pem-file';
      expectedExtensions = ['pem', 'crt', 'cer', 'key'];
    } else if (headText.startsWith('<svg') || (headText.startsWith('<?xml') && headText.includes('<svg'))) {
      detectedFileType = 'رسم متجهي SVG (Scalable Vector Graphics - قد يحتوي سكربت)';
      mimeTypeDetected = 'image/svg+xml';
      expectedExtensions = ['svg'];
    } else if (headText.toLowerCase().startsWith('<!doctype html') || headText.toLowerCase().startsWith('<html')) {
      detectedFileType = 'صفحة ويب HTML (HyperText Markup Language)';
      mimeTypeDetected = 'text/html';
      expectedExtensions = ['html', 'htm'];
    } else if (headText.startsWith('<?xml')) {
      detectedFileType = 'مستند بيانات XML (Extensible Markup Language)';
      mimeTypeDetected = 'application/xml';
      expectedExtensions = ['xml'];
    } else if (
      (headText.startsWith('{') || headText.startsWith('[')) &&
      entropy < 5.8
    ) {
      detectedFileType = 'بيانات مهيكلة JSON / نص منسق';
      mimeTypeDetected = 'application/json';
      expectedExtensions = ['json', 'jsonl', 'txt', 'log'];
    } else if (entropy < 5.5 && uint8.slice(0, 128).every((b) => b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126) || b >= 128)) {
      detectedFileType = 'ملف نصي أو سجل نظام (Plain Text / Log / CSV / Script)';
      mimeTypeDetected = 'text/plain';
      expectedExtensions = ['txt', 'log', 'csv', 'md', 'conf', 'ini', 'yaml', 'yml', 'ps1', 'bat', 'js', 'ts'];
    }
  }

  // Masquerade Detection: Compare declared file extension with detected Magic Bytes
  let isMasqueraded = false;
  let masqueradeWarning: string | null = null;
  const fileExt = fileName.includes('.') ? fileName.split('.').pop()?.toLowerCase() || '' : '';

  if (fileExt && expectedExtensions.length > 0 && !expectedExtensions.includes(fileExt)) {
    isMasqueraded = true;
    if (isExecOrDangerous) {
      masqueradeWarning = `تحذير تزوير حرج (CRITICAL TROJAN / MASQUERADE): الملف يحمل امتداداً ظاهراً (.${fileExt}) ولكنه ملف تنفيذي حقيقي (${detectedFileType}) بموجب ترويسة البايتات السحرية!`;
    } else {
      masqueradeWarning = `عدم تطابق الامتداد مع الترويسة (Extension Mismatch): الامتداد الظاهر (.${fileExt}) لا يتطابق مع التوقيع الفعلي المكتشف (${detectedFileType}).`;
    }
  }

  return {
    hexBytes,
    extendedHexBytes,
    totalByteLength: uint8.length,
    headerHex,
    headerAscii,
    detectedFileType,
    mimeTypeDetected,
    expectedExtensions,
    isExecOrDangerous,
    entropy,
    entropyClassification,
    isMasqueraded,
    masqueradeWarning,
    sha256,
    sha1,
    sha512,
    md5,
  };
}

function formatDms(degFloat: number, posHemisphere: string, negHemisphere: string): string {
  const absVal = Math.abs(degFloat);
  const deg = Math.floor(absVal);
  const minFloat = (absVal - deg) * 60;
  const min = Math.floor(minFloat);
  const sec = ((minFloat - min) * 60).toFixed(2);
  const hemi = degFloat >= 0 ? posHemisphere : negHemisphere;
  return `${deg}° ${min}' ${sec}" ${hemi}`;
}

function parseTiffExifBlock(
  view: DataView,
  tiffStart: number,
  maxEnd: number,
  containerFormat: string
): FullExifData {
  if (tiffStart + 8 > maxEnd) {
    return { hasExif: false, containerFormat, message: 'ترويسة TIFF غير مكتملة' };
  }

  const endian = view.getUint16(tiffStart, false);
  if (endian !== 0x4949 && endian !== 0x4d4d) {
    return { hasExif: false, containerFormat, message: 'ترتيب بايتات EXIF غير صالح' };
  }
  const le = endian === 0x4949;
  const getU16 = (rel: number) => (tiffStart + rel + 2 <= maxEnd ? view.getUint16(tiffStart + rel, le) : 0);
  const getU32 = (rel: number) => (tiffStart + rel + 4 <= maxEnd ? view.getUint32(tiffStart + rel, le) : 0);

  if (getU16(2) !== 0x002a) {
    return { hasExif: false, containerFormat, message: 'توقيع TIFF القياسي (0x002A) غير موجود' };
  }

  const readStringAt = (relOffset: number, count: number): string => {
    let out = '';
    const limit = Math.min(count, 256);
    for (let i = 0; i < limit; i++) {
      const abs = tiffStart + relOffset + i;
      if (abs >= maxEnd) break;
      const ch = view.getUint8(abs);
      if (ch === 0) break;
      out += String.fromCharCode(ch);
    }
    return out.trim();
  };

  const readRationalsAt = (relOffset: number, count: number): number[] => {
    const arr: number[] = [];
    const safeCount = Math.min(count, 16);
    for (let i = 0; i < safeCount; i++) {
      const pos = relOffset + i * 8;
      if (tiffStart + pos + 8 > maxEnd) break;
      const num = getU32(pos);
      const den = getU32(pos + 4);
      arr.push(den !== 0 ? num / den : 0);
    }
    return arr;
  };

  const typeSize = (t: number): number => {
    if (t === 1 || t === 2 || t === 6 || t === 7) return 1;
    if (t === 3 || t === 8) return 2;
    if (t === 4 || t === 9 || t === 11) return 4;
    if (t === 5 || t === 10 || t === 12) return 8;
    return 1;
  };

  const result: FullExifData = {
    hasExif: false,
    containerFormat,
    rawTags: [],
  };

  const tagLabels: Record<number, string> = {
    0x010f: 'Make (الشركة المصنعة)',
    0x0110: 'Model (طراز الجهاز/الكاميرا)',
    0x0131: 'Software (البرنامج المستخدم)',
    0x0132: 'DateTime (تاريخ التعديل)',
    0x9003: 'DateTimeOriginal (تاريخ الالتقاط الأصلي)',
    0x9004: 'DateTimeDigitized (تاريخ الرقمنة)',
    0xa434: 'LensModel (طراز العدسة)',
    0x829a: 'ExposureTime (سرعة الغالق)',
    0x829d: 'FNumber (فتحة العدسة)',
    0x8827: 'ISOSpeedRatings (حساسية الضوء ISO)',
    0x920a: 'FocalLength (البعد البؤري)',
    0x0001: 'GPSLatitudeRef (نصف الكرة العرضي)',
    0x0002: 'GPSLatitude (خط العرض)',
    0x0003: 'GPSLongitudeRef (نصف الكرة الطولي)',
    0x0004: 'GPSLongitude (خط الطول)',
    0x0006: 'GPSAltitude (الارتفاع عن سطح البحر)',
    0x0007: 'GPSTimeStamp (توقيت GPS UTC)',
    0x001d: 'GPSDateStamp (تاريخ GPS)',
  };

  let exifIfdOffset = 0;
  let gpsIfdOffset = 0;

  let gpsLatRef = 'N';
  let gpsLonRef = 'E';
  let gpsLatArr: number[] | null = null;
  let gpsLonArr: number[] | null = null;
  let gpsAlt: number | undefined;
  let gpsAltRef = 'فوق سطح البحر';
  let gpsTimeStr: string | undefined;
  let gpsDateStr: string | undefined;

  const parseIfd = (ifdRelOffset: number, ifdName: 'IFD0' | 'ExifIFD' | 'GPS') => {
    if (!ifdRelOffset || tiffStart + ifdRelOffset + 2 > maxEnd) return;
    const count = Math.min(getU16(ifdRelOffset), 120);
    for (let i = 0; i < count; i++) {
      const entryRel = ifdRelOffset + 2 + i * 12;
      if (tiffStart + entryRel + 12 > maxEnd) break;

      const tag = getU16(entryRel);
      const type = getU16(entryRel + 2);
      const valCount = getU32(entryRel + 4);
      const byteLen = valCount * typeSize(type);
      const dataRel = byteLen <= 4 ? entryRel + 8 : getU32(entryRel + 8);

      if (ifdName === 'IFD0') {
        if (tag === 0x8769) {
          exifIfdOffset = getU32(entryRel + 8);
          continue;
        }
        if (tag === 0x8825) {
          gpsIfdOffset = getU32(entryRel + 8);
          continue;
        }
      }

      let formattedValue = '';

      if (type === 2) {
        const str = readStringAt(dataRel, valCount);
        formattedValue = str;
        if (ifdName === 'IFD0') {
          if (tag === 0x010f && str) result.make = str;
          if (tag === 0x0110 && str) result.model = str;
          if (tag === 0x0131 && str) result.software = str;
          if (tag === 0x0132 && str) result.dateTime = str;
        } else if (ifdName === 'ExifIFD') {
          if (tag === 0x9003 && str) result.dateTimeOriginal = str;
          if (tag === 0x9004 && str) result.dateTimeDigitized = str;
          if (tag === 0xa434 && str) result.lensModel = str;
        } else if (ifdName === 'GPS') {
          if (tag === 0x0001 && str) gpsLatRef = str.toUpperCase();
          if (tag === 0x0003 && str) gpsLonRef = str.toUpperCase();
          if (tag === 0x001d && str) gpsDateStr = str;
        }
      } else if (type === 5) {
        const rats = readRationalsAt(dataRel, valCount);
        if (ifdName === 'ExifIFD') {
          if (tag === 0x829a && rats.length > 0 && rats[0] > 0) {
            result.exposureTime = rats[0] < 1 ? `1/${Math.round(1 / rats[0])} s` : `${rats[0].toFixed(2)} s`;
            formattedValue = result.exposureTime;
          } else if (tag === 0x829d && rats.length > 0) {
            result.fNumber = `f/${rats[0].toFixed(1)}`;
            formattedValue = result.fNumber;
          } else if (tag === 0x920a && rats.length > 0) {
            result.focalLength = `${rats[0].toFixed(1)} mm`;
            formattedValue = result.focalLength;
          }
        } else if (ifdName === 'GPS') {
          if (tag === 0x0002 && rats.length >= 3) {
            gpsLatArr = rats;
            formattedValue = `${rats[0].toFixed(0)}° ${rats[1].toFixed(0)}' ${rats[2].toFixed(2)}"`;
          } else if (tag === 0x0004 && rats.length >= 3) {
            gpsLonArr = rats;
            formattedValue = `${rats[0].toFixed(0)}° ${rats[1].toFixed(0)}' ${rats[2].toFixed(2)}"`;
          } else if (tag === 0x0006 && rats.length > 0) {
            gpsAlt = Number(rats[0].toFixed(1));
            formattedValue = `${gpsAlt} m`;
          } else if (tag === 0x0007 && rats.length >= 3) {
            const hh = String(Math.floor(rats[0])).padStart(2, '0');
            const mm = String(Math.floor(rats[1])).padStart(2, '0');
            const ss = String(Math.floor(rats[2])).padStart(2, '0');
            gpsTimeStr = `${hh}:${mm}:${ss} UTC`;
            formattedValue = gpsTimeStr;
          }
        }
      } else if (type === 3 || type === 4 || type === 1) {
        const numericVal =
          type === 1
            ? view.getUint8(tiffStart + dataRel)
            : type === 3
            ? getU16(dataRel)
            : getU32(dataRel);
        formattedValue = String(numericVal);
        if (ifdName === 'ExifIFD' && tag === 0x8827) {
          result.iso = `ISO ${numericVal}`;
          formattedValue = result.iso;
        } else if (ifdName === 'GPS' && tag === 0x0005) {
          gpsAltRef = numericVal === 1 ? 'تحت سطح البحر' : 'فوق سطح البحر';
          formattedValue = gpsAltRef;
        }
      }

      if (formattedValue && tagLabels[tag]) {
        result.rawTags!.push({
          tagId: `0x${tag.toString(16).padStart(4, '0').toUpperCase()}`,
          ifd: ifdName,
          name: tagLabels[tag],
          value: formattedValue,
        });
      }
    }
  };

  const firstIfdOffset = getU32(4);
  parseIfd(firstIfdOffset, 'IFD0');
  if (exifIfdOffset) parseIfd(exifIfdOffset, 'ExifIFD');
  if (gpsIfdOffset) parseIfd(gpsIfdOffset, 'GPS');

  if (gpsLatArr && gpsLonArr) {
    const rawLat = gpsLatArr[0] + gpsLatArr[1] / 60 + gpsLatArr[2] / 3600;
    const rawLon = gpsLonArr[0] + gpsLonArr[1] / 60 + gpsLonArr[2] / 3600;
    const lat = Number((gpsLatRef === 'S' ? -rawLat : rawLat).toFixed(6));
    const lon = Number((gpsLonRef === 'W' ? -rawLon : rawLon).toFixed(6));
    const gpsObj: GpsMetadata = {
      latitude: lat,
      longitude: lon,
      latitudeRef: gpsLatRef,
      longitudeRef: gpsLonRef,
      latitudeDms: formatDms(lat, 'N', 'S'),
      longitudeDms: formatDms(lon, 'E', 'W'),
    };
    if (gpsAlt !== undefined) gpsObj.altitude = gpsAlt;
    if (gpsAltRef) gpsObj.altitudeRef = gpsAltRef;
    if (gpsTimeStr) gpsObj.timeStamp = gpsTimeStr;
    if (gpsDateStr) gpsObj.dateStamp = gpsDateStr;
    result.gps = gpsObj;
  }

  if (
    result.make ||
    result.model ||
    result.dateTime ||
    result.dateTimeOriginal ||
    result.software ||
    result.gps ||
    (result.rawTags && result.rawTags.length > 0)
  ) {
    result.hasExif = true;
    if (!result.dateTime && result.dateTimeOriginal) {
      result.dateTime = result.dateTimeOriginal;
    }
  } else {
    result.message = 'توجد ترويسة EXIF فارغة أو منزوعة الوسوم (EXIF Stripped)';
  }

  return result;
}

export function parseFullExifMetadata(buffer: ArrayBuffer): FullExifData {
  try {
    const view = new DataView(buffer);
    const len = view.byteLength;
    if (len < 12) {
      return { hasExif: false, message: 'حجم الملف صغير جداً ولا يحتوي على بيانات EXIF' };
    }

    // 1. JPEG (0xFFD8) -> Scan all APP segments properly
    if (view.getUint16(0, false) === 0xffd8) {
      let offset = 2;
      while (offset + 4 <= len) {
        const marker = view.getUint16(offset, false);
        offset += 2;

        // End of Image or Start of Scan
        if (marker === 0xffda || marker === 0xffd9) break;
        // Standalone markers (RST0-RST7, TEM, etc.)
        if ((marker >= 0xffd0 && marker <= 0xffd9) || marker === 0xff01) continue;
        if ((marker & 0xff00) !== 0xff00) break;

        if (offset + 2 > len) break;
        const segLen = view.getUint16(offset, false);
        if (segLen < 2) break;
        const segEnd = Math.min(len, offset + segLen);

        if (
          marker === 0xffe1 &&
          offset + 8 <= segEnd &&
          view.getUint32(offset + 2, false) === 0x45786966 &&
          view.getUint16(offset + 6, false) === 0x0000
        ) {
          return parseTiffExifBlock(view, offset + 8, segEnd, 'JPEG APP1 (EXIF)');
        }

        offset = segEnd;
      }
      return {
        hasExif: false,
        containerFormat: 'JPEG',
        message: 'لا توجد بيانات EXIF أو إحداثيات GPS مدمجة (تم مسح الميتاداتا أو إعادة ضغط الصورة)',
      };
    }

    // 2. PNG (89 50 4E 47 0D 0A 1A 0A) -> Check for eXIf chunk
    if (view.getUint32(0, false) === 0x89504e47 && view.getUint32(4, false) === 0x0d0a1a0a) {
      let offset = 8;
      while (offset + 12 <= len) {
        const chunkLen = view.getUint32(offset, false);
        const chunkType = view.getUint32(offset + 4, false);
        const dataStart = offset + 8;
        const dataEnd = Math.min(len, dataStart + chunkLen);
        if (chunkType === 0x65584966) {
          // 'eXIf'
          return parseTiffExifBlock(view, dataStart, dataEnd, 'PNG (eXIf Chunk)');
        }
        if (chunkType === 0x49454e44) break; // 'IEND'
        offset = dataEnd + 4; // skip 4-byte CRC
      }
      return {
        hasExif: false,
        containerFormat: 'PNG',
        message: 'ملف PNG بدون كتلة بيانات EXIF مدمجة (eXIf Chunk Not Found)',
      };
    }

    // 3. WebP (RIFF....WEBP) -> Check for EXIF chunk
    if (
      view.getUint32(0, false) === 0x52494646 &&
      view.getUint32(8, false) === 0x57454250
    ) {
      let offset = 12;
      while (offset + 8 <= len) {
        const chunkId = view.getUint32(offset, false);
        const chunkSize = view.getUint32(offset + 4, true);
        const dataStart = offset + 8;
        const dataEnd = Math.min(len, dataStart + chunkSize);
        if (chunkId === 0x45584946) {
          // 'EXIF'
          const hasExifPrefix =
            dataStart + 6 <= dataEnd &&
            view.getUint32(dataStart, false) === 0x45786966 &&
            view.getUint16(dataStart + 4, false) === 0x0000;
          return parseTiffExifBlock(
            view,
            hasExifPrefix ? dataStart + 6 : dataStart,
            dataEnd,
            'WebP (RIFF EXIF)'
          );
        }
        offset = dataStart + chunkSize + (chunkSize % 2);
      }
      return {
        hasExif: false,
        containerFormat: 'WebP',
        message: 'ملف WebP لا يحتوي على مقطع EXIF مدمج',
      };
    }

    return {
      hasExif: false,
      message: 'لا توجد ميتاداتا EXIF مدمجة في هذا النوع من الملفات',
    };
  } catch {
    return { hasExif: false, message: 'تعذر فك بنية EXIF الثنائية للملف' };
  }
}

export function injectRealExifGpsIntoJpeg(
  jpegBytes: Uint8Array,
  meta: {
    make?: string;
    model?: string;
    software?: string;
    dateTimeOriginal?: string;
    latitude?: number;
    longitude?: number;
    altitude?: number;
  } = {}
): ArrayBuffer {
  const make = meta.make || 'SOVEREIGN OPTICS';
  const model = meta.model || 'Forensic Field Cam X2';
  const software = meta.software || 'Sovereign Imaging Firmware v2.5';
  const dt = meta.dateTimeOriginal || '2026:11:13 14:30:22';
  const lat = meta.latitude ?? 24.713552;
  const lon = meta.longitude ?? 46.675296;
  const alt = meta.altitude ?? 612.4;

  const toDmsRationals = (dec: number): Array<[number, number]> => {
    const abs = Math.abs(dec);
    const d = Math.floor(abs);
    const mFull = (abs - d) * 60;
    const m = Math.floor(mFull);
    const sScaled = Math.round((mFull - m) * 60 * 100);
    return [
      [d, 1],
      [m, 1],
      [sScaled, 100],
    ];
  };

  // Build Big-Endian TIFF payload dynamically
  const buf = new ArrayBuffer(1024);
  const v = new DataView(buf);
  const u8 = new Uint8Array(buf);

  const writeStr = (pos: number, s: string): number => {
    for (let i = 0; i < s.length; i++) u8[pos + i] = s.charCodeAt(i);
    u8[pos + s.length] = 0;
    return s.length + 1;
  };

  // TIFF Header (8 bytes)
  v.setUint16(0, 0x4d4d, false); // 'MM' Big-endian
  v.setUint16(2, 0x002a, false);
  v.setUint32(4, 8, false); // IFD0 starts at 8

  // IFD0: 6 entries (Make, Model, Software, DateTime, ExifIFDPtr, GPSIFDPtr)
  const ifd0Offset = 8;
  const ifd0Count = 6;
  v.setUint16(ifd0Offset, ifd0Count, false);
  let cursor = ifd0Offset + 2 + ifd0Count * 12 + 4; // Next IFD = 0

  const setIfdEntry = (
    base: number,
    idx: number,
    tag: number,
    type: number,
    count: number,
    valOrOffset: number
  ) => {
    const p = base + 2 + idx * 12;
    v.setUint16(p, tag, false);
    v.setUint16(p + 2, type, false);
    v.setUint32(p + 4, count, false);
    v.setUint32(p + 8, valOrOffset, false);
  };

  const makeLen = writeStr(cursor, make);
  setIfdEntry(ifd0Offset, 0, 0x010f, 2, makeLen, cursor);
  cursor += makeLen;

  const modelLen = writeStr(cursor, model);
  setIfdEntry(ifd0Offset, 1, 0x0110, 2, modelLen, cursor);
  cursor += modelLen;

  const swLen = writeStr(cursor, software);
  setIfdEntry(ifd0Offset, 2, 0x0131, 2, swLen, cursor);
  cursor += swLen;

  const dtLen = writeStr(cursor, dt);
  setIfdEntry(ifd0Offset, 3, 0x0132, 2, dtLen, cursor);
  cursor += dtLen;

  // Align cursor to even boundary
  if (cursor % 2 !== 0) cursor++;
  const exifIfdOffset = cursor;
  setIfdEntry(ifd0Offset, 4, 0x8769, 4, 1, exifIfdOffset);

  // ExifIFD: 4 entries (DateTimeOriginal, DateTimeDigitized, FNumber, ISO)
  const exifCount = 4;
  v.setUint16(exifIfdOffset, exifCount, false);
  cursor = exifIfdOffset + 2 + exifCount * 12 + 4;

  const dtoLen = writeStr(cursor, dt);
  setIfdEntry(exifIfdOffset, 0, 0x9003, 2, dtoLen, cursor);
  cursor += dtoLen;

  const dtdLen = writeStr(cursor, dt);
  setIfdEntry(exifIfdOffset, 1, 0x9004, 2, dtdLen, cursor);
  cursor += dtdLen;

  if (cursor % 2 !== 0) cursor++;
  // FNumber f/1.8 (18/10)
  v.setUint32(cursor, 18, false);
  v.setUint32(cursor + 4, 10, false);
  setIfdEntry(exifIfdOffset, 2, 0x829d, 5, 1, cursor);
  cursor += 8;

  // ISO 100 (inline SHORT in 4-byte slot: high 2 bytes = 100 << 16 in big-endian)
  setIfdEntry(exifIfdOffset, 3, 0x8827, 3, 1, 100 << 16);

  // GPS IFD: 6 entries (LatRef, Lat, LonRef, Lon, Alt, DateStamp)
  const gpsIfdOffset = cursor;
  setIfdEntry(ifd0Offset, 5, 0x8825, 4, 1, gpsIfdOffset);
  const gpsCount = 6;
  v.setUint16(gpsIfdOffset, gpsCount, false);
  cursor = gpsIfdOffset + 2 + gpsCount * 12 + 4;

  const latRefChar = (lat >= 0 ? 'N' : 'S').charCodeAt(0);
  setIfdEntry(gpsIfdOffset, 0, 0x0001, 2, 2, latRefChar << 24);

  const latRats = toDmsRationals(lat);
  setIfdEntry(gpsIfdOffset, 1, 0x0002, 5, 3, cursor);
  for (const [n, d] of latRats) {
    v.setUint32(cursor, n, false);
    v.setUint32(cursor + 4, d, false);
    cursor += 8;
  }

  const lonRefChar = (lon >= 0 ? 'E' : 'W').charCodeAt(0);
  setIfdEntry(gpsIfdOffset, 2, 0x0003, 2, 2, lonRefChar << 24);

  const lonRats = toDmsRationals(lon);
  setIfdEntry(gpsIfdOffset, 3, 0x0004, 5, 3, cursor);
  for (const [n, d] of lonRats) {
    v.setUint32(cursor, n, false);
    v.setUint32(cursor + 4, d, false);
    cursor += 8;
  }

  // Altitude rational
  v.setUint32(cursor, Math.round(alt * 10), false);
  v.setUint32(cursor + 4, 10, false);
  setIfdEntry(gpsIfdOffset, 4, 0x0006, 5, 1, cursor);
  cursor += 8;

  const gpsDateLen = writeStr(cursor, dt.split(' ')[0]);
  setIfdEntry(gpsIfdOffset, 5, 0x001d, 2, gpsDateLen, cursor);
  cursor += gpsDateLen;

  const tiffBytes = u8.slice(0, cursor);
  const app1DataLen = 2 + 6 + tiffBytes.length; // length field + "Exif\0\0" + TIFF
  const app1Segment = new Uint8Array(2 + app1DataLen);
  const av = new DataView(app1Segment.buffer);
  av.setUint16(0, 0xffe1, false);
  av.setUint16(2, app1DataLen, false);
  av.setUint32(4, 0x45786966, false); // "Exif"
  av.setUint16(8, 0x0000, false);
  app1Segment.set(tiffBytes, 10);

  // Inject right after SOI (FF D8) of the canvas JPEG
  if (jpegBytes.length >= 2 && jpegBytes[0] === 0xff && jpegBytes[1] === 0xd8) {
    const out = new Uint8Array(2 + app1Segment.length + (jpegBytes.length - 2));
    out.set(jpegBytes.slice(0, 2), 0);
    out.set(app1Segment, 2);
    out.set(jpegBytes.slice(2), 2 + app1Segment.length);
    return out.buffer;
  }

  return jpegBytes.slice().buffer;
}

export async function computeCustodyBlockHash(
  prevHash: string,
  evidenceId: string,
  action: string,
  location: string,
  timestamp: string,
  userId: string,
  officerName: string
): Promise<string> {
  const payload = `${prevHash}|${evidenceId}|${action}|${location}|${timestamp}|${userId}|${officerName}`;
  const enc = new TextEncoder();
  const hashBuf = await crypto.subtle.digest('SHA-256', enc.encode(payload));
  return bufferToHex(hashBuf);
}

export async function verifyCustodyChainAsync(
  history: ChainOfCustodyRecord[]
): Promise<ChainVerificationResult> {
  if (!history || history.length === 0) {
    return { verified: true, count: 0, status: 'empty' };
  }

  const sorted = [...history].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  for (let i = 0; i < sorted.length; i++) {
    const current = sorted[i];
    const expectedPrevHash = i === 0 ? MAGIC_GENESIS_HASH : sorted[i - 1].recordHash || '';

    if (i === 0) {
      if (current.prevHash && current.prevHash !== MAGIC_GENESIS_HASH) {
        return {
          verified: false,
          count: sorted.length,
          status: 'tampered',
          brokenAtIndex: 0,
          reason: 'كتلة البداية (Genesis Block) لا تبدأ ببصمة التأسيس الصفرية القياسية',
        };
      }
    } else {
      if (!current.prevHash || current.prevHash !== expectedPrevHash) {
        return {
          verified: false,
          count: sorted.length,
          status: 'tampered',
          brokenAtIndex: i,
          reason: `انقطاع في الربط التشفيري بين الكتلة #${i} والكتلة #${i + 1}`,
        };
      }
    }

    // Recompute cryptographic SHA-256 block digest from actual stored fields
    if (current.recordHash) {
      const recomputed = await computeCustodyBlockHash(
        current.prevHash || expectedPrevHash,
        current.evidenceId,
        current.action,
        current.location,
        current.timestamp,
        current.userId,
        current.officerName || 'كبير المحققين السياديين'
      );

      if (recomputed !== current.recordHash) {
        return {
          verified: false,
          count: sorted.length,
          status: 'tampered',
          brokenAtIndex: i,
          reason: `فشل التحقق التشفيري SHA-256 للكتلة #${i + 1}: تم تعديل بيانات الحدث بعد التوثيق`,
        };
      }
    }
  }

  return { verified: true, count: sorted.length, status: 'valid' };
}

function refangLogText(raw: string): string {
  return raw
    .replace(/hxxps?:\/\//gi, (m) => (m.toLowerCase().startsWith('hxxps') ? 'https://' : 'http://'))
    .replace(/\[\.\]/g, '.')
    .replace(/\(dot\)/gi, '.')
    .replace(/\[:\]/g, ':');
}

export function extractIoCsFromLogs(rawInput: string): {
  iocs: ExtractedIoCRecord[];
  stats: IoCStatsSummary;
} {
  const normalizedText = refangLogText(rawInput);
  const lines = normalizedText.split(/\r?\n/);

  interface Accumulator {
    item: Omit<ExtractedIoCRecord, 'occurrences' | 'lines'>;
    occurrences: number;
    lineSet: Set<number>;
  }

  const map = new Map<string, Accumulator>();
  const sha256Set = new Set<string>();
  const sha1Set = new Set<string>();

  const registerMatch = (
    type: IoCType,
    value: string,
    details: string,
    severity: ExtractedIoCRecord['severity'],
    lineNum: number,
    isPrivateIp?: boolean
  ) => {
    const key = `${type}:${value.toLowerCase()}`;
    const existing = map.get(key);
    if (existing) {
      existing.occurrences += 1;
      existing.lineSet.add(lineNum);
    } else {
      map.set(key, {
        item: {
          id: `ioc-${type}-${map.size + 1}`,
          type,
          value,
          details,
          severity,
          ...(typeof isPrivateIp === 'boolean' ? { isPrivateIp } : {}),
        },
        occurrences: 1,
        lineSet: new Set([lineNum]),
      });
    }
  };

  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    if (!line.trim()) return;

    let m: RegExpExecArray | null;

    // 1. IPv4
    const ipv4Re = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
    while ((m = ipv4Re.exec(line)) !== null) {
      const ip = m[0];
      const p = ip.split('.').map(Number);
      const isPrivate =
        p[0] === 10 ||
        (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
        (p[0] === 192 && p[1] === 168) ||
        p[0] === 127 ||
        p[0] === 0;
      const isMetadata = ip === '169.254.169.254';
      registerMatch(
        'ipv4',
        ip,
        isMetadata
          ? 'عنوان Cloud Metadata (مؤشر SSRF حرج)'
          : isPrivate
          ? 'عنوان شبكة محلية داخلية (RFC1918 Private / Loopback)'
          : 'عنوان إنترنت خارجي عام (Public Routable IPv4)',
        isMetadata ? 'critical' : isPrivate ? 'info' : 'medium',
        lineNum,
        isPrivate
      );
    }

    // 2. IPv6
    const ipv6Re = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b/g;
    while ((m = ipv6Re.exec(line)) !== null) {
      registerMatch('ipv6', m[0], 'عنوان بروتوكول IPv6', 'medium', lineNum);
    }

    // 3. URLs (HTTP/HTTPS/FTP/LDAP/RMI/DNS)
    const urlRe = /(?:https?|ftp|ldap|ldaps|rmi):\/\/[^\s"'<>`]+/gi;
    while ((m = urlRe.exec(line)) !== null) {
      const cleanUrl = m[0].replace(/[.,;)\]]+$/, '');
      const isJndi = /^(?:ldap|ldaps|rmi):\/\//i.test(cleanUrl);
      registerMatch(
        'url',
        cleanUrl,
        isJndi ? 'رابط استغلال خادم خبيث (LDAP/RMI Payload Endpoint)' : 'رابط اتصال خارجي مستخرج من السجلات',
        isJndi ? 'critical' : 'high',
        lineNum
      );
    }

    // 4. Emails
    const emailRe = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
    while ((m = emailRe.exec(line)) !== null) {
      registerMatch('email', m[0].toLowerCase(), 'عنوان بريد إلكتروني مرصود في السجل', 'medium', lineNum);
    }

    // 5. Domains (FQDN)
    const domainRe = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|io|co|ai|xyz|ru|cn|ir|top|cc|info|biz|me|live|pro|onion|cloud|app|dev|uk|de|fr|sa|ae|eg|jo|qa|kw|bh|om|su|tk|pw|club|online|site|tech|shop|store|vip|click|link|lat|cfd|sbs|icu|eu|ca|au|jp|br|in|us|nl|ch|se|pl|ua|tr|tv|ws|sh|gg|to|ly)\b/gi;
    while ((m = domainRe.exec(line)) !== null) {
      const dom = m[0].toLowerCase();
      if (/\.(png|jpg|jpeg|gif|css|js|svg|woff2?)$/.test(dom)) continue;
      registerMatch(
        'domain',
        dom,
        dom.endsWith('.onion')
          ? 'نطاق شبكة مظلمة (Tor Hidden Service)'
          : 'اسم نطاق مؤهل بالكامل (FQDN)',
        dom.endsWith('.onion') || dom.endsWith('.ru') || dom.endsWith('.top') || dom.endsWith('.tk')
          ? 'high'
          : 'medium',
        lineNum
      );
    }

    // 6. CVEs
    const cveRe = /\bCVE-\d{4}-\d{4,7}\b/gi;
    while ((m = cveRe.exec(line)) !== null) {
      registerMatch(
        'cve',
        m[0].toUpperCase(),
        'معرّف ثغرة أمنية مسجلة (CVE Identifier)',
        'critical',
        lineNum
      );
    }

    // 7. Cryptographic Hashes (SHA-256 -> SHA-1 -> MD5)
    const sha256Re = /\b[a-fA-F0-9]{64}\b/g;
    while ((m = sha256Re.exec(line)) !== null) {
      const h = m[0].toLowerCase();
      sha256Set.add(h);
      registerMatch('sha256', h, 'بصمة SHA-256 لملف أو حمولة تنفيذية', 'high', lineNum);
    }

    const sha1Re = /\b[a-fA-F0-9]{40}\b/g;
    while ((m = sha1Re.exec(line)) !== null) {
      const h = m[0].toLowerCase();
      const isSubstringOfSha256 = Array.from(sha256Set).some((s) => s.includes(h));
      if (!isSubstringOfSha256) {
        sha1Set.add(h);
        registerMatch('sha1', h, 'بصمة SHA-1', 'medium', lineNum);
      }
    }

    const md5Re = /\b[a-fA-F0-9]{32}\b/g;
    while ((m = md5Re.exec(line)) !== null) {
      const h = m[0].toLowerCase();
      const isSubstring =
        Array.from(sha256Set).some((s) => s.includes(h)) ||
        Array.from(sha1Set).some((s) => s.includes(h));
      if (!isSubstring) {
        registerMatch('md5', h, 'بصمة MD5 لملف أو جلسة', 'medium', lineNum);
      }
    }

    // 8. Exploit & Attack Signatures
    const exploitMatchers: Array<{ re: RegExp; details: string; severity: 'critical' | 'high' }> = [
      {
        re: /(?:\b(?:union\s+(?:all\s+)?select|select\s+.+?\s+from|information_schema|waitfor\s+delay|sleep\(\d+\)|pg_sleep\(\d+\))\b|(?:'|"|;)\s*(?:or|and)\s*(?:'|")?\d+(?:'|")?\s*=\s*(?:'|")?\d+)/gi,
        details: 'نمط حقن قواعد البيانات (SQL Injection Payload)',
        severity: 'critical',
      },
      {
        re: /(?:\.\.\/|\.\.\\|\/etc\/(?:passwd|shadow|hosts)|\/proc\/self|c:[\\/]windows[\\/]win\.ini)/gi,
        details: 'محاولة اجتياز المسارات وقراءة ملفات النظام (Path Traversal / LFI)',
        severity: 'critical',
      },
      {
        re: /(?:;\s*(?:cat|whoami|id|uname|curl|wget|nc|ncat|bash|sh|powershell|cmd\.exe)\b|\$\{jndi:(?:ldap|ldaps|rmi|dns):)/gi,
        details: 'محاولة تنفيذ أوامر عن بُعد (RCE / Command Injection / JNDI)',
        severity: 'critical',
      },
      {
        re: /(?:powershell(?:\.exe)?\s+[^\r\n]*-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}|certutil(?:\.exe)?\s+[^\r\n]*-urlcache)/gi,
        details: 'أمر استغلال وتنزيل برمجيات ضارة (LOLBins / Encoded PowerShell)',
        severity: 'critical',
      },
      {
        re: /(?:eval\(base64_decode|c99shell|r57shell|passthru\(|shell_exec\(|system\()/gi,
        details: 'مؤشر برمجية تحكم خلفية (WebShell / Backdoor)',
        severity: 'critical',
      },
      {
        re: /(?:<script\b[^>]*>|javascript:|onerror\s*=|onload\s*=)/gi,
        details: 'محاولة حقن سكربت عبر المواقع (XSS Payload)',
        severity: 'high',
      },
    ];

    for (const matcher of exploitMatchers) {
      while ((m = matcher.re.exec(line)) !== null) {
        registerMatch('exploit', m[0].trim(), matcher.details, matcher.severity, lineNum);
      }
    }

    // 9. System Artifacts (Registry Persistence, Dropper Paths, MAC Addresses, JWT Tokens)
    const artifactRe = /(?:(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s"'<>]+|[A-Za-z]:\\(?:Users\\Public|Windows\\Temp|ProgramData)\\[^\s"'<>]+\.(?:exe|dll|ps1|bat|vbs|bin))/gi;
    while ((m = artifactRe.exec(line)) !== null) {
      registerMatch(
        'artifact',
        m[0],
        'أثر نظام مشبوه (Registry Persistence / Dropper Path)',
        'high',
        lineNum
      );
    }

    const macRe = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
    while ((m = macRe.exec(line)) !== null) {
      registerMatch(
        'artifact',
        m[0].toUpperCase(),
        'عنوان عتاد الشبكة (MAC Address)',
        'info',
        lineNum
      );
    }

    const jwtRe = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
    while ((m = jwtRe.exec(line)) !== null) {
      registerMatch(
        'artifact',
        m[0],
        'رمز مصادقة مسرب في السجل (Exposed JWT Session Token)',
        'high',
        lineNum
      );
    }
  });

  const severityRank: Record<ExtractedIoCRecord['severity'], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    info: 3,
  };

  const iocs: ExtractedIoCRecord[] = Array.from(map.values())
    .map(({ item, occurrences, lineSet }) => ({
      ...item,
      occurrences,
      lines: Array.from(lineSet).sort((a, b) => a - b),
    }))
    .sort((a, b) => severityRank[a.severity] - severityRank[b.severity]);

  const stats: IoCStatsSummary = {
    total: iocs.length,
    critical: iocs.filter((i) => i.severity === 'critical').length,
    high: iocs.filter((i) => i.severity === 'high').length,
    ipv4: iocs.filter((i) => i.type === 'ipv4').length,
    ipv6: iocs.filter((i) => i.type === 'ipv6').length,
    domain: iocs.filter((i) => i.type === 'domain').length,
    url: iocs.filter((i) => i.type === 'url').length,
    email: iocs.filter((i) => i.type === 'email').length,
    hash: iocs.filter((i) => i.type === 'sha256' || i.type === 'sha1' || i.type === 'md5').length,
    cve: iocs.filter((i) => i.type === 'cve').length,
    exploit: iocs.filter((i) => i.type === 'exploit').length,
    artifact: iocs.filter((i) => i.type === 'artifact').length,
  };

  return { iocs, stats };
}

export interface ElaHotspotRegion {
  col: number;
  row: number;
  xPct: number;
  yPct: number;
  wPct: number;
  hPct: number;
  meanError: number;
  zScore: number;
}

export interface ElaAnalysisResult {
  rgbDataUrl: string;
  heatmapDataUrl: string;
  grayscaleDataUrl: string;
  width: number;
  height: number;
  jpegQuality: number;
  amplification: number;
  meanError: number;
  peakError: number;
  stdDevError: number;
  elaTamperScore: number;
  suspiciousBlocksCount: number;
  totalBlocks: number;
  hotspots: ElaHotspotRegion[];
  verdictSummary: string;
}

function jetThermalColor(t: number): [number, number, number] {
  const v = Math.max(0, Math.min(1, t));
  if (v < 0.08) {
    // Deep forensic navy/black background for zero-diff areas
    const k = v / 0.08;
    return [Math.round(8 * k), Math.round(14 * k), Math.round(45 * k)];
  }
  if (v < 0.35) {
    const k = (v - 0.08) / 0.27;
    return [0, Math.round(180 * k), Math.round(130 + 125 * k)];
  }
  if (v < 0.65) {
    const k = (v - 0.35) / 0.3;
    return [Math.round(255 * k), Math.round(180 + 75 * (1 - Math.abs(k - 0.3))), Math.round(255 * (1 - k))];
  }
  const k = (v - 0.65) / 0.35;
  return [255, Math.round(230 * (1 - k)), Math.round(30 * (1 - k))];
}

export function runCanvasElaAnalysis(
  imgElement: HTMLImageElement,
  amplification: number = 30,
  jpegQuality: number = 0.75
): Promise<ElaAnalysisResult> {
  const amp = Math.max(5, Math.min(100, amplification));
  const qual = Math.max(0.3, Math.min(0.95, jpegQuality));

  const fallbackResult: ElaAnalysisResult = {
    rgbDataUrl: imgElement.src,
    heatmapDataUrl: imgElement.src,
    grayscaleDataUrl: imgElement.src,
    width: imgElement.naturalWidth || imgElement.width || 300,
    height: imgElement.naturalHeight || imgElement.height || 300,
    jpegQuality: qual,
    amplification: amp,
    meanError: 0,
    peakError: 0,
    stdDevError: 0,
    elaTamperScore: 0,
    suspiciousBlocksCount: 0,
    totalBlocks: 0,
    hotspots: [],
    verdictSummary: 'تعذر الوصول لوحدات البكسل عبر Canvas (قيود مصدر الصورة).',
  };

  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(fallbackResult), 4000);
    try {
      const maxDim = 760;
      let width = imgElement.naturalWidth || imgElement.width || 300;
      let height = imgElement.naturalHeight || imgElement.height || 300;
      if (width > maxDim || height > maxDim) {
        if (width > height) {
          height = Math.round((height * maxDim) / width);
          width = maxDim;
        } else {
          width = Math.round((width * maxDim) / height);
          height = maxDim;
        }
      }
      width = Math.max(32, width);
      height = Math.max(32, height);

      const baseCanvas = document.createElement('canvas');
      baseCanvas.width = width;
      baseCanvas.height = height;
      const baseCtx = baseCanvas.getContext('2d', { willReadFrequently: true });
      if (!baseCtx) {
        clearTimeout(timer);
        resolve(fallbackResult);
        return;
      }

      baseCtx.drawImage(imgElement, 0, 0, width, height);
      const originalData = baseCtx.getImageData(0, 0, width, height);
      const recompressedUrl = baseCanvas.toDataURL('image/jpeg', qual);

      const recompImg = new Image();
      recompImg.onload = () => {
        clearTimeout(timer);
        try {
          const recompCanvas = document.createElement('canvas');
          recompCanvas.width = width;
          recompCanvas.height = height;
          const recompCtx = recompCanvas.getContext('2d', { willReadFrequently: true });
          if (!recompCtx) {
            resolve(fallbackResult);
            return;
          }
          recompCtx.drawImage(recompImg, 0, 0, width, height);
          const recompData = recompCtx.getImageData(0, 0, width, height);

          const oBytes = originalData.data;
          const cBytes = recompData.data;
          const pixelCount = width * height;
          const lumDiffs = new Float32Array(pixelCount);

          const rgbImage = baseCtx.createImageData(width, height);
          const heatImage = baseCtx.createImageData(width, height);
          const grayImage = baseCtx.createImageData(width, height);

          let sumErr = 0;
          let maxErr = 0;

          for (let p = 0; p < pixelCount; p++) {
            const idx = p * 4;
            const dr = Math.abs(oBytes[idx] - cBytes[idx]);
            const dg = Math.abs(oBytes[idx + 1] - cBytes[idx + 1]);
            const db = Math.abs(oBytes[idx + 2] - cBytes[idx + 2]);
            const err = (dr + dg + db) / 3;

            lumDiffs[p] = err;
            sumErr += err;
            if (err > maxErr) maxErr = err;

            const rAmp = Math.min(255, Math.round(dr * amp));
            const gAmp = Math.min(255, Math.round(dg * amp));
            const bAmp = Math.min(255, Math.round(db * amp));

            rgbImage.data[idx] = rAmp;
            rgbImage.data[idx + 1] = gAmp;
            rgbImage.data[idx + 2] = bAmp;
            rgbImage.data[idx + 3] = 255;

            const grayVal = Math.min(255, Math.round(err * amp));
            grayImage.data[idx] = grayVal;
            grayImage.data[idx + 1] = grayVal;
            grayImage.data[idx + 2] = grayVal;
            grayImage.data[idx + 3] = 255;

            const [hr, hg, hb] = jetThermalColor(Math.min(1, (err * amp) / 255));
            heatImage.data[idx] = hr;
            heatImage.data[idx + 1] = hg;
            heatImage.data[idx + 2] = hb;
            heatImage.data[idx + 3] = 255;
          }

          const meanErr = sumErr / pixelCount;
          let sqSum = 0;
          for (let p = 0; p < pixelCount; p++) {
            const d = lumDiffs[p] - meanErr;
            sqSum += d * d;
          }
          const stdDevErr = Math.sqrt(sqSum / pixelCount);

          // Grid Block Anomaly Analysis (16x16 grid on Canvas)
          const gridCols = 16;
          const gridRows = 16;
          const blockErrors: Array<{ col: number; row: number; mean: number }> = [];

          for (let row = 0; row < gridRows; row++) {
            const y0 = Math.floor((row * height) / gridRows);
            const y1 = Math.floor(((row + 1) * height) / gridRows);
            for (let col = 0; col < gridCols; col++) {
              const x0 = Math.floor((col * width) / gridCols);
              const x1 = Math.floor(((col + 1) * width) / gridCols);
              let bSum = 0;
              let bCount = 0;
              for (let y = y0; y < y1; y++) {
                for (let x = x0; x < x1; x++) {
                  bSum += lumDiffs[y * width + x];
                  bCount++;
                }
              }
              blockErrors.push({ col, row, mean: bCount > 0 ? bSum / bCount : 0 });
            }
          }

          const blockMeanAvg =
            blockErrors.reduce((acc, b) => acc + b.mean, 0) / Math.max(1, blockErrors.length);
          const blockStd = Math.sqrt(
            blockErrors.reduce((acc, b) => acc + Math.pow(b.mean - blockMeanAvg, 2), 0) /
              Math.max(1, blockErrors.length)
          );

          const hotspots: ElaHotspotRegion[] = [];
          for (const b of blockErrors) {
            const z = blockStd > 0.05 ? (b.mean - blockMeanAvg) / blockStd : 0;
            if (z >= 1.9 && b.mean >= 1.8) {
              hotspots.push({
                col: b.col,
                row: b.row,
                xPct: Number(((b.col / gridCols) * 100).toFixed(2)),
                yPct: Number(((b.row / gridRows) * 100).toFixed(2)),
                wPct: Number((100 / gridCols).toFixed(2)),
                hPct: Number((100 / gridRows).toFixed(2)),
                meanError: Number(b.mean.toFixed(2)),
                zScore: Number(z.toFixed(2)),
              });
            }
          }

          hotspots.sort((a, b) => b.zScore - a.zScore);

          // Render all 3 Canvas Data URLs
          const rgbCanvas = document.createElement('canvas');
          rgbCanvas.width = width;
          rgbCanvas.height = height;
          rgbCanvas.getContext('2d')!.putImageData(rgbImage, 0, 0);

          const heatCanvas = document.createElement('canvas');
          heatCanvas.width = width;
          heatCanvas.height = height;
          heatCanvas.getContext('2d')!.putImageData(heatImage, 0, 0);

          const grayCanvas = document.createElement('canvas');
          grayCanvas.width = width;
          grayCanvas.height = height;
          grayCanvas.getContext('2d')!.putImageData(grayImage, 0, 0);

          // Compute forensic ELA tamper likelihood from hotspot localization & variance disparity
          const hotspotRatio = hotspots.length / blockErrors.length;
          const peakZ = hotspots.length > 0 ? hotspots[0].zScore : 0;
          const rawScore = Math.round(
            Math.min(98, Math.max(4, hotspots.length * 4.5 + peakZ * 8 + (stdDevErr > 4 ? 12 : 0)))
          );
          const elaTamperScore =
            hotspots.length >= 2 && hotspotRatio <= 0.35
              ? Math.max(45, rawScore)
              : hotspots.length === 0
              ? Math.min(22, rawScore)
              : rawScore;

          let verdictSummary = 'توزيع خطأ الضغط متجانس عبر الكتل — لا توجد مؤشرات واضحة على لصق موضعي (Splicing).';
          if (elaTamperScore >= 65) {
            verdictSummary = `اشتباه تلاعب مرتفع: رصد ${hotspots.length} مناطق ذات تباين ضغطي شاذ (ذروة Z=${peakZ.toFixed(1)}) مما يرجح تعديلاً أو لصقاً موضعياً.`;
          } else if (elaTamperScore >= 38) {
            verdictSummary = `تباين ضغطي متوسط في ${hotspots.length} كتلة؛ يُنصح بمطابقة المناطق الساطعة في الخريطة الحرارية.`;
          }

          resolve({
            rgbDataUrl: rgbCanvas.toDataURL('image/png'),
            heatmapDataUrl: heatCanvas.toDataURL('image/png'),
            grayscaleDataUrl: grayCanvas.toDataURL('image/png'),
            width,
            height,
            jpegQuality: qual,
            amplification: amp,
            meanError: Number(meanErr.toFixed(2)),
            peakError: Number(maxErr.toFixed(2)),
            stdDevError: Number(stdDevErr.toFixed(2)),
            elaTamperScore,
            suspiciousBlocksCount: hotspots.length,
            totalBlocks: blockErrors.length,
            hotspots: hotspots.slice(0, 24),
            verdictSummary,
          });
        } catch {
          resolve(fallbackResult);
        }
      };
      recompImg.onerror = () => {
        clearTimeout(timer);
        resolve(fallbackResult);
      };
      recompImg.src = recompressedUrl;
    } catch {
      clearTimeout(timer);
      resolve(fallbackResult);
    }
  });
}
