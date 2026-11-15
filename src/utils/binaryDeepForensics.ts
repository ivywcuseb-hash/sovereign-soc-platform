export type BinaryFormatType = 'PE32' | 'PE32+' | 'ELF32' | 'ELF64' | 'Mach-O' | 'SQLite' | 'ZIP / Archive' | 'Text / Script' | 'Raw Binary';

export interface PeSectionInfo {
  name: string;
  virtualAddress: string;
  virtualSize: number;
  rawSize: number;
  entropy: number;
  isExecutable: boolean;
  isWritable: boolean;
  isReadable: boolean;
  isPackedAnomaly: boolean;
}

export interface PeHeaderDetails {
  machine: string;
  architecture: 'x64' | 'x86' | 'ARM64' | 'ARM' | 'Other';
  compileTimestampUtc: string;
  compileTimestampRaw: number;
  numberOfSections: number;
  subsystem: string;
  entryPointRva: string;
  imageBase: string;
  hasAslr: boolean;
  hasDepNx: boolean;
  hasCfg: boolean;
  sections: PeSectionInfo[];
  hasRwxSection: boolean;
  hasHighEntropySection: boolean;
}

export interface ElfHeaderDetails {
  elfClass: 'ELF32' | 'ELF64';
  endianness: 'Little Endian' | 'Big Endian';
  elfType: string;
  machine: string;
  entryPoint: string;
  programHeaderCount: number;
  sectionHeaderCount: number;
}

export interface ExtractedBinaryString {
  value: string;
  encoding: 'ASCII' | 'UTF-16LE';
  offsetHex: string;
  category: 'url' | 'ip' | 'dll_api' | 'registry_path' | 'command' | 'email' | 'general';
}

export interface SuspiciousApiMatch {
  api: string;
  category: 'Injection / Memory' | 'Network / C2' | 'Anti-Analysis / Evasion' | 'Crypto / Ransom' | 'Persistence / Registry' | 'Execution / Shell';
  severity: 'critical' | 'high' | 'medium';
}

export interface BinaryEntropyWindow {
  offsetStart: number;
  offsetEnd: number;
  entropy: number;
}

export interface BinaryDeepForensicsResult {
  fileName: string;
  fileSize: number;
  format: BinaryFormatType;
  magicDescription: string;
  headerHexDump: string[];
  overallEntropy: number;
  entropyClassification: string;
  entropyWindows: BinaryEntropyWindow[];
  peDetails: PeHeaderDetails | null;
  elfDetails: ElfHeaderDetails | null;
  detectedDlls: string[];
  suspiciousApis: SuspiciousApiMatch[];
  extractedUrls: string[];
  extractedIps: string[];
  registryAndPaths: string[];
  suspiciousStrings: ExtractedBinaryString[];
  sampleStrings: ExtractedBinaryString[];
  totalStringsCount: number;
  extractionTimestamp: string;
}

function computeBytesEntropy(bytes: Uint8Array): number {
  if (!bytes.length) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let ent = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / bytes.length;
      ent -= p * Math.log2(p);
    }
  }
  return Number(ent.toFixed(3));
}

function formatHexDumpLines(bytes: Uint8Array, maxBytes = 512): string[] {
  const len = Math.min(bytes.length, maxBytes);
  const lines: string[] = [];
  for (let offset = 0; offset < len; offset += 16) {
    const slice = bytes.subarray(offset, Math.min(offset + 16, len));
    const hexPart = Array.from(slice)
      .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
      .join(' ')
      .padEnd(47, ' ');
    const asciiPart = Array.from(slice)
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${offset.toString(16).padStart(8, '0').toUpperCase()}  ${hexPart}  |${asciiPart}|`);
  }
  return lines;
}

function parsePeHeaders(bytes: Uint8Array): PeHeaderDetails | null {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null; // 'MZ'
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const peOffset = view.getUint32(0x3c, true);
  if (peOffset < 0x40 || peOffset + 24 >= bytes.length) return null;

  // Check 'PE\0\0'
  if (
    bytes[peOffset] !== 0x50 ||
    bytes[peOffset + 1] !== 0x45 ||
    bytes[peOffset + 2] !== 0x00 ||
    bytes[peOffset + 3] !== 0x00
  ) {
    return null;
  }

  const coffOffset = peOffset + 4;
  const machineVal = view.getUint16(coffOffset, true);
  const numberOfSections = view.getUint16(coffOffset + 2, true);
  const timeDateStamp = view.getUint32(coffOffset + 4, true);
  const sizeOfOptionalHeader = view.getUint16(coffOffset + 16, true);

  let machine = `0x${machineVal.toString(16).toUpperCase()}`;
  let architecture: PeHeaderDetails['architecture'] = 'Other';
  if (machineVal === 0x8664) {
    machine = 'x64 (AMD64)';
    architecture = 'x64';
  } else if (machineVal === 0x014c) {
    machine = 'x86 (i386)';
    architecture = 'x86';
  } else if (machineVal === 0xaa64) {
    machine = 'ARM64 (AArch64)';
    architecture = 'ARM64';
  } else if (machineVal === 0x01c0 || machineVal === 0x01c4) {
    machine = 'ARM';
    architecture = 'ARM';
  }

  const compileTimestampUtc =
    timeDateStamp > 0 ? new Date(timeDateStamp * 1000).toISOString() : '1970-01-01T00:00:00.000Z (Zeroed)';

  const optOffset = coffOffset + 20;
  let subsystem = 'Unknown';
  let entryPointRva = '0x0';
  let imageBase = '0x0';
  let hasAslr = false;
  let hasDepNx = false;
  let hasCfg = false;

  if (optOffset + 2 <= bytes.length && sizeOfOptionalHeader >= 68) {
    const magic = view.getUint16(optOffset, true);
    const isPePlus = magic === 0x020b;
    if (optOffset + 20 <= bytes.length) {
      entryPointRva = '0x' + view.getUint32(optOffset + 16, true).toString(16).toUpperCase();
    }
    if (isPePlus && optOffset + 32 <= bytes.length) {
      const low = view.getUint32(optOffset + 24, true);
      const high = view.getUint32(optOffset + 28, true);
      imageBase = '0x' + (BigInt(high) * 0x100000000n + BigInt(low)).toString(16).toUpperCase();
    } else if (!isPePlus && optOffset + 32 <= bytes.length) {
      imageBase = '0x' + view.getUint32(optOffset + 28, true).toString(16).toUpperCase();
    }

    if (optOffset + 72 <= bytes.length) {
      const subVal = view.getUint16(optOffset + 68, true);
      const subMap: Record<number, string> = {
        1: 'Native / Kernel Driver',
        2: 'Windows GUI',
        3: 'Windows Console (CUI)',
        5: 'OS/2 Console',
        7: 'POSIX Console',
        9: 'Windows CE',
        10: 'EFI Application',
      };
      subsystem = subMap[subVal] || `Subsystem (${subVal})`;

      const dllChars = view.getUint16(optOffset + 70, true);
      hasAslr = (dllChars & 0x0040) !== 0;
      hasDepNx = (dllChars & 0x0100) !== 0;
      hasCfg = (dllChars & 0x4000) !== 0;
    }
  }

  const sections: PeSectionInfo[] = [];
  const secTableStart = optOffset + sizeOfOptionalHeader;
  const maxSecs = Math.min(numberOfSections, 64);

  for (let i = 0; i < maxSecs; i++) {
    const sOff = secTableStart + i * 40;
    if (sOff + 40 > bytes.length) break;

    let secName = '';
    for (let j = 0; j < 8; j++) {
      const ch = bytes[sOff + j];
      if (ch === 0) break;
      if (ch >= 0x20 && ch <= 0x7e) secName += String.fromCharCode(ch);
    }
    const virtualSize = view.getUint32(sOff + 8, true);
    const virtualAddress = '0x' + view.getUint32(sOff + 12, true).toString(16).toUpperCase();
    const rawSize = view.getUint32(sOff + 16, true);
    const rawPtr = view.getUint32(sOff + 20, true);
    const chars = view.getUint32(sOff + 36, true);

    const isExecutable = (chars & 0x20000000) !== 0;
    const isReadable = (chars & 0x40000000) !== 0;
    const isWritable = (chars & 0x80000000) !== 0;

    let secEntropy = 0;
    if (rawSize > 0 && rawPtr < bytes.length) {
      const end = Math.min(bytes.length, rawPtr + rawSize);
      secEntropy = computeBytesEntropy(bytes.subarray(rawPtr, end));
    }

    const isPackedAnomaly =
      secEntropy >= 7.0 ||
      (rawSize === 0 && virtualSize > 4096) ||
      (isExecutable && isWritable) ||
      /^(UPX|ASPack|\.vmp|\.themida|\.enigma)/i.test(secName);

    sections.push({
      name: secName || `SEC_${i}`,
      virtualAddress,
      virtualSize,
      rawSize,
      entropy: secEntropy,
      isExecutable,
      isWritable,
      isReadable,
      isPackedAnomaly,
    });
  }

  return {
    machine,
    architecture,
    compileTimestampUtc,
    compileTimestampRaw: timeDateStamp,
    numberOfSections,
    subsystem,
    entryPointRva,
    imageBase,
    hasAslr,
    hasDepNx,
    hasCfg,
    sections,
    hasRwxSection: sections.some((s) => s.isExecutable && s.isWritable),
    hasHighEntropySection: sections.some((s) => s.entropy >= 7.0),
  };
}

function parseElfHeaders(bytes: Uint8Array): ElfHeaderDetails | null {
  if (bytes.length < 52) return null;
  if (bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) return null;

  const is64 = bytes[4] === 2;
  const littleEndian = bytes[5] !== 2;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  const eTypeVal = view.getUint16(16, littleEndian);
  const eMachineVal = view.getUint16(18, littleEndian);

  const typeMap: Record<number, string> = {
    1: 'ET_REL (Relocatable)',
    2: 'ET_EXEC (Executable)',
    3: 'ET_DYN (Shared Object / PIE)',
    4: 'ET_CORE (Core Dump)',
  };
  const machMap: Record<number, string> = {
    0x03: 'x86 (EM_386)',
    0x28: 'ARM (EM_ARM)',
    0x3e: 'x86-64 (EM_X86_64)',
    0xb7: 'AArch64 (ARM64)',
    0xf3: 'RISC-V',
  };

  let entryPoint = '0x0';
  let programHeaderCount = 0;
  let sectionHeaderCount = 0;

  if (is64 && bytes.length >= 64) {
    const lo = view.getUint32(24, littleEndian);
    const hi = view.getUint32(28, littleEndian);
    entryPoint = '0x' + (BigInt(hi) * 0x100000000n + BigInt(lo)).toString(16).toUpperCase();
    programHeaderCount = view.getUint16(56, littleEndian);
    sectionHeaderCount = view.getUint16(60, littleEndian);
  } else {
    entryPoint = '0x' + view.getUint32(24, littleEndian).toString(16).toUpperCase();
    programHeaderCount = view.getUint16(44, littleEndian);
    sectionHeaderCount = view.getUint16(48, littleEndian);
  }

  return {
    elfClass: is64 ? 'ELF64' : 'ELF32',
    endianness: littleEndian ? 'Little Endian' : 'Big Endian',
    elfType: typeMap[eTypeVal] || `Type (${eTypeVal})`,
    machine: machMap[eMachineVal] || `Machine (0x${eMachineVal.toString(16)})`,
    entryPoint,
    programHeaderCount,
    sectionHeaderCount,
  };
}

function classifyExtractedString(val: string): ExtractedBinaryString['category'] {
  if (/^https?:\/\/[A-Za-z0-9.-]+/i.test(val)) return 'url';
  if (/^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(val)) return 'ip';
  if (/\.(dll|so|dylib)$/i.test(val)) return 'dll_api';
  if (/^(HKEY_|HKLM\\|HKCU\\|[A-Z]:\\|\/etc\/|\/tmp\/|\/dev\/shm)/i.test(val)) return 'registry_path';
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) return 'email';
  if (/(powershell|cmd\.exe|\/bin\/sh|wget |curl |Invoke-|schtasks|chmod \+x)/i.test(val)) return 'command';
  return 'general';
}

function extractBinaryStrings(bytes: Uint8Array, minLen = 5, maxTotal = 2500): {
  allStrings: ExtractedBinaryString[];
  asciiBlob: string;
} {
  const results: ExtractedBinaryString[] = [];
  const seen = new Set<string>();
  const scanLimit = Math.min(bytes.length, 3 * 1024 * 1024); // Cap at 3MB fast scan
  const asciiParts: string[] = [];

  // 1. ASCII printable sequences
  let start = -1;
  for (let i = 0; i <= scanLimit; i++) {
    const b = i < scanLimit ? bytes[i] : 0;
    const isPrintable = b >= 0x20 && b <= 0x7e;
    if (isPrintable) {
      if (start === -1) start = i;
    } else {
      if (start !== -1 && i - start >= minLen) {
        let s = '';
        const endIdx = Math.min(i, start + 300);
        for (let k = start; k < endIdx; k++) s += String.fromCharCode(bytes[k]);
        const trimmed = s.trim();
        if (trimmed.length >= minLen && !seen.has(trimmed)) {
          seen.add(trimmed);
          asciiParts.push(trimmed);
          if (results.length < maxTotal) {
            results.push({
              value: trimmed,
              encoding: 'ASCII',
              offsetHex: '0x' + start.toString(16).padStart(6, '0').toUpperCase(),
              category: classifyExtractedString(trimmed),
            });
          }
        }
      }
      start = -1;
    }
  }

  // 2. UTF-16LE wide strings (common in Windows PE binaries)
  let wStart = -1;
  let wBuf = '';
  for (let i = 0; i + 1 < scanLimit; i += 2) {
    const lo = bytes[i];
    const hi = bytes[i + 1];
    if (lo >= 0x20 && lo <= 0x7e && hi === 0x00) {
      if (wStart === -1) wStart = i;
      if (wBuf.length < 300) wBuf += String.fromCharCode(lo);
    } else {
      if (wStart !== -1 && wBuf.trim().length >= minLen) {
        const trimmed = wBuf.trim();
        if (!seen.has(trimmed)) {
          seen.add(trimmed);
          asciiParts.push(trimmed);
          if (results.length < maxTotal) {
            results.push({
              value: trimmed,
              encoding: 'UTF-16LE',
              offsetHex: '0x' + wStart.toString(16).padStart(6, '0').toUpperCase(),
              category: classifyExtractedString(trimmed),
            });
          }
        }
      }
      wStart = -1;
      wBuf = '';
    }
  }

  return { allStrings: results, asciiBlob: asciiParts.join('\n') };
}

const SUSPICIOUS_API_SIGNATURES: SuspiciousApiMatch[] = [
  { api: 'VirtualAllocEx', category: 'Injection / Memory', severity: 'critical' },
  { api: 'WriteProcessMemory', category: 'Injection / Memory', severity: 'critical' },
  { api: 'CreateRemoteThread', category: 'Injection / Memory', severity: 'critical' },
  { api: 'NtUnmapViewOfSection', category: 'Injection / Memory', severity: 'critical' },
  { api: 'QueueUserAPC', category: 'Injection / Memory', severity: 'critical' },
  { api: 'VirtualProtect', category: 'Injection / Memory', severity: 'high' },
  { api: 'SetWindowsHookEx', category: 'Anti-Analysis / Evasion', severity: 'critical' },
  { api: 'GetAsyncKeyState', category: 'Anti-Analysis / Evasion', severity: 'critical' },
  { api: 'IsDebuggerPresent', category: 'Anti-Analysis / Evasion', severity: 'high' },
  { api: 'CheckRemoteDebuggerPresent', category: 'Anti-Analysis / Evasion', severity: 'high' },
  { api: 'URLDownloadToFile', category: 'Network / C2', severity: 'critical' },
  { api: 'InternetOpen', category: 'Network / C2', severity: 'high' },
  { api: 'HttpSendRequest', category: 'Network / C2', severity: 'high' },
  { api: 'WSAStartup', category: 'Network / C2', severity: 'medium' },
  { api: 'CryptEncrypt', category: 'Crypto / Ransom', severity: 'critical' },
  { api: 'BCryptEncrypt', category: 'Crypto / Ransom', severity: 'high' },
  { api: 'RegSetValueEx', category: 'Persistence / Registry', severity: 'high' },
  { api: 'CreateService', category: 'Persistence / Registry', severity: 'high' },
  { api: 'WinExec', category: 'Execution / Shell', severity: 'critical' },
  { api: 'ShellExecute', category: 'Execution / Shell', severity: 'high' },
  { api: 'CreateProcess', category: 'Execution / Shell', severity: 'medium' },
  { api: 'ptrace', category: 'Anti-Analysis / Evasion', severity: 'high' },
  { api: 'execve', category: 'Execution / Shell', severity: 'high' },
  { api: 'mprotect', category: 'Injection / Memory', severity: 'high' },
  { api: 'LD_PRELOAD', category: 'Persistence / Registry', severity: 'critical' },
];

export function parseHexTextToBytes(hexText: string): Uint8Array | null {
  const cleaned = hexText.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
  if (cleaned.length < 4 || cleaned.length % 2 !== 0) return null;
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function analyzeBinaryDeeply(buffer: ArrayBuffer, fileName: string): BinaryDeepForensicsResult {
  const bytes = new Uint8Array(buffer);
  const overallEntropy = computeBytesEntropy(bytes);
  const entropyClassification =
    overallEntropy >= 7.2
      ? 'تشفير أو ضغط مرتفع جداً (Packed / Encrypted Payload Likely)'
      : overallEntropy >= 6.0
      ? 'كثافة ثنائية مرتفعة (Compiled Binary / Compressed Data)'
      : 'كثافة قياسية (Standard Executable / Clear Text)';

  const peDetails = parsePeHeaders(bytes);
  const elfDetails = !peDetails ? parseElfHeaders(bytes) : null;

  let format: BinaryFormatType = 'Raw Binary';
  let magicDescription = 'Unknown Binary Stream';

  if (peDetails) {
    format = peDetails.architecture === 'x64' || peDetails.architecture === 'ARM64' ? 'PE32+' : 'PE32';
    magicDescription = `Windows Portable Executable (${peDetails.machine} • ${peDetails.subsystem})`;
  } else if (elfDetails) {
    format = elfDetails.elfClass;
    magicDescription = `Linux / Unix Executable (${elfDetails.elfClass} • ${elfDetails.machine})`;
  } else if (
    bytes.length >= 4 &&
    ((bytes[0] === 0xfe && bytes[1] === 0xed && bytes[2] === 0xfa && (bytes[3] === 0xce || bytes[3] === 0xcf)) ||
      (bytes[0] === 0xcf && bytes[1] === 0xfa && bytes[2] === 0xed && bytes[3] === 0xfe) ||
      (bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe))
  ) {
    format = 'Mach-O';
    magicDescription = 'macOS Mach-O / Universal Binary';
  } else if (bytes.length >= 16 && new TextDecoder().decode(bytes.subarray(0, 15)) === 'SQLite format 3') {
    format = 'SQLite';
    magicDescription = 'SQLite Format 3 Database File';
  } else if (bytes.length >= 2 && bytes[0] === 0x50 && bytes[1] === 0x4b) {
    format = 'ZIP / Archive';
    magicDescription = 'ZIP / APK / DOCX Archive Container (PK\\x03\\x04)';
  } else {
    // Check if mostly UTF-8 printable text
    const sample = bytes.subarray(0, Math.min(bytes.length, 1024));
    let printable = 0;
    for (let i = 0; i < sample.length; i++) {
      if ((sample[i] >= 0x20 && sample[i] <= 0x7e) || sample[i] === 9 || sample[i] === 10 || sample[i] === 13) {
        printable++;
      }
    }
    if (sample.length > 0 && printable / sample.length > 0.85) {
      format = 'Text / Script';
      magicDescription = 'Structured Text / Script Artifact';
    }
  }

  // Sliding-window entropy map (up to 16 equal slices)
  const entropyWindows: BinaryEntropyWindow[] = [];
  if (bytes.length > 0) {
    const slices = Math.min(16, Math.max(1, Math.ceil(bytes.length / 256)));
    const chunkSize = Math.ceil(bytes.length / slices);
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const end = Math.min(bytes.length, i + chunkSize);
      entropyWindows.push({
        offsetStart: i,
        offsetEnd: end,
        entropy: computeBytesEntropy(bytes.subarray(i, end)),
      });
    }
  }

  // Deep Strings & Artifact Extraction
  const { allStrings, asciiBlob } = extractBinaryStrings(bytes, 5, 2500);

  const dllSet = new Set<string>();
  const urlSet = new Set<string>();
  const ipSet = new Set<string>();
  const pathSet = new Set<string>();

  const dllMatches = asciiBlob.match(/\b[A-Za-z0-9_-]{2,40}\.(?:dll|so(?:\.\d+)?|dylib)\b/gi) || [];
  for (const d of dllMatches) dllSet.add(d);

  const urlMatches = asciiBlob.match(/https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g) || [];
  for (const u of urlMatches) {
    const clean = u.replace(/[.,;:'")\]}>]+$/, '');
    if (clean.length >= 10) urlSet.add(clean);
  }

  const ipMatches =
    asciiBlob.match(/(?<![.\d])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![.\d])/g) || [];
  for (const ip of ipMatches) {
    if (ip !== '0.0.0.0' && ip !== '255.255.255.255') ipSet.add(ip);
  }

  const regMatches =
    asciiBlob.match(/(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s"']{3,160}/gi) || [];
  for (const r of regMatches) pathSet.add(r);

  const pathMatches =
    asciiBlob.match(/(?:[A-Z]:\\(?:Users|Windows|Temp|ProgramData|AppData)[^\s"']{2,160}|\/(?:tmp|etc|var\/tmp|dev\/shm)\/[^\s"']{2,160})/gi) ||
    [];
  for (const p of pathMatches) pathSet.add(p);

  const suspiciousApis: SuspiciousApiMatch[] = [];
  for (const sig of SUSPICIOUS_API_SIGNATURES) {
    const re = new RegExp(`\\b${sig.api}\\b`, 'i');
    if (re.test(asciiBlob)) {
      suspiciousApis.push(sig);
    }
  }

  const suspiciousStrings = allStrings.filter((s) => s.category !== 'general').slice(0, 150);

  return {
    fileName,
    fileSize: bytes.length,
    format,
    magicDescription,
    headerHexDump: formatHexDumpLines(bytes, 512),
    overallEntropy,
    entropyClassification,
    entropyWindows,
    peDetails,
    elfDetails,
    detectedDlls: Array.from(dllSet).slice(0, 50),
    suspiciousApis,
    extractedUrls: Array.from(urlSet).slice(0, 50),
    extractedIps: Array.from(ipSet).slice(0, 40),
    registryAndPaths: Array.from(pathSet).slice(0, 60),
    suspiciousStrings,
    sampleStrings: allStrings.slice(0, 200),
    totalStringsCount: allStrings.length,
    extractionTimestamp: new Date().toISOString(),
  };
}
