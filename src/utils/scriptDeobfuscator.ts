export type ScriptLanguage =
  | 'PowerShell'
  | 'JavaScript / JScript'
  | 'Python'
  | 'VBScript / WSH'
  | 'Bash / Shell'
  | 'Batch (CMD)'
  | 'Unknown Script';

export interface DeobfuscationLayer {
  layerIndex: number;
  technique: string;
  description: string;
  inputPreview: string;
  decodedPreview: string;
  decodedFull: string;
}

export interface ExtractedScriptCommand {
  command: string;
  category: 'Execution' | 'Download / C2' | 'Persistence' | 'Defense Evasion' | 'Discovery / Exfil';
  severity: 'critical' | 'high' | 'medium';
  foundInLayer: number; // 0 = original, >=1 = decoded layer
  context: string;
}

export interface ExtractedScriptUrl {
  url: string;
  domain: string;
  foundInLayer: number;
  isObfuscatedSource: boolean;
}

export interface ExtractedScriptIp {
  ip: string;
  isPrivate: boolean;
  foundInLayer: number;
}

export interface ScriptDeobfuscationResult {
  fileName: string;
  fileSize: number;
  language: ScriptLanguage;
  lineCount: number;
  originalCode: string;
  finalDeobfuscatedCode: string;
  layersCount: number;
  obfuscationTechniques: string[];
  layers: DeobfuscationLayer[];
  extractedUrls: ExtractedScriptUrl[];
  extractedIps: ExtractedScriptIp[];
  extractedCommands: ExtractedScriptCommand[];
  registryAndPaths: string[];
  entropy: number;
  extractionTimestamp: string;
}

export function detectScriptLanguage(fileName: string, code: string): ScriptLanguage {
  const lower = fileName.toLowerCase();
  if (/\.(ps1|psm1|psd1)$/i.test(lower)) return 'PowerShell';
  if (/\.(js|mjs|cjs|jse)$/i.test(lower)) return 'JavaScript / JScript';
  if (/\.pyw?$/i.test(lower)) return 'Python';
  if (/\.(vbs|vbe|wsf|hta)$/i.test(lower)) return 'VBScript / WSH';
  if (/\.(sh|bash|zsh)$/i.test(lower)) return 'Bash / Shell';
  if (/\.(bat|cmd)$/i.test(lower)) return 'Batch (CMD)';

  if (/(powershell|invoke-expression|frombase64string|-encodedcommand|\biex\b|\$[a-z_]+\s*=)/i.test(code)) {
    return 'PowerShell';
  }
  if (/(import\s+base64|def\s+[a-z0-9_]+\s*\(|zlib\.decompress|__import__|exec\()/i.test(code)) {
    return 'Python';
  }
  if (/(String\.fromCharCode|atob\(|document\.write|WScript\.|ActiveXObject|require\(['"]child_process)/i.test(code)) {
    return 'JavaScript / JScript';
  }
  if (/(CreateObject\(|ExecuteGlobal|ChrW?\(|Dim\s+[a-z])/i.test(code)) {
    return 'VBScript / WSH';
  }
  if (/(^#!\/bin\/(ba)?sh|\bcurl\s+-|\bwget\s+|\bchmod\s+\+x)/im.test(code)) {
    return 'Bash / Shell';
  }
  if (/(@echo\s+off|cmd\.exe\s+\/c|certutil\s+-urlcache)/i.test(code)) {
    return 'Batch (CMD)';
  }
  return 'Unknown Script';
}

function calculateTextEntropy(text: string): number {
  if (!text.length) return 0;
  const bytes = new TextEncoder().encode(text);
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

function decodeBase64ToBytes(b64: string): Uint8Array | null {
  try {
    const clean = b64.replace(/\s+/g, '');
    if (clean.length < 12 || !/^[A-Za-z0-9+/=_-]+$/.test(clean)) return null;
    const normalized = clean.replace(/-/g, '+').replace(/_/g, '/');
    const pad = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    const binStr = atob(normalized + pad);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
      bytes[i] = binStr.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

function bytesToBestReadableString(bytes: Uint8Array): string | null {
  if (!bytes || bytes.length === 0) return null;

  // Detect UTF-16LE (common in PowerShell -EncodedCommand where every odd byte is 0x00)
  let zeroOdd = 0;
  const samplePairs = Math.min(bytes.length, 64);
  for (let i = 1; i < samplePairs; i += 2) {
    if (bytes[i] === 0) zeroOdd++;
  }
  let text = '';
  if (bytes.length >= 4 && bytes.length % 2 === 0 && zeroOdd >= Math.floor(samplePairs / 4)) {
    text = new TextDecoder('utf-16le', { fatal: false }).decode(bytes);
  } else {
    text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  // Check printability ratio
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if ((code >= 0x20 && code <= 0x7e) || code === 9 || code === 10 || code === 13 || code >= 0x80) {
      printable++;
    }
  }
  if (printable / Math.max(1, text.length) < 0.72) return null;
  return text.replace(/\0/g, '').trim();
}

async function tryDecompressStream(bytes: Uint8Array): Promise<string | null> {
  if (typeof DecompressionStream === 'undefined') return null;
  const formats: CompressionFormat[] = ['deflate', 'deflate-raw', 'gzip'];
  for (const fmt of formats) {
    try {
      const ds = new DecompressionStream(fmt);
      const writer = ds.writable.getWriter();
      const copy = new Uint8Array(bytes.length);
      copy.set(bytes);
      await writer.write(copy);
      await writer.close();
      const resp = new Response(ds.readable);
      const outBuf = await resp.arrayBuffer();
      const decoded = bytesToBestReadableString(new Uint8Array(outBuf));
      if (decoded && decoded.length > 4) return decoded;
    } catch {
      // try next format
    }
  }
  return null;
}

function decodeHexString(hex: string): string | null {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length < 16 || clean.length % 2 !== 0) return null;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytesToBestReadableString(bytes);
}

function isPrivateIp(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return false;
  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254)
  );
}

function extractIndicatorsFromText(
  text: string,
  layerIndex: number,
  urlMap: Map<string, ExtractedScriptUrl>,
  ipMap: Map<string, ExtractedScriptIp>,
  cmdMap: Map<string, ExtractedScriptCommand>,
  pathSet: Set<string>
) {
  // 1. URLs (including hxxp / hxxps defanged URLs)
  const normalizedForUrl = text.replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().replace('hxxp', 'http'));
  const urlMatches = normalizedForUrl.match(/https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g) || [];
  for (const raw of urlMatches) {
    const cleaned = raw.replace(/[.,;:'")\]}>\\`]+$/, '');
    if (cleaned.length < 10 || cleaned.length > 512) continue;
    let domain = '';
    try {
      domain = new URL(cleaned).hostname.toLowerCase();
    } catch {
      continue;
    }
    if (!domain) continue;
    if (!urlMap.has(cleaned)) {
      urlMap.set(cleaned, {
        url: cleaned,
        domain,
        foundInLayer: layerIndex,
        isObfuscatedSource: layerIndex > 0,
      });
    }
  }

  // 2. IPv4 addresses
  const ipRegex =
    /(?<![.\d])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![.\d])/g;
  const ipMatches = text.match(ipRegex) || [];
  for (const ip of ipMatches) {
    if (ip === '0.0.0.0' || ip === '255.255.255.255') continue;
    if (!ipMap.has(ip)) {
      ipMap.set(ip, { ip, isPrivate: isPrivateIp(ip), foundInLayer: layerIndex });
    }
  }

  // 3. Suspicious Commands & Behavior Triggers
  const commandPatterns: {
    regex: RegExp;
    label: string;
    category: ExtractedScriptCommand['category'];
    severity: ExtractedScriptCommand['severity'];
  }[] = [
    { regex: /\b(Invoke-Expression|IEX)\b/gi, label: 'Invoke-Expression (IEX) Dynamic Code Execution', category: 'Execution', severity: 'critical' },
    { regex: /\b(eval|exec|Function|ExecuteGlobal)\s*\(/gi, label: 'Dynamic eval()/exec() Payload Execution', category: 'Execution', severity: 'critical' },
    { regex: /(WScript\.Shell|Shell\.Application|ActiveXObject|child_process|subprocess\.(Popen|run|call)|os\.system)/gi, label: 'OS Process / Shell Spawning', category: 'Execution', severity: 'critical' },
    { regex: /(cmd\.exe\s+\/c|powershell(?:\.exe)?\s+[^\n]{0,80})/gi, label: 'Command / PowerShell Subprocess Call', category: 'Execution', severity: 'high' },
    { regex: /(Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|\biwr\b|\bcurl\s+|\bwget\s+|certutil\s+-urlcache|bitsadmin|urllib\.request|requests\.(get|post))/gi, label: 'Remote Payload Download / C2 Fetch', category: 'Download / C2', severity: 'critical' },
    { regex: /(api\.telegram\.org|discord\.com\/api\/webhooks|pastebin\.com|ngrok\.io)/gi, label: 'Data Exfiltration / External C2 Channel', category: 'Download / C2', severity: 'critical' },
    { regex: /(-WindowStyle\s+Hidden|-w\s+hidden|-ExecutionPolicy\s+Bypass|-ep\s+bypass|-NoProfile|-nop|amsiInitFailed|Set-MpPreference\s+-DisableRealtimeMonitoring)/gi, label: 'AV / AMSI Evasion & Stealth Flags', category: 'Defense Evasion', severity: 'critical' },
    { regex: /(CurrentVersion\\Run|schtasks\s+\/create|New-ScheduledTask|crontab|chmod\s+\+x)/gi, label: 'Persistence Mechanism (Registry / Scheduled Task)', category: 'Persistence', severity: 'critical' },
    { regex: /\b(whoami|ipconfig|ifconfig|net\s+user|systeminfo|hostname)\b/gi, label: 'Host Reconnaissance / Discovery', category: 'Discovery / Exfil', severity: 'medium' },
  ];

  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;
    for (const pat of commandPatterns) {
      if (pat.regex.test(trimmedLine)) {
        const key = `${pat.label}::${trimmedLine.substring(0, 80)}`;
        if (!cmdMap.has(key)) {
          cmdMap.set(key, {
            command: pat.label,
            category: pat.category,
            severity: pat.severity,
            foundInLayer: layerIndex,
            context: trimmedLine.slice(0, 220),
          });
        }
      }
      pat.regex.lastIndex = 0;
    }

    // Extract Windows/Unix paths & Registry keys
    const regMatches = trimmedLine.match(/(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\[^\s"']+/gi) || [];
    for (const r of regMatches) pathSet.add(r);

    const filePathMatches =
      trimmedLine.match(/(?:[A-Z]:\\(?:Users|Windows|Temp|ProgramData|AppData)[^\s"';]+|%[A-Z_]+%\\[^\s"';]+|\/(?:tmp|var\/tmp|dev\/shm|etc)\/[^\s"';]+)/gi) ||
      [];
    for (const p of filePathMatches) pathSet.add(p);
  }
}

export async function deobfuscateScriptPayload(
  rawCode: string,
  fileName: string
): Promise<ScriptDeobfuscationResult> {
  const language = detectScriptLanguage(fileName, rawCode);
  const layers: DeobfuscationLayer[] = [];
  const techniquesSet = new Set<string>();

  const urlMap = new Map<string, ExtractedScriptUrl>();
  const ipMap = new Map<string, ExtractedScriptIp>();
  const cmdMap = new Map<string, ExtractedScriptCommand>();
  const pathSet = new Set<string>();

  // Extract artifacts from original Layer 0
  extractIndicatorsFromText(rawCode, 0, urlMap, ipMap, cmdMap, pathSet);

  let currentCode = rawCode;
  const maxPasses = 6;

  for (let pass = 1; pass <= maxPasses; pass++) {
    let passChanged = false;
    let nextCode = currentCode;
    const passNotes: string[] = [];

    // 1. Caret / Backtick anti-signature obfuscation cleanup (e.g., p^o^w^e^r^s^h^e^l^l or I`E`X)
    const caretMatches = nextCode.match(/(?:[A-Za-z]\^){3,}[A-Za-z]/g);
    if (caretMatches && caretMatches.length > 0) {
      nextCode = nextCode.replace(/([A-Za-z0-9])\^([A-Za-z0-9])/g, '$1$2');
      passNotes.push('Batch Caret (^) Evasion Removal');
      techniquesSet.add('Batch Caret (^) Character Splitting');
      passChanged = true;
    }
    const backtickTokens = nextCode.match(/(?:[A-Za-z]`){2,}[A-Za-z]/g);
    if (backtickTokens && backtickTokens.length > 0) {
      nextCode = nextCode.replace(/([A-Za-z])`([A-Za-z])/g, '$1$2');
      passNotes.push('PowerShell Backtick (`) Stripping');
      techniquesSet.add('PowerShell Backtick (`) Obfuscation');
      passChanged = true;
    }

    // 2. String concatenation folding ('ht' + 'tp' + '://')
    const concatRegex = /(['"])([^'"\\\r\n]{1,64})\1\s*\+\s*(['"])([^'"\\\r\n]{1,64})\3/g;
    if (concatRegex.test(nextCode)) {
      let folded = nextCode;
      for (let k = 0; k < 10; k++) {
        const replaced = folded.replace(concatRegex, (_m, q1, a, _q2, b) => `${q1}${a}${b}${q1}`);
        if (replaced === folded) break;
        folded = replaced;
      }
      if (folded !== nextCode) {
        nextCode = folded;
        passNotes.push('String Concatenation Folding');
        techniquesSet.add('String Concatenation Obfuscation');
        passChanged = true;
      }
    }

    // 3. String.fromCharCode(...) and VBScript Chr()/ChrW() reconstruction
    nextCode = nextCode.replace(/String\.fromCharCode\(([\d\s,xXa-fA-F]+)\)/gi, (full, args) => {
      const nums = String(args)
        .split(',')
        .map((n) => n.trim())
        .filter(Boolean)
        .map((n) => (n.toLowerCase().startsWith('0x') ? parseInt(n, 16) : parseInt(n, 10)));
      if (nums.length >= 4 && nums.every((n) => Number.isFinite(n) && n >= 0 && n <= 65535)) {
        const decoded = String.fromCharCode(...nums);
        passNotes.push('String.fromCharCode() Decoding');
        techniquesSet.add('JavaScript String.fromCharCode Array');
        passChanged = true;
        return JSON.stringify(decoded);
      }
      return full;
    });

    // PowerShell [char[]]@(72,101,...) or [char]72+[char]101
    nextCode = nextCode.replace(/(?:\[char\]\s*(\d{2,3})\s*(?:\+\s*\[char\]\s*(\d{2,3})\s*)+)/gi, (full) => {
      const nums = (full.match(/\d{2,3}/g) || []).map(Number);
      if (nums.length >= 4) {
        const decoded = String.fromCharCode(...nums);
        passNotes.push('PowerShell [char] Addition Decoding');
        techniquesSet.add('PowerShell [char] Character Array');
        passChanged = true;
        return JSON.stringify(decoded);
      }
      return full;
    });

    nextCode = nextCode.replace(/(?:\[char\[\]\]|\[int\[\]\])\s*@\(([\d\s,]+)\)/gi, (full, args) => {
      const nums = String(args)
        .split(',')
        .map((n) => parseInt(n.trim(), 10))
        .filter((n) => Number.isFinite(n) && n >= 0 && n <= 65535);
      if (nums.length >= 4) {
        const decoded = String.fromCharCode(...nums);
        passNotes.push('PowerShell [char[]]@(...) Decoding');
        techniquesSet.add('PowerShell [char[]] Array Obfuscation');
        passChanged = true;
        return JSON.stringify(decoded);
      }
      return full;
    });

    // 4. PowerShell Format String ("{1}{0}" -f 'b','a')
    nextCode = nextCode.replace(
      /["']((?:\{\d+\})+)["']\s*-f\s*((?:['"][^'"]*['"]\s*,?\s*)+)/gi,
      (full, fmt, argsStr) => {
        const parts: string[] = [];
        const argRe = /['"]([^'"]*)['"]/g;
        let m: RegExpExecArray | null;
        while ((m = argRe.exec(argsStr)) !== null) {
          parts.push(m[1]);
        }
        if (parts.length > 0) {
          const rebuilt = String(fmt).replace(/\{(\d+)\}/g, (_x, idx) => parts[Number(idx)] ?? '');
          passNotes.push('PowerShell -f Format String Reordering');
          techniquesSet.add('PowerShell Format-String (-f) Splitting');
          passChanged = true;
          return JSON.stringify(rebuilt);
        }
        return full;
      }
    );

    // 5. Hex & Unicode escape sequences (\x68\x74\x74\x70 or \u0068...)
    const hasEscapes = /(?:\\x[0-9a-fA-F]{2}){4,}|(?:\\u[0-9a-fA-F]{4}){4,}|(?:%[0-9a-fA-F]{2}){5,}/.test(nextCode);
    if (hasEscapes) {
      let unescaped = nextCode.replace(/\\x([0-9a-fA-F]{2})/g, (_m, h) => {
        const code = parseInt(h, 16);
        return code >= 32 && code <= 126 ? String.fromCharCode(code) : _m;
      });
      unescaped = unescaped.replace(/\\u([0-9a-fA-F]{4})/g, (_m, h) => {
        const code = parseInt(h, 16);
        return code >= 32 && code <= 126 ? String.fromCharCode(code) : _m;
      });
      unescaped = unescaped.replace(/(?:%[0-9a-fA-F]{2}){5,}/g, (seq) => {
        try {
          return decodeURIComponent(seq);
        } catch {
          return seq;
        }
      });
      if (unescaped !== nextCode) {
        nextCode = unescaped;
        passNotes.push('Hex / Unicode / URL Percent-Escape Decoding');
        techniquesSet.add('Hex / Unicode / Percent Escape Encoding');
        passChanged = true;
      }
    }

    // 6. Base64 & Zlib/Deflate Payloads (PowerShell -EncodedCommand, FromBase64String, atob, Python b64decode)
    const decodedBlocks: string[] = [];

    // PowerShell -EncodedCommand / -enc
    const psEncRe = /(?:-(?:e|en|enc|encodedcommand)\s+)([A-Za-z0-9+/=]{16,})/gi;
    let psMatch: RegExpExecArray | null;
    while ((psMatch = psEncRe.exec(nextCode)) !== null) {
      const bytes = decodeBase64ToBytes(psMatch[1]);
      const decoded = bytes ? bytesToBestReadableString(bytes) : null;
      if (decoded) {
        decodedBlocks.push(decoded);
        passNotes.push('PowerShell -EncodedCommand (UTF-16LE Base64)');
        techniquesSet.add('PowerShell -EncodedCommand Base64');
        passChanged = true;
      }
    }

    // Generic Base64 literals (FromBase64String, atob, b64decode, Buffer.from, standalone large B64)
    const b64LiteralRe = /['"]([A-Za-z0-9+/=_-]{24,})['"]/g;
    let b64m: RegExpExecArray | null;
    const seenB64 = new Set<string>();
    while ((b64m = b64LiteralRe.exec(nextCode)) !== null) {
      const token = b64m[1];
      if (seenB64.has(token)) continue;
      seenB64.add(token);
      const bytes = decodeBase64ToBytes(token);
      if (!bytes) continue;

      // Try zlib / deflate / gzip first if zlib/DeflateStream/GzipStream present or binary zlib header (0x78)
      let decoded: string | null = null;
      if (bytes[0] === 0x78 || bytes[0] === 0x1f || /DeflateStream|GzipStream|zlib\.decompress/i.test(nextCode)) {
        decoded = await tryDecompressStream(bytes);
        if (decoded) {
          passNotes.push('Base64 + Zlib/Deflate Compression Unwrapping');
          techniquesSet.add('Compressed Base64 Stage (Zlib/Deflate/Gzip)');
        }
      }
      if (!decoded) {
        decoded = bytesToBestReadableString(bytes);
        if (decoded) {
          passNotes.push('Base64 Payload Decoding');
          techniquesSet.add('Base64 Payload Encoding');
        }
      }
      if (decoded && decoded.length >= 6 && decoded !== token) {
        decodedBlocks.push(decoded);
        passChanged = true;
      }
    }

    // Raw large Hex Strings
    const rawHexRe = /['"]([0-9a-fA-F]{32,})['"]/g;
    let hm: RegExpExecArray | null;
    while ((hm = rawHexRe.exec(nextCode)) !== null) {
      const decodedHex = decodeHexString(hm[1]);
      if (decodedHex && decodedHex.length >= 8) {
        decodedBlocks.push(decodedHex);
        passNotes.push('Hexadecimal Payload Decoding');
        techniquesSet.add('Hexadecimal String Encoding');
        passChanged = true;
      }
    }

    if (!passChanged) break;

    layers.push({
      layerIndex: pass,
      technique: Array.from(new Set(passNotes)).join(' + '),
      description: `فك طبقة التمويه رقم ${pass} (${Array.from(new Set(passNotes)).join('، ')})`,
      inputPreview: currentCode.slice(0, 320),
      decodedPreview: (decodedBlocks.length > 0 ? decodedBlocks.join('\n') : nextCode).slice(0, 500),
      decodedFull: decodedBlocks.length > 0 ? decodedBlocks.join('\n\n') : nextCode,
    });

    const artifactTarget = decodedBlocks.length > 0 ? decodedBlocks.join('\n') + '\n' + nextCode : nextCode;
    extractIndicatorsFromText(artifactTarget, pass, urlMap, ipMap, cmdMap, pathSet);

    // Feed decoded payloads forward for nested multi-layer obfuscation!
    currentCode = decodedBlocks.length > 0 ? decodedBlocks.join('\n\n') : nextCode;
  }

  const finalDeobfuscatedCode =
    layers.length > 0
      ? layers.map((l) => `### [Layer ${l.layerIndex}: ${l.technique}]\n${l.decodedFull}`).join('\n\n')
      : rawCode;

  return {
    fileName,
    fileSize: new TextEncoder().encode(rawCode).byteLength,
    language,
    lineCount: rawCode.split(/\r?\n/).length,
    originalCode: rawCode,
    finalDeobfuscatedCode,
    layersCount: layers.length,
    obfuscationTechniques: Array.from(techniquesSet),
    layers,
    extractedUrls: Array.from(urlMap.values()),
    extractedIps: Array.from(ipMap.values()),
    extractedCommands: Array.from(cmdMap.values()),
    registryAndPaths: Array.from(pathSet).slice(0, 80),
    entropy: calculateTextEntropy(rawCode),
    extractionTimestamp: new Date().toISOString(),
  };
}
