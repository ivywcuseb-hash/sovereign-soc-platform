import React, { useMemo, useState } from 'react';
import {
  Upload,
  Search,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  AlertTriangle,
  Download,
  RotateCcw,
  FileText,
  Filter,
  ChevronRight,
  ChevronLeft,
  X,
} from 'lucide-react';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface RealLogAnalyzerLabProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

type DetectedLogFormat = 'Apache/Nginx Access Log' | 'CSV / TSV Log' | 'JSON / NDJSON Log' | 'Syslog / Plain Text Log';
type StatusCategoryFilter = 'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'errors';
type SortField = 'line' | 'ip' | 'status' | 'timestamp';
type SortDirection = 'asc' | 'desc';

interface ParsedLogEntry {
  lineNumber: number;
  timestamp: string;
  ip: string;
  method: string;
  path: string;
  status: number | null;
  level: string;
  message: string;
  isErrorLine: boolean;
  matchedSignatures: string[];
  raw: string;
}

interface IpStatItem {
  ip: string;
  count: number;
  errorCount: number;
  lastTimestamp: string;
}

interface StatusStatItem {
  code: number;
  count: number;
}

interface PatternStatItem {
  id: string;
  label: string;
  kind: 'request' | 'error';
  count: number;
  sample: string;
}

interface RealLogAnalysisResult {
  fileName: string;
  fileSize: number;
  sha256: string;
  format: DetectedLogFormat;
  totalRawLines: number;
  parsedLinesCount: number;
  blankLinesSkipped: number;
  entries: ParsedLogEntry[];
  topIps: IpStatItem[];
  uniqueIpCount: number;
  statusStats: StatusStatItem[];
  statusCodedCount: number;
  errorLineCount: number;
  topEndpoints: Array<{ endpoint: string; count: number; errorCount: number }>;
  errorPatterns: PatternStatItem[];
}

const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/;
const HTTP_ACCESS_REGEX = /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^\s"]+)\s*([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

const ERROR_SIGNATURE_RULES: Array<{ id: string; label: string; test: RegExp }> = [
  { id: 'server_5xx', label: 'أخطاء الخادم (5xx)', test: /\b5\d{2}\b|internal server error|bad gateway|service unavailable/i },
  { id: 'auth_denied', label: 'فشل مصادقة أو رفض وصول (401/403)', test: /\b401\b|\b403\b|unauthorized|forbidden|failed password|authentication failure|invalid token/i },
  { id: 'not_found_404', label: 'مسارات غير موجودة (404)', test: /\b404\b|not found/i },
  { id: 'rate_limit_429', label: 'تجاوز حد الطلبات (429)', test: /\b429\b|too many requests|rate limit/i },
  { id: 'probe_traversal', label: 'محاولات استكشاف مسارات أو ثغرات', test: /\.\.\/|%2e%2e|wp-login|xmlrpc|\.env\b|phpMyAdmin|\/etc\/passwd|union\s+select|<script/i },
  { id: 'runtime_exception', label: 'استثناءات وأخطاء تشغيل (ERROR/FATAL)', test: /\b(?:error|fatal|critical|panic|exception|traceback|segfault|timeout)\b/i },
];

async function computeSha256Hex(buffer: ArrayBuffer): Promise<string> {
  const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatFileSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

function splitDelimitedRow(line: string, delimiter: ',' | '\t' | ';'): string[] {
  const result: string[] = [];
  let current = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"') {
      if (inQuotes && line[i + 1] === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (ch === delimiter && !inQuotes) {
      result.push(current.trim());
      current = '';
    } else {
      current += ch;
    }
  }
  result.push(current.trim());
  return result;
}

function extractFirstIp(text: string): string {
  const v4 = text.match(IPV4_REGEX);
  if (v4) return v4[0];
  const v6 = text.match(IPV6_REGEX);
  if (v6) return v6[0];
  return '';
}

function extractHttpStatus(text: string): number | null {
  const quotedStatus = text.match(/"\s+([1-5]\d{2})\s+(?:\d+|-)\b/);
  if (quotedStatus) return Number(quotedStatus[1]);

  const kvStatus = text.match(/\b(?:status|code|http_status|status_code)\s*[:=]\s*"?([1-5]\d{2})"?\b/i);
  if (kvStatus) return Number(kvStatus[1]);

  const bracketOrPipeStatus = text.match(/(?:^|[\s|;])([2345]\d{2})(?=[\s|;]|$)/);
  if (bracketOrPipeStatus) {
    const code = Number(bracketOrPipeStatus[1]);
    if (code >= 200 && code <= 599) return code;
  }
  return null;
}

function extractTimestamp(text: string): string {
  const iso = text.match(/\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/);
  if (iso) return iso[0];
  const clf = text.match(/\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)\]/);
  if (clf) return clf[1];
  const syslog = text.match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b/);
  if (syslog) return syslog[1];
  return '';
}

function detectSignatures(raw: string, status: number | null, path: string, level: string): string[] {
  const matches: string[] = [];
  const combined = `${raw} ${path} ${level}`;
  for (const rule of ERROR_SIGNATURE_RULES) {
    if (rule.id === 'server_5xx' && status !== null && status >= 500 && status <= 599) {
      matches.push(rule.label);
      continue;
    }
    if (rule.id === 'auth_denied' && (status === 401 || status === 403)) {
      matches.push(rule.label);
      continue;
    }
    if (rule.id === 'not_found_404' && status === 404) {
      matches.push(rule.label);
      continue;
    }
    if (rule.id === 'rate_limit_429' && status === 429) {
      matches.push(rule.label);
      continue;
    }
    if (rule.test.test(combined)) {
      matches.push(rule.label);
    }
  }
  return matches;
}

function neutralizeCsvCell(val: string | number | null): string {
  const s = val === null || val === undefined ? '' : String(val);
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
}

function parseLogFileContent(
  text: string,
  fileName: string,
  fileSize: number,
  sha256: string
): RealLogAnalysisResult {
  const normalized = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const rawLines = normalized.split('\n');
  const totalRawLines = rawLines.length;
  const nonEmptyLines: Array<{ lineNumber: number; content: string }> = [];

  for (let i = 0; i < rawLines.length; i++) {
    const trimmed = rawLines[i].trim();
    if (trimmed.length > 0) {
      nonEmptyLines.push({ lineNumber: i + 1, content: trimmed });
    }
  }

  const blankLinesSkipped = totalRawLines - nonEmptyLines.length;

  let format: DetectedLogFormat = 'Syslog / Plain Text Log';
  const lowerName = fileName.toLowerCase();
  const entries: ParsedLogEntry[] = [];

  // 1. Check JSON array or NDJSON
  const firstNonEmpty = nonEmptyLines[0]?.content || '';
  if (lowerName.endsWith('.json') && firstNonEmpty.startsWith('[')) {
    try {
      const parsedArray = JSON.parse(normalized);
      if (Array.isArray(parsedArray)) {
        format = 'JSON / NDJSON Log';
        parsedArray.forEach((item, idx) => {
          const obj = item && typeof item === 'object' ? (item as Record<string, unknown>) : { message: String(item) };
          const raw = JSON.stringify(obj);
          const ip =
            String(obj.ip || obj.client_ip || obj.remote_addr || obj.src_ip || obj.sourceIp || '').trim() ||
            extractFirstIp(raw);
          const rawStatus = obj.status ?? obj.statusCode ?? obj.status_code ?? obj.code;
          const status =
            typeof rawStatus === 'number' && rawStatus >= 100 && rawStatus <= 599
              ? rawStatus
              : typeof rawStatus === 'string' && /^[1-5]\d{2}$/.test(rawStatus.trim())
              ? Number(rawStatus.trim())
              : extractHttpStatus(raw);
          const method = String(obj.method || obj.http_method || '').toUpperCase();
          const path = String(obj.path || obj.url || obj.uri || obj.endpoint || '');
          const timestamp = String(obj.timestamp || obj.time || obj.date || obj['@timestamp'] || '') || extractTimestamp(raw);
          const level = String(obj.level || obj.severity || '').toUpperCase();
          const message = String(obj.message || obj.msg || obj.error || raw);
          const matchedSignatures = detectSignatures(raw, status, path, level);
          const isErrorLine =
            (status !== null && status >= 400) ||
            ['ERROR', 'FATAL', 'CRITICAL', 'ALERT', 'EMERG'].includes(level) ||
            matchedSignatures.length > 0;

          entries.push({
            lineNumber: idx + 1,
            timestamp,
            ip,
            method,
            path,
            status,
            level: level || (status !== null && status >= 500 ? 'ERROR' : status !== null && status >= 400 ? 'WARN' : 'INFO'),
            message,
            isErrorLine,
            matchedSignatures,
            raw,
          });
        });
      }
    } catch {
      // Fall through to line-by-line parser
    }
  }

  if (entries.length === 0 && nonEmptyLines.length > 0) {
    // Check CSV / TSV header
    const sample = nonEmptyLines.slice(0, 5).map((l) => l.content);
    const jsonLineCount = sample.filter((l) => l.startsWith('{') && l.endsWith('}')).length;
    const accessMatchCount = sample.filter((l) => HTTP_ACCESS_REGEX.test(l)).length;
    const csvDelimiter: ',' | '\t' | ';' | null =
      lowerName.endsWith('.tsv')
        ? '\t'
        : lowerName.endsWith('.csv')
        ? ','
        : firstNonEmpty.includes(',') && splitDelimitedRow(firstNonEmpty, ',').length >= 3 && accessMatchCount === 0 && jsonLineCount === 0
        ? ','
        : firstNonEmpty.includes('\t') && splitDelimitedRow(firstNonEmpty, '\t').length >= 3
        ? '\t'
        : null;

    if (jsonLineCount >= Math.ceil(sample.length / 2)) {
      format = 'JSON / NDJSON Log';
      for (const item of nonEmptyLines) {
        let obj: Record<string, unknown> | null = null;
        try {
          const parsed = JSON.parse(item.content);
          if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            obj = parsed as Record<string, unknown>;
          }
        } catch {
          obj = null;
        }
        if (obj) {
          const ip =
            String(obj.ip || obj.client_ip || obj.remote_addr || obj.src_ip || '').trim() ||
            extractFirstIp(item.content);
          const rawStatus = obj.status ?? obj.statusCode ?? obj.status_code ?? obj.code;
          const status =
            typeof rawStatus === 'number' && rawStatus >= 100 && rawStatus <= 599
              ? rawStatus
              : typeof rawStatus === 'string' && /^[1-5]\d{2}$/.test(rawStatus.trim())
              ? Number(rawStatus.trim())
              : extractHttpStatus(item.content);
          const method = String(obj.method || obj.http_method || '').toUpperCase();
          const path = String(obj.path || obj.url || obj.uri || obj.endpoint || '');
          const timestamp = String(obj.timestamp || obj.time || obj.date || obj['@timestamp'] || '') || extractTimestamp(item.content);
          const level = String(obj.level || obj.severity || '').toUpperCase();
          const message = String(obj.message || obj.msg || obj.error || item.content);
          const matchedSignatures = detectSignatures(item.content, status, path, level);
          const isErrorLine =
            (status !== null && status >= 400) ||
            ['ERROR', 'FATAL', 'CRITICAL', 'ALERT', 'EMERG'].includes(level) ||
            matchedSignatures.length > 0;
          entries.push({
            lineNumber: item.lineNumber,
            timestamp,
            ip,
            method,
            path,
            status,
            level: level || (status !== null && status >= 500 ? 'ERROR' : status !== null && status >= 400 ? 'WARN' : 'INFO'),
            message,
            isErrorLine,
            matchedSignatures,
            raw: item.content,
          });
        } else {
          const ip = extractFirstIp(item.content);
          const status = extractHttpStatus(item.content);
          const timestamp = extractTimestamp(item.content);
          const matchedSignatures = detectSignatures(item.content, status, '', '');
          entries.push({
            lineNumber: item.lineNumber,
            timestamp,
            ip,
            method: '',
            path: '',
            status,
            level: status !== null && status >= 500 ? 'ERROR' : status !== null && status >= 400 ? 'WARN' : 'INFO',
            message: item.content,
            isErrorLine: (status !== null && status >= 400) || matchedSignatures.length > 0,
            matchedSignatures,
            raw: item.content,
          });
        }
      }
    } else if (csvDelimiter) {
      format = 'CSV / TSV Log';
      const firstCells = splitDelimitedRow(nonEmptyLines[0].content, csvDelimiter);
      const lowerHeaders = firstCells.map((h) => h.toLowerCase());
      const hasHeaderRow = lowerHeaders.some((h) =>
        ['ip', 'client_ip', 'remote_addr', 'src_ip', 'status', 'status_code', 'code', 'method', 'path', 'url', 'uri', 'timestamp', 'time', 'date', 'level', 'message', 'msg'].includes(h)
      );

      const findCol = (names: string[]) => lowerHeaders.findIndex((h) => names.includes(h));
      const ipIdx = hasHeaderRow ? findCol(['ip', 'client_ip', 'remote_addr', 'src_ip', 'source_ip', 'host']) : -1;
      const statusIdx = hasHeaderRow ? findCol(['status', 'status_code', 'http_status', 'code']) : -1;
      const methodIdx = hasHeaderRow ? findCol(['method', 'http_method', 'verb']) : -1;
      const pathIdx = hasHeaderRow ? findCol(['path', 'url', 'uri', 'endpoint', 'request']) : -1;
      const timeIdx = hasHeaderRow ? findCol(['timestamp', 'time', 'date', 'datetime', 'created_at']) : -1;
      const levelIdx = hasHeaderRow ? findCol(['level', 'severity', 'type']) : -1;
      const msgIdx = hasHeaderRow ? findCol(['message', 'msg', 'error', 'details', 'description']) : -1;

      const dataLines = hasHeaderRow ? nonEmptyLines.slice(1) : nonEmptyLines;
      for (const item of dataLines) {
        const cols = splitDelimitedRow(item.content, csvDelimiter);
        const ip = (ipIdx >= 0 ? cols[ipIdx] : '')?.trim() || extractFirstIp(item.content);
        const statusRaw = statusIdx >= 0 ? cols[statusIdx]?.trim() : '';
        const status =
          statusRaw && /^[1-5]\d{2}$/.test(statusRaw) ? Number(statusRaw) : extractHttpStatus(item.content);
        const method = (methodIdx >= 0 ? cols[methodIdx] : '')?.trim().toUpperCase() || '';
        const path = (pathIdx >= 0 ? cols[pathIdx] : '')?.trim() || '';
        const timestamp = (timeIdx >= 0 ? cols[timeIdx] : '')?.trim() || extractTimestamp(item.content);
        const level = (levelIdx >= 0 ? cols[levelIdx] : '')?.trim().toUpperCase() || '';
        const message = (msgIdx >= 0 ? cols[msgIdx] : '')?.trim() || item.content;
        const matchedSignatures = detectSignatures(item.content, status, path, level);
        const isErrorLine =
          (status !== null && status >= 400) ||
          ['ERROR', 'FATAL', 'CRITICAL', 'ALERT', 'EMERG'].includes(level) ||
          matchedSignatures.length > 0;

        entries.push({
          lineNumber: item.lineNumber,
          timestamp,
          ip,
          method,
          path,
          status,
          level: level || (status !== null && status >= 500 ? 'ERROR' : status !== null && status >= 400 ? 'WARN' : 'INFO'),
          message,
          isErrorLine,
          matchedSignatures,
          raw: item.content,
        });
      }
    } else {
      if (accessMatchCount > 0) {
        format = 'Apache/Nginx Access Log';
      }
      for (const item of nonEmptyLines) {
        const accessM = item.content.match(HTTP_ACCESS_REGEX);
        if (accessM) {
          const ip = accessM[1] === '-' ? '' : accessM[1];
          const timestamp = accessM[2] || '';
          const method = accessM[3].toUpperCase();
          const path = accessM[4];
          const status = Number(accessM[6]);
          const userAgent = accessM[9] || '';
          const level = status >= 500 ? 'ERROR' : status >= 400 ? 'WARN' : 'INFO';
          const matchedSignatures = detectSignatures(item.content, status, path, level);
          entries.push({
            lineNumber: item.lineNumber,
            timestamp,
            ip,
            method,
            path,
            status,
            level,
            message: userAgent ? `${method} ${path} · ${userAgent}` : `${method} ${path}`,
            isErrorLine: status >= 400 || matchedSignatures.length > 0,
            matchedSignatures,
            raw: item.content,
          });
        } else {
          const ip = extractFirstIp(item.content);
          const status = extractHttpStatus(item.content);
          const timestamp = extractTimestamp(item.content);
          const methodM = item.content.match(/\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\/[^\s"]*)/);
          const method = methodM ? methodM[1] : '';
          const path = methodM ? methodM[2] : '';
          const levelM = item.content.match(/\b(FATAL|CRITICAL|ERROR|WARN|WARNING|INFO|DEBUG)\b/i);
          const level = levelM ? levelM[1].toUpperCase() : status !== null && status >= 500 ? 'ERROR' : status !== null && status >= 400 ? 'WARN' : 'INFO';
          const matchedSignatures = detectSignatures(item.content, status, path, level);
          const isErrorLine =
            (status !== null && status >= 400) ||
            ['ERROR', 'FATAL', 'CRITICAL', 'WARN', 'WARNING'].includes(level) ||
            matchedSignatures.length > 0;

          entries.push({
            lineNumber: item.lineNumber,
            timestamp,
            ip,
            method,
            path,
            status,
            level,
            message: item.content,
            isErrorLine,
            matchedSignatures,
            raw: item.content,
          });
        }
      }
    }
  }

  // Aggregate real stats from parsed entries
  const ipMap = new Map<string, IpStatItem>();
  const statusMap = new Map<number, number>();
  const endpointMap = new Map<string, { endpoint: string; count: number; errorCount: number }>();
  const patternMap = new Map<string, PatternStatItem>();
  let errorLineCount = 0;
  let statusCodedCount = 0;

  for (const entry of entries) {
    if (entry.isErrorLine) errorLineCount++;

    if (entry.ip) {
      const existing = ipMap.get(entry.ip) || {
        ip: entry.ip,
        count: 0,
        errorCount: 0,
        lastTimestamp: entry.timestamp,
      };
      existing.count++;
      if (entry.isErrorLine) existing.errorCount++;
      if (entry.timestamp) existing.lastTimestamp = entry.timestamp;
      ipMap.set(entry.ip, existing);
    }

    if (entry.status !== null) {
      statusCodedCount++;
      statusMap.set(entry.status, (statusMap.get(entry.status) || 0) + 1);
    }

    if (entry.path) {
      const cleanPath = entry.path.split('?')[0] || entry.path;
      const epKey = entry.method ? `${entry.method} ${cleanPath}` : cleanPath;
      const existingEp = endpointMap.get(epKey) || { endpoint: epKey, count: 0, errorCount: 0 };
      existingEp.count++;
      if (entry.isErrorLine) existingEp.errorCount++;
      endpointMap.set(epKey, existingEp);
    }

    for (const sig of entry.matchedSignatures) {
      const existingSig = patternMap.get(sig) || {
        id: sig,
        label: sig,
        kind: 'error' as const,
        count: 0,
        sample: entry.raw.slice(0, 120),
      };
      existingSig.count++;
      patternMap.set(sig, existingSig);
    }
  }

  const topIps = Array.from(ipMap.values()).sort((a, b) => b.count - a.count);
  const statusStats = Array.from(statusMap.entries())
    .map(([code, count]) => ({ code, count }))
    .sort((a, b) => b.count - a.count || a.code - b.code);
  const topEndpoints = Array.from(endpointMap.values()).sort((a, b) => b.count - a.count);
  const errorPatterns = Array.from(patternMap.values()).sort((a, b) => b.count - a.count);

  return {
    fileName,
    fileSize,
    sha256,
    format,
    totalRawLines,
    parsedLinesCount: entries.length,
    blankLinesSkipped,
    entries,
    topIps,
    uniqueIpCount: ipMap.size,
    statusStats,
    statusCodedCount,
    errorLineCount,
    topEndpoints,
    errorPatterns,
  };
}

export const RealLogAnalyzerLab: React.FC<RealLogAnalyzerLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [loading, setLoading] = useState(false);
  const [emptyFileWarning, setEmptyFileWarning] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<RealLogAnalysisResult | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusCategory, setStatusCategory] = useState<StatusCategoryFilter>('all');
  const [selectedIpFilter, setSelectedIpFilter] = useState<string>('');
  const [selectedStatusFilter, setSelectedStatusFilter] = useState<number | null>(null);
  const [sortField, setSortField] = useState<SortField>('line');
  const [sortDir, setSortDir] = useState<SortDirection>('asc');
  const [pageSize, setPageSize] = useState<number>(50);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [selectedEntry, setSelectedEntry] = useState<ParsedLogEntry | null>(null);

  const resetFilters = () => {
    setSearchQuery('');
    setStatusCategory('all');
    setSelectedIpFilter('');
    setSelectedStatusFilter(null);
    setSortField('line');
    setSortDir('asc');
    setCurrentPage(1);
  };

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    setEmptyFileWarning(null);
    setSelectedEntry(null);
    resetFilters();

    try {
      if (file.size === 0) {
        setAnalysis(null);
        setEmptyFileWarning(`الملف "${file.name}" فارغ (0 بايت). يرجى رفع ملف سجل حقيقي يحتوي على أسطر بيانات للتحليل.`);
        onNotify('الملف المرفوع فارغ — يرجى رفع ملف سجل حقيقي.', 'warning');
        return;
      }

      const buffer = await file.arrayBuffer();
      const sha256 = await computeSha256Hex(buffer);
      const text = new TextDecoder('utf-8', { fatal: false }).decode(buffer);

      if (!text.trim()) {
        setAnalysis(null);
        setEmptyFileWarning(`الملف "${file.name}" لا يحتوي على أي أسطر نصية صالحة للتحليل. يرجى رفع ملف سجل حقيقي.`);
        onNotify('الملف لا يحتوي على أسطر نصية للتحليل.', 'warning');
        return;
      }

      const result = parseLogFileContent(text, file.name, file.size, sha256);
      if (result.parsedLinesCount === 0) {
        setAnalysis(null);
        setEmptyFileWarning(`لم يتم استخراج أي سجلات قابلة للتحليل من الملف "${file.name}". يرجى التحقق من محتوى الملف ورفع ملف سجل حقيقي.`);
        onNotify('الملف لا يحتوي على سجلات صالحة.', 'warning');
        return;
      }

      setAnalysis(result);

      const errorRatio = Math.round((result.errorLineCount / Math.max(1, result.parsedLinesCount)) * 100);
      const risk: 'منخفض' | 'متوسط' | 'مرتفع' | 'حرج' =
        errorRatio >= 40 ? 'حرج' : errorRatio >= 20 ? 'مرتفع' : errorRatio >= 5 ? 'متوسط' : 'منخفض';

      onRecordAudit({
        id: `log-${Date.now()}`,
        fileName: file.name,
        fileSize: formatFileSize(file.size),
        verdict: `تحليل سجل (${result.parsedLinesCount} سطر · ${result.uniqueIpCount} IP · ${result.errorLineCount} خطأ)`,
        score: Math.max(0, 100 - errorRatio),
        risk,
        sha256,
      });
      onNotify(`تم تحليل ${result.parsedLinesCount} سطراً حقيقياً من "${file.name}".`, 'success');
    } catch (err) {
      setAnalysis(null);
      setEmptyFileWarning(err instanceof Error ? err.message : 'تعذر قراءة ملف السجل.');
      onNotify('تعذر قراءة ملف السجل المرفوع.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const filteredAndSortedEntries = useMemo(() => {
    if (!analysis) return [];
    const q = searchQuery.trim().toLowerCase();

    const filtered = analysis.entries.filter((entry) => {
      if (selectedIpFilter && entry.ip !== selectedIpFilter) return false;
      if (selectedStatusFilter !== null && entry.status !== selectedStatusFilter) return false;

      if (statusCategory === '2xx' && (entry.status === null || entry.status < 200 || entry.status >= 300)) return false;
      if (statusCategory === '3xx' && (entry.status === null || entry.status < 300 || entry.status >= 400)) return false;
      if (statusCategory === '4xx' && (entry.status === null || entry.status < 400 || entry.status >= 500)) return false;
      if (statusCategory === '5xx' && (entry.status === null || entry.status < 500 || entry.status >= 600)) return false;
      if (statusCategory === 'errors' && !entry.isErrorLine) return false;

      if (q) {
        const haystack = `${entry.lineNumber} ${entry.ip} ${entry.status ?? ''} ${entry.method} ${entry.path} ${entry.level} ${entry.timestamp} ${entry.raw}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });

    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (sortField === 'line') {
        cmp = a.lineNumber - b.lineNumber;
      } else if (sortField === 'status') {
        cmp = (a.status ?? -1) - (b.status ?? -1);
      } else if (sortField === 'ip') {
        cmp = a.ip.localeCompare(b.ip);
      } else if (sortField === 'timestamp') {
        cmp = a.timestamp.localeCompare(b.timestamp);
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return sorted;
  }, [analysis, searchQuery, statusCategory, selectedIpFilter, selectedStatusFilter, sortField, sortDir]);

  const totalPages = Math.max(1, Math.ceil(filteredAndSortedEntries.length / pageSize));
  const safePage = Math.min(currentPage, totalPages);
  const pagedEntries = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return filteredAndSortedEntries.slice(start, start + pageSize);
  }, [filteredAndSortedEntries, safePage, pageSize]);

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortField(field);
      setSortDir(field === 'line' ? 'asc' : 'desc');
    }
    setCurrentPage(1);
  };

  const renderSortIcon = (field: SortField) => {
    if (sortField !== field) return <ArrowUpDown className="w-3.5 h-3.5 opacity-50" />;
    return sortDir === 'asc' ? <ArrowUp className="w-3.5 h-3.5 text-[#D4AF37]" /> : <ArrowDown className="w-3.5 h-3.5 text-[#D4AF37]" />;
  };

  const exportFilteredCsv = () => {
    if (!analysis || filteredAndSortedEntries.length === 0) return;
    const headers = ['Line', 'Timestamp', 'IP', 'Method', 'Path', 'Status', 'Level', 'Signatures', 'RawLine'];
    const rows = filteredAndSortedEntries.map((e) =>
      [
        neutralizeCsvCell(e.lineNumber),
        neutralizeCsvCell(e.timestamp),
        neutralizeCsvCell(e.ip),
        neutralizeCsvCell(e.method),
        neutralizeCsvCell(e.path),
        neutralizeCsvCell(e.status),
        neutralizeCsvCell(e.level),
        neutralizeCsvCell(e.matchedSignatures.join(' | ')),
        neutralizeCsvCell(e.raw),
      ].join(',')
    );
    const csvContent = '\uFEFF' + [headers.join(','), ...rows].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `log-analysis-${analysis.fileName.replace(/[^a-zA-Z0-9._-]/g, '_')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify(`تم تصدير ${filteredAndSortedEntries.length} سطراً بصيغة CSV.`, 'success');
  };

  return (
    <div className="space-y-6" dir="rtl">
      {/* Header & Real File Upload */}
      <div className="rounded-xl bg-gray-900 border border-gray-800 p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-lg font-bold text-white">محلل السجلات الحقيقي (Real Log Analyzer)</h2>
            <p className="text-xs text-gray-400">
              تحليل فعلي لملفات السجلات المرفوعة (access.log, syslog, CSV, TSV, JSON/NDJSON) لاستخراج عناوين IP ورموز الحالة وأنماط الطلبات والأخطاء دون أي بيانات وهمية.
            </p>
          </div>
          {analysis && (
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={exportFilteredCsv}
                disabled={filteredAndSortedEntries.length === 0}
                className="px-4 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 text-xs font-bold inline-flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>تصدير CSV ({filteredAndSortedEntries.length})</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setAnalysis(null);
                  setEmptyFileWarning(null);
                  setSelectedEntry(null);
                  resetFilters();
                }}
                className="px-4 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-300 text-xs font-bold inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>مسح السجل</span>
              </button>
            </div>
          )}
        </div>

        <label className="flex flex-col items-center justify-center p-7 rounded-xl border-2 border-dashed border-gray-700 hover:border-[#D4AF37] bg-gray-950/70 cursor-pointer text-center transition">
          <Upload className="w-7 h-7 text-[#D4AF37] mb-2" />
          <span className="text-sm font-bold text-white">
            {loading ? 'جاري قراءة وتحليل ملف السجل...' : 'ارفع ملف سجل حقيقي للتحليل (access.log, .txt, .csv, .json, .jsonl)'}
          </span>
          <span className="text-xs text-gray-400 mt-1">
            تتم القراءة والفحص محلياً داخل المتصفح مباشرة من محتوى الملف المرفوع
          </span>
          <input
            type="file"
            accept=".log,.txt,.csv,.tsv,.json,.jsonl,.ndjson,.out,.syslog"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleFileUpload(f);
              e.target.value = '';
            }}
          />
        </label>

        {emptyFileWarning && (
          <div className="p-4 rounded-xl bg-amber-950/30 border border-amber-500/40 text-amber-200 text-xs flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span>{emptyFileWarning}</span>
          </div>
        )}
      </div>

      {/* Strict Empty State when no real file has been uploaded */}
      {!analysis && !emptyFileWarning && (
        <div className="rounded-xl bg-gray-900 border border-gray-800 p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-xl bg-gray-950 border border-gray-800 flex items-center justify-center text-[#D4AF37] mx-auto">
            <FileText className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-bold text-white">لم يتم رفع أي ملف سجل بعد</h3>
          <p className="text-xs text-gray-400 max-w-lg mx-auto leading-relaxed">
            لا يتم عرض أي إحصائيات أو سجلات افتراضية مسبقاً. ارفع ملف سجل حقيقي (مثل Apache/Nginx access.log أو ملف CSV/JSON/نصي) لاستخراج أكثر عناوين IP تكراراً، توزيع رموز الحالة، وأنماط الطلبات والأخطاء الفعلية.
          </p>
        </div>
      )}

      {/* Real Analysis Results */}
      {analysis && (
        <div className="space-y-6">
          {/* File Metadata Strip (unboxed text with typographic separators) */}
          <div className="px-4 py-3 rounded-xl bg-gray-900 border border-gray-800 flex flex-wrap items-center justify-between gap-2 text-xs text-gray-300">
            <div className="flex flex-wrap items-center gap-2 font-mono">
              <span className="text-white font-bold">{analysis.fileName}</span>
              <span aria-hidden="true" className="text-gray-600">·</span>
              <span>{analysis.format}</span>
              <span aria-hidden="true" className="text-gray-600">·</span>
              <span className="tabular-nums">{formatFileSize(analysis.fileSize)}</span>
            </div>
            <div className="text-[11px] font-mono text-gray-400 truncate max-w-full" dir="ltr">
              SHA-256: {analysis.sha256}
            </div>
          </div>

          {/* 4 Summary Metrics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-xs text-gray-400">الأسطر المحللة فعلياً</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-[#D4AF37]">
                {analysis.parsedLinesCount.toLocaleString()}
              </div>
              <div className="text-[11px] text-gray-400 font-mono tabular-nums">
                إجمالي {analysis.totalRawLines} · فارغ {analysis.blankLinesSkipped}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-xs text-gray-400">عناوين IP الفريدة</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-white">
                {analysis.uniqueIpCount.toLocaleString()}
              </div>
              <div className="text-[11px] text-gray-400 font-mono tabular-nums">
                {analysis.topIps[0]
                  ? `الأكثر تكراراً: ${analysis.topIps[0].ip} (${analysis.topIps[0].count})`
                  : 'لا توجد عناوين IP في الملف'}
              </div>
            </div>

            <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-xs text-gray-400">رموز الحالة المرصودة</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
                {analysis.statusCodedCount.toLocaleString()}
              </div>
              <div className="text-[11px] text-gray-400 font-mono tabular-nums">
                {analysis.statusStats.length} رمز حالة مختلف
              </div>
            </div>

            <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 space-y-1">
              <div className="text-xs text-gray-400">أسطر الأخطاء والتحذيرات</div>
              <div className={`text-2xl font-bold font-mono tabular-nums ${analysis.errorLineCount > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                {analysis.errorLineCount.toLocaleString()}
              </div>
              <div className="text-[11px] text-gray-400 font-mono tabular-nums">
                {((analysis.errorLineCount / Math.max(1, analysis.parsedLinesCount)) * 100).toFixed(1)}% من السجلات
              </div>
            </div>
          </div>

          {/* Top IPs & Status Codes */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Top IPs */}
            <div className="p-5 rounded-xl bg-gray-900 border border-gray-800 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-bold text-white">أكثر عناوين IP تكراراً</h3>
                {selectedIpFilter && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedIpFilter('');
                      setCurrentPage(1);
                    }}
                    className="text-[11px] text-[#D4AF37] hover:underline cursor-pointer whitespace-nowrap shrink-0"
                  >
                    إلغاء تصفية IP ({selectedIpFilter})
                  </button>
                )}
              </div>

              {analysis.topIps.length === 0 ? (
                <p className="text-xs text-gray-400 py-4">لم يتم العثور على عناوين IPv4 أو IPv6 في هذا الملف.</p>
              ) : (
                <div className="divide-y divide-gray-800 max-h-72 overflow-y-auto">
                  {analysis.topIps.slice(0, 15).map((item) => {
                    const pct = ((item.count / Math.max(1, analysis.parsedLinesCount)) * 100).toFixed(1);
                    const active = selectedIpFilter === item.ip;
                    return (
                      <button
                        key={item.ip}
                        type="button"
                        onClick={() => {
                          setSelectedIpFilter(active ? '' : item.ip);
                          setCurrentPage(1);
                        }}
                        className={`w-full py-2.5 px-3 flex items-center justify-between gap-3 text-right transition cursor-pointer ${
                          active ? 'bg-[#D4AF37]/15 text-white' : 'hover:bg-gray-950/70 text-gray-200'
                        }`}
                      >
                        <div className="min-w-0 flex items-center gap-2">
                          <span className="font-mono text-xs text-emerald-300 truncate" dir="ltr">
                            {item.ip}
                          </span>
                          {item.errorCount > 0 && (
                            <span className="text-[11px] font-mono tabular-nums text-red-400">
                              · {item.errorCount} خطأ
                            </span>
                          )}
                        </div>
                        <div className="font-mono tabular-nums text-xs text-gray-300 shrink-0">
                          {item.count.toLocaleString()} ({pct}%)
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Status Codes */}
            <div className="p-5 rounded-xl bg-gray-900 border border-gray-800 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <h3 className="text-xs font-bold text-white">توزيع رموز الحالة (Status Codes)</h3>
                {selectedStatusFilter !== null && (
                  <button
                    type="button"
                    onClick={() => {
                      setSelectedStatusFilter(null);
                      setCurrentPage(1);
                    }}
                    className="text-[11px] text-[#D4AF37] hover:underline cursor-pointer whitespace-nowrap shrink-0"
                  >
                    إلغاء تصفية ({selectedStatusFilter})
                  </button>
                )}
              </div>

              {analysis.statusStats.length === 0 ? (
                <p className="text-xs text-gray-400 py-4">لم يتم العثور على رموز حالة HTTP في أسطر هذا الملف.</p>
              ) : (
                <div className="divide-y divide-gray-800 max-h-72 overflow-y-auto">
                  {analysis.statusStats.map((st) => {
                    const pct = ((st.count / Math.max(1, analysis.statusCodedCount)) * 100).toFixed(1);
                    const active = selectedStatusFilter === st.code;
                    const colorClass =
                      st.code >= 500
                        ? 'text-red-400'
                        : st.code >= 400
                        ? 'text-amber-300'
                        : st.code >= 300
                        ? 'text-sky-300'
                        : 'text-emerald-300';
                    return (
                      <button
                        key={st.code}
                        type="button"
                        onClick={() => {
                          setSelectedStatusFilter(active ? null : st.code);
                          setCurrentPage(1);
                        }}
                        className={`w-full py-2.5 px-3 flex items-center justify-between gap-3 transition cursor-pointer ${
                          active ? 'bg-[#D4AF37]/15' : 'hover:bg-gray-950/70'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className={`font-mono font-bold text-xs tabular-nums ${colorClass}`}>
                            HTTP {st.code}
                          </span>
                          <span className="text-[11px] text-gray-400">
                            {st.code >= 500
                              ? 'خطأ خادم'
                              : st.code === 404
                              ? 'غير موجود'
                              : st.code === 403
                              ? 'ممنوع'
                              : st.code === 401
                              ? 'غير مصرح'
                              : st.code >= 400
                              ? 'خطأ طلب'
                              : st.code >= 300
                              ? 'إعادة توجيه'
                              : 'ناجح'}
                          </span>
                        </div>
                        <div className="font-mono tabular-nums text-xs text-gray-300">
                          {st.count.toLocaleString()} ({pct}%)
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* Request Endpoints & Detected Error Patterns */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="p-5 rounded-xl bg-gray-900 border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-white">أكثر أنماط الطلبات والمسارات تكراراً</h3>
              {analysis.topEndpoints.length === 0 ? (
                <p className="text-xs text-gray-400 py-3">لم تُرصد مسارات طلبات HTTP (مثل GET /path) في الملف.</p>
              ) : (
                <div className="divide-y divide-gray-800 max-h-64 overflow-y-auto">
                  {analysis.topEndpoints.slice(0, 12).map((ep) => (
                    <button
                      key={ep.endpoint}
                      type="button"
                      onClick={() => {
                        const pathOnly = ep.endpoint.includes(' ') ? ep.endpoint.split(' ').slice(1).join(' ') : ep.endpoint;
                        setSearchQuery(pathOnly);
                        setCurrentPage(1);
                      }}
                      className="w-full py-2 px-3 flex items-center justify-between gap-3 text-right hover:bg-gray-950/70 transition cursor-pointer"
                    >
                      <span className="font-mono text-xs text-gray-200 truncate" dir="ltr">
                        {ep.endpoint}
                      </span>
                      <span className="font-mono tabular-nums text-xs text-gray-400 shrink-0">
                        {ep.count.toLocaleString()}
                        {ep.errorCount > 0 ? ` · ${ep.errorCount} خطأ` : ''}
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div className="p-5 rounded-xl bg-gray-900 border border-gray-800 space-y-3">
              <h3 className="text-xs font-bold text-white">أنماط الأخطاء والمؤشرات المرصودة</h3>
              {analysis.errorPatterns.length === 0 ? (
                <p className="text-xs text-gray-400 py-3">لم تطابق أي أسطر أنماط أخطاء أو تحذيرات في هذا الملف.</p>
              ) : (
                <div className="divide-y divide-gray-800 max-h-64 overflow-y-auto">
                  {analysis.errorPatterns.map((pat) => (
                    <button
                      key={pat.id}
                      type="button"
                      onClick={() => {
                        setStatusCategory('errors');
                        setCurrentPage(1);
                      }}
                      className="w-full py-2.5 px-3 flex items-center justify-between gap-3 text-right hover:bg-gray-950/70 transition cursor-pointer"
                    >
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-red-300 truncate">{pat.label}</div>
                        <div className="text-[11px] font-mono text-gray-500 truncate mt-0.5" dir="ltr">
                          {pat.sample}
                        </div>
                      </div>
                      <span className="font-mono tabular-nums text-xs font-bold text-white shrink-0">
                        {pat.count.toLocaleString()} سطر
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Search, Filter, Sort & Log Lines Table */}
          <div className="rounded-xl bg-gray-900 border border-gray-800 p-5 space-y-4">
            <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs font-bold text-white">
                <Filter className="w-4 h-4 text-[#D4AF37]" />
                <span>جدول الأسطر والسجلات ({filteredAndSortedEntries.length.toLocaleString()} من {analysis.parsedLinesCount.toLocaleString()})</span>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="relative flex-1 min-w-[220px]">
                  <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      setCurrentPage(1);
                    }}
                    placeholder="بحث في السجلات (IP، مسار، رمز حالة، نص الخطأ)..."
                    className="w-full pr-9 pl-8 py-2 bg-gray-950 border border-gray-800 rounded-lg text-xs text-white focus:border-[#D4AF37] outline-none"
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      onClick={() => {
                        setSearchQuery('');
                        setCurrentPage(1);
                      }}
                      aria-label="مسح البحث"
                      className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white cursor-pointer"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                <div className="flex items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
                  {(
                    [
                      { id: 'all', label: 'الكل' },
                      { id: '2xx', label: '2xx' },
                      { id: '3xx', label: '3xx' },
                      { id: '4xx', label: '4xx' },
                      { id: '5xx', label: '5xx' },
                      { id: 'errors', label: 'أخطاء' },
                    ] as Array<{ id: StatusCategoryFilter; label: string }>
                  ).map((btn) => (
                    <button
                      key={btn.id}
                      type="button"
                      onClick={() => {
                        setStatusCategory(btn.id);
                        setCurrentPage(1);
                      }}
                      className={`px-2.5 py-1 rounded text-xs font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                        statusCategory === btn.id
                          ? 'bg-[#D4AF37] text-gray-950'
                          : 'text-gray-400 hover:text-white'
                      }`}
                    >
                      {btn.label}
                    </button>
                  ))}
                </div>

                {(searchQuery || statusCategory !== 'all' || selectedIpFilter || selectedStatusFilter !== null) && (
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs text-gray-300 font-bold cursor-pointer whitespace-nowrap shrink-0"
                  >
                    إعادة ضبط التصفية
                  </button>
                )}
              </div>
            </div>

            <div className="overflow-x-auto border border-gray-800 rounded-xl">
              <table className="w-full text-xs text-right">
                <thead className="bg-gray-950 text-gray-400 border-b border-gray-800 font-mono">
                  <tr>
                    <th className="py-2.5 px-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => toggleSort('line')}
                        className="inline-flex items-center gap-1 hover:text-white cursor-pointer"
                      >
                        <span>#</span>
                        {renderSortIcon('line')}
                      </button>
                    </th>
                    <th className="py-2.5 px-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => toggleSort('timestamp')}
                        className="inline-flex items-center gap-1 hover:text-white cursor-pointer"
                      >
                        <span>الوقت</span>
                        {renderSortIcon('timestamp')}
                      </button>
                    </th>
                    <th className="py-2.5 px-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => toggleSort('ip')}
                        className="inline-flex items-center gap-1 hover:text-white cursor-pointer"
                      >
                        <span>IP</span>
                        {renderSortIcon('ip')}
                      </button>
                    </th>
                    <th className="py-2.5 px-3 whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => toggleSort('status')}
                        className="inline-flex items-center gap-1 hover:text-white cursor-pointer"
                      >
                        <span>الحالة</span>
                        {renderSortIcon('status')}
                      </button>
                    </th>
                    <th className="py-2.5 px-3 whitespace-nowrap">الطريقة / المسار</th>
                    <th className="py-2.5 px-3">التفاصيل</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800 font-mono text-[11px]">
                  {pagedEntries.map((entry) => {
                    const statusColor =
                      entry.status === null
                        ? 'text-gray-500'
                        : entry.status >= 500
                        ? 'text-red-400 font-bold'
                        : entry.status >= 400
                        ? 'text-amber-300 font-bold'
                        : entry.status >= 300
                        ? 'text-sky-300'
                        : 'text-emerald-300';

                    return (
                      <tr
                        key={entry.lineNumber}
                        onClick={() => setSelectedEntry(entry)}
                        className={`cursor-pointer transition ${
                          selectedEntry?.lineNumber === entry.lineNumber
                            ? 'bg-[#D4AF37]/15'
                            : 'hover:bg-gray-950/70'
                        }`}
                      >
                        <td className="py-2 px-3 tabular-nums text-gray-500">{entry.lineNumber}</td>
                        <td className="py-2 px-3 tabular-nums text-gray-300 whitespace-nowrap" dir="ltr">
                          {entry.timestamp || '—'}
                        </td>
                        <td className="py-2 px-3 text-emerald-300 whitespace-nowrap" dir="ltr">
                          {entry.ip || '—'}
                        </td>
                        <td className={`py-2 px-3 tabular-nums whitespace-nowrap ${statusColor}`}>
                          {entry.status !== null ? entry.status : entry.level}
                        </td>
                        <td className="py-2 px-3 text-gray-200 whitespace-nowrap max-w-[240px] truncate" dir="ltr">
                          {entry.method || entry.path ? `${entry.method} ${entry.path}`.trim() : '—'}
                        </td>
                        <td className="py-2 px-3 text-gray-300 max-w-md truncate" dir="ltr">
                          {entry.message}
                        </td>
                      </tr>
                    );
                  })}
                  {pagedEntries.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-gray-500 font-sans text-xs">
                        لا توجد أسطر مطابقة لمعايير البحث والتصفية الحالية.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-gray-400">
              <div className="flex items-center gap-2">
                <span>عدد الصفوف بالصفحة:</span>
                <select
                  value={pageSize}
                  onChange={(e) => {
                    setPageSize(Number(e.target.value));
                    setCurrentPage(1);
                  }}
                  className="px-2 py-1 rounded bg-gray-950 border border-gray-800 text-white text-xs outline-none"
                >
                  <option value={50}>50</option>
                  <option value={100}>100</option>
                  <option value={250}>250</option>
                </select>
              </div>

              <div className="flex items-center gap-2 font-mono tabular-nums">
                <button
                  type="button"
                  disabled={safePage <= 1}
                  onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  className="px-2.5 py-1 rounded bg-gray-950 border border-gray-800 text-gray-200 disabled:opacity-40 cursor-pointer inline-flex items-center gap-1"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                  <span>السابق</span>
                </button>
                <span>
                  صفحة {safePage} / {totalPages}
                </span>
                <button
                  type="button"
                  disabled={safePage >= totalPages}
                  onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                  className="px-2.5 py-1 rounded bg-gray-950 border border-gray-800 text-gray-200 disabled:opacity-40 cursor-pointer inline-flex items-center gap-1"
                >
                  <span>التالي</span>
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>

            {/* Selected Raw Log Line Detail */}
            {selectedEntry && (
              <div className="p-4 rounded-xl bg-gray-950 border border-[#D4AF37]/40 space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between gap-2 text-[#D4AF37] font-bold">
                  <span>
                    السطر #{selectedEntry.lineNumber}
                    {selectedEntry.ip ? ` · ${selectedEntry.ip}` : ''}
                    {selectedEntry.status !== null ? ` · HTTP ${selectedEntry.status}` : ''}
                  </span>
                  <button
                    type="button"
                    onClick={() => setSelectedEntry(null)}
                    className="text-gray-400 hover:text-white cursor-pointer"
                  >
                    إغلاق
                  </button>
                </div>
                {selectedEntry.matchedSignatures.length > 0 && (
                  <div className="text-[11px] text-red-300 font-sans">
                    الأنماط المطابقة: {selectedEntry.matchedSignatures.join(' · ')}
                  </div>
                )}
                <pre className="text-[11px] text-gray-200 whitespace-pre-wrap break-all leading-relaxed" dir="ltr">
                  {selectedEntry.raw}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
