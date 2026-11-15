import initSqlJs, { type Database, type SqlValue } from 'sql.js';

export type BrowserEngineType =
  | 'chromium_history'
  | 'firefox_places'
  | 'safari_history'
  | 'generic_sqlite';

export type LocalUrlRiskHint =
  | 'suspicious_keyword'
  | 'ip_host'
  | 'high_risk_tld'
  | 'download_payload'
  | 'insecure_http'
  | 'normal';

export interface SqliteTableSummary {
  name: string;
  rowCount: number;
  columns: string[];
}

export interface BrowserUrlRecord {
  id: string;
  url: string;
  domain: string;
  title: string;
  visitCount: number;
  typedCount: number;
  lastVisitIso: string | null;
  lastVisitFormatted: string;
  rawTimestamp: number | null;
  sourceTable: string;
  riskHint: LocalUrlRiskHint;
}

export interface BrowserVisitEvent {
  id: string;
  url: string;
  domain: string;
  title: string;
  visitIso: string | null;
  visitFormatted: string;
  rawTimestamp: number | null;
  transitionType: string;
  durationSeconds: number | null;
  sourceTable: string;
  riskHint: LocalUrlRiskHint;
}

export interface BrowserDownloadRecord {
  id: string;
  url: string;
  targetPath: string;
  fileName: string;
  mimeType: string;
  totalBytes: number;
  receivedBytes: number;
  startTimeIso: string | null;
  startTimeFormatted: string;
  dangerType: string;
  isDangerousExtension: boolean;
}

export interface BrowserSearchTermRecord {
  term: string;
  url: string;
  visitTimeIso: string | null;
  visitTimeFormatted: string;
  source: 'keyword_search_terms' | 'url_query_param';
}

export interface DomainFrequencyItem {
  domain: string;
  urlCount: number;
  totalVisits: number;
  latestVisitIso: string | null;
  hasFlaggedUrl: boolean;
}

export interface SqliteBrowserForensicsResult {
  fileName: string;
  fileSize: number;
  sqliteVersionHeader: string;
  pageSize: number;
  browserEngine: BrowserEngineType;
  browserLabel: string;
  tables: SqliteTableSummary[];
  urls: BrowserUrlRecord[];
  visits: BrowserVisitEvent[];
  downloads: BrowserDownloadRecord[];
  searchTerms: BrowserSearchTermRecord[];
  topDomains: DomainFrequencyItem[];
  totalUrlsCount: number;
  totalVisitsCount: number;
  flaggedUrlsCount: number;
  dateRangeStart: string | null;
  dateRangeEnd: string | null;
  extractionTimestamp: string;
}

const WEBKIT_EPOCH_OFFSET_US = 11644473600000000; // microseconds between 1601-01-01 and 1970-01-01
const COCOA_EPOCH_OFFSET_SEC = 978307200; // seconds between 1970-01-01 and 2001-01-01

let sqlJsPromise: Promise<Awaited<ReturnType<typeof initSqlJs>>> | null = null;

async function getSqlJs() {
  if (!sqlJsPromise) {
    const isBrowser = typeof window !== 'undefined' && typeof document !== 'undefined';
    sqlJsPromise = initSqlJs(
      isBrowser
        ? { locateFile: () => './sql-wasm.wasm' }
        : { locateFile: (file: string) => `./node_modules/sql.js/dist/${file}` }
    );
  }
  return sqlJsPromise;
}

function formatIsoToArabic(iso: string | null): string {
  if (!iso) return 'غير محدد';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return 'غير محدد';
  return d.toLocaleString('ar-SA', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Converts Chromium WebKit timestamp (microseconds since 1601-01-01 UTC) to ISO string.
 */
export function convertWebKitTimestamp(val: unknown): { iso: string | null; raw: number | null } {
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0) return { iso: null, raw: null };
  // Reasonable Chrome timestamps: between ~1995 and ~2100
  const unixMs = (num - WEBKIT_EPOCH_OFFSET_US) / 1000;
  if (unixMs < 631152000000 || unixMs > 4102444800000) {
    return convertAutoDetectedTimestamp(num);
  }
  return { iso: new Date(unixMs).toISOString(), raw: num };
}

/**
 * Converts Firefox PRTime timestamp (microseconds since 1970-01-01 UTC) to ISO string.
 */
export function convertFirefoxPrTime(val: unknown): { iso: string | null; raw: number | null } {
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0) return { iso: null, raw: null };
  const unixMs = num / 1000;
  if (unixMs < 631152000000 || unixMs > 4102444800000) {
    return convertAutoDetectedTimestamp(num);
  }
  return { iso: new Date(unixMs).toISOString(), raw: num };
}

/**
 * Converts Apple Safari Cocoa timestamp (seconds since 2001-01-01 UTC) to ISO string.
 */
export function convertCocoaTimestamp(val: unknown): { iso: string | null; raw: number | null } {
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0) return { iso: null, raw: null };
  const unixMs = (num + COCOA_EPOCH_OFFSET_SEC) * 1000;
  if (unixMs < 946684800000 || unixMs > 4102444800000) {
    return convertAutoDetectedTimestamp(num);
  }
  return { iso: new Date(unixMs).toISOString(), raw: num };
}

/**
 * Auto-detects timestamp epoch format across Unix s/ms/us, WebKit us, and Cocoa s.
 */
export function convertAutoDetectedTimestamp(val: unknown): { iso: string | null; raw: number | null } {
  if (typeof val === 'string' && /\d{4}-\d{2}-\d{2}/.test(val)) {
    const parsed = new Date(val);
    if (!isNaN(parsed.getTime())) {
      return { iso: parsed.toISOString(), raw: parsed.getTime() };
    }
  }
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0) return { iso: null, raw: null };

  // WebKit microseconds (~1.16e16 to 1.6e16)
  if (num > 12000000000000000 && num < 18000000000000000) {
    const ms = (num - WEBKIT_EPOCH_OFFSET_US) / 1000;
    return { iso: new Date(ms).toISOString(), raw: num };
  }
  // Unix microseconds (~1e15 to 4e15)
  if (num > 900000000000000 && num < 4200000000000000) {
    return { iso: new Date(num / 1000).toISOString(), raw: num };
  }
  // Unix milliseconds (~9e11 to 4e12)
  if (num > 900000000000 && num < 4200000000000) {
    return { iso: new Date(num).toISOString(), raw: num };
  }
  // Unix seconds (~9e8 to 4e9)
  if (num > 900000000 && num < 4200000000) {
    return { iso: new Date(num * 1000).toISOString(), raw: num };
  }
  // Cocoa / Mac Absolute seconds since 2001-01-01 (~1e7 to 1.5e9)
  if (num > 10000000 && num < 1500000000) {
    const ms = (num + COCOA_EPOCH_OFFSET_SEC) * 1000;
    if (ms > 978307200000 && ms < 4102444800000) {
      return { iso: new Date(ms).toISOString(), raw: num };
    }
  }
  return { iso: null, raw: num };
}

function extractDomain(rawUrl: string): string {
  try {
    const u = new URL(rawUrl);
    return u.hostname.toLowerCase() || u.protocol.replace(':', '');
  } catch {
    const match = rawUrl.match(/^https?:\/\/([^/:?#]+)/i);
    return match ? match[1].toLowerCase() : 'local-or-scheme';
  }
}

function classifyLocalUrlRisk(url: string, domain: string): LocalUrlRiskHint {
  const lowerUrl = url.toLowerCase();
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(domain)) {
    return 'ip_host';
  }
  if (
    /\.(onion|top|xyz|tk|ml|ga|cf|gq|ru|su|pw|cc|icu|click|work|buzz)$/i.test(domain) &&
    !domain.endsWith('google.com')
  ) {
    return 'high_risk_tld';
  }
  if (
    /(login[-_.]?verify|secure[-_.]?update|webscr|signin[-_.]?account|auth[-_.]?session|wallet[-_.]?connect|pastebin\.com\/raw|raw\.githubusercontent|discord\.com\/api\/webhooks|api\.telegram\.org|ngrok|duckdns|no-ip|evil|phish|exploit|c2|gate\.php|shell\.php|payload|crack|keygen|stealer)/i.test(
      lowerUrl
    )
  ) {
    return 'suspicious_keyword';
  }
  if (/\.(exe|msi|bat|cmd|ps1|vbs|scr|apk|dmg|pkg|zip|rar|7z|iso)(\?|$)/i.test(lowerUrl)) {
    return 'download_payload';
  }
  if (lowerUrl.startsWith('http://') && !domain.startsWith('localhost') && !domain.startsWith('127.')) {
    return 'insecure_http';
  }
  return 'normal';
}

function decodeChromiumTransition(transitionVal: unknown): string {
  const code = Number(transitionVal);
  if (!Number.isFinite(code)) return 'زيارة ويب';
  const core = code & 0xff;
  const map: Record<number, string> = {
    0: 'رابط منقر (Link)',
    1: 'إدخال مباشر (Typed)',
    2: 'علامة مرجعية (Bookmark)',
    3: 'إطار فرعي تلقائي',
    4: 'إطار فرعي يدوي',
    5: 'إكمال تلقائي (Generated)',
    6: 'صفحة بداية (Start Page)',
    7: 'إرسال نموذج (Form Submit)',
    8: 'إعادة تحميل (Reload)',
    9: 'كلمة مفتاحية (Keyword)',
  };
  return map[core] || `انتقال (${core})`;
}

function decodeFirefoxVisitType(visitType: unknown): string {
  const code = Number(visitType);
  const map: Record<number, string> = {
    1: 'رابط منقر (Link)',
    2: 'إدخال مباشر (Typed)',
    3: 'علامة مرجعية (Bookmark)',
    4: 'تضمين (Embed)',
    5: 'إعادة توجيه دائمة',
    6: 'إعادة توجيه مؤقتة',
    7: 'تنزيل ملف (Download)',
    8: 'إطار فرعي',
    9: 'إعادة تحميل (Reload)',
  };
  return map[code] || 'زيارة Firefox';
}

function decodeChromiumDangerType(dangerCode: unknown): string {
  const code = Number(dangerCode);
  const map: Record<number, string> = {
    0: 'سليم (Not Dangerous)',
    1: 'ملف خطر محتمل (Dangerous File)',
    2: 'رابط خطير (Dangerous URL)',
    3: 'محتوى خطر (Dangerous Content)',
    4: 'ملف غير مألوف (Uncommon)',
    5: 'غير مرغوب فيه (Potentially Unwanted)',
    6: 'مضيف خطير (Dangerous Host)',
    7: 'مرفوض من المستخدم (User Validated)',
    8: 'أرشيف محمي بكلمة مرور',
    9: 'أرشيف غير شائع',
  };
  return map[code] || `تصنيف (${code})`;
}

function queryRows(db: Database, sql: string): Record<string, SqlValue>[] {
  try {
    const res = db.exec(sql);
    if (!res.length) return [];
    const { columns, values } = res[0];
    return values.map((row) => {
      const obj: Record<string, SqlValue> = {};
      columns.forEach((col, i) => {
        obj[col] = row[i];
      });
      return obj;
    });
  } catch {
    return [];
  }
}

export async function analyzeSqliteBrowserDatabase(
  buffer: ArrayBuffer,
  fileName: string
): Promise<SqliteBrowserForensicsResult> {
  const u8 = new Uint8Array(buffer);
  if (u8.length < 100) {
    throw new Error('حجم الملف أصغر من الحد الأدنى لترويسة قواعد بيانات SQLite.');
  }

  const headerStr = new TextDecoder('ascii').decode(u8.subarray(0, 15));
  if (headerStr !== 'SQLite format 3') {
    throw new Error('الملف المرفوع ليس قاعدة بيانات SQLite3 صالحة (ترويسة "SQLite format 3" مفقودة).');
  }

  const rawPageSize = (u8[16] << 8) | u8[17];
  const pageSize = rawPageSize === 1 ? 65536 : rawPageSize;

  const SQL = await getSqlJs();
  const db = new SQL.Database(u8);

  try {
    const masterRows = queryRows(
      db,
      `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`
    );
    const tableNames = masterRows.map((r) => String(r.name || '')).filter(Boolean);

    const tables: SqliteTableSummary[] = [];
    for (const tName of tableNames) {
      const safeName = tName.replace(/"/g, '""');
      const infoRows = queryRows(db, `PRAGMA table_info("${safeName}")`);
      const countRows = queryRows(db, `SELECT COUNT(*) AS cnt FROM "${safeName}"`);
      tables.push({
        name: tName,
        rowCount: Number(countRows[0]?.cnt || 0),
        columns: infoRows.map((c) => String(c.name || '')),
      });
    }

    const tableSet = new Set(tableNames.map((t) => t.toLowerCase()));
    let browserEngine: BrowserEngineType = 'generic_sqlite';
    let browserLabel = 'قاعدة بيانات SQLite عامة';

    if (tableSet.has('urls') && tableSet.has('visits')) {
      browserEngine = 'chromium_history';
      browserLabel = 'Chromium / Chrome / Edge / Brave (History SQLite)';
    } else if (tableSet.has('moz_places')) {
      browserEngine = 'firefox_places';
      browserLabel = 'Mozilla Firefox (places.sqlite)';
    } else if (tableSet.has('history_items') && tableSet.has('history_visits')) {
      browserEngine = 'safari_history';
      browserLabel = 'Apple Safari (History.db)';
    }

    const urls: BrowserUrlRecord[] = [];
    const visits: BrowserVisitEvent[] = [];
    const downloads: BrowserDownloadRecord[] = [];
    const searchTerms: BrowserSearchTermRecord[] = [];
    const seenSearch = new Set<string>();

    if (browserEngine === 'chromium_history') {
      const urlRows = queryRows(
        db,
        `SELECT id, url, title, visit_count, typed_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1500`
      );
      for (const r of urlRows) {
        const urlStr = String(r.url || '').trim();
        if (!urlStr) continue;
        const domain = extractDomain(urlStr);
        const { iso, raw } = convertWebKitTimestamp(r.last_visit_time);
        urls.push({
          id: `url-${r.id ?? urls.length}`,
          url: urlStr,
          domain,
          title: String(r.title || '').trim() || domain,
          visitCount: Number(r.visit_count || 1),
          typedCount: Number(r.typed_count || 0),
          lastVisitIso: iso,
          lastVisitFormatted: formatIsoToArabic(iso),
          rawTimestamp: raw,
          sourceTable: 'urls',
          riskHint: classifyLocalUrlRisk(urlStr, domain),
        });
      }

      const visitRows = queryRows(
        db,
        `SELECT v.id AS vid, u.url AS url, u.title AS title, v.visit_time AS visit_time, v.transition AS transition, v.visit_duration AS visit_duration
         FROM visits v LEFT JOIN urls u ON v.url = u.id
         ORDER BY v.visit_time DESC LIMIT 2000`
      );
      for (const r of visitRows) {
        const urlStr = String(r.url || '').trim();
        if (!urlStr) continue;
        const domain = extractDomain(urlStr);
        const { iso, raw } = convertWebKitTimestamp(r.visit_time);
        const durMicros = Number(r.visit_duration || 0);
        visits.push({
          id: `visit-${r.vid ?? visits.length}`,
          url: urlStr,
          domain,
          title: String(r.title || '').trim() || domain,
          visitIso: iso,
          visitFormatted: formatIsoToArabic(iso),
          rawTimestamp: raw,
          transitionType: decodeChromiumTransition(r.transition),
          durationSeconds: durMicros > 0 ? Math.round(durMicros / 1000000) : null,
          sourceTable: 'visits',
          riskHint: classifyLocalUrlRisk(urlStr, domain),
        });
      }

      if (tableSet.has('downloads')) {
        const dlRows = queryRows(
          db,
          `SELECT d.id AS did, d.target_path AS target_path, d.current_path AS current_path, d.tab_url AS tab_url, d.start_time AS start_time, d.received_bytes AS received_bytes, d.total_bytes AS total_bytes, d.danger_type AS danger_type, d.mime_type AS mime_type,
                  (SELECT url FROM downloads_url_chains c WHERE c.id = d.id ORDER BY c.chain_index DESC LIMIT 1) AS chain_url
           FROM downloads d ORDER BY d.start_time DESC LIMIT 300`
        );
        for (const d of dlRows) {
          const targetPath = String(d.target_path || d.current_path || '');
          const dlUrl = String(d.chain_url || d.tab_url || '');
          const file = targetPath.split(/[/\\]/).pop() || dlUrl.split('/').pop() || 'ملف غير مسمى';
          const { iso } = convertWebKitTimestamp(d.start_time);
          const dangerCode = Number(d.danger_type || 0);
          const isDangerousExtension =
            /\.(exe|msi|bat|cmd|ps1|vbs|scr|apk|jar|hta|iso)$/i.test(file) || dangerCode > 0;
          downloads.push({
            id: `dl-${d.did ?? downloads.length}`,
            url: dlUrl || 'غير متوفر',
            targetPath: targetPath || 'غير مسجل',
            fileName: file,
            mimeType: String(d.mime_type || 'application/octet-stream'),
            totalBytes: Number(d.total_bytes || 0),
            receivedBytes: Number(d.received_bytes || 0),
            startTimeIso: iso,
            startTimeFormatted: formatIsoToArabic(iso),
            dangerType: decodeChromiumDangerType(d.danger_type),
            isDangerousExtension,
          });
        }
      }

      if (tableSet.has('keyword_search_terms')) {
        const kwRows = queryRows(
          db,
          `SELECT k.term AS term, u.url AS url, u.last_visit_time AS last_visit_time
           FROM keyword_search_terms k LEFT JOIN urls u ON k.url_id = u.id
           ORDER BY u.last_visit_time DESC LIMIT 300`
        );
        for (const k of kwRows) {
          const term = String(k.term || '').trim();
          const urlStr = String(k.url || '').trim();
          if (!term) continue;
          const dedup = `${term.toLowerCase()}::${urlStr}`;
          if (seenSearch.has(dedup)) continue;
          seenSearch.add(dedup);
          const { iso } = convertWebKitTimestamp(k.last_visit_time);
          searchTerms.push({
            term,
            url: urlStr,
            visitTimeIso: iso,
            visitTimeFormatted: formatIsoToArabic(iso),
            source: 'keyword_search_terms',
          });
        }
      }
    } else if (browserEngine === 'firefox_places') {
      const placeRows = queryRows(
        db,
        `SELECT id, url, title, visit_count, typed, last_visit_date FROM moz_places ORDER BY last_visit_date DESC LIMIT 1500`
      );
      for (const r of placeRows) {
        const urlStr = String(r.url || '').trim();
        if (!urlStr) continue;
        const domain = extractDomain(urlStr);
        const { iso, raw } = convertFirefoxPrTime(r.last_visit_date);
        urls.push({
          id: `ff-url-${r.id ?? urls.length}`,
          url: urlStr,
          domain,
          title: String(r.title || '').trim() || domain,
          visitCount: Number(r.visit_count || 1),
          typedCount: Number(r.typed || 0),
          lastVisitIso: iso,
          lastVisitFormatted: formatIsoToArabic(iso),
          rawTimestamp: raw,
          sourceTable: 'moz_places',
          riskHint: classifyLocalUrlRisk(urlStr, domain),
        });
      }

      if (tableSet.has('moz_historyvisits')) {
        const visitRows = queryRows(
          db,
          `SELECT hv.id AS vid, p.url AS url, p.title AS title, hv.visit_date AS visit_date, hv.visit_type AS visit_type
           FROM moz_historyvisits hv LEFT JOIN moz_places p ON hv.place_id = p.id
           ORDER BY hv.visit_date DESC LIMIT 2000`
        );
        for (const r of visitRows) {
          const urlStr = String(r.url || '').trim();
          if (!urlStr) continue;
          const domain = extractDomain(urlStr);
          const { iso, raw } = convertFirefoxPrTime(r.visit_date);
          visits.push({
            id: `ff-visit-${r.vid ?? visits.length}`,
            url: urlStr,
            domain,
            title: String(r.title || '').trim() || domain,
            visitIso: iso,
            visitFormatted: formatIsoToArabic(iso),
            rawTimestamp: raw,
            transitionType: decodeFirefoxVisitType(r.visit_type),
            durationSeconds: null,
            sourceTable: 'moz_historyvisits',
            riskHint: classifyLocalUrlRisk(urlStr, domain),
          });
        }
      }
    } else if (browserEngine === 'safari_history') {
      const itemRows = queryRows(
        db,
        `SELECT hi.id AS id, hi.url AS url, hi.visit_count AS visit_count,
                (SELECT hv.title FROM history_visits hv WHERE hv.history_item = hi.id ORDER BY hv.visit_time DESC LIMIT 1) AS title,
                (SELECT MAX(hv.visit_time) FROM history_visits hv WHERE hv.history_item = hi.id) AS last_vt
         FROM history_items hi ORDER BY last_vt DESC LIMIT 1500`
      );
      for (const r of itemRows) {
        const urlStr = String(r.url || '').trim();
        if (!urlStr) continue;
        const domain = extractDomain(urlStr);
        const { iso, raw } = convertCocoaTimestamp(r.last_vt);
        urls.push({
          id: `sf-url-${r.id ?? urls.length}`,
          url: urlStr,
          domain,
          title: String(r.title || '').trim() || domain,
          visitCount: Number(r.visit_count || 1),
          typedCount: 0,
          lastVisitIso: iso,
          lastVisitFormatted: formatIsoToArabic(iso),
          rawTimestamp: raw,
          sourceTable: 'history_items',
          riskHint: classifyLocalUrlRisk(urlStr, domain),
        });
      }

      const visitRows = queryRows(
        db,
        `SELECT hv.id AS vid, hi.url AS url, hv.title AS title, hv.visit_time AS visit_time, hv.load_successful AS load_successful
         FROM history_visits hv LEFT JOIN history_items hi ON hv.history_item = hi.id
         ORDER BY hv.visit_time DESC LIMIT 2000`
      );
      for (const r of visitRows) {
        const urlStr = String(r.url || '').trim();
        if (!urlStr) continue;
        const domain = extractDomain(urlStr);
        const { iso, raw } = convertCocoaTimestamp(r.visit_time);
        visits.push({
          id: `sf-visit-${r.vid ?? visits.length}`,
          url: urlStr,
          domain,
          title: String(r.title || '').trim() || domain,
          visitIso: iso,
          visitFormatted: formatIsoToArabic(iso),
          rawTimestamp: raw,
          transitionType: r.load_successful ? 'زيارة Safari ناجحة' : 'زيارة Safari',
          durationSeconds: null,
          sourceTable: 'history_visits',
          riskHint: classifyLocalUrlRisk(urlStr, domain),
        });
      }
    } else {
      // Generic SQLite table scanner: look for any columns containing URLs and timestamps
      const urlColRegex = /^(url|uri|link|href|website|page_url|tab_url|target_url|origin|host|domain)$/i;
      const titleColRegex = /^(title|name|label|subject|page_title)$/i;
      const timeColRegex = /(time|date|visited|created|updated|timestamp)/i;

      for (const tbl of tables) {
        if (tbl.rowCount === 0) continue;
        const safeName = tbl.name.replace(/"/g, '""');
        const rows = queryRows(db, `SELECT * FROM "${safeName}" LIMIT 1000`);
        const urlCols = tbl.columns.filter((c) => urlColRegex.test(c));
        const titleCol = tbl.columns.find((c) => titleColRegex.test(c));
        const timeCol = tbl.columns.find((c) => timeColRegex.test(c));

        for (let rIdx = 0; rIdx < rows.length; rIdx++) {
          const row = rows[rIdx];
          const candidateValues: string[] = [];
          if (urlCols.length > 0) {
            for (const c of urlCols) {
              if (row[c] != null) candidateValues.push(String(row[c]));
            }
          } else {
            for (const c of tbl.columns) {
              const v = row[c];
              if (typeof v === 'string' && /https?:\/\//i.test(v)) {
                candidateValues.push(v);
              }
            }
          }

          for (const rawVal of candidateValues) {
            const urlMatches = rawVal.match(/https?:\/\/[^\s"'<>]+/gi) || (/^[a-z0-9.-]+\.[a-z]{2,}/i.test(rawVal) ? [`https://${rawVal}`] : []);
            for (const uStr of urlMatches) {
              const domain = extractDomain(uStr);
              const { iso, raw } = timeCol ? convertAutoDetectedTimestamp(row[timeCol]) : { iso: null, raw: null };
              const hint = classifyLocalUrlRisk(uStr, domain);
              urls.push({
                id: `gen-${tbl.name}-${rIdx}-${urls.length}`,
                url: uStr,
                domain,
                title: titleCol && row[titleCol] ? String(row[titleCol]) : domain,
                visitCount: Number(row['visit_count'] || 1),
                typedCount: Number(row['typed_count'] || 0),
                lastVisitIso: iso,
                lastVisitFormatted: formatIsoToArabic(iso),
                rawTimestamp: raw,
                sourceTable: tbl.name,
                riskHint: hint,
              });
              if (iso) {
                visits.push({
                  id: `gen-v-${tbl.name}-${rIdx}-${visits.length}`,
                  url: uStr,
                  domain,
                  title: titleCol && row[titleCol] ? String(row[titleCol]) : domain,
                  visitIso: iso,
                  visitFormatted: formatIsoToArabic(iso),
                  rawTimestamp: raw,
                  transitionType: `سجل من جدول ${tbl.name}`,
                  durationSeconds: null,
                  sourceTable: tbl.name,
                  riskHint: hint,
                });
              }
            }
          }
        }
      }
    }

    // Extract search queries embedded inside search engine URLs as well
    for (const u of urls) {
      try {
        const parsed = new URL(u.url);
        const q = parsed.searchParams.get('q') || parsed.searchParams.get('query') || parsed.searchParams.get('p') || parsed.searchParams.get('wd');
        if (q && q.trim().length > 1) {
          const dedup = `${q.trim().toLowerCase()}::${u.url}`;
          if (!seenSearch.has(dedup)) {
            seenSearch.add(dedup);
            searchTerms.push({
              term: q.trim(),
              url: u.url,
              visitTimeIso: u.lastVisitIso,
              visitTimeFormatted: u.lastVisitFormatted,
              source: 'url_query_param',
            });
          }
        }
      } catch {
        // Ignore unparseable URLs
      }
    }

    // Compute Domain Frequency Map
    const domainMap = new Map<string, DomainFrequencyItem>();
    for (const u of urls) {
      const prev = domainMap.get(u.domain);
      const isFlagged = u.riskHint !== 'normal';
      if (prev) {
        prev.urlCount += 1;
        prev.totalVisits += u.visitCount;
        prev.hasFlaggedUrl = prev.hasFlaggedUrl || isFlagged;
        if (u.lastVisitIso && (!prev.latestVisitIso || u.lastVisitIso > prev.latestVisitIso)) {
          prev.latestVisitIso = u.lastVisitIso;
        }
      } else {
        domainMap.set(u.domain, {
          domain: u.domain,
          urlCount: 1,
          totalVisits: u.visitCount,
          latestVisitIso: u.lastVisitIso,
          hasFlaggedUrl: isFlagged,
        });
      }
    }

    const topDomains = Array.from(domainMap.values())
      .sort((a, b) => Number(b.hasFlaggedUrl) - Number(a.hasFlaggedUrl) || b.totalVisits - a.totalVisits)
      .slice(0, 60);

    const allDates = [
      ...urls.map((u) => u.lastVisitIso).filter((d): d is string => Boolean(d)),
      ...visits.map((v) => v.visitIso).filter((d): d is string => Boolean(d)),
    ].sort();

    const flaggedUrlsCount = urls.filter((u) => u.riskHint !== 'normal').length;

    return {
      fileName,
      fileSize: buffer.byteLength,
      sqliteVersionHeader: headerStr,
      pageSize,
      browserEngine,
      browserLabel,
      tables,
      urls,
      visits,
      downloads,
      searchTerms: searchTerms.slice(0, 250),
      topDomains,
      totalUrlsCount: urls.length,
      totalVisitsCount: visits.length || urls.reduce((sum, u) => sum + u.visitCount, 0),
      flaggedUrlsCount,
      dateRangeStart: allDates.length > 0 ? allDates[0] : null,
      dateRangeEnd: allDates.length > 0 ? allDates[allDates.length - 1] : null,
      extractionTimestamp: new Date().toISOString(),
    };
  } finally {
    db.close();
  }
}
