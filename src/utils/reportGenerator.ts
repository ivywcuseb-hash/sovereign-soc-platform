import type { ExtractedIoCRecord } from './forensics';

export type ReportClassification = 'TOP_SECRET' | 'CONFIDENTIAL' | 'OFFICIAL';

export interface ReportEvidenceItem {
  id: string;
  fileName: string;
  fileSize: number;
  mimeType: string;
  sha256: string;
  sha1?: string;
  md5?: string;
  storageStatus?: string;
  investigationId: string;
  createdAt: string;
  analysis?: {
    detectedFileType?: string;
    headerHex?: string;
    entropy?: number;
    elaScore?: number;
    authenticityScore?: number;
    verdict?: string;
    riskLevel?: string;
    isMasqueraded?: boolean;
    exif?: {
      hasExif?: boolean;
      make?: string;
      model?: string;
      dateTimeOriginal?: string;
      gps?: {
        latitude: number;
        longitude: number;
      };
    };
  };
}

export interface ReportCustodyEntry {
  id: string;
  evidenceId: string;
  actionCategory?: string;
  action: string;
  officerName?: string;
  location: string;
  notes?: string;
  timestamp: string;
  prevHash?: string;
  recordHash?: string;
}

export interface ForensicDossierInput {
  caseNumber: string;
  title: string;
  classification: ReportClassification;
  examinerName: string;
  examinerEmail: string;
  department: string;
  investigationTitle: string;
  summary: string;
  generatedAt: string;
  evidenceItems: ReportEvidenceItem[];
  custodyEntries: ReportCustodyEntry[];
  custodyChainVerified: boolean;
  iocs: ExtractedIoCRecord[];
  includeEvidenceHashes: boolean;
  includeExifEla: boolean;
  includeCustodyChain: boolean;
  includeIoCs: boolean;
}

function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / 1024).toFixed(2)} KB`;
}

export function getClassificationLabel(c: ReportClassification): string {
  if (c === 'TOP_SECRET') return 'سري للغاية — TOP SECRET';
  if (c === 'CONFIDENTIAL') return 'سري ومقيد — CONFIDENTIAL';
  return 'تقرير جنائي رسمي موثق — OFFICIAL FORENSIC DOSSIER';
}

export async function computeReportSealSha256(dossier: ForensicDossierInput): Promise<string> {
  const canonicalPayload = JSON.stringify({
    caseNumber: dossier.caseNumber,
    title: dossier.title,
    classification: dossier.classification,
    examinerName: dossier.examinerName,
    examinerEmail: dossier.examinerEmail,
    generatedAt: dossier.generatedAt,
    evidenceHashes: dossier.evidenceItems.map((e) => ({
      id: e.id,
      fileName: e.fileName,
      sha256: e.sha256,
      sha1: e.sha1 || '',
      md5: e.md5 || '',
    })),
    custodyHashes: dossier.custodyEntries.slice(0, 50).map((c) => c.recordHash || ''),
    iocCount: dossier.iocs.length,
  });

  const enc = new TextEncoder();
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(canonicalPayload));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateOfficialHtmlReport(
  dossier: ForensicDossierInput,
  reportSealSha256: string
): string {
  const classLabel = getClassificationLabel(dossier.classification);
  const classColor =
    dossier.classification === 'TOP_SECRET'
      ? '#b91c1c'
      : dossier.classification === 'CONFIDENTIAL'
      ? '#b45309'
      : '#0f766e';

  const evidenceRows = dossier.evidenceItems
    .map(
      (ev, idx) => `
      <tr>
        <td>${idx + 1}</td>
        <td>
          <strong>${escapeHtml(ev.fileName)}</strong><br/>
          <span class="muted">${formatBytes(ev.fileSize || 0)} • ${escapeHtml(ev.mimeType)}</span>
        </td>
        <td>
          ${escapeHtml(ev.analysis?.detectedFileType || ev.mimeType)}<br/>
          <span class="mono muted">${escapeHtml(ev.analysis?.headerHex || '')}</span>
          ${ev.analysis?.isMasqueraded ? '<br/><span class="badge-danger">انتحال امتداد (Masquerade)</span>' : ''}
        </td>
        <td>
          <span class="badge ${(ev.analysis?.authenticityScore ?? 0) >= 80 ? 'badge-ok' : (ev.analysis?.authenticityScore ?? 0) >= 50 ? 'badge-warn' : 'badge-danger'}">
            ${ev.analysis?.authenticityScore ?? 0}% (${escapeHtml(ev.analysis?.riskLevel || 'غير مصنف')})
          </span>
          ${ev.analysis?.elaScore ? `<br/><span class="muted">ELA Tamper: ${ev.analysis.elaScore}%</span>` : ''}
        </td>
        <td class="mono hash-cell" dir="ltr">
          <div><strong>SHA-256:</strong> ${escapeHtml(ev.sha256)}</div>
          ${ev.sha1 ? `<div class="muted"><strong>SHA-1:</strong> ${escapeHtml(ev.sha1)}</div>` : ''}
          ${ev.md5 ? `<div class="muted"><strong>MD5:</strong> ${escapeHtml(ev.md5)}</div>` : ''}
        </td>
      </tr>`
    )
    .join('\n');

  const exifRows = dossier.evidenceItems
    .filter((ev) => ev.analysis?.exif?.hasExif || ev.analysis?.elaScore)
    .map(
      (ev) => `
      <tr>
        <td><strong>${escapeHtml(ev.fileName)}</strong></td>
        <td dir="ltr" class="mono">${escapeHtml(
          [ev.analysis?.exif?.make, ev.analysis?.exif?.model].filter(Boolean).join(' ') || '—'
        )}</td>
        <td dir="ltr" class="mono">${escapeHtml(ev.analysis?.exif?.dateTimeOriginal || '—')}</td>
        <td dir="ltr" class="mono">${
          ev.analysis?.exif?.gps
            ? `${ev.analysis.exif.gps.latitude}, ${ev.analysis.exif.gps.longitude}`
            : 'غير متوفر'
        }</td>
        <td>${ev.analysis?.elaScore !== undefined ? `${ev.analysis.elaScore}%` : '—'}</td>
      </tr>`
    )
    .join('\n');

  const custodyRows = dossier.custodyEntries
    .slice(0, 60)
    .map(
      (c, i) => `
      <tr>
        <td>${i + 1}</td>
        <td class="mono" dir="ltr">${escapeHtml(c.timestamp)}</td>
        <td><strong>${escapeHtml(c.action)}</strong><br/><span class="muted">${escapeHtml(c.notes || '')}</span></td>
        <td>${escapeHtml(c.officerName || dossier.examinerName)}<br/><span class="muted">${escapeHtml(c.location)}</span></td>
        <td class="mono hash-cell" dir="ltr">${escapeHtml(c.recordHash || '—')}</td>
      </tr>`
    )
    .join('\n');

  const iocRows = dossier.iocs
    .slice(0, 100)
    .map(
      (ioc, i) => `
      <tr>
        <td>${i + 1}</td>
        <td class="mono">${escapeHtml(ioc.type.toUpperCase())}</td>
        <td><span class="badge ${ioc.severity === 'critical' ? 'badge-danger' : ioc.severity === 'high' ? 'badge-warn' : 'badge-ok'}">${escapeHtml(ioc.severity.toUpperCase())}</span></td>
        <td class="mono hash-cell" dir="ltr">${escapeHtml(ioc.value)}</td>
        <td class="mono">×${ioc.occurrences} (أسطر: ${escapeHtml(ioc.lines.slice(0, 6).join(', '))})</td>
        <td>${escapeHtml(ioc.details)}</td>
      </tr>`
    )
    .join('\n');

  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data: https:; script-src 'none'; object-src 'none'; base-uri 'none';" />
  <title>تقرير جنائي موثق | ${escapeHtml(dossier.caseNumber)}</title>
  <style>
    @page { size: A4; margin: 16mm; }
    * { box-sizing: border-box; }
    body {
      font-family: "Segoe UI", Tahoma, Arial, sans-serif;
      background: #f3f4f6;
      color: #111827;
      margin: 0;
      padding: 24px;
      line-height: 1.6;
    }
    .sheet {
      max-width: 1050px;
      margin: 0 auto;
      background: #ffffff;
      border: 1px solid #d1d5db;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.08);
    }
    .class-bar {
      background: ${classColor};
      color: #ffffff;
      text-align: center;
      font-weight: 700;
      font-size: 12px;
      letter-spacing: 1px;
      padding: 8px 16px;
    }
    .header {
      padding: 24px 32px;
      border-bottom: 2px solid #111827;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 20px;
      flex-wrap: wrap;
    }
    .brand-title { font-size: 20px; font-weight: 800; color: #0b0f19; margin: 0; }
    .brand-sub { font-size: 12px; color: #6b7280; font-family: monospace; margin-top: 4px; }
    .meta-box {
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 10px 14px;
      font-size: 12px;
      min-width: 250px;
    }
    .content { padding: 28px 32px; }
    .grid-2 {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 14px;
      margin-bottom: 22px;
    }
    .card {
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 14px;
      font-size: 13px;
    }
    .card-label { font-size: 11px; color: #6b7280; font-weight: 700; margin-bottom: 4px; }
    h2 {
      font-size: 15px;
      color: #0b0f19;
      border-right: 4px solid #b45309;
      padding-right: 10px;
      margin: 26px 0 12px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
      margin-bottom: 18px;
    }
    th, td {
      border: 1px solid #e5e7eb;
      padding: 9px 10px;
      text-align: right;
      vertical-align: top;
    }
    th { background: #111827; color: #ffffff; font-weight: 600; font-size: 11px; }
    tr:nth-child(even) td { background: #f9fafb; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; }
    .hash-cell { word-break: break-all; max-width: 310px; }
    .muted { color: #6b7280; font-size: 11px; }
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 11px;
      font-weight: 700;
    }
    .badge-ok { background: #dcfce7; color: #166534; }
    .badge-warn { background: #fef3c7; color: #92400e; }
    .badge-danger { background: #fee2e2; color: #991b1b; }
    .seal-box {
      margin-top: 28px;
      border: 2px solid #0b0f19;
      border-radius: 10px;
      padding: 18px 20px;
      background: #fffbeb;
    }
    .seal-hash {
      margin-top: 8px;
      padding: 10px;
      background: #111827;
      color: #34d399;
      border-radius: 6px;
      font-family: monospace;
      font-size: 12px;
      word-break: break-all;
      direction: ltr;
      text-align: left;
    }
    @media print {
      body { background: #ffffff; padding: 0; }
      .sheet { box-shadow: none; border: none; }
    }
  </style>
</head>
<body>
  <div class="sheet">
    <div class="class-bar">${escapeHtml(classLabel)}</div>
    <div class="header">
      <div>
        <h1 class="brand-title">${escapeHtml(dossier.title)}</h1>
        <div class="brand-sub">SOVEREIGN DIGITAL FORENSICS CORE • CERTIFIED EVIDENCE DOSSIER</div>
      </div>
      <div class="meta-box">
        <div><strong>رقم القضية:</strong> <span class="mono">${escapeHtml(dossier.caseNumber)}</span></div>
        <div><strong>تاريخ الإصدار:</strong> <span class="mono" dir="ltr">${escapeHtml(dossier.generatedAt)}</span></div>
        <div><strong>عدد الأدلة الموثقة:</strong> ${dossier.evidenceItems.length}</div>
      </div>
    </div>

    <div class="content">
      <div class="grid-2">
        <div class="card">
          <div class="card-label">المحقق المسؤول والجهة</div>
          <div><strong>${escapeHtml(dossier.examinerName)}</strong></div>
          <div class="muted">${escapeHtml(dossier.department)} • ${escapeHtml(dossier.examinerEmail)}</div>
        </div>
        <div class="card">
          <div class="card-label">ملف التحقيق المرتبط</div>
          <div><strong>${escapeHtml(dossier.investigationTitle)}</strong></div>
          <div class="muted">تكامل سلسلة الحيازة: ${dossier.custodyChainVerified ? 'موثق بنسبة 100% (SHA-256 Verified)' : 'تحذير فحص السلسلة'}</div>
        </div>
      </div>

      ${dossier.summary ? `
      <h2>الخلاصة الفنية والتقييم الجنائي</h2>
      <div class="card" style="white-space: pre-wrap;">${escapeHtml(dossier.summary)}</div>
      ` : ''}

      ${dossier.includeEvidenceHashes ? `
      <h2>جرد الأدلة الرقمية وبصمات التحقق التشفيرية (SHA-256 Registry)</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>اسم الملف والحجم</th>
            <th>الترويسة الفعلية (Magic Bytes)</th>
            <th>الأصالة والمخاطر</th>
            <th>البصمات التشفيرية (SHA-256 / SHA-1 / MD5)</th>
          </tr>
        </thead>
        <tbody>
          ${evidenceRows || '<tr><td colspan="5">لا توجد أدلة محددة في هذا التقرير.</td></tr>'}
        </tbody>
      </table>
      ` : ''}

      ${dossier.includeExifEla && exifRows ? `
      <h2>نتائج فحص EXIF والـ GPS ومستوى الخطأ الضغطي (ELA)</h2>
      <table>
        <thead>
          <tr>
            <th>الملف</th>
            <th>الجهاز / الكاميرا</th>
            <th>تاريخ الالتقاط الأصلي</th>
            <th>إحداثيات GPS</th>
            <th>تقييم تلاعب ELA</th>
          </tr>
        </thead>
        <tbody>
          ${exifRows}
        </tbody>
      </table>
      ` : ''}

      ${dossier.includeIoCs && dossier.iocs.length > 0 ? `
      <h2>مؤشرات الاختراق المستخرجة من السجلات (Extracted IoCs — ${dossier.iocs.length})</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>النوع</th>
            <th>الخطورة</th>
            <th>المؤشر (IoC Value)</th>
            <th>التكرار والأسطر</th>
            <th>التوصيف الأمني</th>
          </tr>
        </thead>
        <tbody>
          ${iocRows}
        </tbody>
      </table>
      ` : ''}

      ${dossier.includeCustodyChain && dossier.custodyEntries.length > 0 ? `
      <h2>سجل سلسلة الحيازة المشفر (Cryptographic Chain of Custody Ledger)</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>الطابع الزمني (ISO-8601)</th>
            <th>الإجراء الجنائي</th>
            <th>المحقق والموقع</th>
            <th>بصمة الكتلة (Record SHA-256)</th>
          </tr>
        </thead>
        <tbody>
          ${custodyRows}
        </tbody>
      </table>
      ` : ''}

      <div class="seal-box">
        <strong>الختم الرقمي التشفيري لاعتماد التقرير (Report Attestation Seal — Web Crypto SHA-256)</strong>
        <p class="muted" style="margin: 4px 0 0;">
          أي تعديل في بيانات القضية أو بصمات الأدلة المدرجة يبطل هذه البصمة عند إعادة التحقق.
        </p>
        <div class="seal-hash">${escapeHtml(reportSealSha256)}</div>
      </div>
    </div>
  </div>
</body>
</html>`;
}

export function generateOfficialCsvManifest(dossier: ForensicDossierInput, reportSealSha256: string): string {
  const headers = [
    'CaseNumber',
    'ReportSealSHA256',
    'EvidenceIndex',
    'FileName',
    'FileSizeBytes',
    'MimeType',
    'DetectedMagicType',
    'SHA256',
    'SHA1',
    'MD5',
    'AuthenticityScore',
    'RiskLevel',
    'ELAScore',
    'Masqueraded',
    'StorageStatus',
    'CreatedAt',
  ];

  const escapeCsv = (val: unknown) => {
    let s = String(val ?? '');
    // Neutralize CSV / Spreadsheet Formula Injection (CWE-1236)
    if (/^[=+\-@\t\r]/.test(s)) {
      s = `'${s}`;
    }
    return `"${s.replace(/"/g, '""')}"`;
  };

  const rows = dossier.evidenceItems.map((ev, idx) =>
    [
      dossier.caseNumber,
      reportSealSha256,
      idx + 1,
      ev.fileName,
      ev.fileSize,
      ev.mimeType,
      ev.analysis?.detectedFileType || '',
      ev.sha256,
      ev.sha1 || '',
      ev.md5 || '',
      ev.analysis?.authenticityScore ?? '',
      ev.analysis?.riskLevel || '',
      ev.analysis?.elaScore ?? '',
      ev.analysis?.isMasqueraded ? 'YES' : 'NO',
      ev.storageStatus || 'local',
      ev.createdAt,
    ]
      .map(escapeCsv)
      .join(',')
  );

  // Prepend UTF-8 BOM for clean Arabic Excel support
  return '\uFEFF' + [headers.join(','), ...rows].join('\n');
}

export function generateOfficialJsonDossier(
  dossier: ForensicDossierInput,
  reportSealSha256: string
): string {
  return JSON.stringify(
    {
      schemaVersion: 'sovereign-forensic-dossier-v2.5',
      caseNumber: dossier.caseNumber,
      title: dossier.title,
      classification: dossier.classification,
      examiner: {
        name: dossier.examinerName,
        email: dossier.examinerEmail,
        department: dossier.department,
      },
      investigationTitle: dossier.investigationTitle,
      generatedAt: dossier.generatedAt,
      summary: dossier.summary,
      reportSealSha256,
      custodyChainVerified: dossier.custodyChainVerified,
      evidenceCount: dossier.evidenceItems.length,
      evidenceInventory: dossier.evidenceItems.map((ev) => ({
        id: ev.id,
        fileName: ev.fileName,
        fileSize: ev.fileSize,
        mimeType: ev.mimeType,
        sha256: ev.sha256,
        sha1: ev.sha1 || '',
        md5: ev.md5 || '',
        storageStatus: ev.storageStatus || 'local',
        createdAt: ev.createdAt,
        forensicAnalysis: ev.analysis || {},
      })),
      ...(dossier.includeIoCs ? { extractedIoCs: dossier.iocs } : {}),
      ...(dossier.includeCustodyChain ? { custodyLedger: dossier.custodyEntries } : {}),
    },
    null,
    2
  );
}
