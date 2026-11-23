import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  getClassificationLabel,
  type ForensicDossierInput,
} from './reportGenerator';
import {
  formatPdfText,
  hasArabicText,
  wrapAndFormatPdfLines,
} from './arabicPdfText';

interface FontBundle {
  normal: string;
  bold: string;
}

let cachedFontBundle: FontBundle | null = null;

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const sub = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode(...sub);
  }
  return btoa(binary);
}

async function loadUnicodeFonts(): Promise<FontBundle> {
  if (cachedFontBundle) return cachedFontBundle;

  const [normalRes, boldRes] = await Promise.all([
    fetch('./fonts/DejaVuSans.ttf'),
    fetch('./fonts/DejaVuSans-Bold.ttf'),
  ]);

  if (!normalRes.ok || !boldRes.ok) {
    throw new Error('تعذر تحميل خطوط Unicode العربية المطلوبة لتوليد ملف PDF.');
  }

  const [normalBuf, boldBuf] = await Promise.all([
    normalRes.arrayBuffer(),
    boldRes.arrayBuffer(),
  ]);

  cachedFontBundle = {
    normal: arrayBufferToBase64(normalBuf),
    bold: arrayBufferToBase64(boldBuf),
  };
  return cachedFontBundle;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / 1024).toFixed(2)} KB`;
}

function getLastTableFinalY(doc: jsPDF, fallbackY: number): number {
  const withTable = doc as jsPDF & { lastAutoTable?: { finalY?: number } };
  return withTable.lastAutoTable?.finalY ?? fallbackY;
}

function wrapCellText(
  doc: jsPDF,
  text: string,
  colWidthMm: number,
  fontSize: number,
  bold = false
): string {
  doc.setFont('DejaVuSans', bold ? 'bold' : 'normal');
  doc.setFontSize(fontSize);
  const innerWidth = Math.max(8, colWidthMm - 4);
  const lines = wrapAndFormatPdfLines(
    (t, w) => doc.splitTextToSize(t, w) as string[],
    text,
    innerWidth
  );
  return lines.join('\n');
}

function ensureSpace(doc: jsPDF, cursorY: number, neededHeight: number, topMargin = 14): number {
  const pageHeight = doc.internal.pageSize.getHeight();
  const bottomLimit = pageHeight - 18;
  if (cursorY + neededHeight > bottomLimit) {
    doc.addPage();
    return topMargin;
  }
  return cursorY;
}

function drawSectionHeading(doc: jsPDF, title: string, cursorY: number, rightX: number): number {
  const y = ensureSpace(doc, cursorY, 14);
  doc.setFillColor(180, 83, 9); // #b45309
  doc.rect(rightX - 1.4, y - 4, 1.4, 5.2, 'F');
  doc.setFont('DejaVuSans', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(11, 15, 25);
  doc.text(formatPdfText(title), rightX - 3.2, y, { align: 'right' });
  return y + 4.5;
}

export async function generateOfficialPdfDocument(
  dossier: ForensicDossierInput,
  reportSealSha256: string,
  customFonts?: FontBundle
): Promise<jsPDF> {
  const fonts = customFonts ?? (await loadUnicodeFonts());

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
    compress: true,
  });

  doc.addFileToVFS('DejaVuSans.ttf', fonts.normal);
  doc.addFont('DejaVuSans.ttf', 'DejaVuSans', 'normal');
  doc.addFileToVFS('DejaVuSans-Bold.ttf', fonts.bold);
  doc.addFont('DejaVuSans-Bold.ttf', 'DejaVuSans', 'bold');
  doc.setFont('DejaVuSans', 'normal');

  const pageWidth = doc.internal.pageSize.getWidth(); // 210
  const pageHeight = doc.internal.pageSize.getHeight(); // 297
  const marginX = 12;
  const contentWidth = pageWidth - marginX * 2; // 186
  const rightX = pageWidth - marginX; // 198
  const leftX = marginX; // 12

  // 1. Top classification bar
  const classRgb: [number, number, number] =
    dossier.classification === 'TOP_SECRET'
      ? [185, 28, 28]
      : dossier.classification === 'CONFIDENTIAL'
      ? [180, 83, 9]
      : [15, 118, 110];

  doc.setFillColor(...classRgb);
  doc.rect(0, 0, pageWidth, 8.5, 'F');
  doc.setFont('DejaVuSans', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(255, 255, 255);
  doc.text(
    formatPdfText(getClassificationLabel(dossier.classification)),
    pageWidth / 2,
    5.6,
    { align: 'center' }
  );

  // 2. Header row: Metadata box (left) & Dossier Title (right)
  let cursorY = 13;
  const metaW = 68;
  const metaH = 19.5;
  doc.setFillColor(249, 250, 251);
  doc.setDrawColor(229, 231, 235);
  doc.setLineWidth(0.3);
  doc.roundedRect(leftX, cursorY, metaW, metaH, 2, 2, 'FD');

  doc.setFont('DejaVuSans', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(17, 24, 39);
  const metaRight = leftX + metaW - 3;
  doc.text(formatPdfText(`رقم القضية: ${dossier.caseNumber}`), metaRight, cursorY + 5.5, { align: 'right' });
  doc.text(formatPdfText(`تاريخ الإصدار: ${dossier.generatedAt}`), metaRight, cursorY + 11, { align: 'right' });
  doc.text(formatPdfText(`عدد الأدلة الموثقة: ${dossier.evidenceItems.length}`), metaRight, cursorY + 16.5, { align: 'right' });

  const titleMaxW = contentWidth - metaW - 6; // 112mm
  doc.setFont('DejaVuSans', 'bold');
  doc.setFontSize(13.5);
  doc.setTextColor(11, 15, 25);
  const titleLines = wrapAndFormatPdfLines(
    (t, w) => doc.splitTextToSize(t, w) as string[],
    dossier.title || 'التقرير الجنائي الرقمي المعتمد',
    titleMaxW
  );
  let titleY = cursorY + 5.5;
  for (const line of titleLines) {
    doc.text(line, rightX, titleY, { align: 'right' });
    titleY += 5.5;
  }

  doc.setFont('DejaVuSans', 'normal');
  doc.setFontSize(7.2);
  doc.setTextColor(107, 114, 128);
  doc.text(
    'SOVEREIGN DIGITAL FORENSICS CORE • CERTIFIED EVIDENCE DOSSIER',
    rightX,
    Math.max(titleY + 0.5, cursorY + 15),
    { align: 'right' }
  );

  const headerBottomY = Math.max(cursorY + metaH, titleY + 4) + 3;
  doc.setDrawColor(17, 24, 39);
  doc.setLineWidth(0.55);
  doc.line(leftX, headerBottomY, rightX, headerBottomY);
  cursorY = headerBottomY + 5;

  // 3. 2-Card Info Grid (Examiner & Investigation)
  const cardGap = 4;
  const cardW = (contentWidth - cardGap) / 2; // 91mm
  const rightCardX = leftX + cardW + cardGap;

  doc.setFont('DejaVuSans', 'normal');
  doc.setFontSize(8);
  const examinerSubLines = wrapAndFormatPdfLines(
    (t, w) => doc.splitTextToSize(t, w) as string[],
    `${dossier.department} • ${dossier.examinerEmail}`,
    cardW - 7
  );
  const custodyText = `تكامل سلسلة الحيازة: ${
    dossier.custodyChainVerified ? 'موثق بنسبة 100% (SHA-256 Verified)' : 'تحذير فحص السلسلة'
  }`;
  const custodySubLines = wrapAndFormatPdfLines(
    (t, w) => doc.splitTextToSize(t, w) as string[],
    custodyText,
    cardW - 7
  );
  const invTitleLines = wrapAndFormatPdfLines(
    (t, w) => doc.splitTextToSize(t, w) as string[],
    dossier.investigationTitle || 'ملف التحقيق الأساسي',
    cardW - 7
  );
  const cardH = Math.max(
    20,
    13 + Math.max(examinerSubLines.length, custodySubLines.length + invTitleLines.length - 1) * 4.2
  );

  // Right Card: Examiner
  doc.setFillColor(249, 250, 251);
  doc.setDrawColor(229, 231, 235);
  doc.setLineWidth(0.3);
  doc.roundedRect(rightCardX, cursorY, cardW, cardH, 2, 2, 'FD');
  doc.setFont('DejaVuSans', 'bold');
  doc.setFontSize(7.2);
  doc.setTextColor(107, 114, 128);
  doc.text(formatPdfText('المحقق المسؤول والجهة'), rightCardX + cardW - 3.5, cursorY + 5, { align: 'right' });
  doc.setFontSize(9);
  doc.setTextColor(17, 24, 39);
  doc.text(formatPdfText(dossier.examinerName), rightCardX + cardW - 3.5, cursorY + 10.2, { align: 'right' });
  doc.setFont('DejaVuSans', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(107, 114, 128);
  examinerSubLines.forEach((line, idx) => {
    doc.text(line, rightCardX + cardW - 3.5, cursorY + 15 + idx * 4, { align: 'right' });
  });

  // Left Card: Investigation
  doc.setFillColor(249, 250, 251);
  doc.setDrawColor(229, 231, 235);
  doc.roundedRect(leftX, cursorY, cardW, cardH, 2, 2, 'FD');
  doc.setFont('DejaVuSans', 'bold');
  doc.setFontSize(7.2);
  doc.setTextColor(107, 114, 128);
  doc.text(formatPdfText('ملف التحقيق المرتبط'), leftX + cardW - 3.5, cursorY + 5, { align: 'right' });
  doc.setFontSize(9);
  doc.setTextColor(17, 24, 39);
  let leftCardY = cursorY + 10.2;
  invTitleLines.forEach((line) => {
    doc.text(line, leftX + cardW - 3.5, leftCardY, { align: 'right' });
    leftCardY += 4.3;
  });
  doc.setFont('DejaVuSans', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(dossier.custodyChainVerified ? 22 : 180, dossier.custodyChainVerified ? 101 : 83, dossier.custodyChainVerified ? 52 : 9);
  custodySubLines.forEach((line, idx) => {
    doc.text(line, leftX + cardW - 3.5, leftCardY + 0.5 + idx * 4, { align: 'right' });
  });

  cursorY += cardH + 7;

  // 4. Technical Summary (optional)
  if (dossier.summary && dossier.summary.trim().length > 0) {
    cursorY = drawSectionHeading(doc, 'الخلاصة الفنية والتقييم الجنائي', cursorY, rightX);
    doc.setFont('DejaVuSans', 'normal');
    doc.setFontSize(8.5);
    const summaryLines = wrapAndFormatPdfLines(
      (t, w) => doc.splitTextToSize(t, w) as string[],
      dossier.summary.trim(),
      contentWidth - 8
    );

    const lineStep = 4.4;
    const summaryBoxH = Math.max(12, summaryLines.length * lineStep + 6);
    if (cursorY + summaryBoxH <= pageHeight - 18) {
      doc.setFillColor(249, 250, 251);
      doc.setDrawColor(229, 231, 235);
      doc.roundedRect(leftX, cursorY, contentWidth, summaryBoxH, 2, 2, 'FD');
      doc.setTextColor(17, 24, 39);
      summaryLines.forEach((line, idx) => {
        doc.text(line, rightX - 4, cursorY + 5.5 + idx * lineStep, { align: 'right' });
      });
      cursorY += summaryBoxH + 7;
    } else {
      // Multi-page summary rendering
      doc.setTextColor(17, 24, 39);
      for (const line of summaryLines) {
        cursorY = ensureSpace(doc, cursorY, lineStep + 2);
        doc.text(line, rightX - 2, cursorY, { align: 'right' });
        cursorY += lineStep;
      }
      cursorY += 5;
    }
  }

  // 5. Table 1: Evidence Inventory & SHA-256 Registry
  if (dossier.includeEvidenceHashes) {
    cursorY = drawSectionHeading(
      doc,
      'جرد الأدلة الرقمية وبصمات التحقق التشفيرية (SHA-256 Registry)',
      cursorY,
      rightX
    );

    const evHeaders = [
      formatPdfText('البصمات التشفيرية (SHA-256 / SHA-1 / MD5)'),
      formatPdfText('الأصالة والمخاطر'),
      formatPdfText('الترويسة الفعلية (Magic Bytes)'),
      formatPdfText('اسم الملف والحجم'),
      '#',
    ];

    const evBody =
      dossier.evidenceItems.length > 0
        ? dossier.evidenceItems.map((ev, idx) => {
            const hashLines = [`SHA-256: ${ev.sha256}`];
            if (ev.sha1) hashLines.push(`SHA-1: ${ev.sha1}`);
            if (ev.md5) hashLines.push(`MD5: ${ev.md5}`);

            const score = ev.analysis?.authenticityScore ?? 0;
            const authLines = [`${score}% (${ev.analysis?.riskLevel || 'غير مصنف'})`];
            if (ev.analysis?.elaScore !== undefined) {
              authLines.push(`ELA Tamper: ${ev.analysis.elaScore}%`);
            }

            const magicLines = [ev.analysis?.detectedFileType || ev.mimeType];
            if (ev.analysis?.headerHex) magicLines.push(ev.analysis.headerHex);
            if (ev.analysis?.isMasqueraded) magicLines.push('انتحال امتداد (Masquerade)');

            const fileLines = [
              ev.fileName,
              `${formatBytes(ev.fileSize || 0)} • ${ev.mimeType}`,
            ];

            return [
              wrapCellText(doc, hashLines.join('\n'), 74, 6.8),
              wrapCellText(doc, authLines.join('\n'), 30, 7.2, true),
              wrapCellText(doc, magicLines.join('\n'), 34, 7.2),
              wrapCellText(doc, fileLines.join('\n'), 38, 7.5),
              String(idx + 1),
            ];
          })
        : [
            [
              {
                content: formatPdfText('لا توجد أدلة محددة في هذا التقرير.'),
                colSpan: 5,
                styles: { halign: 'center' as const },
              },
            ],
          ];

    autoTable(doc, {
      startY: cursorY,
      margin: { left: marginX, right: marginX, bottom: 18 },
      head: [evHeaders],
      body: evBody,
      theme: 'grid',
      styles: {
        font: 'DejaVuSans',
        fontSize: 7.4,
        cellPadding: 2.2,
        textColor: [17, 24, 39],
        lineColor: [229, 231, 235],
        lineWidth: 0.2,
        valign: 'top',
        overflow: 'linebreak',
      },
      headStyles: {
        font: 'DejaVuSans',
        fontStyle: 'bold',
        fillColor: [17, 24, 39],
        textColor: [255, 255, 255],
        fontSize: 7.5,
        halign: 'center',
        valign: 'middle',
      },
      alternateRowStyles: {
        fillColor: [249, 250, 251],
      },
      columnStyles: {
        0: { cellWidth: 74, halign: 'left', fontSize: 6.7 },
        1: { cellWidth: 30, halign: 'right' },
        2: { cellWidth: 34, halign: 'right' },
        3: { cellWidth: 38, halign: 'right' },
        4: { cellWidth: 10, halign: 'center' },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1 && dossier.evidenceItems[data.row.index]) {
          const score = dossier.evidenceItems[data.row.index].analysis?.authenticityScore ?? 0;
          if (score >= 80) {
            data.cell.styles.fillColor = [220, 252, 231];
            data.cell.styles.textColor = [22, 101, 52];
          } else if (score >= 50) {
            data.cell.styles.fillColor = [254, 243, 199];
            data.cell.styles.textColor = [146, 64, 14];
          } else {
            data.cell.styles.fillColor = [254, 226, 226];
            data.cell.styles.textColor = [153, 27, 27];
          }
        }
      },
    });

    cursorY = getLastTableFinalY(doc, cursorY) + 7;
  }

  // 6. Table 2: EXIF, GPS & ELA
  const exifItems = dossier.evidenceItems.filter(
    (ev) => ev.analysis?.exif?.hasExif || ev.analysis?.elaScore !== undefined
  );
  if (dossier.includeExifEla && exifItems.length > 0) {
    cursorY = drawSectionHeading(
      doc,
      'نتائج فحص EXIF والـ GPS ومستوى الخطأ الضغطي (ELA)',
      cursorY,
      rightX
    );

    const exifHeaders = [
      formatPdfText('تقييم تلاعب ELA'),
      formatPdfText('إحداثيات GPS'),
      formatPdfText('تاريخ الالتقاط الأصلي'),
      formatPdfText('الجهاز / الكاميرا'),
      formatPdfText('الملف'),
    ];

    const exifBody = exifItems.map((ev) => {
      const elaVal = ev.analysis?.elaScore !== undefined ? `${ev.analysis.elaScore}%` : '—';
      const gpsVal = ev.analysis?.exif?.gps
        ? `${ev.analysis.exif.gps.latitude}, ${ev.analysis.exif.gps.longitude}`
        : 'غير متوفر';
      const dtVal = ev.analysis?.exif?.dateTimeOriginal || '—';
      const camVal = [ev.analysis?.exif?.make, ev.analysis?.exif?.model].filter(Boolean).join(' ') || '—';

      return [
        elaVal,
        wrapCellText(doc, gpsVal, 44, 7.2),
        wrapCellText(doc, dtVal, 36, 7.2),
        wrapCellText(doc, camVal, 38, 7.2),
        wrapCellText(doc, ev.fileName, 42, 7.4, true),
      ];
    });

    autoTable(doc, {
      startY: cursorY,
      margin: { left: marginX, right: marginX, bottom: 18 },
      head: [exifHeaders],
      body: exifBody,
      theme: 'grid',
      styles: {
        font: 'DejaVuSans',
        fontSize: 7.4,
        cellPadding: 2.2,
        textColor: [17, 24, 39],
        lineColor: [229, 231, 235],
        lineWidth: 0.2,
        valign: 'top',
        overflow: 'linebreak',
      },
      headStyles: {
        font: 'DejaVuSans',
        fontStyle: 'bold',
        fillColor: [17, 24, 39],
        textColor: [255, 255, 255],
        fontSize: 7.5,
        halign: 'center',
      },
      alternateRowStyles: { fillColor: [249, 250, 251] },
      columnStyles: {
        0: { cellWidth: 26, halign: 'center' },
        1: { cellWidth: 44, halign: 'left' },
        2: { cellWidth: 36, halign: 'left' },
        3: { cellWidth: 38, halign: 'left' },
        4: { cellWidth: 42, halign: 'right' },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1) {
          const item = exifItems[data.row.index];
          if (item && !item.analysis?.exif?.gps) {
            data.cell.styles.halign = 'right';
            data.cell.styles.textColor = [107, 114, 128];
          }
        }
      },
    });

    cursorY = getLastTableFinalY(doc, cursorY) + 7;
  }

  // 7. Table 3: Extracted IoCs
  if (dossier.includeIoCs && dossier.iocs.length > 0) {
    cursorY = drawSectionHeading(
      doc,
      `مؤشرات الاختراق المستخرجة من السجلات (Extracted IoCs — ${dossier.iocs.length})`,
      cursorY,
      rightX
    );

    const iocSlice = dossier.iocs.slice(0, 100);
    const iocHeaders = [
      formatPdfText('التوصيف الأمني'),
      formatPdfText('التكرار والأسطر'),
      formatPdfText('المؤشر (IoC Value)'),
      formatPdfText('الخطورة'),
      formatPdfText('النوع'),
      '#',
    ];

    const iocBody = iocSlice.map((ioc, i) => [
      wrapCellText(doc, ioc.details || '—', 46, 7.2),
      wrapCellText(doc, `×${ioc.occurrences} (أسطر: ${ioc.lines.slice(0, 6).join(', ')})`, 28, 7),
      wrapCellText(doc, ioc.value, 56, 7),
      ioc.severity.toUpperCase(),
      ioc.type.toUpperCase(),
      String(i + 1),
    ]);

    autoTable(doc, {
      startY: cursorY,
      margin: { left: marginX, right: marginX, bottom: 18 },
      head: [iocHeaders],
      body: iocBody,
      theme: 'grid',
      styles: {
        font: 'DejaVuSans',
        fontSize: 7.2,
        cellPadding: 2.1,
        textColor: [17, 24, 39],
        lineColor: [229, 231, 235],
        lineWidth: 0.2,
        valign: 'top',
        overflow: 'linebreak',
      },
      headStyles: {
        font: 'DejaVuSans',
        fontStyle: 'bold',
        fillColor: [17, 24, 39],
        textColor: [255, 255, 255],
        fontSize: 7.4,
        halign: 'center',
      },
      alternateRowStyles: { fillColor: [249, 250, 251] },
      columnStyles: {
        0: { cellWidth: 46, halign: 'right' },
        1: { cellWidth: 28, halign: 'right' },
        2: { cellWidth: 56, halign: 'left', fontSize: 6.9 },
        3: { cellWidth: 22, halign: 'center', fontStyle: 'bold' },
        4: { cellWidth: 24, halign: 'center' },
        5: { cellWidth: 10, halign: 'center' },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 3 && iocSlice[data.row.index]) {
          const sev = iocSlice[data.row.index].severity;
          if (sev === 'critical') {
            data.cell.styles.fillColor = [254, 226, 226];
            data.cell.styles.textColor = [153, 27, 27];
          } else if (sev === 'high') {
            data.cell.styles.fillColor = [254, 243, 199];
            data.cell.styles.textColor = [146, 64, 14];
          } else {
            data.cell.styles.fillColor = [220, 252, 231];
            data.cell.styles.textColor = [22, 101, 52];
          }
        }
      },
    });

    cursorY = getLastTableFinalY(doc, cursorY) + 7;
  }

  // 8. Table 4: Chain of Custody Ledger
  if (dossier.includeCustodyChain && dossier.custodyEntries.length > 0) {
    cursorY = drawSectionHeading(
      doc,
      'سجل سلسلة الحيازة المشفر (Cryptographic Chain of Custody Ledger)',
      cursorY,
      rightX
    );

    const custodySlice = dossier.custodyEntries.slice(0, 60);
    const custodyHeaders = [
      formatPdfText('بصمة الكتلة (Record SHA-256)'),
      formatPdfText('المحقق والموقع'),
      formatPdfText('الإجراء الجنائي'),
      formatPdfText('الطابع الزمني (ISO-8601)'),
      '#',
    ];

    const custodyBody = custodySlice.map((c, i) => {
      const officerText = [c.officerName || dossier.examinerName, c.location].filter(Boolean).join('\n');
      const actionText = [c.action, c.notes || ''].filter(Boolean).join('\n');
      return [
        wrapCellText(doc, c.recordHash || '—', 54, 6.7),
        wrapCellText(doc, officerText, 36, 7.2),
        wrapCellText(doc, actionText, 50, 7.2),
        wrapCellText(doc, c.timestamp, 36, 7),
        String(i + 1),
      ];
    });

    autoTable(doc, {
      startY: cursorY,
      margin: { left: marginX, right: marginX, bottom: 18 },
      head: [custodyHeaders],
      body: custodyBody,
      theme: 'grid',
      styles: {
        font: 'DejaVuSans',
        fontSize: 7.2,
        cellPadding: 2.1,
        textColor: [17, 24, 39],
        lineColor: [229, 231, 235],
        lineWidth: 0.2,
        valign: 'top',
        overflow: 'linebreak',
      },
      headStyles: {
        font: 'DejaVuSans',
        fontStyle: 'bold',
        fillColor: [17, 24, 39],
        textColor: [255, 255, 255],
        fontSize: 7.4,
        halign: 'center',
      },
      alternateRowStyles: { fillColor: [249, 250, 251] },
      columnStyles: {
        0: { cellWidth: 54, halign: 'left', fontSize: 6.7 },
        1: { cellWidth: 36, halign: 'right' },
        2: { cellWidth: 50, halign: 'right' },
        3: { cellWidth: 36, halign: 'left' },
        4: { cellWidth: 10, halign: 'center' },
      },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 1) {
          const entry = custodySlice[data.row.index];
          const sample = `${entry?.officerName || ''} ${entry?.location || ''}`;
          if (!hasArabicText(sample)) {
            data.cell.styles.halign = 'left';
          }
        }
      },
    });

    cursorY = getLastTableFinalY(doc, cursorY) + 7;
  }

  // 9. Attestation Seal Box
  const sealBoxH = 30;
  cursorY = ensureSpace(doc, cursorY, sealBoxH + 6);

  doc.setFillColor(255, 251, 235); // #fffbeb
  doc.setDrawColor(11, 15, 25); // #0b0f19
  doc.setLineWidth(0.6);
  doc.roundedRect(leftX, cursorY, contentWidth, sealBoxH, 2.5, 2.5, 'FD');

  doc.setFont('DejaVuSans', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(17, 24, 39);
  doc.text(
    formatPdfText('الختم الرقمي التشفيري لاعتماد التقرير (Report Attestation Seal — Web Crypto SHA-256)'),
    rightX - 4,
    cursorY + 6.5,
    { align: 'right' }
  );

  doc.setFont('DejaVuSans', 'normal');
  doc.setFontSize(7.2);
  doc.setTextColor(107, 114, 128);
  doc.text(
    formatPdfText('أي تعديل في بيانات القضية أو بصمات الأدلة المدرجة يبطل هذه البصمة عند إعادة التحقق.'),
    rightX - 4,
    cursorY + 11.8,
    { align: 'right' }
  );

  // Dark seal hash container
  doc.setFillColor(17, 24, 39); // #111827
  doc.roundedRect(leftX + 4, cursorY + 15, contentWidth - 8, 10.5, 1.8, 1.8, 'F');
  doc.setFont('DejaVuSans', 'bold');
  doc.setFontSize(8);
  doc.setTextColor(52, 211, 153); // #34d399
  doc.text(reportSealSha256, leftX + 7, cursorY + 21.6, { align: 'left' });

  // 10. Page footers on all pages
  const totalPages = doc.getNumberOfPages();
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p);
    doc.setDrawColor(229, 231, 235);
    doc.setLineWidth(0.25);
    doc.line(leftX, pageHeight - 13, rightX, pageHeight - 13);

    doc.setFont('DejaVuSans', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(107, 114, 128);
    doc.text(`Case: ${dossier.caseNumber}`, leftX, pageHeight - 8.5, { align: 'left' });
    doc.text(
      `SHA-256 Seal: ${reportSealSha256.slice(0, 16)}...`,
      pageWidth / 2,
      pageHeight - 8.5,
      { align: 'center' }
    );
    doc.text(
      formatPdfText(`صفحة ${p} من ${totalPages}`),
      rightX,
      pageHeight - 8.5,
      { align: 'right' }
    );
  }

  return doc;
}

export async function generateOfficialPdfBlob(
  dossier: ForensicDossierInput,
  reportSealSha256: string,
  customFonts?: FontBundle
): Promise<Blob> {
  const doc = await generateOfficialPdfDocument(dossier, reportSealSha256, customFonts);
  return doc.output('blob');
}
