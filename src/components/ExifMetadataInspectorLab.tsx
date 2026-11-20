import React, { useMemo, useState } from 'react';
import SparkMD5 from 'spark-md5';
import {
  Upload,
  Search,
  Download,
  RotateCcw,
  FileSearch,
  CheckCircle2,
  MinusCircle,
  AlertTriangle,
  Copy,
  Check,
  X,
} from 'lucide-react';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

interface ExifMetadataInspectorLabProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

interface ExtractedMetaTag {
  group: 'Header' | 'IFD0' | 'ExifIFD' | 'GPS' | 'XMP' | 'PNG' | 'PDF';
  tagId: string;
  name: string;
  value: string;
}

interface StandardFieldStatus {
  key: string;
  label: string;
  value: string | null;
}

interface ExtractedMetadataReport {
  fileName: string;
  fileSize: number;
  mimeType: string;
  lastModifiedIso: string;
  lastModifiedLocal: string;
  sha256: string;
  md5: string;
  detectedSignature: string;
  firstBytesHex: string;
  firstBytesAscii: string;
  dimensions: { width: number; height: number } | null;
  tags: ExtractedMetaTag[];
  standardChecklist: StandardFieldStatus[];
}

const TIFF_TAG_NAMES: Record<number, string> = {
  0x0100: 'ImageWidth',
  0x0101: 'ImageLength',
  0x0102: 'BitsPerSample',
  0x0103: 'Compression',
  0x010e: 'ImageDescription',
  0x010f: 'Make',
  0x0110: 'Model',
  0x0112: 'Orientation',
  0x011a: 'XResolution',
  0x011b: 'YResolution',
  0x0128: 'ResolutionUnit',
  0x0131: 'Software',
  0x0132: 'DateTime',
  0x013b: 'Artist',
  0x013e: 'WhitePoint',
  0x8298: 'Copyright',
  0x829a: 'ExposureTime',
  0x829d: 'FNumber',
  0x8822: 'ExposureProgram',
  0x8827: 'ISOSpeedRatings',
  0x9000: 'ExifVersion',
  0x9003: 'DateTimeOriginal',
  0x9004: 'DateTimeDigitized',
  0x9101: 'ComponentsConfiguration',
  0x9201: 'ShutterSpeedValue',
  0x9202: 'ApertureValue',
  0x9203: 'BrightnessValue',
  0x9204: 'ExposureBiasValue',
  0x9207: 'MeteringMode',
  0x9208: 'LightSource',
  0x9209: 'Flash',
  0x920a: 'FocalLength',
  0x9290: 'SubSecTime',
  0x9291: 'SubSecTimeOriginal',
  0xa001: 'ColorSpace',
  0xa002: 'PixelXDimension',
  0xa003: 'PixelYDimension',
  0xa402: 'ExposureMode',
  0xa403: 'WhiteBalance',
  0xa405: 'FocalLengthIn35mmFilm',
  0xa420: 'ImageUniqueID',
  0xa430: 'CameraOwnerName',
  0xa431: 'BodySerialNumber',
  0xa432: 'LensSpecification',
  0xa433: 'LensMake',
  0xa434: 'LensModel',
  0xa435: 'LensSerialNumber',
};

const GPS_TAG_NAMES: Record<number, string> = {
  0x0000: 'GPSVersionID',
  0x0001: 'GPSLatitudeRef',
  0x0002: 'GPSLatitude',
  0x0003: 'GPSLongitudeRef',
  0x0004: 'GPSLongitude',
  0x0005: 'GPSAltitudeRef',
  0x0006: 'GPSAltitude',
  0x0007: 'GPSTimeStamp',
  0x0010: 'GPSImgDirectionRef',
  0x0011: 'GPSImgDirection',
  0x0012: 'GPSMapDatum',
  0x001d: 'GPSDateStamp',
};

const ORIENTATION_LABELS: Record<number, string> = {
  1: '1 (Normal / أفقي طبيعي)',
  2: '2 (Mirrored Horizontal)',
  3: '3 (Rotated 180°)',
  4: '4 (Mirrored Vertical)',
  5: '5 (Mirrored Horizontal + 270°)',
  6: '6 (Rotated 90° CW)',
  7: '7 (Mirrored Horizontal + 90°)',
  8: '8 (Rotated 270° CW)',
};

function formatFileSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

function sanitizeCsvCell(val: string | number): string {
  const s = String(val ?? '');
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
}

function readAscii(bytes: Uint8Array, start: number, len: number): string {
  const end = Math.min(bytes.length, start + len);
  let out = '';
  for (let i = start; i < end; i++) {
    const b = bytes[i];
    if (b === 0) break;
    out += b >= 32 && b <= 126 ? String.fromCharCode(b) : '';
  }
  return out.trim();
}

function detectMagicSignature(bytes: Uint8Array): string {
  if (bytes.length === 0) return 'ملف فارغ (0 bytes)';
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
    return 'JPEG Image (FF D8 FF)';
  }
  if (
    bytes.length >= 8 &&
    bytes[0] === 0x89 &&
    bytes[1] === 0x50 &&
    bytes[2] === 0x4e &&
    bytes[3] === 0x47 &&
    bytes[4] === 0x0d &&
    bytes[5] === 0x0a &&
    bytes[6] === 0x1a &&
    bytes[7] === 0x0a
  ) {
    return 'PNG Image (89 50 4E 47)';
  }
  if (bytes.length >= 12 && readAscii(bytes, 0, 4) === 'RIFF' && readAscii(bytes, 8, 4) === 'WEBP') {
    return 'WebP Image (RIFF/WEBP)';
  }
  if (bytes.length >= 6 && (readAscii(bytes, 0, 6) === 'GIF89a' || readAscii(bytes, 0, 6) === 'GIF87a')) {
    return `GIF Image (${readAscii(bytes, 0, 6)})`;
  }
  if (bytes.length >= 4 && ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2a && bytes[3] === 0x00) || (bytes[0] === 0x4d && bytes[1] === 0x4d && bytes[2] === 0x00 && bytes[3] === 0x2a))) {
    return 'TIFF Image';
  }
  if (bytes.length >= 5 && readAscii(bytes, 0, 5) === '%PDF-') {
    const ver = readAscii(bytes, 0, 8);
    return `PDF Document (${ver})`;
  }
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04) {
    return 'ZIP Archive / Office / APK (50 4B 03 04)';
  }
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a) {
    return 'Windows PE Executable / DLL (MZ)';
  }
  if (bytes.length >= 4 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46) {
    return 'Linux ELF Binary (7F 45 4C 46)';
  }
  if (bytes.length >= 3 && readAscii(bytes, 0, 3) === 'ID3') {
    return 'MP3 Audio (ID3v2)';
  }
  if (bytes.length >= 12 && readAscii(bytes, 4, 4) === 'ftyp') {
    return `ISO Media / MP4 / HEIC (${readAscii(bytes, 8, 4)})`;
  }
  return 'بيانات نصية أو صيغة غير مصنفة بوسم بايتي قياسي';
}

function parseTiffBlock(
  tiffBytes: Uint8Array,
  tagsOut: ExtractedMetaTag[],
  rawGps: {
    latRef?: string;
    latNums?: number[];
    lonRef?: string;
    lonNums?: number[];
  }
): { width?: number; height?: number } {
  const dims: { width?: number; height?: number } = {};
  if (tiffBytes.length < 8) return dims;

  const bom = (tiffBytes[0] << 8) | tiffBytes[1];
  const le = bom === 0x4949;
  if (!le && bom !== 0x4d4d) return dims;

  const dv = new DataView(tiffBytes.buffer, tiffBytes.byteOffset, tiffBytes.byteLength);
  const magic = dv.getUint16(2, le);
  if (magic !== 42) return dims;

  const firstIfdOffset = dv.getUint32(4, le);
  const visitedOffsets = new Set<number>();

  const TYPE_SIZES: Record<number, number> = {
    1: 1, // BYTE
    2: 1, // ASCII
    3: 2, // SHORT
    4: 4, // LONG
    5: 8, // RATIONAL
    7: 1, // UNDEFINED
    9: 4, // SLONG
    10: 8, // SRATIONAL
  };

  const readIfd = (ifdOffset: number, group: 'IFD0' | 'ExifIFD' | 'GPS') => {
    if (ifdOffset <= 0 || ifdOffset + 2 > tiffBytes.length || visitedOffsets.has(ifdOffset)) return;
    visitedOffsets.add(ifdOffset);

    const entryCount = dv.getUint16(ifdOffset, le);
    if (entryCount > 200) return;

    let exifSubIfdOffset = 0;
    let gpsSubIfdOffset = 0;

    for (let i = 0; i < entryCount; i++) {
      const entryOff = ifdOffset + 2 + i * 12;
      if (entryOff + 12 > tiffBytes.length) break;

      const tagId = dv.getUint16(entryOff, le);
      const type = dv.getUint16(entryOff + 2, le);
      const count = dv.getUint32(entryOff + 4, le);
      const typeSize = TYPE_SIZES[type] || 1;
      const byteLength = count * typeSize;

      const valueOffset = byteLength <= 4 ? entryOff + 8 : dv.getUint32(entryOff + 8, le);
      if (valueOffset + byteLength > tiffBytes.length) continue;

      if (tagId === 0x8769 && (type === 4 || type === 3)) {
        exifSubIfdOffset = type === 3 ? dv.getUint16(valueOffset, le) : dv.getUint32(valueOffset, le);
        continue;
      }
      if (tagId === 0x8825 && (type === 4 || type === 3)) {
        gpsSubIfdOffset = type === 3 ? dv.getUint16(valueOffset, le) : dv.getUint32(valueOffset, le);
        continue;
      }

      let formattedValue = '';
      const numericValues: number[] = [];

      if (type === 2) {
        formattedValue = readAscii(tiffBytes, valueOffset, Math.min(byteLength, 256));
      } else if (type === 3) {
        const items: number[] = [];
        for (let k = 0; k < Math.min(count, 16); k++) {
          items.push(dv.getUint16(valueOffset + k * 2, le));
        }
        numericValues.push(...items);
        formattedValue = items.join(', ');
      } else if (type === 4 || type === 9) {
        const items: number[] = [];
        for (let k = 0; k < Math.min(count, 16); k++) {
          items.push(type === 9 ? dv.getInt32(valueOffset + k * 4, le) : dv.getUint32(valueOffset + k * 4, le));
        }
        numericValues.push(...items);
        formattedValue = items.join(', ');
      } else if (type === 5 || type === 10) {
        const items: string[] = [];
        for (let k = 0; k < Math.min(count, 8); k++) {
          const base = valueOffset + k * 8;
          const num = type === 10 ? dv.getInt32(base, le) : dv.getUint32(base, le);
          const den = type === 10 ? dv.getInt32(base + 4, le) : dv.getUint32(base + 4, le);
          if (den !== 0) {
            const dec = num / den;
            numericValues.push(dec);
            if (tagId === 0x829a && num > 0 && dec < 1) {
              items.push(`1/${Math.round(den / num)}s`);
            } else if (tagId === 0x829d) {
              items.push(`f/${Number(dec.toFixed(2))}`);
            } else {
              items.push(Number.isInteger(dec) ? String(dec) : dec.toFixed(4).replace(/\.?0+$/, ''));
            }
          }
        }
        formattedValue = items.join(' · ');
      } else if (type === 1 || type === 7) {
        if (tagId === 0x9000 || tagId === 0x0000) {
          formattedValue = Array.from(tiffBytes.subarray(valueOffset, valueOffset + Math.min(count, 8)))
            .map((b) => (b >= 48 && b <= 57 ? String.fromCharCode(b) : b))
            .join('.');
        } else {
          formattedValue = `${byteLength} bytes`;
        }
      }

      if (!formattedValue) continue;

      if (tagId === 0x0112 && numericValues[0] && ORIENTATION_LABELS[numericValues[0]]) {
        formattedValue = ORIENTATION_LABELS[numericValues[0]];
      }

      if ((tagId === 0x0100 || tagId === 0xa002) && numericValues[0]) {
        dims.width = numericValues[0];
      }
      if ((tagId === 0x0101 || tagId === 0xa003) && numericValues[0]) {
        dims.height = numericValues[0];
      }

      if (group === 'GPS') {
        if (tagId === 0x0001) rawGps.latRef = formattedValue;
        if (tagId === 0x0002 && numericValues.length >= 3) rawGps.latNums = numericValues;
        if (tagId === 0x0003) rawGps.lonRef = formattedValue;
        if (tagId === 0x0004 && numericValues.length >= 3) rawGps.lonNums = numericValues;
      }

      const tagName =
        (group === 'GPS' ? GPS_TAG_NAMES[tagId] : TIFF_TAG_NAMES[tagId]) ||
        `Tag_0x${tagId.toString(16).toUpperCase().padStart(4, '0')}`;

      tagsOut.push({
        group,
        tagId: `0x${tagId.toString(16).toUpperCase().padStart(4, '0')}`,
        name: tagName,
        value: formattedValue,
      });
    }

    if (exifSubIfdOffset > 0) readIfd(exifSubIfdOffset, 'ExifIFD');
    if (gpsSubIfdOffset > 0) readIfd(gpsSubIfdOffset, 'GPS');
  };

  readIfd(firstIfdOffset, 'IFD0');
  return dims;
}

function parseXmpFields(xmlText: string, tagsOut: ExtractedMetaTag[]) {
  const xmpTargets: Array<{ label: string; regex: RegExp }> = [
    { label: 'xmp:CreatorTool', regex: /<xmp:CreatorTool>([^<]+)<\/xmp:CreatorTool>/i },
    { label: 'xmp:CreateDate', regex: /<xmp:CreateDate>([^<]+)<\/xmp:CreateDate>/i },
    { label: 'xmp:ModifyDate', regex: /<xmp:ModifyDate>([^<]+)<\/xmp:ModifyDate>/i },
    { label: 'pdf:Producer', regex: /<pdf:Producer>([^<]+)<\/pdf:Producer>/i },
    { label: 'dc:creator', regex: /<dc:creator>[\s\S]*?<rdf:li[^>]*>([^<]+)<\/rdf:li>/i },
    { label: 'dc:title', regex: /<dc:title>[\s\S]*?<rdf:li[^>]*>([^<]+)<\/rdf:li>/i },
    { label: 'photoshop:DateCreated', regex: /<photoshop:DateCreated>([^<]+)<\/photoshop:DateCreated>/i },
  ];
  for (const t of xmpTargets) {
    const m = xmlText.match(t.regex);
    if (m?.[1]?.trim()) {
      tagsOut.push({
        group: 'XMP',
        tagId: 'XMP',
        name: t.label,
        value: m[1].trim(),
      });
    }
  }
}

function parseJpegMetadata(
  bytes: Uint8Array,
  tagsOut: ExtractedMetaTag[],
  rawGps: { latRef?: string; latNums?: number[]; lonRef?: string; lonNums?: number[] }
): { width?: number; height?: number } {
  const dims: { width?: number; height?: number } = {};
  let offset = 2;

  while (offset + 4 <= bytes.length) {
    if (bytes[offset] !== 0xff) break;
    while (offset < bytes.length && bytes[offset] === 0xff) offset++;
    if (offset >= bytes.length) break;
    const marker = bytes[offset];
    offset++;

    // SOS (Start of Scan) or EOI
    if (marker === 0xda || marker === 0xd9) break;
    // Standalone markers
    if (marker === 0x00 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;

    if (offset + 2 > bytes.length) break;
    const segLen = (bytes[offset] << 8) | bytes[offset + 1];
    if (segLen < 2 || offset + segLen > bytes.length) break;

    const segData = bytes.subarray(offset + 2, offset + segLen);

    // APP1: EXIF or XMP
    if (marker === 0xe1) {
      if (
        segData.length >= 6 &&
        segData[0] === 0x45 &&
        segData[1] === 0x78 &&
        segData[2] === 0x69 &&
        segData[3] === 0x66 &&
        segData[4] === 0x00 &&
        segData[5] === 0x00
      ) {
        const tiffDims = parseTiffBlock(segData.subarray(6), tagsOut, rawGps);
        if (tiffDims.width) dims.width = tiffDims.width;
        if (tiffDims.height) dims.height = tiffDims.height;
      } else {
        const headerStr = readAscii(segData, 0, 32);
        if (headerStr.includes('ns.adobe.com/xap/1.0/')) {
          const xmpText = new TextDecoder('utf-8', { fatal: false }).decode(segData);
          parseXmpFields(xmpText, tagsOut);
        }
      }
    }

    // SOF0..SOF3 for real pixel dimensions
    if ((marker >= 0xc0 && marker <= 0xc3) && segData.length >= 5) {
      const h = (segData[1] << 8) | segData[2];
      const w = (segData[3] << 8) | segData[4];
      if (w > 0 && h > 0) {
        dims.width = w;
        dims.height = h;
      }
    }

    offset += segLen;
  }
  return dims;
}

function parsePngMetadata(
  bytes: Uint8Array,
  tagsOut: ExtractedMetaTag[],
  rawGps: { latRef?: string; latNums?: number[]; lonRef?: string; lonNums?: number[] }
): { width?: number; height?: number } {
  const dims: { width?: number; height?: number } = {};
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 8;

  while (offset + 12 <= bytes.length) {
    const length = dv.getUint32(offset, false);
    const chunkType = readAscii(bytes, offset + 4, 4);
    const dataStart = offset + 8;
    if (dataStart + length + 4 > bytes.length) break;
    const chunkData = bytes.subarray(dataStart, dataStart + length);

    if (chunkType === 'IHDR' && length >= 13) {
      dims.width = dv.getUint32(dataStart, false);
      dims.height = dv.getUint32(dataStart + 4, false);
      const bitDepth = chunkData[8];
      const colorType = chunkData[9];
      tagsOut.push({
        group: 'PNG',
        tagId: 'IHDR',
        name: 'ImageHeader',
        value: `${dims.width} × ${dims.height} · ${bitDepth}-bit · ColorType=${colorType}`,
      });
    } else if (chunkType === 'pHYs' && length >= 9) {
      const ppuX = dv.getUint32(dataStart, false);
      const ppuY = dv.getUint32(dataStart + 4, false);
      const unit = chunkData[8] === 1 ? 'px/meter' : 'ratio';
      tagsOut.push({
        group: 'PNG',
        tagId: 'pHYs',
        name: 'PhysicalPixelDimensions',
        value: `${ppuX} × ${ppuY} (${unit})`,
      });
    } else if (chunkType === 'tEXt' && length > 0) {
      const nullIdx = chunkData.indexOf(0);
      if (nullIdx > 0) {
        const key = new TextDecoder('latin1').decode(chunkData.subarray(0, nullIdx));
        const val = new TextDecoder('latin1').decode(chunkData.subarray(nullIdx + 1));
        if (key === 'XML:com.adobe.xmp') {
          parseXmpFields(val, tagsOut);
        } else if (val.trim()) {
          tagsOut.push({
            group: 'PNG',
            tagId: 'tEXt',
            name: key,
            value: val.slice(0, 300),
          });
        }
      }
    } else if (chunkType === 'iTXt' && length > 0) {
      const nullIdx = chunkData.indexOf(0);
      if (nullIdx > 0) {
        const key = new TextDecoder('utf-8', { fatal: false }).decode(chunkData.subarray(0, nullIdx));
        const rest = new TextDecoder('utf-8', { fatal: false }).decode(chunkData.subarray(nullIdx + 1)).replace(/\u0000+/g, ' ').trim();
        if (key === 'XML:com.adobe.xmp') {
          parseXmpFields(rest, tagsOut);
        } else if (rest) {
          tagsOut.push({
            group: 'PNG',
            tagId: 'iTXt',
            name: key,
            value: rest.slice(0, 300),
          });
        }
      }
    } else if (chunkType === 'eXIf' && length >= 8) {
      parseTiffBlock(chunkData, tagsOut, rawGps);
    }

    if (chunkType === 'IEND') break;
    offset = dataStart + length + 4;
  }

  return dims;
}

function parsePdfMetadata(bytes: Uint8Array, tagsOut: ExtractedMetaTag[]) {
  const sampleText = new TextDecoder('latin1').decode(bytes.subarray(0, Math.min(bytes.length, 512_000)));
  const pdfVerM = sampleText.match(/^%PDF-([0-9.]+)/);
  if (pdfVerM) {
    tagsOut.push({
      group: 'PDF',
      tagId: 'PDF',
      name: 'PDFVersion',
      value: pdfVerM[1],
    });
  }

  const infoKeys = ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate'];
  for (const key of infoKeys) {
    const regex = new RegExp(`/${key}\\s*\\(([^()]{1,220})\\)`);
    const m = sampleText.match(regex);
    if (m?.[1]?.trim()) {
      tagsOut.push({
        group: 'PDF',
        tagId: 'Info',
        name: key,
        value: m[1].trim(),
      });
    }
  }

  if (sampleText.includes('<x:xmpmeta')) {
    const start = sampleText.indexOf('<x:xmpmeta');
    const end = sampleText.indexOf('</x:xmpmeta>', start);
    if (end > start) {
      parseXmpFields(sampleText.slice(start, end + 12), tagsOut);
    }
  }
}

function parseWebpMetadata(
  bytes: Uint8Array,
  tagsOut: ExtractedMetaTag[],
  rawGps: { latRef?: string; latNums?: number[]; lonRef?: string; lonNums?: number[] }
): { width?: number; height?: number } {
  const dims: { width?: number; height?: number } = {};
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let offset = 12;

  while (offset + 8 <= bytes.length) {
    const fourCC = readAscii(bytes, offset, 4);
    const chunkSize = dv.getUint32(offset + 4, true);
    const dataStart = offset + 8;
    if (dataStart + chunkSize > bytes.length) break;
    const chunkData = bytes.subarray(dataStart, dataStart + chunkSize);

    if (fourCC === 'VP8X' && chunkSize >= 10) {
      dims.width = 1 + (chunkData[4] | (chunkData[5] << 8) | (chunkData[6] << 16));
      dims.height = 1 + (chunkData[7] | (chunkData[8] << 8) | (chunkData[9] << 16));
    } else if (fourCC === 'EXIF') {
      const exifSlice =
        chunkData.length >= 6 && readAscii(chunkData, 0, 4) === 'Exif'
          ? chunkData.subarray(6)
          : chunkData;
      parseTiffBlock(exifSlice, tagsOut, rawGps);
    } else if (fourCC === 'XMP ') {
      const xmpText = new TextDecoder('utf-8', { fatal: false }).decode(chunkData);
      parseXmpFields(xmpText, tagsOut);
    }

    offset = dataStart + chunkSize + (chunkSize % 2);
  }
  return dims;
}

function formatGpsCoord(nums?: number[], ref?: string): string | null {
  if (!nums || nums.length < 3) return null;
  const decimal = nums[0] + nums[1] / 60 + nums[2] / 3600;
  if (Number.isNaN(decimal)) return null;
  const signed = ref === 'S' || ref === 'W' ? -decimal : decimal;
  return `${signed.toFixed(6)}° (${nums[0].toFixed(0)}° ${nums[1].toFixed(0)}' ${nums[2].toFixed(2)}" ${ref || ''})`.trim();
}

async function resolveBrowserImageDimensions(file: File): Promise<{ width: number; height: number } | null> {
  if (!file.type.startsWith('image/')) return null;
  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const w = img.naturalWidth;
      const h = img.naturalHeight;
      URL.revokeObjectURL(url);
      resolve(w > 0 && h > 0 ? { width: w, height: h } : null);
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      resolve(null);
    };
    img.src = url;
  });
}

export const ExifMetadataInspectorLab: React.FC<ExifMetadataInspectorLabProps> = ({
  onNotify,
  onRecordAudit,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ExtractedMetadataReport | null>(null);
  const [tagSearch, setTagSearch] = useState('');
  const [copiedSha, setCopiedSha] = useState(false);

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    setError(null);
    setTagSearch('');

    try {
      const buffer = await file.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      const hashBuf = await crypto.subtle.digest('SHA-256', buffer);
      const sha256 = Array.from(new Uint8Array(hashBuf))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const md5 = SparkMD5.ArrayBuffer.hash(buffer);

      const detectedSignature = detectMagicSignature(bytes);
      const slice = bytes.subarray(0, Math.min(bytes.length, 64));
      const firstBytesHex = Array.from(slice)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');
      const firstBytesAscii = Array.from(slice)
        .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
        .join('');

      const tags: ExtractedMetaTag[] = [];
      const rawGps: { latRef?: string; latNums?: number[]; lonRef?: string; lonNums?: number[] } = {};
      let dims: { width?: number; height?: number } = {};

      if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) {
        dims = parseJpegMetadata(bytes, tags, rawGps);
      } else if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) {
        dims = parsePngMetadata(bytes, tags, rawGps);
      } else if (bytes.length >= 12 && readAscii(bytes, 0, 4) === 'RIFF' && readAscii(bytes, 8, 4) === 'WEBP') {
        dims = parseWebpMetadata(bytes, tags, rawGps);
      } else if (bytes.length >= 4 && ((bytes[0] === 0x49 && bytes[1] === 0x49 && bytes[2] === 0x2a && bytes[3] === 0x00) || (bytes[0] === 0x4d && bytes[1] === 0x4d && bytes[2] === 0x00 && bytes[3] === 0x2a))) {
        dims = parseTiffBlock(bytes, tags, rawGps);
      } else if (bytes.length >= 6 && (readAscii(bytes, 0, 6) === 'GIF89a' || readAscii(bytes, 0, 6) === 'GIF87a')) {
        const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        if (bytes.length >= 10) {
          dims = { width: dv.getUint16(6, true), height: dv.getUint16(8, true) };
        }
      } else if (bytes.length >= 5 && readAscii(bytes, 0, 5) === '%PDF-') {
        parsePdfMetadata(bytes, tags);
      }

      let resolvedDimensions: { width: number; height: number } | null =
        dims.width && dims.height ? { width: dims.width, height: dims.height } : null;

      if (!resolvedDimensions) {
        resolvedDimensions = await resolveBrowserImageDimensions(file);
      }

      const findTag = (names: string[]) => {
        const lower = names.map((n) => n.toLowerCase());
        return tags.find((t) => lower.includes(t.name.toLowerCase()))?.value || null;
      };

      const latStr = formatGpsCoord(rawGps.latNums, rawGps.latRef);
      const lonStr = formatGpsCoord(rawGps.lonNums, rawGps.lonRef);
      const gpsCombined = latStr && lonStr ? `${latStr} , ${lonStr}` : null;

      const exposureParts = [
        findTag(['ExposureTime']),
        findTag(['FNumber']),
        findTag(['ISOSpeedRatings']) ? `ISO ${findTag(['ISOSpeedRatings'])}` : null,
        findTag(['FocalLength']) ? `${findTag(['FocalLength'])}mm` : null,
      ].filter(Boolean);

      const standardChecklist: StandardFieldStatus[] = [
        {
          key: 'dimensions',
          label: 'أبعاد الصورة (Width × Height)',
          value: resolvedDimensions ? `${resolvedDimensions.width} × ${resolvedDimensions.height} px` : null,
        },
        {
          key: 'make',
          label: 'الشركة المصنعة للجهاز (Camera Make)',
          value: findTag(['Make']),
        },
        {
          key: 'model',
          label: 'طراز الجهاز / الكاميرا (Model)',
          value: findTag(['Model']),
        },
        {
          key: 'software',
          label: 'البرنامج أو أداة التعديل (Software / CreatorTool)',
          value: findTag(['Software', 'xmp:CreatorTool', 'Producer', 'Creator']),
        },
        {
          key: 'dateOriginal',
          label: 'تاريخ الالتقاط أو الإنشاء الأصلي (DateTimeOriginal)',
          value: findTag(['DateTimeOriginal', 'DateTimeDigitized', 'xmp:CreateDate', 'CreationDate', 'photoshop:DateCreated']),
        },
        {
          key: 'modifyDate',
          label: 'تاريخ التعديل داخل الترويسة (ModifyDate)',
          value: findTag(['DateTime', 'xmp:ModifyDate', 'ModDate']),
        },
        {
          key: 'orientation',
          label: 'اتجاه الصورة (Orientation)',
          value: findTag(['Orientation']),
        },
        {
          key: 'cameraSettings',
          label: 'إعدادات التعريض والعدسة (Exposure / Aperture / ISO)',
          value: exposureParts.length > 0 ? exposureParts.join(' · ') : null,
        },
        {
          key: 'gps',
          label: 'الإحداثيات الجغرافية (GPS Coordinates)',
          value: gpsCombined,
        },
        {
          key: 'author',
          label: 'المؤلف / حقوق النشر (Author / Copyright)',
          value: findTag(['Artist', 'Author', 'dc:creator', 'Copyright']),
        },
      ];

      const lastModDate = file.lastModified ? new Date(file.lastModified) : null;
      const reportObj: ExtractedMetadataReport = {
        fileName: file.name,
        fileSize: file.size,
        mimeType: file.type || 'غير محدد من المتصفح (application/octet-stream)',
        lastModifiedIso: lastModDate ? lastModDate.toISOString() : 'غير متوفر',
        lastModifiedLocal: lastModDate ? lastModDate.toLocaleString('ar-SA') : 'غير متوفر',
        sha256,
        md5,
        detectedSignature,
        firstBytesHex,
        firstBytesAscii,
        dimensions: resolvedDimensions,
        tags,
        standardChecklist,
      };

      setReport(reportObj);

      const foundCount = standardChecklist.filter((f) => f.value !== null).length;
      onNotify(
        `تم استخراج ${tags.length} وسماً وصفياً و${foundCount} حقلاً قياسياً من "${file.name}".`,
        gpsCombined ? 'warning' : 'success'
      );
      onRecordAudit({
        id: `meta-${Date.now()}`,
        fileName: file.name,
        fileSize: formatFileSize(file.size),
        verdict: `فحص EXIF والبيانات الوصفية (${tags.length} وسم${gpsCombined ? ' · يحتوي GPS' : ''})`,
        score: gpsCombined ? 65 : 95,
        risk: gpsCombined ? 'متوسط' : 'منخفض',
        sha256,
      });
    } catch (err: any) {
      setReport(null);
      setError(err?.message || 'تعذر قراءة الملف واستخراج بياناته الوصفية.');
    } finally {
      setLoading(false);
    }
  };

  const filteredTags = useMemo(() => {
    if (!report) return [];
    const q = tagSearch.trim().toLowerCase();
    if (!q) return report.tags;
    return report.tags.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.value.toLowerCase().includes(q) ||
        t.group.toLowerCase().includes(q) ||
        t.tagId.toLowerCase().includes(q)
    );
  }, [report, tagSearch]);

  const exportReportJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `metadata-${report.fileName.replace(/[^a-zA-Z0-9._-]/g, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify('تم تصدير تقرير البيانات الوصفية بصيغة JSON.', 'success');
  };

  const exportReportCsv = () => {
    if (!report) return;
    const headers = ['Category', 'FieldOrTagID', 'Name', 'StatusOrValue'];
    const coreRows = [
      ['File', 'Name', 'اسم الملف', report.fileName],
      ['File', 'Size', 'الحجم', `${report.fileSize} bytes (${formatFileSize(report.fileSize)})`],
      ['File', 'MIME', 'MIME Type', report.mimeType],
      ['File', 'LastModified', 'تاريخ آخر تعديل', report.lastModifiedIso],
      ['File', 'SHA256', 'SHA-256', report.sha256],
      ['File', 'MD5', 'MD5', report.md5],
      ['File', 'Signature', 'التوقيع البايتي', report.detectedSignature],
    ];
    const checklistRows = report.standardChecklist.map((item) => [
      'StandardCheck',
      item.key,
      item.label,
      item.value ?? 'غير موجود في الملف',
    ]);
    const tagRows = report.tags.map((t) => [t.group, t.tagId, t.name, t.value]);
    const allRows = [...coreRows, ...checklistRows, ...tagRows].map((row) =>
      row.map((cell) => sanitizeCsvCell(cell)).join(',')
    );
    const csv = '\uFEFF' + [headers.join(','), ...allRows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `metadata-${report.fileName.replace(/[^a-zA-Z0-9._-]/g, '_')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify('تم تصدير تقرير البيانات الوصفية بصيغة CSV.', 'success');
  };

  const copySha256 = () => {
    if (!report) return;
    navigator.clipboard?.writeText(report.sha256);
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 1800);
    onNotify('تم نسخ بصمة SHA-256 بنجاح.', 'success');
  };

  return (
    <div className="space-y-6" dir="rtl">
      <div className="rounded-xl bg-gray-900 border border-gray-800 p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-lg font-bold text-white">
              مستخرج البيانات الوصفية (EXIF & Metadata Inspector)
            </h2>
            <p className="text-xs text-gray-400">
              استخراج البيانات الوصفية الحقيقية من الملفات والصور المرفوعة داخل المتصفح (الخصائص الأساسية، بصمة SHA-256، ووسوم EXIF / XMP / PNG / PDF) مع توضيح الحقول الغائبة دون اختلاق أي قيم.
            </p>
          </div>
          {report && (
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={exportReportCsv}
                className="px-4 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5 text-[#D4AF37]" />
                <span>تصدير CSV</span>
              </button>
              <button
                type="button"
                onClick={exportReportJson}
                className="px-4 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-200 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0"
              >
                <Download className="w-3.5 h-3.5 text-emerald-400" />
                <span>تصدير JSON</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setReport(null);
                  setError(null);
                  setTagSearch('');
                }}
                className="px-4 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-gray-300 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>مسح</span>
              </button>
            </div>
          )}
        </div>

        <label className="flex flex-col items-center justify-center p-8 rounded-xl border-2 border-dashed border-gray-700 hover:border-[#D4AF37] bg-gray-950/70 cursor-pointer text-center transition">
          <Upload className="w-7 h-7 text-[#D4AF37] mb-2" />
          <span className="text-sm font-bold text-white">
            {loading ? 'جاري قراءة واستخراج البيانات الوصفية...' : 'ارفع صورة أو أي ملف لاستخراج بياناته الوصفية الحقيقية'}
          </span>
          <span className="text-xs text-gray-400 mt-1">
            يدعم الصور (JPEG, PNG, WebP, TIFF, GIF) والمستندات (PDF) وأي ملف آخر لاستخراج خصائصه وترويسته وبصمته محلياً
          </span>
          <input
            type="file"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void handleFileUpload(f);
              e.target.value = '';
            }}
          />
        </label>

        {error && (
          <div className="p-3.5 rounded-xl bg-red-950/40 border border-red-500/40 text-red-200 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Waiting State when no file is uploaded */}
      {!report && !loading && (
        <div className="rounded-xl bg-gray-900 border border-gray-800 p-10 text-center space-y-3">
          <div className="w-12 h-12 rounded-xl bg-gray-950 border border-gray-800 flex items-center justify-center text-[#D4AF37] mx-auto">
            <FileSearch className="w-6 h-6" />
          </div>
          <h3 className="text-sm font-bold text-white">بانتظار رفع ملف للفحص</h3>
          <p className="text-xs text-gray-400 max-w-md mx-auto leading-relaxed">
            ارفع صورة أو ملفاً من الجهاز أعلاه لقراءة بياناته الوصفية الحقيقية داخل المتصفح. لا يتم عرض أي بيانات افتراضية أو محاكاة قبل رفع الملف.
          </p>
        </div>
      )}

      {/* Real Extracted Metadata Results */}
      {report && (
        <div className="space-y-6">
          {/* Core File Metadata */}
          <div className="rounded-xl bg-gray-900 border border-gray-800 p-5 space-y-4">
            <h3 className="text-xs font-bold text-white">الخصائص الأساسية والبصمة الرقمية للملف</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-[11px] text-gray-400">اسم الملف</div>
                <div className="text-xs font-mono font-bold text-white break-all" dir="ltr">
                  {report.fileName}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-[11px] text-gray-400">الحجم الفعلي</div>
                <div className="text-xs font-mono tabular-nums font-bold text-[#D4AF37]">
                  {formatFileSize(report.fileSize)} · {report.fileSize.toLocaleString()} bytes
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-[11px] text-gray-400">النوع (MIME Type)</div>
                <div className="text-xs font-mono text-gray-200 break-all" dir="ltr">
                  {report.mimeType}
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-[11px] text-gray-400">تاريخ آخر تعديل</div>
                <div className="text-xs font-mono tabular-nums text-gray-200" dir="ltr">
                  {report.lastModifiedIso}
                </div>
                <div className="text-[11px] text-gray-400">{report.lastModifiedLocal}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-[11px] text-gray-400">التوقيع البايتي للترويسة (Magic Header)</div>
                <div className="text-xs font-mono text-emerald-300">{report.detectedSignature}</div>
              </div>

              <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 space-y-1">
                <div className="text-[11px] text-gray-400">بصمة MD5</div>
                <div className="text-xs font-mono text-gray-300 break-all" dir="ltr">
                  {report.md5}
                </div>
              </div>
            </div>

            <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="min-w-0 space-y-0.5">
                <div className="text-[11px] text-gray-400">بصمة SHA-256 الحقيقية</div>
                <div className="text-xs font-mono text-[#D4AF37] break-all" dir="ltr">
                  {report.sha256}
                </div>
              </div>
              <button
                type="button"
                onClick={copySha256}
                className="px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0 self-start sm:self-center"
              >
                {copiedSha ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedSha ? 'تم النسخ' : 'نسخ SHA-256'}</span>
              </button>
            </div>

            {report.firstBytesHex && (
              <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 space-y-1 font-mono text-[11px]">
                <div className="text-gray-400">أول 64 بايت من ترويسة الملف (HEX / ASCII)</div>
                <div className="text-gray-300 break-all" dir="ltr">{report.firstBytesHex}</div>
                <div className="text-emerald-300 break-all" dir="ltr">{report.firstBytesAscii}</div>
              </div>
            )}
          </div>

          {/* Standard Metadata & EXIF Field Presence Checklist */}
          <div className="rounded-xl bg-gray-900 border border-gray-800 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <h3 className="text-xs font-bold text-white">حالة حقول EXIF والبيانات الوصفية القياسية</h3>
              <span className="text-xs font-mono tabular-nums text-gray-400">
                متوفر: {report.standardChecklist.filter((x) => x.value !== null).length} / {report.standardChecklist.length}
              </span>
            </div>

            <div className="overflow-x-auto border border-gray-800 rounded-xl">
              <table className="w-full text-xs text-right">
                <thead className="bg-gray-950 text-gray-400 border-b border-gray-800">
                  <tr>
                    <th className="py-2.5 px-3">الحقل</th>
                    <th className="py-2.5 px-3">الحالة</th>
                    <th className="py-2.5 px-3">القيمة المستخرجة فعلياً</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {report.standardChecklist.map((item) => (
                    <tr key={item.key} className="hover:bg-gray-950/60">
                      <td className="py-2.5 px-3 font-bold text-gray-200">{item.label}</td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        {item.value !== null ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400 font-bold">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>موجود</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-gray-500">
                            <MinusCircle className="w-3.5 h-3.5" />
                            <span>غير موجود</span>
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-xs" dir="ltr">
                        {item.value !== null ? (
                          <span className="text-white break-all">{item.value}</span>
                        ) : (
                          <span className="text-gray-500 font-sans">غير موجود في الملف</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* All Extracted EXIF / XMP / PNG / PDF Tags */}
          <div className="rounded-xl bg-gray-900 border border-gray-800 p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <h3 className="text-xs font-bold text-white">
                كافة الوسوم والحقول المستخرجة من ترويسة الملف ({report.tags.length})
              </h3>
              {report.tags.length > 0 && (
                <div className="relative sm:w-72">
                  <Search className="w-3.5 h-3.5 text-gray-500 absolute right-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    value={tagSearch}
                    onChange={(e) => setTagSearch(e.target.value)}
                    placeholder="بحث في الوسوم أو القيم..."
                    className="w-full pr-9 pl-8 py-1.5 rounded-lg bg-gray-950 border border-gray-800 text-xs text-white focus:border-[#D4AF37] outline-none"
                  />
                  {tagSearch && (
                    <button
                      type="button"
                      onClick={() => setTagSearch('')}
                      aria-label="مسح البحث"
                      className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white cursor-pointer"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              )}
            </div>

            {report.tags.length === 0 ? (
              <div className="p-6 rounded-xl bg-gray-950 border border-gray-800 text-center text-xs text-gray-400">
                لا توجد وسوم EXIF أو XMP أو حقول ترويسة إضافية داخل هذا الملف (قد يكون ملفاً نصياً، أو صورة بدون بيانات EXIF، أو تم مسح البيانات الوصفية منها مسبقاً).
              </div>
            ) : (
              <div className="overflow-x-auto border border-gray-800 rounded-xl max-h-96 overflow-y-auto">
                <table className="w-full text-xs text-right">
                  <thead className="bg-gray-950 text-gray-400 border-b border-gray-800 font-mono sticky top-0">
                    <tr>
                      <th className="py-2.5 px-3">القسم</th>
                      <th className="py-2.5 px-3">المعرّف</th>
                      <th className="py-2.5 px-3">اسم الحقل</th>
                      <th className="py-2.5 px-3">القيمة</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 font-mono text-[11px]">
                    {filteredTags.map((tag, idx) => (
                      <tr key={`${tag.group}-${tag.tagId}-${idx}`} className="hover:bg-gray-950/60">
                        <td className="py-2 px-3 text-[#D4AF37] font-bold">{tag.group}</td>
                        <td className="py-2 px-3 text-gray-400 tabular-nums">{tag.tagId}</td>
                        <td className="py-2 px-3 text-emerald-300">{tag.name}</td>
                        <td className="py-2 px-3 text-gray-200 break-all" dir="ltr">
                          {tag.value}
                        </td>
                      </tr>
                    ))}
                    {filteredTags.length === 0 && (
                      <tr>
                        <td colSpan={4} className="py-6 text-center text-gray-500 font-sans text-xs">
                          لا توجد وسوم مطابقة لعبارة البحث.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
