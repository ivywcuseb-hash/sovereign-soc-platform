/**
 * Arabic Contextual Reshaping & BiDi Visual Line Ordering for jsPDF
 * Converts logical UTF-8 Arabic text into Presentation Forms-B (U+FE70..U+FEFC)
 * with Lam-Alef ligatures and right-to-left visual run ordering for LTR PDF engines.
 */

const ARABIC_CHAR_REGEX = /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]/;
const DIACRITICS_REGEX = /[\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06ED]/g;

// [isolated, final, initial, medial]
type GlyphForms = readonly [number, number, number, number];

const ARABIC_FORMS: Record<number, GlyphForms> = {
  0x0621: [0xfe80, 0xfe80, 0xfe80, 0xfe80], // ء (non-joining)
  0x0622: [0xfe81, 0xfe82, 0xfe81, 0xfe82], // آ
  0x0623: [0xfe83, 0xfe84, 0xfe83, 0xfe84], // أ
  0x0624: [0xfe85, 0xfe86, 0xfe85, 0xfe86], // ؤ
  0x0625: [0xfe87, 0xfe88, 0xfe87, 0xfe88], // إ
  0x0626: [0xfe89, 0xfe8a, 0xfe8b, 0xfe8c], // ئ
  0x0627: [0xfe8d, 0xfe8e, 0xfe8d, 0xfe8e], // ا
  0x0628: [0xfe8f, 0xfe90, 0xfe91, 0xfe92], // ب
  0x0629: [0xfe93, 0xfe94, 0xfe93, 0xfe94], // ة
  0x062a: [0xfe95, 0xfe96, 0xfe97, 0xfe98], // ت
  0x062b: [0xfe99, 0xfe9a, 0xfe9b, 0xfe9c], // ث
  0x062c: [0xfe9d, 0xfe9e, 0xfe9f, 0xfea0], // ج
  0x062d: [0xfea1, 0xfea2, 0xfea3, 0xfea4], // ح
  0x062e: [0xfea5, 0xfea6, 0xfea7, 0xfea8], // خ
  0x062f: [0xfea9, 0xfeaa, 0xfea9, 0xfeaa], // د
  0x0630: [0xfeab, 0xfeac, 0xfeab, 0xfeac], // ذ
  0x0631: [0xfead, 0xfeae, 0xfead, 0xfeae], // ر
  0x0632: [0xfeaf, 0xfeb0, 0xfeaf, 0xfeb0], // ز
  0x0633: [0xfeb1, 0xfeb2, 0xfeb3, 0xfeb4], // س
  0x0634: [0xfeb5, 0xfeb6, 0xfeb7, 0xfeb8], // ش
  0x0635: [0xfeb9, 0xfeba, 0xfebb, 0xfebc], // ص
  0x0636: [0xfebd, 0xfebe, 0xfebf, 0xfec0], // ض
  0x0637: [0xfec1, 0xfec2, 0xfec3, 0xfec4], // ط
  0x0638: [0xfec5, 0xfec6, 0xfec7, 0xfec8], // ظ
  0x0639: [0xfec9, 0xfeca, 0xfecb, 0xfecc], // ع
  0x063a: [0xfecd, 0xfece, 0xfecf, 0xfed0], // غ
  0x0640: [0x0640, 0x0640, 0x0640, 0x0640], // ـ (tatweel)
  0x0641: [0xfed1, 0xfed2, 0xfed3, 0xfed4], // ف
  0x0642: [0xfed5, 0xfed6, 0xfed7, 0xfed8], // ق
  0x0643: [0xfed9, 0xfeda, 0xfedb, 0xfedc], // ك
  0x0644: [0xfedd, 0xfede, 0xfedf, 0xfee0], // ل
  0x0645: [0xfee1, 0xfee2, 0xfee3, 0xfee4], // م
  0x0646: [0xfee5, 0xfee6, 0xfee7, 0xfee8], // ن
  0x0647: [0xfee9, 0xfeea, 0xfeeb, 0xfeec], // ه
  0x0648: [0xfeed, 0xfeee, 0xfeed, 0xfeee], // و
  0x0649: [0xfeef, 0xfef0, 0xfeef, 0xfef0], // ى
  0x064a: [0xfef1, 0xfef2, 0xfef3, 0xfef4], // ي
  0x0671: [0xfe8d, 0xfe8e, 0xfe8d, 0xfe8e], // ٱ
  0x067e: [0xfb56, 0xfb57, 0xfb58, 0xfb59], // پ
  0x0686: [0xfb7a, 0xfb7b, 0xfb7c, 0xfb7d], // چ
  0x0698: [0xfb8a, 0xfb8b, 0xfb8a, 0xfb8b], // ژ
  0x06a4: [0xfb6a, 0xfb6b, 0xfb6c, 0xfb6d], // ڤ
  0x06a9: [0xfb8e, 0xfb8f, 0xfb90, 0xfb91], // ک
  0x06af: [0xfb92, 0xfb93, 0xfb94, 0xfb95], // گ
  0x06cc: [0xfbfc, 0xfbfd, 0xfbfe, 0xfbff], // ی
};

const NON_JOINING = new Set<number>([0x0621]);
const RIGHT_JOINING_ONLY = new Set<number>([
  0x0622, 0x0623, 0x0624, 0x0625, 0x0627, 0x0629,
  0x062f, 0x0630, 0x0631, 0x0632, 0x0648, 0x0649,
  0x0671, 0x0698,
]);

// Lam (0x0644) + Alef ligatures: [isolated, final]
const LAM_ALEF_LIGATURES: Record<number, readonly [number, number]> = {
  0x0622: [0xfef5, 0xfef6], // لآ
  0x0623: [0xfef7, 0xfef8], // لأ
  0x0625: [0xfef9, 0xfefa], // لإ
  0x0627: [0xfefb, 0xfefc], // لا
};

function canConnectForward(code: number | undefined): boolean {
  if (code === undefined) return false;
  if (!(code in ARABIC_FORMS)) return false;
  return !NON_JOINING.has(code) && !RIGHT_JOINING_ONLY.has(code);
}

function canConnectBackward(code: number | undefined): boolean {
  if (code === undefined) return false;
  if (!(code in ARABIC_FORMS)) return false;
  return !NON_JOINING.has(code);
}

export function hasArabicText(text: string): boolean {
  return ARABIC_CHAR_REGEX.test(text);
}

/**
 * Converts logical Arabic letters to contextual Presentation Forms-B glyphs
 * while keeping logical character sequence intact (ready for width wrapping).
 */
export function shapeArabicLogical(input: string): string {
  if (!input || !hasArabicText(input)) return input;

  const cleaned = input.replace(DIACRITICS_REGEX, '');
  const codes = Array.from(cleaned).map((ch) => ch.codePointAt(0) ?? 0);
  const out: number[] = [];

  for (let i = 0; i < codes.length; i++) {
    const curr = codes[i];
    const prev = i > 0 ? codes[i - 1] : undefined;
    const next = i + 1 < codes.length ? codes[i + 1] : undefined;

    if (curr === 0x0644 && next !== undefined && next in LAM_ALEF_LIGATURES) {
      const lig = LAM_ALEF_LIGATURES[next];
      const joinedPrev = canConnectForward(prev);
      out.push(joinedPrev ? lig[1] : lig[0]);
      i += 1; // consume Alef variant
      continue;
    }

    const forms = ARABIC_FORMS[curr];
    if (!forms) {
      out.push(curr);
      continue;
    }

    const joinedPrev = canConnectBackward(curr) && canConnectForward(prev);
    const joinedNext = canConnectForward(curr) && canConnectBackward(next);

    if (joinedPrev && joinedNext) {
      out.push(forms[3]); // medial
    } else if (joinedPrev) {
      out.push(forms[1]); // final
    } else if (joinedNext) {
      out.push(forms[2]); // initial
    } else {
      out.push(forms[0]); // isolated
    }
  }

  return String.fromCodePoint(...out);
}

const MIRROR_BRACKETS: Record<string, string> = {
  '(': ')',
  ')': '(',
  '[': ']',
  ']': '[',
  '{': '}',
  '}': '{',
  '<': '>',
  '>': '<',
  '«': '»',
  '»': '«',
};

function isStrongLtrChar(ch: string): boolean {
  return /[A-Za-z0-9]/.test(ch);
}

function isLtrBridgeChar(ch: string): boolean {
  return /[\s\-_.:/@+#=,%&]/.test(ch);
}

interface BidiRun {
  dir: 'ltr' | 'rtl';
  text: string;
}

/**
 * Reorders a single shaped logical line into visual LTR string order for jsPDF.
 */
export function reorderBiDiLine(shapedLine: string): string {
  if (!shapedLine || !hasArabicText(shapedLine)) return shapedLine;

  const chars = Array.from(shapedLine);
  const runs: BidiRun[] = [];
  let i = 0;

  while (i < chars.length) {
    if (isStrongLtrChar(chars[i])) {
      let end = i + 1;
      let lastStrong = i;
      while (end < chars.length) {
        const ch = chars[end];
        if (isStrongLtrChar(ch)) {
          lastStrong = end;
          end++;
        } else if (ch === '%' || ch === '+') {
          // Trailing percentage/sign attached to number stays LTR
          lastStrong = end;
          end++;
        } else if (isLtrBridgeChar(ch)) {
          // Look ahead to see if another strong LTR char follows before any Arabic char
          let look = end + 1;
          while (look < chars.length && isLtrBridgeChar(chars[look])) {
            look++;
          }
          if (look < chars.length && isStrongLtrChar(chars[look])) {
            end = look;
          } else {
            break;
          }
        } else {
          break;
        }
      }
      runs.push({ dir: 'ltr', text: chars.slice(i, lastStrong + 1).join('') });
      i = lastStrong + 1;
    } else {
      let end = i + 1;
      while (end < chars.length && !isStrongLtrChar(chars[end])) {
        end++;
      }
      const rtlSegment = chars
        .slice(i, end)
        .map((c) => MIRROR_BRACKETS[c] || c)
        .reverse()
        .join('');
      runs.push({ dir: 'rtl', text: rtlSegment });
      i = end;
    }
  }

  return runs
    .reverse()
    .map((r) => r.text)
    .join('');
}

/**
 * Shapes and reorders a single-line or multi-line string (respecting existing `\n`).
 */
export function formatPdfText(raw: string): string {
  const safe = String(raw ?? '');
  if (!safe || !hasArabicText(safe)) return safe;
  return safe
    .split('\n')
    .map((line) => reorderBiDiLine(shapeArabicLogical(line)))
    .join('\n');
}

/**
 * Wraps text at `maxWidthMm` using the provided jsPDF split function BEFORE
 * reversing each line visually, so multi-line Arabic paragraphs and table cells
 * read in exact top-to-bottom RTL order.
 */
export function wrapAndFormatPdfLines(
  splitTextFn: (text: string, maxWidth: number) => string[],
  raw: string,
  maxWidthMm: number
): string[] {
  const safe = String(raw ?? '');
  if (!safe) return [''];

  const paragraphs = safe.split('\n');
  const visualLines: string[] = [];

  for (const para of paragraphs) {
    if (!para) {
      visualLines.push('');
      continue;
    }
    if (!hasArabicText(para)) {
      const wrapped = splitTextFn(para, maxWidthMm);
      visualLines.push(...(wrapped.length > 0 ? wrapped : ['']));
    } else {
      const shaped = shapeArabicLogical(para);
      const wrapped = splitTextFn(shaped, maxWidthMm);
      for (const line of wrapped) {
        visualLines.push(reorderBiDiLine(line));
      }
    }
  }

  return visualLines.length > 0 ? visualLines : [''];
}
