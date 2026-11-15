export type ProceduralCategory =
  | 'tactical'
  | 'cyber'
  | 'terminal'
  | 'stealth';

export interface ProceduralPaletteDef {
  id: string;
  nameEn: string;
  nameAr: string;
  category: ProceduralCategory;
  categoryAr: string;
  hue: number;
  sat: number;
  lum: number;
  secondaryHueOffset: number;
  bgLum: number;
  bgSat: number;
}

export interface ProceduralPatternDef {
  id: string;
  nameEn: string;
  nameAr: string;
  buildCss: (accentRgbaSoft: string, accentRgbaMid: string) => {
    bgImage: string;
    bgSize: string;
  };
}

export interface ProceduralSurfaceDef {
  id: string;
  nameEn: string;
  nameAr: string;
  surfaceAlpha: number;
  deepAlpha: number;
  borderAlpha: number;
  backdropBlur: string;
  radiusScale: 'sharp' | 'balanced' | 'soft';
  glowStrength: number;
}

export interface ProceduralTheme {
  id: string; // e.g. 'proc-001' .. 'proc-540'
  index: number;
  nameEn: string;
  nameAr: string;
  category: ProceduralCategory;
  categoryAr: string;
  paletteId: string;
  patternId: string;
  surfaceStyleId: string;
  accentHex: string;
  secondaryHex: string;
  bgHex: string;
  surfaceRgba: string;
  surfaceDeepRgba: string;
  surfacePreviewHex: string;
  borderRgba: string;
  bgImageCss: string;
  bgSizeCss: string;
  backdropBlur: string;
  cardShadowCss: string;
  radiusCss: string;
  searchIndex: string;
}

function hslToHex(h: number, s: number, l: number): string {
  const hue = ((h % 360) + 360) % 360;
  const sat = Math.max(0, Math.min(100, s)) / 100;
  const lig = Math.max(0, Math.min(100, l)) / 100;
  const a = sat * Math.min(lig, 1 - lig);
  const f = (n: number) => {
    const k = (n + hue / 30) % 12;
    const color = lig - a * Math.max(Math.min(k - 3, 9 - k, 1), -1);
    return Math.round(255 * color)
      .toString(16)
      .padStart(2, '0');
  };
  return `#${f(0)}${f(8)}${f(4)}`;
}

function hexToRgba(hex: string, alpha: number): string {
  const clean = hex.replace('#', '');
  const r = parseInt(clean.slice(0, 2), 16);
  const g = parseInt(clean.slice(2, 4), 16);
  const b = parseInt(clean.slice(4, 6), 16);
  return `rgba(${r}, ${g}, ${b}, ${alpha.toFixed(2)})`;
}

export const PROCEDURAL_PALETTES: ProceduralPaletteDef[] = [
  { id: 'sov_gold', nameEn: 'Sovereign Gold', nameAr: 'الذهب السيادي', category: 'tactical', categoryAr: 'عسكري / تكتيكي', hue: 45, sat: 74, lum: 53, secondaryHueOffset: 115, bgLum: 5, bgSat: 34 },
  { id: 'matrix_green', nameEn: 'Cyber Matrix', nameAr: 'مصفوفة سايبر', category: 'cyber', categoryAr: 'سايبر / نيون', hue: 152, sat: 92, lum: 52, secondaryHueOffset: 24, bgLum: 4, bgSat: 48 },
  { id: 'intel_blue', nameEn: 'Deep Blue Intel', nameAr: 'الأزرق الاستخباراتي', category: 'tactical', categoryAr: 'عسكري / تكتيكي', hue: 199, sat: 93, lum: 60, secondaryHueOffset: 22, bgLum: 5, bgSat: 55 },
  { id: 'crimson_ops', nameEn: 'Crimson Cyber', nameAr: 'القرمزي الهجومي', category: 'cyber', categoryAr: 'سايبر / نيون', hue: 350, sat: 89, lum: 60, secondaryHueOffset: 18, bgLum: 4, bgSat: 44 },
  { id: 'neon_violet', nameEn: 'Neon Purple Hack', nameAr: 'نيون بنفسجي', category: 'cyber', categoryAr: 'سايبر / نيون', hue: 272, sat: 94, lum: 71, secondaryHueOffset: 36, bgLum: 4, bgSat: 52 },
  { id: 'solar_amber', nameEn: 'Solar Amber CRT', nameAr: 'كهرمان شمسي', category: 'terminal', categoryAr: 'طرفية / كلاسيكي', hue: 37, sat: 92, lum: 51, secondaryHueOffset: 10, bgLum: 4, bgSat: 56 },
  { id: 'titanium_carbon', nameEn: 'Midnight Carbon', nameAr: 'كربون تيتانيوم', category: 'stealth', categoryAr: 'شبح / بسيط', hue: 215, sat: 22, lum: 78, secondaryHueOffset: -10, bgLum: 4, bgSat: 10 },
  { id: 'cobalt_radar', nameEn: 'Cobalt Radar', nameAr: 'رادار كوبالت', category: 'tactical', categoryAr: 'عسكري / تكتيكي', hue: 218, sat: 90, lum: 64, secondaryHueOffset: -28, bgLum: 5, bgSat: 46 },
  { id: 'biohazard_lime', nameEn: 'Biohazard Lime', nameAr: 'لايم حيوي', category: 'cyber', categoryAr: 'سايبر / نيون', hue: 85, sat: 88, lum: 54, secondaryHueOffset: 48, bgLum: 4, bgSat: 42 },
  { id: 'arctic_recon', nameEn: 'Arctic Cyan Recon', nameAr: 'استطلاع قطبي', category: 'tactical', categoryAr: 'عسكري / تكتيكي', hue: 186, sat: 92, lum: 54, secondaryHueOffset: 20, bgLum: 5, bgSat: 44 },
  { id: 'thermal_infra', nameEn: 'Thermal Infrared', nameAr: 'أشعة تحت حمراء', category: 'tactical', categoryAr: 'عسكري / تكتيكي', hue: 18, sat: 94, lum: 58, secondaryHueOffset: 24, bgLum: 4, bgSat: 40 },
  { id: 'magenta_payload', nameEn: 'Magenta Payload', nameAr: 'أرجواني بايلود', category: 'cyber', categoryAr: 'سايبر / نيون', hue: 316, sat: 88, lum: 65, secondaryHueOffset: -35, bgLum: 4, bgSat: 45 },
  { id: 'emerald_soc', nameEn: 'Emerald Guard', nameAr: 'زمرد عمليات SOC', category: 'terminal', categoryAr: 'طرفية / كلاسيكي', hue: 162, sat: 84, lum: 48, secondaryHueOffset: 26, bgLum: 4, bgSat: 42 },
  { id: 'tungsten_stealth', nameEn: 'Stealth Tungsten', nameAr: 'تنجستن شبح', category: 'stealth', categoryAr: 'شبح / بسيط', hue: 222, sat: 14, lum: 72, secondaryHueOffset: 140, bgLum: 6, bgSat: 12 },
  { id: 'blood_zero', nameEn: 'Zero-Day Scarlet', nameAr: 'قرمزي زيرو-داي', category: 'cyber', categoryAr: 'سايبر / نيون', hue: 4, sat: 88, lum: 58, secondaryHueOffset: 30, bgLum: 4, bgSat: 46 },
  { id: 'electric_indigo', nameEn: 'Electric Indigo', nameAr: 'نيلي كهربائي', category: 'cyber', categoryAr: 'سايبر / نيون', hue: 246, sat: 90, lum: 69, secondaryHueOffset: -42, bgLum: 5, bgSat: 50 },
  { id: 'desert_specops', nameEn: 'Desert SpecOps', nameAr: 'صحراوي تكتيكي', category: 'tactical', categoryAr: 'عسكري / تكتيكي', hue: 34, sat: 62, lum: 57, secondaryHueOffset: 92, bgLum: 5, bgSat: 28 },
  { id: 'plasma_teal', nameEn: 'Plasma Teal CRT', nameAr: 'بلازما تيل', category: 'terminal', categoryAr: 'طرفية / كلاسيكي', hue: 172, sat: 86, lum: 50, secondaryHueOffset: 24, bgLum: 4, bgSat: 45 },
];

export const PROCEDURAL_PATTERNS: ProceduralPatternDef[] = [
  {
    id: 'radar_dots',
    nameEn: 'Dot Matrix',
    nameAr: 'نقط رادار',
    buildCss: (soft) => ({
      bgImage: `radial-gradient(${soft} 1px, transparent 1px)`,
      bgSize: '24px 24px',
    }),
  },
  {
    id: 'cyber_grid',
    nameEn: 'Cyber Grid',
    nameAr: 'شبكة سايبر',
    buildCss: (soft) => ({
      bgImage: `linear-gradient(${soft} 1px, transparent 1px), linear-gradient(90deg, ${soft} 1px, transparent 1px)`,
      bgSize: '30px 30px',
    }),
  },
  {
    id: 'crt_scanlines',
    nameEn: 'CRT Scanlines',
    nameAr: 'خطوط طرفية CRT',
    buildCss: (soft) => ({
      bgImage: `linear-gradient(${soft} 50%, transparent 50%)`,
      bgSize: '100% 4px',
    }),
  },
  {
    id: 'carbon_weave',
    nameEn: 'Carbon Weave',
    nameAr: 'نسيج كربون',
    buildCss: (soft) => ({
      bgImage: `repeating-linear-gradient(45deg, ${soft} 0px, ${soft} 2px, transparent 2px, transparent 10px)`,
      bgSize: 'auto',
    }),
  },
  {
    id: 'hex_horizon',
    nameEn: 'Tactical Glow',
    nameAr: 'أفق تكتيكي',
    buildCss: (soft, mid) => ({
      bgImage: `radial-gradient(circle at 15% 12%, ${mid} 0%, transparent 42%), radial-gradient(${soft} 1px, transparent 1px)`,
      bgSize: '100% 100%, 26px 26px',
    }),
  },
  {
    id: 'pure_stealth',
    nameEn: 'Clean Matte',
    nameAr: 'مسطح نقي',
    buildCss: () => ({
      bgImage: 'none',
      bgSize: 'auto',
    }),
  },
];

export const PROCEDURAL_SURFACES: ProceduralSurfaceDef[] = [
  {
    id: 'glass_frosted',
    nameEn: 'Frosted Glass',
    nameAr: 'زجاجي شفاف',
    surfaceAlpha: 0.74,
    deepAlpha: 0.66,
    borderAlpha: 0.34,
    backdropBlur: 'blur(12px)',
    radiusScale: 'soft',
    glowStrength: 0.14,
  },
  {
    id: 'solid_armored',
    nameEn: 'Armored Matte',
    nameAr: 'مصفّح معتم',
    surfaceAlpha: 0.98,
    deepAlpha: 0.96,
    borderAlpha: 0.28,
    backdropBlur: 'none',
    radiusScale: 'balanced',
    glowStrength: 0.08,
  },
  {
    id: 'neon_wireframe',
    nameEn: 'Neon Wireframe',
    nameAr: 'إطار نيون متوهج',
    surfaceAlpha: 0.84,
    deepAlpha: 0.78,
    borderAlpha: 0.56,
    backdropBlur: 'blur(6px)',
    radiusScale: 'balanced',
    glowStrength: 0.26,
  },
  {
    id: 'minimal_hairline',
    nameEn: 'Hairline Clean',
    nameAr: 'حدود فائقة الدقة',
    surfaceAlpha: 0.9,
    deepAlpha: 0.88,
    borderAlpha: 0.18,
    backdropBlur: 'none',
    radiusScale: 'soft',
    glowStrength: 0.04,
  },
  {
    id: 'hud_beveled',
    nameEn: 'Military HUD',
    nameAr: 'شاشة HUD عسكرية',
    surfaceAlpha: 0.82,
    deepAlpha: 0.72,
    borderAlpha: 0.44,
    backdropBlur: 'blur(8px)',
    radiusScale: 'sharp',
    glowStrength: 0.18,
  },
];

function buildProceduralCatalog(): ProceduralTheme[] {
  const list: ProceduralTheme[] = [];
  let counter = 1;

  for (const pal of PROCEDURAL_PALETTES) {
    for (const pat of PROCEDURAL_PATTERNS) {
      for (const surf of PROCEDURAL_SURFACES) {
        const index = counter++;
        const id = `proc-${String(index).padStart(3, '0')}`;
        const accentHex = hslToHex(pal.hue, pal.sat, pal.lum);
        const secondaryHex = hslToHex(pal.hue + pal.secondaryHueOffset, Math.max(40, pal.sat - 8), Math.min(72, pal.lum + 2));
        const bgHex = hslToHex(pal.hue, pal.bgSat, pal.bgLum);
        const surfaceBaseHex = hslToHex(pal.hue, Math.max(12, pal.bgSat - 4), pal.bgLum + 4);
        const surfaceDeepHex = hslToHex(pal.hue, pal.bgSat, Math.max(2, pal.bgLum - 2));

        const patternCss = pat.buildCss(
          hexToRgba(accentHex, pat.id === 'crt_scanlines' ? 0.04 : 0.07),
          hexToRgba(accentHex, 0.14)
        );

        const surfaceRgba = hexToRgba(surfaceBaseHex, surf.surfaceAlpha);
        const surfaceDeepRgba = hexToRgba(surfaceDeepHex, surf.deepAlpha);
        const borderRgba = hexToRgba(accentHex, surf.borderAlpha);
        const cardShadowCss =
          surf.glowStrength > 0.1
            ? `0 12px 32px -12px rgba(0,0,0,0.75), 0 0 0 1px ${hexToRgba(accentHex, surf.glowStrength * 0.45)}`
            : `0 10px 25px -12px rgba(0,0,0,0.65)`;
        const radiusCss =
          surf.radiusScale === 'sharp' ? '0.55rem' : surf.radiusScale === 'soft' ? '1.25rem' : '1rem';

        const nameEn = `${pal.nameEn} • ${pat.nameEn} • ${surf.nameEn}`;
        const nameAr = `${pal.nameAr} • ${pat.nameAr} • ${surf.nameAr}`;

        list.push({
          id,
          index,
          nameEn,
          nameAr,
          category: pal.category,
          categoryAr: pal.categoryAr,
          paletteId: pal.id,
          patternId: pat.id,
          surfaceStyleId: surf.id,
          accentHex,
          secondaryHex,
          bgHex,
          surfaceRgba,
          surfaceDeepRgba,
          surfacePreviewHex: surfaceBaseHex,
          borderRgba,
          bgImageCss: patternCss.bgImage,
          bgSizeCss: patternCss.bgSize,
          backdropBlur: surf.backdropBlur,
          cardShadowCss,
          radiusCss,
          searchIndex: `${id} ${nameEn} ${nameAr} ${pal.categoryAr} ${accentHex}`.toLowerCase(),
        });
      }
    }
  }

  return list;
}

export const PROCEDURAL_THEMES_CATALOG: ProceduralTheme[] = buildProceduralCatalog();

const PROCEDURAL_THEME_MAP = new Map<string, ProceduralTheme>(
  PROCEDURAL_THEMES_CATALOG.map((t) => [t.id, t])
);

export function getProceduralThemeById(id?: string | null): ProceduralTheme | undefined {
  if (!id) return undefined;
  return PROCEDURAL_THEME_MAP.get(id);
}

export function pickRandomProceduralTheme(excludeId?: string): ProceduralTheme {
  const pool = excludeId
    ? PROCEDURAL_THEMES_CATALOG.filter((t) => t.id !== excludeId)
    : PROCEDURAL_THEMES_CATALOG;
  const idx = Math.floor(Math.random() * pool.length);
  return pool[idx] || PROCEDURAL_THEMES_CATALOG[0];
}

export function applyProceduralThemeVariablesToRoot(theme: ProceduralTheme | null) {
  const root = document.documentElement;
  if (!theme) {
    const vars = [
      '--sov-accent',
      '--sov-secondary',
      '--sov-bg',
      '--sov-surface',
      '--sov-surface-deep',
      '--sov-border',
      '--sov-bg-image',
      '--sov-bg-size',
      '--sov-backdrop',
      '--sov-card-shadow',
      '--sov-radius',
    ];
    vars.forEach((v) => root.style.removeProperty(v));
    return;
  }

  root.style.setProperty('--sov-accent', theme.accentHex);
  root.style.setProperty('--sov-secondary', theme.secondaryHex);
  root.style.setProperty('--sov-bg', theme.bgHex);
  root.style.setProperty('--sov-surface', theme.surfaceRgba);
  root.style.setProperty('--sov-surface-deep', theme.surfaceDeepRgba);
  root.style.setProperty('--sov-border', theme.borderRgba);
  root.style.setProperty('--sov-bg-image', theme.bgImageCss);
  root.style.setProperty('--sov-bg-size', theme.bgSizeCss);
  root.style.setProperty('--sov-backdrop', theme.backdropBlur);
  root.style.setProperty('--sov-card-shadow', theme.cardShadowCss);
  root.style.setProperty('--sov-radius', theme.radiusCss);
}
