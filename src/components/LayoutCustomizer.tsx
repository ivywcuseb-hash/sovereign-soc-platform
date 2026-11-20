import React, { useMemo, useState } from 'react';
import {
  Sliders,
  X,
  LayoutDashboard,
  PanelRight,
  LayoutGrid,
  Palette,
  Type,
  Maximize2,
  Minimize2,
  RotateCcw,
  Check,
  Cloud,
  HardDrive,
  Sparkles,
  Columns,
  Shield,
  FileSearch,
  Briefcase,
  History,
  Mail,
  Clipboard,
  Search,
  Layers,
  Code,
  FileText,
  Diff,
  Terminal,
  Smartphone,
  Database,
  Globe,
  FileCode,
  Cpu,
  Activity,
  User as UserIcon,
  Dices,
  Shuffle,
  Wand2,
  KeyRound,
  FolderArchive,
  Lock,
  MapPin,
  Bug,
  FileCheck2,
  Route,
  ScanEye,
  Radar,
  ShieldAlert,
  PieChart,
  AudioLines,
  MailCheck,
  FileCode2,
  Network,
  ScrollText,
} from 'lucide-react';
import {
  PROCEDURAL_THEMES_CATALOG,
  getProceduralThemeById,
  pickRandomProceduralTheme,
  type ProceduralCategory,
} from '../utils/proceduralThemeEngine';

export type AppTabId =
  | 'dashboard'
  | 'analyzer'
  | 'apk'
  | 'browser'
  | 'threat_intel'
  | 'deobfuscator'
  | 'binary_lab'
  | 'live_feeds'
  | 'email'
  | 'clipboard'
  | 'search'
  | 'ela'
  | 'hex'
  | 'audit'
  | 'evidence'
  | 'profile'
  | 'samples'
  | 'comparison'
  | 'custody'
  | 'parser'
  | 'reports'
  | 'breach_lookup'
  | 'archive_extractor'
  | 'ssl_inspector'
  | 'ip_mapper'
  | 'malware_hash'
  | 'pdf_forensics'
  | 'url_tracer'
  | 'steg_inspector'
  | 'cyber_telemetry'
  | 'vuln_kev_dashboard'
  | 'asset_os_dashboard'
  | 'live_voice'
  | 'dns_email_auditor'
  | 'yara_scanner'
  | 'jwt_inspector'
  | 'pcap_inspector'
  | 'log_analyzer';

export type LayoutStructure =
  | 'top'
  | 'sidebar'
  | 'multi_grid'
  | 'compact_dashboard'
  | 'full_width_stack'
  | 'minimal_sidebar';

export type ThemePresetId =
  | 'sovereign_gold'
  | 'cyber_matrix'
  | 'deep_blue'
  | 'crimson_red'
  | 'neon_purple'
  | 'midnight_carbon'
  | 'minimalist_dark'
  | 'solar_amber'
  | 'procedural';

export type FontScaleId = 'sm' | 'md' | 'lg';
export type DensityMode = 'compact' | 'comfortable';

export interface UiPreferences {
  layoutStructure: LayoutStructure;
  themePreset: ThemePresetId;
  proceduralThemeId?: string;
  fontScale: FontScaleId;
  density: DensityMode;
  sidebarCollapsed: boolean;
  multiGridColumns: 2 | 3;
  multiGridPanels: AppTabId[];
  updatedAt: string;
}

export const DEFAULT_UI_PREFERENCES: UiPreferences = {
  layoutStructure: 'top',
  themePreset: 'sovereign_gold',
  proceduralThemeId: 'proc-001',
  fontScale: 'md',
  density: 'comfortable',
  sidebarCollapsed: false,
  multiGridColumns: 2,
  multiGridPanels: ['dashboard', 'live_feeds', 'threat_intel', 'binary_lab'],
  updatedAt: new Date().toISOString(),
};

export type NavGroupId = 'command' | 'files' | 'network' | 'security' | 'system';

export const NAV_GROUP_ORDER: readonly NavGroupId[] = ['command', 'files', 'network', 'security', 'system'];

export interface NavTabMeta {
  id: AppTabId;
  label: string;
  shortLabel: string;
  group: NavGroupId;
  groupLabel: string;
}

export const NAV_TABS_META: NavTabMeta[] = [
  // 1. القيادة والمراقبة
  { id: 'dashboard', label: 'لوحة التحكم', shortLabel: 'الرئيسية', group: 'command', groupLabel: 'القيادة والمراقبة' },
  { id: 'cyber_telemetry', label: 'مراقبة تدفق الشبكة', shortLabel: 'تدفق الشبكة', group: 'command', groupLabel: 'القيادة والمراقبة' },
  { id: 'vuln_kev_dashboard', label: 'الثغرات المستغلة (KEV)', shortLabel: 'ثغرات KEV', group: 'command', groupLabel: 'القيادة والمراقبة' },
  { id: 'asset_os_dashboard', label: 'الأصول وأنظمة التشغيل', shortLabel: 'توزيع الأصول', group: 'command', groupLabel: 'القيادة والمراقبة' },
  { id: 'live_feeds', label: 'التغذيات الأمنية الحية', shortLabel: 'التغذيات', group: 'command', groupLabel: 'القيادة والمراقبة' },
  { id: 'audit', label: 'سجل العمليات', shortLabel: 'السجل', group: 'command', groupLabel: 'القيادة والمراقبة' },
  { id: 'reports', label: 'التقارير الرسمية', shortLabel: 'التقارير', group: 'command', groupLabel: 'القيادة والمراقبة' },

  // 2. تحليل الملفات والوسائط
  { id: 'analyzer', label: 'تحليل الملفات الشامل', shortLabel: 'تحليل الملفات', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'hex', label: 'عارض البايتات (Hex)', shortLabel: 'Hex', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'ela', label: 'فحص تلاعب الصور (ELA)', shortLabel: 'ELA', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'steg_inspector', label: 'كاشف الإخفاء (LSB)', shortLabel: 'إخفاء الصور', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'pdf_forensics', label: 'محلل مستندات PDF', shortLabel: 'مستندات PDF', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'archive_extractor', label: 'فحص الأرشيف (ZIP)', shortLabel: 'الأرشيف', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'binary_lab', label: 'تحليل الباينري (PE/ELF)', shortLabel: 'الباينري', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'apk', label: 'تحليل حزم APK', shortLabel: 'APK', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'yara_scanner', label: 'ماسح قواعد YARA (YARA Pattern Scanner)', shortLabel: 'ماسح YARA', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },
  { id: 'comparison', label: 'مقارنة الأدلة', shortLabel: 'المقارنة', group: 'files', groupLabel: 'تحليل الملفات والوسائط' },

  // 3. الشبكات والاستخبارات
  { id: 'dns_email_auditor', label: 'أمان النطاقات (DNS/SPF)', shortLabel: 'فحص DNS/SPF', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'email', label: 'تحليل ترويسة البريد', shortLabel: 'البريد', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'ssl_inspector', label: 'فحص شهادات SSL/TLS', shortLabel: 'SSL/TLS', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'url_tracer', label: 'متتبع تحويلات الروابط', shortLabel: 'تتبع الروابط', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'ip_mapper', label: 'خريطة وتحديد موقع IP', shortLabel: 'خريطة IP', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'pcap_inspector', label: 'محلل حزم الشبكة (PCAP)', shortLabel: 'محلل PCAP', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'threat_intel', label: 'استخبارات التهديدات', shortLabel: 'الاستخبارات', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'search', label: 'البحث المفتوح (OSINT)', shortLabel: 'OSINT', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'browser', label: 'سجل المتصفح (SQLite)', shortLabel: 'المتصفح', group: 'network', groupLabel: 'الشبكات والاستخبارات' },
  { id: 'parser', label: 'استخراج المؤشرات (IoC)', shortLabel: 'محلل IoC', group: 'network', groupLabel: 'الشبكات والاستخبارات' },

  // 4. الأدلة والهوية والبرمجيات
  { id: 'evidence', label: 'مخزن الأدلة الرقمية', shortLabel: 'الأدلة', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },
  { id: 'custody', label: 'سلسلة الحيازة', shortLabel: 'الحيازة', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },
  { id: 'clipboard', label: 'فحص الحافظة', shortLabel: 'الحافظة', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },
  { id: 'breach_lookup', label: 'فحص التسريبات', shortLabel: 'التسريبات', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },
  { id: 'malware_hash', label: 'فحص بصمات الفيروسات', shortLabel: 'فحص Hash', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },
  { id: 'deobfuscator', label: 'فك تشويه السكربتات', shortLabel: 'السكربتات', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },
  { id: 'jwt_inspector', label: 'محلل رموز التوثيق (JWT)', shortLabel: 'محلل JWT', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },
  { id: 'log_analyzer', label: 'محلل السجلات الحقيقي (Real Log Analyzer)', shortLabel: 'محلل السجلات', group: 'security', groupLabel: 'الأدلة والهوية والبرمجيات' },

  // 5. المساعد والنظام
  { id: 'live_voice', label: 'المساعد الذكي والصوتي', shortLabel: 'المساعد الحي', group: 'system', groupLabel: 'المساعد والنظام' },
  { id: 'profile', label: 'الحساب والإعدادات', shortLabel: 'الحساب', group: 'system', groupLabel: 'المساعد والنظام' },
];

export function renderTabIcon(tabId: AppTabId, className = 'w-4 h-4') {
  switch (tabId) {
    case 'dashboard':
      return <LayoutDashboard className={className} />;
    case 'analyzer':
      return <FileSearch className={className} />;
    case 'evidence':
      return <Briefcase className={className} />;
    case 'custody':
      return <History className={className} />;
    case 'email':
      return <Mail className={className} />;
    case 'clipboard':
      return <Clipboard className={className} />;
    case 'search':
      return <Search className={className} />;
    case 'ela':
      return <Layers className={className} />;
    case 'hex':
      return <Code className={className} />;
    case 'audit':
      return <FileText className={className} />;
    case 'comparison':
      return <Diff className={className} />;
    case 'parser':
      return <Terminal className={className} />;
    case 'apk':
      return <Smartphone className={className} />;
    case 'browser':
      return <Database className={className} />;
    case 'threat_intel':
      return <Globe className={className} />;
    case 'deobfuscator':
      return <FileCode className={className} />;
    case 'binary_lab':
      return <Cpu className={className} />;
    case 'live_feeds':
      return <Activity className={className} />;
    case 'reports':
      return <Shield className={className} />;
    case 'breach_lookup':
      return <KeyRound className={className} />;
    case 'archive_extractor':
      return <FolderArchive className={className} />;
    case 'ssl_inspector':
      return <Lock className={className} />;
    case 'ip_mapper':
      return <MapPin className={className} />;
    case 'malware_hash':
      return <Bug className={className} />;
    case 'pdf_forensics':
      return <FileCheck2 className={className} />;
    case 'url_tracer':
      return <Route className={className} />;
    case 'steg_inspector':
      return <ScanEye className={className} />;
    case 'cyber_telemetry':
      return <Radar className={className} />;
    case 'vuln_kev_dashboard':
      return <ShieldAlert className={className} />;
    case 'asset_os_dashboard':
      return <PieChart className={className} />;
    case 'live_voice':
      return <AudioLines className={className} />;
    case 'dns_email_auditor':
      return <MailCheck className={className} />;
    case 'yara_scanner':
      return <FileCode2 className={className} />;
    case 'jwt_inspector':
      return <KeyRound className={className} />;
    case 'pcap_inspector':
      return <Network className={className} />;
    case 'log_analyzer':
      return <ScrollText className={className} />;
    case 'profile':
      return <UserIcon className={className} />;
    default:
      return <Sparkles className={className} />;
  }
}

export const LAYOUT_PRESETS: {
  id: LayoutStructure;
  title: string;
  subtitle: string;
  badge: string;
}[] = [
  {
    id: 'top',
    title: 'شريط علوي أفقي (Top Navbar)',
    subtitle: 'التصميم القياسي مع شريط تنقل علوي وعرض مركز للوحة النشطة',
    badge: 'قياسي',
  },
  {
    id: 'sidebar',
    title: 'قائمة جانبية عمودية ذكية (Collapsible Sidebar)',
    subtitle: 'تصنيف المختبرات عمودياً مع بحث سريع وإمكانية الطي والتوسيع',
    badge: 'ذكي',
  },
  {
    id: 'minimal_sidebar',
    title: 'هيكل القائمة الجانبية البسيطة (Minimal Sidebar Layout)',
    subtitle: 'شريط أيقونات أنيق وخالٍ من المشتتات للتركيز التام على الفحص',
    badge: 'تركيز',
  },
  {
    id: 'compact_dashboard',
    title: 'لوحة مضغوطة عالية الكثافة (Compact Dashboard)',
    subtitle: 'أقصى قدر من المعلومات والأزرار في الشاشة الواحدة بهوامش مضغوطة',
    badge: 'مكثّف',
  },
  {
    id: 'full_width_stack',
    title: 'تكديس البطاقات بعرض كامل (Full-Width Card Stack)',
    subtitle: 'مساحة بانورامية ممتدة بكامل عرض الشاشة للبيانات والجداول الطويلة',
    badge: 'بانورامي',
  },
  {
    id: 'multi_grid',
    title: 'تخطيط الشبكة المتعددة (Multi-Panel Dashboard Grid)',
    subtitle: 'عرض وتشغيل عدة مختبرات جنائية جنباً إلى جنب في نفس الشاشة',
    badge: 'متعدد',
  },
];

export const THEME_PRESETS: {
  id: ThemePresetId;
  name: string;
  subtitle: string;
  accent: string;
  secondary: string;
  bg: string;
  surface: string;
}[] = [
  {
    id: 'sovereign_gold',
    name: 'Sovereign Gold',
    subtitle: 'الذهبي السيادي الكلاسيكي • تباين رسمي',
    accent: '#D4AF37',
    secondary: '#10B981',
    bg: '#0b0f19',
    surface: '#111827',
  },
  {
    id: 'cyber_matrix',
    name: 'Cyber Matrix Green',
    subtitle: 'أخضر المصفوفة السيبرانية • طرفية فحص حي',
    accent: '#10F58A',
    secondary: '#34D399',
    bg: '#030b07',
    surface: '#071710',
  },
  {
    id: 'deep_blue',
    name: 'Deep Blue Intel',
    subtitle: 'الأزرق الاستخباراتي العميق • مركز عمليات SOC',
    accent: '#38BDF8',
    secondary: '#60A5FA',
    bg: '#040b18',
    surface: '#0b182e',
  },
  {
    id: 'crimson_red',
    name: 'Crimson Cyber Red',
    subtitle: 'الأحمر القرمزي الهجومي • طابع استجابة الحوادث',
    accent: '#F43F5E',
    secondary: '#FB7185',
    bg: '#0e0508',
    surface: '#1a0a0f',
  },
  {
    id: 'neon_purple',
    name: 'Neon Purple Hacking',
    subtitle: 'البنفسجي النيون السيبراني • هندسة عكسية متقدمة',
    accent: '#C084FC',
    secondary: '#E879F9',
    bg: '#080312',
    surface: '#130926',
  },
  {
    id: 'midnight_carbon',
    name: 'Midnight Carbon',
    subtitle: 'الكربون الليلي المعدني • فضي تيتانيوم هادئ',
    accent: '#E2E8F0',
    secondary: '#94A3B8',
    bg: '#09090b',
    surface: '#121317',
  },
  {
    id: 'minimalist_dark',
    name: 'Minimalist Clean Dark',
    subtitle: 'الداكن النظيف البسيط • أسطح هادئة بدون ضوضاء',
    accent: '#60A5FA',
    secondary: '#93C5FD',
    bg: '#101216',
    surface: '#181b21',
  },
  {
    id: 'solar_amber',
    name: 'Solar Amber Terminal',
    subtitle: 'طرفية الكهرمان الشمسية • فوسفور دافئ كلاسيكي',
    accent: '#F59E0B',
    secondary: '#FBBF24',
    bg: '#0c0802',
    surface: '#171004',
  },
];

function LayoutMiniPreview({ id }: { id: LayoutStructure }) {
  if (id === 'top') {
    return (
      <div className="w-12 h-9 rounded-lg bg-gray-950 border border-gray-700 p-1 flex flex-col gap-1 shrink-0">
        <div className="h-1.5 w-full rounded bg-[#D4AF37]" />
        <div className="flex-1 rounded bg-gray-800" />
      </div>
    );
  }
  if (id === 'sidebar') {
    return (
      <div className="w-12 h-9 rounded-lg bg-gray-950 border border-gray-700 p-1 flex gap-1 shrink-0">
        <div className="w-3.5 h-full rounded bg-[#D4AF37]" />
        <div className="flex-1 rounded bg-gray-800" />
      </div>
    );
  }
  if (id === 'minimal_sidebar') {
    return (
      <div className="w-12 h-9 rounded-lg bg-gray-950 border border-gray-700 p-1 flex gap-1 shrink-0">
        <div className="w-1.5 h-full rounded-sm bg-[#D4AF37]" />
        <div className="flex-1 rounded bg-gray-800/80 border border-gray-700/60" />
      </div>
    );
  }
  if (id === 'compact_dashboard') {
    return (
      <div className="w-12 h-9 rounded-lg bg-gray-950 border border-gray-700 p-1 flex flex-col gap-0.5 shrink-0">
        <div className="h-1 w-full rounded-sm bg-[#D4AF37]" />
        <div className="grid grid-cols-3 gap-0.5 flex-1">
          <div className="rounded-sm bg-gray-800" />
          <div className="rounded-sm bg-gray-800" />
          <div className="rounded-sm bg-gray-800" />
          <div className="col-span-2 rounded-sm bg-gray-700" />
          <div className="rounded-sm bg-emerald-400/50" />
        </div>
      </div>
    );
  }
  if (id === 'full_width_stack') {
    return (
      <div className="w-12 h-9 rounded-lg bg-gray-950 border border-gray-700 p-0.5 flex flex-col gap-0.5 shrink-0">
        <div className="h-1 w-full bg-[#D4AF37]" />
        <div className="h-2.5 w-full bg-gray-800" />
        <div className="flex-1 w-full bg-gray-800/70" />
      </div>
    );
  }
  return (
    <div className="w-12 h-9 rounded-lg bg-gray-950 border border-gray-700 p-1 grid grid-cols-2 gap-1 shrink-0">
      <div className="rounded bg-[#D4AF37]" />
      <div className="rounded bg-emerald-400/70" />
      <div className="rounded bg-gray-700" />
      <div className="rounded bg-gray-700" />
    </div>
  );
}

interface LayoutCustomizerDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  preferences: UiPreferences;
  onUpdatePreferences: (patch: Partial<UiPreferences>) => void;
  onResetPreferences: () => void;
  syncStatus: 'idle' | 'saving' | 'saved' | 'local-only';
  isCloudAuthenticated: boolean;
  isOwner?: boolean;
  isTabPaidForUsers?: (tabId: AppTabId) => boolean;
  isTabLocked?: (tabId: AppTabId) => boolean;
  onLockedTabClick?: (tabId: AppTabId) => void;
}

export const LayoutCustomizerDrawer: React.FC<LayoutCustomizerDrawerProps> = ({
  isOpen,
  onClose,
  preferences,
  onUpdatePreferences,
  onResetPreferences,
  syncStatus,
  isCloudAuthenticated,
  isOwner,
  isTabPaidForUsers,
  isTabLocked,
  onLockedTabClick,
}) => {
  const [procSearch, setProcSearch] = useState('');
  const [procCategory, setProcCategory] = useState<'all' | ProceduralCategory>('all');
  const [procVisibleLimit, setProcVisibleLimit] = useState(36);

  const filteredProceduralThemes = useMemo(() => {
    const q = procSearch.trim().toLowerCase();
    return PROCEDURAL_THEMES_CATALOG.filter((theme) => {
      if (procCategory !== 'all' && theme.category !== procCategory) return false;
      if (q && !theme.searchIndex.includes(q)) return false;
      return true;
    });
  }, [procSearch, procCategory]);

  const activeProceduralTheme = useMemo(() => {
    if (preferences.themePreset !== 'procedural') return null;
    return getProceduralThemeById(preferences.proceduralThemeId) || PROCEDURAL_THEMES_CATALOG[0];
  }, [preferences.themePreset, preferences.proceduralThemeId]);

  if (!isOpen) return null;

  const handleInstantRandomTheme = () => {
    const picked = pickRandomProceduralTheme(preferences.proceduralThemeId);
    onUpdatePreferences({
      themePreset: 'procedural',
      proceduralThemeId: picked.id,
    });
  };

  const handleRandomThemeAndLayout = () => {
    const picked = pickRandomProceduralTheme(preferences.proceduralThemeId);
    const otherLayouts = LAYOUT_PRESETS.filter((l) => l.id !== preferences.layoutStructure);
    const randomLayout = otherLayouts[Math.floor(Math.random() * otherLayouts.length)] || LAYOUT_PRESETS[0];
    onUpdatePreferences({
      themePreset: 'procedural',
      proceduralThemeId: picked.id,
      layoutStructure: randomLayout.id,
    });
  };

  const toggleGridPanel = (tabId: AppTabId) => {
    if (isTabLocked?.(tabId)) {
      onLockedTabClick?.(tabId);
      return;
    }
    const exists = preferences.multiGridPanels.includes(tabId);
    let next: AppTabId[];
    if (exists) {
      if (preferences.multiGridPanels.length <= 1) return;
      next = preferences.multiGridPanels.filter((t) => t !== tabId);
    } else {
      next = [...preferences.multiGridPanels, tabId].slice(0, 6);
    }
    onUpdatePreferences({ multiGridPanels: next });
  };

  return (
    <div className="fixed inset-0 z-[75] flex justify-end no-print" dir="rtl">
      {/* Backdrop */}
      <div
        onClick={onClose}
        className="fixed inset-0 bg-black/70 backdrop-blur-sm transition-opacity"
      />

      {/* Slide-over Panel */}
      <aside className="relative z-10 w-full max-w-md h-full bg-gray-950 border-r border-gray-800 shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-gray-800 flex items-center justify-between bg-gray-900/70">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#D4AF37]/15 border border-[#D4AF37]/40 flex items-center justify-center text-[#D4AF37]">
              <Sliders className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white">مُخصِّص الواجهة والهيكل الديناميكي</h2>
              <p className="text-[11px] text-gray-400">
                {PROCEDURAL_THEMES_CATALOG.length + THEME_PRESETS.length} ثيم سيبراني حقيقي و6 هياكل بصرية فورية
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="إغلاق لوحة التخصيص"
            className="p-2 rounded-xl bg-gray-900 hover:bg-gray-800 text-gray-400 hover:text-white border border-gray-800 transition cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Auto-Save Status Bar */}
        <div className="px-5 py-2.5 bg-gray-900/40 border-b border-gray-800/80 flex items-center justify-between text-[11px]">
          <div className="flex items-center gap-2 text-gray-300">
            <HardDrive className="w-3.5 h-3.5 text-emerald-400" />
            <span>LocalStorage نشط</span>
            <span className="text-gray-600">•</span>
            <Cloud className={`w-3.5 h-3.5 ${isCloudAuthenticated ? 'text-emerald-400' : 'text-amber-400'}`} />
            <span>{isCloudAuthenticated ? 'مزامن مع Firebase' : 'محلي (مزامنة Firebase عند الدخول)'}</span>
          </div>
          <span
            className={`font-bold ${
              syncStatus === 'saving'
                ? 'text-amber-400'
                : syncStatus === 'saved'
                ? 'text-emerald-400'
                : 'text-gray-400'
            }`}
          >
            {syncStatus === 'saving' ? 'جاري الحفظ...' : syncStatus === 'saved' ? 'تم الحفظ ✓' : 'تلقائي'}
          </span>
        </div>

        {/* Scrollable Controls */}
        <div className="flex-1 overflow-y-auto p-5 space-y-6">
          {/* 1. Layout Structure */}
          <section className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold text-white flex items-center gap-2">
                <LayoutGrid className="w-4 h-4 text-[#D4AF37]" />
                1. أنماط الهياكل البصرية لتوزيع اللوحة (6 أنماط)
              </h3>
            </div>

            <div className="grid grid-cols-1 gap-2">
              {LAYOUT_PRESETS.map((layout) => {
                const active = preferences.layoutStructure === layout.id;
                return (
                  <button
                    key={layout.id}
                    type="button"
                    onClick={() => onUpdatePreferences({ layoutStructure: layout.id })}
                    className={`p-3 rounded-2xl border text-right transition flex items-center justify-between gap-3 cursor-pointer ${
                      active
                        ? 'bg-[#D4AF37]/10 border-[#D4AF37] shadow-lg'
                        : 'bg-gray-900/70 border-gray-800 hover:border-gray-700'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <LayoutMiniPreview id={layout.id} />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-white truncate">{layout.title}</span>
                          <span className="px-1.5 py-0.5 rounded bg-gray-800 text-[9px] text-[#D4AF37] font-bold shrink-0">
                            {layout.badge}
                          </span>
                        </div>
                        <div className="text-[11px] text-gray-400 leading-snug mt-0.5">{layout.subtitle}</div>
                      </div>
                    </div>
                    {active && <Check className="w-4 h-4 text-[#D4AF37] shrink-0" />}
                  </button>
                );
              })}
            </div>

            {/* Sidebar Collapse Quick Switch */}
            {preferences.layoutStructure === 'sidebar' && (
              <div className="p-3.5 rounded-xl bg-gray-900 border border-gray-800 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-gray-300">
                  <PanelRight className="w-4 h-4 text-[#D4AF37]" />
                  <span>وضع طي القائمة الجانبية (أيقونات فقط)</span>
                </div>
                <button
                  type="button"
                  onClick={() => onUpdatePreferences({ sidebarCollapsed: !preferences.sidebarCollapsed })}
                  className={`px-3 py-1 rounded-lg text-[11px] font-bold transition cursor-pointer ${
                    preferences.sidebarCollapsed
                      ? 'bg-[#D4AF37] text-gray-950'
                      : 'bg-gray-800 text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  {preferences.sidebarCollapsed ? 'مطوية' : 'موسّعة'}
                </button>
              </div>
            )}

            {/* Multi-Grid Configuration */}
            {preferences.layoutStructure === 'multi_grid' && (
              <div className="p-4 rounded-2xl bg-gray-900/90 border border-[#D4AF37]/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-[#D4AF37] flex items-center gap-1.5">
                    <Columns className="w-3.5 h-3.5" />
                    إعدادات الشبكة المتعددة (حتى 6 مختبرات)
                  </span>
                  <div className="flex items-center gap-1 bg-gray-950 p-1 rounded-lg border border-gray-800">
                    <button
                      type="button"
                      onClick={() => onUpdatePreferences({ multiGridColumns: 2 })}
                      className={`px-2 py-0.5 rounded text-[10px] font-bold cursor-pointer ${
                        preferences.multiGridColumns === 2 ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400'
                      }`}
                    >
                      عمودان
                    </button>
                    <button
                      type="button"
                      onClick={() => onUpdatePreferences({ multiGridColumns: 3 })}
                      className={`px-2 py-0.5 rounded text-[10px] font-bold cursor-pointer ${
                        preferences.multiGridColumns === 3 ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400'
                      }`}
                    >
                      3 أعمدة
                    </button>
                  </div>
                </div>

                {/* Quick Presets */}
                <div className="flex flex-wrap gap-1.5">
                  <button
                    type="button"
                    onClick={() => {
                      const preset: AppTabId[] = ['dashboard', 'live_feeds', 'threat_intel', 'audit'];
                      const locked = preset.find((t) => isTabLocked?.(t));
                      if (locked) {
                        onLockedTabClick?.(locked);
                        return;
                      }
                      onUpdatePreferences({ multiGridPanels: preset });
                    }}
                    className="px-2.5 py-1 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-800 text-[10px] text-gray-300 cursor-pointer"
                  >
                    حزمة غرفة العمليات (SOC)
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const preset: AppTabId[] = ['binary_lab', 'deobfuscator', 'apk', 'parser'];
                      const locked = preset.find((t) => isTabLocked?.(t));
                      if (locked) {
                        onLockedTabClick?.(locked);
                        return;
                      }
                      onUpdatePreferences({ multiGridPanels: preset });
                    }}
                    className="px-2.5 py-1 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-800 text-[10px] text-gray-300 cursor-pointer"
                  >
                    حزمة البرمجيات الخبيثة
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const preset: AppTabId[] = ['evidence', 'custody', 'hex', 'ela'];
                      const locked = preset.find((t) => isTabLocked?.(t));
                      if (locked) {
                        onLockedTabClick?.(locked);
                        return;
                      }
                      onUpdatePreferences({ multiGridPanels: preset });
                    }}
                    className="px-2.5 py-1 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-800 text-[10px] text-gray-300 cursor-pointer"
                  >
                    حزمة الأدلة والوسائط
                  </button>
                </div>

                <div className="grid grid-cols-2 gap-1.5 max-h-48 overflow-y-auto pr-1">
                  {NAV_TABS_META.map((tab) => {
                    const locked = !isOwner && Boolean(isTabLocked?.(tab.id));
                    const lockedForOthers = Boolean(isOwner && isTabPaidForUsers?.(tab.id));
                    const active = !locked && preferences.multiGridPanels.includes(tab.id);
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => toggleGridPanel(tab.id)}
                        title={lockedForOthers ? `${tab.label} — مقفلة للمستخدمين الآخرين (مفتوحة لك)` : tab.label}
                        className={`px-2.5 py-2 rounded-xl border text-[11px] font-medium flex items-center justify-between gap-1.5 transition cursor-pointer ${
                          active
                            ? 'bg-[#D4AF37]/15 border-[#D4AF37]/60 text-white'
                            : locked
                            ? 'bg-gray-950/60 border-gray-800/80 text-gray-500 hover:border-amber-500/40'
                            : 'bg-gray-950 border-gray-800 text-gray-400 hover:border-gray-700'
                        }`}
                      >
                        <span className="truncate">{tab.shortLabel}</span>
                        {locked ? (
                          <Lock className="w-3 h-3 text-amber-400/80 shrink-0" />
                        ) : (
                          <span className="flex items-center gap-1 shrink-0">
                            {lockedForOthers && <Lock className="w-2.5 h-2.5 text-amber-400/80" />}
                            {active && <Check className="w-3 h-3 text-[#D4AF37]" />}
                          </span>
                        )}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}
          </section>

          {/* 2. Curated Base Theme Presets */}
          <section className="space-y-3">
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <Palette className="w-4 h-4 text-[#D4AF37]" />
              2. الثيمات الرئيسية المختارة (8 ثيمات)
            </h3>

            <div className="grid grid-cols-1 gap-2">
              {THEME_PRESETS.map((theme) => {
                const selected = preferences.themePreset === theme.id;
                return (
                  <button
                    key={theme.id}
                    type="button"
                    onClick={() => onUpdatePreferences({ themePreset: theme.id })}
                    className={`w-full p-3 rounded-2xl border text-right transition flex items-center justify-between gap-3 cursor-pointer ${
                      selected
                        ? 'bg-gray-900 border-[#D4AF37] shadow-lg'
                        : 'bg-gray-900/60 border-gray-800 hover:border-gray-700'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div
                        className="w-11 h-11 rounded-xl border border-white/15 flex flex-col items-center justify-center gap-1 shadow-inner shrink-0 p-1.5"
                        style={{ backgroundColor: theme.bg }}
                      >
                        <div className="w-full h-2 rounded-sm" style={{ backgroundColor: theme.surface }} />
                        <div className="flex items-center gap-1">
                          <span className="w-3 h-3 rounded-full" style={{ backgroundColor: theme.accent }} />
                          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: theme.secondary }} />
                        </div>
                      </div>
                      <div className="min-w-0">
                        <div className="text-xs font-bold text-white truncate">{theme.name}</div>
                        <div className="text-[11px] text-gray-400 truncate">{theme.subtitle}</div>
                      </div>
                    </div>
                    {selected && <Check className="w-4 h-4 text-[#D4AF37] shrink-0" />}
                  </button>
                );
              })}
            </div>
          </section>

          {/* 3. Procedural 540+ Themes Generator & Instant Search */}
          <section className="space-y-3 p-4 rounded-2xl bg-gray-900/80 border border-[#D4AF37]/35">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-bold text-white flex items-center gap-2">
                <Wand2 className="w-4 h-4 text-[#D4AF37]" />
                3. محرك الثيمات الإجرائي (+540 ثيم وهيكل)
              </h3>
              <span className="px-2 py-0.5 rounded-md bg-[#D4AF37]/15 border border-[#D4AF37]/40 text-[10px] font-mono font-bold text-[#D4AF37]">
                {PROCEDURAL_THEMES_CATALOG.length} THEME
              </span>
            </div>

            {/* Instant Theme Generator Buttons */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <button
                type="button"
                onClick={handleInstantRandomTheme}
                className="px-3 py-2.5 rounded-xl bg-[#D4AF37] hover:opacity-90 text-gray-950 font-bold text-xs flex items-center justify-center gap-2 transition cursor-pointer shadow-md"
              >
                <Dices className="w-4 h-4 shrink-0" />
                <span>تغيير عشوائي حقيقي</span>
              </button>
              <button
                type="button"
                onClick={handleRandomThemeAndLayout}
                className="px-3 py-2.5 rounded-xl bg-gray-950 hover:bg-gray-800 border border-[#D4AF37]/50 text-[#D4AF37] font-bold text-xs flex items-center justify-center gap-2 transition cursor-pointer"
              >
                <Shuffle className="w-4 h-4 shrink-0" />
                <span>عشوائي: ثيم + هيكل</span>
              </button>
            </div>

            {/* Active Procedural Theme Readout */}
            {activeProceduralTheme && (
              <div className="p-3 rounded-xl bg-gray-950/90 border border-[#D4AF37]/50 flex items-center justify-between gap-3">
                <div className="flex items-center gap-2.5 min-w-0">
                  <div
                    className="w-10 h-10 rounded-lg border shrink-0 flex items-center justify-center"
                    style={{
                      backgroundColor: activeProceduralTheme.bgHex,
                      backgroundImage: activeProceduralTheme.bgImageCss,
                      backgroundSize: activeProceduralTheme.bgSizeCss,
                      borderColor: activeProceduralTheme.accentHex,
                    }}
                  >
                    <span
                      className="w-3.5 h-3.5 rounded-full shadow"
                      style={{ backgroundColor: activeProceduralTheme.accentHex }}
                    />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-900 text-[#D4AF37] border border-gray-800">
                        #{activeProceduralTheme.id.toUpperCase()}
                      </span>
                      <span className="text-[10px] text-emerald-400 font-bold">مُفعّل حالياً</span>
                    </div>
                    <div className="text-[11px] font-bold text-white truncate mt-0.5">
                      {activeProceduralTheme.nameAr}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Instant Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-gray-400 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                type="text"
                value={procSearch}
                onChange={(e) => {
                  setProcSearch(e.target.value);
                  setProcVisibleLimit(36);
                }}
                placeholder="ابحث ضمن 540 ثيماً (Matrix, Glass, Grid, كربون, #042)..."
                className="w-full pr-9 pl-8 py-2 rounded-xl bg-gray-950 border border-gray-800 focus:border-[#D4AF37] text-xs text-white placeholder-gray-500 outline-none transition"
              />
              {procSearch && (
                <button
                  type="button"
                  onClick={() => setProcSearch('')}
                  aria-label="مسح البحث"
                  className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Category Filter Buttons */}
            <div className="flex flex-wrap gap-1.5">
              {(
                [
                  { id: 'all', label: `الكل (${PROCEDURAL_THEMES_CATALOG.length})` },
                  { id: 'tactical', label: 'عسكري / تكتيكي' },
                  { id: 'cyber', label: 'سايبر / نيون' },
                  { id: 'terminal', label: 'طرفية كلاسيكية' },
                  { id: 'stealth', label: 'شبح / بسيط' },
                ] as { id: 'all' | ProceduralCategory; label: string }[]
              ).map((cat) => (
                <button
                  key={cat.id}
                  type="button"
                  onClick={() => {
                    setProcCategory(cat.id);
                    setProcVisibleLimit(36);
                  }}
                  className={`px-2.5 py-1 rounded-lg text-[10px] font-bold border transition cursor-pointer ${
                    procCategory === cat.id
                      ? 'bg-[#D4AF37]/20 border-[#D4AF37] text-white'
                      : 'bg-gray-950 border-gray-800 text-gray-400 hover:border-gray-700'
                  }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>

            {/* Count indicator */}
            <div className="flex items-center justify-between text-[10px] text-gray-400 font-mono">
              <span>
                النتائج المطابقة: <strong className="text-white">{filteredProceduralThemes.length}</strong> /{' '}
                {PROCEDURAL_THEMES_CATALOG.length}
              </span>
              {filteredProceduralThemes.length > procVisibleLimit && (
                <span>عرض أول {procVisibleLimit}</span>
              )}
            </div>

            {/* Procedural Themes Grid */}
            {filteredProceduralThemes.length === 0 ? (
              <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 text-center text-xs text-gray-400">
                لا توجد ثيمات مطابقة لعبارة البحث الحالية.
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-2 max-h-80 overflow-y-auto pr-1">
                {filteredProceduralThemes.slice(0, procVisibleLimit).map((theme) => {
                  const selected =
                    preferences.themePreset === 'procedural' &&
                    preferences.proceduralThemeId === theme.id;
                  return (
                    <button
                      key={theme.id}
                      type="button"
                      onClick={() =>
                        onUpdatePreferences({
                          themePreset: 'procedural',
                          proceduralThemeId: theme.id,
                        })
                      }
                      className={`p-2.5 rounded-xl border text-right transition flex flex-col gap-2 cursor-pointer ${
                        selected
                          ? 'bg-gray-900 border-[#D4AF37] ring-1 ring-[#D4AF37]/60'
                          : 'bg-gray-950/90 border-gray-800 hover:border-gray-600'
                      }`}
                    >
                      {/* Live CSS Swatch Strip */}
                      <div
                        className="w-full h-11 rounded-lg border p-1.5 flex items-end justify-between relative overflow-hidden"
                        style={{
                          backgroundColor: theme.bgHex,
                          backgroundImage: theme.bgImageCss,
                          backgroundSize: theme.bgSizeCss,
                          borderColor: theme.borderRgba,
                        }}
                      >
                        <div
                          className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold border"
                          style={{
                            backgroundColor: theme.surfaceRgba,
                            borderColor: theme.borderRgba,
                            color: theme.accentHex,
                          }}
                        >
                          {theme.id}
                        </div>
                        <div className="flex items-center gap-1">
                          <span
                            className="w-2.5 h-2.5 rounded-full"
                            style={{ backgroundColor: theme.accentHex }}
                          />
                          <span
                            className="w-2 h-2 rounded-full"
                            style={{ backgroundColor: theme.secondaryHex }}
                          />
                        </div>
                      </div>

                      <div className="min-w-0">
                        <div className="text-[10px] font-bold text-white leading-tight line-clamp-2">
                          {theme.nameAr}
                        </div>
                        <div className="text-[9px] text-gray-400 truncate mt-0.5 font-mono">
                          {theme.accentHex} • {theme.backdropBlur !== 'none' ? 'Glass' : 'Solid'}
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            )}

            {filteredProceduralThemes.length > procVisibleLimit && (
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setProcVisibleLimit((prev) => prev + 54)}
                  className="flex-1 py-2 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-700 text-[11px] font-bold text-gray-200 transition cursor-pointer"
                >
                  عرض 54 ثيماً إضافياً ({filteredProceduralThemes.length - procVisibleLimit} متبقي)
                </button>
                <button
                  type="button"
                  onClick={() => setProcVisibleLimit(filteredProceduralThemes.length)}
                  className="px-3 py-2 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-800 text-[11px] font-bold text-[#D4AF37] transition cursor-pointer"
                >
                  عرض الكل
                </button>
              </div>
            )}
          </section>

          {/* 4. Font Scale */}
          <section className="space-y-3">
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <Type className="w-4 h-4 text-[#D4AF37]" />
              4. حجم الخط (Typography Scale)
            </h3>
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: 'sm' as FontScaleId, label: 'صغير', sub: '14px' },
                { id: 'md' as FontScaleId, label: 'قياسي', sub: '16px' },
                { id: 'lg' as FontScaleId, label: 'كبير', sub: '18px' },
              ].map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => onUpdatePreferences({ fontScale: opt.id })}
                  className={`p-3 rounded-xl border text-center transition cursor-pointer ${
                    preferences.fontScale === opt.id
                      ? 'bg-[#D4AF37]/15 border-[#D4AF37] text-white font-bold'
                      : 'bg-gray-900 border-gray-800 text-gray-400 hover:border-gray-700'
                  }`}
                >
                  <div className="text-xs">{opt.label}</div>
                  <div className="text-[10px] font-mono opacity-75">{opt.sub}</div>
                </button>
              ))}
            </div>
          </section>

          {/* 5. Density */}
          <section className="space-y-3">
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <Maximize2 className="w-4 h-4 text-[#D4AF37]" />
              5. كثافة العناصر والمسافات (UI Density)
            </h3>
            <div className="grid grid-cols-2 gap-2.5">
              <button
                type="button"
                onClick={() => onUpdatePreferences({ density: 'compact' })}
                className={`p-3.5 rounded-xl border flex items-center justify-center gap-2 text-xs transition cursor-pointer ${
                  preferences.density === 'compact'
                    ? 'bg-[#D4AF37]/15 border-[#D4AF37] text-white font-bold'
                    : 'bg-gray-900 border-gray-800 text-gray-400 hover:border-gray-700'
                }`}
              >
                <Minimize2 className="w-4 h-4" />
                <span>مضغوط (Compact)</span>
              </button>
              <button
                type="button"
                onClick={() => onUpdatePreferences({ density: 'comfortable' })}
                className={`p-3.5 rounded-xl border flex items-center justify-center gap-2 text-xs transition cursor-pointer ${
                  preferences.density === 'comfortable'
                    ? 'bg-[#D4AF37]/15 border-[#D4AF37] text-white font-bold'
                    : 'bg-gray-900 border-gray-800 text-gray-400 hover:border-gray-700'
                }`}
              >
                <Maximize2 className="w-4 h-4" />
                <span>مريح (Comfortable)</span>
              </button>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800 bg-gray-900/80 flex items-center justify-between gap-3">
          <button
            type="button"
            onClick={onResetPreferences}
            className="px-4 py-2.5 rounded-xl bg-gray-900 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-300 flex items-center gap-2 transition cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            استعادة الافتراضي
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-2.5 rounded-xl bg-[#D4AF37] hover:opacity-90 text-gray-950 text-xs font-bold transition cursor-pointer"
          >
            اعتماد وإغلاق
          </button>
        </div>
      </aside>
    </div>
  );
};
