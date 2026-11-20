import React, { useCallback, useEffect, useMemo, useState } from 'react';
import SparkMD5 from 'spark-md5';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from 'recharts';
import {
  addDoc,
  collection,
  getDocs,
  getDocsFromServer,
  onSnapshot,
  query,
  where,
} from 'firebase/firestore';
import {
  BarChart3,
  TrendingUp,
  RefreshCw,
  Upload,
  Download,
  ExternalLink,
  X,
} from 'lucide-react';
import { db } from '../firebase';

export interface EvidenceChartRecord {
  id?: string;
  userId?: string;
  investigationId?: string;
  fileName?: string;
  fileSize?: number;
  mimeType?: string;
  sha256?: string;
  storageStatus?: 'cloud' | 'local';
  createdAt?: string | number | { toDate?: () => Date; seconds?: number };
}

interface EvidenceDailyChartProps {
  evidenceList: EvidenceChartRecord[];
  currentUserUid?: string;
  isAdmin?: boolean;
  currentInvestigationId?: string | null;
  loading?: boolean;
  onOpenEvidenceVault?: () => void;
  onEvidenceAdded?: () => void;
  onNotify?: (msg: string, type?: 'success' | 'warning' | 'error') => void;
}

interface DailyBucket {
  dateKey: string;
  shortLabel: string;
  fullDateLabel: string;
  count: number;
  items: EvidenceChartRecord[];
}

function toLocalDateKey(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function parseEvidenceDate(raw: EvidenceChartRecord['createdAt']): Date | null {
  if (!raw) return null;
  if (typeof raw === 'string' || typeof raw === 'number') {
    const dt = new Date(raw);
    return Number.isNaN(dt.getTime()) ? null : dt;
  }
  if (typeof raw === 'object') {
    if (typeof raw.toDate === 'function') {
      const dt = raw.toDate();
      return Number.isNaN(dt.getTime()) ? null : dt;
    }
    if (typeof raw.seconds === 'number') {
      const dt = new Date(raw.seconds * 1000);
      return Number.isNaN(dt.getTime()) ? null : dt;
    }
  }
  return null;
}

function formatBytes(bytes?: number): string {
  if (typeof bytes !== 'number' || Number.isNaN(bytes)) return '—';
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  return `${bytes} B`;
}

async function digestHex(algo: 'SHA-256' | 'SHA-1', buffer: ArrayBuffer): Promise<string> {
  const hashBuf = await crypto.subtle.digest(algo, buffer);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function sanitizeCsvCell(val: string | number): string {
  const s = String(val ?? '');
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
}

export const EvidenceDailyChart: React.FC<EvidenceDailyChartProps> = ({
  evidenceList,
  currentUserUid,
  isAdmin = false,
  currentInvestigationId,
  loading = false,
  onOpenEvidenceVault,
  onEvidenceAdded,
  onNotify,
}) => {
  const [chartMode, setChartMode] = useState<'bar' | 'area'>('bar');
  const [rangeDays, setRangeDays] = useState<7 | 14 | 30>(30);
  const [scopeMode, setScopeMode] = useState<'mine' | 'all'>('mine');
  const [firestoreRecords, setFirestoreRecords] = useState<EvidenceChartRecord[] | null>(null);
  const [syncingServer, setSyncingServer] = useState(false);
  const [uploadingEvidence, setUploadingEvidence] = useState(false);
  const [lastServerSyncAt, setLastServerSyncAt] = useState<string | null>(null);
  const [selectedDateKey, setSelectedDateKey] = useState<string | null>(null);

  const activeScope: 'mine' | 'all' = isAdmin && scopeMode === 'all' ? 'all' : 'mine';

  const buildEvidenceQuery = useCallback(() => {
    const colRef = collection(db, 'evidence');
    if (activeScope === 'all' && isAdmin) {
      return query(colRef);
    }
    return query(colRef, where('userId', '==', currentUserUid || '__none__'));
  }, [activeScope, isAdmin, currentUserUid]);

  // Direct real-time Firestore subscription + authoritative server refresh
  useEffect(() => {
    if (!currentUserUid) {
      setFirestoreRecords(null);
      return;
    }

    let cancelled = false;
    const q = buildEvidenceQuery();

    const unsub = onSnapshot(
      q,
      (snap) => {
        if (cancelled) return;
        const rows: EvidenceChartRecord[] = [];
        snap.forEach((docSnap) => {
          rows.push({ id: docSnap.id, ...(docSnap.data() as EvidenceChartRecord) });
        });
        setFirestoreRecords(rows);
        if (!snap.metadata.fromCache) {
          setLastServerSyncAt(new Date().toISOString());
        }
      },
      (err) => {
        console.warn('[EvidenceDailyChart] Firestore listener note:', err?.message || err);
      }
    );

    return () => {
      cancelled = true;
      unsub();
    };
  }, [currentUserUid, buildEvidenceQuery]);

  const handleRefreshFromFirestore = async () => {
    if (!currentUserUid) return;
    setSyncingServer(true);
    try {
      const snap = await getDocsFromServer(buildEvidenceQuery());
      const rows: EvidenceChartRecord[] = [];
      snap.forEach((docSnap) => {
        rows.push({ id: docSnap.id, ...(docSnap.data() as EvidenceChartRecord) });
      });
      setFirestoreRecords(rows);
      setLastServerSyncAt(new Date().toISOString());
      onNotify?.(`تمت المزامنة المباشرة مع Firestore: ${rows.length} دليل مسجل.`, 'success');
    } catch (err: any) {
      onNotify?.(`تعذرت المزامنة المباشرة مع Firestore: ${err?.message || 'خطأ غير معروف'}`, 'error');
    } finally {
      setSyncingServer(false);
    }
  };

  const handleDirectUploadToFirestore = async (file: File) => {
    if (!currentUserUid) {
      onNotify?.('يرجى تسجيل الدخول أولاً لرفع الأدلة إلى Firestore.', 'warning');
      return;
    }
    if (file.size > 104_857_600) {
      onNotify?.('الحد الأقصى لحجم الدليل هو 100 MB.', 'warning');
      return;
    }

    setUploadingEvidence(true);
    try {
      const buffer = await file.arrayBuffer();
      const [sha256, sha1] = await Promise.all([
        digestHex('SHA-256', buffer),
        digestHex('SHA-1', buffer),
      ]);
      const md5 = SparkMD5.ArrayBuffer.hash(buffer);

      // Check duplicate SHA-256 for this user
      const dupSnap = await getDocs(
        query(
          collection(db, 'evidence'),
          where('userId', '==', currentUserUid),
          where('sha256', '==', sha256)
        )
      );
      if (!dupSnap.empty) {
        onNotify?.(`هذا الملف مسجل مسبقاً في Firestore بنفس بصمة SHA-256 (${sha256.slice(0, 12)}...).`, 'warning');
        return;
      }

      const nowIso = new Date().toISOString();
      const safeMime = (file.type || 'application/octet-stream').slice(0, 128);
      const safeName = (file.name || 'evidence-file').slice(0, 256);
      const invId = (currentInvestigationId || 'inv-sovereign-default').slice(0, 128);

      await addDoc(collection(db, 'evidence'), {
        userId: currentUserUid,
        investigationId: invId,
        fileName: safeName,
        fileUrl: '',
        storagePath: '',
        storageStatus: 'local',
        fileSize: file.size,
        mimeType: safeMime,
        sha256,
        sha1,
        md5,
        createdAt: nowIso,
      });

      setSelectedDateKey(toLocalDateKey(new Date()));
      onEvidenceAdded?.();
      onNotify?.(`تم حفظ الدليل "${safeName}" في مجموعة evidence بـ Firestore وتحديث الرسم البياني.`, 'success');
    } catch (err: any) {
      onNotify?.(`فشل حفظ الدليل في Firestore: ${err?.message || 'خطأ في الصلاحيات'}`, 'error');
    } finally {
      setUploadingEvidence(false);
    }
  };

  // Prefer live Firestore snapshot when available, fallback to parent evidenceList when signed out/loading
  const effectiveEvidence = useMemo(() => {
    if (firestoreRecords !== null) return firestoreRecords;
    return activeScope === 'mine' ? evidenceList : [];
  }, [firestoreRecords, activeScope, evidenceList]);

  const { dailyData, totalInRange, todayCount, peakBucket, activeDaysCount } = useMemo(() => {
    const buckets: DailyBucket[] = [];
    const indexByKey = new Map<string, number>();
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    for (let offset = rangeDays - 1; offset >= 0; offset--) {
      const day = new Date(todayStart);
      day.setDate(todayStart.getDate() - offset);
      const key = toLocalDateKey(day);
      const shortLabel = `${String(day.getDate()).padStart(2, '0')}/${String(day.getMonth() + 1).padStart(2, '0')}`;
      const fullDateLabel = day.toLocaleDateString('ar-SA', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
      indexByKey.set(key, buckets.length);
      buckets.push({
        dateKey: key,
        shortLabel,
        fullDateLabel,
        count: 0,
        items: [],
      });
    }

    for (const item of effectiveEvidence) {
      const parsed = parseEvidenceDate(item.createdAt);
      if (!parsed) continue;
      const key = toLocalDateKey(parsed);
      const idx = indexByKey.get(key);
      if (idx !== undefined) {
        buckets[idx].count += 1;
        buckets[idx].items.push(item);
      }
    }

    for (const b of buckets) {
      b.items.sort((a, bItem) => {
        const ta = parseEvidenceDate(a.createdAt)?.getTime() || 0;
        const tb = parseEvidenceDate(bItem.createdAt)?.getTime() || 0;
        return tb - ta;
      });
    }

    let sum = 0;
    let activeDays = 0;
    let peak: DailyBucket | null = null;
    for (const b of buckets) {
      sum += b.count;
      if (b.count > 0) {
        activeDays += 1;
        if (!peak || b.count > peak.count) {
          peak = b;
        }
      }
    }

    const todayKey = toLocalDateKey(todayStart);
    const todayIdx = indexByKey.get(todayKey);
    const todayVal = todayIdx !== undefined ? buckets[todayIdx].count : 0;

    return {
      dailyData: buckets,
      totalInRange: sum,
      todayCount: todayVal,
      peakBucket: peak,
      activeDaysCount: activeDays,
    };
  }, [effectiveEvidence, rangeDays]);

  const selectedBucket = useMemo(() => {
    if (!selectedDateKey) return null;
    return dailyData.find((b) => b.dateKey === selectedDateKey) || null;
  }, [dailyData, selectedDateKey]);

  const handleChartClick = (state: { activeTooltipIndex?: number | string | null; activeLabel?: string | number } | undefined) => {
    if (!state) return;
    const rawIdx = state.activeTooltipIndex;
    if (rawIdx !== undefined && rawIdx !== null) {
      const idx = Number(rawIdx);
      if (!Number.isNaN(idx) && dailyData[idx]) {
        const key = dailyData[idx].dateKey;
        setSelectedDateKey((prev) => (prev === key ? null : key));
        return;
      }
    }
    if (state.activeLabel) {
      const found = dailyData.find((b) => b.shortLabel === String(state.activeLabel));
      if (found) {
        setSelectedDateKey((prev) => (prev === found.dateKey ? null : found.dateKey));
      }
    }
  };

  const exportDailyCsv = () => {
    const headers = ['Date', 'UploadedEvidenceCount', 'EvidenceFiles'];
    const rows = dailyData.map((b) => [
      sanitizeCsvCell(b.dateKey),
      sanitizeCsvCell(b.count),
      sanitizeCsvCell(b.items.map((x) => x.fileName || x.id || '').join(' | ')),
    ]);
    const csv = '\uFEFF' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `firestore-evidence-last-${rangeDays}d.csv`;
    a.click();
    URL.revokeObjectURL(url);
    onNotify?.(`تم تصدير إحصائيات آخر ${rangeDays} يوماً بصيغة CSV.`, 'success');
  };

  const isWaitingInitial = loading && firestoreRecords === null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-5">
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 pb-4 border-b border-gray-800">
        <div className="space-y-1">
          <h3 className="text-sm font-bold text-white">
            الأدلة المرفوعة يومياً (آخر {rangeDays} يوماً)
          </h3>
          <p className="text-xs text-gray-400">
            ربط مباشر مع مجموعة <span className="font-mono text-gray-300">evidence</span> في Firestore · إجمالي آخر {rangeDays} يوماً:{' '}
            <span className="font-mono tabular-nums text-[#D4AF37] font-bold">{totalInRange}</span>
            {' · '}
            اليوم: <span className="font-mono tabular-nums text-emerald-400 font-bold">{todayCount}</span>
            {peakBucket ? (
              <>
                {' · '}
                الذروة: <span className="font-mono tabular-nums text-white font-bold">{peakBucket.count}</span> ({peakBucket.shortLabel})
              </>
            ) : null}
            {' · '}
            أيام نشطة: <span className="font-mono tabular-nums text-gray-300">{activeDaysCount}/{rangeDays}</span>
            {lastServerSyncAt ? (
              <>
                {' · '}
                <span className="font-mono tabular-nums text-gray-500">
                  آخر مزامنة: {new Date(lastServerSyncAt).toLocaleTimeString('ar-SA')}
                </span>
              </>
            ) : null}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          {isAdmin && (
            <div className="flex items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
              <button
                type="button"
                onClick={() => {
                  setScopeMode('mine');
                  setSelectedDateKey(null);
                }}
                className={`px-2.5 py-1 rounded text-xs font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                  activeScope === 'mine' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'
                }`}
              >
                أدلتي
              </button>
              <button
                type="button"
                onClick={() => {
                  setScopeMode('all');
                  setSelectedDateKey(null);
                }}
                className={`px-2.5 py-1 rounded text-xs font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                  activeScope === 'all' ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'
                }`}
              >
                كل المنصة
              </button>
            </div>
          )}

          <div className="flex items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
            {([7, 14, 30] as const).map((days) => (
              <button
                key={days}
                type="button"
                onClick={() => {
                  setRangeDays(days);
                  setSelectedDateKey(null);
                }}
                className={`px-2.5 py-1 rounded text-xs font-mono font-bold transition cursor-pointer whitespace-nowrap shrink-0 ${
                  rangeDays === days ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-white'
                }`}
              >
                {days}d
              </button>
            ))}
          </div>

          <div className="flex items-center gap-1 p-1 rounded-lg bg-gray-950 border border-gray-800">
            <button
              type="button"
              onClick={() => setChartMode('bar')}
              className={`px-2.5 py-1 rounded text-xs font-bold inline-flex items-center gap-1 transition cursor-pointer whitespace-nowrap shrink-0 ${
                chartMode === 'bar'
                  ? 'bg-[#D4AF37] text-gray-950'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>أعمدة</span>
            </button>
            <button
              type="button"
              onClick={() => setChartMode('area')}
              className={`px-2.5 py-1 rounded text-xs font-bold inline-flex items-center gap-1 transition cursor-pointer whitespace-nowrap shrink-0 ${
                chartMode === 'area'
                  ? 'bg-[#D4AF37] text-gray-950'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              <TrendingUp className="w-3.5 h-3.5" />
              <span>مساحي</span>
            </button>
          </div>

          <label className="px-3 py-2 rounded-lg bg-[#D4AF37] hover:opacity-90 text-gray-950 text-xs font-bold inline-flex items-center gap-1.5 cursor-pointer whitespace-nowrap shrink-0">
            <Upload className="w-3.5 h-3.5" />
            <span>{uploadingEvidence ? 'جاري الحفظ...' : 'رفع دليل إلى Firestore'}</span>
            <input
              type="file"
              disabled={uploadingEvidence}
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void handleDirectUploadToFirestore(f);
                e.target.value = '';
              }}
            />
          </label>

          <button
            type="button"
            disabled={syncingServer}
            onClick={() => void handleRefreshFromFirestore()}
            title="مزامنة مباشرة من خادم Firestore"
            className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50 whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3.5 h-3.5 text-[#D4AF37] ${syncingServer ? 'animate-spin' : ''}`} />
            <span>تحديث</span>
          </button>

          <button
            type="button"
            onClick={exportDailyCsv}
            title="تصدير إحصائيات الأيام CSV"
            className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
          >
            <Download className="w-3.5 h-3.5" />
            <span>CSV</span>
          </button>

          {onOpenEvidenceVault && (
            <button
              type="button"
              onClick={onOpenEvidenceVault}
              className="px-3 py-2 rounded-lg bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 inline-flex items-center gap-1.5 transition cursor-pointer whitespace-nowrap shrink-0"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              <span>مخزن الأدلة</span>
            </button>
          )}
        </div>
      </div>

      {isWaitingInitial ? (
        <div className="h-64 w-full rounded-xl bg-gray-950 border border-gray-800 flex items-center justify-center text-xs text-gray-400">
          جاري قراءة سجلات مجموعة evidence من Firestore...
        </div>
      ) : (
        <div className="space-y-4">
          <div className="h-64 w-full" dir="ltr">
            <ResponsiveContainer width="100%" height="100%">
              {chartMode === 'bar' ? (
                <BarChart
                  data={dailyData}
                  margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
                  onClick={handleChartClick}
                  style={{ cursor: 'pointer' }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                  <XAxis
                    dataKey="shortLabel"
                    stroke="#6b7280"
                    tick={{ fill: '#9ca3af', fontSize: 11 }}
                    interval={rangeDays === 30 ? 4 : rangeDays === 14 ? 1 : 0}
                    tickLine={false}
                  />
                  <YAxis
                    stroke="#6b7280"
                    tick={{ fill: '#9ca3af', fontSize: 11 }}
                    allowDecimals={false}
                    tickLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(212, 175, 55, 0.08)' }}
                    contentStyle={{
                      backgroundColor: '#030712',
                      borderColor: '#374151',
                      borderRadius: '0.75rem',
                      fontSize: '12px',
                      color: '#f9fafb',
                    }}
                    labelFormatter={(_label, payload) => {
                      const row = payload?.[0]?.payload as DailyBucket | undefined;
                      return row ? `${row.fullDateLabel} (${row.dateKey}) — اضغط لعرض الأدلة` : '';
                    }}
                    formatter={(value: unknown) => [`${Number(value ?? 0)} دليل`, 'الأدلة المرفوعة']}
                  />
                  <Bar
                    dataKey="count"
                    name="الأدلة المرفوعة"
                    radius={[4, 4, 0, 0]}
                    maxBarSize={24}
                  >
                    {dailyData.map((entry) => (
                      <Cell
                        key={entry.dateKey}
                        fill={
                          selectedDateKey === entry.dateKey
                            ? '#10B981'
                            : entry.count > 0
                            ? '#D4AF37'
                            : '#374151'
                        }
                      />
                    ))}
                  </Bar>
                </BarChart>
              ) : (
                <AreaChart
                  data={dailyData}
                  margin={{ top: 8, right: 12, left: -16, bottom: 0 }}
                  onClick={handleChartClick}
                  style={{ cursor: 'pointer' }}
                >
                  <defs>
                    <linearGradient id="evidenceGoldGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#D4AF37" stopOpacity={0.35} />
                      <stop offset="95%" stopColor="#D4AF37" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
                  <XAxis
                    dataKey="shortLabel"
                    stroke="#6b7280"
                    tick={{ fill: '#9ca3af', fontSize: 11 }}
                    interval={rangeDays === 30 ? 4 : rangeDays === 14 ? 1 : 0}
                    tickLine={false}
                  />
                  <YAxis
                    stroke="#6b7280"
                    tick={{ fill: '#9ca3af', fontSize: 11 }}
                    allowDecimals={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#030712',
                      borderColor: '#374151',
                      borderRadius: '0.75rem',
                      fontSize: '12px',
                      color: '#f9fafb',
                    }}
                    labelFormatter={(_label, payload) => {
                      const row = payload?.[0]?.payload as DailyBucket | undefined;
                      return row ? `${row.fullDateLabel} (${row.dateKey}) — اضغط لعرض الأدلة` : '';
                    }}
                    formatter={(value: unknown) => [`${Number(value ?? 0)} دليل`, 'الأدلة المرفوعة']}
                  />
                  <Area
                    type="monotone"
                    dataKey="count"
                    name="الأدلة المرفوعة"
                    stroke="#D4AF37"
                    strokeWidth={2}
                    fill="url(#evidenceGoldGradient)"
                  />
                </AreaChart>
              )}
            </ResponsiveContainer>
          </div>

          {/* Real Clickable Active Days Strip or Empty Notice */}
          {totalInRange === 0 ? (
            <div className="p-4 rounded-xl bg-gray-950 border border-gray-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <span className="text-gray-400">
                مجموعة <span className="font-mono text-gray-200">evidence</span> في Firestore لا تحتوي على أدلة مرفوعة خلال آخر {rangeDays} يوماً حتى الآن. يمكنك رفع دليل حقيقي الآن لتسجيله في Firestore ومشاهدة تحديث الرسم فوراً.
              </span>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="text-gray-400">اضغط على أي يوم في الرسم أو اختر يوماً نشطاً:</span>
              {dailyData
                .filter((b) => b.count > 0)
                .slice(-8)
                .reverse()
                .map((b) => (
                  <button
                    key={b.dateKey}
                    type="button"
                    onClick={() =>
                      setSelectedDateKey((prev) => (prev === b.dateKey ? null : b.dateKey))
                    }
                    className={`px-2.5 py-1 rounded-lg border font-mono tabular-nums text-[11px] transition cursor-pointer ${
                      selectedDateKey === b.dateKey
                        ? 'bg-[#D4AF37] text-gray-950 border-[#D4AF37] font-bold'
                        : 'bg-gray-950 border-gray-800 text-gray-300 hover:border-gray-600'
                    }`}
                  >
                    {b.shortLabel} ({b.count})
                  </button>
                ))}
            </div>
          )}

          {/* Selected Day Drill-down Table from Firestore */}
          {selectedBucket && (
            <div className="rounded-xl bg-gray-950 border border-[#D4AF37]/40 p-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="text-xs font-bold text-white">
                  أدلة Firestore ليوم <span className="font-mono text-[#D4AF37]">{selectedBucket.dateKey}</span> ({selectedBucket.items.length} سجل)
                </div>
                <button
                  type="button"
                  onClick={() => setSelectedDateKey(null)}
                  className="text-xs text-gray-400 hover:text-white inline-flex items-center gap-1 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                  <span>إغلاق</span>
                </button>
              </div>

              {selectedBucket.items.length === 0 ? (
                <div className="text-xs text-gray-500 py-2">
                  لم يتم رفع أي أدلة إلى Firestore في يوم {selectedBucket.dateKey}.
                </div>
              ) : (
                <div className="overflow-x-auto border border-gray-800 rounded-lg">
                  <table className="w-full text-xs text-right">
                    <thead className="bg-gray-900 text-gray-400 border-b border-gray-800 font-mono">
                      <tr>
                        <th className="py-2 px-3">اسم الدليل</th>
                        <th className="py-2 px-3">الحجم</th>
                        <th className="py-2 px-3">النوع</th>
                        <th className="py-2 px-3">SHA-256</th>
                        <th className="py-2 px-3">الوقت</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800 font-mono text-[11px]">
                      {selectedBucket.items.map((ev, idx) => {
                        const dt = parseEvidenceDate(ev.createdAt);
                        return (
                          <tr key={ev.id || `${ev.sha256}-${idx}`} className="hover:bg-gray-900/50">
                            <td className="py-2 px-3 text-white font-bold max-w-[200px] truncate" dir="ltr">
                              {ev.fileName || ev.id || '—'}
                            </td>
                            <td className="py-2 px-3 text-gray-300 tabular-nums whitespace-nowrap">
                              {formatBytes(ev.fileSize)}
                            </td>
                            <td className="py-2 px-3 text-emerald-300 max-w-[160px] truncate" dir="ltr">
                              {ev.mimeType || '—'}
                            </td>
                            <td className="py-2 px-3 text-[#D4AF37] max-w-[180px] truncate" dir="ltr">
                              {ev.sha256 || '—'}
                            </td>
                            <td className="py-2 px-3 text-gray-400 tabular-nums whitespace-nowrap">
                              {dt ? dt.toLocaleTimeString('ar-SA') : '—'}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
