import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Radar,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Search,
  Download,
  ExternalLink,
  Server,
  Monitor,
  Smartphone,
  Router,
  Plus,
  Trash2,
  Upload,
  CheckCircle2,
  XCircle,
  Pause,
  Play,
  SlidersHorizontal,
} from 'lucide-react';
import { apiUrl, safeReadJsonResponse } from '../utils/apiBase';
import type { ToolkitAuditPayload } from './SecurityToolkitLabs';

export interface SocAuditRow {
  id: string;
  timestamp: string;
  fileName: string;
  fileSize?: string;
  verdict: string;
  score: number;
  risk: string;
  type?: string;
  sha256?: string;
}

export interface SocEvidenceRow {
  id: string;
  title?: string;
  fileName?: string;
  fileType?: string;
  sha256?: string;
  status?: string;
  riskLevel?: string;
  authenticityScore?: number;
  createdAt?: string;
}

export interface SocTelemetryRow {
  id: string;
  timestamp: string;
  level: string;
  subsystem?: string;
  category?: string;
  message: string;
  detail?: string;
}

export interface SocLiveFeedItem {
  id: string;
  sourceId: string;
  sourceName: string;
  category: string;
  severity: string;
  title: string;
  summary: string;
  indicator: string;
  link?: string;
  publishedAt?: string;
}

interface CommonSocProps {
  onNotify: (msg: string, type?: 'success' | 'warning' | 'error') => void;
  onRecordAudit: (payload: ToolkitAuditPayload) => void;
}

// ============================================================================
// 1. Cybernetic Telemetry & Live Network Traffic Dashboard
// ============================================================================
interface TrafficPoint {
  timeLabel: string;
  ingressKb: number;
  egressKb: number;
  rttMs: number;
  requestsCount: number;
}

interface GeoThreatNode {
  ip: string;
  country: string;
  city: string;
  asn: string;
  isp: string;
  latitude: number;
  longitude: number;
  label: string;
  severity: string;
}

export const CyberTelemetryNetworkDashboard: React.FC<
  CommonSocProps & {
    auditLogs: SocAuditRow[];
    telemetryLogs: SocTelemetryRow[];
    liveFeedItems: SocLiveFeedItem[];
  }
> = ({ auditLogs, telemetryLogs, liveFeedItems, onNotify }) => {
  const [pollingActive, setPollingActive] = useState(true);
  const [samples, setSamples] = useState<TrafficPoint[]>([]);
  const [latestRttMs, setLatestRttMs] = useState<number | null>(null);
  const [eventFilter, setEventFilter] = useState<'all' | 'critical' | 'network' | 'forensic'>('all');
  const [radarNodes, setRadarNodes] = useState<GeoThreatNode[]>([]);
  const [radarLoading, setRadarLoading] = useState(false);
  const [selectedNode, setSelectedNode] = useState<GeoThreatNode | null>(null);

  const prevBytesRef = useRef<{ totalTransfer: number; totalDecoded: number; resourceCount: number }>({
    totalTransfer: 0,
    totalDecoded: 0,
    resourceCount: 0,
  });

  const sampleBrowserNetworkTelemetry = useCallback(async (probeHealth = true) => {
    const entries = (performance.getEntriesByType('resource') || []) as PerformanceResourceTiming[];
    let totalTransfer = 0;
    let totalDecoded = 0;
    for (const e of entries) {
      totalTransfer += e.transferSize || 0;
      totalDecoded += e.decodedBodySize || e.encodedBodySize || 0;
    }

    let rttMs = 0;
    if (probeHealth) {
      const t0 = performance.now();
      try {
        await fetch(apiUrl('/api/health'), { cache: 'no-store' });
        rttMs = Math.round(performance.now() - t0);
      } catch {
        const nav = (navigator as any).connection;
        rttMs = typeof nav?.rtt === 'number' && nav.rtt > 0 ? nav.rtt : 0;
      }
      setLatestRttMs(rttMs);
    }

    const prev = prevBytesRef.current;
    const isInitial = prev.resourceCount === 0;
    const deltaIngressBytes = isInitial
      ? Math.max(totalTransfer, totalDecoded)
      : Math.max(0, totalTransfer - prev.totalTransfer || totalDecoded - prev.totalDecoded);
    const deltaReqs = isInitial ? entries.length : Math.max(0, entries.length - prev.resourceCount);

    prevBytesRef.current = {
      totalTransfer,
      totalDecoded,
      resourceCount: entries.length,
    };

    const egressEstimateBytes = deltaReqs * 520 + (probeHealth ? 380 : 0);
    const point: TrafficPoint = {
      timeLabel: new Date().toLocaleTimeString('en-GB', { hour12: false }),
      ingressKb: Number((deltaIngressBytes / 1024).toFixed(2)),
      egressKb: Number((egressEstimateBytes / 1024).toFixed(2)),
      rttMs,
      requestsCount: deltaReqs,
    };

    setSamples((old) => [...old.slice(-23), point]);
  }, []);

  useEffect(() => {
    void sampleBrowserNetworkTelemetry(true);
  }, [sampleBrowserNetworkTelemetry]);

  useEffect(() => {
    if (!pollingActive) return;
    const id = window.setInterval(() => {
      void sampleBrowserNetworkTelemetry(false);
    }, 2500);
    return () => window.clearInterval(id);
  }, [pollingActive, sampleBrowserNetworkTelemetry]);

  // Real Data Flow Analytics aggregated from PerformanceResourceTiming entries
  const dataFlowBreakdown = useMemo(() => {
    const entries = (performance.getEntriesByType('resource') || []) as PerformanceResourceTiming[];
    const buckets: Record<string, { label: string; count: number; kb: number }> = {
      api: { label: 'بوابات الـ API والتغذيات الحية', count: 0, kb: 0 },
      scripts: { label: 'محركات الفحص (JS / WASM)', count: 0, kb: 0 },
      media: { label: 'الوسائط والخطوط والواجهات', count: 0, kb: 0 },
      other: { label: 'اتصالات الشبكة والملحقات', count: 0, kb: 0 },
    };

    for (const e of entries) {
      const sizeKb = (e.transferSize || e.decodedBodySize || 512) / 1024;
      if (e.initiatorType === 'fetch' || e.initiatorType === 'xmlhttprequest' || e.name.includes('/api/')) {
        buckets.api.count++;
        buckets.api.kb += sizeKb;
      } else if (e.initiatorType === 'script' || e.name.endsWith('.wasm') || e.name.endsWith('.js')) {
        buckets.scripts.count++;
        buckets.scripts.kb += sizeKb;
      } else if (e.initiatorType === 'img' || e.initiatorType === 'css' || e.name.includes('font')) {
        buckets.media.count++;
        buckets.media.kb += sizeKb;
      } else {
        buckets.other.count++;
        buckets.other.kb += sizeKb;
      }
    }

    const totalKb = Object.values(buckets).reduce((s, b) => s + b.kb, 0) || 1;
    return {
      totalResources: entries.length,
      totalKb: Number(totalKb.toFixed(1)),
      rows: Object.entries(buckets).map(([key, b]) => ({
        key,
        ...b,
        kb: Number(b.kb.toFixed(1)),
        pct: Math.round((b.kb / totalKb) * 100),
      })),
    };
  }, [samples.length]);

  // Real Global Threat Radar Scanner using active C2 IPs from Live Feeds or Abuse.ch Feodo Tracker
  const scanGlobalThreatNodes = useCallback(async () => {
    if (radarLoading) return;
    setRadarLoading(true);
    try {
      const candidateIps: Array<{ ip: string; label: string; severity: string }> = [];
      const seen = new Set<string>();

      for (const item of liveFeedItems) {
        const m = String(item.indicator || item.title || '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        if (m && !seen.has(m[0])) {
          seen.add(m[0]);
          candidateIps.push({ ip: m[0], label: item.title, severity: item.severity });
          if (candidateIps.length >= 7) break;
        }
      }

      if (candidateIps.length === 0) {
        // Fetch live Botnet C2 feed directly from /api/live-feeds/sync or Abuse.ch Feodo JSON
        const feedRes = await fetch(apiUrl('/api/live-feeds/sync'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ limitPerSource: 6 }),
        })
          .then((r) => safeReadJsonResponse(r))
          .catch(() => null);

        const feedItems: SocLiveFeedItem[] = Array.isArray(feedRes?.data?.items) ? feedRes.data.items : [];
        for (const item of feedItems) {
          const m = String(item.indicator || item.title || '').match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
          if (m && !seen.has(m[0])) {
            seen.add(m[0]);
            candidateIps.push({ ip: m[0], label: item.title, severity: item.severity });
            if (candidateIps.length >= 7) break;
          }
        }
      }

      if (candidateIps.length === 0) {
        onNotify('لم تُرصد عناوين C2 نشطة في الدورة الحالية؛ قم بمزامنة التغذيات الحية أولاً.', 'warning');
        setRadarLoading(false);
        return;
      }

      const resolved = await Promise.all(
        candidateIps.map(async (c) => {
          try {
            const gRes = await fetch(`https://ipwho.is/${encodeURIComponent(c.ip)}`);
            const parsed = await safeReadJsonResponse(gRes);
            const g = parsed.data;
            if (g && typeof g.latitude === 'number' && typeof g.longitude === 'number') {
              return {
                ip: c.ip,
                country: String(g.country || 'Unknown'),
                city: String(g.city || '—'),
                asn: g.connection?.asn ? `AS${g.connection.asn}` : '—',
                isp: String(g.connection?.isp || '—'),
                latitude: g.latitude,
                longitude: g.longitude,
                label: c.label,
                severity: c.severity,
              } as GeoThreatNode;
            }
          } catch {
            // ignore individual IP lookup failure
          }
          return null;
        })
      );

      const valid = resolved.filter((n): n is GeoThreatNode => Boolean(n));
      setRadarNodes(valid);
      if (valid.length > 0) {
        setSelectedNode(valid[0]);
        onNotify(`تم تحديد إحداثيات ${valid.length} عقد تهديد C2 حية على الرادار العالمي.`, 'success');
      }
    } finally {
      setRadarLoading(false);
    }
  }, [liveFeedItems, onNotify, radarLoading]);

  useEffect(() => {
    if (liveFeedItems.length > 0 && radarNodes.length === 0) {
      void scanGlobalThreatNodes();
    }
  }, [liveFeedItems.length, radarNodes.length, scanGlobalThreatNodes]);

  // SVG Waveform polyline path computation
  const waveformPaths = useMemo(() => {
    const w = 680;
    const h = 180;
    const padY = 16;
    const pts =
      samples.length >= 2
        ? samples
        : samples.length === 1
        ? [samples[0], samples[0]]
        : [
            { timeLabel: '—', ingressKb: 0, egressKb: 0, rttMs: 0, requestsCount: 0 },
            { timeLabel: '—', ingressKb: 0, egressKb: 0, rttMs: 0, requestsCount: 0 },
          ];
    const maxVal = Math.max(5, ...pts.map((p) => Math.max(p.ingressKb, p.egressKb)));
    const mapX = (idx: number) => (idx / Math.max(1, pts.length - 1)) * w;
    const mapY = (val: number) => h - padY - (val / maxVal) * (h - padY * 2);

    const ingressLine = pts.map((p, i) => `${mapX(i).toFixed(1)},${mapY(p.ingressKb).toFixed(1)}`).join(' ');
    const egressLine = pts.map((p, i) => `${mapX(i).toFixed(1)},${mapY(p.egressKb).toFixed(1)}`).join(' ');
    const ingressArea = `0,${h} ${ingressLine} ${w},${h}`;
    return { w, h, maxVal, ingressLine, egressLine, ingressArea };
  }, [samples]);

  // Merged Real-Time Event Stream
  const mergedEvents = useMemo(() => {
    const rows: Array<{ id: string; time: string; channel: 'forensic' | 'network' | 'critical'; title: string; detail: string; status: string }> = [];

    for (const t of telemetryLogs.slice(0, 20)) {
      rows.push({
        id: `tel-${t.id}`,
        time: t.timestamp,
        channel: t.level === 'error' || t.level === 'warn' ? 'critical' : 'network',
        title: `${t.subsystem || t.category || 'SYSTEM'}: ${t.message}`,
        detail: t.detail || 'Telemetry Stream',
        status: t.level.toUpperCase(),
      });
    }
    for (const a of auditLogs.slice(0, 20)) {
      rows.push({
        id: `aud-${a.id}`,
        time: a.timestamp,
        channel: a.risk === 'حرج' || a.risk === 'مرتفع' ? 'critical' : 'forensic',
        title: a.fileName,
        detail: a.verdict,
        status: a.risk,
      });
    }

    return rows
      .sort((a, b) => String(b.time).localeCompare(String(a.time)))
      .filter((r) => eventFilter === 'all' || r.channel === eventFilter)
      .slice(0, 30);
  }, [auditLogs, telemetryLogs, eventFilter]);

  const netConn = (navigator as any).connection;

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header & Controls */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="text-xs font-mono text-gray-400">
            Cybernetic Telemetry · Network Ingress/Egress · C2 Threat Radar
          </div>
          <h2 className="text-xl md:text-2xl font-bold text-white">
            لوحة مراقبة تدفق الشبكة والرادار السيبراني (Cybernetic Telemetry Dashboard)
          </h2>
          <p className="text-xs text-gray-400 max-w-3xl">
            مراقبة حية لاستجابة البوابة وأحجام النقل الفعلية عبر PerformanceResourceTiming API، تحليل تدفق البيانات، ورادار تتبع خوادم C2 العالمية النشطة.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setPollingActive((v) => !v)}
            className={`px-4 py-2 rounded-xl text-xs font-bold border flex items-center gap-2 transition cursor-pointer whitespace-nowrap shrink-0 ${
              pollingActive
                ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                : 'bg-gray-950 border-gray-700 text-gray-300'
            }`}
          >
            {pollingActive ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{pollingActive ? 'إيقاف الرصد الحي' : 'تشغيل الرصد الحي'}</span>
          </button>
          <button
            type="button"
            onClick={() => void sampleBrowserNetworkTelemetry(true)}
            className="px-4 py-2 rounded-xl bg-[#D4AF37] hover:bg-[#c49f2c] text-gray-950 text-xs font-bold flex items-center gap-2 transition cursor-pointer whitespace-nowrap shrink-0"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>فحص النبض الفعلي الآن</span>
          </button>
        </div>
      </div>

      {/* Top 4 Real Telemetry KPI Strip */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">إجمالي الموارد المنقولة فعلياً</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white">{dataFlowBreakdown.totalKb} KB</div>
          <div className="text-[11px] font-mono text-gray-500">{dataFlowBreakdown.totalResources} طلب شبكي مسجل</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">زمن استجابة البوابة (RTT Ping)</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
            {latestRttMs !== null ? `${latestRttMs} ms` : '—'}
          </div>
          <div className="text-[11px] font-mono text-gray-500">
            {netConn?.effectiveType ? `الشبكة: ${String(netConn.effectiveType).toUpperCase()} · ${netConn.downlink || '—'} Mbps` : 'اتصال متصفح مباشر'}
          </div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">عقد التهديد العالمية على الرادار</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-red-400">{radarNodes.length}</div>
          <div className="text-[11px] font-mono text-gray-500">إحداثيات C2 حية من التغذيات المفتوحة</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">الأحداث الجنائية الحرجة المسجلة</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-[#D4AF37]">
            {auditLogs.filter((a) => a.risk === 'حرج' || a.risk === 'مرتفع').length}
          </div>
          <div className="text-[11px] font-mono text-gray-500">من أصل {auditLogs.length} سجل تدقيق</div>
        </div>
      </div>

      {/* Main Grid: Live Ingress/Egress Waveform + Global Threat Radar */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Live Network Ingress/Egress SVG Chart */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#D4AF37]" />
                <span>تدفق بيانات الشبكة الحقيقي (Ingress / Egress Telemetry)</span>
              </h3>
              <p className="text-[11px] text-gray-400 font-mono">
                Max Scale: {waveformPaths.maxVal.toFixed(1)} KB/cycle · Samples: {samples.length}
              </p>
            </div>
            <div className="flex items-center gap-4 text-[11px] font-mono">
              <span className="flex items-center gap-1.5 text-emerald-400">
                <span className="w-2.5 h-0.5 bg-emerald-400 inline-block" />
                Ingress (KB)
              </span>
              <span className="flex items-center gap-1.5 text-[#D4AF37]">
                <span className="w-2.5 h-0.5 bg-[#D4AF37] inline-block" />
                Egress (KB)
              </span>
            </div>
          </div>

          <div className="bg-gray-950 border border-gray-800 rounded-xl p-3">
            <svg viewBox={`0 0 ${waveformPaths.w} ${waveformPaths.h}`} className="w-full h-48 overflow-visible">
              <defs>
                <linearGradient id="ingressFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#10B981" stopOpacity="0.35" />
                  <stop offset="100%" stopColor="#10B981" stopOpacity="0.02" />
                </linearGradient>
              </defs>
              {[0.25, 0.5, 0.75].map((ratio) => (
                <line
                  key={ratio}
                  x1="0"
                  y1={waveformPaths.h * ratio}
                  x2={waveformPaths.w}
                  y2={waveformPaths.h * ratio}
                  stroke="#1f2937"
                  strokeDasharray="4 4"
                  strokeWidth="1"
                />
              ))}
              <polygon points={waveformPaths.ingressArea} fill="url(#ingressFill)" />
              <polyline fill="none" stroke="#10B981" strokeWidth="2.5" points={waveformPaths.ingressLine} />
              <polyline fill="none" stroke="#D4AF37" strokeWidth="2" strokeDasharray="5 3" points={waveformPaths.egressLine} />
            </svg>
            <div className="flex justify-between text-[10px] font-mono tabular-nums text-gray-500 mt-1" dir="ltr">
              <span>{samples[0]?.timeLabel || '—'}</span>
              <span>Latest: {samples[samples.length - 1]?.ingressKb ?? 0} KB IN / {samples[samples.length - 1]?.egressKb ?? 0} KB OUT</span>
              <span>{samples[samples.length - 1]?.timeLabel || '—'}</span>
            </div>
          </div>

          {/* Data Flow Analytics Bars */}
          <div className="space-y-2.5 pt-1">
            <div className="text-xs font-bold text-gray-300">تحليل تدفق البيانات حسب القناة (Data Flow Analytics):</div>
            {dataFlowBreakdown.rows.map((row) => (
              <div key={row.key} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-gray-300">{row.label}</span>
                  <span className="font-mono tabular-nums text-gray-400">
                    {row.kb} KB · {row.count} طلب ({row.pct}%)
                  </span>
                </div>
                <div className="h-1.5 w-full bg-gray-950 rounded-full overflow-hidden border border-gray-800">
                  <div className="h-full bg-[#D4AF37]" style={{ width: `${Math.max(3, row.pct)}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Global Threat Scanning Radar */}
        <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Radar className="w-4 h-4 text-red-400" />
                <span>رادار الفحص العالمي للتهديدات (Global Threat Scanning Radar)</span>
              </h3>
              <p className="text-[11px] text-gray-400">
                تحديد جغرافي حي لعناوين خوادم التحكم C2 النشطة المرصودة في التغذيات الأمنية المفتوحة.
              </p>
            </div>
            <button
              type="button"
              disabled={radarLoading}
              onClick={() => void scanGlobalThreatNodes()}
              className="px-3 py-1.5 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-[#D4AF37] flex items-center gap-1.5 cursor-pointer shrink-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${radarLoading ? 'animate-spin' : ''}`} />
              <span>{radarLoading ? 'جاري المسح...' : 'مسح عقد التهديد الحية'}</span>
            </button>
          </div>

          <div className="bg-[#060a14] border border-gray-800 rounded-xl overflow-hidden">
            <svg viewBox="0 0 800 400" className="w-full h-56 block">
              {[100, 200, 300].map((y) => (
                <line key={`rh-${y}`} x1="0" y1={y} x2="800" y2={y} stroke="#1f2937" strokeWidth="1" strokeDasharray="3 4" />
              ))}
              {[160, 320, 400, 480, 640].map((x) => (
                <line key={`rv-${x}`} x1={x} y1="0" x2={x} y2="400" stroke="#1f2937" strokeWidth="1" strokeDasharray="3 4" />
              ))}
              <g fill="#141e33" stroke="#293a59" strokeWidth="1">
                <path d="M95,70 L235,65 L255,130 L185,180 L125,155 Z" />
                <path d="M210,195 L280,210 L295,305 L245,355 L210,285 Z" />
                <path d="M365,65 L470,60 L485,130 L375,140 Z" />
                <path d="M370,155 L490,150 L510,270 L440,320 L385,240 Z" />
                <path d="M485,55 L700,65 L730,185 L590,215 L500,155 Z" />
                <path d="M625,255 L725,260 L735,325 L640,330 Z" />
              </g>
              {radarNodes.map((node) => {
                const x = ((node.longitude + 180) / 360) * 800;
                const y = ((90 - node.latitude) / 180) * 400;
                const isSelected = selectedNode?.ip === node.ip;
                return (
                  <g key={node.ip} className="cursor-pointer" onClick={() => setSelectedNode(node)}>
                    <circle cx={x} cy={y} r={isSelected ? 18 : 12} fill="#ef4444" fillOpacity="0.22" />
                    <circle
                      cx={x}
                      cy={y}
                      r={isSelected ? 6.5 : 4.5}
                      fill={isSelected ? '#D4AF37' : '#ef4444'}
                      stroke="#ffffff"
                      strokeWidth="1.5"
                    />
                  </g>
                );
              })}
            </svg>
          </div>

          {selectedNode ? (
            <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="space-y-0.5">
                <div className="font-mono font-bold text-red-400" dir="ltr">
                  {selectedNode.ip} · {selectedNode.city}, {selectedNode.country}
                </div>
                <div className="text-gray-400 truncate max-w-md">{selectedNode.label}</div>
              </div>
              <div className="font-mono text-[11px] text-gray-300 shrink-0" dir="ltr">
                {selectedNode.asn} · {selectedNode.isp}
              </div>
            </div>
          ) : (
            <div className="p-3.5 rounded-xl bg-gray-950 border border-gray-800 text-xs text-gray-400 text-center">
              اضغط على «مسح عقد التهديد الحية» لجلب الإحداثيات الجغرافية الفعلية لخوادم C2 النشطة.
            </div>
          )}
        </div>
      </div>

      {/* Real-Time Event Log */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h3 className="text-sm font-bold text-white">سجل الأحداث الفعلي (Real-Time SOC Event Log)</h3>
          <div className="flex flex-wrap gap-1.5 bg-gray-950 p-1 rounded-xl border border-gray-800">
            {(
              [
                { id: 'all', label: 'الكل' },
                { id: 'critical', label: 'الأحداث الحرجة' },
                { id: 'network', label: 'الشبكة والـ Telemetry' },
                { id: 'forensic', label: 'التحقيق الجنائي' },
              ] as const
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setEventFilter(tab.id)}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition cursor-pointer ${
                  eventFilter === tab.id ? 'bg-[#D4AF37] text-gray-950' : 'text-gray-400 hover:text-white'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {mergedEvents.length === 0 ? (
          <div className="p-8 rounded-xl bg-gray-950 border border-gray-800 text-center text-xs text-gray-400">
            لا توجد أحداث مطابقة للفلتر الحالي بعد. قم بتشغيل أي فحص أو مزامنة تغذية حية لتدفق السجلات فوراً.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs border-collapse">
              <thead>
                <tr className="border-b border-gray-800 text-gray-400">
                  <th className="py-2.5 px-3 font-medium">الوقت</th>
                  <th className="py-2.5 px-3 font-medium">الحدث / المصدر</th>
                  <th className="py-2.5 px-3 font-medium">التفاصيل الفنية</th>
                  <th className="py-2.5 px-3 font-medium">الحالة</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/70">
                {mergedEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-gray-950/70">
                    <td className="py-2.5 px-3 font-mono tabular-nums text-gray-400 whitespace-nowrap" dir="ltr">
                      {new Date(ev.time).toLocaleString('en-GB')}
                    </td>
                    <td className="py-2.5 px-3 font-medium text-white max-w-xs truncate">{ev.title}</td>
                    <td className="py-2.5 px-3 text-gray-300 max-w-md truncate">{ev.detail}</td>
                    <td className="py-2.5 px-3 font-mono whitespace-nowrap">
                      <span
                        className={
                          ev.channel === 'critical'
                            ? 'text-red-400 font-bold'
                            : ev.channel === 'network'
                            ? 'text-emerald-400'
                            : 'text-[#D4AF37]'
                        }
                      >
                        {ev.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// 2. Vuln Mgmt + CISA KEV & EPSS Distribution Dashboard
// ============================================================================
export const VulnMgmtKevDashboard: React.FC<
  CommonSocProps & {
    liveFeedItems: SocLiveFeedItem[];
  }
> = ({ liveFeedItems, onNotify, onRecordAudit }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [catalogData, setCatalogData] = useState<any | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [priorityFilter, setPriorityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const [cveLookupInput, setCveLookupInput] = useState('');
  const [cveDetailResult, setCveDetailResult] = useState<any | null>(null);
  const [cveLookupLoading, setCveLookupLoading] = useState(false);

  const loadKevEpssCatalog = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      let loaded: any = null;
      try {
        const res = await fetch(apiUrl('/api/soc-kev-epss'));
        const parsed = await safeReadJsonResponse(res);
        if (res.ok && parsed.isJson && parsed.data?.summary) {
          loaded = parsed.data;
        }
      } catch {
        // fall through to browser fallback
      }

      if (!loaded) {
        // Real CORS-enabled client fallback via FIRST EPSS + Live Feed CVEs / CIRCL CVE
        const feedCves = liveFeedItems
          .map((f) => {
            const m = String(f.indicator || f.title).match(/CVE-\d{4}-\d{4,}/i);
            return m ? { cveId: m[0].toUpperCase(), feed: f } : null;
          })
          .filter((x): x is { cveId: string; feed: SocLiveFeedItem } => Boolean(x));

        const uniqueCves = Array.from(new Map(feedCves.map((x) => [x.cveId, x])).values()).slice(0, 30);
        const queryIds = uniqueCves.map((c) => c.cveId);
        const epssUrl = queryIds.length
          ? `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(queryIds.join(','))}`
          : `https://api.first.org/data/v1/epss?order=!epss&limit=35`;

        const epssParsed = await fetch(epssUrl)
          .then((r) => safeReadJsonResponse(r))
          .catch(() => null);

        const epssRows: any[] = Array.isArray(epssParsed?.data?.data) ? epssParsed.data.data : [];
        if (!epssRows.length && !uniqueCves.length) {
          throw new Error('تعذر جلب كتالوج الثغرات و EPSS حالياً.');
        }

        const epssMap = new Map<string, any>(epssRows.map((r) => [String(r.cve).toUpperCase(), r]));
        const combinedItems = (uniqueCves.length ? uniqueCves : epssRows.map((r) => ({ cveId: String(r.cve).toUpperCase(), feed: null }))).map((entry) => {
          const ep = epssMap.get(entry.cveId);
          const epssPct = ep ? Number((Number.parseFloat(ep.epss || '0') * 100).toFixed(2)) : null;
          const percentilePct = ep ? Number((Number.parseFloat(ep.percentile || '0') * 100).toFixed(1)) : null;
          const priority = epssPct !== null && epssPct >= 70 ? 'critical' : epssPct !== null && epssPct >= 35 ? 'high' : epssPct !== null && epssPct < 10 ? 'low' : 'medium';
          return {
            cveId: entry.cveId,
            vendorProject: entry.feed?.sourceName || 'FIRST EPSS Live Feed',
            product: entry.feed?.category || 'Exploit Prediction',
            vulnerabilityName: entry.feed?.title || `Active Vulnerability ${entry.cveId}`,
            shortDescription: entry.feed?.summary || `EPSS Score: ${epssPct ?? '—'}%`,
            dateAdded: ep?.date || new Date().toISOString().slice(0, 10),
            dueDate: '—',
            knownRansomware: /ransomware/i.test(entry.feed?.summary || ''),
            epssPct,
            percentilePct,
            priority,
          };
        });

        loaded = {
          catalogVersion: 'FIRST EPSS Live Stream',
          dateReleased: new Date().toISOString().slice(0, 10),
          summary: {
            totalKevCount: combinedItems.length,
            totalRansomware: combinedItems.filter((i) => i.knownRansomware).length,
            addedLast30Days: combinedItems.length,
            enrichedCount: combinedItems.length,
            epssCoverageCount: epssRows.length,
            avgEpssPct: combinedItems.length
              ? Number((combinedItems.reduce((s, i) => s + (i.epssPct ?? 0), 0) / combinedItems.length).toFixed(2))
              : 0,
            epssBuckets: {
              critical70Plus: combinedItems.filter((i) => (i.epssPct ?? 0) >= 70).length,
              high40To69: combinedItems.filter((i) => (i.epssPct ?? 0) >= 40 && (i.epssPct ?? 0) < 70).length,
              medium10To39: combinedItems.filter((i) => (i.epssPct ?? 0) >= 10 && (i.epssPct ?? 0) < 40).length,
              lowUnder10: combinedItems.filter((i) => i.epssPct !== null && i.epssPct < 10).length,
            },
            topVendors: [],
          },
          items: combinedItems,
        };
      }

      setCatalogData(loaded);
    } catch (err: any) {
      setError(err?.message || 'فشل تحميل بيانات الثغرات العالمية و EPSS.');
    } finally {
      setLoading(false);
    }
  }, [liveFeedItems]);

  useEffect(() => {
    void loadKevEpssCatalog();
  }, [loadKevEpssCatalog]);

  const lookupSpecificCve = async (e: React.FormEvent) => {
    e.preventDefault();
    const cve = cveLookupInput.trim().toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) {
      onNotify('يرجى إدخال معرف CVE صحيح مثل CVE-2024-3094.', 'warning');
      return;
    }
    setCveLookupLoading(true);
    setCveDetailResult(null);
    try {
      let detail: any = null;
      const res = await fetch(apiUrl('/api/soc-kev-epss'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cve }),
      }).catch(() => null);
      if (res) {
        const parsed = await safeReadJsonResponse(res);
        if (parsed.isJson && parsed.data?.cveDetail) detail = parsed.data.cveDetail;
      }
      if (!detail) {
        const epRes = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`);
        const epParsed = await safeReadJsonResponse(epRes);
        const row = epParsed.data?.data?.[0];
        detail = {
          cveId: cve,
          summary: row ? 'تم استخراج احتمال الاستغلال الحي من FIRST.org EPSS.' : 'لم يُعثر على سجل EPSS لهذا الـ CVE.',
          cvss: null,
          epss: row ? Number.parseFloat(row.epss) : null,
          percentile: row ? Number.parseFloat(row.percentile) : null,
          epssDate: row?.date || null,
        };
      }
      setCveDetailResult(detail);
      onRecordAudit({
        id: 'cve-' + Math.random().toString(36).slice(2, 9),
        fileName: `فحص ثغرة CVE + EPSS: ${cve}`,
        fileSize: detail.epss !== null ? `EPSS ${(detail.epss * 100).toFixed(2)}%` : 'CVE Lookup',
        verdict: detail.summary?.slice(0, 110) || cve,
        score: detail.epss !== null ? Math.max(10, Math.round(100 - detail.epss * 100)) : 70,
        risk: detail.epss >= 0.7 ? 'حرج' : detail.epss >= 0.3 ? 'مرتفع' : 'متوسط',
        sha256: cve,
      });
    } finally {
      setCveLookupLoading(false);
    }
  };

  const filteredItems = useMemo(() => {
    const items: any[] = Array.isArray(catalogData?.items) ? catalogData.items : [];
    const q = searchQuery.trim().toLowerCase();
    return items.filter((item) => {
      if (ransomwareOnly && !item.knownRansomware) return false;
      if (priorityFilter !== 'all' && item.priority !== priorityFilter) return false;
      if (
        q &&
        !String(item.cveId).toLowerCase().includes(q) &&
        !String(item.vendorProject).toLowerCase().includes(q) &&
        !String(item.product).toLowerCase().includes(q) &&
        !String(item.vulnerabilityName).toLowerCase().includes(q)
      ) {
        return false;
      }
      return true;
    });
  }, [catalogData, priorityFilter, ransomwareOnly, searchQuery]);

  const exportCsv = () => {
    if (!filteredItems.length) return;
    const header = ['CVE', 'Vendor', 'Product', 'Priority', 'EPSS_Pct', 'Percentile', 'Ransomware', 'DateAdded', 'DueDate'];
    const lines = [
      header.join(','),
      ...filteredItems.map((i) =>
        [
          i.cveId,
          `"${String(i.vendorProject).replace(/"/g, '""')}"`,
          `"${String(i.product).replace(/"/g, '""')}"`,
          i.priority,
          i.epssPct ?? '',
          i.percentilePct ?? '',
          i.knownRansomware ? 'Yes' : 'No',
          i.dateAdded,
          i.dueDate,
        ].join(',')
      ),
    ];
    const blob = new Blob([lines.join('\n')], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sovereign_kev_epss_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const summary = catalogData?.summary;
  const buckets = summary?.epssBuckets || { critical70Plus: 0, high40To69: 0, medium10To39: 0, lowUnder10: 0 };
  const totalBucket = buckets.critical70Plus + buckets.high40To69 + buckets.medium10To39 + buckets.lowUnder10 || 1;

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header & Single CVE Search */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-gray-800 pb-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-gray-400">
              CISA KEV Live Catalog · FIRST.org EPSS Scoring · CIRCL CVE
            </div>
            <h2 className="text-xl md:text-2xl font-bold text-white">
              لوحة إدارة الثغرات ونقاط الضعف (Vuln Mgmt + KEV & EPSS Dashboard)
            </h2>
            <p className="text-xs text-gray-400">
              تتبع حي للثغرات المستغلة فعلياً عالمياً (CISA KEV) مع تصنيف احتمالية الاستغلال خلال 30 يوماً (EPSS) وتوزيع الأولوية ومؤشرات برامج الفدية.
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={exportCsv}
              disabled={!filteredItems.length}
              className="px-4 py-2 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 flex items-center gap-2 cursor-pointer whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>تصدير CSV</span>
            </button>
            <button
              type="button"
              disabled={loading}
              onClick={() => void loadKevEpssCatalog()}
              className="px-4 py-2 rounded-xl bg-[#D4AF37] hover:bg-[#c49f2c] text-gray-950 text-xs font-bold flex items-center gap-2 cursor-pointer whitespace-nowrap shrink-0"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>تحديث KEV & EPSS</span>
            </button>
          </div>
        </div>

        <form onSubmit={lookupSpecificCve} className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            value={cveLookupInput}
            onChange={(e) => setCveLookupInput(e.target.value)}
            placeholder="فحص فوري لأي ثغرة CVE (مثال: CVE-2024-3094 أو CVE-2021-44228)..."
            className="flex-1 bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-2.5 text-xs sm:text-sm text-white font-mono outline-none"
            dir="ltr"
          />
          <button
            type="submit"
            disabled={cveLookupLoading || !cveLookupInput.trim()}
            className="px-5 py-2.5 rounded-xl bg-gray-950 hover:bg-gray-800 border border-[#D4AF37]/50 text-[#D4AF37] text-xs font-bold flex items-center justify-center gap-2 cursor-pointer whitespace-nowrap shrink-0"
          >
            {cveLookupLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            <span>جلب CVSS و EPSS للثغرة</span>
          </button>
        </form>

        {cveDetailResult && (
          <div className="p-4 rounded-xl bg-gray-950 border border-[#D4AF37]/40 space-y-2 text-xs">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="font-mono font-bold text-sm text-[#D4AF37]" dir="ltr">{cveDetailResult.cveId}</span>
              <div className="flex items-center gap-4 font-mono tabular-nums text-gray-200" dir="ltr">
                <span>CVSS: {cveDetailResult.cvss ?? 'N/A'}</span>
                <span className="text-red-400 font-bold">
                  EPSS: {cveDetailResult.epss !== null ? `${(cveDetailResult.epss * 100).toFixed(2)}%` : 'N/A'}
                </span>
                <span>Percentile: {cveDetailResult.percentile !== null ? `${(cveDetailResult.percentile * 100).toFixed(1)}%` : '—'}</span>
              </div>
            </div>
            <p className="text-gray-300 leading-relaxed" dir="ltr">{cveDetailResult.summary}</p>
          </div>
        )}

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/40 text-red-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* KPI Strip */}
      {summary && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
            <div className="text-xs text-gray-400">إجمالي الثغرات المستغلة (KEV)</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-white">
              {Number(summary.totalKevCount).toLocaleString('en-US')}
            </div>
            <div className="text-[11px] font-mono text-gray-500">إصدار الكتالوج: {catalogData.catalogVersion || 'Live'}</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
            <div className="text-xs text-gray-400">مرتبطة بهجمات الفدية (Ransomware)</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-red-400">
              {Number(summary.totalRansomware).toLocaleString('en-US')}
            </div>
            <div className="text-[11px] font-mono text-gray-500">مؤكدة في حملات نشطة</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
            <div className="text-xs text-gray-400">ثغرات مضافة آخر 30 يوماً</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-amber-400">{summary.addedLast30Days}</div>
            <div className="text-[11px] font-mono text-gray-500">تحديث مستمر من CISA</div>
          </div>
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
            <div className="text-xs text-gray-400">متوسط احتمال الاستغلال (EPSS)</div>
            <div className="text-2xl font-bold font-mono tabular-nums text-[#D4AF37]">{summary.avgEpssPct}%</div>
            <div className="text-[11px] font-mono text-gray-500">تغطية {summary.epssCoverageCount} ثغرة من FIRST.org</div>
          </div>
        </div>
      )}

      {/* EPSS & Severity Distribution + Top Affected Vendors */}
      {summary && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white">توزيع نسب المخاطر والاحتمالية (EPSS & Severity Distribution)</h3>
            <div className="space-y-3">
              {[
                { label: 'حرج (EPSS ≥ 70%)', count: buckets.critical70Plus, color: 'bg-red-500', text: 'text-red-400' },
                { label: 'مرتفع (EPSS 40% – 69%)', count: buckets.high40To69, color: 'bg-amber-500', text: 'text-amber-400' },
                { label: 'متوسط (EPSS 10% – 39%)', count: buckets.medium10To39, color: 'bg-[#D4AF37]', text: 'text-[#D4AF37]' },
                { label: 'منخفض (EPSS < 10%)', count: buckets.lowUnder10, color: 'bg-emerald-500', text: 'text-emerald-400' },
              ].map((b) => {
                const pct = Math.round((b.count / totalBucket) * 100);
                return (
                  <div key={b.label} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className={b.text}>{b.label}</span>
                      <span className="font-mono tabular-nums text-gray-300">{b.count} CVE ({pct}%)</span>
                    </div>
                    <div className="h-2 w-full bg-gray-950 rounded-full overflow-hidden border border-gray-800">
                      <div className={`h-full ${b.color}`} style={{ width: `${Math.max(2, pct)}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
            <h3 className="text-sm font-bold text-white">أكثر الموردين والأنظمة تأثراً في الكتالوج العالمي</h3>
            {summary.topVendors?.length > 0 ? (
              <div className="grid grid-cols-2 gap-2.5">
                {summary.topVendors.map((v: any) => (
                  <button
                    key={v.vendor}
                    type="button"
                    onClick={() => setSearchQuery(v.vendor)}
                    className="p-3 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-800 text-right flex items-center justify-between gap-2 transition cursor-pointer"
                  >
                    <span className="text-xs font-medium text-gray-200 truncate">{v.vendor}</span>
                    <span className="text-xs font-mono tabular-nums font-bold text-[#D4AF37] shrink-0">{v.count}</span>
                  </button>
                ))}
              </div>
            ) : (
              <div className="text-xs text-gray-400 p-4 bg-gray-950 rounded-xl border border-gray-800">
                تمت تغذية قائمة الثغرات من تغذية FIRST EPSS الحية.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Prioritized CVEs Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {(
              [
                { id: 'all', label: 'الكل' },
                { id: 'critical', label: 'أولوية حرجة' },
                { id: 'high', label: 'مرتفعة' },
                { id: 'medium', label: 'متوسطة' },
                { id: 'low', label: 'منخفضة' },
              ] as const
            ).map((f) => (
              <button
                key={f.id}
                type="button"
                onClick={() => setPriorityFilter(f.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-bold transition cursor-pointer ${
                  priorityFilter === f.id ? 'bg-[#D4AF37] text-gray-950' : 'bg-gray-950 text-gray-300 border border-gray-800'
                }`}
              >
                {f.label}
              </button>
            ))}
            <button
              type="button"
              onClick={() => setRansomwareOnly((v) => !v)}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition cursor-pointer ${
                ransomwareOnly ? 'bg-red-500/20 border-red-500/50 text-red-300' : 'bg-gray-950 border-gray-800 text-gray-400'
              }`}
            >
              الفدية فقط (Ransomware)
            </button>
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="تصفية برقم CVE أو المنتج أو المورد..."
            className="bg-gray-950 border border-gray-800 focus:border-[#D4AF37] rounded-xl px-3.5 py-2 text-xs text-white font-mono outline-none w-full lg:w-72"
            dir="ltr"
          />
        </div>

        {loading && !catalogData ? (
          <div className="p-10 text-center text-xs text-gray-400 flex items-center justify-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin text-[#D4AF37]" />
            <span>جاري سحب الثغرات المستغلة وحساب احتمالات EPSS الحية...</span>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-right text-xs border-collapse">
              <thead>
                <tr className="border-b border-gray-800 text-gray-400">
                  <th className="py-2.5 px-3 font-medium">CVE ID</th>
                  <th className="py-2.5 px-3 font-medium">المورد / المنتج</th>
                  <th className="py-2.5 px-3 font-medium">الوصف المختصر</th>
                  <th className="py-2.5 px-3 font-medium">EPSS %</th>
                  <th className="py-2.5 px-3 font-medium">الاستغلال بالفدية</th>
                  <th className="py-2.5 px-3 font-medium">الموعد / الإدراج</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/70">
                {filteredItems.map((item) => (
                  <tr key={item.cveId} className="hover:bg-gray-950/70">
                    <td className="py-3 px-3 font-mono font-bold text-[#D4AF37] whitespace-nowrap" dir="ltr">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${item.cveId}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:underline inline-flex items-center gap-1"
                      >
                        <span>{item.cveId}</span>
                        <ExternalLink className="w-3 h-3 opacity-70" />
                      </a>
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-medium text-white">{item.vendorProject}</div>
                      <div className="text-[11px] text-gray-400">{item.product}</div>
                    </td>
                    <td className="py-3 px-3 text-gray-300 max-w-md">{item.vulnerabilityName}</td>
                    <td className="py-3 px-3 font-mono tabular-nums whitespace-nowrap">
                      <span
                        className={
                          (item.epssPct ?? 0) >= 70
                            ? 'text-red-400 font-bold'
                            : (item.epssPct ?? 0) >= 35
                            ? 'text-amber-300 font-bold'
                            : 'text-emerald-400'
                        }
                      >
                        {item.epssPct !== null ? `${item.epssPct}%` : '—'}
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      {item.knownRansomware ? (
                        <span className="text-red-400 font-bold">مؤكد (Known)</span>
                      ) : (
                        <span className="text-gray-400">غير مرصود</span>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono tabular-nums text-gray-400 whitespace-nowrap" dir="ltr">
                      {item.dateAdded}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

// ============================================================================
// 3. Asset & OS Distribution + High-Risk Endpoints Dashboard (SVG Donut Charts)
// ============================================================================
type OsCategory = 'Windows' | 'Linux / Servers' | 'Android / Mobile' | 'Network / Web';

interface MonitoredEndpointAsset {
  id: string;
  name: string;
  target: string;
  osCategory: OsCategory;
  riskScore: number;
  riskLevel: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض';
  source: string;
  findings: string;
  checkedAt: string;
}

const ASSET_STORAGE_KEY = 'sovereign_monitored_endpoints_v1';

function detectCurrentClientOs(): OsCategory {
  const ua = navigator.userAgent || '';
  if (/Android|iPhone|iPad|iPod|Mobile/i.test(ua)) return 'Android / Mobile';
  if (/Windows/i.test(ua)) return 'Windows';
  return 'Linux / Servers';
}

function classifyAuditIntoAsset(row: SocAuditRow): MonitoredEndpointAsset {
  const txt = `${row.fileName} ${row.verdict} ${row.fileSize || ''}`.toLowerCase();
  let osCategory: OsCategory = 'Network / Web';
  if (/apk|android|\.dex|mobile|jailbreak/i.test(txt)) {
    osCategory = 'Android / Mobile';
  } else if (/\.exe|\.dll|pe\b|windows|powershell|\.bat|\.vbs|\.ps1/i.test(txt)) {
    osCategory = 'Windows';
  } else if (/elf|linux|ssl|tls|server|ssh|nginx|apache|cve|ubuntu|debian/i.test(txt)) {
    osCategory = 'Linux / Servers';
  }

  const normalizedRisk: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض' =
    row.risk === 'حرج' ? 'حرج' : row.risk === 'مرتفع' ? 'مرتفع' : row.risk === 'متوسط' ? 'متوسط' : 'منخفض';
  const riskScore = Math.max(0, Math.min(100, 100 - (typeof row.score === 'number' ? row.score : 80)));

  return {
    id: `aud-${row.id}`,
    name: row.fileName.slice(0, 64),
    target: row.sha256 ? `${row.sha256.slice(0, 14)}...` : row.fileSize || 'Local Artifact',
    osCategory,
    riskScore,
    riskLevel: normalizedRisk,
    source: 'سجل التحقيق الجنائي الفعلي',
    findings: row.verdict,
    checkedAt: row.timestamp,
  };
}

interface DonutSlice {
  label: string;
  count: number;
  color: string;
}

const SvgDonutChart: React.FC<{
  title: string;
  slices: DonutSlice[];
  selectedLabel: string | null;
  onSelectLabel: (label: string | null) => void;
}> = ({ title, slices, selectedLabel, onSelectLabel }) => {
  const total = slices.reduce((s, x) => s + x.count, 0);
  const radius = 64;
  const stroke = 20;
  const circumference = 2 * Math.PI * radius;

  let offsetAcc = 0;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-white">{title}</h3>
        {selectedLabel && (
          <button
            type="button"
            onClick={() => onSelectLabel(null)}
            className="text-[11px] text-[#D4AF37] hover:underline cursor-pointer"
          >
            إظهار الكل
          </button>
        )}
      </div>

      <div className="flex flex-col sm:flex-row items-center gap-6">
        <div className="relative w-44 h-44 shrink-0 flex items-center justify-center">
          <svg viewBox="0 0 180 180" className="w-full h-full -rotate-90">
            <circle cx="90" cy="90" r={radius} fill="none" stroke="#1f2937" strokeWidth={stroke} />
            {total > 0 &&
              slices.map((s) => {
                if (s.count === 0) return null;
                const segLen = (s.count / total) * circumference;
                const dashArray = `${segLen} ${circumference - segLen}`;
                const dashOffset = -offsetAcc;
                offsetAcc += segLen;
                const dimmed = selectedLabel && selectedLabel !== s.label;
                return (
                  <circle
                    key={s.label}
                    cx="90"
                    cy="90"
                    r={radius}
                    fill="none"
                    stroke={s.color}
                    strokeWidth={selectedLabel === s.label ? stroke + 4 : stroke}
                    strokeDasharray={dashArray}
                    strokeDashoffset={dashOffset}
                    opacity={dimmed ? 0.3 : 1}
                    className="cursor-pointer transition-opacity"
                    onClick={() => onSelectLabel(selectedLabel === s.label ? null : s.label)}
                  />
                );
              })}
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-2xl font-bold font-mono tabular-nums text-white">{total}</span>
            <span className="text-[10px] text-gray-400">إجمالي الأصول</span>
          </div>
        </div>

        <div className="flex-1 w-full space-y-2">
          {slices.map((s) => {
            const pct = total ? Math.round((s.count / total) * 100) : 0;
            const active = selectedLabel === s.label;
            return (
              <button
                key={s.label}
                type="button"
                onClick={() => onSelectLabel(active ? null : s.label)}
                className={`w-full px-3 py-2 rounded-xl border text-xs flex items-center justify-between gap-2 transition cursor-pointer ${
                  active
                    ? 'bg-gray-950 border-[#D4AF37] text-white'
                    : 'bg-gray-950/70 border-gray-800 text-gray-300 hover:border-gray-700'
                }`}
              >
                <span className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: s.color }} />
                  <span>{s.label}</span>
                </span>
                <span className="font-mono tabular-nums text-gray-200">
                  {s.count} ({pct}%)
                </span>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
};

export const AssetOsDistributionDashboard: React.FC<
  CommonSocProps & {
    auditLogs: SocAuditRow[];
    evidenceList: SocEvidenceRow[];
  }
> = ({ auditLogs, evidenceList, onNotify, onRecordAudit }) => {
  const [customEndpoints, setCustomEndpoints] = useState<MonitoredEndpointAsset[]>(() => {
    try {
      const saved = localStorage.getItem(ASSET_STORAGE_KEY);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });
  const [probeHost, setProbeHost] = useState('');
  const [probeOs, setProbeOs] = useState<OsCategory>('Linux / Servers');
  const [probing, setProbing] = useState(false);
  const [osSliceFilter, setOsSliceFilter] = useState<string | null>(null);
  const [riskSliceFilter, setRiskSliceFilter] = useState<string | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem(ASSET_STORAGE_KEY, JSON.stringify(customEndpoints));
    } catch {
      // ignore storage quota errors
    }
  }, [customEndpoints]);

  // Real local analyst workstation asset derived from live Navigator telemetry
  const localWorkstationAsset = useMemo<MonitoredEndpointAsset>(() => {
    const osCat = detectCurrentClientOs();
    const cores = navigator.hardwareConcurrency || '—';
    const mem = (navigator as any).deviceMemory ? `${(navigator as any).deviceMemory}GB RAM` : '';
    return {
      id: 'local-workstation',
      name: `محطة المحقق الحالية (${navigator.platform || osCat})`,
      target: `${cores} Cores ${mem}`.trim(),
      osCategory: osCat,
      riskScore: 8,
      riskLevel: 'منخفض',
      source: 'بيانات المتصفح الحية',
      findings: navigator.userAgent.slice(0, 80),
      checkedAt: new Date().toISOString(),
    };
  }, []);

  // Combined real assets = custom probed/imported endpoints + real derived forensic audit endpoints + local workstation
  const allAssets = useMemo<MonitoredEndpointAsset[]>(() => {
    const derivedFromAudit = auditLogs.slice(0, 35).map(classifyAuditIntoAsset);
    const derivedFromEvidence: MonitoredEndpointAsset[] = evidenceList.slice(0, 20).map((ev) => {
      const name = ev.fileName || ev.title || 'Evidence Item';
      const osCategory: OsCategory = /\.apk/i.test(name)
        ? 'Android / Mobile'
        : /\.(exe|dll|ps1|bat)/i.test(name)
        ? 'Windows'
        : /\.(elf|sh|log|conf)/i.test(name)
        ? 'Linux / Servers'
        : 'Network / Web';
      const rawRisk = ev.riskLevel === 'حرج' || ev.riskLevel === 'مرتفع' || ev.riskLevel === 'متوسط' || ev.riskLevel === 'منخفض'
        ? ev.riskLevel
        : 'منخفض';
      return {
        id: `ev-${ev.id}`,
        name,
        target: ev.sha256 ? `${ev.sha256.slice(0, 14)}...` : ev.fileType || 'Evidence',
        osCategory,
        riskScore: Math.max(0, 100 - (ev.authenticityScore ?? 85)),
        riskLevel: rawRisk,
        source: 'خزنة الأدلة (Firestore)',
        findings: ev.status || 'محفوظ بسلسلة الحيازة',
        checkedAt: ev.createdAt || new Date().toISOString(),
      };
    });

    return [localWorkstationAsset, ...customEndpoints, ...derivedFromAudit, ...derivedFromEvidence];
  }, [auditLogs, customEndpoints, evidenceList, localWorkstationAsset]);

  // Live Endpoint Probe (queries real /api/ip-geo-threat or /api/ssl-inspect to score & classify host!)
  const handleProbeAndRegisterHost = async (e: React.FormEvent) => {
    e.preventDefault();
    const target = probeHost.trim();
    if (!target || probing) return;
    setProbing(true);

    try {
      const isIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(target);
      let riskScore = 15;
      let findings = 'اتصال قياسي — لم تُرصد تهديدات مباشرة';
      let resolvedTarget = target;

      if (isIp) {
        const res = await fetch(apiUrl('/api/ip-geo-threat'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: target }),
        }).catch(() => null);
        const parsed = res ? await safeReadJsonResponse(res) : null;
        const g = parsed?.data?.geoThreat;
        if (g) {
          resolvedTarget = `${g.ip} (${g.countryCode || g.country} · ${g.asn})`;
          if (g.blocklisted) {
            riskScore = 92;
            findings = `مدرج في ${g.blocklistHits.length} قائمة حظر (${g.blocklistHits.map((h: any) => h.source).join(', ')})`;
          } else {
            riskScore = 12;
            findings = `نظيف في قوائم الحظر · ${g.isp}`;
          }
        }
      } else {
        const res = await fetch(apiUrl('/api/ssl-inspect'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ target }),
        }).catch(() => null);
        const parsed = res ? await safeReadJsonResponse(res) : null;
        const cert = parsed?.data?.certificate;
        if (cert) {
          resolvedTarget = `${cert.hostname} (${cert.resolvedIp})`;
          if (cert.isExpired) {
            riskScore = 88;
            findings = `شهادة SSL منتهية الصلاحية (${cert.validTo})`;
          } else if (!cert.authorized) {
            riskScore = 65;
            findings = `سلسلة ثقة SSL غير مكتملة · ${cert.protocol}`;
          } else {
            riskScore = 10;
            findings = `${cert.protocol} صالح (${cert.daysRemaining ?? '—'} يوم) · ${cert.issuerO}`;
          }
        }
      }

      const riskLevel: 'حرج' | 'مرتفع' | 'متوسط' | 'منخفض' =
        riskScore >= 80 ? 'حرج' : riskScore >= 55 ? 'مرتفع' : riskScore >= 30 ? 'متوسط' : 'منخفض';

      const newAsset: MonitoredEndpointAsset = {
        id: 'ep-' + Date.now(),
        name: target,
        target: resolvedTarget,
        osCategory: probeOs,
        riskScore,
        riskLevel,
        source: 'فحص أصل شبكي حي',
        findings,
        checkedAt: new Date().toISOString(),
      };

      setCustomEndpoints((prev) => [newAsset, ...prev]);
      setProbeHost('');
      onRecordAudit({
        id: newAsset.id,
        fileName: `تسجيل وفحص أصل (${probeOs}): ${target}`,
        fileSize: resolvedTarget,
        verdict: findings,
        score: 100 - riskScore,
        risk: riskLevel,
        sha256: target,
      });
      onNotify(`تم فحص الأصل ${target} وتصنيفه (${riskLevel}).`, riskLevel === 'حرج' ? 'error' : 'success');
    } finally {
      setProbing(false);
    }
  };

  // Real JSON / CSV Asset Inventory Import
  const handleImportInventory = async (file: File) => {
    try {
      const text = await file.text();
      const imported: MonitoredEndpointAsset[] = [];

      if (file.name.endsWith('.json')) {
        const json = JSON.parse(text);
        const arr = Array.isArray(json) ? json : Array.isArray(json.assets) ? json.assets : [];
        for (const row of arr.slice(0, 100)) {
          const osRaw = String(row.os || row.osCategory || row.platform || '');
          const osCategory: OsCategory = /win/i.test(osRaw)
            ? 'Windows'
            : /android|ios|mobile/i.test(osRaw)
            ? 'Android / Mobile'
            : /linux|ubuntu|debian|centos|server/i.test(osRaw)
            ? 'Linux / Servers'
            : 'Network / Web';
          const score = Math.max(0, Math.min(100, Number(row.riskScore ?? 35) || 35));
          imported.push({
            id: 'imp-' + Math.random().toString(36).slice(2, 9),
            name: String(row.name || row.hostname || row.host || 'Imported Asset'),
            target: String(row.ip || row.target || 'Inventory'),
            osCategory,
            riskScore: score,
            riskLevel: score >= 75 ? 'حرج' : score >= 50 ? 'مرتفع' : score >= 25 ? 'متوسط' : 'منخفض',
            source: `ملف جرد (${file.name})`,
            findings: String(row.findings || row.status || 'مستورد من جرد المؤسسة'),
            checkedAt: new Date().toISOString(),
          });
        }
      } else {
        const lines = text.split(/\r?\n/).filter((l) => l.trim());
        for (const line of lines.slice(1, 101)) {
          const [name = 'Endpoint', osRaw = 'Linux', target = '—', scoreStr = '25', findings = 'CSV Inventory'] = line
            .split(',')
            .map((c) => c.trim().replace(/^"|"$/g, ''));
          const osCategory: OsCategory = /win/i.test(osRaw)
            ? 'Windows'
            : /android|ios|mobile/i.test(osRaw)
            ? 'Android / Mobile'
            : /linux|server|ubuntu/i.test(osRaw)
            ? 'Linux / Servers'
            : 'Network / Web';
          const score = Math.max(0, Math.min(100, Number.parseInt(scoreStr, 10) || 25));
          imported.push({
            id: 'csv-' + Math.random().toString(36).slice(2, 9),
            name,
            target,
            osCategory,
            riskScore: score,
            riskLevel: score >= 75 ? 'حرج' : score >= 50 ? 'مرتفع' : score >= 25 ? 'متوسط' : 'منخفض',
            source: `جرد CSV (${file.name})`,
            findings,
            checkedAt: new Date().toISOString(),
          });
        }
      }

      if (!imported.length) {
        onNotify('لم يتم العثور على سجلات أصول صالحة داخل الملف.', 'warning');
        return;
      }
      setCustomEndpoints((prev) => [...imported, ...prev]);
      onNotify(`تم استيراد ${imported.length} أصل فعلي من ${file.name}.`, 'success');
    } catch {
      onNotify('تعذر قراءة ملف الجرد. تأكد من تنسيق JSON أو CSV.', 'error');
    }
  };

  const osSlices: DonutSlice[] = useMemo(() => {
    const counts: Record<OsCategory, number> = {
      Windows: 0,
      'Linux / Servers': 0,
      'Android / Mobile': 0,
      'Network / Web': 0,
    };
    for (const a of allAssets) counts[a.osCategory]++;
    return [
      { label: 'Windows', count: counts.Windows, color: '#38BDF8' },
      { label: 'Linux / Servers', count: counts['Linux / Servers'], color: '#D4AF37' },
      { label: 'Android / Mobile', count: counts['Android / Mobile'], color: '#10B981' },
      { label: 'Network / Web', count: counts['Network / Web'], color: '#A855F7' },
    ];
  }, [allAssets]);

  const riskSlices: DonutSlice[] = useMemo(() => {
    const c = { حرج: 0, مرتفع: 0, متوسط: 0, منخفض: 0 };
    for (const a of allAssets) c[a.riskLevel]++;
    return [
      { label: 'حرج', count: c.حرج, color: '#EF4444' },
      { label: 'مرتفع', count: c.مرتفع, color: '#F59E0B' },
      { label: 'متوسط', count: c.متوسط, color: '#D4AF37' },
      { label: 'منخفض', count: c.منخفض, color: '#10B981' },
    ];
  }, [allAssets]);

  const filteredAssets = useMemo(() => {
    return allAssets
      .filter((a) => (!osSliceFilter || a.osCategory === osSliceFilter) && (!riskSliceFilter || a.riskLevel === riskSliceFilter))
      .sort((a, b) => b.riskScore - a.riskScore);
  }, [allAssets, osSliceFilter, riskSliceFilter]);

  const highRiskCount = allAssets.filter((a) => a.riskLevel === 'حرج' || a.riskLevel === 'مرتفع').length;

  return (
    <div className="space-y-6 animate-fadeIn">
      {/* Header & Live Host Probe / CSV Import */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-gray-800 pb-4">
          <div className="space-y-1">
            <div className="text-xs font-mono text-gray-400">
              Asset & OS Telemetry · Endpoint Risk Posture · Live Host Probe
            </div>
            <h2 className="text-xl md:text-2xl font-bold text-white">
              لوحة إحصائيات أنظمة التشغيل والأصول المهددة (Asset & OS Distribution)
            </h2>
            <p className="text-xs text-gray-400">
              توزيع تفاعلي (Donut Charts) لأنظمة التشغيل والأصول المستخلصة فعلياً من سجل العمليات، خزنة الأدلة، وفحوصات المضيفين المباشرة أو ملفات جرد المؤسسة.
            </p>
          </div>
          <label className="px-4 py-2 rounded-xl bg-gray-950 hover:bg-gray-800 border border-gray-700 text-xs font-bold text-gray-200 flex items-center gap-2 cursor-pointer whitespace-nowrap shrink-0">
            <Upload className="w-3.5 h-3.5 text-[#D4AF37]" />
            <span>استيراد جرد أصول (CSV / JSON)</span>
            <input
              type="file"
              accept=".json,.csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void handleImportInventory(f);
                e.target.value = '';
              }}
            />
          </label>
        </div>

        <form onSubmit={handleProbeAndRegisterHost} className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <input
            type="text"
            value={probeHost}
            onChange={(e) => setProbeHost(e.target.value)}
            placeholder="أدخل IP أو Domain أصل/خادم لفحصه وإدراجه حياً (مثال: 8.8.8.8 أو github.com)..."
            className="md:col-span-6 bg-gray-950 border border-gray-700 focus:border-[#D4AF37] rounded-xl px-4 py-2.5 text-xs sm:text-sm text-white font-mono outline-none"
            dir="ltr"
          />
          <select
            value={probeOs}
            onChange={(e) => setProbeOs(e.target.value as OsCategory)}
            className="md:col-span-3 bg-gray-950 border border-gray-700 rounded-xl px-3 py-2.5 text-xs text-white outline-none"
          >
            <option value="Linux / Servers">Linux / Servers</option>
            <option value="Windows">Windows Endpoint</option>
            <option value="Android / Mobile">Android / Mobile</option>
            <option value="Network / Web">Network / Web Gateway</option>
          </select>
          <button
            type="submit"
            disabled={probing || !probeHost.trim()}
            className="md:col-span-3 px-4 py-2.5 rounded-xl bg-[#D4AF37] hover:bg-[#c49f2c] disabled:opacity-50 text-gray-950 text-xs font-bold flex items-center justify-center gap-2 cursor-pointer"
          >
            {probing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />}
            <span>{probing ? 'جاري الفحص...' : 'فحص وإضافة الأصل'}</span>
          </button>
        </form>
      </div>

      {/* Summary KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">إجمالي الأصول المرصودة</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white">{allAssets.length}</div>
          <div className="text-[11px] font-mono text-gray-500">محطة العمل + الأدلة + الخوادم</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">أجهزة عالية الخطورة (High-Risk)</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-red-400">{highRiskCount}</div>
          <div className="text-[11px] font-mono text-gray-500">تصنيف حرج أو مرتفع الخطورة</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">خوادم Linux / Web</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-[#D4AF37]">
            {(osSlices[1]?.count || 0) + (osSlices[3]?.count || 0)}
          </div>
          <div className="text-[11px] font-mono text-gray-500">خوادم وخدمات شبكية</div>
        </div>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 space-y-1">
          <div className="text-xs text-gray-400">أجهزة Windows & Mobile</div>
          <div className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
            {(osSlices[0]?.count || 0) + (osSlices[2]?.count || 0)}
          </div>
          <div className="text-[11px] font-mono text-gray-500">نقاط نهاية وباينري وأندرويد</div>
        </div>
      </div>

      {/* Dual Interactive Donut Charts */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <SvgDonutChart
          title="توزيع أنظمة التشغيل والأصول (OS Distribution Donut)"
          slices={osSlices}
          selectedLabel={osSliceFilter}
          onSelectLabel={setOsSliceFilter}
        />
        <SvgDonutChart
          title="توزيع حالة المخاطر للأصول (Endpoint Risk Posture Donut)"
          slices={riskSlices}
          selectedLabel={riskSliceFilter}
          onSelectLabel={setRiskSliceFilter}
        />
      </div>

      {/* High-Risk Endpoints Prioritization Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-5 space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <SlidersHorizontal className="w-4 h-4 text-[#D4AF37]" />
            <span>قائمة الأصول والأجهزة مرتبة حسب الخطورة ({filteredAssets.length})</span>
          </h3>
          {(osSliceFilter || riskSliceFilter) && (
            <button
              type="button"
              onClick={() => {
                setOsSliceFilter(null);
                setRiskSliceFilter(null);
              }}
              className="text-xs text-[#D4AF37] hover:underline cursor-pointer"
            >
              إعادة ضبط الفلاتر
            </button>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-right text-xs border-collapse">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="py-2.5 px-3 font-medium">الأصل / نقطة النهاية</th>
                <th className="py-2.5 px-3 font-medium">نظام التشغيل</th>
                <th className="py-2.5 px-3 font-medium">المعرّف / IP</th>
                <th className="py-2.5 px-3 font-medium">النتائج المكتشفة</th>
                <th className="py-2.5 px-3 font-medium">الخطورة</th>
                <th className="py-2.5 px-3 font-medium">إجراء</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/70">
              {filteredAssets.map((asset) => (
                <tr key={asset.id} className="hover:bg-gray-950/70">
                  <td className="py-3 px-3">
                    <div className="font-medium text-white max-w-xs truncate">{asset.name}</div>
                    <div className="text-[10px] text-gray-500">{asset.source}</div>
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap text-gray-200">
                    <span className="inline-flex items-center gap-1.5">
                      {asset.osCategory === 'Windows' ? (
                        <Monitor className="w-3.5 h-3.5 text-sky-400" />
                      ) : asset.osCategory === 'Linux / Servers' ? (
                        <Server className="w-3.5 h-3.5 text-[#D4AF37]" />
                      ) : asset.osCategory === 'Android / Mobile' ? (
                        <Smartphone className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Router className="w-3.5 h-3.5 text-purple-400" />
                      )}
                      <span>{asset.osCategory}</span>
                    </span>
                  </td>
                  <td className="py-3 px-3 font-mono text-gray-300 whitespace-nowrap" dir="ltr">{asset.target}</td>
                  <td className="py-3 px-3 text-gray-300 max-w-sm truncate">{asset.findings}</td>
                  <td className="py-3 px-3 font-mono tabular-nums whitespace-nowrap">
                    <span
                      className={`inline-flex items-center gap-1 font-bold ${
                        asset.riskLevel === 'حرج'
                          ? 'text-red-400'
                          : asset.riskLevel === 'مرتفع'
                          ? 'text-amber-400'
                          : asset.riskLevel === 'متوسط'
                          ? 'text-[#D4AF37]'
                          : 'text-emerald-400'
                      }`}
                    >
                      {asset.riskLevel === 'حرج' ? (
                        <XCircle className="w-3.5 h-3.5" />
                      ) : asset.riskLevel === 'مرتفع' ? (
                        <AlertTriangle className="w-3.5 h-3.5" />
                      ) : (
                        <CheckCircle2 className="w-3.5 h-3.5" />
                      )}
                      <span>{asset.riskLevel} ({asset.riskScore}%)</span>
                    </span>
                  </td>
                  <td className="py-3 px-3 whitespace-nowrap">
                    {asset.id.startsWith('ep-') || asset.id.startsWith('imp-') || asset.id.startsWith('csv-') ? (
                      <button
                        type="button"
                        onClick={() => setCustomEndpoints((prev) => prev.filter((x) => x.id !== asset.id))}
                        className="text-gray-400 hover:text-red-400 cursor-pointer"
                        title="حذف من الجرد"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    ) : (
                      <span className="text-[10px] text-gray-500">تلقائي</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
