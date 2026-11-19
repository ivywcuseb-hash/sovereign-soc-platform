import React, { useEffect, useState } from 'react';
import {
  Activity,
  ChevronDown,
  ChevronUp,
  Cpu,
  HardDrive,
  Lock,
  Server,
  Terminal,
} from 'lucide-react';
import { apiUrl } from '../utils/apiBase';

export interface TelemetryLogEntry {
  id: string;
  timestamp: string;
  subsystem: 'KERNEL' | 'DAEMON' | 'CRYPTO' | 'GATEWAY' | 'PARSER';
  message: string;
  level: 'info' | 'ok' | 'warn';
}

interface DeveloperTelemetryBarProps {
  networkOnline: boolean;
  activeTab: string;
  logs: TelemetryLogEntry[];
}

export const DeveloperTelemetryBar: React.FC<DeveloperTelemetryBarProps> = ({
  networkOnline,
  activeTab,
  logs,
}) => {
  const [expanded, setExpanded] = useState(false);
  const [gatewayLatencyMs, setGatewayLatencyMs] = useState<number | null>(null);
  const [gatewayConnected, setGatewayConnected] = useState<boolean>(networkOnline);
  const [heapMb, setHeapMb] = useState<string | null>(null);
  const [securityAlertLevel, setSecurityAlertLevel] = useState<'NORMAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL'>('NORMAL');
  const [securityBlockedCount, setSecurityBlockedCount] = useState<number>(0);

  useEffect(() => {
    let mounted = true;
    const probeGateway = async () => {
      const start = performance.now();
      try {
        const [verRes, secRes] = await Promise.all([
          fetch(apiUrl('/api/version?clientVersion=2.5.2'), { cache: 'no-store' }),
          fetch(apiUrl('/api/security/status'), { cache: 'no-store' }).catch(() => null),
        ]);
        if (!mounted) return;
        const elapsed = Math.max(1, Math.round(performance.now() - start));
        setGatewayConnected(verRes.ok);
        setGatewayLatencyMs(elapsed);
        if (secRes && secRes.ok) {
          const secData = await secRes.json().catch(() => null);
          if (secData && secData.alertLevel) {
            setSecurityAlertLevel(secData.alertLevel);
            setSecurityBlockedCount(Number(secData.totalBlocked || 0));
          }
        }
      } catch {
        if (!mounted) return;
        setGatewayConnected(false);
        setGatewayLatencyMs(null);
      }

      const mem = (performance as any)?.memory;
      if (mem && typeof mem.usedJSHeapSize === 'number') {
        const mb = (mem.usedJSHeapSize / (1024 * 1024)).toFixed(1);
        setHeapMb(`${mb} MB`);
      }
    };

    void probeGateway();
    const timer = window.setInterval(probeGateway, 30000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [networkOnline]);

  return (
    <div className="fixed bottom-0 inset-x-0 z-30 no-print" dir="ltr">
      {/* Expandable System Event Log */}
      {expanded && (
        <div className="bg-gray-950/95 backdrop-blur-md border-t border-gray-800 px-4 py-3 max-h-60 flex flex-col gap-2">
          <div className="flex items-center justify-between text-[11px] font-mono border-b border-gray-800 pb-2">
            <div className="flex items-center gap-2 text-[#D4AF37] font-bold">
              <Terminal className="w-3.5 h-3.5" />
              <span>SYSTEM EVENT LOG · SOVEREIGN FORENSIC ENGINE</span>
            </div>
            <div className="flex items-center gap-3 text-gray-400">
              <span>TAB: {activeTab.toUpperCase()}</span>
              <span className={securityAlertLevel === 'CRITICAL' || securityAlertLevel === 'HIGH' ? 'text-red-400' : 'text-emerald-400'}>
                SECURITY: {securityAlertLevel} ({securityBlockedCount} BLOCKED)
              </span>
              <button
                type="button"
                onClick={() => setExpanded(false)}
                className="px-2 py-0.5 rounded bg-gray-900 border border-gray-700 hover:border-[#D4AF37] text-gray-300 cursor-pointer transition-colors"
              >
                إغلاق
              </button>
            </div>
          </div>

          <div className="overflow-y-auto space-y-1 font-mono text-[11px] pr-1">
            {logs.map((entry) => (
              <div
                key={entry.id}
                className="flex items-start gap-2.5 py-0.5 border-b border-gray-900/80 last:border-b-0"
              >
                <span className="text-gray-500 shrink-0">[{entry.timestamp}]</span>
                <span
                  className={`px-1.5 py-0 rounded text-[10px] font-bold shrink-0 ${
                    entry.subsystem === 'KERNEL'
                      ? 'bg-[#D4AF37]/15 text-[#D4AF37]'
                      : entry.subsystem === 'CRYPTO'
                      ? 'bg-emerald-500/15 text-emerald-400'
                      : entry.subsystem === 'GATEWAY'
                      ? 'bg-blue-500/15 text-blue-400'
                      : 'bg-purple-500/15 text-purple-300'
                  }`}
                >
                  {entry.subsystem}
                </span>
                <span
                  className={
                    entry.level === 'warn'
                      ? 'text-amber-300'
                      : entry.level === 'ok'
                      ? 'text-emerald-300'
                      : 'text-gray-300'
                  }
                >
                  {entry.message}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Persistent Compact System Bar */}
      <div className="bg-gray-950/95 backdrop-blur-md border-t border-gray-800 px-4 py-1.5 flex items-center justify-between gap-3 text-[10px] font-mono text-gray-300 overflow-x-auto">
        <div className="flex items-center gap-4 shrink-0">
          <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
            <Cpu className="w-3 h-3" />
            Session: Active
          </span>

          {heapMb && (
            <span className="hidden sm:inline-flex items-center gap-1.5 text-gray-400">
              <HardDrive className="w-3 h-3 text-[#D4AF37]" />
              Heap: {heapMb}
            </span>
          )}

          <span
            className={`inline-flex items-center gap-1.5 ${
              gatewayConnected && networkOnline ? 'text-blue-400' : 'text-amber-400'
            }`}
          >
            <Server className="w-3 h-3" />
            {gatewayConnected && networkOnline
              ? `API Gateway${gatewayLatencyMs ? ` (${gatewayLatencyMs}ms)` : ''}`
              : 'Local Mode (Offline)'}
          </span>

          <span className="hidden md:inline-flex items-center gap-1.5 text-gray-400">
            <Lock className="w-3 h-3 text-emerald-400" />
            WebCrypto SHA-256
          </span>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <span className="hidden lg:inline-flex items-center gap-1 text-gray-400">
            <Activity className="w-3 h-3 text-[#D4AF37]" />
            Defense: {securityAlertLevel}
          </span>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-gray-900 hover:bg-gray-800 border border-gray-800 hover:border-[#D4AF37]/60 text-[#D4AF37] font-bold transition-colors cursor-pointer"
          >
            <Terminal className="w-3 h-3" />
            <span>سجل النظام ({logs.length})</span>
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />}
          </button>
        </div>
      </div>
    </div>
  );
};
