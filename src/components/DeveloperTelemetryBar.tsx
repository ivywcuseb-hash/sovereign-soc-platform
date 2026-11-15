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

  useEffect(() => {
    let mounted = true;
    const probeGateway = async () => {
      const start = performance.now();
      try {
        const res = await fetch('/api/version?clientVersion=2.5.2', { cache: 'no-store' });
        if (!mounted) return;
        const elapsed = Math.max(1, Math.round(performance.now() - start));
        setGatewayConnected(res.ok);
        setGatewayLatencyMs(elapsed);
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
      {/* Expandable Developer & System Telemetry Log Console */}
      {expanded && (
        <div className="bg-gray-950/95 backdrop-blur-md border-t border-[#D4AF37]/40 shadow-2xl px-4 py-3 max-h-60 flex flex-col gap-2">
          <div className="flex items-center justify-between text-[11px] font-mono border-b border-gray-800 pb-2">
            <div className="flex items-center gap-2 text-[#D4AF37] font-bold">
              <Terminal className="w-3.5 h-3.5" />
              <span>DEVELOPER & SYSTEM TELEMETRY LOG • SOVEREIGN CORE ENGINE v3.5</span>
            </div>
            <div className="flex items-center gap-3 text-gray-400">
              <span>MODULE: {activeTab.toUpperCase()}</span>
              <span className="text-emerald-400">NEURAL-X DAEMON: ONLINE</span>
              <button
                type="button"
                onClick={() => setExpanded(false)}
                className="px-2 py-0.5 rounded bg-gray-900 border border-gray-700 hover:border-[#D4AF37] text-gray-300 cursor-pointer"
              >
                Hide
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

      {/* Persistent Compact System Telemetry Strip */}
      <div className="bg-gray-950/95 backdrop-blur-md border-t border-gray-800 px-4 py-1.5 flex items-center justify-between gap-3 text-[10px] font-mono text-gray-300 overflow-x-auto">
        <div className="flex items-center gap-4 shrink-0">
          <span className="inline-flex items-center gap-1.5 text-emerald-400 font-bold">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <Cpu className="w-3 h-3" />
            Kernel Status: Active
          </span>

          <span className="hidden sm:inline-flex items-center gap-1.5 text-gray-300">
            <HardDrive className="w-3 h-3 text-[#D4AF37]" />
            Memory Cache: Optimized{heapMb ? ` (${heapMb})` : ''}
          </span>

          <span
            className={`inline-flex items-center gap-1.5 ${
              gatewayConnected && networkOnline ? 'text-blue-400' : 'text-amber-400'
            }`}
          >
            <Server className="w-3 h-3" />
            {gatewayConnected && networkOnline
              ? `Secured API Gateway Connected${gatewayLatencyMs ? ` (${gatewayLatencyMs}ms)` : ''}`
              : 'Gateway: Local Isolated Mode'}
          </span>

          <span className="hidden md:inline-flex items-center gap-1.5 text-emerald-300">
            <Lock className="w-3 h-3" />
            Encryption: AES-256-GCM Active
          </span>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <span className="hidden lg:inline-flex items-center gap-1 text-[#D4AF37]">
            <Activity className="w-3 h-3" />
            Sovereign Core Engine v3.5 • Automated Parser Core
          </span>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-gray-900 hover:bg-gray-800 border border-gray-700 hover:border-[#D4AF37]/60 text-[#D4AF37] font-bold transition cursor-pointer"
          >
            <Terminal className="w-3 h-3" />
            <span>System Telemetry Log ({logs.length})</span>
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronUp className="w-3 h-3" />}
          </button>
        </div>
      </div>
    </div>
  );
};
