"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { Scan, HealthEvent } from "@/lib/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F59E0B",
  medium: "#3B82F6",
  low: "#22C55E",
  info: "#64748B",
};

function StatCard({ label, value, color, delta }: { label: string; value: string | number; color?: string; delta?: number }) {
  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
      <p className="text-xs text-sentinel-muted">{label}</p>
      <div className="flex items-end gap-2 mt-1">
        <p className="text-2xl font-semibold" style={color ? { color } : {}}>{value}</p>
        {delta !== undefined && delta !== 0 && (
          <span className={`text-xs font-medium pb-0.5 ${delta > 0 ? "text-sentinel-green" : "text-sentinel-red"}`}>
            {delta > 0 ? `↑${delta}` : `↓${Math.abs(delta)}`} since last
          </span>
        )}
      </div>
    </div>
  );
}

// Simple SVG donut chart
function SeverityDonut({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const radius = 40;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const segments = Object.entries(counts)
    .filter(([, v]) => v > 0)
    .map(([severity, count]) => {
      const pct = count / total;
      const dashLength = pct * circumference;
      const seg = { severity, count, pct, offset, dashLength };
      offset += dashLength;
      return seg;
    });

  return (
    <div className="flex items-center gap-4">
      <svg width="100" height="100" viewBox="0 0 100 100" className="shrink-0">
        {segments.map((seg) => (
          <circle
            key={seg.severity}
            cx="50" cy="50" r={radius}
            fill="none"
            stroke={SEVERITY_COLORS[seg.severity] || "#64748B"}
            strokeWidth="14"
            strokeDasharray={`${seg.dashLength} ${circumference - seg.dashLength}`}
            strokeDashoffset={-seg.offset}
            className="transition-all duration-500"
          />
        ))}
        <text x="50" y="48" textAnchor="middle" className="fill-sentinel-text text-lg font-semibold" fontSize="18">{total}</text>
        <text x="50" y="62" textAnchor="middle" className="fill-sentinel-muted" fontSize="9">findings</text>
      </svg>
      <div className="space-y-1">
        {segments.map((seg) => (
          <div key={seg.severity} className="flex items-center gap-2 text-xs">
            <span className="w-2.5 h-2.5 rounded-sm shrink-0" style={{ backgroundColor: SEVERITY_COLORS[seg.severity] }} />
            <span className="text-sentinel-muted capitalize w-14">{seg.severity}</span>
            <span className="font-medium">{seg.count}</span>
            <span className="text-sentinel-muted">({Math.round(seg.pct * 100)}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Mini Health Feed — last 5 events
function MiniHealthFeed({ events }: { events: HealthEvent[] }) {
  const EVENT_ICONS: Record<string, { icon: string; color: string }> = {
    anomaly_detected: { icon: "⚠", color: "text-sentinel-orange" },
    self_correction: { icon: "⟳", color: "text-sentinel-accent" },
    correction_success: { icon: "✓", color: "text-sentinel-green" },
    escalate_user: { icon: "!", color: "text-sentinel-red" },
  };

  if (events.length === 0) return null;

  return (
    <div>
      <div className="flex items-center justify-between mb-2">
        <p className="text-xs font-medium text-sentinel-muted">Recent Self-Corrections</p>
        <a href="/health" className="text-[10px] text-sentinel-accent hover:underline">View all →</a>
      </div>
      <div className="space-y-1.5">
        {events.slice(0, 5).map((e) => {
          const meta = EVENT_ICONS[e.event_type] || { icon: "ℹ", color: "text-sentinel-muted" };
          return (
            <div key={e.id} className="flex items-start gap-2 text-xs">
              <span className={`${meta.color} shrink-0 mt-0.5`}>{meta.icon}</span>
              <span className="text-sentinel-text/80 truncate flex-1">{e.detail}</span>
              <span className="text-sentinel-muted shrink-0">{new Date(e.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ScanRow({ scan, onClick }: { scan: Scan; onClick: () => void }) {
  const statusColor =
    scan.status === "completed" ? "text-sentinel-green" :
    scan.status === "running" ? "text-sentinel-accent" :
    scan.status === "paused" ? "text-sentinel-orange" :
    "text-sentinel-muted";

  return (
    <tr onClick={onClick} className="border-b border-sentinel-border/50 hover:bg-sentinel-hover/50 transition-colors cursor-pointer">
      <td className="py-3 px-4 text-sm font-mono text-sentinel-muted">{scan.target_value || scan.id?.slice(0, 8)}</td>
      <td className="py-3 px-4">
        <span className={`text-sm font-medium ${statusColor}`}>{scan.status}</span>
        <span className="text-xs text-sentinel-muted ml-2">{scan.phase}</span>
      </td>
      <td className="py-3 px-4 text-sm">{scan.total_findings}</td>
      <td className="py-3 px-4">
        {scan.critical_count > 0 && (
          <span className="text-xs bg-sentinel-red/20 text-sentinel-red px-1.5 py-0.5 rounded mr-1">{scan.critical_count}C</span>
        )}
        {scan.high_count > 0 && (
          <span className="text-xs bg-sentinel-orange/20 text-sentinel-orange px-1.5 py-0.5 rounded">{scan.high_count}H</span>
        )}
      </td>
      <td className="py-3 px-4 text-xs text-sentinel-muted">{scan.profile}</td>
    </tr>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [healthEvents, setHealthEvents] = useState<HealthEvent[]>([]);
  const [stats, setStats] = useState({ total: 0, running: 0, critical: 0, findings: 0 });
  const [severityCounts, setSeverityCounts] = useState<Record<string, number>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => { loadDashboard(); }, []);

  async function loadDashboard() {
    try {
      const scanList = await api.listScans("limit=10");
      setScans(scanList);

      const running = scanList.filter((s: Scan) => s.status === "running").length;
      const totalFindings = scanList.reduce((sum: number, s: Scan) => sum + (s.total_findings || 0), 0);
      const criticals = scanList.reduce((sum: number, s: Scan) => sum + (s.critical_count || 0), 0);

      setStats({ total: scanList.length, running, critical: criticals, findings: totalFindings });

      // Aggregate severity counts across recent scans
      const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const s of scanList) {
        counts.critical += s.critical_count || 0;
        counts.high += s.high_count || 0;
        counts.medium += s.medium_count || 0;
        counts.low += s.low_count || 0;
        counts.info += s.info_count || 0;
      }
      setSeverityCounts(counts);

      // Load health events from most recent running or completed scan
      const activeScan = scanList.find((s: Scan) => s.status === "running") || scanList[0];
      if (activeScan) {
        try {
          const events = await api.getHealthEvents(activeScan.id);
          setHealthEvents(events);
        } catch {}
      }
    } catch {} finally { setLoading(false); }
  }

  return (
    <AppLayout>
      <div className="max-w-7xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Dashboard</h1>
        <p className="text-sentinel-muted text-sm mb-4">Overview of your reconnaissance activity and findings</p>

        {/* Stat Cards */}
        <div className="grid grid-cols-5 gap-4 mb-6">
          <StatCard label="Total Scans" value={stats.total} />
          <StatCard label="Active Scans" value={stats.running} color="#3B82F6" />
          <StatCard label="Critical Findings" value={stats.critical} color="#EF4444" />
          <StatCard label="Total Findings" value={stats.findings} />
          <StatCard label="Subdomains" value={scans.reduce((s, sc) => s + (sc.subdomain_count || 0), 0)} />
        </div>

        {/* Middle Row: Donut + Health Feed */}
        <div className="grid grid-cols-2 gap-6 mb-6">
          {/* Severity Donut */}
          <div className="bg-sentinel-surface border border-sentinel-border rounded-lg p-5">
            <h2 className="text-sm font-medium mb-4">Severity Breakdown</h2>
            {stats.findings > 0 ? (
              <SeverityDonut counts={severityCounts} />
            ) : (
              <p className="text-sm text-sentinel-muted py-4">No findings yet.</p>
            )}
          </div>

          {/* Mini Health Feed */}
          <div className="bg-sentinel-surface border border-sentinel-border rounded-lg p-5">
            <h2 className="text-sm font-medium mb-4">Self-Correction Activity</h2>
            {healthEvents.length > 0 ? (
              <MiniHealthFeed events={healthEvents} />
            ) : (
              <p className="text-sm text-sentinel-muted py-4">No self-correction events yet. Launch a scan to see AI agents at work.</p>
            )}
          </div>
        </div>

        {/* Recent Scans */}
        <div className="bg-sentinel-surface border border-sentinel-border rounded-lg">
          <div className="px-4 py-3 border-b border-sentinel-border flex items-center justify-between">
            <h2 className="text-sm font-medium">Recent Scans</h2>
            <a href="/scans" className="text-xs text-sentinel-accent hover:underline">View all →</a>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-sentinel-border text-xs text-sentinel-muted">
                <th className="text-left py-2 px-4 font-medium">Target</th>
                <th className="text-left py-2 px-4 font-medium">Status</th>
                <th className="text-left py-2 px-4 font-medium">Findings</th>
                <th className="text-left py-2 px-4 font-medium">Severity</th>
                <th className="text-left py-2 px-4 font-medium">Profile</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-12 text-center">
                    <div className="space-y-3">
                      <p className="text-sentinel-muted text-sm">No scans yet.</p>
                      <button
                        onClick={() => router.push("/scans")}
                        className="bg-sentinel-accent text-white text-sm font-medium px-6 py-2 rounded hover:bg-sentinel-accent/90 transition-colors"
                      >
                        Launch Your First Scan
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                scans.map((scan) => (
                  <ScanRow key={scan.id} scan={scan} onClick={() => router.push(`/agents?scan_id=${scan.id}`)} />
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </AppLayout>
  );
}
