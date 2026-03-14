"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { Target, Project, Scan } from "@/lib/types";

interface TargetWithScans extends Target {
  scans: Scan[];
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  lastScanDate: string | null;
  lastScanStatus: string | null;
}

export default function TargetsPage() {
  const router = useRouter();
  const [targets, setTargets] = useState<TargetWithScans[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedTarget, setExpandedTarget] = useState<string | null>(null);

  useEffect(() => { loadTargets(); }, []);

  async function loadTargets() {
    try {
      const projects = await api.listProjects();
      const allScans = await api.listScans("limit=100");
      const allTargets: TargetWithScans[] = [];

      for (const project of projects) {
        const projectTargets = await api.listTargets(project.id);
        for (const target of projectTargets) {
          const targetScans = allScans
            .filter((s: Scan) => s.target_id === target.id)
            .sort((a: Scan, b: Scan) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

          allTargets.push({
            ...target,
            scans: targetScans,
            totalFindings: targetScans.reduce((sum: number, s: Scan) => sum + (s.total_findings || 0), 0),
            criticalCount: targetScans.reduce((sum: number, s: Scan) => sum + (s.critical_count || 0), 0),
            highCount: targetScans.reduce((sum: number, s: Scan) => sum + (s.high_count || 0), 0),
            lastScanDate: targetScans[0]?.created_at || null,
            lastScanStatus: targetScans[0]?.status || null,
          });
        }
      }

      // Sort by most recent scan
      allTargets.sort((a, b) => {
        if (!a.lastScanDate && !b.lastScanDate) return 0;
        if (!a.lastScanDate) return 1;
        if (!b.lastScanDate) return -1;
        return new Date(b.lastScanDate).getTime() - new Date(a.lastScanDate).getTime();
      });

      setTargets(allTargets);
    } catch {} finally { setLoading(false); }
  }

  function timeAgo(dateStr: string): string {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  }

  const statusColor = (s: string | null) =>
    s === "completed" ? "text-sentinel-green" :
    s === "running" ? "text-sentinel-accent" :
    s === "paused" ? "text-sentinel-orange" :
    s === "failed" ? "text-sentinel-red" :
    "text-sentinel-muted";

  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-semibold">Targets</h1>
            <p className="text-sm text-sentinel-muted mt-0.5">{targets.length} target{targets.length !== 1 ? "s" : ""} across all projects</p>
          </div>
          <button
            onClick={() => router.push("/scans")}
            className="bg-sentinel-accent hover:bg-sentinel-accent/90 text-white text-sm font-medium px-4 py-2 rounded transition-colors"
          >
            + New Scan
          </button>
        </div>

        {loading ? (
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="h-24 bg-sentinel-card border border-sentinel-border rounded-lg animate-pulse" />
            ))}
          </div>
        ) : targets.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 gap-4">
            <div className="text-4xl">🎯</div>
            <p className="text-sentinel-muted text-sm">No targets yet. Launch a scan to add your first target.</p>
            <button
              onClick={() => router.push("/scans")}
              className="bg-sentinel-accent text-white text-sm px-6 py-2 rounded hover:bg-sentinel-accent/90"
            >
              Launch Your First Scan
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {targets.map((target) => {
              const isExpanded = expandedTarget === target.id;
              return (
                <div key={target.id} className="bg-sentinel-surface border border-sentinel-border rounded-lg overflow-hidden">
                  {/* Target Card */}
                  <button
                    onClick={() => setExpandedTarget(isExpanded ? null : target.id)}
                    className="w-full text-left p-4 hover:bg-sentinel-hover/30 transition-colors"
                    aria-expanded={isExpanded}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-8 h-8 rounded-lg bg-sentinel-accent/10 flex items-center justify-center text-sentinel-accent text-sm font-medium shrink-0">
                          {target.input_type === "domain" ? "🌐" : target.input_type === "ip" ? "🔢" : "📦"}
                        </div>
                        <div className="min-w-0">
                          <p className="text-sm font-semibold font-mono truncate">{target.target_value}</p>
                          <p className="text-xs text-sentinel-muted mt-0.5">
                            {target.scans.length} scan{target.scans.length !== 1 ? "s" : ""}
                            {target.lastScanDate && ` · last ${timeAgo(target.lastScanDate)}`}
                            {target.lastScanStatus && (
                              <span className={`ml-1 ${statusColor(target.lastScanStatus)}`}>
                                · {target.lastScanStatus}
                              </span>
                            )}
                          </p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3 shrink-0">
                        {/* Severity summary */}
                        <div className="flex gap-1.5">
                          {target.criticalCount > 0 && (
                            <span className="text-xs bg-sentinel-red/20 text-sentinel-red px-2 py-0.5 rounded">{target.criticalCount} critical</span>
                          )}
                          {target.highCount > 0 && (
                            <span className="text-xs bg-sentinel-orange/20 text-sentinel-orange px-2 py-0.5 rounded">{target.highCount} high</span>
                          )}
                          {target.totalFindings > 0 && target.criticalCount === 0 && target.highCount === 0 && (
                            <span className="text-xs text-sentinel-muted">{target.totalFindings} findings</span>
                          )}
                        </div>
                        <span className="text-sentinel-muted text-xs">{isExpanded ? "▲" : "▼"}</span>
                      </div>
                    </div>
                  </button>

                  {/* Expanded: Scan list */}
                  {isExpanded && (
                    <div className="border-t border-sentinel-border">
                      {target.scans.length === 0 ? (
                        <p className="text-sm text-sentinel-muted py-6 text-center">No scans for this target yet.</p>
                      ) : (
                        <div className="divide-y divide-sentinel-border/30">
                          {target.scans.map((scan) => (
                            <button
                              key={scan.id}
                              onClick={() => router.push(`/agents?scan_id=${scan.id}`)}
                              className="w-full text-left px-4 py-3 hover:bg-sentinel-hover/50 transition-colors flex items-center justify-between"
                            >
                              <div className="flex items-center gap-3">
                                <span className={`text-xs font-medium ${statusColor(scan.status)}`}>
                                  {scan.status}
                                </span>
                                <span className="text-xs text-sentinel-muted">{scan.profile}</span>
                                <span className="text-xs text-sentinel-muted">{scan.phase}</span>
                              </div>
                              <div className="flex items-center gap-3">
                                <span className="text-xs">{scan.total_findings} findings</span>
                                {scan.critical_count > 0 && (
                                  <span className="text-[10px] bg-sentinel-red/20 text-sentinel-red px-1.5 py-0.5 rounded">{scan.critical_count}C</span>
                                )}
                                <span className="text-[10px] text-sentinel-muted">
                                  {new Date(scan.created_at).toLocaleDateString()}
                                </span>
                              </div>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
