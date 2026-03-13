"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";

interface DiffSummary {
  id: string;
  scan_id: string;
  prev_scan_id: string;
  new_findings_count: number;
  removed_findings_count: number;
  new_subdomains: number;
  removed_subdomains: number;
  new_ports: number;
  closed_ports: number;
  new_vulns: number;
  resolved_vulns: number;
  new_credentials: number;
  ai_diff_summary: string | null;
  computed_at: string;
}

interface DiffItem {
  id: string;
  change_type: "new" | "removed" | "changed";
  finding_type: string;
  value: string;
  detail: string | null;
  severity: string | null;
}

const CHANGE_STYLES = {
  new: { bg: "bg-green-500/10 border-green-500/30", text: "text-green-400", label: "NEW" },
  removed: { bg: "bg-red-500/10 border-red-500/30", text: "text-red-400", label: "REMOVED" },
  changed: { bg: "bg-yellow-500/10 border-yellow-500/30", text: "text-yellow-400", label: "CHANGED" },
};

export default function HistoryPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";
  const [scans, setScans] = useState<Scan[]>([]);
  const [diff, setDiff] = useState<DiffSummary | null>(null);
  const [items, setItems] = useState<DiffItem[]>([]);
  const [filter, setFilter] = useState<"all" | "new" | "removed" | "changed">("all");
  const [loading, setLoading] = useState(false);
  const [computing, setComputing] = useState(false);
  const [selectedScan, setSelectedScan] = useState(scanId);
  const [prevScan, setPrevScan] = useState("");

  useEffect(() => { loadScans(); }, []);
  useEffect(() => { if (selectedScan) loadDiff(); }, [selectedScan]);

  async function loadScans() {
    try {
      setScans(await api.listScans("limit=50"));
    } catch {}
  }

  async function loadDiff() {
    if (!selectedScan) return;
    setLoading(true);
    try {
      const d = await api.getDiff(selectedScan) as DiffSummary | null;
      if (d) {
        setDiff(d);
        setPrevScan(d.prev_scan_id);
        // Load diff items
        const diffItems = await api.getDiffItems(d.id) as DiffItem[];
        setItems(diffItems);
      } else {
        setDiff(null);
        setItems([]);
      }
    } catch {}
    setLoading(false);
  }

  async function triggerCompute() {
    if (!selectedScan || !prevScan) return;
    setComputing(true);
    try {
      await api.computeDiff(selectedScan, prevScan);
      // Poll for completion
      setTimeout(loadDiff, 3000);
    } catch {}
    setComputing(false);
  }

  const filtered = filter === "all" ? items : items.filter((i) => i.change_type === filter);
  const newCount = items.filter((i) => i.change_type === "new").length;
  const removedCount = items.filter((i) => i.change_type === "removed").length;
  const changedCount = items.filter((i) => i.change_type === "changed").length;

  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Scan History & Diff</h1>

        {/* Scan selector */}
        <div className="flex gap-3 mb-6">
          <select
            value={selectedScan}
            onChange={(e) => setSelectedScan(e.target.value)}
            className="flex-1 bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm"
          >
            <option value="">Select a scan...</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id.slice(0, 8)} — {s.status} — {s.total_findings} findings
              </option>
            ))}
          </select>
          {!diff && selectedScan && (
            <>
              <select
                value={prevScan}
                onChange={(e) => setPrevScan(e.target.value)}
                className="flex-1 bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm"
              >
                <option value="">Compare against...</option>
                {scans.filter((s) => s.id !== selectedScan).map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id.slice(0, 8)} — {s.total_findings} findings
                  </option>
                ))}
              </select>
              <button
                onClick={triggerCompute}
                disabled={computing || !prevScan}
                className="bg-sentinel-accent text-white text-sm px-4 py-2 rounded disabled:opacity-50"
              >
                {computing ? "Computing..." : "Compute Diff"}
              </button>
            </>
          )}
        </div>

        {loading ? (
          <p className="text-sentinel-muted text-sm py-12 text-center animate-pulse">Loading diff...</p>
        ) : !diff ? (
          <p className="text-sentinel-muted text-sm py-12 text-center">
            {selectedScan ? "No diff available. Select a previous scan and click Compute Diff." : "Select a scan to view its diff."}
          </p>
        ) : (
          <>
            {/* AI Summary */}
            {diff.ai_diff_summary && (
              <div className="bg-sentinel-accent/10 border border-sentinel-accent/30 rounded-lg p-4 mb-6">
                <p className="text-xs text-sentinel-accent font-medium mb-1">AI Diff Summary</p>
                <div
                  className="text-sm prose prose-invert prose-sm max-w-none [&>p]:mb-1"
                  dangerouslySetInnerHTML={{
                    __html: (() => {
                      // Sanitize: strip ALL HTML tags first, then apply safe markdown transforms
                      const sanitized = diff.ai_diff_summary
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")
                        .replace(/"/g, "&quot;");
                      return sanitized
                        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
                        .replace(/\n- /g, "<br/>• ")
                        .replace(/\n/g, "<br/>");
                    })(),
                  }}
                />
              </div>
            )}

            {/* Stats */}
            <div className="grid grid-cols-6 gap-3 mb-6">
              <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-3 text-center">
                <p className="text-lg font-semibold text-green-400">+{diff.new_findings_count}</p>
                <p className="text-[10px] text-sentinel-muted">New Findings</p>
              </div>
              <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-3 text-center">
                <p className="text-lg font-semibold text-red-400">-{diff.removed_findings_count}</p>
                <p className="text-[10px] text-sentinel-muted">Removed</p>
              </div>
              <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-3 text-center">
                <p className="text-lg font-semibold text-green-400">+{diff.new_subdomains}</p>
                <p className="text-[10px] text-sentinel-muted">Subdomains</p>
              </div>
              <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-3 text-center">
                <p className="text-lg font-semibold text-green-400">+{diff.new_ports}</p>
                <p className="text-[10px] text-sentinel-muted">Ports</p>
              </div>
              <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-3 text-center">
                <p className="text-lg font-semibold text-green-400">+{diff.new_vulns}</p>
                <p className="text-[10px] text-sentinel-muted">New Vulns</p>
              </div>
              <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-3 text-center">
                <p className="text-lg font-semibold text-sentinel-green">{diff.resolved_vulns}</p>
                <p className="text-[10px] text-sentinel-muted">Resolved</p>
              </div>
            </div>

            {/* Filter tabs */}
            <div className="flex gap-1 mb-4 bg-sentinel-surface rounded-lg p-1 w-fit">
              {([["all", `All (${items.length})`], ["new", `New (${newCount})`], ["removed", `Removed (${removedCount})`], ["changed", `Changed (${changedCount})`]] as const).map(([key, label]) => (
                <button key={key} onClick={() => setFilter(key as typeof filter)}
                  className={`px-3 py-1 rounded text-xs font-medium ${filter === key ? "bg-sentinel-card text-sentinel-text" : "text-sentinel-muted"}`}>
                  {label}
                </button>
              ))}
            </div>

            {/* Diff Items */}
            <div className="space-y-2">
              {filtered.map((item) => {
                const style = CHANGE_STYLES[item.change_type];
                return (
                  <div key={item.id} className={`border rounded-lg p-3 ${style.bg}`}>
                    <div className="flex items-center gap-3">
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${style.text} bg-black/20`}>
                        {style.label}
                      </span>
                      {item.severity && (
                        <span className="text-[10px] text-sentinel-muted">{item.severity}</span>
                      )}
                      <span className="text-[10px] text-sentinel-muted">{item.finding_type}</span>
                    </div>
                    <p className="text-sm font-mono mt-1">{item.value}</p>
                    {item.detail && (
                      <p className="text-xs text-sentinel-muted mt-1 truncate">{item.detail}</p>
                    )}
                  </div>
                );
              })}
              {filtered.length === 0 && (
                <p className="text-sentinel-muted text-sm py-8 text-center">No changes in this category.</p>
              )}
            </div>
          </>
        )}
      </div>
    </AppLayout>
  );
}
