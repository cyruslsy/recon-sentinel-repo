"use client";

import { useScanContext } from "@/lib/scan-context";
import { useState } from "react";

const PHASE_LABELS: Record<string, string> = {
  passive: "Passive",
  gate_1: "Gate 1",
  active: "Active",
  gate_2: "Gate 2",
  replan: "Re-plan",
  vuln: "Vuln",
  report: "Report",
  done: "Done",
};

const STATUS_COLORS: Record<string, string> = {
  running: "bg-sentinel-green",
  paused: "bg-sentinel-orange",
  completed: "bg-sentinel-accent",
  failed: "bg-sentinel-red",
  pending: "bg-sentinel-muted",
  cancelled: "bg-sentinel-muted",
};

export default function ScanSelector() {
  const { activeScan, recentScans, loading, setActiveScanId } = useScanContext();
  const [open, setOpen] = useState(false);

  if (loading && !activeScan) {
    return (
      <div className="mx-3 mt-3 p-3 rounded-lg bg-sentinel-card border border-sentinel-border animate-pulse">
        <div className="h-3 bg-sentinel-border rounded w-3/4 mb-2" />
        <div className="h-2 bg-sentinel-border rounded w-1/2" />
      </div>
    );
  }

  if (!activeScan && recentScans.length === 0) {
    return (
      <div className="mx-3 mt-3 p-3 rounded-lg bg-sentinel-card border border-sentinel-border">
        <p className="text-[10px] text-sentinel-muted text-center">No active scans</p>
      </div>
    );
  }

  return (
    <div className="mx-3 mt-3 relative">
      {/* Active scan card */}
      <button
        onClick={() => setOpen(!open)}
        aria-expanded={open}
        className="w-full text-left p-3 rounded-lg bg-sentinel-card border border-sentinel-border hover:border-sentinel-accent/40 transition-colors"
      >
        {activeScan ? (
          <>
            <div className="flex items-center gap-2 mb-1">
              <span className={`w-1.5 h-1.5 rounded-full ${STATUS_COLORS[activeScan.status] || "bg-sentinel-muted"}`} />
              <span className="text-xs font-medium text-sentinel-text truncate">
                {activeScan.target_value || activeScan.id.slice(0, 8)}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-[10px] text-sentinel-muted">
                {PHASE_LABELS[activeScan.phase] || activeScan.phase} · {activeScan.status}
              </span>
              <span className="text-[10px] text-sentinel-accent font-medium">
                {activeScan.total_findings} findings
              </span>
            </div>
          </>
        ) : (
          <p className="text-xs text-sentinel-muted">Select a scan…</p>
        )}
        <span className="absolute right-4 top-1/2 -translate-y-1/2 text-sentinel-muted text-[10px]">
          {open ? "▲" : "▼"}
        </span>
      </button>

      {/* Dropdown */}
      {open && (
        <div className="absolute z-50 mt-1 w-full bg-sentinel-surface border border-sentinel-border rounded-lg shadow-xl max-h-60 overflow-y-auto">
          {recentScans.length === 0 && (
            <p className="text-xs text-sentinel-muted p-3 text-center">No scans found</p>
          )}
          {recentScans.map((scan) => (
            <button
              key={scan.id}
              onClick={() => {
                setActiveScanId(scan.id);
                setOpen(false);
              }}
              className={`w-full text-left px-3 py-2 hover:bg-sentinel-hover transition-colors border-b border-sentinel-border/50 last:border-0 ${
                scan.id === activeScan?.id ? "bg-sentinel-accent/10" : ""
              }`}
            >
              <div className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${STATUS_COLORS[scan.status] || "bg-sentinel-muted"}`} />
                <span className="text-xs font-medium text-sentinel-text truncate">
                  {scan.target_value || scan.id.slice(0, 8)}
                </span>
                <span className="text-[9px] text-sentinel-muted ml-auto shrink-0">
                  {scan.total_findings}
                </span>
              </div>
              <div className="text-[10px] text-sentinel-muted ml-4 mt-0.5">
                {scan.profile} · {scan.status} · {PHASE_LABELS[scan.phase] || scan.phase}
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
