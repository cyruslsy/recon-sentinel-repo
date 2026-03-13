"use client";

import { useEffect, useState, useRef } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { Finding } from "@/lib/types";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-blue-500/20 text-blue-400",
  low: "bg-green-500/20 text-green-400",
  info: "bg-gray-500/20 text-gray-400",
};

export default function FindingsPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState({ severity: "", search: "", showFP: false });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const debounceRef = useRef<NodeJS.Timeout | null>(null);

  // Debounce search — only fire after 300ms of no typing
  useEffect(() => {
    if (!scanId) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => loadFindings(), 300);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [scanId, filter.severity, filter.search, filter.showFP]);

  async function loadFindings() {
    if (!scanId) return;
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (filter.severity) params.set("severity", filter.severity);
      if (filter.search) params.set("search", filter.search);
      if (!filter.showFP) params.set("is_false_positive", "false");
      setFindings(await api.listFindings(scanId, params.toString()));
    } catch {}
    setLoading(false);
  }

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function selectAll() {
    if (selected.size === findings.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(findings.map((f) => f.id)));
    }
  }

  async function handleBulkAction(action: string) {
    if (selected.size === 0) return;
    try {
      await api.bulkAction({ finding_ids: Array.from(selected), action });
      setSelected(new Set());
      loadFindings();
    } catch {}
  }

  return (
    <AppLayout>
      <div className="max-w-7xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Findings</h1>

        {/* Filters */}
        <div className="flex items-center gap-3 mb-4">
          <input
            type="text"
            placeholder="Search findings..."
            value={filter.search}
            onChange={(e) => setFilter((f) => ({ ...f, search: e.target.value }))}
            className="bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm w-64 focus:outline-none focus:border-sentinel-accent"
          />
          <select
            value={filter.severity}
            onChange={(e) => setFilter((f) => ({ ...f, severity: e.target.value }))}
            className="bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm focus:outline-none focus:border-sentinel-accent"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <label className="flex items-center gap-1.5 text-sm text-sentinel-muted cursor-pointer">
            <input
              type="checkbox"
              checked={filter.showFP}
              onChange={(e) => setFilter((f) => ({ ...f, showFP: e.target.checked }))}
              className="rounded"
            />
            Show false positives
          </label>

          {selected.size > 0 && (
            <div className="flex items-center gap-2 ml-auto">
              <span className="text-xs text-sentinel-muted">{selected.size} selected</span>
              <button
                onClick={() => handleBulkAction("mark_false_positive")}
                className="text-xs bg-sentinel-border hover:bg-sentinel-hover text-sentinel-text px-3 py-1 rounded"
              >
                Mark False Positive
              </button>
              <button
                onClick={() => handleBulkAction("add_tag")}
                className="text-xs bg-sentinel-border hover:bg-sentinel-hover text-sentinel-text px-3 py-1 rounded"
              >
                Add Tag
              </button>
            </div>
          )}
        </div>

        {/* Table */}
        <div className="bg-sentinel-surface border border-sentinel-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-sentinel-border text-xs text-sentinel-muted">
                <th className="py-2 px-3 w-8">
                  <input type="checkbox" onChange={selectAll} checked={selected.size === findings.length && findings.length > 0} />
                </th>
                <th className="text-left py-2 px-3 font-medium">Severity</th>
                <th className="text-left py-2 px-3 font-medium">Type</th>
                <th className="text-left py-2 px-3 font-medium">Value</th>
                <th className="text-left py-2 px-3 font-medium">Detail</th>
                <th className="text-left py-2 px-3 font-medium">MITRE</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
                <tr
                  key={f.id}
                  className={`border-b border-sentinel-border/30 hover:bg-sentinel-hover/50 transition-colors ${
                    f.is_false_positive ? "opacity-40" : ""
                  }`}
                >
                  <td className="py-2.5 px-3">
                    <input
                      type="checkbox"
                      checked={selected.has(f.id)}
                      onChange={() => toggleSelect(f.id)}
                    />
                  </td>
                  <td className="py-2.5 px-3">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${SEVERITY_BADGE[f.severity] || ""}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-xs text-sentinel-muted">{f.finding_type}</td>
                  <td className="py-2.5 px-3 text-sm font-mono truncate max-w-[280px]">{f.value}</td>
                  <td className="py-2.5 px-3 text-xs text-sentinel-muted truncate max-w-[300px]">{f.detail}</td>
                  <td className="py-2.5 px-3">
                    {(f.mitre_technique_ids || []).map((t: string) => (
                      <span key={t} className="text-[10px] bg-sentinel-purple/20 text-sentinel-purple px-1.5 py-0.5 rounded mr-1">
                        {t}
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-sentinel-muted text-sm">
                    {loading ? "Loading..." : "No findings match the current filters."}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </AppLayout>
  );
}
