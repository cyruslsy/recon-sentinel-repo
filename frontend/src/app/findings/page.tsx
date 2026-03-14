"use client";

import { useEffect, useState, useRef, useCallback , Suspense } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { Finding, FindingSeverity, VerificationStatus } from "@/lib/types";

const SEVERITY_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400",
  high: "bg-orange-500/20 text-orange-400",
  medium: "bg-blue-500/20 text-blue-400",
  low: "bg-green-500/20 text-green-400",
  info: "bg-gray-500/20 text-gray-400",
};

const SEVERITY_ICON: Record<string, string> = {
  critical: "▲ ",
  high: "◆ ",
  medium: "● ",
  low: "○ ",
  info: "— ",
};

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const VERIFICATION_BADGE: Record<string, { label: string; color: string }> = {
  unverified: { label: "Unverified", color: "text-sentinel-muted bg-sentinel-surface" },
  confirmed: { label: "Confirmed", color: "text-sentinel-green bg-sentinel-green/10" },
  false_positive: { label: "False Positive", color: "text-sentinel-muted bg-sentinel-border/50 line-through" },
  disputed: { label: "Disputed", color: "text-sentinel-orange bg-sentinel-orange/10" },
  remediated: { label: "Remediated", color: "text-sentinel-accent bg-sentinel-accent/10" },
};

type SortField = "severity" | "finding_type" | "value" | "created_at";
type SortDir = "asc" | "desc";
const PAGE_SIZE = 50;

// ─── Detail Slide-Over Panel ─────────────────────────────────────────

function FindingDetail({
  finding,
  onClose,
  onUpdate,
}: {
  finding: Finding;
  onClose: () => void;
  onUpdate: () => void;
}) {
  const [retesting, setRetesting] = useState(false);
  const [triage, setTriage] = useState({
    verification_status: finding.verification_status || "unverified",
    severity_override: finding.severity_override || "",
    severity_override_reason: finding.severity_override_reason || "",
  });
  const [saving, setSaving] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);

  // Close on Escape
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [onClose]);

  // Focus trap
  useEffect(() => {
    panelRef.current?.focus();
  }, []);

  async function handleRetest() {
    setRetesting(true);
    try {
      await api.retestFinding(finding.id);
    } catch {}
    setRetesting(false);
  }

  async function handleSaveTriage() {
    setSaving(true);
    try {
      await api.updateFinding(finding.id, {
        verification_status: triage.verification_status,
        severity_override: (triage.severity_override || null) as any,
        severity_override_reason: triage.severity_override_reason || null,
      });
      onUpdate();
    } catch {}
    setSaving(false);
  }

  const vs = VERIFICATION_BADGE[finding.verification_status || "unverified"] || VERIFICATION_BADGE.unverified;
  const effectiveSeverity = finding.severity_override || finding.severity;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/40 z-40" onClick={onClose} aria-hidden />

      {/* Panel */}
      <div
        ref={panelRef}
        tabIndex={-1}
        role="dialog"
        aria-label={`Finding detail: ${finding.value}`}
        className="fixed right-0 top-0 h-full w-[480px] max-w-[90vw] bg-sentinel-surface border-l border-sentinel-border z-50 overflow-y-auto shadow-2xl"
      >
        {/* Header */}
        <div className="sticky top-0 bg-sentinel-surface border-b border-sentinel-border px-5 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-2 min-w-0">
            <span className={`text-xs px-2 py-0.5 rounded font-medium ${SEVERITY_BADGE[effectiveSeverity] || ""}`}>
              {SEVERITY_ICON[effectiveSeverity] || ""}{effectiveSeverity}
            </span>
            {finding.severity_override && (
              <span className="text-[10px] text-sentinel-muted">(was {finding.severity})</span>
            )}
          </div>
          <button onClick={onClose} className="text-sentinel-muted hover:text-sentinel-text text-lg" aria-label="Close detail panel">✕</button>
        </div>

        <div className="px-5 py-4 space-y-5">
          {/* Value */}
          <div>
            <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Value</p>
            <p className="text-sm font-mono break-all bg-sentinel-bg rounded p-2 border border-sentinel-border">{finding.value}</p>
          </div>

          {/* Detail / Evidence */}
          <div>
            <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Detail / Evidence</p>
            <p className="text-sm text-sentinel-text/90 whitespace-pre-wrap">{finding.detail}</p>
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Type</p>
              <p className="text-sm">{finding.finding_type.replace(/_/g, " ")}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Confidence</p>
              <p className="text-sm">{finding.confidence !== null ? `${finding.confidence}%` : "—"}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Fingerprint</p>
              <p className="text-xs font-mono text-sentinel-muted truncate">{finding.fingerprint || "—"}</p>
            </div>
            <div>
              <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Discovered</p>
              <p className="text-sm">{new Date(finding.created_at).toLocaleString()}</p>
            </div>
          </div>

          {/* MITRE ATT&CK */}
          {finding.mitre_technique_ids?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">MITRE ATT&CK</p>
              <div className="flex flex-wrap gap-1.5">
                {finding.mitre_technique_ids.map((t) => (
                  <a
                    key={t}
                    href={`/mitre?scan_id=${finding.scan_id}&technique=${t}`}
                    className="text-[11px] bg-sentinel-purple/20 text-sentinel-purple px-2 py-0.5 rounded hover:bg-sentinel-purple/30 transition-colors"
                  >
                    {t}
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* Tags */}
          {finding.tags?.length > 0 && (
            <div>
              <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Tags</p>
              <div className="flex flex-wrap gap-1.5">
                {finding.tags.map((t) => (
                  <span key={t} className="text-[11px] bg-sentinel-accent/10 text-sentinel-accent px-2 py-0.5 rounded">{t}</span>
                ))}
              </div>
            </div>
          )}

          {/* Verification & Triage */}
          <div className="border-t border-sentinel-border pt-4">
            <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-3">Triage</p>

            <div className="space-y-3">
              <div>
                <label className="text-xs text-sentinel-muted block mb-1">Verification Status</label>
                <select
                  value={triage.verification_status}
                  onChange={(e) => setTriage((t) => ({ ...t, verification_status: e.target.value as VerificationStatus }))}
                  className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm"
                >
                  <option value="unverified">Unverified</option>
                  <option value="confirmed">Confirmed</option>
                  <option value="false_positive">False Positive</option>
                  <option value="disputed">Disputed</option>
                  <option value="remediated">Remediated</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-sentinel-muted block mb-1">Severity Override</label>
                <select
                  value={triage.severity_override}
                  onChange={(e) => setTriage((t) => ({ ...t, severity_override: e.target.value }))}
                  className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm"
                >
                  <option value="">No override (use {finding.severity})</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>

              {triage.severity_override && (
                <div>
                  <label className="text-xs text-sentinel-muted block mb-1">Override Reason</label>
                  <input
                    value={triage.severity_override_reason}
                    onChange={(e) => setTriage((t) => ({ ...t, severity_override_reason: e.target.value }))}
                    placeholder="e.g. Behind WAF, requires auth, test environment"
                    className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm"
                  />
                </div>
              )}

              <div className="flex gap-2">
                <button
                  onClick={handleSaveTriage}
                  disabled={saving}
                  className="bg-sentinel-accent text-white text-xs px-4 py-1.5 rounded disabled:opacity-50"
                >
                  {saving ? "Saving..." : "Save Triage"}
                </button>
                <button
                  onClick={handleRetest}
                  disabled={retesting}
                  className="bg-sentinel-green/10 text-sentinel-green text-xs px-4 py-1.5 rounded border border-sentinel-green/30 disabled:opacity-50"
                >
                  {retesting ? "Queuing..." : "⟳ Retest"}
                </button>
              </div>
            </div>
          </div>

          {/* User Notes */}
          {finding.user_notes && (
            <div>
              <p className="text-[10px] uppercase text-sentinel-muted tracking-wider mb-1">Notes</p>
              <p className="text-sm text-sentinel-text/80 whitespace-pre-wrap">{finding.user_notes}</p>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────

function FindingsPageInner() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";
  const [findings, setFindings] = useState<Finding[]>([]);
  const [filter, setFilter] = useState({ severity: "", search: "", showFP: false });
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null);
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [page, setPage] = useState(0);
  const debounceRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!scanId) return;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => { setPage(0); loadFindings(); }, 300);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [scanId, filter.severity, filter.search, filter.showFP]);

  const loadFindings = useCallback(async () => {
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
  }, [scanId, filter]);

  // Sort
  const sorted = [...findings].sort((a, b) => {
    let cmp = 0;
    if (sortField === "severity") {
      cmp = (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5);
    } else if (sortField === "finding_type") {
      cmp = a.finding_type.localeCompare(b.finding_type);
    } else if (sortField === "value") {
      cmp = a.value.localeCompare(b.value);
    } else if (sortField === "created_at") {
      cmp = new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
    }
    return sortDir === "asc" ? cmp : -cmp;
  });

  // Paginate
  const totalPages = Math.ceil(sorted.length / PAGE_SIZE);
  const paginated = sorted.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  function sortArrow(field: SortField) {
    if (sortField !== field) return " ↕";
    return sortDir === "asc" ? " ↑" : " ↓";
  }

  function toggleSelect(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function selectAll() {
    if (selected.size === paginated.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(paginated.map((f) => f.id)));
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

  function handleExport() {
    const url = `/api/v1/findings/export/csv?scan_id=${scanId}${filter.severity ? `&severity=${filter.severity}` : ""}`;
    window.open(url, "_blank");
  }

  return (
    <AppLayout>
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold">Findings</h1>
          {/* Export */}
          {findings.length > 0 && (
            <div className="flex gap-2">
              <button
                onClick={() => handleExport()}
                className="text-xs bg-sentinel-surface border border-sentinel-border px-3 py-1.5 rounded hover:border-sentinel-accent/50 transition-colors"
              >
                ↓ Export CSV
              </button>
            </div>
          )}
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 mb-4 flex-wrap">
          <input
            type="text"
            aria-label="Search findings" placeholder="Search findings..."
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

        {/* Pagination header */}
        {findings.length > 0 && (
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs text-sentinel-muted">
              Showing {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, sorted.length)} of {sorted.length} findings
            </p>
            {totalPages > 1 && (
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPage((p) => Math.max(0, p - 1))}
                  disabled={page === 0}
                  className="text-xs px-2 py-1 rounded bg-sentinel-surface border border-sentinel-border disabled:opacity-30 hover:border-sentinel-accent/50"
                >
                  ← Prev
                </button>
                <span className="text-xs text-sentinel-muted px-2">
                  Page {page + 1} of {totalPages}
                </span>
                <button
                  onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                  disabled={page >= totalPages - 1}
                  className="text-xs px-2 py-1 rounded bg-sentinel-surface border border-sentinel-border disabled:opacity-30 hover:border-sentinel-accent/50"
                >
                  Next →
                </button>
              </div>
            )}
          </div>
        )}

        {/* Table */}
        <div className="bg-sentinel-surface border border-sentinel-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-sentinel-border text-xs text-sentinel-muted">
                <th className="py-2 px-3 w-8">
                  <input type="checkbox" onChange={selectAll} checked={selected.size === paginated.length && paginated.length > 0} />
                </th>
                <th className="text-left py-2 px-3 font-medium cursor-pointer hover:text-sentinel-text select-none" onClick={() => handleSort("severity")}>
                  Severity{sortArrow("severity")}
                </th>
                <th className="text-left py-2 px-3 font-medium cursor-pointer hover:text-sentinel-text select-none" onClick={() => handleSort("finding_type")}>
                  Type{sortArrow("finding_type")}
                </th>
                <th className="text-left py-2 px-3 font-medium cursor-pointer hover:text-sentinel-text select-none" onClick={() => handleSort("value")}>
                  Value{sortArrow("value")}
                </th>
                <th className="text-left py-2 px-3 font-medium">Status</th>
                <th className="text-left py-2 px-3 font-medium">MITRE</th>
              </tr>
            </thead>
            <tbody>
              {paginated.map((f) => {
                const vs = VERIFICATION_BADGE[f.verification_status || "unverified"] || VERIFICATION_BADGE.unverified;
                return (
                  <tr
                    key={f.id}
                    onClick={() => setDetailFinding(f)}
                    className={`border-b border-sentinel-border/30 hover:bg-sentinel-hover/50 transition-colors cursor-pointer ${
                      f.is_false_positive ? "opacity-40" : ""
                    }`}
                  >
                    <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={selected.has(f.id)}
                        onChange={() => toggleSelect(f.id)}
                      />
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`text-xs px-2 py-0.5 rounded font-medium ${SEVERITY_BADGE[f.severity_override || f.severity] || ""}`}>
                        {SEVERITY_ICON[f.severity_override || f.severity] || ""}{f.severity_override || f.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-xs text-sentinel-muted">{f.finding_type.replace(/_/g, " ")}</td>
                    <td className="py-2.5 px-3 text-sm font-mono truncate max-w-[320px]" title={f.value}>{f.value}</td>
                    <td className="py-2.5 px-3">
                      <span className={`text-[10px] px-1.5 py-0.5 rounded ${vs.color}`}>{vs.label}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      {(f.mitre_technique_ids || []).slice(0, 2).map((t: string) => (
                        <span key={t} className="text-[10px] bg-sentinel-purple/20 text-sentinel-purple px-1.5 py-0.5 rounded mr-1">
                          {t}
                        </span>
                      ))}
                      {(f.mitre_technique_ids || []).length > 2 && (
                        <span className="text-[10px] text-sentinel-muted">+{f.mitre_technique_ids.length - 2}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
              {findings.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-12 text-center text-sentinel-muted text-sm">
                    {loading ? (
                      <span className="animate-pulse">Loading findings...</span>
                    ) : !scanId ? (
                      "Select a scan to view findings."
                    ) : (
                      "No findings match the current filters."
                    )}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Bottom pagination */}
        {totalPages > 1 && (
          <div className="flex justify-center mt-4">
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                className="text-xs px-2 py-1 rounded bg-sentinel-surface border border-sentinel-border disabled:opacity-30"
              >
                ←
              </button>
              {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
                const pageNum = totalPages <= 7 ? i : (page < 3 ? i : page > totalPages - 4 ? totalPages - 7 + i : page - 3 + i);
                return (
                  <button
                    key={pageNum}
                    onClick={() => setPage(pageNum)}
                    className={`text-xs px-2.5 py-1 rounded ${page === pageNum ? "bg-sentinel-accent text-white" : "bg-sentinel-surface border border-sentinel-border text-sentinel-muted hover:text-sentinel-text"}`}
                  >
                    {pageNum + 1}
                  </button>
                );
              })}
              <button
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="text-xs px-2 py-1 rounded bg-sentinel-surface border border-sentinel-border disabled:opacity-30"
              >
                →
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Slide-Over Detail Panel */}
      {detailFinding && (
        <FindingDetail
          finding={detailFinding}
          onClose={() => setDetailFinding(null)}
          onUpdate={() => { loadFindings(); setDetailFinding(null); }}
        />
      )}
    </AppLayout>
  );
}

export default function FindingsPage() {
  return (<Suspense fallback={<div className="p-8 text-center text-sentinel-muted">Loading...</div>}><FindingsPageInner /></Suspense>);
}
