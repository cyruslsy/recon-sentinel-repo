"use client";

import { useEffect, useState } from "react";
import AppLayout from "@/components/AppLayout";
import { fetcher } from "@/lib/api";

export default function ReportsPage() {
  const [reports, setReports] = useState<any[]>([]);
  const [scans, setScans] = useState<any[]>([]);
  const [generating, setGenerating] = useState(false);
  const [selectedScan, setSelectedScan] = useState("");
  const [template, setTemplate] = useState("full");

  useEffect(() => { loadData(); }, []);

  async function loadData() {
    try {
      setReports(await fetcher("/reports"));
      setScans(await fetcher("/scans?limit=20"));
    } catch {}
  }

  async function handleGenerate(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedScan) return;
    setGenerating(true);
    try {
      await fetch("/api/v1/reports", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ scan_id: selectedScan, template, format: "json" }),
      });
      setTimeout(loadData, 2000); // Refresh after generation starts
    } catch {}
    setGenerating(false);
  }

  return (
    <AppLayout>
      <div className="max-w-5xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Reports</h1>

        {/* Generate Form */}
        <form onSubmit={handleGenerate} className="bg-sentinel-surface border border-sentinel-border rounded-lg p-5 mb-6">
          <h2 className="text-sm font-medium mb-3">Generate New Report</h2>
          <div className="flex gap-3">
            <select value={selectedScan} onChange={(e) => setSelectedScan(e.target.value)}
              className="flex-1 bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm">
              <option value="">Select a scan...</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>{s.id?.slice(0, 8)} — {s.profile} — {s.total_findings} findings</option>
              ))}
            </select>
            <select value={template} onChange={(e) => setTemplate(e.target.value)}
              className="bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm">
              <option value="full">Full Report</option>
              <option value="executive">Executive Summary</option>
              <option value="vulnerability">Vulnerability Report</option>
              <option value="credential">Credential Report</option>
            </select>
            <button type="submit" disabled={generating || !selectedScan}
              className="bg-sentinel-accent text-white text-sm px-5 py-1.5 rounded disabled:opacity-50">
              {generating ? "Generating..." : "Generate"}
            </button>
          </div>
        </form>

        {/* Report List */}
        <div className="space-y-2">
          {reports.map((r: any) => (
            <div key={r.id} className="bg-sentinel-surface border border-sentinel-border rounded-lg p-4 flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">{r.report_title || `Report ${r.id?.slice(0, 8)}`}</p>
                <p className="text-xs text-sentinel-muted">{r.template} · {r.format} · {new Date(r.generated_at).toLocaleDateString()}</p>
              </div>
              <a href={`/api/v1/reports/${r.id}/download`}
                className="text-xs bg-sentinel-card border border-sentinel-border px-3 py-1.5 rounded hover:border-sentinel-accent/50">
                Download
              </a>
            </div>
          ))}
          {reports.length === 0 && (
            <p className="text-sentinel-muted text-sm py-8 text-center">No reports generated yet.</p>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
