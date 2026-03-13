"use client";

import { useEffect, useState } from "react";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { Report, Scan } from "@/lib/types";

const TEMPLATES = [
  { id: "full", name: "Full Pentest Report", desc: "Complete findings with MITRE mapping, risk scores, and remediation", icon: "📋" },
  { id: "executive", name: "Executive Summary", desc: "High-level overview for non-technical stakeholders", icon: "📊" },
  { id: "vulnerability", name: "Vulnerability Report", desc: "CVEs, misconfigurations, and exposure analysis", icon: "🔓" },
  { id: "credential", name: "Credential Report", desc: "Leaked credentials, password reuse, and breach correlation", icon: "🔑" },
  { id: "compliance", name: "Compliance Report", desc: "OWASP Top 10, PTES, or custom framework mapping", icon: "✓" },
];

const SECTIONS = [
  { id: "exec_summary", label: "Executive Summary", default: true },
  { id: "methodology", label: "Methodology", default: true },
  { id: "scope", label: "Scope & Targets", default: true },
  { id: "findings", label: "Detailed Findings", default: true },
  { id: "mitre", label: "MITRE ATT&CK Mapping", default: true },
  { id: "credentials", label: "Credential Analysis", default: false },
  { id: "attack_chain", label: "Attack Chain Analysis", default: false },
  { id: "remediation", label: "Remediation Priorities", default: true },
  { id: "appendix", label: "Technical Appendix", default: false },
];

export default function ReportsPage() {
  const [reports, setReports] = useState<Report[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [selectedScan, setSelectedScan] = useState("");
  const [selectedTemplate, setSelectedTemplate] = useState("full");
  const [sections, setSections] = useState<Record<string, boolean>>(
    Object.fromEntries(SECTIONS.map(s => [s.id, s.default]))
  );

  useEffect(() => {
    (async () => {
      try {
        setReports(await api.listReports());
        setScans(await api.listScans("limit=20"));
      } catch {} finally { setLoading(false); }
    })();
  }, []);

  async function handleGenerate() {
    if (!selectedScan) return;
    setGenerating(true);
    try {
      const enabledSections = Object.entries(sections).filter(([, v]) => v).map(([k]) => k);
      await api.generateReport({
        scan_id: selectedScan,
        template: selectedTemplate,
        format: "json",
        sections: enabledSections,
      });
      // Poll for report completion (LLM takes 15-30s)
      let attempts = 0;
      const maxAttempts = 12;
      const poll = async () => {
        attempts++;
        const updated = await api.listReports();
        setReports(updated);
        const latest = updated[0];
        if (latest && latest.file_path !== "pending") {
          setGenerating(false);
          return;
        }
        if (attempts < maxAttempts) {
          setTimeout(poll, 5000);
        } else {
          setGenerating(false);
        }
      };
      setTimeout(poll, 3000);
    } catch { setGenerating(false); }
  }

  return (
    <AppLayout>
      <div className="max-w-5xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Reports</h1>

        {/* ─── Template Selector ─── */}
        <div className="bg-sentinel-surface border border-sentinel-border rounded-lg p-5 mb-6">
          <h2 className="text-sm font-medium mb-4">Generate New Report</h2>

          {/* Scan selector */}
          <select
            value={selectedScan}
            onChange={(e) => setSelectedScan(e.target.value)}
            className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm mb-4"
            aria-label="Select scan for report"
          >
            <option value="">Select a scan...</option>
            {scans.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id?.slice(0, 8)} — {s.profile} — {s.total_findings} findings — {s.status}
              </option>
            ))}
          </select>

          {/* Template cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2 mb-4">
            {TEMPLATES.map(t => (
              <button
                key={t.id}
                onClick={() => setSelectedTemplate(t.id)}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  selectedTemplate === t.id
                    ? "border-sentinel-accent bg-sentinel-accent/10"
                    : "border-sentinel-border bg-sentinel-card hover:border-sentinel-accent/30"
                }`}
                aria-pressed={selectedTemplate === t.id}
              >
                <span className="text-lg">{t.icon}</span>
                <p className="text-xs font-medium mt-1">{t.name}</p>
                <p className="text-[10px] text-sentinel-muted mt-0.5 leading-tight">{t.desc}</p>
              </button>
            ))}
          </div>

          {/* Section toggles */}
          <div className="mb-4">
            <p className="text-xs text-sentinel-muted mb-2">Include sections:</p>
            <div className="flex flex-wrap gap-2">
              {SECTIONS.map(s => (
                <button
                  key={s.id}
                  onClick={() => setSections(prev => ({ ...prev, [s.id]: !prev[s.id] }))}
                  className={`text-xs px-3 py-1.5 rounded-full border transition-colors ${
                    sections[s.id]
                      ? "border-sentinel-accent/50 bg-sentinel-accent/10 text-sentinel-accent"
                      : "border-sentinel-border text-sentinel-muted hover:border-sentinel-accent/30"
                  }`}
                  aria-pressed={sections[s.id]}
                >
                  {sections[s.id] ? "✓ " : ""}{s.label}
                </button>
              ))}
            </div>
          </div>

          {/* Generate button */}
          <button
            onClick={handleGenerate}
            disabled={generating || !selectedScan}
            className="bg-sentinel-accent text-white text-sm px-6 py-2 rounded font-medium disabled:opacity-50 transition-colors hover:bg-sentinel-accent/90"
          >
            {generating ? "Generating report..." : "Generate Report"}
          </button>
        </div>

        {/* ─── Report List ─── */}
        <h2 className="text-sm font-medium text-sentinel-muted mb-3">Generated Reports</h2>
        <div className="space-y-2">
          {loading ? (
            <p className="text-sentinel-muted text-sm py-8 text-center animate-pulse">Loading reports...</p>
          ) : reports.length === 0 ? (
            <p className="text-sentinel-muted text-sm py-8 text-center">No reports generated yet. Select a scan and template above.</p>
          ) : reports.map((r) => (
            <div key={r.id} className="bg-sentinel-card border border-sentinel-border rounded-lg p-4 flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">{r.report_title || `Report ${r.id?.slice(0, 8)}`}</p>
                <p className="text-xs text-sentinel-muted mt-0.5">
                  {r.template} · {new Date(r.generated_at).toLocaleDateString()} · {new Date(r.generated_at).toLocaleTimeString()}
                </p>
              </div>
              <a
                href={`/api/v1/reports/${r.id}/download`}
                className="text-xs bg-sentinel-surface border border-sentinel-border px-3 py-1.5 rounded hover:border-sentinel-accent/50 transition-colors"
              >
                ↓ Download
              </a>
            </div>
          ))}
        </div>
      </div>
    </AppLayout>
  );
}
