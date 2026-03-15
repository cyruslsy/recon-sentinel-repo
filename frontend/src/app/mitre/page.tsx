"use client";

import { useEffect, useState , Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { MitreHeatmapItem } from "@/lib/types";

const SEVERITY_BG: Record<string, string> = {
  critical: "bg-red-500/30 border-red-500/50",
  high: "bg-orange-500/25 border-orange-500/40",
  medium: "bg-blue-500/20 border-blue-500/35",
  low: "bg-green-500/15 border-green-500/30",
  info: "bg-gray-500/10 border-gray-500/20",
};

// Static MITRE technique name map (covers the 15 techniques used by Recon Sentinel agents)
const TECHNIQUE_NAMES: Record<string, { name: string; tactic: string }> = {
  "T1593": { name: "Search Open Websites/Domains", tactic: "Reconnaissance" },
  "T1596": { name: "Search Open Technical Databases", tactic: "Reconnaissance" },
  "T1589": { name: "Gather Victim Identity Information", tactic: "Reconnaissance" },
  "T1590": { name: "Gather Victim Network Information", tactic: "Reconnaissance" },
  "T1595": { name: "Active Scanning", tactic: "Reconnaissance" },
  "T1592": { name: "Gather Victim Host Information", tactic: "Reconnaissance" },
  "T1566": { name: "Phishing", tactic: "Initial Access" },
  "T1190": { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "T1078": { name: "Valid Accounts", tactic: "Defense Evasion" },
  "T1552": { name: "Unsecured Credentials", tactic: "Credential Access" },
  "T1530": { name: "Data from Cloud Storage", tactic: "Collection" },
  "T1580": { name: "Cloud Infrastructure Discovery", tactic: "Discovery" },
  "T1584": { name: "Compromise Infrastructure", tactic: "Resource Development" },
};

// Group techniques by tactic
function groupByTactic(techniques: (MitreHeatmapItem & { name?: string; tactic?: string })[]) {
  const groups = new Map<string, typeof techniques>();
  for (const t of techniques) {
    const tactic = t.tactic || "Other";
    if (!groups.has(tactic)) groups.set(tactic, []);
    groups.get(tactic)!.push(t);
  }
  return groups;
}

function MitrePageInner() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const scanId = searchParams?.get("scan_id") || "";
  const [techniques, setTechniques] = useState<MitreHeatmapItem[]>([]);
  const [techNames, setTechNames] = useState<Record<string, { technique_name: string; tactic_names: string[] }>>({});
  const [loading, setLoading] = useState(false);
  const [viewMode, setViewMode] = useState<"grid" | "matrix">("grid");

  useEffect(() => {
    if (scanId) {
      loadHeatmap();
      loadTechniqueNames();
    }
  }, [scanId]);

  async function loadHeatmap() {
    setLoading(true);
    try {
      const data = await api.mitreHeatmap(scanId);
      setTechniques(data.techniques || []);
    } catch {}
    setLoading(false);
  }

  async function loadTechniqueNames() {
    try {
      const data = await api.listMitreTechniques();
      const map: Record<string, { technique_name: string; tactic_names: string[] }> = {};
      for (const t of data) {
        map[t.technique_id || t.id] = { technique_name: t.technique_name, tactic_names: t.tactic_names || [] };
      }
      setTechNames(map);
    } catch {
      // Fallback to static names if API not available
    }
  }

  function getTechniqueName(id: string): string {
    return techNames[id]?.technique_name || TECHNIQUE_NAMES[id]?.name || "";
  }

  function getTacticName(id: string): string {
    const apiTactic = techNames[id]?.tactic_names?.[0];
    if (apiTactic) return apiTactic;
    return TECHNIQUE_NAMES[id]?.tactic || "Other";
  }

  function handleClick(techniqueId: string) {
    router.push(`/findings?scan_id=${scanId}&mitre_technique=${techniqueId}`);
  }

  const maxCount = Math.max(...techniques.map((t) => t.finding_count), 1);

  // Enrich techniques with names and tactic
  const enriched = techniques.map((t) => ({
    ...t,
    name: getTechniqueName(t.technique_id),
    tactic: getTacticName(t.technique_id),
  }));

  const grouped = groupByTactic(enriched);
  const tacticOrder = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Defense Evasion", "Credential Access", "Discovery", "Collection", "Other",
  ];

  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-2">
          <h1 className="text-xl font-semibold">MITRE ATT&CK Heatmap</h1>
        <p className="text-sentinel-muted text-sm mb-4">Map findings to MITRE ATT&CK techniques and tactics</p>
          {techniques.length > 0 && (
            <div className="flex gap-1 bg-sentinel-surface rounded-lg p-0.5">
              <button
                onClick={() => setViewMode("grid")}
                className={`text-xs px-3 py-1 rounded ${viewMode === "grid" ? "bg-sentinel-card text-sentinel-text" : "text-sentinel-muted"}`}
              >
                Grid
              </button>
              <button
                onClick={() => setViewMode("matrix")}
                className={`text-xs px-3 py-1 rounded ${viewMode === "matrix" ? "bg-sentinel-card text-sentinel-text" : "text-sentinel-muted"}`}
              >
                By Tactic
              </button>
            </div>
          )}
        </div>
        <p className="text-sm text-sentinel-muted mb-4">
          Click any technique to view its findings. Color intensity = finding count.
        </p>

        {/* Legend */}
        {techniques.length > 0 && (
          <div className="flex items-center gap-4 mb-6 text-[10px] text-sentinel-muted">
            <span>Severity:</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500/40 border border-red-500/60" /> Critical</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-orange-500/35 border border-orange-500/50" /> High</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-500/30 border border-blue-500/45" /> Medium</span>
            <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-green-500/25 border border-green-500/40" /> Low</span>
          </div>
        )}

        {!scanId ? (
          <p className="text-sentinel-muted text-sm py-12 text-center">Select a scan to view the MITRE heatmap.</p>
        ) : loading ? (
          <div className="grid grid-cols-4 gap-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="h-24 bg-sentinel-card border border-sentinel-border rounded-lg animate-pulse" />
            ))}
          </div>
        ) : techniques.length === 0 ? (
          <p className="text-sentinel-muted text-sm py-12 text-center">No MITRE-tagged findings for this scan.</p>
        ) : viewMode === "grid" ? (
          /* Flat grid view */
          <div className="grid grid-cols-4 gap-3">
            {enriched.map((t) => {
              const severity = t.max_severity || "info";
              const intensity = Math.min(t.finding_count / maxCount, 1);
              return (
                <button
                  key={t.technique_id}
                  onClick={() => handleClick(t.technique_id)}
                  className={`border rounded-lg p-3 transition-all text-left hover:border-sentinel-accent/50 hover:scale-[1.02] ${SEVERITY_BG[severity] || SEVERITY_BG.info}`}
                  style={{ opacity: 0.4 + intensity * 0.6 }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-medium">{t.technique_id}</span>
                    <span className="text-lg font-semibold">{t.finding_count}</span>
                  </div>
                  {t.name && (
                    <p className="text-[10px] text-sentinel-text/70 leading-tight mb-1.5 line-clamp-2">{t.name}</p>
                  )}
                  <div className="flex gap-1 text-[10px]">
                    {t.critical_count > 0 && <span className="text-red-400">{t.critical_count}C</span>}
                    {t.high_count > 0 && <span className="text-orange-400">{t.high_count}H</span>}
                    {t.medium_count > 0 && <span className="text-blue-400">{t.medium_count}M</span>}
                  </div>
                </button>
              );
            })}
          </div>
        ) : (
          /* Tactic-grouped matrix view */
          <div className="space-y-6">
            {tacticOrder.map((tactic) => {
              const items = grouped.get(tactic);
              if (!items || items.length === 0) return null;
              return (
                <div key={tactic}>
                  <h2 className="text-xs font-semibold tracking-wider text-sentinel-muted mb-2 uppercase">{tactic}</h2>
                  <div className="grid grid-cols-4 gap-3">
                    {items.map((t) => {
                      const severity = t.max_severity || "info";
                      const intensity = Math.min(t.finding_count / maxCount, 1);
                      return (
                        <button
                          key={t.technique_id}
                          onClick={() => handleClick(t.technique_id)}
                          className={`border rounded-lg p-3 transition-all text-left hover:border-sentinel-accent/50 hover:scale-[1.02] ${SEVERITY_BG[severity] || SEVERITY_BG.info}`}
                          style={{ opacity: 0.4 + intensity * 0.6 }}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs font-mono font-medium">{t.technique_id}</span>
                            <span className="text-lg font-semibold">{t.finding_count}</span>
                          </div>
                          {t.name && (
                            <p className="text-[10px] text-sentinel-text/70 leading-tight mb-1.5 line-clamp-2">{t.name}</p>
                          )}
                          <div className="flex gap-1 text-[10px]">
                            {t.critical_count > 0 && <span className="text-red-400">{t.critical_count}C</span>}
                            {t.high_count > 0 && <span className="text-orange-400">{t.high_count}H</span>}
                            {t.medium_count > 0 && <span className="text-blue-400">{t.medium_count}M</span>}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppLayout>
  );
}

export default function MitrePage() {
  return (<Suspense fallback={<div className="p-8 text-center text-sentinel-muted">Loading...</div>}><MitrePageInner /></Suspense>);
}
