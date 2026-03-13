"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";

const SEVERITY_BG: Record<string, string> = {
  critical: "bg-red-500/30 border-red-500/50",
  high: "bg-orange-500/25 border-orange-500/40",
  medium: "bg-blue-500/20 border-blue-500/35",
  low: "bg-green-500/15 border-green-500/30",
  info: "bg-gray-500/10 border-gray-500/20",
};

interface HeatmapItem {
  technique_id: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  max_severity: string | null;
}

export default function MitrePage() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";
  const [techniques, setTechniques] = useState<HeatmapItem[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (scanId) loadHeatmap();
  }, [scanId]);

  async function loadHeatmap() {
    setLoading(true);
    try {
      const data = await api.mitreHeatmap(scanId);
      setTechniques(data.techniques || []);
    } catch {}
    setLoading(false);
  }

  const maxCount = Math.max(...techniques.map((t) => t.finding_count), 1);

  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto">
        <h1 className="text-xl font-semibold mb-2">MITRE ATT&CK Heatmap</h1>
        <p className="text-sm text-sentinel-muted mb-6">
          Findings mapped to MITRE ATT&CK techniques. Color intensity = finding count.
        </p>

        {!scanId ? (
          <p className="text-sentinel-muted text-sm py-12 text-center">Select a scan to view the MITRE heatmap.</p>
        ) : loading ? (
          <p className="text-sentinel-muted text-sm py-12 text-center animate-pulse">Loading heatmap...</p>
        ) : techniques.length === 0 ? (
          <p className="text-sentinel-muted text-sm py-12 text-center">No MITRE-tagged findings for this scan.</p>
        ) : (
          <div className="grid grid-cols-4 gap-3">
            {techniques.map((t) => {
              const severity = t.max_severity || "info";
              const intensity = Math.min(t.finding_count / maxCount, 1);
              return (
                <div
                  key={t.technique_id}
                  className={`border rounded-lg p-3 transition-colors cursor-pointer hover:border-sentinel-accent/50 ${SEVERITY_BG[severity] || SEVERITY_BG.info}`}
                  style={{ opacity: 0.4 + intensity * 0.6 }}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono font-medium">{t.technique_id}</span>
                    <span className="text-lg font-semibold">{t.finding_count}</span>
                  </div>
                  <div className="flex gap-1 text-[10px]">
                    {t.critical_count > 0 && <span className="text-red-400">{t.critical_count}C</span>}
                    {t.high_count > 0 && <span className="text-orange-400">{t.high_count}H</span>}
                    {t.medium_count > 0 && <span className="text-blue-400">{t.medium_count}M</span>}
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
