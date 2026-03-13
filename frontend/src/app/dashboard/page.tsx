"use client";

import { useEffect, useState } from "react";
import useSWR from "swr";
import AppLayout from "@/components/AppLayout";
import { api, fetcher } from "@/lib/api";
import type { Scan } from "@/lib/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high: "#F59E0B",
  medium: "#3B82F6",
  low: "#22C55E",
  info: "#64748B",
};

function StatCard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (

    <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
      <p className="text-xs text-sentinel-muted">{label}</p>
      <p className="text-2xl font-semibold mt-1" style={color ? { color } : {}}>
        {value}
      </p>
    </div>
  );
}

function ScanRow({ scan }: { scan: Scan }) {
  const statusColor =
    scan.status === "completed" ? "text-sentinel-green" :
    scan.status === "running" ? "text-sentinel-accent" :
    scan.status === "paused" ? "text-sentinel-orange" :
    "text-sentinel-muted";

  return (

    <tr className="border-b border-sentinel-border/50 hover:bg-sentinel-hover/50 transition-colors">
      <td className="py-3 px-4 text-sm font-mono text-sentinel-muted">{scan.id?.slice(0, 8)}</td>
      <td className="py-3 px-4">
        <span className={`text-sm font-medium ${statusColor}`}>
          {scan.status}
        </span>
        <span className="text-xs text-sentinel-muted ml-2">{scan.phase}</span>
      </td>
      <td className="py-3 px-4 text-sm">{scan.total_findings}</td>
      <td className="py-3 px-4">
        {scan.critical_count > 0 && (
          <span className="text-xs bg-sentinel-red/20 text-sentinel-red px-1.5 py-0.5 rounded mr-1">
            {scan.critical_count}C
          </span>
        )}
        {scan.high_count > 0 && (
          <span className="text-xs bg-sentinel-orange/20 text-sentinel-orange px-1.5 py-0.5 rounded">
            {scan.high_count}H
          </span>
        )}
      </td>
      <td className="py-3 px-4 text-xs text-sentinel-muted">
        {scan.profile}
      </td>
    </tr>
  );
}

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [stats, setStats] = useState({ total: 0, running: 0, critical: 0, findings: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboard();
  }, []);

  async function loadDashboard() {
    try {
      const scanList = await api.listScans("limit=10");
      setScans(scanList);

      const running = scanList.filter((s) => s.status === "running").length;
      const totalFindings = scanList.reduce((sum, s) => sum + (s.total_findings || 0), 0);
      const criticals = scanList.reduce((sum, s) => sum + (s.critical_count || 0), 0);

      setStats({
        total: scanList.length,
        running,
        critical: criticals,
        findings: totalFindings,
      });
    } catch {} finally { setLoading(false); }
  }

  return (

    <AppLayout>
      <div className="max-w-7xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Dashboard</h1>

        {/* Stat Cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          <StatCard label="Total Scans" value={stats.total} />
          <StatCard label="Active Scans" value={stats.running} color="#3B82F6" />
          <StatCard label="Critical Findings" value={stats.critical} color="#EF4444" />
          <StatCard label="Total Findings" value={stats.findings} />
        </div>

        {/* Recent Scans */}
        <div className="bg-sentinel-surface border border-sentinel-border rounded-lg">
          <div className="px-4 py-3 border-b border-sentinel-border">
            <h2 className="text-sm font-medium">Recent Scans</h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-sentinel-border text-xs text-sentinel-muted">
                <th className="text-left py-2 px-4 font-medium">ID</th>
                <th className="text-left py-2 px-4 font-medium">Status</th>
                <th className="text-left py-2 px-4 font-medium">Findings</th>
                <th className="text-left py-2 px-4 font-medium">Severity</th>
                <th className="text-left py-2 px-4 font-medium">Profile</th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-sentinel-muted text-sm">
                    No scans yet. Launch your first scan from the Scans page.
                  </td>
                </tr>
              ) : (
                scans.map((scan) => <ScanRow key={scan.id} scan={scan} />)
              )}
            </tbody>
          </table>
        </div>
      </div>
    </AppLayout>
  );
}
