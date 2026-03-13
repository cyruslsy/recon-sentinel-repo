"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";

const PROFILES = [
  { value: "full", label: "Full Scan", desc: "All agents, all phases" },
  { value: "passive_only", label: "Passive Only", desc: "No active probing" },
  { value: "quick", label: "Quick Scan", desc: "Top 100 ports, fast wordlist" },
  { value: "stealth", label: "Stealth", desc: "Low rate, minimal footprint" },
];

export default function ScansPage() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [showLaunch, setShowLaunch] = useState(false);
  const [target, setTarget] = useState("");
  const [profile, setProfile] = useState("full");
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => { loadScans(); }, []);

  async function loadScans() {
    try {
      setScans(await api.listScans("limit=50"));
    setLoading(false);
    } catch {}
  }

  async function handleLaunch(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLaunching(true);
    try {
      // For MVP: auto-create org/project/target if needed
      let orgs = await api.listOrgs();
      let org = orgs[0];
      if (!org) {
        org = await api.createOrg({ name: "Default" });
      }
      let projects = await api.listProjects();
      let project = projects[0];
      if (!project) {
        project = await api.createProject(org.id, { name: "Default Project" });
      }

      // Detect input type
      const inputType = target.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
        ? target.includes("/") ? "cidr" : "ip"
        : target.startsWith("http") ? "url" : "domain";

      const t = await api.createTarget(project.id, { target_value: target, input_type: inputType });
      const scan = await api.launchScan({ target_id: t.id, profile });
      router.push(`/agents?scan_id=${scan.id}`);
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Failed to launch scan");
    } finally {
      setLaunching(false);
    }
  }

  const statusIcon = (s: string) =>
    s === "running" ? "🟢" : s === "paused" ? "🟡" : s === "completed" ? "✅" : "⬛";

  return (

    <AppLayout>
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-xl font-semibold">Scans</h1>
          <button
            onClick={() => setShowLaunch(!showLaunch)}
            className="bg-sentinel-accent hover:bg-sentinel-accent/90 text-white text-sm font-medium px-4 py-2 rounded transition-colors"
          >
            + New Scan
          </button>
        </div>

        {/* Launch Form */}
        {showLaunch && (
          <form onSubmit={handleLaunch} aria-label="Launch scan" className="bg-sentinel-surface border border-sentinel-border rounded-lg p-5 mb-6">
            {error && <div className="bg-sentinel-red/10 text-sentinel-red text-sm p-3 rounded mb-4">{error}</div>}
            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-xs text-sentinel-muted mb-1.5">Target (domain, IP, CIDR, or URL)</label>
                <input
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="example.com or 10.0.0.0/24"
                  className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-sentinel-muted mb-1.5">Scan Profile</label>
                <select
                  value={profile}
                  onChange={(e) => setProfile(e.target.value)}
                  className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent"
                >
                  {PROFILES.map((p) => (
                    <option key={p.value} value={p.value}>{p.label} — {p.desc}</option>
                  ))}
                </select>
              </div>
            </div>
            <button
              type="submit"
              disabled={launching}
              className="bg-sentinel-green hover:bg-sentinel-green/90 text-white text-sm font-medium px-6 py-2 rounded disabled:opacity-50"
            >
              {launching ? "Launching..." : "Launch Scan"}
            </button>
          </form>
        )}

        {/* Scan List */}
        <div className="space-y-2">
          {scans.map((scan) => (
            <div
              key={scan.id}
              onClick={() => router.push(`/agents?scan_id=${scan.id}`)}
              className="bg-sentinel-surface border border-sentinel-border rounded-lg p-4 flex items-center gap-4 cursor-pointer hover:border-sentinel-accent/50 transition-colors"
            >
              <span className="text-lg">{statusIcon(scan.status)}</span>
              <div className="flex-1">
                <p className="text-sm font-medium">{scan.id?.slice(0, 8)} · {scan.profile}</p>
                <p className="text-xs text-sentinel-muted">{scan.phase} · {scan.total_findings} findings</p>
              </div>
              <div className="flex gap-2">
                {scan.critical_count > 0 && (
                  <span className="text-xs bg-sentinel-red/20 text-sentinel-red px-2 py-0.5 rounded">{scan.critical_count} critical</span>
                )}
                {scan.high_count > 0 && (
                  <span className="text-xs bg-sentinel-orange/20 text-sentinel-orange px-2 py-0.5 rounded">{scan.high_count} high</span>
                )}
              </div>
            </div>
          ))}
          {scans.length === 0 && (
            <p className="text-center text-sentinel-muted py-12 text-sm">No scans yet. Click "New Scan" to get started.</p>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
