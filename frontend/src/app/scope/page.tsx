"use client";

import { useEffect, useState } from "react";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { ScopeItem, ScopeViolation } from "@/lib/types";

export default function ScopePage() {
  const [projectId, setProjectId] = useState("");
  const [items, setItems] = useState<ScopeItem[]>([]);
  const [violations, setViolations] = useState<ScopeViolation[]>([]);
  const [newItem, setNewItem] = useState({ item_type: "domain", item_value: "", status: "in_scope" });
  const [tab, setTab] = useState<"scope" | "violations">("scope");
  const [loading, setLoading] = useState(true);

  useEffect(() => { loadProject(); }, []);

  async function loadProject() {
    try {
      const projects = await api.listProjects();
      if (projects.length > 0) {
        setProjectId(projects[0].id);
        loadScope(projects[0].id);
        loadViolations(projects[0].id);
      }
    } catch {} finally { setLoading(false); }
  }

  async function loadScope(pid: string) {
    try { setItems(await api.listScope(pid)); } catch {}
  }

  async function loadViolations(pid: string) {
    try { setViolations(await api.listViolations(pid)); } catch {}
  }

  async function addItem(e: React.FormEvent) {
    e.preventDefault();
    if (!projectId || !newItem.item_value) return;
    try {
      await api.addScopeItem(projectId, newItem);
      setNewItem({ item_type: "domain", item_value: "", status: "in_scope" });
      loadScope(projectId);
    } catch {}
  }

  async function toggleItem(id: string, currentStatus: string) {
    const newStatus = currentStatus === "in_scope" ? "out_of_scope" : "in_scope";
    try {
      await api.toggleScopeItem(id, newStatus);
      loadScope(projectId);
    } catch {}
  }

  const inScope = items.filter((i) => i.status === "in_scope");
  const outScope = items.filter((i) => i.status === "out_of_scope");

  return (

    <AppLayout>
      <div className="max-w-5xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Scope Control</h1>
        <p className="text-sentinel-muted text-sm mb-4">Define in-scope and out-of-scope boundaries for scanning</p>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-sentinel-surface rounded-lg p-1 w-fit">
          {(["scope", "violations"] as const).map((t) => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${tab === t ? "bg-sentinel-card text-sentinel-text" : "text-sentinel-muted hover:text-sentinel-text"}`}>
              {t === "scope" ? `Scope (${items.length})` : `Violations (${violations.length})`}
            </button>
          ))}
        </div>

        {tab === "scope" && (
          <>
            {/* Add Item Form */}
            <form onSubmit={addItem} aria-label="Add scope item" className="flex gap-3 mb-6">
              <select value={newItem.item_type} onChange={(e) => setNewItem((n) => ({ ...n, item_type: e.target.value }))}
                className="bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm">
                <option value="domain">Domain</option>
                <option value="ip">IP</option>
                <option value="cidr">CIDR</option>
                <option value="regex">Regex</option>
              </select>
              <input value={newItem.item_value} onChange={(e) => setNewItem((n) => ({ ...n, item_value: e.target.value }))}
                placeholder="*.example.com or 10.0.0.0/24"
                className="flex-1 bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm focus:outline-none focus:border-sentinel-accent" />
              <select value={newItem.status} onChange={(e) => setNewItem((n) => ({ ...n, status: e.target.value }))}
                className="bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm">
                <option value="in_scope">In Scope</option>
                <option value="out_of_scope">Excluded</option>
              </select>
              <button type="submit" className="bg-sentinel-accent text-white text-sm px-4 py-1.5 rounded">Add</button>
            </form>

            {/* In Scope */}
            <h2 className="text-sm font-medium text-sentinel-green mb-2">In Scope ({inScope.length})</h2>
            <div className="space-y-1 mb-6">
              {inScope.map((item) => (
                <div key={item.id} className="flex items-center justify-between bg-sentinel-surface border border-sentinel-border rounded px-4 py-2">
                  <div>
                    <span className="text-sm font-mono">{item.item_value}</span>
                    <span className="text-xs text-sentinel-muted ml-2">{item.item_type}</span>
                  </div>
                  <button onClick={() => toggleItem(item.id, item.status)}
                    className="text-xs text-sentinel-muted hover:text-sentinel-red">Exclude</button>
                </div>
              ))}
            </div>

            {/* Out of Scope */}
            <h2 className="text-sm font-medium text-sentinel-red mb-2">Excluded ({outScope.length})</h2>
            <div className="space-y-1">
              {outScope.map((item) => (
                <div key={item.id} className="flex items-center justify-between bg-sentinel-surface border border-sentinel-border rounded px-4 py-2 opacity-60">
                  <div>
                    <span className="text-sm font-mono">{item.item_value}</span>
                    <span className="text-xs text-sentinel-muted ml-2">{item.item_type}</span>
                  </div>
                  <button onClick={() => toggleItem(item.id, item.status)}
                    className="text-xs text-sentinel-muted hover:text-sentinel-green">Re-include</button>
                </div>
              ))}
            </div>
          </>
        )}

        {tab === "violations" && (
          <div className="space-y-2">
            {violations.length === 0 ? (
              <p className="text-sentinel-muted text-sm py-8 text-center">No scope violations recorded.</p>
            ) : violations.map((v) => (
              <div key={v.id} className="bg-sentinel-red/5 border border-sentinel-red/20 rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium text-sentinel-red">{v.attempted_target}</span>
                  <span className="text-xs text-sentinel-muted">{v.agent_type}</span>
                </div>
                <p className="text-xs text-sentinel-muted mt-1">{v.reason}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </AppLayout>
  );
}
