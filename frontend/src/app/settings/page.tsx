"use client";

import { useEffect, useState } from "react";
  const [loading, setLoading] = useState(true);
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { ApiKeyConfig, LlmUsageSummary } from "@/lib/types";

export default function SettingsPage() {
  const [tab, setTab] = useState<"api-keys" | "llm">("api-keys");
  const [apiKeys, setApiKeys] = useState<ApiKeyConfig[]>([]);
  const [llmUsage, setLlmUsage] = useState<LlmUsageSummary[]>([]);
  const [newKey, setNewKey] = useState({ service_name: "", api_key: "" });

  useEffect(() => { loadData(); }, [tab]);

  async function loadData() {
    try {
      if (tab === "api-keys") setApiKeys(await api.listApiKeys());
      if (tab === "llm") setLlmUsage(await api.llmUsage());
    setLoading(false);
    } catch {}
  }

  async function addKey(e: React.FormEvent) {
    e.preventDefault();
    if (!newKey.service_name || !newKey.api_key) return;
    try {
      await api.addApiKey(newKey);
      setNewKey({ service_name: "", api_key: "" });
      loadData();
    } catch {}
  }

  async function deleteKey(id: string) {
    try {
      await api.deleteApiKey(id);
      loadData();
    } catch {}
  }

  const totalCost = llmUsage.reduce((sum, u) => sum + (u.cost_usd || 0), 0);

  return (

    <AppLayout>
      <div className="max-w-5xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Settings</h1>

        {/* Tabs */}
        <div className="flex gap-1 mb-6 bg-sentinel-surface rounded-lg p-1 w-fit">
          {([["api-keys", "API Keys"], ["llm", "LLM Usage"]] as const).map(([key, label]) => (
            <button key={key} onClick={() => setTab(key as "api-keys" | "llm")}
              className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${tab === key ? "bg-sentinel-card text-sentinel-text" : "text-sentinel-muted"}`}>
              {label}
            </button>
          ))}
        </div>

        {tab === "api-keys" && (
          <>
            <form onSubmit={addKey} aria-label="Add API key" className="flex gap-3 mb-6">
              <select value={newKey.service_name} onChange={(e) => setNewKey((n) => ({ ...n, service_name: e.target.value }))}
                className="bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm">
                <option value="">Select service...</option>
                <option value="shodan">Shodan</option>
                <option value="virustotal">VirusTotal</option>
                <option value="hibp">HIBP</option>
                <option value="greynoise">GreyNoise</option>
                <option value="dehashed">DeHashed</option>
                <option value="leakcheck">LeakCheck</option>
              </select>
              <input value={newKey.api_key} onChange={(e) => setNewKey((n) => ({ ...n, api_key: e.target.value }))}
                type="password" placeholder="API key value"
                className="flex-1 bg-sentinel-bg border border-sentinel-border rounded px-3 py-1.5 text-sm" />
              <button type="submit" className="bg-sentinel-accent text-white text-sm px-4 py-1.5 rounded">Add Key</button>
            </form>

            <div className="space-y-2">
              {apiKeys.map((k) => (
                <div key={k.id} className="flex items-center justify-between bg-sentinel-surface border border-sentinel-border rounded-lg px-4 py-3">
                  <div>
                    <span className="text-sm font-medium">{k.service_name}</span>
                    <span className={`text-xs ml-2 px-1.5 py-0.5 rounded ${k.status === "valid" ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
                      {k.status}
                    </span>
                  </div>
                  <button onClick={() => deleteKey(k.id)} className="text-xs text-sentinel-muted hover:text-sentinel-red">Remove</button>
                </div>
              ))}
              {apiKeys.length === 0 && <p className="text-sentinel-muted text-sm py-8 text-center">No API keys configured.</p>}
            </div>
          </>
        )}

        {tab === "llm" && (
          <>
            <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4 mb-6">
              <p className="text-xs text-sentinel-muted">Total LLM Cost (Current Month)</p>
              <p className="text-2xl font-semibold mt-1">${totalCost.toFixed(4)}</p>
            </div>

            <div className="bg-sentinel-surface border border-sentinel-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-sentinel-border text-xs text-sentinel-muted">
                    <th className="text-left py-2 px-4 font-medium">Model</th>
                    <th className="text-left py-2 px-4 font-medium">Task</th>
                    <th className="text-right py-2 px-4 font-medium">Tokens In</th>
                    <th className="text-right py-2 px-4 font-medium">Tokens Out</th>
                    <th className="text-right py-2 px-4 font-medium">Cost</th>
                    <th className="text-right py-2 px-4 font-medium">Calls</th>
                  </tr>
                </thead>
                <tbody>
                  {llmUsage.map((u, i) => (
                    <tr key={i} className="border-b border-sentinel-border/30">
                      <td className="py-2 px-4 text-sm font-mono">{u.model?.split("/").pop()?.split("-")[0]}</td>
                      <td className="py-2 px-4 text-sm">{u.task}</td>
                      <td className="py-2 px-4 text-sm text-right">{u.tokens_in?.toLocaleString()}</td>
                      <td className="py-2 px-4 text-sm text-right">{u.tokens_out?.toLocaleString()}</td>
                      <td className="py-2 px-4 text-sm text-right">${u.cost_usd?.toFixed(4)}</td>
                      <td className="py-2 px-4 text-sm text-right">{u.calls}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </AppLayout>
  );
}
