"use client";

import { useEffect, useState, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import { useWebSocket, useFilteredEvents } from "@/hooks/useWebSocket";
import type { Scan, AgentRun, ApprovalGate } from "@/lib/types";

function ProgressBar({ pct, color = "bg-sentinel-accent" }: { pct: number; color?: string }) {
  return (
    <div className="w-full h-1.5 bg-sentinel-bg rounded-full overflow-hidden">
      <div
        className={`h-full rounded-full transition-all duration-500 ${color}`}
        style={{ width: `${Math.min(pct, 100)}%` }}
      />
    </div>
  );
}

function AgentCard({ agent, wsData }: { agent: AgentRun; wsData?: Record<string, unknown> }) {
  const data = wsData || agent;
  const pct = data.progress_pct || 0;
  const status = data.status || agent.status;

  const statusColor =
    status === "completed" ? "text-sentinel-green" :
    status === "running" ? "text-sentinel-accent" :
    status === "self_correcting" ? "text-sentinel-orange" :
    status === "error" ? "text-sentinel-red" :
    "text-sentinel-muted";

  const barColor =
    status === "completed" ? "bg-sentinel-green" :
    status === "self_correcting" ? "bg-sentinel-orange" :
    status === "error" ? "bg-sentinel-red" :
    "bg-sentinel-accent";

  return (
    <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-medium">{agent.agent_name}</h3>
        <span className={`text-xs font-medium ${statusColor}`}>{status}</span>
      </div>

      <ProgressBar pct={pct} color={barColor} />

      <div className="flex items-center justify-between mt-2">
        <span className="text-xs text-sentinel-muted">
          {pct}% {data.current_tool ? `· ${data.current_tool}` : ""}
        </span>
        <span className="text-xs text-sentinel-muted">
          {data.findings_count || agent.findings_count || 0} findings
        </span>
      </div>

      {data.last_log_line && (
        <p className="text-[11px] text-sentinel-muted mt-2 font-mono truncate">
          {data.last_log_line}
        </p>
      )}
    </div>
  );
}

function GateBanner({ gate, scanId, onDecided }: { gate: ApprovalGate; scanId: string; onDecided: () => void }) {
  const [deciding, setDeciding] = useState(false);

  async function handleDecide(decision: string) {
    setDeciding(true);
    try {
      await api.decideGate(scanId, gate.gate_number, decision);
      onDecided();
    } catch {}
    setDeciding(false);
  }

  return (
    <div className="bg-sentinel-accent/10 border border-sentinel-accent/30 rounded-lg p-5 mb-6">
      <div className="flex items-start gap-3">
        <span className="text-2xl">🛡️</span>
        <div className="flex-1">
          <h3 className="text-sm font-semibold text-sentinel-accent">
            Approval Gate {gate.gate_number} — Human Decision Required
          </h3>
          <p className="text-sm mt-2">{gate.ai_summary}</p>

          {gate.ai_recommendation?.risk_assessment && (
            <p className="text-xs text-sentinel-muted mt-2">
              Risk: {gate.ai_recommendation.risk_assessment}
            </p>
          )}

          <div className="flex gap-2 mt-4">
            <button
              onClick={() => handleDecide("approved")}
              disabled={deciding}
              className="bg-sentinel-green hover:bg-sentinel-green/90 text-white text-sm px-4 py-1.5 rounded disabled:opacity-50"
            >
              Approve
            </button>
            <button
              onClick={() => handleDecide("customized")}
              disabled={deciding}
              className="bg-sentinel-orange hover:bg-sentinel-orange/90 text-white text-sm px-4 py-1.5 rounded disabled:opacity-50"
            >
              Customize
            </button>
            <button
              onClick={() => handleDecide("skipped")}
              disabled={deciding}
              className="bg-sentinel-border hover:bg-sentinel-hover text-sentinel-muted text-sm px-4 py-1.5 rounded disabled:opacity-50"
            >
              Skip
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AgentsPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || null;
  const [agents, setAgents] = useState<AgentRun[]>([]);
  const [gates, setGates] = useState<ApprovalGate[]>([]);
  const [scan, setScan] = useState<Scan | null>(null);
  const { status: wsStatus, events } = useWebSocket(scanId);

  // Memoize agent WS data map — only rebuilds when events array changes
  const agentUpdates = useFilteredEvents(events, "agent.status");
  const wsAgentMap = useMemo(() => {
    const map = new Map<string, any>();
    agentUpdates.forEach((e) => {
      if (e.data?.agent_run_id) map.set(e.data.agent_run_id, e.data);
    });
    return map;
  }, [agentUpdates]);

  useEffect(() => {
    if (scanId) loadScanData();
  }, [scanId]);

  async function loadScanData() {
    if (!scanId) return;
    try {
      setScan(await api.getScan(scanId));
      setAgents(await api.listAgentRuns(scanId));
      setGates(await api.listGates(scanId));
    } catch {}
  }

  const pendingGate = gates.find((g) => g.decision === "pending");

  if (!scanId) {
    return (
      <AppLayout>
        <div className="flex items-center justify-center h-[60vh]">
          <p className="text-sentinel-muted">Select a scan from the Scans page to view agent progress.</p>
        </div>
      </AppLayout>
    );
  }

  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-semibold">Agent Orchestration</h1>
            <p className="text-sm text-sentinel-muted mt-0.5">
              Scan {scanId?.slice(0, 8)} · {scan?.phase || "loading"} ·{" "}
              <span className={wsStatus === "connected" ? "text-sentinel-green" : "text-sentinel-muted"}>
                WS: {wsStatus}
              </span>
            </p>
          </div>
          {scan?.status === "running" && (
            <button
              onClick={() => api.stopScan(scanId!)}
              className="bg-sentinel-red/20 text-sentinel-red text-sm px-4 py-1.5 rounded hover:bg-sentinel-red/30"
            >
              Stop Scan
            </button>
          )}
        </div>

        {/* Approval Gate Banner */}
        {pendingGate && (
          <GateBanner gate={pendingGate} scanId={scanId!} onDecided={loadScanData} />
        )}

        {/* Agent Grid */}
        <div className="grid grid-cols-2 gap-4">
          {agents.map((agent) => (
            <AgentCard
              key={agent.id}
              agent={agent}
              wsData={wsAgentMap.get(agent.id)}
            />
          ))}
          {agents.length === 0 && (
            <p className="col-span-2 text-center text-sentinel-muted py-12 text-sm">
              Waiting for agents to start...
            </p>
          )}
        </div>
      </div>
    </AppLayout>
  );
}
