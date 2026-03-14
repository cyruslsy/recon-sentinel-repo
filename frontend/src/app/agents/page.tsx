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
  const [expanded, setExpanded] = useState(false);
  const [rerunning, setRerunning] = useState(false);
  const data = wsData || agent;
  const pct = data.progress_pct || 0;
  const status = data.status || agent.status;

  const statusColor =
    status === "completed" ? "text-sentinel-green" :
    status === "running" ? "text-sentinel-accent" :
    status === "self_correcting" ? "text-sentinel-orange" :
    status === "error" ? "text-sentinel-red" :
    "text-sentinel-muted";

  const statusIcon: string =
    status === "completed" ? "✓ " :
    status === "running" ? "● " :
    status === "self_correcting" ? "⟳ " :
    status === "error" ? "✗ " :
    status === "paused" ? "❚❚ " :
    "";

  const barColor =
    status === "completed" ? "bg-sentinel-green" :
    status === "self_correcting" ? "bg-sentinel-orange" :
    status === "error" ? "bg-sentinel-red" :
    "bg-sentinel-accent";

  // Health note strip color
  const healthStrip =
    status === "self_correcting" ? "border-l-sentinel-orange" :
    status === "error" ? "border-l-sentinel-red" :
    status === "completed" ? "border-l-sentinel-green" :
    "border-l-transparent";

  const handleRerun = async () => {
    setRerunning(true);
    try {
      await api.rerunAgent(agent.id);
    } catch {} finally { setRerunning(false); }
  };

  return (
    <button
      onClick={() => setExpanded(!expanded)}
      className={`w-full text-left bg-sentinel-card border border-sentinel-border border-l-2 ${healthStrip} rounded-lg p-4 hover:border-sentinel-accent/30 transition-colors`}
      aria-expanded={expanded}
      aria-label={`Agent: ${agent.agent_name}, status: ${status}`}
    >
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-2 min-w-0">
          <h3 className="text-sm font-medium truncate">{agent.agent_name}</h3>
          {agent.target_host && (
            <span className="text-[10px] text-sentinel-muted font-mono truncate">
              {agent.target_host}
            </span>
          )}
          {/* MITRE tag — only shown if agent has tags */}
          {agent.mitre_tags?.length > 0 && (
            <span className="text-[9px] font-mono px-1.5 py-0.5 bg-sentinel-purple/10 text-sentinel-purple rounded">
              {agent.mitre_tags[0]}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-xs font-medium ${statusColor}`}>{statusIcon}{status}</span>
          <span className="text-[10px] text-sentinel-muted">{expanded ? "▲" : "▼"}</span>
        </div>
      </div>

      <ProgressBar pct={pct} color={barColor} />

      <div className="flex items-center justify-between mt-2">
        <span className="text-xs text-sentinel-muted">
          {pct}% {data.current_tool ? `· ${data.current_tool}` : ""}
        </span>
        <span className="text-xs text-sentinel-muted">
          {data.findings_count || agent.findings_count || 0} findings
          {agent.duration_seconds ? ` · ${Math.round(agent.duration_seconds)}s` : ""}
        </span>
      </div>

      {/* Health note (self-correction status) */}
      {status === "self_correcting" && (
        <div className="mt-2 text-[11px] bg-sentinel-orange/5 border border-sentinel-orange/20 rounded px-2 py-1 text-sentinel-orange">
          ⟳ Self-correcting: detecting anomaly pattern and adjusting parameters...
        </div>
      )}

      {data.last_log_line && (
        <p className="text-[11px] text-sentinel-muted mt-2 font-mono truncate">
          {data.last_log_line}
        </p>
      )}

      {/* Expanded section: full log + actions */}
      {expanded && (
        <div className="mt-3 space-y-2" onClick={e => e.stopPropagation()}>
          {/* Last command */}
          {data.last_log_line && (
            <div className="p-2 bg-sentinel-bg rounded border border-sentinel-border">
              <p className="text-[10px] text-sentinel-muted mb-1">LAST COMMAND</p>
              <p className="text-xs font-mono text-sentinel-text/80 break-all">{data.last_log_line}</p>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex gap-2 pt-1">
            {(status === "error" || status === "completed") && (
              <button
                disabled={rerunning}
                onClick={handleRerun}
                className="text-[11px] font-medium px-3 py-1 rounded bg-sentinel-accent/10 text-sentinel-accent hover:bg-sentinel-accent/20 border border-sentinel-accent/30 transition-colors disabled:opacity-50"
              >
                {rerunning ? "Queuing..." : "⟳ Re-run"}
              </button>
            )}
            {status === "running" && (
              <button
                onClick={async () => { try { await api.pauseAgent(agent.id); } catch {} }}
                className="text-[11px] font-medium px-3 py-1 rounded bg-sentinel-orange/10 text-sentinel-orange hover:bg-sentinel-orange/20 border border-sentinel-orange/30 transition-colors"
              >
                ⏸ Pause
              </button>
            )}
            <a
              href={`/health?scan_id=${agent.scan_id}`}
              className="text-[11px] font-medium px-3 py-1 rounded bg-sentinel-surface text-sentinel-muted hover:text-sentinel-text border border-sentinel-border transition-colors"
            >
              View Health Feed
            </a>
          </div>
        </div>
      )}
    </button>
  );
}

function GateBanner({ gate, scanId, onDecided }: { gate: ApprovalGate; scanId: string; onDecided: () => void }) {
  const [deciding, setDeciding] = useState(false);
  const [showCustomize, setShowCustomize] = useState(false);
  const [modifications, setModifications] = useState("");

  async function handleDecide(decision: string, mods?: string) {
    setDeciding(true);
    try {
      await api.decideGate(scanId, gate.gate_number, decision, mods ? { notes: mods } : undefined);
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

          {/* Customization panel */}
          {showCustomize && (
            <div className="mt-4 p-3 bg-sentinel-surface border border-sentinel-border rounded-lg">
              <label className="text-xs font-medium text-sentinel-muted block mb-2">
                Scope modifications (agents to add/skip, targets to include/exclude):
              </label>
              <textarea
                value={modifications}
                onChange={(e) => setModifications(e.target.value)}
                placeholder="e.g. Skip vuln scanning on staging.target.com&#10;Add cloud asset agent&#10;Exclude *.internal.target.com"
                rows={3}
                className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm text-sentinel-text placeholder:text-sentinel-muted/50 focus:outline-none focus:border-sentinel-accent"
              />
              <div className="flex gap-2 mt-2">
                <button
                  onClick={() => handleDecide("customized", modifications)}
                  disabled={deciding || !modifications.trim()}
                  className="bg-sentinel-orange hover:bg-sentinel-orange/90 text-white text-xs px-3 py-1.5 rounded disabled:opacity-50"
                >
                  {deciding ? "Submitting..." : "Submit Modifications"}
                </button>
                <button
                  onClick={() => { setShowCustomize(false); setModifications(""); }}
                  className="text-xs text-sentinel-muted hover:text-sentinel-text px-3 py-1.5"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          <div className="flex gap-2 mt-4">
            <button
              onClick={() => handleDecide("approved")}
              disabled={deciding}
              className="bg-sentinel-green hover:bg-sentinel-green/90 text-white text-sm px-4 py-1.5 rounded disabled:opacity-50"
            >
              Approve
            </button>
            {!showCustomize && (
              <button
                onClick={() => setShowCustomize(true)}
                disabled={deciding}
                className="bg-sentinel-orange hover:bg-sentinel-orange/90 text-white text-sm px-4 py-1.5 rounded disabled:opacity-50"
              >
                Customize
              </button>
            )}
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
        <div className="flex flex-col items-center justify-center h-[60vh] gap-4">
          <div className="text-4xl">🔍</div>
          <p className="text-sentinel-muted text-sm">Select a scan from the Scans page to view agent progress.</p>
          <a href="/scans" className="text-xs bg-sentinel-accent text-white px-4 py-2 rounded hover:bg-sentinel-accent/90 transition-colors">
            Go to Scans
          </a>
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
              {scan?.target_value || scanId?.slice(0, 8)} · {scan?.phase || "loading"} ·{" "}
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

        {/* Agent Grid — grouped by phase */}
        {(() => {
          const PHASE_CONFIG: Record<string, { label: string; border: string }> = {
            passive: { label: "PHASE 1: PASSIVE", border: "border-l-sentinel-accent" },
            active: { label: "PHASE 2: ACTIVE", border: "border-l-sentinel-green" },
            vuln: { label: "PHASE 3: VULNERABILITY", border: "border-l-sentinel-orange" },
          };
          const grouped = new Map<string, typeof agents>();
          for (const agent of agents) {
            const phase = (agent as any).phase || "passive";
            if (!grouped.has(phase)) grouped.set(phase, []);
            grouped.get(phase)!.push(agent);
          }
          const phaseOrder = ["passive", "active", "vuln"];
          return phaseOrder.map((phase) => {
            const phaseAgents = grouped.get(phase);
            if (!phaseAgents || phaseAgents.length === 0) return null;
            const config = PHASE_CONFIG[phase] || { label: phase.toUpperCase(), border: "border-l-sentinel-muted" };
            return (
              <div key={phase} className="mb-6">
                <div className={`border-l-2 ${config.border} pl-3 mb-3`}>
                  <h2 className="text-xs font-semibold tracking-wider text-sentinel-muted">{config.label}</h2>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  {phaseAgents.map((agent) => (
                    <AgentCard
                      key={agent.id}
                      agent={agent}
                      wsData={wsAgentMap.get(agent.id)}
                    />
                  ))}
                </div>
              </div>
            );
          });
        })()}
        {agents.length === 0 && (
          <p className="text-center text-sentinel-muted py-12 text-sm">
            Waiting for agents to start...
          </p>
        )}
      </div>
    </AppLayout>
  );
}
