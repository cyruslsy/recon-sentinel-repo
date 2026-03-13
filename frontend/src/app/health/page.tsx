"use client";

import { useEffect, useState, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import { useWebSocket } from "@/hooks/useWebSocket";
import type { HealthEvent } from "@/lib/types";

type FilterTab = "all" | "anomalies" | "corrections" | "resolved" | "needs_action";

const TAB_LABELS: Record<FilterTab, string> = {
  all: "All Events",
  anomalies: "Anomalies",
  corrections: "Auto-Fixed",
  resolved: "Resolved",
  needs_action: "Needs Action",
};

const EVENT_ICONS: Record<string, { icon: string; color: string; bg: string; label: string }> = {
  anomaly_detected:   { icon: "⚠", color: "text-sentinel-orange", bg: "bg-sentinel-orange/10", label: "Warning" },
  self_correcting:    { icon: "⟳", color: "text-sentinel-accent", bg: "bg-sentinel-accent/10", label: "Auto-fixing" },
  correction_success: { icon: "✓", color: "text-sentinel-green", bg: "bg-sentinel-green/10", label: "Fixed" },
  correction_failed:  { icon: "✗", color: "text-sentinel-red", bg: "bg-sentinel-red/10", label: "Failed" },
  escalate_user:      { icon: "!", color: "text-sentinel-red", bg: "bg-sentinel-red/10", label: "Action needed" },
  info:               { icon: "ℹ", color: "text-sentinel-muted", bg: "bg-sentinel-surface", label: "Info" },
};

export default function HealthFeedPage() {
  const [events, setEvents] = useState<HealthEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<FilterTab>("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";

  // Stats
  const anomalyCount = events.filter(e => e.event_type === "anomaly_detected").length;
  const autoFixedCount = events.filter(e => e.event_type === "correction_success").length;
  const needsActionCount = events.filter(e => e.event_type === "escalate_user" && !e.user_decision).length;

  const loadEvents = useCallback(async () => {
    if (!scanId) return;
    try {
      const data = await api.getHealthEvents(scanId);
      setEvents(data);
    } catch {} finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => { loadEvents(); }, [loadEvents]);

  // Live WebSocket updates
  const { lastEvent } = useWebSocket(scanId);
  useEffect(() => {
    if (lastEvent?.event === "agent.health") {
      setEvents(prev => [lastEvent.data as HealthEvent, ...prev]);
    }
  }, [lastEvent]);

  // Filter and sort events chronologically for correct timeline connections
  const filtered = events
    .filter(e => {
      if (filter === "all") return true;
      if (filter === "anomalies") return e.event_type === "anomaly_detected";
      if (filter === "corrections") return e.event_type === "correction_success";
      if (filter === "resolved") return e.event_type === "correction_success" || e.user_decision;
      if (filter === "needs_action") return e.event_type === "escalate_user" && !e.user_decision;
      return true;
    })
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return (
    <AppLayout>
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-semibold">Health Feed</h1>
            <p className="text-sm text-sentinel-muted mt-1">
              Self-correction timeline — anomaly detection, auto-fix, and resolution
            </p>
          </div>
          {/* Live stats */}
          <div className="flex gap-3">
            <StatBadge label="Anomalies" count={anomalyCount} color="text-sentinel-orange" bg="bg-sentinel-orange/10" />
            <StatBadge label="Auto-Fixed" count={autoFixedCount} color="text-sentinel-green" bg="bg-sentinel-green/10" />
            <StatBadge label="Needs Action" count={needsActionCount} color="text-sentinel-red" bg="bg-sentinel-red/10" />
          </div>
        </div>

        {/* Filter tabs */}
        <div className="flex gap-1 mb-4 border-b border-sentinel-border pb-2">
          {(Object.keys(TAB_LABELS) as FilterTab[]).map(tab => (
            <button
              key={tab}
              onClick={() => setFilter(tab)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                filter === tab
                  ? "bg-sentinel-accent/10 text-sentinel-accent"
                  : "text-sentinel-muted hover:text-sentinel-text"
              }`}
            >
              {TAB_LABELS[tab]}
              {tab === "needs_action" && needsActionCount > 0 && (
                <span className="ml-1.5 px-1.5 py-0.5 text-[10px] bg-sentinel-red/20 text-sentinel-red rounded-full">
                  {needsActionCount}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Timeline */}
        {loading ? (
          <div className="text-center py-12 text-sentinel-muted">Loading health events...</div>
        ) : !scanId ? (
          <div className="text-center py-12 text-sentinel-muted">Select a scan to view health events</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-sentinel-muted">No events match the current filter</div>
        ) : (
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-6 top-0 bottom-0 w-px bg-sentinel-border" />

            {filtered.map((event, i) => {
              const meta = EVENT_ICONS[event.event_type] || EVENT_ICONS.info;
              const isExpanded = expandedId === event.id;
              const isConnected = i > 0 && events[i - 1]?.agent_run_id === event.agent_run_id;

              return (
                <div key={event.id} className={`relative pl-14 pb-4 ${isConnected ? "pt-0" : "pt-2"}`}>
                  {/* Timeline dot */}
                  <div
                    className={`absolute left-4 w-5 h-5 rounded-full flex items-center justify-center text-[10px] ${meta.bg} ${meta.color} border border-sentinel-border`}
                    aria-label={meta.label}
                    role="img"
                  >
                    <span aria-hidden="true">{meta.icon}</span>
                    <span className="sr-only">{meta.label}</span>
                  </div>

                  {/* Event card */}
                  <button
                    onClick={() => setExpandedId(isExpanded ? null : event.id)}
                    className="w-full text-left bg-sentinel-card border border-sentinel-border rounded-lg p-4 hover:border-sentinel-accent/30 transition-colors"
                    aria-expanded={isExpanded}
                    aria-label={`Health event: ${event.event_type}`}
                  >
                    {/* Header row */}
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`text-xs font-medium px-2 py-0.5 rounded ${meta.bg} ${meta.color}`}>
                          {event.event_type.replace(/_/g, " ").toUpperCase()}
                        </span>
                        <span className="text-xs text-sentinel-muted font-mono truncate">
                          {event.agent_name || event.agent_type}
                        </span>
                      </div>
                      <span className="text-[10px] text-sentinel-muted whitespace-nowrap">
                        {new Date(event.created_at).toLocaleTimeString()}
                      </span>
                    </div>

                    {/* Description */}
                    <p className="text-sm mt-2 text-sentinel-text/90">{event.detail}</p>

                    {/* Correction summary (for correction events) */}
                    {event.corrected_params && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {Object.entries(event.corrected_params).map(([k, v]) => (
                          <span key={k} className="text-[10px] font-mono px-2 py-0.5 bg-sentinel-surface rounded text-sentinel-accent">
                            {k}={String(v)}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Expanded: raw data */}
                    {isExpanded && event.raw_data && (
                      <div className="mt-3 p-3 bg-sentinel-bg rounded-md border border-sentinel-border">
                        <p className="text-[10px] text-sentinel-muted mb-1 font-medium">RAW DATA</p>
                        <pre className="text-xs font-mono text-sentinel-muted overflow-x-auto whitespace-pre-wrap">
                          {JSON.stringify(event.raw_data, null, 2)}
                        </pre>
                      </div>
                    )}

                    {/* Escalation: action button */}
                    {event.event_type === "escalate_user" && !event.user_decision && (
                      <div className="mt-3 flex gap-2">
                        <ActionButton label="Continue Scanning" variant="green" eventId={event.id} decision="continue" onDecided={loadEvents} />
                        <ActionButton label="Skip Agent" variant="orange" eventId={event.id} decision="skip" onDecided={loadEvents} />
                        <ActionButton label="Stop Scan" variant="red" eventId={event.id} decision="stop" onDecided={loadEvents} />
                      </div>
                    )}

                    {event.user_decision && (
                      <div className="mt-2 text-xs text-sentinel-muted">
                        Decision: <span className="text-sentinel-accent font-medium">{event.user_decision}</span>
                        {event.decided_at && ` at ${new Date(event.decided_at).toLocaleTimeString()}`}
                      </div>
                    )}
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AppLayout>
  );
}

function StatBadge({ label, count, color, bg }: { label: string; count: number; color: string; bg: string }) {
  return (
    <div className={`${bg} px-3 py-1.5 rounded-lg flex items-center gap-2`}>
      <span className={`text-lg font-semibold font-mono ${color}`}>{count}</span>
      <span className="text-[10px] text-sentinel-muted">{label}</span>
    </div>
  );
}

function ActionButton({ label, variant, eventId, decision, onDecided }: {
  label: string; variant: "green" | "orange" | "red"; eventId: string; decision: string; onDecided: () => void;
}) {
  const [loading, setLoading] = useState(false);
  const colors = {
    green: "bg-sentinel-green/10 text-sentinel-green hover:bg-sentinel-green/20 border-sentinel-green/30",
    orange: "bg-sentinel-orange/10 text-sentinel-orange hover:bg-sentinel-orange/20 border-sentinel-orange/30",
    red: "bg-sentinel-red/10 text-sentinel-red hover:bg-sentinel-red/20 border-sentinel-red/30",
  };

  return (
    <button
      disabled={loading}
      onClick={async (e) => {
        e.stopPropagation();
        setLoading(true);
        try {
          await api.decideHealthEvent(eventId, decision);
          onDecided();
        } catch {} finally { setLoading(false); }
      }}
      className={`text-xs font-medium px-3 py-1.5 rounded border ${colors[variant]} transition-colors disabled:opacity-50`}
    >
      {loading ? "..." : label}
    </button>
  );
}
