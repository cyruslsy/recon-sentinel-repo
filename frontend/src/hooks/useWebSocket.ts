"use client";

import { useEffect, useRef, useState, useCallback } from "react";

type WSStatus = "connecting" | "connected" | "disconnected" | "reconnecting";

interface ScanEvent {
  event: string;
  data: any;
}

export function useWebSocket(scanId: string | null) {
  const [status, setStatus] = useState<WSStatus>("disconnected");
  const [lastEvent, setLastEvent] = useState<ScanEvent | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const retriesRef = useRef(0);
  const maxRetries = 10;

  const connect = useCallback(() => {
    if (!scanId) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws/scan/${scanId}`;

    setStatus("connecting");
    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("connected");
      retriesRef.current = 0;
    };

    ws.onmessage = (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data);
        setLastEvent(event);
        setEvents((prev) => [...prev.slice(-200), event]); // Keep last 200 events
      } catch {}
    };

    ws.onclose = () => {
      setStatus("disconnected");
      wsRef.current = null;

      // Exponential backoff reconnect
      if (retriesRef.current < maxRetries) {
        const delay = Math.min(1000 * Math.pow(2, retriesRef.current), 30000);
        retriesRef.current += 1;
        setStatus("reconnecting");
        setTimeout(connect, delay);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }, [scanId]);

  useEffect(() => {
    connect();
    return () => {
      retriesRef.current = maxRetries; // Prevent reconnect on unmount
      wsRef.current?.close();
    };
  }, [connect]);

  const sendAction = useCallback((action: string, data: any = {}) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action, ...data }));
    }
  }, []);

  // Reset events when scanId changes
  useEffect(() => {
    setEvents([]);
    setLastEvent(null);
  }, [scanId]);

  return { status, lastEvent, events, sendAction };
}

/**
 * Hook to filter WebSocket events by type.
 * Usage: const agentUpdates = useFilteredEvents(events, "agent.status");
 */
export function useFilteredEvents(events: ScanEvent[], eventType: string) {
  return events.filter((e) => e.event === eventType);
}
