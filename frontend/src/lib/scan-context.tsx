"use client";

import { createContext, useContext, useState, useEffect, useCallback, ReactNode } from "react";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";

interface ScanContextType {
  activeScan: Scan | null;
  activeScanId: string | null;
  recentScans: Scan[];
  loading: boolean;
  setActiveScanId: (id: string | null) => void;
  refresh: () => Promise<void>;
}

const ScanContext = createContext<ScanContextType | null>(null);

export function ScanProvider({ children }: { children: ReactNode }) {
  const searchParams = useSearchParams();
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(false);

  // Sync scan_id from URL params
  useEffect(() => {
    const urlScanId = searchParams.get("scan_id");
    if (urlScanId && urlScanId !== activeScanId) {
      setActiveScanId(urlScanId);
    }
  }, [searchParams, activeScanId]);

  // Fetch active scan details when ID changes
  useEffect(() => {
    if (!activeScanId) {
      setActiveScan(null);
      return;
    }
    (async () => {
      setLoading(true);
      try {
        const scan = await api.getScan(activeScanId);
        setActiveScan(scan);
      } catch {
        setActiveScan(null);
      } finally {
        setLoading(false);
      }
    })();
  }, [activeScanId]);

  // Load recent scans for the selector dropdown
  const refresh = useCallback(async () => {
    try {
      const scans = await api.listScans("limit=10");
      setRecentScans(scans);
      // Auto-select the most recent running scan if none selected
      if (!activeScanId && scans.length > 0) {
        const running = scans.find((s) => s.status === "running");
        if (running) setActiveScanId(running.id);
      }
    } catch {}
  }, [activeScanId]);

  useEffect(() => {
    refresh();
    const interval = setInterval(refresh, 30000);
    return () => clearInterval(interval);
  }, [refresh]);

  return (
    <ScanContext.Provider value={{ activeScan, activeScanId, recentScans, loading, setActiveScanId, refresh }}>
      {children}
    </ScanContext.Provider>
  );
}

export function useScanContext() {
  const ctx = useContext(ScanContext);
  if (!ctx) throw new Error("useScanContext must be used within ScanProvider");
  return ctx;
}
