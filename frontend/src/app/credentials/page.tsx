"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { CredentialLeak, CredentialSummary } from "@/lib/types";

export default function CredentialsPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";
  const [creds, setCreds] = useState<CredentialLeak[]>([]);
  const [summary, setSummary] = useState<CredentialSummary | null>(null);

  useEffect(() => { if (scanId) loadCreds(); }, [scanId]);

  async function loadCreds() {
    try {
      setCreds(await api.listCredentials(scanId));
      setSummary(await api.credentialSummary(scanId));
    } catch {}
  }

  return (
    <AppLayout>
      <div className="max-w-6xl mx-auto">
        <h1 className="text-xl font-semibold mb-6">Credential Leaks</h1>

        {!scanId ? (
          <p className="text-sentinel-muted text-sm py-12 text-center">Select a scan to view credential leak data.</p>
        ) : (
          <>
            {/* Summary Cards */}
            {summary && (
              <div className="grid grid-cols-4 gap-4 mb-6">
                <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
                  <p className="text-xs text-sentinel-muted">Total Emails</p>
                  <p className="text-2xl font-semibold mt-1">{summary.total_emails}</p>
                </div>
                <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
                  <p className="text-xs text-sentinel-muted">With Passwords</p>
                  <p className="text-2xl font-semibold mt-1 text-sentinel-orange">{summary.with_passwords}</p>
                </div>
                <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
                  <p className="text-xs text-sentinel-muted">Plaintext Passwords</p>
                  <p className="text-2xl font-semibold mt-1 text-sentinel-red">{summary.with_plaintext}</p>
                </div>
                <div className="bg-sentinel-card border border-sentinel-border rounded-lg p-4">
                  <p className="text-xs text-sentinel-muted">Password Reuse</p>
                  <p className="text-2xl font-semibold mt-1 text-sentinel-purple">{summary.password_reuse_count}</p>
                </div>
              </div>
            )}

            {/* Credential Table */}
            <div className="bg-sentinel-surface border border-sentinel-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-sentinel-border text-xs text-sentinel-muted">
                    <th className="text-left py-2 px-4 font-medium">Email</th>
                    <th className="text-left py-2 px-4 font-medium">Breaches</th>
                    <th className="text-left py-2 px-4 font-medium">Password</th>
                    <th className="text-left py-2 px-4 font-medium">Sources</th>
                  </tr>
                </thead>
                <tbody>
                  {creds.map((c) => (
                    <tr key={c.id} className="border-b border-sentinel-border/30 hover:bg-sentinel-hover/50">
                      <td className="py-2.5 px-4 text-sm font-mono">{c.email}</td>
                      <td className="py-2.5 px-4 text-sm">{c.breach_count}</td>
                      <td className="py-2.5 px-4">
                        {c.has_plaintext ? (
                          <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded">PLAINTEXT</span>
                        ) : c.has_password ? (
                          <span className="text-xs bg-orange-500/20 text-orange-400 px-2 py-0.5 rounded">HASHED</span>
                        ) : (
                          <span className="text-xs text-sentinel-muted">None</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-xs text-sentinel-muted">{(c.sources || []).join(", ")}</td>
                    </tr>
                  ))}
                  {creds.length === 0 && (
                    <tr><td colSpan={4} className="py-8 text-center text-sentinel-muted text-sm">No credential leaks found.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </AppLayout>
  );
}
