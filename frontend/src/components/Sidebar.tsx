"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { useState, useEffect } from "react";
import { api } from "@/lib/api";

interface NavItem {
  href: string;
  label: string;
  icon: string;
  badgeKey?: string;
}

const NAV_GROUPS = [
  {
    label: null,
    items: [
      { href: "/dashboard", label: "Dashboard", icon: "◉" },
    ],
  },
  {
    label: "Scanning",
    items: [
      { href: "/dashboard", label: "Dashboard", icon: "◉" },
      { href: "/scans", label: "Scans", icon: "⟐" },
      { href: "/targets", label: "Targets", icon: "◎" },
      { href: "/agents", label: "Agents", icon: "⚡" },
      { href: "/health", label: "Health Feed", icon: "♡", badgeKey: "health" },
      { href: "/scope", label: "Scope", icon: "⊘" },
    ],
  },
  {
    label: "Results",
    items: [
      { href: "/findings", label: "Findings", icon: "🎯" },
      { href: "/mitre", label: "MITRE ATT&CK", icon: "⬡" },
      { href: "/credentials", label: "Credentials", icon: "🔑" },
      { href: "/reports", label: "Reports", icon: "📄" },
      { href: "/history", label: "Scan Diff", icon: "🔄" },
    ],
  },
  {
    label: "Tools",
    items: [
      { href: "/chat", label: "AI Copilot", icon: "💬", badgeKey: "chat" },
      { href: "/settings", label: "Settings", icon: "⚙" },
    ],
  },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const [badges, setBadges] = useState<Record<string, number | string>>({});

  // Poll for badge counts (lightweight — replace with WebSocket context in production)
  useEffect(() => {
    async function fetchBadges() {
      try {
        const scans = await api.listScans("limit=10");
        const running = scans.filter((s: { status: string }) => s.status === "running").length;
        if (running > 0) {
          setBadges(prev => ({ ...prev, health: running }));
        } else {
          setBadges(prev => {
            const next = { ...prev };
            delete next.health;
            return next;
          });
        }
      } catch {}
    }
    fetchBadges();
    const interval = setInterval(fetchBadges, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <aside className="w-56 h-screen fixed left-0 top-0 bg-sentinel-surface border-r border-sentinel-border flex flex-col">
      {/* Logo */}
      <div className="p-4 border-b border-sentinel-border">
        <h1 className="text-lg font-semibold tracking-tight">
          <span className="text-sentinel-accent">⦿</span> Recon Sentinel
        </h1>
        <p className="text-xs text-sentinel-muted mt-0.5">AI-Powered Recon</p>
      </div>

      {/* Navigation */}
      <nav aria-label="Main navigation" className="flex-1 py-2 overflow-y-auto">
        {NAV_GROUPS.map((group, gi) => (
          <div key={gi} className={gi > 0 ? "mt-3" : ""}>
            {group.label && (
              <p className="text-[9px] uppercase tracking-wider text-sentinel-muted/60 px-6 py-1 font-semibold">
                {group.label}
              </p>
            )}
            {group.items.map((item) => {
              const active = pathname?.startsWith(item.href);
              const badge = item.badgeKey ? badges[item.badgeKey] : null;

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`flex items-center gap-3 px-4 py-2 mx-2 rounded-md text-sm transition-colors ${
                    active
                      ? "bg-sentinel-accent/10 text-sentinel-accent"
                      : "text-sentinel-muted hover:text-sentinel-text hover:bg-sentinel-hover"
                  }`}
                >
                  <span className="text-base w-5 text-center">{item.icon}</span>
                  <span className="flex-1">{item.label}</span>
                  {badge !== null && badge !== undefined && badge !== 0 && (
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${
                      typeof badge === "string"
                        ? "bg-sentinel-accent/20 text-sentinel-accent"
                        : "bg-sentinel-red/20 text-sentinel-red"
                    }`}>
                      {badge}
                    </span>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

      {/* User */}
      {user && (
        <div className="p-3 border-t border-sentinel-border">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-7 h-7 rounded-full bg-sentinel-accent/20 flex items-center justify-center text-xs font-medium text-sentinel-accent">
              {user.display_name?.charAt(0).toUpperCase()}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-medium truncate">{user.display_name}</p>
              <p className="text-[10px] text-sentinel-muted truncate">{user.role}</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="w-full text-xs text-sentinel-muted hover:text-sentinel-red py-1 text-left transition-colors"
          >
            Sign out
          </button>
        </div>
      )}
    </aside>
  );
}
