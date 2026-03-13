"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth";

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard", icon: "◉" },
  { href: "/scans", label: "Scans", icon: "⟐" },
  { href: "/agents", label: "Agents", icon: "⚡" },
  { href: "/findings", label: "Findings", icon: "🎯" },
  { href: "/mitre", label: "MITRE ATT&CK", icon: "⬡" },
  { href: "/credentials", label: "Credentials", icon: "🔑" },
  { href: "/scope", label: "Scope", icon: "◎" },
  { href: "/reports", label: "Reports", icon: "📄" },
  { href: "/chat", label: "AI Copilot", icon: "💬" },
  { href: "/settings", label: "Settings", icon: "⚙" },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { user, logout } = useAuth();

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
      <nav className="flex-1 py-2 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const active = pathname?.startsWith(item.href);
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
              {item.label}
            </Link>
          );
        })}
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
