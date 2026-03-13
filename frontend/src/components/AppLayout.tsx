"use client";

import { useAuth } from "@/lib/auth";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import Sidebar from "@/components/Sidebar";
import ErrorBoundary from "@/components/ErrorBoundary";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) router.push("/login");
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-sentinel-muted animate-pulse">Loading...</div>
      </div>
    );
  }

  if (!user) return null;

  return (
    <div className="flex min-h-screen">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:top-2 focus:left-2 focus:bg-sentinel-accent focus:text-white focus:px-4 focus:py-2 focus:rounded focus:text-sm"
      >
        Skip to content
      </a>
      <Sidebar />
      <main role="main" id="main-content" className="ml-56 flex-1 p-6" tabIndex={-1}>
        <ErrorBoundary>{children}</ErrorBoundary>
      </main>
    </div>
  );
}
