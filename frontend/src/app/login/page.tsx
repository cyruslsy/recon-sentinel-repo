"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";

export default function LoginPage() {
  const { login, register } = useAuth();
  const router = useRouter();
  const [needsSetup, setNeedsSetup] = useState<boolean | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    api.setupStatus().then((s) => setNeedsSetup(s.needs_setup)).catch(() => setNeedsSetup(false));
  }, []);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      router.push("/dashboard");
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  async function handleSetup(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await register(email, password, displayName);
      router.push("/dashboard");
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Setup failed");
    } finally {
      setLoading(false);
    }
  }

  if (needsSetup === null) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-sentinel-bg">
        <p className="text-sentinel-muted text-sm">Loading...</p>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-sentinel-bg">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-semibold">
            <span className="text-sentinel-accent">⦿</span> Recon Sentinel
          </h1>
          <p className="text-sentinel-muted text-sm mt-1">
            {needsSetup ? "Create the first admin account to get started" : "Sign in to your account"}
          </p>
        </div>

        {needsSetup ? (
          <form onSubmit={handleSetup} aria-label="Setup form" className="bg-sentinel-surface border border-sentinel-border rounded-lg p-6 space-y-4">
            {error && (
              <div className="bg-sentinel-red/10 border border-sentinel-red/20 text-sentinel-red text-sm p-3 rounded">
                {error}
              </div>
            )}

            <div className="bg-sentinel-accent/10 border border-sentinel-accent/20 text-sentinel-accent text-sm p-3 rounded">
              This is the initial setup. The first account will have admin privileges.
            </div>

            <div>
              <label className="block text-xs text-sentinel-muted mb-1.5">Display Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent transition-colors"
                required
              />
            </div>

            <div>
              <label className="block text-xs text-sentinel-muted mb-1.5">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent transition-colors"
                required
              />
            </div>

            <div>
              <label className="block text-xs text-sentinel-muted mb-1.5">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent transition-colors"
                required
                minLength={8}
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-sentinel-accent hover:bg-sentinel-accent/90 text-white font-medium py-2 rounded text-sm transition-colors disabled:opacity-50"
            >
              {loading ? "Creating admin..." : "Create Admin Account"}
            </button>
          </form>
        ) : (
          <>
            <form onSubmit={handleLogin} aria-label="Login form" className="bg-sentinel-surface border border-sentinel-border rounded-lg p-6 space-y-4">
              {error && (
                <div className="bg-sentinel-red/10 border border-sentinel-red/20 text-sentinel-red text-sm p-3 rounded">
                  {error}
                </div>
              )}

              <div>
                <label className="block text-xs text-sentinel-muted mb-1.5">Email</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent transition-colors"
                  required
                />
              </div>

              <div>
                <label className="block text-xs text-sentinel-muted mb-1.5">Password</label>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent transition-colors"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-sentinel-accent hover:bg-sentinel-accent/90 text-white font-medium py-2 rounded text-sm transition-colors disabled:opacity-50"
              >
                {loading ? "Signing in..." : "Sign in"}
              </button>
            </form>

            <p className="text-center text-sm text-sentinel-muted mt-4">
              Don&apos;t have an account?{" "}
              <a href="/register" className="text-sentinel-accent hover:underline">
                Register
              </a>
            </p>
          </>
        )}
      </div>
    </div>
  );
}
