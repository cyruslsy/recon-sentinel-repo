"use client";

import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { useRouter } from "next/navigation";

export default function RegisterPage() {
  const { register } = useAuth();
  const router = useRouter();
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await register(email, password, displayName);
      router.push("/dashboard");
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Registration failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-sentinel-bg">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <h1 className="text-2xl font-semibold">
            <span className="text-sentinel-accent">⦿</span> Recon Sentinel
          </h1>
          <p className="text-sentinel-muted text-sm mt-1">Create your account</p>
        </div>

        <form onSubmit={handleSubmit} aria-label="Register form" className="bg-sentinel-surface border border-sentinel-border rounded-lg p-6 space-y-4">
          {error && (
            <div className="bg-sentinel-red/10 border border-sentinel-red/20 text-sentinel-red text-sm p-3 rounded">
              {error}
            </div>
          )}

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
            {loading ? "Creating account..." : "Create account"}
          </button>
        </form>

        <p className="text-center text-sm text-sentinel-muted mt-4">
          Already have an account?{" "}
          <a href="/login" className="text-sentinel-accent hover:underline">
            Sign in
          </a>
        </p>
      </div>
    </div>
  );
}
