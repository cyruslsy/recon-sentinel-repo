"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api, setAccessToken, getAccessToken } from "@/lib/api";
import type { User } from "@/lib/types";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Try to restore session on mount
    loadUser();
  }, []);

  async function loadUser() {
    try {
      const profile = await api.me();
      setUser(profile);
    } catch {
      setAccessToken(null);
    } finally {
      setLoading(false);
    }
  }

  async function login(email: string, password: string) {
    const data = await api.login(email, password);
    setAccessToken(data.access_token);
    const profile = await api.me();
    setUser(profile);
  }

  async function register(email: string, password: string, name: string) {
    const data = await api.register(email, password, name);
    setAccessToken(data.access_token);
    const profile = await api.me();
    setUser(profile);
  }

  async function logout() {
    try {
      await api.logout();
    } catch {}
    setAccessToken(null);
    setUser(null);
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
