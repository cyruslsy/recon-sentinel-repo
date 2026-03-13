"use client";

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { fetcher } from "@/lib/api";

export default function ChatPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";
  const [sessionId, setSessionId] = useState("");
  const [messages, setMessages] = useState<any[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { initSession(); }, [scanId]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  async function initSession() {
    try {
      const sessions = await fetcher(`/chat/sessions${scanId ? `?scan_id=${scanId}` : ""}`);
      if (sessions.length > 0) {
        setSessionId(sessions[0].id);
        const msgs = await fetcher(`/chat/sessions/${sessions[0].id}/messages`);
        setMessages(msgs);
      } else {
        // Create new session
        const res = await fetch(`/api/v1/chat/sessions${scanId ? `?scan_id=${scanId}` : ""}`, {
          method: "POST", credentials: "include",
        });
        const session = await res.json();
        setSessionId(session.id);
      }
    } catch {}
  }

  async function handleSend(e: React.FormEvent) {
    e.preventDefault();
    if (!input.trim() || !sessionId) return;
    const content = input.trim();
    setInput("");
    setSending(true);

    // Optimistic: show user message immediately
    setMessages((prev) => [...prev, { role: "user", content, id: `temp-${Date.now()}` }]);

    try {
      const res = await fetch(`/api/v1/chat/sessions/${sessionId}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ content }),
      });
      const aiMsg = await res.json();
      setMessages((prev) => [...prev, aiMsg]);
    } catch {
      setMessages((prev) => [...prev, { role: "ai", content: "Failed to get response. Try again.", id: `err-${Date.now()}` }]);
    }
    setSending(false);
  }

  const slashCommands = [
    { cmd: "/findings", desc: "Search findings" },
    { cmd: "/summarize", desc: "Scan summary" },
    { cmd: "/mitre", desc: "MITRE lookup" },
  ];

  return (
    <AppLayout>
      <div className="max-w-3xl mx-auto flex flex-col h-[calc(100vh-6rem)]">
        <div className="flex items-center justify-between mb-4">
          <h1 className="text-xl font-semibold">AI Copilot</h1>
          {scanId && <span className="text-xs text-sentinel-muted">Scan: {scanId.slice(0, 8)}</span>}
        </div>

        {/* Messages */}
        <div className="flex-1 overflow-y-auto space-y-3 mb-4 pr-2">
          {messages.length === 0 && (
            <div className="text-center py-12">
              <p className="text-sentinel-muted text-sm mb-4">Ask anything about your scan results.</p>
              <div className="flex gap-2 justify-center flex-wrap">
                {slashCommands.map((s) => (
                  <button key={s.cmd} onClick={() => setInput(s.cmd + " ")}
                    className="text-xs bg-sentinel-card border border-sentinel-border px-3 py-1.5 rounded hover:border-sentinel-accent/50">
                    <span className="text-sentinel-accent font-mono">{s.cmd}</span>
                    <span className="text-sentinel-muted ml-1">{s.desc}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map((msg, i) => (
            <div key={msg.id || i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
              <div className={`max-w-[80%] rounded-lg px-4 py-2.5 text-sm ${
                msg.role === "user"
                  ? "bg-sentinel-accent/20 text-sentinel-text"
                  : "bg-sentinel-card border border-sentinel-border"
              }`}>
                {msg.role === "ai" && (
                  <p className="text-[10px] text-sentinel-muted mb-1">
                    {msg.model_used || "AI"} {msg.cost_usd ? `· $${Number(msg.cost_usd).toFixed(4)}` : ""}
                  </p>
                )}
                <p className="whitespace-pre-wrap">{msg.content}</p>
              </div>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <form onSubmit={handleSend} className="flex gap-2">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about findings, MITRE techniques, or type /slash commands..."
            className="flex-1 bg-sentinel-surface border border-sentinel-border rounded-lg px-4 py-2.5 text-sm focus:outline-none focus:border-sentinel-accent"
            disabled={sending}
          />
          <button type="submit" disabled={sending || !input.trim()}
            className="bg-sentinel-accent text-white px-5 py-2.5 rounded-lg text-sm font-medium disabled:opacity-50">
            {sending ? "..." : "Send"}
          </button>
        </form>
      </div>
    </AppLayout>
  );
}
