"use client";

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import AppLayout from "@/components/AppLayout";
import { api } from "@/lib/api";
import type { ChatMessage, ChatSession } from "@/lib/types";

export default function ChatPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams?.get("scan_id") || "";
  const [sessionId, setSessionId] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [targetName, setTargetName] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => { initSession(); }, [scanId]);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);
  useEffect(() => {
    if (scanId) {
      api.getScan(scanId).then((s: { target_value?: string }) => {
        if (s.target_value) setTargetName(s.target_value);
      }).catch(() => {});
    }
  }, [scanId]);

  async function initSession() {
    try {
      const sessions = await api.listChatSessions(scanId || undefined);
      if (sessions.length > 0) {
        setSessionId(sessions[0].id);
        const msgs = await api.listChatMessages(sessions[0].id);
        setMessages(msgs);
      } else {
        // Create new session
        const session = await api.createChatSession(scanId || undefined);
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
      const aiMsg = await api.sendChatMessage(sessionId, content);
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
          {scanId && <span className="text-xs text-sentinel-muted">Scan: {targetName || scanId.slice(0, 8)}</span>}
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
                <div className="whitespace-pre-wrap [&>p]:mb-2"
                  dangerouslySetInnerHTML={msg.role === "ai" ? {
                    __html: (() => {
                      // Safe markdown: escape HTML first, then apply formatting
                      const safe = msg.content
                        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
                      return safe
                        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
                        .replace(/`([^`]+)`/g, '<code class="text-[13px] bg-sentinel-bg px-1 py-0.5 rounded font-mono">$1</code>')
                        .replace(/^### (.+)$/gm, '<p class="text-sm font-semibold mt-3 mb-1">$1</p>')
                        .replace(/^## (.+)$/gm, '<p class="text-base font-semibold mt-3 mb-1">$1</p>')
                        .replace(/^- (.+)$/gm, '<p class="pl-3">• $1</p>')
                        .replace(/\n/g, "<br/>");
                    })(),
                  } : undefined}
                >
                  {msg.role !== "ai" ? msg.content : undefined}
                </div>
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
            aria-label="Chat message input" placeholder="Ask about findings, MITRE techniques, or type /slash commands..."
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
