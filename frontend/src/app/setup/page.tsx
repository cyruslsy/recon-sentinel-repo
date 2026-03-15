"use client";

import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api";
import { useRouter } from "next/navigation";

const STEPS = [
  { label: "Organization", required: true },
  { label: "Project", required: true },
  { label: "API Keys", required: true },
  { label: "Target", required: false },
];

export default function SetupPage() {
  const { user, loading } = useAuth();
  const router = useRouter();
  const [step, setStep] = useState(0);
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  // Step 1 state
  const [orgName, setOrgName] = useState("");
  const [orgId, setOrgId] = useState("");

  // Step 2 state
  const [projectName, setProjectName] = useState("");
  const [projectId, setProjectId] = useState("");

  // Step 3 state — multiple API keys
  const [addedKeys, setAddedKeys] = useState<string[]>([]);
  const [currentService, setCurrentService] = useState("anthropic");
  const [currentKey, setCurrentKey] = useState("");

  // Step 4 state
  const [targetValue, setTargetValue] = useState("");
  const [inputType, setInputType] = useState("domain");

  useEffect(() => {
    if (!loading && !user) router.push("/login");
    if (!loading && user && user.setup_completed) router.push("/dashboard");
  }, [user, loading, router]);

  if (loading || !user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-sentinel-bg">
        <p className="text-sentinel-muted text-sm animate-pulse">Loading...</p>
      </div>
    );
  }

  if (user.setup_completed) return null;

  async function handleStep1(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const org = await api.createOrg({ name: orgName });
      setOrgId(org.id);
      setStep(1);
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Failed to create organization");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleStep2(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const project = await api.createProject(orgId, { name: projectName });
      setProjectId(project.id);
      setStep(2);
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Failed to create project");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleAddKey(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await api.addApiKey({ service_name: currentService, api_key: currentKey });
      setAddedKeys((prev) => [...prev, currentService]);
      setCurrentKey("");
      // Auto-select next unadded service
      const services = ["anthropic", "shodan", "virustotal", "hibp"];
      const next = services.find((s) => !addedKeys.includes(s) && s !== currentService);
      if (next) setCurrentService(next);
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Failed to add API key");
    } finally {
      setSubmitting(false);
    }
  }

  function handleStep3Continue() {
    setStep(3);
  }

  async function handleStep4(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      await api.createTarget(projectId, { target_value: targetValue, input_type: inputType });
      await finishSetup();
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Failed to add target");
    } finally {
      setSubmitting(false);
    }
  }

  async function finishSetup() {
    try {
      await api.completeSetup();
      router.push("/dashboard");
    } catch (err: unknown) {
      setError((err as { detail?: string })?.detail || "Failed to complete setup");
    }
  }

  const inputClass = "w-full bg-sentinel-bg border border-sentinel-border rounded px-3 py-2 text-sm focus:outline-none focus:border-sentinel-accent transition-colors";
  const labelClass = "block text-xs text-sentinel-muted mb-1.5";
  const btnClass = "w-full bg-sentinel-accent hover:bg-sentinel-accent/90 text-white font-medium py-2 rounded text-sm transition-colors disabled:opacity-50";

  return (
    <div className="min-h-screen flex items-center justify-center bg-sentinel-bg">
      <div className="w-full max-w-md">
        <div className="text-center mb-6">
          <h1 className="text-2xl font-semibold">
            <span className="text-sentinel-accent">⦿</span> Initial Setup
          </h1>
          <p className="text-sentinel-muted text-sm mt-1">
            Configure your platform in a few steps
          </p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center justify-center gap-2 mb-6">
          {STEPS.map((s, i) => (
            <div key={s.label} className="flex items-center gap-2">
              <div
                className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-medium border ${
                  i < step
                    ? "bg-sentinel-green border-sentinel-green text-white"
                    : i === step
                    ? "bg-sentinel-accent border-sentinel-accent text-white"
                    : "border-sentinel-border text-sentinel-muted"
                }`}
              >
                {i < step ? "\u2713" : i + 1}
              </div>
              {i < STEPS.length - 1 && (
                <div className={`w-6 h-px ${i < step ? "bg-sentinel-green" : "bg-sentinel-border"}`} />
              )}
            </div>
          ))}
        </div>

        <div className="text-center text-xs text-sentinel-muted mb-4">
          Step {step + 1} of {STEPS.length}: {STEPS[step].label}
          {!STEPS[step].required && " (Optional)"}
        </div>

        {error && (
          <div className="bg-sentinel-red/10 border border-sentinel-red/20 text-sentinel-red text-sm p-3 rounded mb-4">
            {error}
          </div>
        )}

        {/* Step 1: Create Organization */}
        {step === 0 && (
          <form onSubmit={handleStep1} className="bg-sentinel-surface border border-sentinel-border rounded-lg p-6 space-y-4">
            <p className="text-sm text-sentinel-muted">
              Organizations group your projects and team members.
            </p>
            <div>
              <label className={labelClass}>Organization Name</label>
              <input
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="e.g. Acme Security"
                className={inputClass}
                required
              />
            </div>
            <button type="submit" disabled={submitting} className={btnClass}>
              {submitting ? "Creating..." : "Create Organization"}
            </button>
          </form>
        )}

        {/* Step 2: Create Project */}
        {step === 1 && (
          <form onSubmit={handleStep2} className="bg-sentinel-surface border border-sentinel-border rounded-lg p-6 space-y-4">
            <p className="text-sm text-sentinel-muted">
              Projects contain targets and scans. You can create more later.
            </p>
            <div>
              <label className={labelClass}>Project Name</label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                placeholder="e.g. Q1 2026 Pentest"
                className={inputClass}
                required
              />
            </div>
            <button type="submit" disabled={submitting} className={btnClass}>
              {submitting ? "Creating..." : "Create Project"}
            </button>
          </form>
        )}

        {/* Step 3: Configure API Keys */}
        {step === 2 && (
          <div className="bg-sentinel-surface border border-sentinel-border rounded-lg p-6 space-y-4">
            <p className="text-sm text-sentinel-muted">
              Add API keys for AI analysis and scanning services. You can add more later in Settings.
            </p>

            {/* Added keys */}
            {addedKeys.length > 0 && (
              <div className="space-y-1.5">
                {addedKeys.map((s) => (
                  <div key={s} className="flex items-center gap-2 text-sm text-sentinel-green">
                    <span>&#10003;</span>
                    <span className="capitalize">{s}</span>
                    <span className="text-sentinel-muted text-xs">configured</span>
                  </div>
                ))}
              </div>
            )}

            {/* Add key form */}
            <form onSubmit={handleAddKey} className="space-y-3">
              <div>
                <label className={labelClass}>Service</label>
                <select
                  value={currentService}
                  onChange={(e) => setCurrentService(e.target.value)}
                  className={inputClass}
                >
                  <optgroup label="AI Analysis">
                    <option value="anthropic" disabled={addedKeys.includes("anthropic")}>
                      Anthropic (Claude) {addedKeys.includes("anthropic") ? "- added" : ""}
                    </option>
                    <option value="openai" disabled={addedKeys.includes("openai")}>
                      OpenAI {addedKeys.includes("openai") ? "- added" : ""}
                    </option>
                    <option value="gemini" disabled={addedKeys.includes("gemini")}>
                      Google Gemini {addedKeys.includes("gemini") ? "- added" : ""}
                    </option>
                  </optgroup>
                  <optgroup label="Scanning &amp; OSINT">
                    <option value="shodan" disabled={addedKeys.includes("shodan")}>
                      Shodan {addedKeys.includes("shodan") ? "- added" : ""}
                    </option>
                    <option value="virustotal" disabled={addedKeys.includes("virustotal")}>
                      VirusTotal {addedKeys.includes("virustotal") ? "- added" : ""}
                    </option>
                    <option value="hibp" disabled={addedKeys.includes("hibp")}>
                      Have I Been Pwned {addedKeys.includes("hibp") ? "- added" : ""}
                    </option>
                    <option value="github" disabled={addedKeys.includes("github")}>
                      GitHub (code leak search) {addedKeys.includes("github") ? "- added" : ""}
                    </option>
                  </optgroup>
                </select>
              </div>
              <div>
                <label className={labelClass}>API Key</label>
                <input
                  type="password"
                  value={currentKey}
                  onChange={(e) => setCurrentKey(e.target.value)}
                  placeholder="Paste your API key"
                  className={inputClass}
                  required
                />
              </div>
              <button type="submit" disabled={submitting || !currentKey} className={btnClass}>
                {submitting ? "Adding..." : "Add Key"}
              </button>
            </form>

            {/* Continue button */}
            <button
              type="button"
              onClick={handleStep3Continue}
              className={`w-full font-medium py-2 rounded text-sm transition-colors ${
                addedKeys.length > 0
                  ? "bg-sentinel-accent hover:bg-sentinel-accent/90 text-white"
                  : "border border-sentinel-border hover:bg-sentinel-hover text-sentinel-text"
              }`}
            >
              {addedKeys.length > 0
                ? `Continue (${addedKeys.length} key${addedKeys.length > 1 ? "s" : ""} added)`
                : "Skip \u2014 configure later in Settings"}
            </button>
          </div>
        )}

        {/* Step 4: Add Target (Optional) */}
        {step === 3 && (
          <form onSubmit={handleStep4} className="bg-sentinel-surface border border-sentinel-border rounded-lg p-6 space-y-4">
            <p className="text-sm text-sentinel-muted">
              Add your first reconnaissance target, or skip this for now.
            </p>
            <div>
              <label className={labelClass}>Target</label>
              <input
                type="text"
                value={targetValue}
                onChange={(e) => setTargetValue(e.target.value)}
                placeholder="e.g. example.com or 192.168.1.0/24"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Type</label>
              <select
                value={inputType}
                onChange={(e) => setInputType(e.target.value)}
                className={inputClass}
              >
                <option value="domain">Domain</option>
                <option value="ip">IP Address</option>
                <option value="cidr">CIDR Range</option>
                <option value="url">URL</option>
              </select>
            </div>
            <button type="submit" disabled={submitting || !targetValue} className={btnClass}>
              {submitting ? "Adding..." : "Add Target & Finish"}
            </button>
            <button
              type="button"
              onClick={finishSetup}
              className="w-full border border-sentinel-border hover:bg-sentinel-hover text-sentinel-text font-medium py-2 rounded text-sm transition-colors"
            >
              Skip & Finish Setup
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
