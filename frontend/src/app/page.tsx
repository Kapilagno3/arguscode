"use client";

import React, { useState, useEffect, useCallback } from "react";
import { Header } from "@/components/Header";
import { CodeEditor } from "@/components/CodeEditor";
import { DiffViewer } from "@/components/DiffViewer";
import { AuditReport } from "@/components/AuditReport";
import { PRESETS, CodePreset } from "@/lib/presets";
import { runCodeAudit, checkBackendHealth, AuditResponse } from "@/lib/api";
import { GitCompare, ShieldCheck, Code, AlertCircle, Sparkles } from "lucide-react";

export default function ArgusCodeDashboard() {
  const [selectedPresetId, setSelectedPresetId] = useState<string>(PRESETS[0].id);
  const [code, setCode] = useState<string>(PRESETS[0].code);
  const [auditResult, setAuditResult] = useState<AuditResponse | null>(null);
  const [activeTab, setActiveTab] = useState<"diff" | "report">("report");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // AI Provider & Custom Key Configuration
  const [provider, setProvider] = useState<string>("auto");
  const [apiKey, setApiKey] = useState<string>("");

  useEffect(() => {
    if (typeof window !== "undefined") {
      const savedKey = localStorage.getItem("argus_api_key") || "";
      const savedProvider = localStorage.getItem("argus_provider") || "auto";
      setApiKey(savedKey);
      setProvider(savedProvider);
    }
  }, []);

  // Check backend health periodically
  const pingHealth = useCallback(async () => {
    try {
      await checkBackendHealth();
      setIsBackendConnected(true);
    } catch {
      setIsBackendConnected(false);
    }
  }, []);

  useEffect(() => {
    pingHealth();
    const interval = setInterval(pingHealth, 8000);
    return () => clearInterval(interval);
  }, [pingHealth]);

  const handleSelectPreset = (preset: CodePreset | null) => {
    if (preset) {
      setSelectedPresetId(preset.id);
      setCode(preset.code);
      setErrorMessage(null);
    } else {
      setSelectedPresetId("");
    }
  };

  const handleRunAudit = async () => {
    if (!code.trim()) {
      setErrorMessage("Please enter some Python code before running an audit.");
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);

    try {
      const response = await runCodeAudit(code, "python", apiKey, provider);
      setAuditResult(response);
      if (response.findings.length > 0) {
        setActiveTab("report");
      }
    } catch (err: any) {
      const detail =
        err.response?.data?.detail ||
        err.message ||
        "Failed to connect to the backend server. Please verify backend is running on port 8000.";
      setErrorMessage(detail);
    } finally {
      setIsLoading(false);
    }
  };

  // Keyboard shortcut: Ctrl+Enter or Cmd+Enter to Run Audit
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        handleRunAudit();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [code, apiKey, provider]);

  const handleApplyRefactoring = (newCode: string) => {
    setCode(newCode);
  };

  return (
    <div className="h-screen w-screen flex flex-col bg-[#0a0c10] text-slate-100 overflow-hidden select-none">
      {/* Top Navigation & Controls */}
      <Header
        selectedPresetId={selectedPresetId}
        onSelectPreset={handleSelectPreset}
        onRunAudit={handleRunAudit}
        isLoading={isLoading}
        isBackendConnected={isBackendConnected}
        provider={provider}
        setProvider={setProvider}
        apiKey={apiKey}
        setApiKey={setApiKey}
      />

      {/* Error Banner */}
      {errorMessage && (
        <div className="bg-rose-950/80 border-b border-rose-800/60 px-5 py-2 flex items-center justify-between text-xs text-rose-200 shrink-0">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
            <span>{errorMessage}</span>
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-rose-400 hover:text-rose-200 font-bold ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Split-Screen Workspace */}
      <main className="flex-1 min-h-0 p-3 grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* Left Pane: Code Editor */}
        <section className="h-full min-h-0">
          <CodeEditor
            code={code}
            onChange={(val) => {
              setCode(val ?? "");
              if (selectedPresetId) setSelectedPresetId("");
            }}
            onRunAudit={handleRunAudit}
            language="python"
          />
        </section>

        {/* Right Pane: Multi-Tab Diff & Audit Report */}
        <section className="h-full min-h-0 flex flex-col bg-[#0d1117] border border-[#30363d] rounded-lg overflow-hidden shadow-sm">
          {/* Tab Navigation Header */}
          <div className="h-10 px-3 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between shrink-0">
            <div className="flex items-center gap-1 bg-[#0d1117] p-0.5 rounded-md border border-[#30363d]">
              <button
                onClick={() => setActiveTab("report")}
                className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded transition ${
                  activeTab === "report"
                    ? "bg-[#21262d] text-white shadow-xs font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <ShieldCheck className="h-3.5 w-3.5" />
                <span>Audit Report</span>
                {auditResult && (
                  <span className="ml-1 text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-mono">
                    {auditResult.findings.length}
                  </span>
                )}
              </button>

              <button
                onClick={() => setActiveTab("diff")}
                className={`flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded transition ${
                  activeTab === "diff"
                    ? "bg-[#21262d] text-white shadow-xs font-semibold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <GitCompare className="h-3.5 w-3.5" />
                <span>Unified Diff</span>
              </button>
            </div>

            {auditResult && (
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-slate-400">Score:</span>
                <span
                  className={`text-xs font-bold font-mono px-2 py-0.5 rounded ${
                    auditResult.summary.quality_score >= 80
                      ? "bg-emerald-950/60 text-emerald-400 border border-emerald-800/40"
                      : auditResult.summary.quality_score >= 50
                      ? "bg-amber-950/60 text-amber-400 border border-amber-800/40"
                      : "bg-rose-950/60 text-rose-400 border border-rose-800/40"
                  }`}
                >
                  {auditResult.summary.quality_score}/100
                </span>
              </div>
            )}
          </div>

          {/* Tab Viewport */}
          <div className="flex-1 min-h-0 relative">
            {activeTab === "report" ? (
              <AuditReport
                summary={auditResult?.summary || null}
                findings={auditResult?.findings || []}
                astData={auditResult?.ast_data || null}
                isLoading={isLoading}
              />
            ) : (
              <DiffViewer
                originalCode={code}
                refactoredCode={auditResult?.refactored_code || code}
                gitDiff={auditResult?.git_diff || "diff --git a/source.py b/source.py\n# Run audit to generate refactoring diff"}
                language="python"
                onApplyRefactoring={handleApplyRefactoring}
              />
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
