"use client";

import React, { useState } from "react";
import { PRESETS, CodePreset } from "@/lib/presets";
import { testLLMApiKey } from "@/lib/api";
import { Play, Sparkles, Shield, RefreshCw, CheckCircle2, AlertTriangle, Code2, Settings, Key, X, Check, Loader2, CheckCircle, AlertCircle } from "lucide-react";

interface HeaderProps {
  selectedPresetId: string;
  onSelectPreset: (preset: CodePreset | null) => void;
  onRunAudit: () => void;
  isLoading: boolean;
  isBackendConnected: boolean;
  provider: string;
  setProvider: (p: string) => void;
  apiKey: string;
  setApiKey: (k: string) => void;
}

export const Header: React.FC<HeaderProps> = ({
  selectedPresetId,
  onSelectPreset,
  onRunAudit,
  isLoading,
  isBackendConnected,
  provider,
  setProvider,
  apiKey,
  setApiKey,
}) => {
  const [showSettings, setShowSettings] = useState(false);
  const [tempApiKey, setTempApiKey] = useState(apiKey);
  const [tempProvider, setTempProvider] = useState(provider);
  const [savedToast, setSavedToast] = useState(false);
  const [isTestingKey, setIsTestingKey] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; message: string } | null>(null);

  const handleTestKey = async () => {
    if (!tempApiKey.trim()) {
      setTestResult({ valid: false, message: "Please enter an API key first." });
      return;
    }
    setIsTestingKey(true);
    setTestResult(null);
    try {
      const selectedProv = tempProvider === "gemini" ? "gemini" : "openai";
      const result = await testLLMApiKey(tempApiKey, selectedProv);
      setTestResult({
        valid: result.valid,
        message: result.valid ? result.message : (result.error || result.message),
      });
    } catch (err: any) {
      setTestResult({
        valid: false,
        message: err?.response?.data?.detail || err.message || "Failed to reach backend test endpoint.",
      });
    } finally {
      setIsTestingKey(false);
    }
  };

  const handleSaveSettings = () => {
    setApiKey(tempApiKey);
    setProvider(tempProvider);
    if (typeof window !== "undefined") {
      localStorage.setItem("argus_api_key", tempApiKey);
      localStorage.setItem("argus_provider", tempProvider);
    }
    setSavedToast(true);
    setTimeout(() => {
      setSavedToast(false);
      setShowSettings(false);
    }, 1000);
  };

  return (
    <>
      <header className="h-14 border-b border-[#30363d] bg-[#0d1117] px-4 flex items-center justify-between shrink-0">
        {/* Brand & Logo */}
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-lg bg-[#161b22] border border-[#30363d] flex items-center justify-center text-blue-400 shadow-sm">
            <Shield className="h-4 w-4 stroke-[2.2]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-tight text-white flex items-center gap-1.5">
                Argus Code
                <span className="text-[10px] font-mono font-medium px-1.5 py-0.2 rounded bg-[#161b22] text-slate-400 border border-[#30363d]">
                  v1.0
                </span>
              </h1>
            </div>
            <p className="text-[11px] text-slate-400">
              Automated Security & Performance Remediation
            </p>
          </div>
        </div>

        {/* Controls & Actions */}
        <div className="flex items-center gap-2.5">
          {/* Backend Connectivity Status */}
          <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#161b22] border border-[#30363d] text-xs">
            <span className={`h-2 w-2 rounded-full ${isBackendConnected ? "bg-emerald-500" : "bg-amber-500"}`}></span>
            <span className={`text-[11px] font-medium ${isBackendConnected ? "text-slate-300" : "text-amber-400"}`}>
              {isBackendConnected ? "Ready" : "Connecting..."}
            </span>
          </div>

          {/* Model / Engine Config Button */}
          <button
            onClick={() => {
              setTempApiKey(apiKey);
              setTempProvider(provider);
              setTestResult(null);
              setShowSettings(true);
            }}
            title="Configure AI Engine / API Keys"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md bg-[#161b22] hover:bg-[#21262d] text-slate-300 hover:text-white border border-[#30363d] text-xs font-medium transition"
          >
            <Settings className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden md:inline text-[11px]">
              Engine: <span className="text-slate-200 capitalize">{provider}</span>
            </span>
          </button>

          {/* Demo Preset Selector */}
          <div className="relative">
            <select
              value={selectedPresetId}
              onChange={(e) => {
                const found = PRESETS.find((p) => p.id === e.target.value);
                onSelectPreset(found || null);
              }}
              className="bg-[#161b22] hover:bg-[#21262d] text-slate-200 text-xs font-medium rounded-md border border-[#30363d] focus:border-blue-500 py-1.5 px-3 pr-7 transition cursor-pointer appearance-none outline-none"
            >
              <option value="">Custom Code</option>
              {PRESETS.map((preset) => (
                <option key={preset.id} value={preset.id}>
                  {preset.name}
                </option>
              ))}
            </select>
            <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-slate-400">
              <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
              </svg>
            </div>
          </div>

          {/* Run Audit Primary Button - Solid, Clean, Shortened */}
          <button
            onClick={onRunAudit}
            disabled={isLoading}
            className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-md text-xs font-semibold shadow-sm transition active:scale-[0.99] ${
              isLoading
                ? "bg-blue-600/60 text-blue-200 cursor-not-allowed border border-blue-500/50"
                : "bg-blue-600 hover:bg-blue-500 text-white border border-blue-500"
            }`}
          >
            {isLoading ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 animate-spin text-white" />
                <span>Auditing...</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current text-white" />
                <span>Run Argus</span>
                <kbd className="hidden md:inline-block ml-1 px-1 py-0.2 text-[10px] bg-blue-700/80 rounded border border-blue-400/30 text-blue-100 font-mono">
                  Ctrl+↵
                </kbd>
              </>
            )}
          </button>
        </div>
      </header>

      {/* Engine & API Key Modal */}
      {showSettings && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
          <div className="bg-[#161b22] border border-[#30363d] rounded-xl w-full max-w-lg p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#30363d] pb-3">
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-blue-400" />
                <h3 className="text-sm font-bold text-white">Multi-Agent Engine & API Key Settings</h3>
              </div>
              <button
                onClick={() => setShowSettings(false)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Analysis Engine Provider
                </label>
                <select
                  value={tempProvider}
                  onChange={(e) => {
                    setTempProvider(e.target.value);
                    setTestResult(null);
                  }}
                  className="w-full bg-[#0d1117] border border-[#30363d] rounded-lg p-2.5 text-slate-200 outline-none focus:border-blue-500"
                >
                  <option value="auto">Auto (Offline AST + LLM fallback)</option>
                  <option value="heuristic">Heuristic AST Analyzer (100% Offline)</option>
                  <option value="openai">OpenAI (GPT-4o-mini)</option>
                  <option value="gemini">Google Gemini (Gemini 1.5 Pro)</option>
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  The Offline AST analyzer evaluates custom code locally using AST rules without needing an external API key.
                </p>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Custom LLM API Key (OpenAI / Gemini)
                </label>
                <div className="flex gap-2">
                  <input
                    type="password"
                    value={tempApiKey}
                    onChange={(e) => {
                      setTempApiKey(e.target.value);
                      setTestResult(null);
                    }}
                    placeholder="sk-... or AIzaSy..."
                    className="flex-1 bg-[#0d1117] border border-[#30363d] rounded-lg p-2.5 text-slate-200 font-mono outline-none focus:border-blue-500"
                  />
                  <button
                    type="button"
                    onClick={handleTestKey}
                    disabled={isTestingKey || !tempApiKey.trim()}
                    className="px-3 py-2 bg-[#21262d] hover:bg-[#30363d] disabled:opacity-50 text-slate-200 rounded-lg border border-[#30363d] font-semibold text-xs transition flex items-center gap-1.5 shrink-0"
                  >
                    {isTestingKey ? (
                      <>
                        <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" />
                        <span>Testing...</span>
                      </>
                    ) : (
                      <span>Test Key</span>
                    )}
                  </button>
                </div>
                <p className="text-[11px] text-slate-500 mt-1">
                  Saved securely in your browser localStorage. Click &quot;Test Key&quot; to verify your connection live.
                </p>

                {/* Key Test Results Feedback */}
                {testResult && (
                  <div
                    className={`mt-2.5 p-2.5 rounded-lg border text-xs flex items-start gap-2 ${
                      testResult.valid
                        ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-300"
                        : "bg-rose-950/40 border-rose-800/60 text-rose-300"
                    }`}
                  >
                    {testResult.valid ? (
                      <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    )}
                    <span className="leading-relaxed">{testResult.message}</span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#1f293d]">
              <button
                onClick={() => setShowSettings(false)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveSettings}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold shadow-md transition"
              >
                {savedToast ? (
                  <>
                    <Check className="w-3.5 h-3.5" />
                    <span>Saved!</span>
                  </>
                ) : (
                  <span>Save Configuration</span>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
