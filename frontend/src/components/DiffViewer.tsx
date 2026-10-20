"use client";

import React, { useState, useEffect } from "react";
import { DiffEditor } from "@monaco-editor/react";
import { GitCompare, Copy, Check, ArrowRightLeft, CheckCircle2, SplitSquareVertical } from "lucide-react";

interface DiffViewerProps {
  originalCode: string;
  refactoredCode: string;
  gitDiff: string;
  language?: string;
  onApplyRefactoring: (newCode: string) => void;
}

export const DiffViewer: React.FC<DiffViewerProps> = ({
  originalCode,
  refactoredCode,
  gitDiff,
  language = "python",
  onApplyRefactoring,
}) => {
  const [copied, setCopied] = useState(false);
  const [applied, setApplied] = useState(false);
  const [isMounted, setIsMounted] = useState(false);
  const [isSideBySide, setIsSideBySide] = useState(true);
  const [viewMode, setViewMode] = useState<"diff-editor" | "raw-diff">("diff-editor");

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const handleCopyRefactored = () => {
    navigator.clipboard.writeText(refactoredCode);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleApply = () => {
    onApplyRefactoring(refactoredCode);
    setApplied(true);
    setTimeout(() => setApplied(false), 2500);
  };

  return (
    <div className="h-full flex flex-col bg-[#0d1117] border border-[#30363d] rounded-lg overflow-hidden shadow-sm">
      {/* Diff Viewer Top Toolbar */}
      <div className="h-10 px-3 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <GitCompare className="h-4 w-4 text-slate-400" />
          <span className="text-xs font-semibold text-slate-200 tracking-wide">
            Unified Git Diff
          </span>

          {/* View Mode Toggle */}
          <div className="flex items-center rounded-md bg-[#0d1117] border border-[#30363d] p-0.5 ml-1">
            <button
              onClick={() => setViewMode("diff-editor")}
              className={`px-2 py-0.5 text-[11px] font-medium rounded transition ${
                viewMode === "diff-editor"
                  ? "bg-[#21262d] text-white shadow-xs font-semibold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Side-by-Side
            </button>
            <button
              onClick={() => setViewMode("raw-diff")}
              className={`px-2 py-0.5 text-[11px] font-medium rounded transition ${
                viewMode === "raw-diff"
                  ? "bg-[#21262d] text-white shadow-xs font-semibold"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Raw Patch
            </button>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center gap-1.5">
          {viewMode === "diff-editor" && (
            <button
              onClick={() => setIsSideBySide(!isSideBySide)}
              title="Toggle Inline / Side-by-Side Diff"
              className="flex items-center gap-1 px-2 py-1 text-[11px] font-medium text-slate-300 hover:text-white bg-[#21262d] hover:bg-[#30363d] rounded border border-[#30363d] transition"
            >
              <SplitSquareVertical className="h-3.5 w-3.5 text-slate-400" />
              <span>{isSideBySide ? "Inline View" : "Split View"}</span>
            </button>
          )}

          <button
            onClick={handleCopyRefactored}
            title="Copy Clean Refactored Code"
            className="flex items-center gap-1 px-2.5 py-1 text-[11px] font-medium text-slate-300 hover:text-white bg-[#21262d] hover:bg-[#30363d] rounded border border-[#30363d] transition"
          >
            {copied ? (
              <>
                <Check className="h-3 w-3 text-emerald-400" />
                <span className="text-emerald-400">Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" />
                <span>Copy Refactored</span>
              </>
            )}
          </button>

          <button
            onClick={handleApply}
            disabled={applied}
            title="Apply Refactored Code to Source Editor"
            className="flex items-center gap-1.5 px-3 py-1 text-[11px] font-medium text-white bg-emerald-600 hover:bg-emerald-500 rounded-md border border-emerald-500 shadow-sm transition active:scale-[0.99]"
          >
            {applied ? (
              <>
                <CheckCircle2 className="h-3.5 w-3.5 text-white" />
                <span>Applied to Editor</span>
              </>
            ) : (
              <>
                <ArrowRightLeft className="h-3.5 w-3.5" />
                <span>Apply Refactor</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Editor Content Area */}
      <div className="flex-1 w-full relative">
        {!isMounted ? (
          <div className="h-full w-full flex items-center justify-center bg-[#0d1117] text-slate-500 text-xs font-mono">
            Loading Diff View...
          </div>
        ) : viewMode === "diff-editor" ? (
          <DiffEditor
            height="100%"
            language={language}
            original={originalCode}
            modified={refactoredCode}
            theme="vs-dark"
            options={{
              fontSize: 13,
              lineHeight: 20,
              fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, 'Courier New', monospace",
              readOnly: true,
              renderSideBySide: isSideBySide,
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              automaticLayout: true,
              renderOverviewRuler: false,
              padding: { top: 12, bottom: 12 },
              diffWordWrap: "on",
            }}
            loading={
              <div className="h-full w-full flex items-center justify-center bg-[#0d1117] text-slate-500 text-xs font-mono">
                Loading Monaco Diff Editor...
              </div>
            }
          />
        ) : (
          <div className="h-full w-full p-4 overflow-auto bg-[#0d1117] font-mono text-xs text-slate-300 select-text leading-relaxed">
            <pre className="whitespace-pre">
              {gitDiff.split("\n").map((line, i) => {
                let colorClass = "text-slate-400";
                let bgClass = "";
                if (line.startsWith("+") && !line.startsWith("+++")) {
                  colorClass = "text-emerald-400 font-semibold";
                  bgClass = "bg-emerald-950/20";
                } else if (line.startsWith("-") && !line.startsWith("---")) {
                  colorClass = "text-rose-400 font-semibold";
                  bgClass = "bg-rose-950/20";
                } else if (line.startsWith("@@")) {
                  colorClass = "text-cyan-400 font-bold";
                  bgClass = "bg-cyan-950/20";
                } else if (line.startsWith("diff --git")) {
                  colorClass = "text-blue-400 font-bold";
                }
                return (
                  <div key={i} className={`px-2 py-0.5 ${colorClass} ${bgClass} rounded-sm`}>
                    {line}
                  </div>
                );
              })}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
