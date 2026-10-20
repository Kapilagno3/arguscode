"use client";

import React, { useState } from "react";
import Markdown from "react-markdown";
import { Finding, ASTMetadata, AuditSummary } from "@/lib/api";
import {
  ShieldAlert,
  Zap,
  CheckCircle,
  AlertTriangle,
  Flame,
  FileCode,
  Activity,
  Layers,
  ArrowRight,
  Boxes,
  CodeXml,
  HelpCircle,
  Sparkles,
  RefreshCw,
} from "lucide-react";

interface AuditReportProps {
  summary: AuditSummary | null;
  findings: Finding[];
  astData: ASTMetadata | null;
  isLoading: boolean;
}

export const AuditReport: React.FC<AuditReportProps> = ({
  summary,
  findings,
  astData,
  isLoading,
}) => {
  const [filterType, setFilterType] = useState<string>("ALL");
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");

  if (isLoading) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 bg-[#0d1117] text-center">
        <RefreshCw className="w-7 h-7 text-blue-500 animate-spin mb-3" />
        <h3 className="text-xs font-semibold text-slate-200">
          Running AST & Multi-Agent Audit...
        </h3>
        <p className="text-[11px] text-slate-400 mt-1 max-w-sm">
          Analyzing Abstract Syntax Trees, evaluating CWE threat vectors, and synthesizing code refactoring.
        </p>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="h-full flex flex-col items-center justify-center p-8 bg-[#0d1117] text-center">
        <div className="w-10 h-10 rounded-lg bg-[#161b22] border border-[#30363d] flex items-center justify-center mb-2.5 text-slate-400">
          <Activity className="w-5 h-5" />
        </div>
        <h3 className="text-xs font-semibold text-slate-300">
          No Audit Generated Yet
        </h3>
        <p className="text-[11px] text-slate-500 mt-1 max-w-xs">
          Select a preset snippet or enter code, then click &ldquo;Run Argus&rdquo;.
        </p>
      </div>
    );
  }

  const score = summary.quality_score;
  let scoreColor = "text-emerald-400";
  let verdictBg = "bg-emerald-950/50 text-emerald-300 border-emerald-800/40";

  if (score < 50) {
    scoreColor = "text-rose-400";
    verdictBg = "bg-rose-950/50 text-rose-300 border-rose-800/40";
  } else if (score < 80) {
    scoreColor = "text-amber-400";
    verdictBg = "bg-amber-950/50 text-amber-300 border-amber-800/40";
  }

  const filteredFindings = findings.filter((f) => {
    if (filterType !== "ALL" && f.type.toLowerCase() !== filterType.toLowerCase()) return false;
    if (filterSeverity !== "ALL" && f.severity.toUpperCase() !== filterSeverity.toUpperCase()) return false;
    return true;
  });

  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const medCount = findings.filter((f) => f.severity === "MED").length;
  const lowCount = findings.filter((f) => f.severity === "LOW").length;

  return (
    <div className="h-full flex flex-col bg-[#0d1117] overflow-hidden">
      {/* Scrollable Audit Report Body */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Top Summary & Score Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Health Score Card */}
          <div className="p-3.5 rounded-lg border border-[#30363d] bg-[#161b22] flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                  Quality Score
                </span>
                <span className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border ${verdictBg}`}>
                  {summary.verdict}
                </span>
              </div>
              <div className="flex items-baseline gap-1.5 mt-2">
                <span className={`text-3xl font-bold font-mono tracking-tight ${scoreColor}`}>
                  {score}
                </span>
                <span className="text-xs text-slate-500 font-mono">/100</span>
              </div>
            </div>
            <div className="mt-3 pt-2.5 border-t border-[#21262d] flex items-center justify-between text-[11px] font-mono">
              <span className="text-rose-400 font-medium">{highCount} High</span>
              <span className="text-amber-400 font-medium">{medCount} Medium</span>
              <span className="text-slate-400 font-medium">{lowCount} Low</span>
            </div>
          </div>

          {/* AST Metrics Card */}
          {astData && (
            <div className="p-3.5 rounded-lg border border-[#30363d] bg-[#161b22] col-span-2 flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
                  <Boxes className="w-3.5 h-3.5 text-slate-400" />
                  AST Complexity & Metrics
                </span>
                <span className="text-[11px] text-slate-400 font-mono">
                  {astData.lines_of_code} LOC
                </span>
              </div>
              <div className="grid grid-cols-4 gap-2 mt-2">
                <div className="p-2 rounded bg-[#0d1117] border border-[#21262d] text-center">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider">Branches</div>
                  <div className="text-sm font-bold font-mono text-slate-100 mt-0.5">
                    {astData.complexity_score}
                  </div>
                </div>
                <div className="p-2 rounded bg-[#0d1117] border border-[#21262d] text-center">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider">Functions</div>
                  <div className="text-sm font-bold font-mono text-slate-100 mt-0.5">
                    {astData.functions.length}
                  </div>
                </div>
                <div className="p-2 rounded bg-[#0d1117] border border-[#21262d] text-center">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider">Classes</div>
                  <div className="text-sm font-bold font-mono text-slate-100 mt-0.5">
                    {astData.classes.length}
                  </div>
                </div>
                <div className="p-2 rounded bg-[#0d1117] border border-[#21262d] text-center">
                  <div className="text-[10px] text-slate-400 uppercase tracking-wider">Imports</div>
                  <div className="text-sm font-bold font-mono text-slate-100 mt-0.5">
                    {astData.imports.length}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Overview Box */}
        <div className="p-3 rounded-lg bg-[#161b22] border border-[#30363d] text-xs text-slate-300 leading-relaxed">
          <span className="font-semibold text-slate-100 mr-1.5">Executive Summary:</span>
          {summary.overview}
        </div>

        {/* AST Functions & Classes Drawer (if present) */}
        {astData && (astData.functions.length > 0 || astData.classes.length > 0) && (
          <div className="p-3 rounded-lg bg-[#161b22] border border-[#30363d] space-y-2">
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <CodeXml className="w-3.5 h-3.5 text-slate-400" />
              AST Symbol Declarations
            </div>
            <div className="flex flex-wrap gap-1.5 pt-0.5">
              {astData.functions.map((fn, i) => (
                <div
                  key={i}
                  className="px-2 py-0.5 rounded bg-[#0d1117] border border-[#21262d] text-[11px] font-mono text-slate-300"
                >
                  <span className="text-blue-400">def</span> {fn.name}(
                  {fn.args.join(", ")})
                  {fn.returns && (
                    <span className="text-emerald-400"> -&gt; {fn.returns}</span>
                  )}
                  <span className="text-slate-500 ml-1 text-[10px]">L{fn.lineno}</span>
                </div>
              ))}
              {astData.classes.map((cls, i) => (
                <div
                  key={i}
                  className="px-2 py-0.5 rounded bg-[#0d1117] border border-[#21262d] text-[11px] font-mono text-slate-300"
                >
                  <span className="text-purple-400">class</span> {cls.name}
                  {cls.bases.length > 0 && (
                    <span className="text-slate-400">({cls.bases.join(", ")})</span>
                  )}
                  <span className="text-slate-500 ml-1 text-[10px]">L{cls.lineno}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Findings Header & Filters */}
        <div className="pt-1">
          <div className="flex flex-wrap items-center justify-between gap-2.5 pb-2.5 border-b border-[#30363d]">
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                Detected Issues & Recommendations
              </h3>
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#21262d] text-slate-300 font-mono font-medium border border-[#30363d]">
                {findings.length}
              </span>
            </div>

            {/* Filter Pills */}
            <div className="flex items-center gap-1 text-[11px]">
              <button
                onClick={() => setFilterSeverity("ALL")}
                className={`px-2 py-0.5 rounded transition ${
                  filterSeverity === "ALL"
                    ? "bg-[#21262d] text-white font-medium border border-[#30363d]"
                    : "text-slate-400 hover:text-slate-200 border border-transparent"
                }`}
              >
                All ({findings.length})
              </button>
              {highCount > 0 && (
                <button
                  onClick={() => setFilterSeverity("HIGH")}
                  className={`px-2 py-0.5 rounded transition ${
                    filterSeverity === "HIGH"
                      ? "bg-rose-950/60 text-rose-300 font-medium border border-rose-800/50"
                      : "text-rose-400 hover:text-rose-300 border border-transparent"
                  }`}
                >
                  High ({highCount})
                </button>
              )}
              {medCount > 0 && (
                <button
                  onClick={() => setFilterSeverity("MED")}
                  className={`px-2 py-0.5 rounded transition ${
                    filterSeverity === "MED"
                      ? "bg-amber-950/60 text-amber-300 font-medium border border-amber-800/50"
                      : "text-amber-400 hover:text-amber-300 border border-transparent"
                  }`}
                >
                  Med ({medCount})
                </button>
              )}
              {lowCount > 0 && (
                <button
                  onClick={() => setFilterSeverity("LOW")}
                  className={`px-2 py-0.5 rounded transition ${
                    filterSeverity === "LOW"
                      ? "bg-blue-950/60 text-blue-300 font-medium border border-blue-800/50"
                      : "text-blue-400 hover:text-blue-300 border border-transparent"
                  }`}
                >
                  Low ({lowCount})
                </button>
              )}
            </div>
          </div>

          {/* Finding Cards */}
          <div className="mt-3 space-y-2.5">
            {filteredFindings.length === 0 ? (
              <div className="p-6 text-center rounded-lg bg-[#161b22] border border-[#30363d] text-slate-400 text-xs">
                No issues matching selected filter.
              </div>
            ) : (
              filteredFindings.map((finding, idx) => {
                let badgeColor = "bg-rose-950/50 text-rose-300 border-rose-800/50";
                if (finding.severity === "MED") {
                  badgeColor = "bg-amber-950/50 text-amber-300 border-amber-800/50";
                } else if (finding.severity === "LOW") {
                  badgeColor = "bg-blue-950/50 text-blue-300 border-blue-800/50";
                }

                return (
                  <div
                    key={idx}
                    className="p-3.5 rounded-lg bg-[#161b22] border border-[#30363d] hover:border-slate-600 transition space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`text-[10px] font-bold font-mono px-1.5 py-0.2 rounded border uppercase tracking-wider ${badgeColor}`}
                        >
                          {finding.severity}
                        </span>
                        <span className="text-[10px] font-medium px-1.5 py-0.2 rounded bg-[#21262d] text-slate-300 border border-[#30363d] capitalize">
                          {finding.type}
                        </span>
                        {finding.line && (
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#0d1117] text-slate-400 border border-[#21262d]">
                            Line {finding.line}
                          </span>
                        )}
                      </div>
                    </div>

                    <p className="text-xs text-slate-200 font-medium leading-relaxed">
                      {finding.message}
                    </p>

                    {finding.fix && (
                      <div className="p-2.5 rounded bg-[#0d1117] border border-[#21262d] text-xs">
                        <div className="text-[11px] font-semibold text-emerald-400 mb-0.5 flex items-center gap-1">
                          <CheckCircle className="w-3 h-3" />
                          Recommended Fix:
                        </div>
                        <div className="text-slate-300 prose prose-invert max-w-none text-xs leading-relaxed">
                          <Markdown>{finding.fix}</Markdown>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
