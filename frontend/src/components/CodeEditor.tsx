"use client";

import React, { useState, useEffect } from "react";
import Editor from "@monaco-editor/react";
import { Code, Copy, Check, Trash2, Sliders } from "lucide-react";

interface CodeEditorProps {
  code: string;
  onChange: (value: string | undefined) => void;
  onRunAudit: () => void;
  language?: string;
}

export const CodeEditor: React.FC<CodeEditorProps> = ({
  code,
  onChange,
  onRunAudit,
  language = "python",
}) => {
  const [copied, setCopied] = useState(false);
  const [isMounted, setIsMounted] = useState(false);
  const [editorMode, setEditorMode] = useState<"monaco" | "text">("monaco");

  useEffect(() => {
    setIsMounted(true);
  }, []);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lineCount = code.split("\n").length;

  return (
    <div className="h-full flex flex-col bg-[#0d1117] border border-[#30363d] rounded-lg overflow-hidden shadow-sm">
      {/* Editor Top Bar */}
      <div className="h-10 px-3 bg-[#161b22] border-b border-[#30363d] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Code className="h-4 w-4 text-slate-400" />
          <span className="text-xs font-semibold text-slate-200 tracking-wide">
            Source Code
          </span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#21262d] text-slate-300 border border-[#30363d] font-mono">
            {language}
          </span>
          <span className="text-[11px] text-slate-500 font-mono">
            {lineCount} {lineCount === 1 ? "line" : "lines"}
          </span>
        </div>

        <div className="flex items-center gap-1.5">
          <button
            onClick={() => setEditorMode(editorMode === "monaco" ? "text" : "monaco")}
            title="Toggle Monaco vs Raw Editor"
            className="px-2 py-1 text-[11px] font-medium text-slate-400 hover:text-slate-200 bg-[#21262d] hover:bg-[#30363d] rounded border border-[#30363d] transition"
          >
            {editorMode === "monaco" ? "Monaco IDE" : "Plain Editor"}
          </button>

          <button
            onClick={handleCopy}
            title="Copy Source Code"
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
                <span>Copy</span>
              </>
            )}
          </button>
          <button
            onClick={() => onChange("")}
            title="Clear Code"
            className="p-1 text-slate-400 hover:text-rose-400 hover:bg-rose-950/20 rounded border border-transparent hover:border-rose-900/30 transition"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Editor Container */}
      <div className="flex-1 w-full relative">
        {!isMounted ? (
          <div className="h-full w-full flex items-center justify-center bg-[#0d1117] text-slate-500 text-xs font-mono">
            Loading Editor...
          </div>
        ) : editorMode === "monaco" ? (
          <Editor
            height="100%"
            language={language}
            value={code}
            theme="vs-dark"
            onChange={onChange}
            options={{
              fontSize: 13.5,
              lineHeight: 21,
              fontFamily: "'JetBrains Mono', 'Fira Code', Consolas, 'Courier New', monospace",
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              automaticLayout: true,
              tabSize: 4,
              renderLineHighlight: "all",
              lineNumbers: "on",
              glyphMargin: false,
              folding: true,
              padding: { top: 12, bottom: 12 },
              cursorBlinking: "smooth",
              cursorSmoothCaretAnimation: "on",
              bracketPairColorization: { enabled: true },
            }}
            loading={
              <div className="h-full w-full flex items-center justify-center bg-[#0d1117] text-slate-500 text-xs font-mono">
                Initializing Monaco Editor...
              </div>
            }
          />
        ) : (
          <textarea
            value={code}
            onChange={(e) => onChange(e.target.value)}
            placeholder="Paste or write Python code here..."
            className="w-full h-full p-4 bg-[#0d1117] text-slate-200 font-mono text-xs outline-none resize-none leading-relaxed border-none"
            spellCheck={false}
          />
        )}
      </div>
    </div>
  );
};
