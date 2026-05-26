"use client";

import { useState, useRef, KeyboardEvent } from "react";
import { ShieldCheck, Loader2 } from "lucide-react";
import { ScanState } from "@/types/scan";

interface URLInputProps {
  onScan: (url: string) => void;
  scanState: ScanState;
  value: string;
  onChange: (v: string) => void;
}

function isValidURL(raw: string): boolean {
  try {
    const url = raw.startsWith("http") ? raw : `https://${raw}`;
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

export function URLInput({ onScan, scanState, value, onChange }: URLInputProps) {
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const isScanning = scanState === "scanning";

  const handleSubmit = () => {
    const trimmed = value.trim();
    if (!trimmed) {
      setError("Please enter a URL to scan.");
      return;
    }
    if (!isValidURL(trimmed)) {
      setError("Enter a valid URL (e.g. https://example.com)");
      return;
    }
    setError(null);
    const normalized = trimmed.startsWith("http") ? trimmed : `https://${trimmed}`;
    onScan(normalized);
  };

  const handleKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") handleSubmit();
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div
        className={`
          flex items-center gap-3
          bg-surface border rounded-xl px-4 py-3
          transition-all duration-200
          ${error ? "border-red-500/60" : isScanning ? "border-purple-500/50 shadow-[0_0_20px_rgba(124,58,237,0.3)]" : "border-white/10"}
        `}
        style={{ background: "var(--color-surface)" }}
      >
        <ShieldCheck className="w-5 h-5 text-purple-400 shrink-0" />

        <input
          ref={inputRef}
          id="url-input"
          type="url"
          placeholder="Paste URL here… e.g. https://example.com"
          value={value}
          onChange={(e) => {
            onChange(e.target.value);
            if (error) setError(null);
          }}
          onKeyDown={handleKey}
          disabled={isScanning}
          autoComplete="off"
          spellCheck={false}
          className={`
            input-glow flex-1 bg-transparent text-sm text-slate-100
            placeholder:text-slate-600
            disabled:opacity-50 disabled:cursor-not-allowed
            border border-transparent rounded-lg px-2 py-1
            transition-all duration-200
          `}
        />

        <button
          id="scan-button"
          onClick={handleSubmit}
          disabled={isScanning}
          className={`
            btn-gradient
            shrink-0 flex items-center gap-2
            px-5 py-2 rounded-lg
            text-white text-sm font-semibold
            disabled:opacity-60 disabled:cursor-not-allowed
            transition-all duration-150
          `}
        >
          {isScanning ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning…
            </>
          ) : (
            "Scan URL"
          )}
        </button>
      </div>

      {error && (
        <p className="mt-2 text-xs text-red-400 pl-2 flex items-center gap-1">
          <span>⚠</span> {error}
        </p>
      )}
    </div>
  );
}
