"use client";

import { useState, useCallback } from "react";
import { ScanResult, ScanState, ScanError } from "@/types/scan";
import { analyzeURL } from "@/lib/api";

interface ScanHookState {
  result: ScanResult | null;
  scanState: ScanState;
  error: ScanError | null;
}

export function useScan() {
  const [state, setState] = useState<ScanHookState>({
    result: null,
    scanState: "idle",
    error: null,
  });

  const scan = useCallback(async (url: string) => {
    setState({ result: null, scanState: "scanning", error: null });
    try {
      const result = await analyzeURL(url);
      setState({ result, scanState: "done", error: null });
      
      try {
        const history = JSON.parse(localStorage.getItem('safelink_history') || '[]');
        const newHistory = [result, ...history.filter((item: ScanResult) => item.url !== result.url)].slice(0, 10);
        localStorage.setItem('safelink_history', JSON.stringify(newHistory));
      } catch (err) {
        console.error("Failed to save history", err);
      }
    } catch (e: unknown) {
      const err = e as ScanError;
      setState({
        result: null,
        scanState: "error",
        error: err ?? {
          type: "unknown",
          message: "An unexpected error occurred.",
        },
      });
    }
  }, []);

  const reset = useCallback(() => {
    setState({ result: null, scanState: "idle", error: null });
  }, []);

  return { ...state, scan, reset };
}
