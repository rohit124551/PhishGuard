export interface CheckResult {
  name: string;
  score: number;
  status: "safe" | "warning" | "danger";
  reason: string;
}

export interface ScanResult {
  url: string;
  total_score: number;
  verdict: "safe" | "suspicious" | "dangerous";
  checks: CheckResult[];
  scanned_at: string;
}

export type ScanState = "idle" | "scanning" | "done" | "error";

export interface ScanError {
  type: "network" | "timeout" | "invalid_url" | "unknown";
  message: string;
}
