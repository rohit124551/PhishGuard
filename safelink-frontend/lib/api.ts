import { ScanResult, ScanError } from "@/types/scan";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const TIMEOUT_MS = 10_000;

export async function analyzeURL(url: string): Promise<ScanResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    const response = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "Unknown server error");
      const err: ScanError = {
        type: "unknown",
        message: `Server returned ${response.status}: ${text}`,
      };
      throw err;
    }

    const data: ScanResult = await response.json();
    return data;
  } catch (e: unknown) {
    if (e instanceof Error && e.name === "AbortError") {
      const err: ScanError = {
        type: "timeout",
        message: "Request timed out after 10 seconds. Please try again.",
      };
      throw err;
    }
    if (e instanceof TypeError && e.message.includes("fetch")) {
      const err: ScanError = {
        type: "network",
        message: "Cannot connect to the scanner backend. Is it running?",
      };
      throw err;
    }
    // Re-throw typed errors
    throw e;
  } finally {
    clearTimeout(timer);
  }
}
