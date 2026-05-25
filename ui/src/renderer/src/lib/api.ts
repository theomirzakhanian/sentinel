/**
 * Thin Sentinel daemon client. Resolves base URL via the preload bridge,
 * then drives /scan + /scan/<id>/events.
 */
import type { HistoryEntry, Report, SentinelEvent } from "./types";

interface PreloadAPI {
  getDaemonUrl(): Promise<string | { error: string }>;
  pickFile(): Promise<string | null>;
  pathForFile(file: File): string;
}

declare global {
  interface Window {
    sentinel: PreloadAPI;
  }
}

let cachedBase: string | null = null;

export async function baseUrl(): Promise<string> {
  if (cachedBase) return cachedBase;
  const r = await window.sentinel.getDaemonUrl();
  if (typeof r === "string") {
    cachedBase = r;
    return r;
  }
  throw new Error(r.error || "daemon unreachable");
}

export interface DaemonSettings {
  version: string;
  ai_mode: "mcp" | "headless" | "static";
  block_threshold: number;
  env_file: string;
  env_file_exists: boolean;
  keys: {
    VT_API_KEY: string | null;
    TRIAGE_API_KEY: string | null;
    MALWAREBAZAAR_API_KEY: string | null;
  };
  engine: {
    claude_bin: string;
    claude_model: string | null;
    ghidra_home: string | null;
    analyze_headless_path: string | null;
  };
}

export async function fetchSettings(): Promise<DaemonSettings> {
  const base = await baseUrl();
  const r = await fetch(`${base}/settings`);
  if (!r.ok) throw new Error(`settings: HTTP ${r.status}`);
  return (await r.json()) as DaemonSettings;
}

export async function fetchHistory(): Promise<HistoryEntry[]> {
  const base = await baseUrl();
  const r = await fetch(`${base}/history`);
  if (!r.ok) throw new Error(`history: HTTP ${r.status}`);
  const body = (await r.json()) as { history: HistoryEntry[] };
  return body.history;
}

export async function startScan(filePath: string, options: { skipTriage?: boolean; skipAi?: boolean; upload?: boolean } = {}): Promise<string> {
  const base = await baseUrl();
  const r = await fetch(`${base}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      file_path: filePath,
      options: {
        skip_triage: options.skipTriage ?? false,
        skip_ai: options.skipAi ?? false,
        upload: options.upload ?? false,
      },
    }),
  });
  if (!r.ok) throw new Error(`scan: HTTP ${r.status}`);
  const body = (await r.json()) as { scan_id: string };
  return body.scan_id;
}

export async function cancelScan(scanId: string): Promise<void> {
  const base = await baseUrl();
  await fetch(`${base}/scan/${scanId}`, { method: "DELETE" });
}

export async function fetchReport(scanId: string): Promise<Report | null> {
  const base = await baseUrl();
  const r = await fetch(`${base}/scan/${scanId}`);
  if (!r.ok) return null;
  const body = (await r.json()) as { status: string; report?: Report };
  return body.report ?? null;
}

/**
 * Subscribe to SSE events for a running scan. Returns an unsubscribe fn.
 * The browser's EventSource handles reconnects but our daemon emits an
 * "end" event that signals we should close.
 */
export async function subscribeToScan(
  scanId: string,
  onEvent: (e: SentinelEvent) => void,
): Promise<() => void> {
  const base = await baseUrl();
  const es = new EventSource(`${base}/scan/${scanId}/events`);
  es.onmessage = (ev) => {
    try {
      const parsed = JSON.parse(ev.data) as SentinelEvent;
      onEvent(parsed);
      if (parsed.type === "end") es.close();
    } catch {
      // ignore malformed lines
    }
  };
  es.onerror = () => {
    // EventSource will attempt to reconnect automatically; only close on end.
  };
  return () => es.close();
}
