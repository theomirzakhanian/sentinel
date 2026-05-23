export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)} ms`;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds - m * 60);
  return `${m}m ${s}s`;
}

export function relTime(iso: string | number): string {
  const t = typeof iso === "string" ? new Date(iso).getTime() : iso;
  const dt = Date.now() - t;
  if (dt < 60_000) return "just now";
  if (dt < 3_600_000) return `${Math.floor(dt / 60_000)}m ago`;
  if (dt < 86_400_000) return `${Math.floor(dt / 3_600_000)}h ago`;
  return `${Math.floor(dt / 86_400_000)}d ago`;
}

export function shortHash(sha: string): string {
  return `${sha.slice(0, 8)}…${sha.slice(-4)}`;
}

export const STAGE_LABEL: Record<string, string> = {
  virustotal: "VirusTotal",
  triage: "Triage sandbox",
  ai_review: "AI deep dive",
};

export const STAGE_ORDER = ["virustotal", "triage", "ai_review"] as const;
