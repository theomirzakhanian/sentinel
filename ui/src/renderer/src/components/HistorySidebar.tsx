import { useEffect, useState } from "react";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import { fetchHistory } from "../lib/api";
import type { HistoryEntry } from "../lib/types";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function relTime(iso: string): string {
  const t = new Date(iso).getTime();
  const dt = Date.now() - t;
  if (dt < 60_000) return "just now";
  if (dt < 3_600_000) return `${Math.floor(dt / 60_000)}m ago`;
  if (dt < 86_400_000) return `${Math.floor(dt / 3_600_000)}h ago`;
  return `${Math.floor(dt / 86_400_000)}d ago`;
}

interface Props {
  refreshKey: number;
  onSelect?: (reportFile: string) => void;
}

export function HistorySidebar({ refreshKey, onSelect }: Props) {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setErr(null);
    fetchHistory()
      .then((h) => alive && setEntries(h))
      .catch((e: Error) => alive && setErr(e.message))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  return (
    <aside className="card-dark flex h-full w-72 shrink-0 flex-col overflow-hidden rounded-xl">
      <header className="border-b border-line px-4 py-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
          History
        </h2>
      </header>
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="space-y-2 p-3">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-14 animate-pulse rounded-md bg-surface-2"
                style={{ animationDelay: `${i * 80}ms` }}
              />
            ))}
          </div>
        )}
        {err && (
          <p className="p-4 text-sm text-ink-muted">
            Daemon offline. Start it with{" "}
            <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs">
              sentinel serve
            </code>
          </p>
        )}
        {!loading && !err && entries.length === 0 && (
          <p className="p-4 text-sm text-ink-muted">
            No scans yet. Drop a file to begin.
          </p>
        )}
        {!loading && entries.length > 0 && (
          <ul className="divide-y divide-line">
            {entries.map((e) => {
              const block = e.final_verdict === "BLOCK";
              return (
                <li
                  key={e.report_file}
                  onClick={() => onSelect?.(e.report_file)}
                  className="group cursor-pointer px-4 py-3 transition-colors duration-fast ease-tesla hover:bg-surface-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <p className="min-w-0 flex-1 truncate text-sm font-medium text-ink">
                      {e.file_name}
                    </p>
                    <span
                      className={[
                        "shrink-0 rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
                        block
                          ? "bg-[color:var(--color-threat-block-bg)] text-threat-block"
                          : "bg-[color:var(--color-threat-allow-bg)] text-threat-allow",
                      ].join(" ")}
                      title={e.final_verdict}
                    >
                      {block ? <ShieldAlert size={11} className="inline" /> : <ShieldCheck size={11} className="inline" />}
                    </span>
                  </div>
                  <p className="mt-1 truncate font-mono text-[11px] text-ink-muted">
                    {e.sha256.slice(0, 10)} · {formatBytes(e.size_bytes)}
                  </p>
                  <p className="mt-0.5 text-[11px] text-ink-muted">
                    {relTime(e.completed_at)}
                  </p>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </aside>
  );
}
