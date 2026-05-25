import { useEffect, useState } from "react";
import { ArrowRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { fetchHistory } from "../lib/api";
import type { HistoryEntry } from "../lib/types";
import { formatBytes, relTime } from "../lib/format";

interface Props {
  refreshKey: number;
  onOpenReport: (reportFile: string) => void;
}

export function HistoryPage({ refreshKey, onOpenReport }: Props) {
  const [history, setHistory] = useState<HistoryEntry[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setErr(null);
    fetchHistory()
      .then((h) => alive && setHistory(h))
      .catch((e: Error) => alive && setErr(e.message));
    return () => {
      alive = false;
    };
  }, [refreshKey]);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden">
      <header className="shrink-0 border-b border-line px-8 py-6">
        <h1 className="text-2xl font-bold tracking-tight text-ink">History</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Every scan, most recent first. Click a row to re-open its verdict.
        </p>
      </header>

      <div className="flex-1 overflow-y-auto px-8 py-6">
        {err && (
          <p className="text-sm text-ink-muted">
            Daemon offline. Run <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]">sentinel serve</code>.
          </p>
        )}

        {!history && !err && (
          <div className="space-y-2">
            {[0, 1, 2, 3].map((i) => (
              <div
                key={i}
                className="h-16 animate-pulse rounded-md bg-surface-2"
                style={{ animationDelay: `${i * 80}ms` }}
              />
            ))}
          </div>
        )}

        {history && history.length === 0 && !err && (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <p className="text-base font-medium text-ink">No scans yet</p>
            <p className="mt-1 text-sm text-ink-muted">
              Drop a file on the Scan tab to begin building history.
            </p>
          </div>
        )}

        {history && history.length > 0 && (
          <ul className="space-y-1.5">
            {history.map((e) => (
              <HistoryRow
                key={e.report_file}
                entry={e}
                onClick={() => onOpenReport(e.report_file)}
              />
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function HistoryRow({
  entry,
  onClick,
}: {
  entry: HistoryEntry;
  onClick: () => void;
}) {
  const block = entry.final_verdict === "BLOCK";
  const Icon = block ? ShieldAlert : ShieldCheck;
  const pillClass = block
    ? "bg-[color:var(--color-threat-block-bg)] text-threat-block"
    : "bg-[color:var(--color-threat-allow-bg)] text-threat-allow";

  return (
    <li>
      <button
        onClick={onClick}
        className="focus-ring card-dark group flex w-full items-center gap-4 rounded-md px-5 py-4 text-left transition-colors duration-fast ease-tesla hover:bg-surface-2"
      >
        <span className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded ${pillClass}`}>
          <Icon size={16} strokeWidth={2} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline justify-between gap-3">
            <p className="truncate text-sm font-medium text-ink">{entry.file_name}</p>
            <span className="shrink-0 text-[11px] text-ink-muted">
              {relTime(entry.completed_at)}
            </span>
          </div>
          <p className="mt-0.5 truncate font-mono text-[11px] text-ink-muted">
            {entry.sha256.slice(0, 16)} · {formatBytes(entry.size_bytes)}
          </p>
        </div>
        <span
          className={`shrink-0 rounded px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${pillClass}`}
        >
          {entry.final_verdict}
        </span>
        <ArrowRight
          size={14}
          strokeWidth={2}
          className="shrink-0 text-ink-muted opacity-0 transition-all duration-fast ease-tesla group-hover:translate-x-0.5 group-hover:opacity-100"
        />
      </button>
    </li>
  );
}
