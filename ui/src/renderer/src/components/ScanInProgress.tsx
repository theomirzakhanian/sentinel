import { motion } from "framer-motion";
import { Activity, X } from "lucide-react";
import { ScoreGauge } from "./ScoreGauge";
import { StageIndicator, type StageStatus } from "./StageIndicator";
import type { ScanState } from "../lib/useScan";
import type { Signal } from "../lib/types";
import { STAGE_LABEL, STAGE_ORDER, formatBytes, formatDuration, shortHash } from "../lib/format";

interface Props {
  state: ScanState;
  onCancel: () => void;
}

function stageStatus(stage: string, current: string | null, signal: Signal | undefined): StageStatus {
  if (signal) {
    if (signal.verdict === "SKIPPED") return "skipped";
    if (signal.verdict === "ALLOW") return "allow";
    if (signal.verdict === "BLOCK") return "block";
    return "warn";
  }
  if (current === stage) return "running";
  return "pending";
}

const STAGE_DESCRIPTION: Record<string, string> = {
  virustotal: "Multi-engine signature lookup",
  triage: "Sandbox detonation",
  ai_review: "Ghidra decompilation + Claude reasoning",
};

export function ScanInProgress({ state, onCancel }: Props) {
  const file = state.file;
  return (
    <div className="card-dark flex h-full w-full flex-col overflow-hidden rounded-xl">
      {/* Header strip */}
      <header className="flex shrink-0 items-center justify-between border-b border-line px-6 py-4">
        <div className="flex items-center gap-3">
          <motion.span
            animate={{ opacity: [0.5, 1, 0.5] }}
            transition={{ duration: 1.8, ease: "easeInOut", repeat: Infinity }}
            className="inline-block h-1.5 w-1.5 rounded-full bg-accent"
          />
          <div className="flex items-center gap-2">
            <Activity size={14} className="text-accent" />
            <span className="text-xs font-semibold uppercase tracking-[0.18em] text-ink">
              Analyzing
            </span>
          </div>
        </div>
        <button
          onClick={onCancel}
          className="focus-ring inline-flex items-center gap-1.5 rounded-md border border-line bg-surface-2 px-3 py-1.5 text-xs font-medium text-ink-body transition-colors duration-fast ease-tesla hover:bg-surface-3 hover:text-ink"
        >
          <X size={13} />
          Cancel scan
        </button>
      </header>

      {/* File strip */}
      {file && (
        <div className="border-b border-line bg-surface-0/40 px-6 py-3">
          <div className="flex items-baseline justify-between gap-6">
            <h1 className="truncate text-base font-medium tracking-tight text-ink">
              {file.name}
            </h1>
            <span className="shrink-0 font-mono text-[11px] text-ink-muted">
              {shortHash(file.sha256)} · {formatBytes(file.size)}
            </span>
          </div>
        </div>
      )}

      {/* Body: stages + gauge */}
      <div className="flex flex-1 items-center gap-8 px-6 py-8">
        <ol className="flex flex-1 flex-col gap-3">
          {STAGE_ORDER.map((stage, i) => {
            const sig = state.signals[stage];
            const status = stageStatus(stage, state.currentStage, sig);
            const isActive = status === "running";
            return (
              <li
                key={stage}
                className={[
                  "card-dark flex items-center gap-4 rounded-lg px-4 py-3 transition-colors duration-base ease-tesla",
                  isActive ? "border-accent/30" : "",
                ].join(" ")}
              >
                <span className="w-6 text-center font-mono text-xs text-ink-muted">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <StageIndicator status={status} size={28} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline justify-between gap-3">
                    <p className="text-sm font-medium text-ink">{STAGE_LABEL[stage]}</p>
                    {sig?.duration_seconds != null && (
                      <span className="font-mono text-[11px] tabular-nums text-ink-muted">
                        {formatDuration(sig.duration_seconds)}
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 truncate text-xs text-ink-muted">
                    {sig?.summary ??
                      (status === "running" ? "Working…" : STAGE_DESCRIPTION[stage])}
                  </p>
                </div>
              </li>
            );
          })}
        </ol>

        <div className="shrink-0">
          <ScoreGauge score={state.partialScore} size={240} label="EVIDENCE SCORE" />
        </div>
      </div>

      {/* Footer hint */}
      <footer className="shrink-0 border-t border-line px-6 py-3">
        <p className="text-[11px] text-ink-muted">
          Static analysis · file is never executed
        </p>
      </footer>
    </div>
  );
}
