/**
 * Per-stage signal card on the verdict screen. Collapsed shows verdict + summary;
 * expanded reveals stage-specific evidence (VT stats, AI reasoning, Triage sigs).
 */
import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown } from "lucide-react";
import { StageIndicator, type StageStatus } from "./StageIndicator";
import type { Signal } from "../lib/types";
import { STAGE_LABEL, formatDuration } from "../lib/format";

interface Props {
  stage: string;
  signal: Signal | undefined;
}

function statusFor(signal: Signal | undefined): StageStatus {
  if (!signal) return "pending";
  if (signal.verdict === "SKIPPED") return "skipped";
  if (signal.verdict === "ALLOW") return "allow";
  if (signal.verdict === "BLOCK") return "block";
  return "warn";
}

function verdictPillClass(v: string): string {
  if (v === "ALLOW")
    return "bg-[color:var(--color-threat-allow-bg)] text-threat-allow";
  if (v === "BLOCK")
    return "bg-[color:var(--color-threat-block-bg)] text-threat-block";
  if (v === "SKIPPED") return "bg-surface-2 text-ink-muted";
  return "bg-[color:var(--color-threat-warn-bg)] text-threat-warn";
}

export function SignalCard({ stage, signal }: Props) {
  const [open, setOpen] = useState(false);
  const status = statusFor(signal);
  const v = signal?.verdict ?? "PENDING";

  return (
    <article className="card-dark shrink-0 overflow-hidden rounded-lg">
      <button
        onClick={() => setOpen((o) => !o)}
        className="focus-ring flex w-full items-center gap-4 overflow-hidden px-4 py-3 text-left transition-colors duration-fast ease-tesla hover:bg-surface-2"
      >
        <StageIndicator status={status} size={26} />
        <div className="min-w-0 flex-1 overflow-hidden">
          <div className="flex items-baseline justify-between gap-3">
            <h3 className="truncate text-sm font-medium text-ink">{STAGE_LABEL[stage] ?? stage}</h3>
            <div className="flex shrink-0 items-baseline gap-2">
              {signal?.duration_seconds != null && (
                <span className="font-mono text-[11px] tabular-nums text-ink-muted">
                  {formatDuration(signal.duration_seconds)}
                </span>
              )}
              <span
                className={`rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${verdictPillClass(v)}`}
              >
                {v}
              </span>
            </div>
          </div>
          {signal?.summary && (
            <p className="mt-0.5 truncate text-xs text-ink-muted">
              {signal.summary}
            </p>
          )}
        </div>
        <ChevronDown
          size={14}
          className={`shrink-0 text-ink-muted transition-transform duration-base ease-tesla ${open ? "rotate-180" : ""}`}
        />
      </button>

      <AnimatePresence initial={false}>
        {open && signal && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden border-t border-line"
          >
            <div className="bg-surface-0/60 px-4 py-4">
              <StageEvidence stage={stage} signal={signal} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </article>
  );
}

function StageEvidence({ stage, signal }: { stage: string; signal: Signal }) {
  if (stage === "virustotal") return <VTEvidence signal={signal} />;
  if (stage === "ai_review") return <AIEvidence signal={signal} />;
  if (stage === "triage") return <TriageEvidence signal={signal} />;
  return null;
}

function KV({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-3">
      <span className="w-32 shrink-0 text-[11px] uppercase tracking-wider text-ink-muted">{k}</span>
      <span className="text-xs text-ink-body">{v}</span>
    </div>
  );
}

function VTEvidence({ signal }: { signal: Signal }) {
  const stats = (signal.evidence?.stats as Record<string, number>) ?? {};
  const total = Object.values(stats).reduce<number>((a, b) => a + Number(b ?? 0), 0);
  const names = (signal.evidence?.names as string[]) ?? [];
  const firstSeen = signal.evidence?.first_submission_date as number | undefined;
  const reputation = signal.evidence?.reputation as number | undefined;

  return (
    <div className="space-y-2">
      <KV
        k="Detections"
        v={
          <span className="font-mono tabular-nums">
            {stats.malicious ?? 0} malicious · {stats.suspicious ?? 0} suspicious · {stats.undetected ?? 0} undetected · {total} engines
          </span>
        }
      />
      {firstSeen != null && (
        <KV
          k="First seen on VT"
          v={new Date(firstSeen * 1000).toISOString().slice(0, 10)}
        />
      )}
      {reputation != null && <KV k="Reputation" v={<span className="font-mono tabular-nums">{reputation}</span>} />}
      {names.length > 0 && (
        <KV
          k="Known names"
          v={
            <span className="font-mono text-[11px]">
              {names.slice(0, 4).join(", ")}
              {names.length > 4 && ` +${names.length - 4} more`}
            </span>
          }
        />
      )}
    </div>
  );
}

function AIEvidence({ signal }: { signal: Signal }) {
  const ev = signal.evidence ?? {};
  const mode = ev.mode as string | undefined;
  const reasoning = ev.reasoning as string | undefined;
  const indicators = (ev.indicators as string[]) ?? [];
  const functions = (ev.functions_reviewed as string[]) ?? [];
  const confidence = ev.confidence as number | undefined;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-4">
        {mode && (
          <span className="rounded bg-surface-2 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-ink-muted">
            mode · {mode}
          </span>
        )}
        {confidence != null && (
          <span className="font-mono text-[11px] tabular-nums text-ink-body">
            confidence {confidence.toFixed(2)}
          </span>
        )}
      </div>
      {reasoning && (
        <p className="text-xs leading-relaxed text-ink-body">{reasoning}</p>
      )}
      {indicators.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
            Indicators
          </p>
          <ul className="space-y-1">
            {indicators.map((ind, i) => (
              <li key={i} className="flex gap-2 text-xs text-ink-body">
                <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent" />
                <span>{ind}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {functions.length > 0 && (
        <KV
          k="Functions reviewed"
          v={
            <span className="font-mono text-[11px]">
              {functions.join(", ")}
            </span>
          }
        />
      )}
    </div>
  );
}

function TriageEvidence({ signal }: { signal: Signal }) {
  const ev = signal.evidence ?? {};
  const score = ev.score as number | undefined;
  const families = (ev.families as string[]) ?? [];
  const signatures = (ev.signatures as string[]) ?? [];
  return (
    <div className="space-y-2">
      {score != null && <KV k="Triage score" v={<span className="font-mono tabular-nums">{score} / 10</span>} />}
      {families.length > 0 && (
        <KV k="Families" v={<span className="font-mono text-[11px]">{families.join(", ")}</span>} />
      )}
      {signatures.length > 0 && (
        <div>
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
            Signatures
          </p>
          <ul className="grid grid-cols-2 gap-x-3 gap-y-1">
            {signatures.slice(0, 12).map((s, i) => (
              <li key={i} className="text-xs text-ink-body">{s}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
