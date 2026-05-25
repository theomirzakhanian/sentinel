import { motion } from "framer-motion";
import { ArrowLeft, ArrowRight, ShieldAlert, ShieldCheck } from "lucide-react";
import { ScoreGauge } from "./ScoreGauge";
import { SignalCard } from "./SignalCard";
import { AnalysisCard } from "./AnalysisCard";
import { CodeReviewCard } from "./CodeReviewCard";
import { RelatedSamplesCard } from "./RelatedSamplesCard";
import type { Report, Verdict } from "../lib/types";
import { STAGE_ORDER, formatBytes, formatDuration, shortHash } from "../lib/format";

interface Props {
  report: Report;
  scoreOverride?: number;  // optional pre-computed weighted score (matches live partialScore)
  source?: "fresh" | "history";
  onScanAnother: () => void;
  onBackToHistory?: () => void;
}

export function VerdictScreen({
  report,
  scoreOverride,
  source = "fresh",
  onScanAnother,
  onBackToHistory,
}: Props) {
  const verdict = report.final_verdict;
  const score = scoreOverride ?? extractScore(report) ?? 0;
  const signalByStage = Object.fromEntries(report.signals.map((s) => [s.stage, s]));
  const durationSeconds =
    (new Date(report.completed_at).getTime() - new Date(report.started_at).getTime()) / 1000;

  const isBlock = verdict === "BLOCK";
  const ringClr = isBlock
    ? "var(--color-threat-block)"
    : "var(--color-threat-allow)";

  return (
    <div className="flex h-full w-full flex-col overflow-hidden">
      {/* Hero band */}
      <VerdictHero verdict={verdict} score={score} />

      {/* File metadata strip */}
      <div className="shrink-0 border-y border-line bg-surface-0/40 px-8 py-4">
        <div className="flex items-baseline justify-between gap-8">
          <div className="min-w-0 flex-1">
            <h2 className="truncate text-base font-medium tracking-tight text-ink">
              {report.file_name}
            </h2>
            <p className="mt-0.5 font-mono text-[11px] text-ink-muted">
              {shortHash(report.sha256)} · {formatBytes(report.size_bytes)} · scanned in {formatDuration(durationSeconds)}
            </p>
          </div>
          {source === "history" && onBackToHistory ? (
            <button
              onClick={onBackToHistory}
              className="focus-ring group inline-flex items-center gap-2 rounded-md border border-line bg-surface-2 px-4 py-2 text-xs font-semibold uppercase tracking-wider text-ink-body transition-all duration-base ease-tesla hover:bg-surface-3 hover:text-ink"
            >
              <ArrowLeft size={14} className="transition-transform duration-base ease-tesla group-hover:-translate-x-0.5" />
              Back to History
            </button>
          ) : (
            <button
              onClick={onScanAnother}
              className="focus-ring group inline-flex items-center gap-2 rounded-md bg-accent px-4 py-2 text-xs font-semibold uppercase tracking-wider text-[#0a0d0f] transition-all duration-base ease-tesla hover:bg-accent-hover"
              style={{ boxShadow: `0 0 0 1px ${ringClr}33` }}
            >
              Scan another file
              <ArrowRight size={14} className="transition-transform duration-base ease-tesla group-hover:translate-x-0.5" />
            </button>
          )}
        </div>
      </div>

      {/* Body — min-h-0 so flex-1 allows scroll instead of squishing siblings */}
      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-8 py-6">
        {/* Headline analysis (what is this file) */}
        <AnalysisCard report={report} />

        {/* Per-stage signal cards */}
        {STAGE_ORDER.map((stage) => (
          <SignalCard key={stage} stage={stage} signal={signalByStage[stage]} />
        ))}

        {/* Decompiled code review */}
        <CodeReviewCard report={report} />

        {/* SentinelNet — related samples in our local corpus */}
        <RelatedSamplesCard report={report} />

        {/* Reasons / aggregator math */}
        {report.reasons.length > 0 && (
          <div className="card-dark mt-2 shrink-0 overflow-hidden rounded-lg">
            <header className="border-b border-line px-4 py-2.5">
              <h3 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
                Aggregator breakdown
              </h3>
            </header>
            <ul className="divide-y divide-line font-mono text-[11px]">
              {report.reasons.map((r, i) => (
                <li
                  key={i}
                  className="whitespace-pre-wrap break-words px-4 py-2 text-ink-body"
                >
                  {r}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}

function VerdictHero({ verdict, score }: { verdict: Verdict; score: number }) {
  const isBlock = verdict === "BLOCK";
  const Icon = isBlock ? ShieldAlert : ShieldCheck;
  const color = isBlock ? "var(--color-threat-block)" : "var(--color-threat-allow)";
  const bg = isBlock ? "var(--color-threat-block-bg)" : "var(--color-threat-allow-bg)";

  return (
    <div className="relative shrink-0 overflow-hidden">
      <div
        className="px-8 pt-6 pb-4"
        style={{
          background: `linear-gradient(180deg, ${bg} 0%, transparent 100%)`,
        }}
      >
        <div className="flex items-center justify-between gap-8">
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
            className="flex items-center gap-4"
          >
            <Icon size={32} strokeWidth={1.75} style={{ color }} />
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-ink-muted">
                Verdict
              </p>
              <h1
                className="font-sans text-[44px] font-bold leading-none tracking-tight"
                style={{ color }}
              >
                {verdict === "BLOCK" ? "BLOCKED" : "ALLOWED"}
              </h1>
            </div>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1], delay: 0.08 }}
          >
            <ScoreGauge score={score} size={220} />
          </motion.div>
        </div>
      </div>
    </div>
  );
}

function extractScore(r: Report): number | null {
  // Try to parse "weighted score: +0.434" from the reasons trail.
  for (const line of r.reasons) {
    const m = line.match(/weighted score:\s*([+-]?\d*\.\d+)/);
    if (m) return parseFloat(m[1]);
  }
  return null;
}
