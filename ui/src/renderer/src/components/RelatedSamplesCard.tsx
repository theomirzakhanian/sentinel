/**
 * SentinelNet Related Samples card.
 *
 * For the current scan, shows which other files in our local corpus share
 * similar decompiled functions. Helps the user see *why* a verdict is what it
 * is — "this binary's main loop matches a known NanoCore sample at 0.94
 * similarity" is way more convincing than a verdict pill alone.
 */
import { useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, GitBranch, ShieldAlert, ShieldCheck } from "lucide-react";
import type { Report } from "../lib/types";

interface RawMatch {
  file_sha256: string;
  file_name: string;
  function_name: string;
  verdict: "ALLOW" | "BLOCK";
  similarity: number;
  malware_class: string[];
  malware_family: string | null;
}

interface FunctionMatches {
  function_name: string;
  matches: RawMatch[];
}

interface Props {
  report: Report;
}

export function RelatedSamplesCard({ report }: Props) {
  const ai = report.signals.find((s) => s.stage === "ai_review");
  if (!ai) return null;
  const sn = (ai.evidence?.sentinelnet_matches as FunctionMatches[]) ?? [];
  if (sn.length === 0) return null;

  const hits = sn.filter((fm) => fm.matches.length > 0);

  // Aggregate stats across all matches for the card header
  const totalBlock = useMemo(
    () =>
      hits.reduce(
        (acc, fm) => acc + fm.matches.filter((m) => m.verdict === "BLOCK").length,
        0,
      ),
    [hits],
  );
  const totalAllow = useMemo(
    () =>
      hits.reduce(
        (acc, fm) => acc + fm.matches.filter((m) => m.verdict === "ALLOW").length,
        0,
      ),
    [hits],
  );

  if (hits.length === 0) {
    // Render an explicit "no matches" message instead of hiding — it's useful
    // signal in its own right ("this file is structurally novel").
    return (
      <article className="card-dark shrink-0 overflow-hidden rounded-xl">
        <header className="flex items-center gap-2.5 border-b border-line px-5 py-3.5">
          <GitBranch size={14} className="text-accent" strokeWidth={2} />
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
            SentinelNet
          </h3>
        </header>
        <p className="px-5 py-5 text-[13px] text-ink-muted">
          No functions in this binary resemble anything else in the corpus yet.
          {sn.length > 0 && ` Queried ${sn.length} function${sn.length === 1 ? "" : "s"}.`}
        </p>
      </article>
    );
  }

  return (
    <article className="card-dark shrink-0 overflow-hidden rounded-xl">
      <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <GitBranch size={14} className="text-accent" strokeWidth={2} />
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
            SentinelNet — related samples
          </h3>
        </div>
        <div className="flex items-center gap-2 font-mono text-[11px]">
          {totalBlock > 0 && (
            <span className="rounded bg-[color:var(--color-threat-block-bg)] px-1.5 py-0.5 text-threat-block">
              {totalBlock} BLOCK
            </span>
          )}
          {totalAllow > 0 && (
            <span className="rounded bg-[color:var(--color-threat-allow-bg)] px-1.5 py-0.5 text-threat-allow">
              {totalAllow} ALLOW
            </span>
          )}
        </div>
      </header>

      <div className="space-y-1.5 px-5 py-4">
        {hits.map((fm) => (
          <FunctionRow key={fm.function_name} fm={fm} />
        ))}
      </div>
    </article>
  );
}

function FunctionRow({ fm }: { fm: FunctionMatches }) {
  const [open, setOpen] = useState(false);
  const blocks = fm.matches.filter((m) => m.verdict === "BLOCK").length;
  const allows = fm.matches.filter((m) => m.verdict === "ALLOW").length;
  const topFamily = fm.matches.find((m) => m.malware_family)?.malware_family;

  return (
    <div className="rounded-md border border-line bg-surface-0/40">
      <button
        onClick={() => setOpen((o) => !o)}
        className="focus-ring flex w-full items-center gap-3 px-3 py-2 text-left transition-colors duration-fast ease-tesla hover:bg-surface-2/60"
      >
        <ChevronDown
          size={12}
          strokeWidth={2}
          className={`shrink-0 text-ink-muted transition-transform duration-base ease-tesla ${
            open ? "rotate-0" : "-rotate-90"
          }`}
        />
        <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-ink">
          {fm.function_name}
        </span>
        {topFamily && (
          <span className="shrink-0 rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-ink">
            {topFamily}
          </span>
        )}
        <span className="shrink-0 font-mono text-[10px] text-ink-muted">
          {blocks} BLOCK · {allows} ALLOW
        </span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <ul className="divide-y divide-line border-t border-line">
              {fm.matches.map((m, i) => (
                <li
                  key={i}
                  className="flex items-center gap-3 px-3 py-2 text-[11px]"
                >
                  {m.verdict === "BLOCK" ? (
                    <ShieldAlert
                      size={13}
                      className="shrink-0 text-threat-block"
                      strokeWidth={2}
                    />
                  ) : (
                    <ShieldCheck
                      size={13}
                      className="shrink-0 text-threat-allow"
                      strokeWidth={2}
                    />
                  )}
                  <span className="min-w-0 flex-1 truncate text-ink-body">
                    {m.file_name}
                    <span className="ml-2 font-mono text-ink-muted">
                      ::{m.function_name}
                    </span>
                  </span>
                  {m.malware_family && (
                    <span className="shrink-0 font-mono text-[10px] text-ink-muted">
                      {m.malware_family}
                    </span>
                  )}
                  <span className="shrink-0 font-mono tabular-nums text-ink">
                    {m.similarity.toFixed(2)}
                  </span>
                </li>
              ))}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
