/**
 * Code Review card: shows what Claude actually saw — meta_flags that fired
 * + per-function decompiled C (expandable). Surfaces Sentinel's reasoning
 * substrate, not just its conclusion.
 */
import { useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ChevronDown, Code2, FlagTriangleRight } from "lucide-react";
import type { Report } from "../lib/types";

interface MetaFlag {
  flag: string;
  severity: "high" | "medium" | "low" | "info" | string;
  detail: string;
}

interface GhidraDump {
  decompiled: Record<string, string>;
  decompiled_names: string[];
  decompiled_selection_reasons: Record<string, string[]>;
  meta_flags: MetaFlag[];
  function_count: number | null;
  imports_count: number;
  executable_format: string | null;
  language_id: string | null;
  compiler_spec_id: string | null;
}

interface Props {
  report: Report;
}

export function CodeReviewCard({ report }: Props) {
  const ai = report.signals.find((s) => s.stage === "ai_review");
  if (!ai) return null;
  const dump = ai.evidence?.ghidra_dump as GhidraDump | undefined;
  if (!dump) return null;

  const names = dump.decompiled_names ?? [];
  const flags = dump.meta_flags ?? [];

  return (
    <article className="card-dark shrink-0 overflow-hidden rounded-xl">
      <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <Code2 size={14} className="text-accent" strokeWidth={2} />
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
            Code review
          </h3>
        </div>
        <p className="font-mono text-[10px] text-ink-muted">
          {dump.executable_format ?? "binary"} · {dump.function_count ?? 0} fns · {dump.imports_count} imports
        </p>
      </header>

      {/* Meta flags (auto-detected concerning patterns) */}
      {flags.length > 0 && (
        <div className="border-b border-line px-5 py-4">
          <p className="mb-2.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
            Meta flags ({flags.length})
          </p>
          <ul className="space-y-2">
            {flags.map((f, i) => (
              <MetaFlagRow key={i} flag={f} />
            ))}
          </ul>
        </div>
      )}

      {/* Decompiled functions Claude reviewed */}
      {names.length > 0 && (
        <div className="px-5 py-4">
          <p className="mb-2.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
            Functions reviewed ({names.length})
          </p>
          <ul className="space-y-1.5">
            {names.map((name) => (
              <FunctionRow
                key={name}
                name={name}
                source={dump.decompiled[name] ?? ""}
                reasons={dump.decompiled_selection_reasons?.[name] ?? []}
              />
            ))}
          </ul>
        </div>
      )}

      {names.length === 0 && flags.length === 0 && (
        <p className="px-5 py-6 text-center text-[12px] text-ink-muted">
          No decompilation data captured for this scan.
        </p>
      )}
    </article>
  );
}

function MetaFlagRow({ flag }: { flag: MetaFlag }) {
  const sev = (flag.severity || "info").toLowerCase();
  const color =
    sev === "high"
      ? "var(--color-threat-block)"
      : sev === "medium"
        ? "var(--color-threat-warn)"
        : "var(--color-ink-muted)";
  const bg =
    sev === "high"
      ? "var(--color-threat-block-bg)"
      : sev === "medium"
        ? "var(--color-threat-warn-bg)"
        : "rgba(255,255,255,0.04)";
  return (
    <li className="flex items-start gap-3 rounded-md px-3 py-2.5" style={{ background: bg }}>
      <FlagTriangleRight size={13} strokeWidth={2} className="mt-0.5 shrink-0" style={{ color }} />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span
            className="font-mono text-[10px] font-semibold uppercase tracking-wider"
            style={{ color }}
          >
            {sev}
          </span>
          <span className="font-mono text-[11px] text-ink">{flag.flag}</span>
        </div>
        <p className="mt-0.5 text-[12px] leading-relaxed text-ink-body">{flag.detail}</p>
      </div>
    </li>
  );
}

function FunctionRow({
  name,
  source,
  reasons,
}: {
  name: string;
  source: string;
  reasons: string[];
}) {
  const [open, setOpen] = useState(false);
  return (
    <li>
      <button
        onClick={() => setOpen((o) => !o)}
        className="focus-ring group flex w-full items-center gap-3 rounded-md border border-line bg-surface-0/40 px-3 py-2 text-left transition-colors duration-fast ease-tesla hover:bg-surface-2/60"
      >
        <ChevronDown
          size={13}
          strokeWidth={2}
          className={`shrink-0 text-ink-muted transition-transform duration-base ease-tesla ${
            open ? "rotate-0" : "-rotate-90"
          }`}
        />
        <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-ink">{name}</span>
        {reasons.length > 0 && (
          <span className="hidden font-mono text-[10px] text-ink-muted sm:inline">
            {reasons.join(" · ").slice(0, 60)}
          </span>
        )}
        <span className="shrink-0 font-mono text-[10px] text-ink-muted">
          {source.split("\n").length} lines
        </span>
      </button>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
            className="overflow-hidden"
          >
            <pre
              className="mt-1.5 max-h-[420px] overflow-auto rounded-md border border-line bg-[color:var(--color-surface-0)] p-3 font-mono text-[11px] leading-snug text-ink-body"
            >
              <code>{source || "// (no source captured)"}</code>
            </pre>
          </motion.div>
        )}
      </AnimatePresence>
    </li>
  );
}
