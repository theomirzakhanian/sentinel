/**
 * Headline "what is this file" panel above the per-stage signal cards.
 * Pulls from the AI signal's evidence: file_description, malware_class[],
 * malware_family, capabilities[]. Only renders when the AI provided a
 * description (otherwise we'd be showing an empty shell).
 */
import { Sparkles } from "lucide-react";
import type { Report } from "../lib/types";

const CLASS_LABEL: Record<string, string> = {
  stealer: "Stealer",
  rat: "RAT",
  backdoor: "Backdoor",
  rootkit: "Rootkit",
  downloader: "Downloader",
  loader: "Loader",
  dropper: "Dropper",
  miner: "Miner",
  ransomware: "Ransomware",
  wiper: "Wiper",
  spyware: "Spyware",
  trojan: "Trojan",
  worm: "Worm",
  adware: "Adware",
  packer: "Packer",
  unknown: "Unknown",
};

interface Props {
  report: Report;
}

export function AnalysisCard({ report }: Props) {
  const ai = report.signals.find((s) => s.stage === "ai_review");
  if (!ai) return null;
  const ev = ai.evidence ?? {};
  const fileDescription = (ev.file_description as string) || "";
  const classes = ((ev.malware_class as string[]) || []).filter(Boolean);
  const family = (ev.malware_family as string | null) || null;
  const capabilities = ((ev.capabilities as string[]) || []).filter(Boolean);

  // Nothing to show — bail. Better than an empty card.
  if (!fileDescription && classes.length === 0 && capabilities.length === 0) {
    return null;
  }

  const isBlock = report.final_verdict === "BLOCK";

  return (
    <article className="card-dark shrink-0 overflow-hidden rounded-xl">
      <header className="flex items-center justify-between gap-3 border-b border-line px-5 py-3.5">
        <div className="flex items-center gap-2.5">
          <Sparkles size={14} className="text-accent" strokeWidth={2} />
          <h3 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
            What this file is
          </h3>
        </div>
        {isBlock && (classes.length > 0 || family) && (
          <div className="flex items-center gap-1.5">
            {family && <FamilyBadge name={family} />}
            {classes.map((c) => (
              <ClassBadge key={c} k={c} />
            ))}
          </div>
        )}
      </header>

      <div className="space-y-5 px-5 py-5">
        {fileDescription && (
          <p className="text-[14px] leading-relaxed text-ink-body">
            {fileDescription}
          </p>
        )}

        {capabilities.length > 0 && (
          <div>
            <p className="mb-2.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
              {isBlock ? "Observed capabilities" : "Capabilities"}
            </p>
            <ul className="flex flex-wrap gap-1.5">
              {capabilities.map((c, i) => (
                <li
                  key={i}
                  className="rounded-md border border-line bg-surface-2/60 px-2.5 py-1 text-[11px] text-ink-body"
                >
                  {c}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </article>
  );
}

function ClassBadge({ k }: { k: string }) {
  const label = CLASS_LABEL[k] ?? k;
  return (
    <span className="rounded bg-[color:var(--color-threat-block-bg)] px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-threat-block">
      {label}
    </span>
  );
}

function FamilyBadge({ name }: { name: string }) {
  return (
    <span className="rounded bg-surface-2 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-ink">
      {name}
    </span>
  );
}
