import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ArrowRight, Clock, Crosshair, ShieldCheck } from "lucide-react";
import { ShieldHero } from "./ShieldHero";
import { fetchHistory } from "../lib/api";
import type { HistoryEntry } from "../lib/types";
import { scanTime } from "../lib/format";

interface Props {
  refreshKey: number;
  onScanClick: () => void;
}

export function OverviewPage({ refreshKey, onScanClick }: Props) {
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

  const total = history?.length ?? 0;
  const blocked = history?.filter((h) => h.final_verdict === "BLOCK").length ?? 0;
  const lastScan = history?.[0];

  const protectionOk = !err && total >= 0;

  const ease = [0.16, 1, 0.3, 1] as const;

  return (
    <div className="flex h-full w-full flex-col overflow-y-auto px-16 pb-12">
      {/* HERO */}
      <section className="flex flex-col items-center pb-10 pt-12">
        <motion.div
          initial={{ opacity: 0, scale: 0.92 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.6, ease }}
        >
          <ShieldHero size={300} />
        </motion.div>
        <motion.h1
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease, delay: 0.15 }}
          className="mt-10 text-[32px] font-bold leading-tight tracking-tight text-ink"
        >
          Your device is protected
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease, delay: 0.22 }}
          className="mt-3 max-w-md text-center text-[14px] leading-relaxed text-ink-muted"
        >
          Sentinel is actively protecting your system.
        </motion.p>
      </section>

      {/* STATS — single horizontal card, 3 divided sections */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease, delay: 0.32 }}
        className="mb-4"
      >
        <div className="card-dark flex items-stretch rounded-xl">
          <StatSection
            Icon={Clock}
            label="Last scan"
            value={lastScan ? scanTime(lastScan.completed_at) : "Never"}
          />
          <Divider />
          <StatSection
            Icon={Crosshair}
            label="Threats blocked"
            value={String(blocked)}
          />
          <Divider />
          <StatSection
            Icon={ShieldCheck}
            label="Protection up to date"
            value={protectionOk ? "Yes" : "No"}
            valueTone="accent"
          />
        </div>
      </motion.section>

      {/* QUICK SCAN — horizontal card with CTA on right */}
      <motion.section
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease, delay: 0.4 }}
      >
        <motion.div
          whileHover={{ y: -1 }}
          transition={{ duration: 0.2, ease }}
          className="card-dark flex items-center justify-between gap-6 rounded-xl px-7 py-6"
        >
          <div className="min-w-0 flex-1">
            <h2 className="text-[18px] font-semibold tracking-tight text-ink">
              Quick Scan
            </h2>
            <p className="mt-1.5 text-[13px] text-ink-muted">
              Scan your system for threats and vulnerabilities.
            </p>
          </div>
          <motion.button
            onClick={onScanClick}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
            transition={{ duration: 0.18, ease }}
            className="focus-ring group inline-flex shrink-0 items-center gap-2 rounded-lg px-6 py-3 text-[14px] font-semibold text-white"
            style={{
              background:
                "linear-gradient(135deg, var(--color-accent-grad-start), var(--color-accent-grad-end))",
              boxShadow:
                "0 0 24px rgba(155,130,245,0.30), inset 0 1px 0 rgba(255,255,255,0.18)",
            }}
          >
            Start Scan
            <ArrowRight
              size={16}
              strokeWidth={2}
              className="transition-transform duration-base ease-tesla group-hover:translate-x-0.5"
            />
          </motion.button>
        </motion.div>
      </motion.section>
    </div>
  );
}

function StatSection({
  Icon,
  label,
  value,
  valueTone,
}: {
  Icon: typeof Clock;
  label: string;
  value: string;
  valueTone?: "accent" | "block";
}) {
  const valueColor =
    valueTone === "accent"
      ? "var(--color-accent)"
      : valueTone === "block"
        ? "var(--color-threat-block)"
        : "var(--color-ink)";
  return (
    <div className="flex flex-1 items-center gap-4 px-6 py-5">
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-surface-2 text-ink-muted">
        <Icon size={18} strokeWidth={1.75} />
      </span>
      <div className="min-w-0 flex-1 leading-tight">
        <p className="truncate text-[12px] text-ink-muted">{label}</p>
        <p
          className="mt-0.5 truncate text-[16px] font-semibold"
          style={{ color: valueColor }}
        >
          {value}
        </p>
      </div>
    </div>
  );
}

function Divider() {
  return <span aria-hidden className="my-3 w-px shrink-0 bg-line" />;
}
