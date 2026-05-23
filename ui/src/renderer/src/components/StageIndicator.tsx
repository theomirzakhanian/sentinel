/**
 * Per-stage status pip — Tesla-style minimal geometric.
 * States: pending (dim ring) | running (cyan ring with pulse) | allow (green dot+check)
 *         | block (red dot+x) | warn (amber dot+!) | skipped (dashed dim ring)
 */
import { motion } from "framer-motion";
import { Check, X, AlertTriangle } from "lucide-react";

export type StageStatus = "pending" | "running" | "allow" | "block" | "warn" | "skipped";

interface Props {
  status: StageStatus;
  size?: number;
}

export function StageIndicator({ status, size = 24 }: Props) {
  if (status === "pending") {
    return (
      <span
        aria-label="pending"
        className="inline-block rounded-full border border-line"
        style={{ width: size, height: size }}
      />
    );
  }

  if (status === "skipped") {
    return (
      <span
        aria-label="skipped"
        className="inline-block rounded-full border border-dashed border-line opacity-50"
        style={{ width: size, height: size }}
      />
    );
  }

  if (status === "running") {
    return (
      <span
        aria-label="running"
        className="relative inline-block"
        style={{ width: size, height: size }}
      >
        <span className="absolute inset-0 rounded-full border-2 border-accent/30" />
        <motion.span
          className="absolute inset-0 rounded-full border-2 border-accent"
          style={{ borderTopColor: "transparent", borderRightColor: "transparent" }}
          animate={{ rotate: 360 }}
          transition={{ duration: 1.4, ease: "linear", repeat: Infinity }}
        />
        <motion.span
          className="absolute inset-0 rounded-full"
          style={{ background: "var(--color-accent)", opacity: 0.15 }}
          animate={{ opacity: [0.1, 0.25, 0.1] }}
          transition={{ duration: 1.8, ease: "easeInOut", repeat: Infinity }}
        />
      </span>
    );
  }

  const cls =
    status === "allow"
      ? "bg-[color:var(--color-threat-allow-bg)] text-threat-allow"
      : status === "block"
        ? "bg-[color:var(--color-threat-block-bg)] text-threat-block"
        : "bg-[color:var(--color-threat-warn-bg)] text-threat-warn";

  const Icon = status === "allow" ? Check : status === "block" ? X : AlertTriangle;

  return (
    <motion.span
      aria-label={status}
      initial={{ scale: 0.6, opacity: 0 }}
      animate={{ scale: 1, opacity: 1 }}
      transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1] }}
      className={`inline-flex items-center justify-center rounded-full ${cls}`}
      style={{ width: size, height: size }}
    >
      <Icon size={Math.round(size * 0.55)} strokeWidth={2.25} />
    </motion.span>
  );
}
