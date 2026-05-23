/**
 * Hero stage indicator for the scanning view.
 * - running.default: rotating cyan comet (used for VirusTotal, generic stages)
 * - running.ai:      three concentric rotating arc trails + glowing core (used for AI deep dive)
 * - allow/block/warn: solid colored disc with check/X, halo burst
 * - skipped:         dashed ring, dim
 */
import { motion } from "framer-motion";
import { AlertTriangle, Check, X } from "lucide-react";

export type BigStatus = "running" | "allow" | "block" | "warn" | "skipped";
export type BigVariant = "default" | "ai";

interface Props {
  status: BigStatus;
  variant?: BigVariant;
  size?: number;
}

export function BigScanIndicator({ status, variant = "default", size = 160 }: Props) {
  if (status === "running") {
    return variant === "ai" ? <RunningAI size={size} /> : <RunningDefault size={size} />;
  }
  if (status === "skipped") return <SkippedRing size={size} />;
  return <DoneCircle status={status} size={size} />;
}

/* --------------------------------------------------------------------------
 * Running variants
 * ------------------------------------------------------------------------ */

function RunningDefault({ size }: { size: number }) {
  const stroke = 3;
  const r = size / 2 - stroke;
  const c = 2 * Math.PI * r;

  return (
    <div className="relative" style={{ width: size, height: size }} aria-label="scanning">
      {/* Sonar pulse rings */}
      {[0, 1].map((i) => (
        <motion.span
          key={i}
          aria-hidden
          className="absolute inset-0 rounded-full border border-accent/40"
          initial={{ scale: 0.85, opacity: 0.55 }}
          animate={{ scale: 1.45, opacity: 0 }}
          transition={{ duration: 2.4, ease: "easeOut", repeat: Infinity, delay: i * 1.2 }}
        />
      ))}

      {/* Halo glow */}
      <motion.span
        aria-hidden
        className="absolute inset-2 rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(126,212,243,0.22) 0%, rgba(126,212,243,0) 65%)",
        }}
        animate={{ opacity: [0.55, 0.95, 0.55] }}
        transition={{ duration: 2.1, ease: "easeInOut", repeat: Infinity }}
      />

      {/* Static base ring */}
      <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size} className="absolute inset-0">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(126,212,243,0.18)" strokeWidth={stroke} />
      </svg>

      {/* Rotating gradient arc */}
      <motion.div
        aria-hidden
        className="absolute inset-0"
        animate={{ rotate: 360 }}
        transition={{ duration: 1.6, ease: "linear", repeat: Infinity }}
        style={{ originX: "50%", originY: "50%" }}
      >
        <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size}>
          <defs>
            <linearGradient id="rd-arc" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0" />
              <stop offset="60%" stopColor="var(--color-accent)" stopOpacity="0.85" />
              <stop offset="95%" stopColor="oklch(95% 0.05 220)" stopOpacity="1" />
              <stop offset="100%" stopColor="#ffffff" stopOpacity="1" />
            </linearGradient>
          </defs>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={r}
            fill="none"
            stroke="url(#rd-arc)"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${c * 0.32} ${c * 0.68}`}
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
          />
        </svg>
      </motion.div>

      {/* Center breathing dot */}
      <motion.span
        aria-hidden
        className="absolute left-1/2 top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent"
        animate={{ opacity: [0.35, 1, 0.35], scale: [0.85, 1.15, 0.85] }}
        transition={{ duration: 1.8, ease: "easeInOut", repeat: Infinity }}
      />
    </div>
  );
}

function RunningAI({ size }: { size: number }) {
  const cx = size / 2;

  // Three orbits at different radii, alternating direction + speed
  const orbits = [
    { rRatio: 0.42, duration: 2.4, reverse: false, dashRatio: 0.28, strokeWidth: 2 },
    { rRatio: 0.66, duration: 3.6, reverse: true, dashRatio: 0.20, strokeWidth: 1.5 },
    { rRatio: 0.92, duration: 5.2, reverse: false, dashRatio: 0.14, strokeWidth: 1.5 },
  ];

  return (
    <div className="relative" style={{ width: size, height: size }} aria-label="ai analyzing">
      {/* Breathing radial halo */}
      <motion.span
        aria-hidden
        className="absolute inset-0 rounded-full"
        style={{
          background:
            "radial-gradient(circle, rgba(126,212,243,0.22) 0%, rgba(126,212,243,0) 70%)",
        }}
        animate={{ opacity: [0.45, 0.95, 0.45], scale: [0.95, 1.05, 0.95] }}
        transition={{ duration: 2.8, ease: "easeInOut", repeat: Infinity }}
      />

      {/* Faint static orbit traces */}
      {orbits.map((o, i) => {
        const r = cx * o.rRatio;
        return (
          <span
            key={`bg-${i}`}
            aria-hidden
            className="absolute rounded-full border border-accent/10"
            style={{
              top: cx - r,
              left: cx - r,
              width: r * 2,
              height: r * 2,
            }}
          />
        );
      })}

      {/* Rotating gradient arc trails */}
      {orbits.map((o, i) => {
        const r = cx * o.rRatio;
        const c = 2 * Math.PI * r;
        const dash = c * o.dashRatio;
        return (
          <motion.div
            key={`orbit-${i}`}
            aria-hidden
            className="absolute inset-0"
            animate={{ rotate: o.reverse ? -360 : 360 }}
            transition={{ duration: o.duration, ease: "linear", repeat: Infinity }}
            style={{ originX: "50%", originY: "50%" }}
          >
            <svg viewBox={`0 0 ${size} ${size}`} width={size} height={size}>
              <defs>
                <linearGradient id={`ai-arc-${i}`} x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0" />
                  <stop offset="70%" stopColor="var(--color-accent)" stopOpacity="0.85" />
                  <stop offset="100%" stopColor="#ffffff" stopOpacity="1" />
                </linearGradient>
              </defs>
              <circle
                cx={cx}
                cy={cx}
                r={r}
                fill="none"
                stroke={`url(#ai-arc-${i})`}
                strokeWidth={o.strokeWidth}
                strokeLinecap="round"
                strokeDasharray={`${dash} ${c - dash}`}
                transform={`rotate(-90 ${cx} ${cx})`}
              />
            </svg>
          </motion.div>
        );
      })}

      {/* Center glowing core */}
      <motion.span
        aria-hidden
        className="absolute left-1/2 top-1/2 rounded-full bg-accent"
        style={{
          width: 10,
          height: 10,
          transform: "translate(-50%, -50%)",
          boxShadow:
            "0 0 14px var(--color-accent), 0 0 28px rgba(126,212,243,0.55), 0 0 48px rgba(126,212,243,0.25)",
        }}
        animate={{ scale: [0.85, 1.4, 0.85], opacity: [0.75, 1, 0.75] }}
        transition={{ duration: 1.7, ease: "easeInOut", repeat: Infinity }}
      />

      {/* Inner halo ring */}
      <motion.span
        aria-hidden
        className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full border border-accent/30"
        style={{ width: 24, height: 24 }}
        animate={{ scale: [1, 1.8, 1], opacity: [0.6, 0, 0.6] }}
        transition={{ duration: 2.0, ease: "easeOut", repeat: Infinity }}
      />
    </div>
  );
}

/* --------------------------------------------------------------------------
 * Done variants
 * ------------------------------------------------------------------------ */

function DoneCircle({ status, size }: { status: "allow" | "block" | "warn"; size: number }) {
  const color =
    status === "allow"
      ? "var(--color-threat-allow)"
      : status === "block"
        ? "var(--color-threat-block)"
        : "var(--color-threat-warn)";
  const Icon = status === "allow" ? Check : status === "block" ? X : AlertTriangle;
  const iconSize = Math.round(size * 0.42);

  return (
    <div className="relative" style={{ width: size, height: size }}>
      {/* Outward burst halo */}
      <motion.span
        aria-hidden
        className="absolute inset-0 rounded-full"
        style={{ background: color, opacity: 0.32 }}
        initial={{ scale: 0.9, opacity: 0.5 }}
        animate={{ scale: 1.5, opacity: 0 }}
        transition={{ duration: 1.0, ease: "easeOut" }}
      />
      {/* Faint outer halo */}
      <motion.span
        aria-hidden
        className="absolute inset-0 rounded-full"
        style={{ background: color, opacity: 0.18 }}
        initial={{ scale: 0.7, opacity: 0 }}
        animate={{ scale: 1, opacity: 0.18 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      />
      {/* Inner solid disc */}
      <motion.span
        aria-hidden
        className="absolute inset-3 rounded-full"
        style={{ background: color }}
        initial={{ scale: 0.6, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
      />
      {/* Icon */}
      <motion.span
        className="absolute inset-0 flex items-center justify-center"
        initial={{ scale: 0.4, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ duration: 0.36, ease: [0.16, 1, 0.3, 1], delay: 0.15 }}
      >
        <Icon size={iconSize} strokeWidth={2.75} className="text-[#0a0d0f]" />
      </motion.span>
    </div>
  );
}

function SkippedRing({ size }: { size: number }) {
  return (
    <motion.div
      initial={{ scale: 0.7, opacity: 0 }}
      animate={{ scale: 1, opacity: 0.5 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className="rounded-full border-2 border-dashed border-line"
      style={{ width: size, height: size }}
      aria-label="skipped"
    />
  );
}
