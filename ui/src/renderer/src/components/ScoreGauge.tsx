/**
 * Semicircular weighted-score gauge — Tesla tachometer feel.
 *
 * Domain: score in [-1, +1].
 *   Left half (negative) = benign evidence (green).
 *   Right half (positive) = malicious evidence (red).
 *   Center = no evidence (zero).
 *   Tick marker at +threshold (default +0.15) — the BLOCK boundary.
 */
import { motion } from "framer-motion";

interface Props {
  score: number;            // current weighted score, [-1, +1]
  threshold?: number;       // BLOCK threshold, default +0.15
  size?: number;            // px width
  label?: string;
}

const R = 80;        // arc radius in viewBox units
const CX = 100;      // center x in viewBox units
const CY = 100;      // center y (semicircle base)
const STROKE = 12;

function polar(angleDeg: number): { x: number; y: number } {
  // 180° = left end of semicircle; 0° = right end. Sweeps over the top.
  const a = ((180 - angleDeg) * Math.PI) / 180;
  return { x: CX + R * Math.cos(a), y: CY - R * Math.sin(a) };
}

function arcPath(fromDeg: number, toDeg: number): string {
  const a = polar(fromDeg);
  const b = polar(toDeg);
  const largeArc = Math.abs(toDeg - fromDeg) > 180 ? 1 : 0;
  const sweep = toDeg > fromDeg ? 1 : 0;
  return `M ${a.x} ${a.y} A ${R} ${R} 0 ${largeArc} ${sweep} ${b.x} ${b.y}`;
}

function scoreToDeg(s: number): number {
  // Map [-1, +1] -> [0°, 180°] left to right.
  const clamped = Math.max(-1, Math.min(1, s));
  return ((clamped + 1) / 2) * 180;
}

export function ScoreGauge({ score, threshold = 0.15, size = 220, label = "WEIGHTED SCORE" }: Props) {
  const center = scoreToDeg(0);
  const target = scoreToDeg(score);
  const threshDeg = scoreToDeg(threshold);

  const verdict = score >= threshold ? "block" : "allow";
  const color = verdict === "block" ? "var(--color-threat-block)" : "var(--color-threat-allow)";

  const labelPos = polar(threshDeg);

  return (
    <div className="flex flex-col items-center" style={{ width: size }}>
      <svg viewBox="0 0 200 110" style={{ width: size }} aria-label={`weighted score ${score.toFixed(3)}`}>
        {/* Resting arc (full semicircle) */}
        <path
          d={arcPath(0, 180)}
          fill="none"
          stroke="var(--color-line)"
          strokeWidth={STROKE}
          strokeLinecap="round"
        />

        {/* Filled portion from center to score */}
        <motion.path
          d={arcPath(Math.min(center, target), Math.max(center, target))}
          fill="none"
          stroke={color}
          strokeWidth={STROKE}
          strokeLinecap="round"
          initial={{ pathLength: 0, opacity: 0.6 }}
          animate={{ pathLength: 1, opacity: 1 }}
          transition={{ duration: 0.55, ease: [0.16, 1, 0.3, 1] }}
        />

        {/* Threshold tick */}
        <line
          x1={polar(threshDeg).x}
          y1={polar(threshDeg).y - 14}
          x2={polar(threshDeg).x}
          y2={polar(threshDeg).y + 2}
          stroke="var(--color-ink-muted)"
          strokeWidth={1.5}
          opacity={0.55}
        />
        <text
          x={labelPos.x}
          y={labelPos.y - 18}
          textAnchor="middle"
          fontSize="7"
          fill="var(--color-ink-muted)"
          fontFamily="var(--font-mono)"
        >
          +{threshold.toFixed(2)}
        </text>

        {/* Center axis tick */}
        <line
          x1={polar(center).x}
          y1={polar(center).y - 10}
          x2={polar(center).x}
          y2={polar(center).y}
          stroke="var(--color-ink-muted)"
          strokeWidth={1}
          opacity={0.4}
        />
      </svg>

      <div className="-mt-3 flex flex-col items-center gap-0.5">
        <span className="font-mono text-2xl font-semibold tabular-nums text-ink" style={{ color }}>
          {score >= 0 ? "+" : ""}{score.toFixed(3)}
        </span>
        <span className="text-[10px] font-medium uppercase tracking-[0.18em] text-ink-muted">
          {label}
        </span>
      </div>
    </div>
  );
}
