/**
 * SENTINEL wordmark, hand-drawn as SVG so the E renders as three free-floating
 * horizontal bars (no vertical spine) — the Tesla branding move. Every letter
 * is a small geometric primitive; no font dependency.
 *
 * Tweak `size` to scale; everything else (stroke, spacing) scales from it.
 */
interface Props {
  size?: number;        // height in px
  color?: string;       // CSS color (defaults to violet accent)
  className?: string;
}

const TXT = "SENTINEL";

// Letter widths — Tesla-style proportions: most letters wide, I narrow.
const W: Record<string, number> = {
  S: 16,
  E: 16,
  N: 18,
  T: 16,
  I: 4,
  L: 14,
};

export function SentinelWordmark({
  size = 24,
  color = "var(--color-accent)",
  className,
}: Props) {
  const H = size;
  const T = Math.max(2, Math.round(H / 10));  // stroke thickness
  const GAP = Math.round(H * 0.28);           // gap between letters

  // Compute x offsets per letter
  const positions: { ch: string; x: number; w: number }[] = [];
  let cursor = 0;
  for (const ch of TXT) {
    const w = W[ch] ?? 14;
    positions.push({ ch, x: cursor, w });
    cursor += w + GAP;
  }
  const totalWidth = cursor - GAP;

  return (
    <svg
      viewBox={`0 0 ${totalWidth} ${H}`}
      height={H}
      width={totalWidth}
      className={className}
      aria-label="Sentinel"
      style={{ display: "block" }}
    >
      <g fill={color}>
        {positions.map(({ ch, x, w }, i) => (
          <Letter key={i} ch={ch} x={x} w={w} h={H} t={T} />
        ))}
      </g>
    </svg>
  );
}

function Letter({
  ch,
  x,
  w,
  h,
  t,
}: {
  ch: string;
  x: number;
  w: number;
  h: number;
  t: number;
}) {
  const half = (h - t) / 2;

  switch (ch) {
    case "S":
      return (
        <g transform={`translate(${x}, 0)`}>
          {/* Top horizontal */}
          <rect x={0} y={0} width={w} height={t} />
          {/* Upper-left vertical (top → middle) */}
          <rect x={0} y={t} width={t} height={half - t} />
          {/* Middle horizontal */}
          <rect x={0} y={half} width={w} height={t} />
          {/* Lower-right vertical (middle → bottom) */}
          <rect x={w - t} y={half + t} width={t} height={half - t} />
          {/* Bottom horizontal */}
          <rect x={0} y={h - t} width={w} height={t} />
        </g>
      );

    case "E":
      // Three free-floating horizontal bars. No vertical spine. Tesla-style.
      // Middle bar slightly shorter so it reads as deliberate, not unfinished.
      return (
        <g transform={`translate(${x}, 0)`}>
          <rect x={0} y={0} width={w} height={t} />
          <rect x={0} y={half} width={Math.round(w * 0.72)} height={t} />
          <rect x={0} y={h - t} width={w} height={t} />
        </g>
      );

    case "N": {
      // Left vertical + diagonal + right vertical.
      // Diagonal drawn as a parallelogram via polygon.
      const dxTopLeft = t;
      const dxBotLeft = w - t;
      return (
        <g transform={`translate(${x}, 0)`}>
          <rect x={0} y={0} width={t} height={h} />
          <polygon
            points={`
              ${dxTopLeft},0
              ${dxTopLeft + t},0
              ${dxBotLeft + t},${h}
              ${dxBotLeft},${h}
            `}
          />
          <rect x={w - t} y={0} width={t} height={h} />
        </g>
      );
    }

    case "T":
      return (
        <g transform={`translate(${x}, 0)`}>
          <rect x={0} y={0} width={w} height={t} />
          <rect x={(w - t) / 2} y={t} width={t} height={h - t} />
        </g>
      );

    case "I":
      return (
        <g transform={`translate(${x}, 0)`}>
          <rect x={0} y={0} width={w} height={h} />
        </g>
      );

    case "L":
      return (
        <g transform={`translate(${x}, 0)`}>
          <rect x={0} y={0} width={t} height={h} />
          <rect x={0} y={h - t} width={w} height={t} />
        </g>
      );

    default:
      return null;
  }
}
