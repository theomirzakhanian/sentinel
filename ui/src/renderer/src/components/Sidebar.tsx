import { useState } from "react";
import { motion } from "framer-motion";
import { History, LayoutGrid, ScanLine, Settings as SettingsIcon } from "lucide-react";
import sentinelShield from "../assets/sentinel-shield.png";

// Rotating tagline shown under the SENTINEL wordmark. One picked per app launch
// so it feels alive without being noisy. Keep these short, general, and confident
// — never overclaim what Sentinel actually does.
const TAGLINES = [
  "Smart Protection",
  "Always On",
  "Standing Watch",
  "Eyes Open",
  "Vigilant Mode",
  "Active Defense",
  "On Duty",
  "Watchful",
  "First Line",
  "Files Under Review",
  "Deep Inspection",
  "Static & Smart",
  "Holding the Line",
  "Steady State",
  "Bytecode Vision",
  "Defensive Posture",
  "Mission Ready",
  "Locked In",
  "Eyes On",
  "On Patrol",
];

function pickTagline(): string {
  return TAGLINES[Math.floor(Math.random() * TAGLINES.length)];
}

export type PageKey = "overview" | "scan" | "history" | "settings";

interface Item {
  key: PageKey;
  label: string;
  Icon: typeof LayoutGrid;
}

const ITEMS: Item[] = [
  { key: "overview", label: "Overview", Icon: LayoutGrid },
  { key: "scan", label: "Scan", Icon: ScanLine },
  { key: "history", label: "History", Icon: History },
  { key: "settings", label: "Settings", Icon: SettingsIcon },
];

interface Props {
  current: PageKey;
  onSelect: (k: PageKey) => void;
}

export function Sidebar({ current, onSelect }: Props) {
  // Pick once per real mount. useState's initializer runs once per session.
  const [tagline] = useState<string>(pickTagline);

  return (
    <aside className="flex h-full w-[260px] shrink-0 flex-col border-r border-line bg-surface-0/60 px-5 pb-5 pt-14">
      <header className="mb-10 flex items-center gap-3 px-2">
        <BrandTile />
        <div className="min-w-0 leading-tight">
          <p
            className="text-[19px] uppercase leading-none tracking-[0.14em] text-ink"
            style={{ fontFamily: "Audiowide, Inter, sans-serif" }}
          >
            S
            <span style={{
                fontFamily: "Tesla, Audiowide",
                fontSize: "1.05em",
                display: "inline-block",
                transform: "translate(1.4px, -0.5px)",
              }}>
              E
            </span>
            NTIN
            <span style={{
                fontFamily: "Tesla, Audiowide",
                fontSize: "1.05em",
                display: "inline-block",
                transform: "translate(1.4px, -0.5px)",
              }}>
              E
            </span>
            L
          </p>
          <p className="mt-0.5 text-[11px] text-ink-muted">
            {tagline}
          </p>
        </div>
      </header>

      <nav className="flex-1 space-y-1">
        {ITEMS.map(({ key, label, Icon }) => {
          const active = key === current;
          return (
            <button
              key={key}
              onClick={() => onSelect(key)}
              aria-current={active ? "page" : undefined}
              className={`focus-ring group relative flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-[14px] transition-colors duration-fast ease-tesla ${
                active
                  ? "text-ink"
                  : "text-ink-muted hover:text-ink-body"
              }`}
            >
              {/* Animated active background — slides between nav items via layoutId */}
              {active && (
                <motion.span
                  layoutId="sidebar-active-bg"
                  aria-hidden
                  className="absolute inset-0 rounded-lg"
                  style={{
                    background:
                      "linear-gradient(135deg, rgba(155,130,245,0.18), rgba(155,130,245,0.08))",
                    boxShadow:
                      "inset 0 1px 0 rgba(255,255,255,0.06), inset 0 0 0 1px rgba(155,130,245,0.20)",
                  }}
                  transition={{ type: "spring", stiffness: 380, damping: 32 }}
                />
              )}
              {/* Hover hint that doesn't conflict with the active layout pill */}
              {!active && (
                <span
                  aria-hidden
                  className="absolute inset-0 rounded-lg bg-surface-2/0 transition-colors duration-fast ease-tesla group-hover:bg-surface-2/50"
                />
              )}
              <span className="relative flex items-center gap-3">
                <Icon
                  size={18}
                  strokeWidth={1.75}
                  className={`transition-colors duration-fast ease-tesla ${
                    active ? "text-accent" : "text-ink-muted group-hover:text-ink-body"
                  }`}
                />
                <span className="font-medium tracking-tight">{label}</span>
              </span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
}

function BrandTile() {
  // The custom shield PNG already has its own gradient, glow, and shading —
  // sit it on a transparent background; don't double-up with a violet tile.
  // PNG is non-square (taller than wide); object-contain + auto width keeps
  // the shield from being squashed horizontally.
  return (
    <div className="flex h-11 w-11 shrink-0 items-center justify-center">
      <img
        src={sentinelShield}
        alt="Sentinel"
        className="h-full w-auto max-w-full select-none object-contain"
        draggable={false}
        style={{
          filter: "drop-shadow(0 0 12px rgba(155,130,245,0.30))",
        }}
      />
    </div>
  );
}
