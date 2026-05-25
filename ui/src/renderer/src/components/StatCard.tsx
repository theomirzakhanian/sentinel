interface Props {
  label: string;
  value: string;
  sub?: string;
  tone?: "default" | "block" | "allow";
}

export function StatCard({ label, value, sub, tone = "default" }: Props) {
  const valueColor =
    tone === "block"
      ? "var(--color-threat-block)"
      : tone === "allow"
        ? "var(--color-threat-allow)"
        : "var(--color-ink)";
  return (
    <div className="card-dark rounded-lg px-5 py-4">
      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
        {label}
      </p>
      <p
        className="mt-1.5 font-mono text-2xl font-semibold leading-tight tabular-nums"
        style={{ color: valueColor }}
      >
        {value}
      </p>
      {sub && (
        <p className="mt-0.5 text-[11px] text-ink-muted">{sub}</p>
      )}
    </div>
  );
}
