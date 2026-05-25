import { useEffect, useState } from "react";
import { ExternalLink, FileCog } from "lucide-react";
import { fetchSettings, type DaemonSettings } from "../lib/api";

export function SettingsPage() {
  const [s, setS] = useState<DaemonSettings | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    fetchSettings()
      .then((d) => alive && setS(d))
      .catch((e: Error) => alive && setErr(e.message));
    return () => {
      alive = false;
    };
  }, []);

  return (
    <div className="flex h-full w-full flex-col overflow-hidden">
      <header className="shrink-0 border-b border-line px-8 py-6">
        <h1 className="text-2xl font-bold tracking-tight text-ink">Settings</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Read-only view of the running daemon's configuration. Edit the values directly in your <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]">.env</code> file and restart the daemon to apply.
        </p>
      </header>

      <div className="flex-1 overflow-y-auto px-8 py-6">
        {err && (
          <p className="text-sm text-ink-muted">
            Daemon offline. Run <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[11px]">sentinel serve</code>.
          </p>
        )}

        {!s && !err && (
          <div className="space-y-3">
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                className="h-24 animate-pulse rounded-md bg-surface-2"
                style={{ animationDelay: `${i * 80}ms` }}
              />
            ))}
          </div>
        )}

        {s && (
          <div className="space-y-6">
            <Section title="API keys">
              <KeyRow
                name="VT_API_KEY"
                value={s.keys.VT_API_KEY}
                getLink="https://www.virustotal.com/gui/my-apikey"
                required
              />
              <KeyRow
                name="TRIAGE_API_KEY"
                value={s.keys.TRIAGE_API_KEY}
                getLink="https://tria.ge/account/api"
              />
              <KeyRow
                name="MALWAREBAZAAR_API_KEY"
                value={s.keys.MALWAREBAZAAR_API_KEY}
                getLink="https://bazaar.abuse.ch/account/"
              />
            </Section>

            <Section title="Engine">
              <Row
                label="AI mode"
                value={
                  <span className="inline-flex items-center gap-2">
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{
                        background:
                          s.ai_mode === "mcp" || s.ai_mode === "headless"
                            ? "var(--color-threat-allow)"
                            : "var(--color-threat-warn)",
                      }}
                    />
                    <span className="font-mono text-xs">{s.ai_mode}</span>
                    <span className="text-[11px] text-ink-muted">
                      {s.ai_mode === "mcp"
                        ? "GUI Ghidra · MCP plugin"
                        : s.ai_mode === "headless"
                          ? "Ghidra analyzeHeadless"
                          : "binutils fallback"}
                    </span>
                  </span>
                }
              />
              <Row
                label="analyzeHeadless"
                value={
                  s.engine.analyze_headless_path ? (
                    <code className="font-mono text-[11px] text-ink-body">
                      {s.engine.analyze_headless_path}
                    </code>
                  ) : (
                    <span className="text-[11px] text-ink-muted">
                      not found · install Ghidra or set <span className="font-mono">GHIDRA_HOME</span>
                    </span>
                  )
                }
              />
              <Row
                label="Claude CLI binary"
                value={
                  <code className="font-mono text-[11px] text-ink-body">
                    {s.engine.claude_bin}
                  </code>
                }
              />
              <Row
                label="Claude model override"
                value={
                  s.engine.claude_model ? (
                    <code className="font-mono text-[11px] text-ink-body">
                      {s.engine.claude_model}
                    </code>
                  ) : (
                    <span className="text-[11px] text-ink-muted">
                      (CLI default)
                    </span>
                  )
                }
              />
            </Section>

            <Section title="Policy">
              <Row
                label="BLOCK threshold"
                value={
                  <span className="font-mono text-xs tabular-nums text-ink-body">
                    +{s.block_threshold.toFixed(3)}
                  </span>
                }
                hint="Weighted score at or above this triggers BLOCK"
              />
            </Section>

            <Section title="Configuration file">
              <div className="card-dark flex items-start gap-3 rounded-md px-4 py-3">
                <FileCog size={16} className="mt-0.5 shrink-0 text-ink-muted" />
                <div className="min-w-0 flex-1">
                  <p className="text-xs text-ink-body">
                    Edit values in:{" "}
                    <code className="break-all font-mono text-[11px] text-ink">
                      {s.env_file}
                    </code>
                  </p>
                  <p className="mt-1 text-[11px] text-ink-muted">
                    {s.env_file_exists
                      ? "File exists. Restart the daemon (or the app) to pick up changes."
                      : "File missing. Copy .env.example to .env and fill in your keys."}
                  </p>
                </div>
              </div>
            </Section>

            <p className="pt-2 text-[11px] text-ink-muted">
              Sentinel {s.version} · in-app editing coming in a future release.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h2 className="mb-2 text-[10px] font-semibold uppercase tracking-[0.18em] text-ink-muted">
        {title}
      </h2>
      <div className="card-dark divide-y divide-line rounded-md">{children}</div>
    </section>
  );
}

function Row({
  label,
  value,
  hint,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
}) {
  return (
    <div className="flex items-baseline justify-between gap-6 px-4 py-3">
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium text-ink">{label}</p>
        {hint && <p className="mt-0.5 text-[10px] text-ink-muted">{hint}</p>}
      </div>
      <div className="min-w-0 max-w-[60%] text-right">{value}</div>
    </div>
  );
}

function KeyRow({
  name,
  value,
  getLink,
  required,
}: {
  name: string;
  value: string | null;
  getLink: string;
  required?: boolean;
}) {
  return (
    <div className="flex items-baseline justify-between gap-6 px-4 py-3">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <code className="font-mono text-xs font-medium text-ink">{name}</code>
          {required && (
            <span className="rounded bg-surface-2 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-ink-muted">
              required
            </span>
          )}
        </div>
        {!value && (
          <a
            href={getLink}
            target="_blank"
            rel="noreferrer"
            className="mt-1 inline-flex items-center gap-1 text-[10px] text-accent hover:text-accent-hover"
          >
            Get a key
            <ExternalLink size={10} />
          </a>
        )}
      </div>
      <div className="min-w-0 text-right">
        {value ? (
          <code className="font-mono text-[11px] text-ink-body">{value}</code>
        ) : (
          <span className="text-[11px] text-ink-muted">not set</span>
        )}
      </div>
    </div>
  );
}
