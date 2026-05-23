import { useCallback, useEffect, useMemo, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { ShieldGlyph } from "./components/ShieldGlyph";
import { DropZone } from "./components/DropZone";
import { HistorySidebar } from "./components/HistorySidebar";
import { ScanInProgress } from "./components/ScanInProgress";
import { VerdictScreen } from "./components/VerdictScreen";
import { useScan } from "./lib/useScan";
import { fetchReport } from "./lib/api";
import type { Report } from "./lib/types";

type View =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "verdict"; report: Report; scoreOverride?: number };

function buildReportFromScan(state: ReturnType<typeof useScan>["state"]): Report | null {
  if (!state.file || state.finalVerdict == null) return null;
  return {
    file_path: state.file.path,
    file_name: state.file.name,
    sha256: state.file.sha256,
    sha1: "",
    md5: "",
    size_bytes: state.file.size,
    started_at: new Date().toISOString(),
    completed_at: new Date().toISOString(),
    signals: Object.values(state.signals),
    final_verdict: state.finalVerdict,
    reasons: state.reasons,
  };
}

export default function App() {
  const [view, setView] = useState<View>({ kind: "idle" });
  const [historyKey, setHistoryKey] = useState(0);
  const { state, begin, cancel, reset } = useScan();

  // Drive view transitions from scan state
  useEffect(() => {
    if (state.phase === "running" && view.kind === "idle") {
      setView({ kind: "scanning" });
    }
    if (state.phase === "complete" && view.kind === "scanning") {
      const report = buildReportFromScan(state);
      if (report) {
        setView({ kind: "verdict", report, scoreOverride: state.finalScore ?? state.partialScore });
        setHistoryKey((k) => k + 1);
      }
    }
    if (state.phase === "error" && view.kind === "scanning") {
      // surface error as a verdict-ish screen later; for now bounce back to idle
      setView({ kind: "idle" });
    }
  }, [state, view.kind]);

  const handleFile = useCallback(
    (path: string) => {
      begin(path);
    },
    [begin],
  );

  const handleScanAnother = useCallback(() => {
    reset();
    setView({ kind: "idle" });
  }, [reset]);

  const handleHistoryClick = useCallback(async (reportFile: string) => {
    // reportFile is like "20260523T034550Z_7451fbbf37fe.json" — use the sha prefix
    const shaPrefix = reportFile.split("_")[1]?.replace(".json", "");
    if (!shaPrefix) return;
    const report = await fetchReport(shaPrefix);
    if (report) setView({ kind: "verdict", report });
  }, []);

  const headerStatus = useMemo(() => {
    if (view.kind === "scanning") return "Analyzing";
    if (view.kind === "verdict") return view.report.final_verdict === "BLOCK" ? "Blocked" : "Allowed";
    return "Ready";
  }, [view]);

  return (
    <div className="flex h-full w-full flex-col bg-surface-0">
      <header className="app-titlebar flex h-11 shrink-0 items-center justify-between border-b border-line px-4">
        <div className="flex items-center gap-2 pl-16 text-ink">
          <ShieldGlyph size={16} className="text-accent" />
          <span className="text-xs font-semibold uppercase tracking-[0.18em]">
            Sentinel
          </span>
        </div>
        <div className="flex items-center gap-2 text-[11px] text-ink-muted">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-accent" />
          <span className="uppercase tracking-wider">{headerStatus}</span>
        </div>
      </header>

      <main className="flex flex-1 gap-4 overflow-hidden p-4">
        <HistorySidebar refreshKey={historyKey} onSelect={handleHistoryClick} />

        <section className="relative min-w-0 flex-1">
          <AnimatePresence mode="wait">
            {view.kind === "idle" && (
              <motion.div
                key="idle"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
                className="h-full"
              >
                <DropZone onFile={handleFile} />
              </motion.div>
            )}
            {view.kind === "scanning" && (
              <motion.div
                key="scanning"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
                className="h-full"
              >
                <ScanInProgress
                  state={state}
                  onCancel={() => {
                    cancel();
                    handleScanAnother();
                  }}
                />
              </motion.div>
            )}
            {view.kind === "verdict" && (
              <motion.div
                key="verdict"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                transition={{ duration: 0.32, ease: [0.16, 1, 0.3, 1] }}
                className="card-dark h-full overflow-hidden rounded-xl"
              >
                <VerdictScreen
                  report={view.report}
                  scoreOverride={view.scoreOverride}
                  onScanAnother={handleScanAnother}
                />
              </motion.div>
            )}
          </AnimatePresence>
        </section>
      </main>
    </div>
  );
}
