import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Sidebar, type PageKey } from "./components/Sidebar";
import { DropZone } from "./components/DropZone";
import { ScanInProgress } from "./components/ScanInProgress";
import { VerdictScreen } from "./components/VerdictScreen";
import { OverviewPage } from "./components/OverviewPage";
import { HistoryPage } from "./components/HistoryPage";
import { SettingsPage } from "./components/SettingsPage";
import { useScan } from "./lib/useScan";
import { fetchReport } from "./lib/api";
import type { Report } from "./lib/types";

type VerdictSource = "fresh" | "history";

type ScanView =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "verdict"; report: Report; scoreOverride?: number; source: VerdictSource };

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
  const [page, setPage] = useState<PageKey>("overview");
  const [scanView, setScanView] = useState<ScanView>({ kind: "idle" });
  const [historyKey, setHistoryKey] = useState(0);
  const { state, begin, cancel, reset } = useScan();

  // Drive scan-view transitions from scan state
  useEffect(() => {
    if (state.phase === "running" && scanView.kind === "idle") {
      setScanView({ kind: "scanning" });
    }
    if (state.phase === "complete" && scanView.kind === "scanning") {
      const report = buildReportFromScan(state);
      if (report) {
        setScanView({
          kind: "verdict",
          report,
          scoreOverride: state.finalScore ?? state.partialScore,
          source: "fresh",
        });
        setHistoryKey((k) => k + 1);
      }
    }
    if (state.phase === "error" && scanView.kind === "scanning") {
      setScanView({ kind: "idle" });
    }
  }, [state, scanView.kind]);

  const handleFile = useCallback(
    (path: string) => {
      setPage("scan");
      begin(path);
    },
    [begin],
  );

  const handleScanAnother = useCallback(() => {
    reset();
    setScanView({ kind: "idle" });
  }, [reset]);

  const handleOpenReport = useCallback(async (reportFile: string) => {
    const shaPrefix = reportFile.split("_")[1]?.replace(".json", "");
    if (!shaPrefix) return;
    const report = await fetchReport(shaPrefix);
    if (report) {
      setScanView({ kind: "verdict", report, source: "history" });
      setPage("scan");
    }
  }, []);

  const handleBackToHistory = useCallback(() => {
    reset();
    setScanView({ kind: "idle" });
    setPage("history");
  }, [reset]);

  return (
    <div className="flex h-full w-full bg-surface-0">
      {/* Title bar — drag region only; no nav (sidebar handles that). */}
      <div className="app-titlebar pointer-events-none absolute inset-x-0 top-0 z-10 h-9" />

      <Sidebar
        current={page}
        onSelect={(p) => {
          // Clear a history-sourced verdict when leaving via the sidebar so the
          // Scan tab returns to its idle drop-zone instead of a stale report.
          if (
            scanView.kind === "verdict" &&
            scanView.source === "history" &&
            p !== "scan"
          ) {
            reset();
            setScanView({ kind: "idle" });
          }
          setPage(p);
        }}
      />

      <main className="flex-1 overflow-hidden">
        <AnimatePresence mode="wait">
          {page === "overview" && (
            <PageWrapper key="overview">
              <OverviewPage
                refreshKey={historyKey}
                onScanClick={() => setPage("scan")}
              />
            </PageWrapper>
          )}

          {page === "scan" && (
            <PageWrapper key="scan">
              <div className="h-full w-full p-4 pt-10">
                <AnimatePresence mode="wait">
                  {scanView.kind === "idle" && (
                    <PageWrapper key="scan-idle">
                      <DropZone onFile={handleFile} />
                    </PageWrapper>
                  )}
                  {scanView.kind === "scanning" && (
                    <PageWrapper key="scan-running">
                      <ScanInProgress
                        state={state}
                        onCancel={() => {
                          cancel();
                          handleScanAnother();
                        }}
                      />
                    </PageWrapper>
                  )}
                  {scanView.kind === "verdict" && (
                    <PageWrapper key="scan-verdict">
                      <div className="card-dark h-full overflow-hidden rounded-xl">
                        <VerdictScreen
                          report={scanView.report}
                          scoreOverride={scanView.scoreOverride}
                          source={scanView.source}
                          onScanAnother={handleScanAnother}
                          onBackToHistory={handleBackToHistory}
                        />
                      </div>
                    </PageWrapper>
                  )}
                </AnimatePresence>
              </div>
            </PageWrapper>
          )}

          {page === "history" && (
            <PageWrapper key="history">
              <HistoryPage refreshKey={historyKey} onOpenReport={handleOpenReport} />
            </PageWrapper>
          )}

          {page === "settings" && (
            <PageWrapper key="settings">
              <SettingsPage />
            </PageWrapper>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}

function PageWrapper({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 4 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -4 }}
      transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
      className="h-full w-full"
    >
      {children}
    </motion.div>
  );
}
