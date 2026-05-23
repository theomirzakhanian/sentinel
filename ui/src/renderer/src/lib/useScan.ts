/**
 * useScan — owns the lifecycle of one running scan against the daemon.
 * Receives SSE events, builds up signals incrementally, computes a partial
 * weighted score as evidence arrives, and produces the final verdict.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { cancelScan, startScan, subscribeToScan } from "./api";
import type { SentinelEvent, Signal, StageName, Verdict } from "./types";

const STAGE_WEIGHTS: Record<string, number> = {
  virustotal: 0.4,
  ai_review: 0.35,
  triage: 0.25,
};

function partialScore(signals: Record<string, Signal>): number {
  let total = 0;
  for (const [stage, sig] of Object.entries(signals)) {
    const w = STAGE_WEIGHTS[stage] ?? 0.2;
    total += signalContribution(stage, sig) * w;
  }
  return total;
}

function signalContribution(stage: string, s: Signal): number {
  if (s.verdict === "SKIPPED") return 0;
  if (stage === "virustotal") {
    if (s.verdict === "ALLOW") return -0.3;
    if (s.verdict === "BLOCK") {
      const stats = (s.evidence?.stats as Record<string, number>) ?? {};
      const mal = Number(stats.malicious ?? 0);
      const susp = Number(stats.suspicious ?? 0);
      const total =
        mal + susp + Number(stats.harmless ?? 0) + Number(stats.undetected ?? 0) + Number(stats.timeout ?? 0);
      if (total === 0) return 0;
      const ratio = (mal + susp) / total;
      if (ratio < 0.04) return 0;
      return Math.min(ratio * 2, 1.0);
    }
    return 0;
  }
  if (stage === "ai_review") {
    const c = s.score ?? 0.5;
    if (s.verdict === "ALLOW") return -c;
    if (s.verdict === "BLOCK") return c;
    return 0;
  }
  if (stage === "triage") {
    if (s.verdict === "ALLOW") return -0.3;
    if (s.verdict === "BLOCK") return Math.min((s.score ?? 5) / 10, 1.0);
    return 0;
  }
  return 0;
}

export type Phase = "queued" | "running" | "complete" | "cancelled" | "error";

export interface ScanState {
  id: string | null;
  phase: Phase;
  file: { name: string; path: string; size: number; sha256: string } | null;
  signals: Record<string, Signal>;
  currentStage: StageName | null;
  partialScore: number;
  finalVerdict: Verdict | null;
  finalScore: number | null;
  reasons: string[];
  error: string | null;
}

const INITIAL: ScanState = {
  id: null,
  phase: "queued",
  file: null,
  signals: {},
  currentStage: null,
  partialScore: 0,
  finalVerdict: null,
  finalScore: null,
  reasons: [],
  error: null,
};

export function useScan() {
  const [state, setState] = useState<ScanState>(INITIAL);
  const unsubRef = useRef<(() => void) | null>(null);

  const reset = useCallback(() => {
    if (unsubRef.current) {
      unsubRef.current();
      unsubRef.current = null;
    }
    setState(INITIAL);
  }, []);

  const begin = useCallback(async (filePath: string) => {
    reset();
    try {
      const scanId = await startScan(filePath);
      setState((s) => ({ ...s, id: scanId, phase: "running" }));
      const unsub = await subscribeToScan(scanId, (ev: SentinelEvent) => {
        setState((s) => applyEvent(s, ev));
      });
      unsubRef.current = unsub;
    } catch (e) {
      setState((s) => ({ ...s, phase: "error", error: (e as Error).message }));
    }
  }, [reset]);

  const cancel = useCallback(async () => {
    if (state.id && state.phase === "running") {
      try {
        await cancelScan(state.id);
      } catch {
        // best-effort
      }
    }
  }, [state.id, state.phase]);

  useEffect(() => () => {
    if (unsubRef.current) unsubRef.current();
  }, []);

  return { state, begin, cancel, reset };
}

function applyEvent(s: ScanState, ev: SentinelEvent): ScanState {
  switch (ev.type) {
    case "scan.started":
      return {
        ...s,
        phase: "running",
        file: {
          name: ev.data.file_name,
          path: ev.data.file_path,
          size: ev.data.size_bytes,
          sha256: ev.data.sha256,
        },
      };
    case "stage.started":
      return { ...s, currentStage: ev.data.stage };
    case "stage.finished": {
      const next = { ...s.signals, [ev.data.stage]: ev.data.signal };
      return {
        ...s,
        signals: next,
        currentStage: null,
        partialScore: partialScore(next),
      };
    }
    case "verdict.final":
      return {
        ...s,
        finalVerdict: ev.data.final_verdict,
        finalScore: ev.data.score,
        reasons: ev.data.reasons,
      };
    case "cancelled":
      return { ...s, phase: "cancelled" };
    case "error":
      return { ...s, phase: "error", error: ev.data.message };
    case "end":
      return {
        ...s,
        phase: ev.data.status === "completed" ? "complete" : (ev.data.status as Phase),
      };
    default:
      return s;
  }
}
