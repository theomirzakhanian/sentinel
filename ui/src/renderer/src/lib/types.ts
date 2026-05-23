/**
 * Shared types mirroring Sentinel's Python models. Keep in sync with
 * sentinel/models.py if anything changes there.
 */

export type Verdict = "ALLOW" | "BLOCK";
export type SignalVerdict =
  | "ALLOW"
  | "BLOCK"
  | "UNKNOWN"
  | "TIMEOUT"
  | "ERROR"
  | "SKIPPED";
export type StageName = "virustotal" | "triage" | "ai_review";

export interface Signal {
  stage: StageName | string;
  verdict: SignalVerdict;
  score: number | null;
  summary: string;
  evidence: Record<string, unknown>;
  duration_seconds: number | null;
}

export interface Report {
  file_path: string;
  file_name: string;
  sha256: string;
  sha1: string;
  md5: string;
  size_bytes: number;
  started_at: string;
  completed_at: string;
  signals: Signal[];
  final_verdict: Verdict;
  reasons: string[];
}

export interface HistoryEntry {
  report_file: string;
  file_name: string;
  sha256: string;
  size_bytes: number;
  final_verdict: Verdict;
  started_at: string;
  completed_at: string;
}

/* ----- SSE event envelopes from /scan/<id>/events ----- */

export type SentinelEvent =
  | { type: "scan.started"; data: { file_path: string; file_name: string; size_bytes: number; sha256: string }; ts: number }
  | { type: "stage.started"; data: { stage: StageName }; ts: number }
  | { type: "stage.finished"; data: { stage: StageName; signal: Signal }; ts: number }
  | { type: "verdict.final"; data: { final_verdict: Verdict; score: number; reasons: string[] }; ts: number }
  | { type: "cancelled"; data: Record<string, never>; ts: number }
  | { type: "error"; data: { message: string }; ts: number }
  | { type: "end"; data: { status: string }; ts: number };
