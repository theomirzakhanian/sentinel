/**
 * Spawn and manage the local Sentinel Python daemon.
 *
 * In dev we shell out to the repo's venv: `<repo>/.venv/bin/sentinel serve`.
 * In production this should be wired to a bundled CPython + sentinel wheel
 * (deferred to packaging phase).
 */
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { app } from "electron";
import path from "node:path";

let proc: ChildProcess | null = null;
let resolvedUrl: string | null = null;

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 7331;
const SENTINEL_REPO = path.resolve(app.getAppPath(), "..");
const SENTINEL_BIN_DEFAULT = path.join(SENTINEL_REPO, ".venv", "bin", "sentinel");

function findFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, DEFAULT_HOST, () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

async function probe(url: string, timeoutMs = 8000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${url}/health`);
      if (r.ok) return true;
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  return false;
}

export async function startDaemon(): Promise<string> {
  if (resolvedUrl) return resolvedUrl;

  let port = DEFAULT_PORT;
  try {
    await new Promise<void>((resolve, reject) => {
      const srv = createServer();
      srv.unref();
      srv.once("error", reject);
      srv.listen(port, DEFAULT_HOST, () => srv.close(() => resolve()));
    });
  } catch {
    port = await findFreePort();
  }

  const binary = process.env.SENTINEL_BIN || SENTINEL_BIN_DEFAULT;
  console.log(`[daemon] launching ${binary} serve --host ${DEFAULT_HOST} --port ${port}`);

  const child = spawn(binary, ["serve", "--host", DEFAULT_HOST, "--port", String(port)], {
    cwd: SENTINEL_REPO,
    env: { ...process.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  proc = child;

  child.stdout?.on("data", (b: Buffer) => console.log(`[daemon] ${b.toString().trimEnd()}`));
  child.stderr?.on("data", (b: Buffer) => console.warn(`[daemon!] ${b.toString().trimEnd()}`));
  child.on("exit", (code, sig) => {
    console.warn(`[daemon] exited code=${code} sig=${sig}`);
    proc = null;
    resolvedUrl = null;
  });

  const url = `http://${DEFAULT_HOST}:${port}`;
  const ready = await probe(url, 10_000);
  if (!ready) {
    throw new Error(`Sentinel daemon failed to start at ${url}. Check that ${binary} exists.`);
  }
  resolvedUrl = url;
  return url;
}

export function stopDaemon(): void {
  if (proc && !proc.killed) {
    proc.kill("SIGTERM");
    proc = null;
    resolvedUrl = null;
  }
}

export function getDaemonUrl(): string | null {
  return resolvedUrl;
}
