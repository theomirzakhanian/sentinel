import { contextBridge, ipcRenderer, webUtils } from "electron";

const api = {
  /** Returns the local daemon base URL (e.g. "http://127.0.0.1:7331"). */
  getDaemonUrl: (): Promise<string | { error: string }> =>
    ipcRenderer.invoke("daemon:url"),

  /** Open native file picker; returns absolute path or null. */
  pickFile: (): Promise<string | null> => ipcRenderer.invoke("dialog:pickFile"),

  /**
   * Convert a drag-dropped DOM File into a filesystem path. Electron 32+
   * removed the legacy `file.path` so we use webUtils.getPathForFile.
   */
  pathForFile: (file: File): string => webUtils.getPathForFile(file),
};

contextBridge.exposeInMainWorld("sentinel", api);

export type SentinelAPI = typeof api;
