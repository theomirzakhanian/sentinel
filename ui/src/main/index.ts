import { app, BrowserWindow, dialog, ipcMain, nativeImage, shell } from "electron";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { getDaemonUrl, startDaemon, stopDaemon } from "./daemon.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ICON_PATH = path.join(__dirname, "..", "..", "resources", "icon.png");

let win: BrowserWindow | null = null;

async function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 960,
    minHeight: 640,
    show: false,
    titleBarStyle: "hiddenInset",
    backgroundColor: "#101113",
    icon: nativeImage.createFromPath(ICON_PATH),
    webPreferences: {
      preload: path.join(__dirname, "../preload/index.mjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  win.once("ready-to-show", () => win?.show());
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  const devUrl = process.env["ELECTRON_RENDERER_URL"];
  if (devUrl) {
    await win.loadURL(devUrl);
  } else {
    await win.loadFile(path.join(__dirname, "../renderer/index.html"));
  }
}

app.whenReady().then(async () => {
  // macOS Dock icon (BrowserWindow.icon doesn't reach the Dock on Mac)
  if (process.platform === "darwin" && app.dock) {
    try {
      app.dock.setIcon(nativeImage.createFromPath(ICON_PATH));
    } catch {
      // ignore — falls back to default
    }
  }

  ipcMain.handle("daemon:url", async () => {
    if (getDaemonUrl()) return getDaemonUrl();
    try {
      return await startDaemon();
    } catch (e) {
      return { error: (e as Error).message };
    }
  });

  ipcMain.handle("dialog:pickFile", async () => {
    const r = await dialog.showOpenDialog({
      properties: ["openFile"],
      title: "Choose a binary to scan",
    });
    if (r.canceled || r.filePaths.length === 0) return null;
    return r.filePaths[0];
  });

  try {
    await startDaemon();
  } catch (e) {
    console.error("[main] daemon failed to start:", e);
  }
  await createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  stopDaemon();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", () => stopDaemon());
