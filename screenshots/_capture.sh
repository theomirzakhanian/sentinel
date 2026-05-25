#!/bin/bash
# Capture the Sentinel Electron window to screenshots/<name>.png.
# Usage:  ./_capture.sh <name>
# Brings Sentinel to front, waits, then captures just the window region.

set -e
NAME="${1:?usage: _capture.sh <name>}"
DEST="$(dirname "$0")/${NAME}.png"
PY="$(dirname "$0")/../.venv/bin/python"

# Activate Sentinel + read current window bounds, then capture.
BOUNDS=$("$PY" -c "
from AppKit import NSWorkspace
import Quartz, time
for app in NSWorkspace.sharedWorkspace().runningApplications():
    if app.localizedName() == 'Electron':
        app.activateWithOptions_(0)
        break
time.sleep(0.6)
wins = Quartz.CGWindowListCopyWindowInfo(
    Quartz.kCGWindowListOptionOnScreenOnly | Quartz.kCGWindowListExcludeDesktopElements,
    Quartz.kCGNullWindowID,
)
for w in wins:
    if w.get('kCGWindowOwnerName') == 'Electron' and 'Sentinel' in (w.get('kCGWindowName') or ''):
        b = w['kCGWindowBounds']
        print(f\"{b['X']:.0f},{b['Y']:.0f},{b['Width']:.0f},{b['Height']:.0f}\")
        break
")

if [[ -z "$BOUNDS" ]]; then
    echo "Sentinel window not found" >&2
    exit 1
fi

screencapture -R "$BOUNDS" -o -x "$DEST"
echo "captured: $DEST  (region: $BOUNDS)"
