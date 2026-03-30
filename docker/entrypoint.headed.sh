#!/usr/bin/env bash
set -euo pipefail

XVFB_WHD="${XVFB_WHD:-1920x1080x24}"
DISPLAY="${DISPLAY:-:99}"
export DISPLAY
export XVFB_WHD
export ALLOW_DOCKER_HEADED_CAPTCHA="${ALLOW_DOCKER_HEADED_CAPTCHA:-true}"

X_NUM="${DISPLAY#:}"
rm -f "/tmp/.X${X_NUM}-lock" "/tmp/.X11-unix/X${X_NUM}" || true

Xvfb "$DISPLAY" -screen 0 "$XVFB_WHD" -ac +extension RANDR +render -nolisten tcp >/tmp/xvfb.log 2>&1 &
fluxbox >/tmp/fluxbox.log 2>&1 &

for i in $(seq 1 30); do
  if xdpyinfo -display "$DISPLAY" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

if ! xdpyinfo -display "$DISPLAY" >/dev/null 2>&1; then
  echo "[entrypoint] Xvfb 初始化失败: DISPLAY=$DISPLAY"
  tail -n 120 /tmp/xvfb.log || true
  exit 1
fi

if [ -z "${BROWSER_EXECUTABLE_PATH:-}" ]; then
  BROWSER_EXECUTABLE_PATH="$(python - <<'PY'
from playwright.sync_api import sync_playwright

try:
    with sync_playwright() as p:
        print(p.chromium.executable_path)
except Exception:
    print("")
PY
)"
  if [ -n "${BROWSER_EXECUTABLE_PATH}" ]; then
    export BROWSER_EXECUTABLE_PATH
    echo "[entrypoint] browser executable: ${BROWSER_EXECUTABLE_PATH}"
  else
    echo "[entrypoint] warning: failed to resolve Playwright Chromium executable"
  fi
fi

exec python main.py
