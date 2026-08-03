#!/usr/bin/env bash
set -euo pipefail

APK_PATH="${1:?Usage: android-emulator-smoke.sh APK_PATH PACKAGE_NAME [EVIDENCE_DIR]}"
PACKAGE_NAME="${2:?Usage: android-emulator-smoke.sh APK_PATH PACKAGE_NAME [EVIDENCE_DIR]}"
EVIDENCE_DIR="${3:-android-emulator-evidence}"

mkdir -p "$EVIDENCE_DIR"

collect_evidence() {
  adb shell uiautomator dump /sdcard/airvault-window.xml >/dev/null 2>&1 || true
  adb pull /sdcard/airvault-window.xml "$EVIDENCE_DIR/window.xml" >/dev/null 2>&1 || true
  adb exec-out screencap -p > "$EVIDENCE_DIR/screenshot.png" 2>/dev/null || true
  adb shell dumpsys activity activities > "$EVIDENCE_DIR/activity.txt" 2>&1 || true
  adb shell dumpsys package "$PACKAGE_NAME" > "$EVIDENCE_DIR/package.txt" 2>&1 || true
  adb logcat -d -b main,system,crash -v threadtime > "$EVIDENCE_DIR/logcat.txt" 2>&1 || true
}
trap collect_evidence EXIT

test -s "$APK_PATH"
adb wait-for-device
adb shell getprop ro.build.version.sdk | tee "$EVIDENCE_DIR/api-level.txt"

if command -v apksigner >/dev/null 2>&1; then
  apksigner verify --verbose --print-certs "$APK_PATH" | tee "$EVIDENCE_DIR/apksigner.txt"
fi

adb install -r -t "$APK_PATH" | tee "$EVIDENCE_DIR/install.txt"
adb shell pm path "$PACKAGE_NAME" | tee "$EVIDENCE_DIR/installed-package.txt"
grep -F "package:" "$EVIDENCE_DIR/installed-package.txt" >/dev/null

LAUNCH_ACTIVITY="$(adb shell cmd package resolve-activity --brief "$PACKAGE_NAME" | tr -d '\r' | tail -n 1)"
if [[ -z "$LAUNCH_ACTIVITY" || "$LAUNCH_ACTIVITY" == "No activity found" ]]; then
  echo "No launcher activity resolved for $PACKAGE_NAME" >&2
  exit 1
fi

adb logcat -c
adb shell am force-stop "$PACKAGE_NAME"
adb shell am start -W -n "$LAUNCH_ACTIVITY" | tee "$EVIDENCE_DIR/launch.txt"
sleep 3

PID="$(adb shell pidof "$PACKAGE_NAME" | tr -d '\r')"
if [[ -z "$PID" ]]; then
  echo "AirVault process exited during cold start" >&2
  exit 1
fi
echo "$PID" > "$EVIDENCE_DIR/pid.txt"

adb shell dumpsys activity activities > "$EVIDENCE_DIR/activity-before-assert.txt"
if ! grep -E "(mResumedActivity|topResumedActivity).*${PACKAGE_NAME}" "$EVIDENCE_DIR/activity-before-assert.txt" >/dev/null; then
  echo "AirVault is not the resumed foreground activity" >&2
  exit 1
fi

for attempt in 1 2 3 4 5; do
  adb shell uiautomator dump /sdcard/airvault-window.xml >/dev/null 2>&1 || true
  adb pull /sdcard/airvault-window.xml "$EVIDENCE_DIR/window-before-assert.xml" >/dev/null 2>&1 || true
  if grep -F 'text="AirVault"' "$EVIDENCE_DIR/window-before-assert.xml" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

grep -F 'text="AirVault"' "$EVIDENCE_DIR/window-before-assert.xml" >/dev/null
grep -E 'text="AV-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}-[A-Z2-7]{5}"' \
  "$EVIDENCE_DIR/window-before-assert.xml" >/dev/null

adb logcat -d -b main,system,crash -v threadtime > "$EVIDENCE_DIR/logcat-before-assert.txt"
if grep -E "FATAL EXCEPTION|Process: ${PACKAGE_NAME}.*has died" "$EVIDENCE_DIR/logcat-before-assert.txt" >/dev/null; then
  echo "Crash evidence was found after launch" >&2
  exit 1
fi

echo "AirVault installed and cold-started successfully as $PACKAGE_NAME (PID $PID)."
