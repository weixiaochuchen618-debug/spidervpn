#!/usr/bin/env python3
"""Verify T-09 through the real WebView2 host without a CDP debug port.

The product writes scheduling-only trace records only when both an isolated
SPIDERVPN_ROOT and SPIDERVPN_TEST_HOST_TRACE=1 are present. Native
mouse input clicks the actual window; WM_NULL probes the tao UI thread.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import winreg

from s0_page_fixtures import sha256_file
from s0_startup_baseline import screenshot, webview_ready, window_for_pid

SOURCE = Path(__file__).resolve().parents[1]
LIVE_EXE = Path(r"C:\SpiderVPN\bin\spidervpn.exe")
LIVE_CONFIG = Path(r"C:\SpiderVPN\data\config.json")
PROXY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
USER32 = ctypes.WinDLL("user32", use_last_error=True)


def proxy_snapshot() -> dict:
    values = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, PROXY_PATH) as key:
        for name in ("ProxyEnable", "ProxyServer", "AutoConfigURL"):
            try:
                values[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                values[name] = None
    return values


def live_snapshot() -> dict:
    return {
        "installedExeSha256": sha256_file(LIVE_EXE),
        "configSha256": sha256_file(LIVE_CONFIG),
        "proxy": proxy_snapshot(),
    }


def native_probe(hwnd: int) -> bool:
    if not hwnd:
        return False
    result = ctypes.c_size_t()
    USER32.SendMessageTimeoutW.argtypes = [
        wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t),
    ]
    USER32.SendMessageTimeoutW.restype = wintypes.LPARAM
    answered = USER32.SendMessageTimeoutW(hwnd, 0, 0, 0, 0x0002, 1000, ctypes.byref(result))
    return bool(answered)


def native_click_client(hwnd: int, x: int, y: int) -> dict:
    point = wintypes.POINT(x, y)
    USER32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
    USER32.ClientToScreen.restype = wintypes.BOOL
    if not USER32.ClientToScreen(hwnd, ctypes.byref(point)):
        raise RuntimeError(f"ClientToScreen 失败：{ctypes.get_last_error()}")
    USER32.SetForegroundWindow.argtypes = [wintypes.HWND]
    USER32.SetForegroundWindow.restype = wintypes.BOOL
    USER32.SetForegroundWindow(hwnd)
    USER32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
    USER32.SetCursorPos.restype = wintypes.BOOL
    if not USER32.SetCursorPos(point.x, point.y):
        raise RuntimeError(f"SetCursorPos 失败：{ctypes.get_last_error()}")
    USER32.mouse_event.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.ULONG)]
    USER32.mouse_event(0x0002, 0, 0, 0, None)
    USER32.mouse_event(0x0004, 0, 0, 0, None)
    return {"client": [x, y], "screen": [point.x, point.y]}


def native_wheel_client(hwnd: int, x: int, y: int, notches: int) -> dict:
    point = wintypes.POINT(x, y)
    USER32.ClientToScreen(hwnd, ctypes.byref(point))
    USER32.SetCursorPos(point.x, point.y)
    USER32.mouse_event.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.ULONG)]
    for _ in range(abs(notches)):
        USER32.mouse_event(0x0800, 0, 0, -120 if notches < 0 else 120, None)
        time.sleep(0.05)
    return {"client": [x, y], "notches": notches}


def prepare_window(hwnd: int) -> dict:
    # Popen 继承的启动环境偶尔会把顶层窗口创建成最小化；此时 ClientToScreen
    # 会返回 -32000 附近的哨兵坐标，原生点击必然落空。先恢复再定位/截图。
    USER32.IsIconic.argtypes = [wintypes.HWND]
    USER32.IsIconic.restype = wintypes.BOOL
    USER32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    USER32.ShowWindow.restype = wintypes.BOOL
    if USER32.IsIconic(hwnd):
        USER32.ShowWindow(hwnd, 9)  # SW_RESTORE
        time.sleep(0.2)
    screen_height = USER32.GetSystemMetrics(1)
    height = min(900, screen_height - 60)
    USER32.SetWindowPos.argtypes = [
        wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
        ctypes.c_int, ctypes.c_int, wintypes.UINT,
    ]
    USER32.SetWindowPos.restype = wintypes.BOOL
    if not USER32.SetWindowPos(hwnd, 0, 20, 20, 1116, height, 0x0004):
        raise RuntimeError(f"SetWindowPos 失败：{ctypes.get_last_error()}")
    time.sleep(0.5)
    return {"x": 20, "y": 20, "width": 1116, "height": height, "screenHeight": screen_height}


def read_trace(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            # 下一次读取会拿到完整行；半截并发写入不能当成终态证据。
            continue
    return records


def prepare_root(work: Path) -> Path:
    root = work / "root"
    data = root / "data"
    fixture = SOURCE / "fixtures" / "root-2lines" / "data"
    shutil.copytree(fixture / "lines", data / "lines")
    shutil.copy2(fixture / "config.json", data / "config.json")
    config_path = data / "config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["selected"] = "fixture-b"
    config["auto_connect"] = False
    config["close_to_tray"] = False
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    exe, work, report_dir = args.exe.resolve(), args.work.resolve(), args.report_dir.resolve()
    if not exe.is_file():
        raise RuntimeError(f"被测程序不存在：{exe}")
    allowed_work = Path(r"C:\tc-rs-build").resolve()
    if allowed_work not in work.parents:
        raise RuntimeError(f"工作目录必须位于 {allowed_work} 下：{work}")
    if work.exists():
        raise RuntimeError(f"工作目录必须不存在：{work}")
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True)
    root = prepare_root(work)
    trace_path = root / "data" / "logs" / "t09-host-events.jsonl"
    live_before = live_snapshot()
    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": f"Software\\SpiderVPN\\tests\\t09-webview-{os.getpid()}-proxy",
        "SPIDERVPN_RUN_KEY": f"Software\\SpiderVPN\\tests\\t09-webview-{os.getpid()}-run",
        "SPIDERVPN_FORCE_NONADMIN": "1",
        "SPIDERVPN_TEST_HOST_TRACE": "1",
    })
    env.pop("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", None)
    stdout_path = report_dir / "host.stdout.txt"
    stderr_path = report_dir / "host.stderr.txt"
    events: list[dict] = []
    samples: list[dict] = []
    native_replies: list[dict] = []
    input_samples: list[dict] = []
    process = None
    hwnd = 0
    close_timed_out = False
    probe_error = None
    real_webview_ready = False
    settings_clicked = False
    diagnose_clicked = False
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            process = subprocess.Popen(
                [str(exe)], cwd="C:\\", env=env,
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            )
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                hwnd = window_for_pid(process.pid)
                if hwnd and webview_ready(hwnd):
                    real_webview_ready = True
                    break
                if process.poll() is not None:
                    raise RuntimeError(f"产品进程提前退出：{process.returncode}")
                time.sleep(0.2)
            if not real_webview_ready:
                raise TimeoutError("真实 WebView2 窗口未就绪")
            window_layout = prepare_window(hwnd)
            input_samples.append({"stage": "window", **window_layout})
            screenshot(hwnd, report_dir / "host-initial.bmp")
            input_samples.append({"stage": "settings-click", **native_click_client(hwnd, 448, 26)})
            settings_clicked = True
            time.sleep(0.8)
            screenshot(hwnd, report_dir / "host-settings.bmp")
            input_samples.append({"stage": "settings-scroll", **native_wheel_client(hwnd, 700, 650, -4)})
            time.sleep(0.8)
            screenshot(hwnd, report_dir / "host-settings-scrolled.bmp")
            click_started = time.perf_counter()
            input_samples.append({"stage": "diagnose-click", **native_click_client(hwnd, 110, 432)})
            diagnose_clicked = True
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                events = [e for e in read_trace(trace_path) if e.get("cmd") == "diagnose"]
                terminal_delivered = any(
                    e.get("action") == "ui-evaluate-script" and e.get("terminal")
                    and e.get("evaluateScriptOk") is True for e in events
                )
                samples.append({
                    "afterClickMs": round((time.perf_counter() - click_started) * 1000, 1),
                    "eventCount": len(events),
                    "actions": [e.get("action") for e in events[-8:]],
                    "terminalDelivered": terminal_delivered,
                })
                if not terminal_delivered:
                    native_replies.append({
                        "afterClickMs": round((time.perf_counter() - click_started) * 1000, 1),
                        "ok": native_probe(hwnd),
                    })
                if terminal_delivered:
                    break
                if process.poll() is not None:
                    raise RuntimeError(f"产品在终态前退出：{process.returncode}")
                time.sleep(0.25)
            else:
                raise TimeoutError("真实宿主终态未在 35 秒内回推到页面")
            screenshot(hwnd, report_dir / "host-after.bmp")
        except Exception as exc:
            probe_error = repr(exc)
        finally:
            events = [e for e in read_trace(trace_path) if e.get("cmd") == "diagnose"]
            if process is not None and process.poll() is None and hwnd:
                USER32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
                USER32.PostMessageW.restype = wintypes.BOOL
                USER32.PostMessageW(hwnd, 0x0010, 0, 0)
            if process is not None:
                try:
                    process.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    close_timed_out = True
                    process.kill()
                    process.wait(timeout=3)

    sent = [e for e in events if e.get("action") == "event-sent"]
    queued = [e for e in sent if e.get("op", {}).get("phase") == "queued"]
    running = [e for e in sent if e.get("op", {}).get("phase") == "running"]
    terminal_sent = [e for e in sent if e.get("terminal")]
    terminal_ui = [
        e for e in events if e.get("action") == "ui-evaluate-script"
        and e.get("terminal") and e.get("evaluateScriptOk") is True
    ]
    first_terminal_at = min((e["observedAtUnixMs"] for e in terminal_sent), default=None)
    running_before_terminal = [
        e for e in running if first_terminal_at is None or e["observedAtUnixMs"] < first_terminal_at
    ]
    heartbeat_gap_ms = None
    if len(running_before_terminal) >= 2:
        heartbeat_gap_ms = (
            running_before_terminal[-1]["observedAtUnixMs"]
            - running_before_terminal[0]["observedAtUnixMs"]
        )
    started_values = {e.get("op", {}).get("startedAtUtc") for e in events}
    started_valid = len(started_values) == 1 and None not in started_values
    if started_valid:
        try:
            datetime.fromisoformat(next(iter(started_values)).replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            started_valid = False
    queued_threads = {e.get("threadId") for e in queued}
    running_threads = {e.get("threadId") for e in running_before_terminal}
    ui_threads = {e.get("threadId") for e in events if e.get("action") == "ui-evaluate-script"}
    live_after = live_snapshot()
    checks = {
        "realWebView2Ready": real_webview_ready,
        "nativeSettingsClickIssued": settings_clicked,
        "nativeDiagnoseClickIssued": diagnose_clicked,
        "noProbeError": probe_error is None,
        "queuedAccepted": bool(queued),
        "crossSecondHeartbeatBeforeTerminal": heartbeat_gap_ms is not None and heartbeat_gap_ms >= 700,
        "heartbeatCameFromWorkerThread": bool(queued_threads and running_threads) and not bool(queued_threads & running_threads),
        "terminalReplyEvaluatedOnUiThread": bool(terminal_ui) and terminal_ui[-1].get("hasDiagnose") is True,
        "terminalUiThreadMatchesAcceptThread": bool(queued_threads & ui_threads),
        "hostStartedAtUtcPresentAndStable": started_valid,
        "diagnoseBudgetFromTwoTcpTargets": all(e.get("op", {}).get("budgetSec") == 10 for e in events),
        "nativeWindowAnsweredDuringOperation": bool(native_replies) and all(x["ok"] for x in native_replies),
        "cleanClose": process is not None and process.returncode == 0 and not close_timed_out,
        "liveUnchanged": live_before == live_after,
    }
    payload = {
        "method": "real SpiderVPN WebView2; native client-coordinate mouse input; isolated host scheduling trace plus native WM_NULL SendMessageTimeout probes; no CDP or .NET UI Automation",
        "exe": str(exe), "exeSha256": sha256_file(exe), "root": str(root),
        "proxyKey": env["SPIDERVPN_PROXY_KEY"], "runKey": env["SPIDERVPN_RUN_KEY"],
        "tracePath": str(trace_path), "events": events, "samples": samples,
        "inputSamples": input_samples, "nativeReplies": native_replies,
        "heartbeatGapMs": heartbeat_gap_ms, "probeError": probe_error,
        "closeTimedOut": close_timed_out, "processExit": process.returncode if process else None,
        "checks": checks, "allPassed": all(checks.values()),
        "liveBefore": live_before, "liveAfter": live_after,
        "liveUnchanged": live_before == live_after, "workPreserved": work.exists(),
        "stdoutPath": str(stdout_path), "stderrPath": str(stderr_path),
    }
    report = report_dir / "t09-webview-runtime-0.1.4.json"
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "allPassed": payload["allPassed"], "checks": checks,
        "eventCount": len(events), "heartbeatGapMs": heartbeat_gap_ms,
        "liveUnchanged": payload["liveUnchanged"], "report": str(report),
        "probeError": probe_error,
    }, ensure_ascii=True))
    return 0 if payload["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
