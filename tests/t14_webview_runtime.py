#!/usr/bin/env python3
"""Verify T-14 through the real WebView2 host and a real reconnect.

The engine is PING.EXE with harmless loopback arguments. Import, connection,
proxy writes, host traces and runtime files are isolated below C:\\tc-rs-build.
No real installation, line configuration or WinINET system proxy is modified.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import winreg

from s0_page_fixtures import sha256_file
from s0_startup_baseline import screenshot, webview_ready, window_for_pid
from t09_webview_runtime import (
    USER32,
    live_snapshot,
    native_click_client,
    native_probe,
    prepare_window,
    read_trace,
)
from t13_webview_runtime import close_window, delete_temp_key

PING = Path(r"C:\Windows\System32\PING.EXE")
ENGINE_ARGS = "-n 300 127.0.0.1"
KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)


def free_port() -> int:
    while True:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port <= 60000:
            return port


def pid_alive(pid: int) -> bool:
    handle = KERNEL32.OpenProcess(0x1000, False, pid)
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        return bool(KERNEL32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
    finally:
        KERNEL32.CloseHandle(handle)


def wait_pid_dead(pid: int, timeout: float = 6) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            return True
        time.sleep(0.1)
    return not pid_alive(pid)


def proxy_snapshot(path: str) -> dict:
    values = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
            try:
                values[name] = winreg.QueryValueEx(key, name)[0]
            except FileNotFoundError:
                values[name] = None
    return values


def transport_shape(path: Path) -> str | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    endpoints = [e for e in value.get("endpoints", []) if e.get("type") == "wireguard"]
    if not endpoints:
        return None
    if all("detour" not in e for e in endpoints):
        return "标准连接"
    if all(e.get("detour") == "tc-transport" for e in endpoints):
        for outbound in value.get("outbounds", []):
            if outbound.get("tag") == "tc-transport" and outbound.get("type") == "vless":
                tls = outbound.get("tls", {})
                if tls.get("enabled") is True and tls.get("reality", {}).get("enabled") is True:
                    return "兼容连接"
    return None


def write_profile(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "inbounds": [{"type": "tun", "tag": "trade-tun"}],
        "dns": {"servers": [{"type": "udp", "tag": "dns-direct", "server": "192.168.1.1"}]},
        "endpoints": [{"type": "wireguard", "tag": "hk", "address": ["10.7.0.2/32"]}],
        "route": {"rules": [], "final": "trade-exit"},
        "outbounds": [
            {
                "type": "vless", "tag": "provider-a", "server": "203.0.113.7", "server_port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "tls": {
                    "enabled": True, "server_name": "cdn.example.com",
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1",
                        "short_id": "ab12",
                    },
                },
            },
            {"type": "selector", "tag": "trade-exit", "outbounds": ["hk"], "default": "hk"},
            {"type": "direct", "tag": "direct"},
        ],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run_cli(exe: Path, env: dict, work: Path, tag: str, args: list[str]) -> dict:
    stdout_path = work / f"{tag}.stdout.txt"
    stderr_path = work / f"{tag}.stderr.txt"
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            [str(exe), *args], cwd="C:\\", env=env,
            stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
        )
        try:
            code = process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            raise TimeoutError(f"CLI {tag} 超过 45 秒")
    return {
        "tag": tag, "args": args, "exit": code,
        "stdout": stdout_path.read_text(encoding="utf-8", errors="replace"),
        "stderr": stderr_path.read_text(encoding="utf-8", errors="replace"),
    }


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--capture-only", action="store_true")
    # 已由真实 WebView2 截图与原生点击验收的按钮中心；仍可显式覆盖以适配布局变化。
    parser.add_argument("--x", type=int, default=150)
    parser.add_argument("--y", type=int, default=550)
    args = parser.parse_args()
    exe, work, report_dir = args.exe.resolve(), args.work.resolve(), args.report_dir.resolve()
    allowed_work = Path(r"C:\tc-rs-build").resolve()
    if not exe.is_file() or not PING.is_file():
        raise RuntimeError(f"被测程序或假引擎不存在：{exe}, {PING}")
    if allowed_work not in work.parents:
        raise RuntimeError(f"工作目录必须位于 {allowed_work} 下：{work}")
    if work.exists():
        raise RuntimeError(f"工作目录必须不存在：{work}")
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True)

    root = work / "root"
    data = root / "data"
    data.mkdir(parents=True)
    runtime_path = data / "runtime.json"
    engine_config_path = data / "runtime-engine.json"
    check_path = data / "last-check.json"
    trace_path = data / "logs" / "t09-host-events.jsonl"
    profile = work / "source" / "dual-mode.json"
    write_profile(profile)
    port = free_port()
    endpoint = f"127.0.0.1:{port}"
    proxy_key = f"Software\\SpiderVPN\\tests\\t14-webview-{os.getpid()}-proxy"
    run_key = f"Software\\SpiderVPN\\tests\\t14-webview-{os.getpid()}-run"
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, proxy_key) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:7897")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*")
    original_proxy = proxy_snapshot(proxy_key)
    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": proxy_key,
        "SPIDERVPN_RUN_KEY": run_key,
        "SPIDERVPN_FORCE_NONADMIN": "1",
        "SPIDERVPN_TEST_HOST_TRACE": "1",
        "SPIDERVPN_ENGINE_ARGS": ENGINE_ARGS,
    })
    env.pop("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", None)

    live_before = live_snapshot()
    cli: list[dict] = []
    process = None
    hwnd = 0
    ready = False
    clicked = False
    close_timed_out = False
    probe_error = None
    events: list[dict] = []
    samples: list[dict] = []
    native_replies: list[dict] = []
    input_samples: list[dict] = []
    screenshots: list[dict] = []
    before_runtime = None
    after_runtime = None
    before_check = None
    before_shape = None
    after_shape = None
    during_proxy = None
    final_proxy = None
    old_pid_dead = False
    new_pid_alive = False
    final_new_pid_dead = False
    final_runtime_absent = False
    config_transport = None
    stdout_path = report_dir / "host.stdout.txt"
    stderr_path = report_dir / "host.stderr.txt"

    try:
        imported = run_cli(exe, env, work, "import", [
            "--import", str(profile), "--engine", str(PING),
            "--port", str(port), "--line-name", "T14 隔离线路",
        ])
        cli.append(imported)
        if imported["exit"] != 0:
            raise RuntimeError(f"隔离线路导入失败：{imported}")
        config_path = data / "config.json"
        config = read_json(config_path)
        config["auto_connect"] = False
        config["close_to_tray"] = False
        config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        connected = run_cli(exe, env, work, "initial-connect", ["--connect"])
        cli.append(connected)
        if connected["exit"] != 0:
            raise RuntimeError(f"初始标准连接失败：{connected}")
        before_runtime = read_json(runtime_path)
        before_check = read_json(check_path)
        before_shape = transport_shape(engine_config_path)
        if before_check.get("ok") is not False or before_check.get("skipped") is not None:
            raise AssertionError(f"动作资格必须来自真实自检未通过：{before_check}")
        if before_shape != "标准连接" or not pid_alive(before_runtime["EnginePid"]):
            raise AssertionError("初始引擎或标准连接运行时证据不成立")

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
                        ready = True
                        break
                    if process.poll() is not None:
                        raise RuntimeError(f"产品进程提前退出：{process.returncode}")
                    time.sleep(0.2)
                if not ready:
                    raise TimeoutError("真实 WebView2 窗口未就绪")
                input_samples.append({"stage": "window", **prepare_window(hwnd)})
                time.sleep(1)
                screenshots.append(screenshot(hwnd, report_dir / "host-initial.bmp"))
                if not args.capture_only:
                    click_started = time.perf_counter()
                    input_samples.append({
                        "stage": "compatible-click",
                        **native_click_client(hwnd, args.x, args.y),
                    })
                    clicked = True
                    second_click = False
                    deadline = time.monotonic() + 35
                    while time.monotonic() < deadline:
                        events = [e for e in read_trace(trace_path) if e.get("cmd") == "use-compatible"]
                        running = [e for e in events if e.get("action") == "ui-evaluate-script"
                                   and e.get("op", {}).get("phase") == "running"]
                        terminal_ui = [e for e in events if e.get("action") == "ui-evaluate-script"
                                       and e.get("terminal") and e.get("evaluateScriptOk") is True]
                        elapsed_ms = round((time.perf_counter() - click_started) * 1000, 1)
                        samples.append({
                            "afterClickMs": elapsed_ms, "eventCount": len(events),
                            "runningUiEvents": len(running), "terminalDelivered": bool(terminal_ui),
                        })
                        if running and not terminal_ui:
                            native_replies.append({"afterClickMs": elapsed_ms, "ok": native_probe(hwnd)})
                            if not second_click and elapsed_ms >= 250:
                                input_samples.append({
                                    "stage": "disabled-second-click",
                                    **native_click_client(hwnd, args.x, args.y),
                                })
                                second_click = True
                        if terminal_ui:
                            break
                        if process.poll() is not None:
                            raise RuntimeError(f"产品在终态前退出：{process.returncode}")
                        time.sleep(0.1)
                    else:
                        raise TimeoutError("真实宿主复合动作终态未在 35 秒内回推到页面")
                    time.sleep(0.3)
                    screenshots.append(screenshot(hwnd, report_dir / "host-after.bmp"))
                    after_runtime = read_json(runtime_path)
                    after_shape = transport_shape(engine_config_path)
                    during_proxy = proxy_snapshot(proxy_key)
                    old_pid_dead = wait_pid_dead(before_runtime["EnginePid"])
                    new_pid_alive = pid_alive(after_runtime["EnginePid"])
                    config_transport = read_json(data / "config.json")["lines"][0].get("transport")
            except Exception as exc:
                probe_error = repr(exc)
            finally:
                events = [e for e in read_trace(trace_path) if e.get("cmd") == "use-compatible"]
                if process is not None:
                    close_timed_out = close_window(process, hwnd)

        if not args.capture_only and after_runtime is not None:
            final_new_pid_dead = wait_pid_dead(after_runtime["EnginePid"])
        final_runtime_absent = not runtime_path.exists() and not engine_config_path.exists()
        final_proxy = proxy_snapshot(proxy_key)
    except Exception as exc:
        probe_error = repr(exc)
        if process is not None and process.poll() is None:
            close_timed_out = close_window(process, hwnd)
        # CLI 阶段失败也必须真实断开；不能留下假引擎或临时代理接管。
        if runtime_path.exists():
            try:
                cli.append(run_cli(exe, env, work, "cleanup-disconnect", ["--disconnect"]))
            except Exception as cleanup_exc:
                probe_error = f"{probe_error}; cleanup={cleanup_exc!r}"
        final_proxy = proxy_snapshot(proxy_key)
        final_runtime_absent = not runtime_path.exists() and not engine_config_path.exists()
    finally:
        # 只清理本测试记录过的引擎 PID，且只删除本测试的临时注册表键。
        pids = {r.get("EnginePid") for r in (before_runtime, after_runtime) if isinstance(r, dict)}
        for pid in pids:
            if pid and pid_alive(pid):
                subprocess.run(["taskkill.exe", "/PID", str(pid), "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, check=False)
        delete_temp_key(proxy_key)
        delete_temp_key(run_key)

    live_after = live_snapshot()
    sent = [e for e in events if e.get("action") == "event-sent"]
    queued = [e for e in sent if e.get("op", {}).get("phase") == "queued"]
    running = [e for e in sent if e.get("op", {}).get("phase") == "running"]
    terminal_sent = [e for e in sent if e.get("terminal")]
    terminal_ui = [e for e in events if e.get("action") == "ui-evaluate-script"
                   and e.get("terminal") and e.get("evaluateScriptOk") is True]
    first_terminal_at = min((e["observedAtUnixMs"] for e in terminal_sent), default=None)
    running_before_terminal = [e for e in running if first_terminal_at is None
                               or e["observedAtUnixMs"] < first_terminal_at]
    heartbeat_gap_ms = None
    if len(running_before_terminal) >= 2:
        heartbeat_gap_ms = (running_before_terminal[-1]["observedAtUnixMs"]
                            - running_before_terminal[0]["observedAtUnixMs"])
    queued_threads = {e.get("threadId") for e in queued}
    running_threads = {e.get("threadId") for e in running_before_terminal}
    ui_threads = {e.get("threadId") for e in events if e.get("action") == "ui-evaluate-script"}

    if args.capture_only:
        payload = {
            "exe": str(exe), "exeSha256": sha256_file(exe), "root": str(root),
            "ready": ready, "probeError": probe_error, "screenshots": screenshots,
            "inputSamples": input_samples, "beforeRuntime": before_runtime,
            "beforeCheck": before_check, "beforeShape": before_shape,
            "cli": cli, "finalProxy": final_proxy, "originalProxy": original_proxy,
            "liveBefore": live_before, "liveAfter": live_after,
            "liveUnchanged": live_before == live_after,
        }
        report = report_dir / "t14-webview-capture.json"
        report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"ready": ready, "liveUnchanged": payload["liveUnchanged"],
                          "report": str(report), "probeError": probe_error}, ensure_ascii=True))
        return 0 if ready and not probe_error and payload["liveUnchanged"] else 1

    old_pid = before_runtime.get("EnginePid") if before_runtime else None
    new_pid = after_runtime.get("EnginePid") if after_runtime else None
    checks = {
        "realWebView2Ready": ready,
        "nativeCompatibleClickIssued": clicked,
        "noProbeError": probe_error is None,
        "realInitialSelfCheckFailed": bool(before_check) and before_check.get("ok") is False
            and before_check.get("skipped") is None,
        "initialRuntimeWasStandard": before_shape == "标准连接",
        "queuedAccepted": bool(queued),
        "crossSecondHeartbeatBeforeTerminal": heartbeat_gap_ms is not None and heartbeat_gap_ms >= 700,
        "heartbeatCameFromWorkerThread": bool(queued_threads and running_threads)
            and not bool(queued_threads & running_threads),
        "successfulTerminalEvaluatedOnUiThread": bool(terminal_ui)
            and terminal_ui[-1].get("op", {}).get("phase") == "finished",
        "compatibleResultDeliveredToPage": bool(terminal_ui)
            and terminal_ui[-1].get("hasCompatibleResult") is True,
        "terminalUiThreadMatchesAcceptThread": bool(queued_threads & ui_threads),
        "compatibleBudgetIsSixtySeconds": bool(events) and all(
            e.get("op", {}).get("budgetSec") == 60 for e in events),
        "nativeWindowAnsweredDuringOperation": bool(native_replies)
            and all(x["ok"] for x in native_replies),
        "singleUseCompatibleCommand": len(queued) == 1,
        "oldEngineStopped": old_pid_dead,
        "newEngineAliveWithDifferentPid": new_pid_alive and old_pid != new_pid and new_pid is not None,
        "newConnectionSession": bool(before_runtime and after_runtime)
            and before_runtime.get("StartedAt") != after_runtime.get("StartedAt"),
        "newRuntimeWasCompatible": after_shape == "兼容连接",
        "compatiblePreferencePersisted": config_transport == "tcp",
        "temporaryProxyPointsToCurrentLine": during_proxy is not None
            and during_proxy.get("ProxyEnable") == 1 and during_proxy.get("ProxyServer") == endpoint,
        "cleanCloseStoppedNewEngine": final_new_pid_dead,
        "runtimeRecordsRemoved": final_runtime_absent,
        "temporaryProxyRestoredExactly": final_proxy == original_proxy,
        "cleanClose": process is not None and process.returncode == 0 and not close_timed_out,
        "liveUnchanged": live_before == live_after,
    }
    payload = {
        "method": "real SpiderVPN WebView2; native mouse input; real OS engine restart; isolated runtime and temporary registry proxy; no CDP or real line",
        "exe": str(exe), "exeSha256": sha256_file(exe), "root": str(root),
        "testScriptSha256": sha256_file(Path(__file__).resolve()),
        "proxyKey": proxy_key, "runKey": run_key, "tracePath": str(trace_path),
        "events": events, "samples": samples, "inputSamples": input_samples,
        "nativeReplies": native_replies, "screenshots": screenshots,
        "heartbeatGapMs": heartbeat_gap_ms, "probeError": probe_error,
        "beforeRuntime": before_runtime, "afterRuntime": after_runtime,
        "beforeCheck": before_check, "beforeShape": before_shape, "afterShape": after_shape,
        "originalProxy": original_proxy, "duringProxy": during_proxy, "finalProxy": final_proxy,
        "oldPidDead": old_pid_dead, "newPidAlive": new_pid_alive,
        "finalNewPidDead": final_new_pid_dead, "configTransport": config_transport,
        "closeTimedOut": close_timed_out, "processExit": process.returncode if process else None,
        "cli": cli, "checks": checks, "allPassed": all(checks.values()),
        "liveBefore": live_before, "liveAfter": live_after,
        "liveUnchanged": live_before == live_after, "workPreserved": work.exists(),
        "stdoutPath": str(stdout_path), "stderrPath": str(stderr_path),
    }
    report = report_dir / "t14-webview-runtime-0.1.4.json"
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "allPassed": payload["allPassed"], "checks": checks,
        "eventCount": len(events), "heartbeatGapMs": heartbeat_gap_ms,
        "oldPid": old_pid, "newPid": new_pid,
        "beforeShape": before_shape, "afterShape": after_shape,
        "liveUnchanged": payload["liveUnchanged"], "report": str(report),
        "probeError": probe_error,
    }, ensure_ascii=True))
    return 0 if payload["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
