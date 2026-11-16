#!/usr/bin/env python3
"""Verify T-13 through the real WebView2 host with isolated runtime evidence.

The only network peer is an authenticated local fake tc-check SOCKS5 service.
No real line, installation, configuration, or system proxy is modified.
"""
from __future__ import annotations

import argparse
from ctypes import wintypes
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import winreg

from s0_page_fixtures import sha256_file
from s0_startup_baseline import screenshot, webview_ready, window_for_pid
from t09_webview_runtime import (
    USER32,
    live_snapshot,
    native_click_client,
    native_probe,
    prepare_root,
    prepare_window,
    read_trace,
)


def recv_exact(conn: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            raise EOFError(f"需要 {count} 字节，只收到 {len(data)}")
        data += chunk
    return data


class FakeProbe:
    def __init__(self, delay_sec: float = 1.2) -> None:
        self.delay_sec = delay_sec
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop_event = threading.Event()
        self.requests: list[dict] = []
        self.errors: list[str] = []
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop_event.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with conn:
                    conn.settimeout(3)
                    greeting = recv_exact(conn, 4)
                    if greeting != b"\x05\x02\x00\x02":
                        raise ValueError(f"SOCKS 问候不符：{greeting.hex()}")
                    conn.sendall(b"\x05\x02")
                    auth_head = recv_exact(conn, 2)
                    user = recv_exact(conn, auth_head[1])
                    pass_len = recv_exact(conn, 1)[0]
                    password = recv_exact(conn, pass_len)
                    if auth_head[0] != 1 or user != b"fixture-user" or password != b"fixture-pass":
                        conn.sendall(b"\x01\x01")
                        raise ValueError("探测凭据不符")
                    conn.sendall(b"\x01\x00")
                    head = recv_exact(conn, 5)
                    host = recv_exact(conn, head[4]).decode("ascii")
                    port = int.from_bytes(recv_exact(conn, 2), "big")
                    if head[:4] != b"\x05\x01\x00\x03" or host != "www.gstatic.com" or port != 80:
                        raise ValueError(f"CONNECT 目标不符：{head.hex()} {host}:{port}")
                    conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                    http = b""
                    while b"\r\n\r\n" not in http:
                        http += conn.recv(1024)
                    self.requests.append({
                        "atUnixMs": int(time.time() * 1000),
                        "user": user.decode("ascii"),
                        "host": host,
                        "port": port,
                        "http": http.decode("latin1"),
                    })
                    time.sleep(self.delay_sec)
                    conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            except Exception as exc:
                if not self.stop_event.is_set():
                    self.errors.append(repr(exc))

    def close(self) -> None:
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=3)


def dummy_process() -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(120)"],
        cwd="C:\\", stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def delete_temp_key(path: str) -> None:
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
    except FileNotFoundError:
        pass


def close_window(process: subprocess.Popen, hwnd: int) -> bool:
    if process.poll() is None and hwnd:
        USER32.PostMessageW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
        ]
        USER32.PostMessageW.restype = wintypes.BOOL
        USER32.PostMessageW(hwnd, 0x0010, 0, 0)
    try:
        process.wait(timeout=12)
        return False
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
        return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--x", type=int, default=104)
    parser.add_argument("--y", type=int, default=758)
    args = parser.parse_args()
    exe, work, report_dir = args.exe.resolve(), args.work.resolve(), args.report_dir.resolve()
    allowed_work = Path(r"C:\tc-rs-build").resolve()
    if not exe.is_file():
        raise RuntimeError(f"被测程序不存在：{exe}")
    if allowed_work not in work.parents:
        raise RuntimeError(f"工作目录必须位于 {allowed_work} 下：{work}")
    if work.exists():
        raise RuntimeError(f"工作目录必须不存在：{work}")
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True)
    probe = FakeProbe()
    supervisor = dummy_process()
    engine = dummy_process()
    root = prepare_root(work)
    data = root / "data"
    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    runtime_path = data / "runtime.json"
    runtime = {
        "SchemaVersion": 1,
        "SupervisorPid": supervisor.pid,
        "EnginePid": engine.pid,
        "StartedAt": started_at,
        "State": "Running",
        "Error": None,
        "ProbeUser": "fixture-user",
        "ProbePass": "fixture-pass",
    }
    runtime_path.write_text(json.dumps(runtime, indent=2) + "\n", encoding="utf-8")
    (data / "runtime-engine.json").write_text(json.dumps({
        "inbounds": [{
            "type": "socks", "tag": "tc-check", "listen": "127.0.0.1",
            "listen_port": probe.port,
        }],
    }, indent=2) + "\n", encoding="utf-8")
    check_path = data / "last-check.json"
    check_path.write_text(json.dumps({
        "ok": True, "status": 204, "error": None,
        "at": int(time.time()), "via_trade_exit": True,
    }, indent=2) + "\n", encoding="utf-8")
    check_before = check_path.read_bytes()
    trace_path = data / "logs" / "t09-host-events.jsonl"
    proxy_key = f"Software\\SpiderVPN\\tests\\t13-webview-{os.getpid()}-proxy"
    run_key = f"Software\\SpiderVPN\\tests\\t13-webview-{os.getpid()}-run"
    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": proxy_key,
        "SPIDERVPN_RUN_KEY": run_key,
        "SPIDERVPN_FORCE_NONADMIN": "1",
        "SPIDERVPN_TEST_HOST_TRACE": "1",
    })
    env.pop("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", None)
    live_before = live_snapshot()
    process = None
    hwnd = 0
    probe_error = None
    close_timed_out = False
    ready = False
    clicked = False
    events: list[dict] = []
    samples: list[dict] = []
    native_replies: list[dict] = []
    input_samples: list[dict] = []
    screenshots: list[dict] = []
    latency = None
    latency_path = data / "last-latency.json"
    initial_latency_absent = not latency_path.exists()
    stdout_path = report_dir / "host.stdout.txt"
    stderr_path = report_dir / "host.stderr.txt"
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
                input_samples.append({"stage": "measure-click", **native_click_client(hwnd, args.x, args.y)})
                clicked = True
                second_click = False
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    events = [e for e in read_trace(trace_path) if e.get("cmd") == "measure-latency"]
                    running = [e for e in events if e.get("action") == "ui-evaluate-script"
                               and e.get("op", {}).get("phase") == "running"]
                    terminal_ui = [e for e in events if e.get("action") == "ui-evaluate-script"
                                   and e.get("terminal") and e.get("evaluateScriptOk") is True]
                    elapsed_ms = round((time.perf_counter() - click_started) * 1000, 1)
                    samples.append({
                        "afterClickMs": elapsed_ms, "eventCount": len(events),
                        "runningUiEvents": len(running), "terminalDelivered": bool(terminal_ui),
                    })
                    # PrintWindow 会同步等待 WebView 绘制；首轮探针在运行中抓屏，
                    # 曾把脚本阻塞到超过等待预算。运行中只读留痕和 WM_NULL，终态后再抓屏。
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
                    raise TimeoutError("真实宿主测量终态未在 12 秒内回推到页面")
                time.sleep(0.3)
                screenshots.append(screenshot(hwnd, report_dir / "host-after.bmp"))
                latency = json.loads(latency_path.read_text(encoding="utf-8"))
                if check_path.read_bytes() != check_before:
                    raise AssertionError("手动测量改写了 last-check.json")
        except Exception as exc:
            probe_error = repr(exc)
        finally:
            events = [e for e in read_trace(trace_path) if e.get("cmd") == "measure-latency"]
            if latency is None and latency_path.is_file():
                latency = json.loads(latency_path.read_text(encoding="utf-8"))
            # 关窗会走产品断开路径。先归档假 runtime，避免清理逻辑把夹具 PID 当引擎停止；
            # 本脚本只验收测量，不把这次关窗计为断开功能验收。
            if runtime_path.exists():
                runtime_path.rename(work / "runtime.fixture-after-measurement.json")
            if process is not None:
                close_timed_out = close_window(process, hwnd)

    probe.close()
    for child in (supervisor, engine):
        if child.poll() is None:
            child.kill()
        child.wait(timeout=3)
    delete_temp_key(proxy_key)
    delete_temp_key(run_key)
    live_after = live_snapshot()
    if args.capture_only:
        payload = {
            "exe": str(exe), "exeSha256": sha256_file(exe), "root": str(root),
            "ready": ready, "probeError": probe_error, "screenshots": screenshots,
            "inputSamples": input_samples, "liveBefore": live_before, "liveAfter": live_after,
            "liveUnchanged": live_before == live_after,
        }
        report = report_dir / "t13-webview-capture.json"
        report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"ready": ready, "liveUnchanged": payload["liveUnchanged"],
                          "report": str(report), "probeError": probe_error}, ensure_ascii=False))
        return 0 if ready and not probe_error and payload["liveUnchanged"] else 1

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
    request_ok = len(probe.requests) == 1 and all(
        r["user"] == "fixture-user" and r["host"] == "www.gstatic.com" and r["port"] == 80
        and r["http"].startswith("GET /generate_204 HTTP/1.1\r\n") for r in probe.requests
    )
    latency_ok = bool(latency) and latency.get("latency_ms", 0) >= 1000 \
        and latency.get("connection_started_at") == started_at and latency.get("at", 0) > 0
    checks = {
        "realWebView2Ready": ready,
        "nativeMeasureClickIssued": clicked,
        "noProbeError": probe_error is None,
        "initialLatencyAbsent": initial_latency_absent,
        "queuedAccepted": bool(queued),
        "crossSecondHeartbeatBeforeTerminal": heartbeat_gap_ms is not None and heartbeat_gap_ms >= 700,
        "heartbeatCameFromWorkerThread": bool(queued_threads and running_threads)
            and not bool(queued_threads & running_threads),
        "successfulTerminalEvaluatedOnUiThread": bool(terminal_ui)
            and terminal_ui[-1].get("op", {}).get("phase") == "finished",
        "terminalUiThreadMatchesAcceptThread": bool(queued_threads & ui_threads),
        "measureBudgetIsFiveSeconds": bool(events) and all(
            e.get("op", {}).get("budgetSec") == 5 for e in events),
        "nativeWindowAnsweredDuringOperation": bool(native_replies)
            and all(x["ok"] for x in native_replies),
        "runningUpdateEvaluatedOnUiThread": any(
            e.get("action") == "ui-evaluate-script" and e.get("evaluateScriptOk") is True
            and e.get("op", {}).get("phase") == "running" for e in events),
        "singleAuthenticatedLocalProbe": request_ok and not probe.errors,
        "realLatencyRecordMatchesConnection": latency_ok,
        "channelCheckBytesUnchanged": check_path.read_bytes() == check_before,
        "cleanClose": process is not None and process.returncode == 0 and not close_timed_out,
        "liveUnchanged": live_before == live_after,
    }
    payload = {
        "method": "real SpiderVPN WebView2; native mouse input; isolated runtime evidence; authenticated local fake tc-check SOCKS5; no CDP or real line",
        "exe": str(exe), "exeSha256": sha256_file(exe), "root": str(root),
        "testScriptSha256": sha256_file(Path(__file__).resolve()),
        "proxyKey": proxy_key, "runKey": run_key, "tracePath": str(trace_path),
        "runtimeQuarantinedBeforeClose": True,
        "events": events, "samples": samples, "inputSamples": input_samples,
        "nativeReplies": native_replies, "screenshots": screenshots,
        "heartbeatGapMs": heartbeat_gap_ms, "probeError": probe_error,
        "probeRequests": probe.requests, "probeErrors": probe.errors,
        "latency": latency, "closeTimedOut": close_timed_out,
        "processExit": process.returncode if process else None,
        "checks": checks, "allPassed": all(checks.values()),
        "liveBefore": live_before, "liveAfter": live_after,
        "liveUnchanged": live_before == live_after, "workPreserved": work.exists(),
        "stdoutPath": str(stdout_path), "stderrPath": str(stderr_path),
    }
    report = report_dir / "t13-webview-runtime-0.1.4.json"
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "allPassed": payload["allPassed"], "checks": checks,
        "eventCount": len(events), "heartbeatGapMs": heartbeat_gap_ms,
        "latency": latency, "liveUnchanged": payload["liveUnchanged"],
        "report": str(report), "probeError": probe_error,
    }, ensure_ascii=True))
    return 0 if payload["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
