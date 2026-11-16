#!/usr/bin/env python3
"""M1 真实 WebView2 回归：新前端的主按钮 → 真实连接事务 → 终态回推 → 关窗清理。

**为什么不再沿用 T-14 的脚本**：T-14 点的是旧自建页面里的「改用兼容连接」（坐标
150,550），而这条入口在 旧版前端里根本不存在——`use-compatible` 没有对应按钮，
`LastOutcome` 也没有投影。那个用户故事（自检失败一键改兼容并重连）目前是**丢失**的，
已登记为待决策项，不能拿别的断言冒充它通过。

本脚本验证的是新前端真正有的那条链路：首页主按钮（Fault 下是「连接」）→ 宿主预算
通道 → 引擎真实重启 → 终态经 UI 线程回推到页面 → 关窗后运行时记录与引擎都清干净。
引擎是 PING.EXE（回环参数），导入/连接/代理写入/运行时/注册表全部隔离在
`C:\\tc-rs-build` 下，不碰真实安装、真实线路与真实 WinINET 代理。

用法：
  python tests/m1_webview_runtime.py --exe <exe> --work <新目录> --report-dir <目录> --capture-only
  python tests/m1_webview_runtime.py --exe <exe> --work <新目录> --report-dir <目录> --x 920 --y 182
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import winreg
from pathlib import Path

from s0_page_fixtures import sha256_file
from s0_startup_baseline import screenshot, webview_ready, window_for_pid
from t09_webview_runtime import live_snapshot, native_click_client, prepare_window, read_trace
from t13_webview_runtime import close_window, delete_temp_key
from t14_webview_runtime import (
    ENGINE_ARGS,
    PING,
    free_port,
    pid_alive,
    proxy_snapshot,
    read_json,
    run_cli,
    wait_pid_dead,
    write_profile,
)

ALLOWED_WORK = Path(r"C:\tc-rs-build")


class _ClickOnly(Exception):
    """校准模式：点完就收工，不算失败。"""


def press_enter() -> None:
    """聚焦后回车：比鼠标坐标更稳，能证明「按钮是启用状态」。"""
    import ctypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.keybd_event(0x0D, 0, 0, 0)
    time.sleep(0.05)
    user32.keybd_event(0x0D, 0, 2, 0)
    time.sleep(0.2)


def focus_window(hwnd: int) -> dict:
    """把窗口真正拿到前台。

    第一下原生点击常常只用来「激活窗口」而被 WebView 吞掉（窗口不在前台时
    SetForegroundWindow 会被系统拒绝）。这里先用 TOPMOST/NOTOPMOST 抖一下，
    再报告 GetForegroundWindow 是不是它。
    """
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.ShowWindow(hwnd, 9)  # SW_RESTORE
    topmost, notopmost = -1, -2
    flags = 0x0001 | 0x0002  # SWP_NOSIZE | SWP_NOMOVE
    user32.SetWindowPos(wintypes.HWND(hwnd), wintypes.HWND(topmost), 0, 0, 0, 0, flags)
    user32.SetWindowPos(wintypes.HWND(hwnd), wintypes.HWND(notopmost), 0, 0, 0, 0, flags)
    user32.BringWindowToTop(wintypes.HWND(hwnd))
    user32.SetForegroundWindow(wintypes.HWND(hwnd))
    user32.SetActiveWindow(wintypes.HWND(hwnd))
    time.sleep(0.3)
    user32.GetForegroundWindow.restype = wintypes.HWND
    foreground = int(user32.GetForegroundWindow() or 0)
    return {"foregroundIsTarget": foreground == int(hwnd), "foreground": foreground}


def window_at(screen_x: int, screen_y: int) -> dict:
    """点击落点下面到底是哪个窗口——原生点击落空时，这是唯一能说清原因的探针。"""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.WindowFromPoint.argtypes = [wintypes.POINT]
    user32.WindowFromPoint.restype = wintypes.HWND
    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    hwnd = user32.WindowFromPoint(wintypes.POINT(screen_x, screen_y))
    buffer = ctypes.create_unicode_buffer(256)
    if hwnd:
        user32.GetClassNameW(hwnd, buffer, 256)
    return {"hwnd": int(hwnd or 0), "class": buffer.value}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--capture-only", action="store_true")
    parser.add_argument("--click-only", action="store_true",
                        help="只点一次并截图，用于校准坐标（不等待事务终态）")
    # 客户区坐标（native_click_client 收的是客户区，不是窗口像素）。
    # 实测：窗口 1116x900、客户区 1098x853，客户区原点比窗口原点偏移 (9,38)。
    parser.add_argument("--x", type=int, default=919)
    parser.add_argument("--y", type=int, default=175)
    # 确认层里「继续交易」的位置（同一窗口尺寸下实测）。
    parser.add_argument("--cx", type=int, default=636)
    parser.add_argument("--cy", type=int, default=501)
    args = parser.parse_args()
    exe, work, report_dir = args.exe.resolve(), args.work.resolve(), args.report_dir.resolve()
    if not exe.is_file() or not PING.is_file():
        raise RuntimeError(f"被测程序或假引擎不存在：{exe}, {PING}")
    if ALLOWED_WORK not in work.parents:
        raise RuntimeError(f"工作目录必须位于 {ALLOWED_WORK} 下：{work}")
    if work.exists():
        raise RuntimeError(f"工作目录必须不存在：{work}")
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True)

    root = work / "root"
    data = root / "data"
    data.mkdir(parents=True)
    runtime_path = data / "runtime.json"
    engine_config_path = data / "runtime-engine.json"
    trace_path = data / "logs" / "t09-host-events.jsonl"
    profile_path = work / "source" / "dual-mode.json"
    write_profile(profile_path)
    port = free_port()
    proxy_key = f"Software\\SpiderVPN\\tests\\m1-webview-{os.getpid()}-proxy"
    run_key = f"Software\\SpiderVPN\\tests\\m1-webview-{os.getpid()}-run"

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
    probe_error = None
    close_timed_out = False
    shots: list[dict] = []
    input_samples: list[dict] = []
    samples: list[dict] = []
    before_runtime = None
    after_runtime = None
    engine_pid = None
    engine_alive_after_connect = False
    dialog_shown = False
    cancel_kept_engine = False
    runtime_removed_after_close = False
    engine_dead_after_close = False
    final_proxy = None
    cli_error = None
    events: list[dict] = []
    stdout_path = report_dir / "host.stdout.txt"
    stderr_path = report_dir / "host.stderr.txt"

    try:
        imported = run_cli(exe, env, work, "import", [
            "--import", str(profile_path), "--engine", str(PING),
            "--port", str(port), "--line-name", "M1 隔离线路",
        ])
        cli.append(imported)
        if imported["exit"] != 0:
            raise RuntimeError(f"隔离线路导入失败：{imported['stdout']}{imported['stderr']}")
        config_path = data / "config.json"
        config = read_json(config_path)
        config["auto_connect"] = False
        config["close_to_tray"] = False
        config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
        connected = run_cli(exe, env, work, "connect", ["--connect"])
        cli.append(connected)
        if connected["exit"] != 0:
            raise RuntimeError(f"初始连接失败：{connected['stdout']}{connected['stderr']}")
        # 先回到干净状态再交给界面：PING 引擎过不了自检，会话会停在「连接需要处理」，
        # 此时再点连接只会被宿主以「请断开后重新连接」拒绝，测不到真实重启。
        disconnected = run_cli(exe, env, work, "clean-before-gui", ["--disconnect"])
        cli.append(disconnected)
        if disconnected["exit"] != 0 or runtime_path.exists():
            raise RuntimeError(f"预清理断开失败：{disconnected['stdout']}{disconnected['stderr']}")
        engine_pid = None

        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                process = subprocess.Popen([str(exe)], cwd="C:\\", env=env,
                                           stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr)
                deadline = time.monotonic() + 30
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
                time.sleep(1.2)
                shots.append(screenshot(hwnd, report_dir / "home.png"))

                if not args.capture_only:
                    started = time.perf_counter()
                    focus = focus_window(hwnd)
                    hit = native_click_client(hwnd, args.x, args.y)
                    input_samples.append({"stage": "connect-click", **hit,
                                          "focus": focus,
                                          "underCursor": window_at(*hit["screen"])})
                    clicked = True
                    if args.click_only:
                        time.sleep(1.2)
                        shots.append(screenshot(hwnd, report_dir / "after-click.png"))
                        raise _ClickOnly()
                    deadline = time.monotonic() + 45
                    while time.monotonic() < deadline:
                        events = [e for e in read_trace(trace_path) if e.get("cmd") == "connect"]
                        queued = [e for e in events if e.get("action") == "event-sent"
                                  and e.get("op", {}).get("phase") == "queued"]
                        running = [e for e in events if e.get("action") == "event-sent"
                                   and e.get("op", {}).get("phase") == "running"]
                        terminal_ui = [e for e in events if e.get("action") == "ui-evaluate-script"
                                       and e.get("terminal") and e.get("evaluateScriptOk") is True]
                        samples.append({
                            "afterClickMs": round((time.perf_counter() - started) * 1000, 1),
                            "eventCount": len(events), "queued": len(queued),
                            "running": len(running), "terminalDelivered": bool(terminal_ui),
                        })
                        if terminal_ui:
                            break
                        if process.poll() is not None:
                            raise RuntimeError(f"产品在终态前退出：{process.returncode}")
                        time.sleep(0.1)
                    else:
                        raise TimeoutError("连接事务终态未在 45 秒内回推到页面")
                    time.sleep(0.4)
                    shots.append(screenshot(hwnd, report_dir / "after-connect.png"))
                    if runtime_path.exists():
                        after_runtime = read_json(runtime_path)
                        pid = after_runtime.get("EnginePid")
                        engine_alive_after_connect = bool(pid) and pid_alive(pid)
                        engine_pid = pid or engine_pid

                    # ② 连上之后主按钮变成「断开连接」：点它应当只弹确认层，不立刻断。
                    if args.cx or args.cy:
                        input_samples.append({
                            "stage": "disconnect-click",
                            **native_click_client(hwnd, args.x, args.y)})
                        time.sleep(1.0)
                        shots.append(screenshot(hwnd, report_dir / "disconnect-prompt.png"))
                        dialog_shown = runtime_path.exists() and bool(engine_pid) \
                            and pid_alive(engine_pid)
                        # ③ 点「继续交易」取消：引擎必须还在。
                        input_samples.append({
                            "stage": "cancel-click",
                            **native_click_client(hwnd, args.cx, args.cy)})
                        time.sleep(1.0)
                        shots.append(screenshot(hwnd, report_dir / "after-cancel.png"))
                        cancel_kept_engine = runtime_path.exists() and bool(engine_pid) \
                            and pid_alive(engine_pid)
            except _ClickOnly:
                pass
            except Exception as exc:  # noqa: BLE001
                probe_error = repr(exc)
            finally:
                events = [e for e in read_trace(trace_path) if e.get("cmd") == "connect"]
                if process is not None:
                    close_timed_out = close_window(process, hwnd)

        # 关窗即断开：运行时记录、引擎进程都应当清干净。
        runtime_removed_after_close = (not runtime_path.exists()
                                       and not engine_config_path.exists())
        if engine_pid:
            engine_dead_after_close = wait_pid_dead(engine_pid, timeout=10)
        if after_runtime and after_runtime.get("EnginePid"):
            wait_pid_dead(after_runtime["EnginePid"], timeout=10)
        final_proxy = proxy_snapshot(proxy_key)
    except Exception as exc:  # noqa: BLE001
        cli_error = repr(exc)
        if process is not None and process.poll() is None:
            close_timed_out = close_window(process, hwnd)
        if runtime_path.exists():
            try:
                cli.append(run_cli(exe, env, work, "cleanup-disconnect", ["--disconnect"]))
            except Exception as cleanup_exc:  # noqa: BLE001
                cli_error = f"{cli_error}; cleanup={cleanup_exc!r}"
        final_proxy = proxy_snapshot(proxy_key)
    finally:
        for pid in {engine_pid, (after_runtime or {}).get("EnginePid")}:
            if pid and pid_alive(pid):
                subprocess.run(["taskkill.exe", "/PID", str(pid), "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=5, check=False)
        delete_temp_key(proxy_key)
        delete_temp_key(run_key)

    live_after = live_snapshot()
    queued = [e for e in events if e.get("action") == "event-sent"
              and e.get("op", {}).get("phase") == "queued"]
    running = [e for e in events if e.get("action") == "event-sent"
               and e.get("op", {}).get("phase") == "running"]
    terminal_ui = [e for e in events if e.get("action") == "ui-evaluate-script"
                   and e.get("terminal") and e.get("evaluateScriptOk") is True]
    old_pid = (before_runtime or {}).get("EnginePid")
    new_pid = (after_runtime or {}).get("EnginePid")
    checks = {
        "realWebView2Ready": ready,
        "nativePrimaryClickIssued": clicked,
        "noProbeError": probe_error is None and cli_error is None,
        "connectOperationQueued": bool(queued),
        "connectRanOnWorker": bool(running),
        "terminalDeliveredToPage": bool(terminal_ui),
        "engineStartedOnClick": engine_alive_after_connect,
        "runtimeWrittenAfterConnect": after_runtime is not None,
        "disconnectAskedBeforeStopping": dialog_shown,
        "cancelKeptEngineRunning": cancel_kept_engine,
        "runtimeRecordsRemovedOnClose": runtime_removed_after_close,
        "enginesStoppedOnClose": engine_dead_after_close,
        "temporaryProxyRestoredExactly": final_proxy == original_proxy,
        "cleanClose": process is not None and process.returncode == 0 and not close_timed_out,
        "liveUnchanged": live_before == live_after,
    }
    payload = {
        "method": "real SpiderVPN WebView2; new 旧版frontend; native mouse input; isolated runtime and temporary registry proxy",
        "exe": str(exe), "exeSha256": sha256_file(exe), "root": str(root),
        "testScriptSha256": sha256_file(Path(__file__).resolve()),
        "proxyKey": proxy_key, "runKey": run_key, "tracePath": str(trace_path),
        "events": events, "samples": samples, "inputSamples": input_samples,
        "screenshots": shots, "cli": cli,
        "probeError": probe_error, "cliError": cli_error,
        "beforeRuntime": before_runtime, "afterRuntime": after_runtime,
        "originalProxy": original_proxy, "finalProxy": final_proxy,
        "closeTimedOut": close_timed_out,
        "processExit": process.returncode if process else None,
        "checks": checks, "allPassed": all(checks.values()),
        "liveBefore": live_before, "liveAfter": live_after,
        "workPreserved": work.exists(),
        "stdoutPath": str(stdout_path), "stderrPath": str(stderr_path),
    }
    report = report_dir / "m1-webview-runtime.json"
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"allPassed": payload["allPassed"], "checks": checks,
                      "events": len(events), "oldPid": old_pid, "newPid": new_pid,
                      "shots": [s["path"] for s in shots], "report": str(report),
                      "probeError": probe_error, "cliError": cli_error},
                     ensure_ascii=True))
    return 0 if payload["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
