#!/usr/bin/env python3
"""0.1.4 宿主性能实测：冷启动（DOM 就绪 / 首屏有内容）、空闲 CPU、常驻内存。

**口径**（写死在报告里，避免以后拿不同定义的数字互相比较）：

- 冷启动：从 `Popen` 返回到页面 `readyState==='complete'` 且 `#main` 有内容的时间。
  这**不是**「首帧上屏」——那要用 GDI 抓帧，普通桌面会话里测不准。
- 首屏有内容：`#main` 的文字长度超过阈值（说明快照已经渲染，不是空壳）。
- 空闲 CPU：**窗口可见、未连接**、预热 25 秒后连续采样 60 秒，
  按「占单核百分比」报（`ΔCPU秒 / Δ墙钟秒 × 100`）。托盘隐藏态不在本脚本范围。
- 内存：同一段采样里的工作集（Working Set）中位数与峰值。
- 关窗：`terminate()` 到进程真正退出的时间。

样本数默认 12 次：报告全部原始值、中位数（p50）与 p95（最近秩法，不插值）。
第一次运行单独列出——WebView2 运行时的首次初始化会让它明显偏慢，混进 p50 会失真。

用法：
  python tests/perf_startup.py --exe <exe> --work <数据根> --report-dir <目录>
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wintypes
import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s0_page_fixtures import WebSocket, free_port  # noqa: E402

ALLOWED_WORK = Path(r"C:\tc-rs-build")
CDP_READY_SECONDS = 30.0
CONTENT_SECONDS = 15.0

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def window_visible(pid: int) -> bool:
    """这个进程有没有一个可见的顶层窗口。"""
    found: list[int] = []

    def callback(hwnd, _lparam):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(WNDENUMPROC(callback), 0)
    return bool(found)


def first_window(pid: int) -> int | None:
    found: list[int] = []

    def callback(hwnd, _lparam):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
            return False
        return True

    user32.EnumWindows(WNDENUMPROC(callback), 0)
    return found[0] if found else None


def wait_window(pid: int, seconds: float) -> float | None:
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        if window_visible(pid):
            return time.perf_counter()
        time.sleep(0.02)
    return None


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


TH32CS_SNAPPROCESS = 0x2


def process_tree(root_pid: int) -> list[int]:
    """root_pid 及其全部后代。WebView2（多个进程）与引擎都挂在这棵树上，
    只算主进程会把常驻内存与 CPU 报小一半以上。"""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (-1, 0xFFFFFFFF):
        return [root_pid]
    entries: list[tuple[int, int]] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            entries.append((int(entry.th32ProcessID), int(entry.th32ParentProcessID)))
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    children: dict[int, list[int]] = {}
    for pid, parent in entries:
        children.setdefault(parent, []).append(pid)
    found: list[int] = []
    stack = [root_pid]
    while stack:
        current = stack.pop()
        found.append(current)
        stack.extend(children.get(current, []))
    return found


def process_map() -> dict[int, tuple[int, str]]:
    """{pid: (父 pid, 可执行文件名)}。用来把 CPU/内存归到具体进程上。"""
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (-1, 0xFFFFFFFF):
        return {}
    result: dict[int, tuple[int, str]] = {}
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        more = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            result[int(entry.th32ProcessID)] = (
                int(entry.th32ParentProcessID),
                str(entry.szExeFile),
            )
            more = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def cpu_by_pid(pids: list[int]) -> dict[int, float]:
    result: dict[int, float] = {}
    for pid in pids:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            result[pid] = process_cpu_seconds(handle)
        except OSError:
            pass
        finally:
            kernel32.CloseHandle(handle)
    return result


def sample_tree(pids: list[int]) -> tuple[float, int, int]:
    """(CPU 秒, 工作集字节, 活着的进程数)。已经退出的进程直接跳过。"""
    cpu = 0.0
    memory = 0
    alive = 0
    for pid in pids:
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            continue
        try:
            cpu += process_cpu_seconds(handle)
            memory += process_working_set(handle)
            alive += 1
        except OSError:
            pass
        finally:
            kernel32.CloseHandle(handle)
    return cpu, memory, alive


def _ft_100ns(value: FILETIME) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def process_cpu_seconds(handle) -> float:
    created, exited, kern, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
    ok = kernel32.GetProcessTimes(
        handle,
        ctypes.byref(created),
        ctypes.byref(exited),
        ctypes.byref(kern),
        ctypes.byref(user),
    )
    if not ok:
        raise OSError(ctypes.get_last_error(), "GetProcessTimes 失败")
    return (_ft_100ns(kern) + _ft_100ns(user)) / 1e7


def process_working_set(handle) -> int:
    # 新版 Windows 导出 K32GetProcessMemoryInfo，老的名字是 GetProcessMemoryInfo。
    entry = getattr(psapi, "K32GetProcessMemoryInfo", None) or psapi.GetProcessMemoryInfo
    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(counters)
    ok = entry(handle, ctypes.byref(counters), counters.cb)
    if not ok:
        raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo 失败")
    return int(counters.WorkingSetSize)


def percentile(values: list[float], fraction: float) -> float:
    """最近秩法：p95 取第 ceil(0.95n) 小的值，不插值。"""
    if not values:
        raise ValueError("没有样本")
    ordered = sorted(values)
    rank = max(1, int(round(fraction * len(ordered) + 0.4999)))
    return ordered[min(rank, len(ordered)) - 1]


def wait_cdp(port: int, seconds: float) -> dict:
    import urllib.request

    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        try:
            raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2).read()
            for item in json.loads(raw or b"[]"):
                if item.get("type") == "page" and "tc.ui" in (item.get("url") or ""):
                    return item
        except Exception as error:
            last = str(error)
        time.sleep(0.05)
    raise TimeoutError(f"CDP 在 {seconds} 秒内没有就绪：{last}")


def wait_js(ws: WebSocket, expression: str, seconds: float) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if ws.evaluate(expression):
                return True
        except Exception:
            pass
        time.sleep(0.03)
    return False


def launch(exe: str, env_extra: dict) -> subprocess.Popen:
    env = dict(os.environ)
    env.update(env_extra)
    return subprocess.Popen(
        [exe],
        cwd=str(ALLOWED_WORK),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def run_once(exe: str, work: Path, run_key: str) -> dict:
    port = free_port()
    env = {
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={port} --remote-allow-origins=*",
        "SPIDERVPN_ROOT": str(work),
        "SPIDERVPN_PROXY_KEY": f"Software\\SpiderVPN\\tests\\perf-{run_key}",
        "SPIDERVPN_RUN_KEY": f"Software\\SpiderVPN\\tests\\perf-{run_key}-run",
    }
    started = time.perf_counter()
    process = launch(exe, env)
    ws = None
    try:
        visible_at = wait_window(process.pid, 10.0)
        window_ms = (visible_at - started) * 1000.0 if visible_at else None
        target = wait_cdp(port, CDP_READY_SECONDS)
        cdp_ms = (time.perf_counter() - started) * 1000.0
        ws = WebSocket(target["webSocketDebuggerUrl"])
        wait_js(
            ws,
            "document.readyState==='complete'&&!!document.querySelector('#main')",
            CDP_READY_SECONDS,
        )
        dom_ready_ms = (time.perf_counter() - started) * 1000.0
        has_content = wait_js(
            ws,
            "(document.querySelector('#main')||{textContent:''}).textContent.trim().length>80",
            CONTENT_SECONDS,
        )
        content_ms = (time.perf_counter() - started) * 1000.0
        return {
            "windowVisibleMs": round(window_ms, 1) if window_ms is not None else None,
            "cdpTargetMs": round(cdp_ms, 1),
            "domReadyMs": round(dom_ready_ms, 1),
            "firstContentMs": round(content_ms, 1) if has_content else None,
        }
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        # 给 WebView2 子进程一点退出时间，别让下一次启动撞到单实例锁。
        time.sleep(0.6)


def prepare_proxy_key(key: str) -> None:
    """连接前必须让「系统代理」可读。

    产品在连接前会读当前代理设置；读不到就拒绝接管（避免覆盖无法还原的配置）。
    隔离键默认不存在 → 一定读不到。这里按真实形状写一份「未启用」的代理设置。
    """
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
        winreg.SetValueEx(handle, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(handle, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:7897")
        winreg.SetValueEx(handle, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*")


def measure_idle(
    exe: str,
    work: Path,
    warmup: float,
    seconds: float,
    connect: bool = False,
    cdp: bool = True,
    minimize: bool = False,
) -> dict:
    port = free_port()
    env = {
        "SPIDERVPN_ROOT": str(work),
        "SPIDERVPN_PROXY_KEY": r"Software\SpiderVPN\tests\perf-idle",
        "SPIDERVPN_RUN_KEY": r"Software\SpiderVPN\tests\perf-idle-run",
    }
    if cdp:
        env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
            f"--remote-debugging-port={port} --remote-allow-origins=*"
        )
    if connect:
        # 必须在进程启动前写好：宿主启动后马上就会读一次代理设置，读不到就拒绝接管。
        prepare_proxy_key(env["SPIDERVPN_PROXY_KEY"])
    process = launch(exe, env)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process.pid)
    if not handle:
        process.terminate()
        raise OSError(ctypes.get_last_error(), "OpenProcess 失败")
    result: dict = {}
    try:
        if connect:
            # 「已连接」的判据用断开按钮出现：它只在连接事务成功后渲染，
            # 比匹配「已连接」三个字稳（页面上还有别处会出现同样的词）。
            target = wait_cdp(port, CDP_READY_SECONDS)
            ws = WebSocket(target["webSocketDebuggerUrl"])
            try:
                wait_js(
                    ws,
                    "document.readyState==='complete'&&!!document.querySelector('#main [data-action=connect]')",
                    CDP_READY_SECONDS,
                )
                clicked_at = time.perf_counter()
                clicked = ws.evaluate(
                    "(()=>{const e=document.querySelector('#main [data-action=connect]');"
                    "if(!e)return false;e.click();return true;})()"
                )
                connected = bool(clicked) and wait_js(
                    ws,
                    "!!document.querySelector('[data-action=disconnect]')",
                    90.0,
                )
            finally:
                try:
                    ws.close()
                except Exception:
                    pass
            result["connected"] = connected
            result["connectSeconds"] = (
                round(time.perf_counter() - clicked_at, 1) if connected else None
            )
            if not connected:
                toast = ""
                try:
                    toast = str(
                        ws.evaluate("(document.getElementById('toast')||{}).textContent") or ""
                    )
                except Exception:
                    pass
                raise RuntimeError(
                    f"连接没有建立（页面提示：{toast or '空'}）——不拿「未连接」的样本冒充「已连接」"
                )
        if minimize:
            hwnd = None
            deadline = time.perf_counter() + 10.0
            while time.perf_counter() < deadline and not hwnd:
                hwnd = first_window(process.pid)
                if not hwnd:
                    time.sleep(0.1)
            if hwnd:
                user32.ShowWindow(wintypes.HWND(hwnd), 6)  # SW_MINIMIZE
                result["minimized"] = True
            else:
                result["minimized"] = False
            # 让合成器真正停下来，再开始采样。
            time.sleep(2.0)
        time.sleep(warmup)
        # 按进程树算：主进程 + WebView2（browser/gpu/renderer）+ 引擎，缺一个都会报小。
        names = process_map()
        tree = process_tree(process.pid)
        first_by_pid = cpu_by_pid(tree)
        first_cpu = sum(first_by_pid.values())
        first_at = time.perf_counter()
        samples: list[int] = []
        process_counts: list[int] = []
        memory_by_pid: dict[int, int] = {}
        deadline = first_at + seconds
        while time.perf_counter() < deadline:
            time.sleep(1.0)
            tree = process_tree(process.pid)
            _, memory, alive = sample_tree(tree)
            samples.append(memory)
            process_counts.append(alive)
            for pid in tree:
                handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if not handle:
                    continue
                try:
                    memory_by_pid[pid] = process_working_set(handle)
                except OSError:
                    pass
                finally:
                    kernel32.CloseHandle(handle)
        last_by_pid = cpu_by_pid(process_tree(process.pid))
        last_cpu = sum(last_by_pid.values())
        elapsed = time.perf_counter() - first_at
        deltas = {
            pid: last_by_pid[pid] - first_by_pid.get(pid, 0.0) for pid in last_by_pid
        }
        top = sorted(deltas.items(), key=lambda item: -item[1])[:5]
        result.update(
            {
                "warmupSeconds": warmup,
                "sampledSeconds": round(elapsed, 1),
                "cpuSeconds": round(last_cpu - first_cpu, 2),
                "idleCpuPercentOfOneCore": round((last_cpu - first_cpu) / elapsed * 100.0, 3),
                "workingSetMedianMB": round(statistics.median(samples) / (1024 * 1024), 1),
                "workingSetPeakMB": round(max(samples) / (1024 * 1024), 1),
                "processCountMedian": statistics.median(process_counts),
                "topCpu": [
                    {
                        "pid": pid,
                        "name": names.get(pid, ("", "?"))[1],
                        "cpuPercentOfOneCore": round(value / elapsed * 100.0, 2),
                    }
                    for pid, value in top
                ],
                "topMemory": [
                    {
                        "pid": pid,
                        "name": names.get(pid, ("", "?"))[1],
                        "workingSetMB": round(value / (1024 * 1024), 1),
                    }
                    for pid, value in sorted(
                        memory_by_pid.items(), key=lambda item: -item[1]
                    )[:5]
                ],
            }
        )
    finally:
        kernel32.CloseHandle(handle)
        closed_at = time.perf_counter()
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        result["closeSeconds"] = round(time.perf_counter() - closed_at, 2)
        result["exitCode"] = process.returncode
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--runs", type=int, default=12)
    parser.add_argument("--idle-seconds", type=float, default=60.0)
    parser.add_argument("--warmup-seconds", type=float, default=25.0)
    parser.add_argument(
        "--idle-only",
        action="store_true",
        help="跳过启动测量，只补一次空闲采样（复用报告里已有的启动样本）",
    )
    parser.add_argument(
        "--connected",
        action="store_true",
        help="先连上线路再采样（口径才有意义：代理软件的主要开销在已连接状态）",
    )
    parser.add_argument(
        "--no-cdp",
        action="store_true",
        help="不开放调试端口（只能测未连接空闲：调试端口本身会影响读数）",
    )
    parser.add_argument(
        "--minimize",
        action="store_true",
        help="采样前把窗口最小化（对应「托盘/最小化」的空闲口径）",
    )
    args = parser.parse_args()
    if args.no_cdp and args.connected:
        raise SystemExit("--no-cdp 不能和 --connected 一起用：没有调试端口就没法点连接")
    if args.no_cdp:
        # 没有调试端口就测不了「页面就绪」，只能单测空闲。
        args.idle_only = True

    exe = str(Path(args.exe).resolve())
    work = Path(args.work).resolve()
    report_dir = Path(args.report_dir).resolve()
    for path in (work, report_dir):
        if ALLOWED_WORK not in path.parents and path != ALLOWED_WORK:
            raise SystemExit(f"只能写在 {ALLOWED_WORK} 下：{path}")
    report_dir.mkdir(parents=True, exist_ok=True)
    if not (work / "data").exists():
        raise SystemExit(f"{work} 不像一个数据根（缺 data 目录）")

    report: dict = {"exe": exe, "work": str(work), "runs": [], "idle": None}
    if args.idle_only:
        try:
            previous = json.loads((report_dir / "startup.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            previous = {}
        report["runs"] = previous.get("runs", [])
        report["summary"] = previous.get("summary")
        print(f"[startup] 复用 {len(report['runs'])} 个样本", flush=True)
    else:
        for index in range(args.runs):
            sample = run_once(exe, work, f"s{index}")
            sample["run"] = index
            report["runs"].append(sample)
            print(f"[startup] #{index:02d} {sample}", flush=True)

        # 样本只有一个时没有「首跑之外」可言，直接把它算进去（否则 p50 会取空列表）。
        steady_runs = report["runs"][1:] or report["runs"]
        steady = [item["domReadyMs"] for item in steady_runs]
        content = [item["firstContentMs"] for item in steady_runs if item["firstContentMs"]]
        windows = [
            item["windowVisibleMs"]
            for item in steady_runs
            if item.get("windowVisibleMs")
        ]
        report["summary"] = {
            "runs": len(report["runs"]),
            "firstRunDomReadyMs": report["runs"][0]["domReadyMs"],
            "windowP50Ms": round(percentile(windows, 0.50), 1) if windows else None,
            "domReadyP50Ms": round(percentile(steady, 0.50), 1),
            "domReadyP95Ms": round(percentile(steady, 0.95), 1),
            "firstContentP50Ms": round(percentile(content, 0.50), 1) if content else None,
            "firstContentP95Ms": round(percentile(content, 0.95), 1) if content else None,
            "contentMissing": sum(1 for item in report["runs"] if not item["firstContentMs"]),
        }

    idle = measure_idle(
        exe,
        work,
        args.warmup_seconds,
        args.idle_seconds,
        connect=args.connected,
        cdp=not args.no_cdp,
        minimize=args.minimize,
    )
    report["idle"] = idle
    report["definition"] = {
        "coldStart": "Popen 返回到 readyState=complete 且 #main 存在；不是首帧上屏",
        "firstContent": "#main 文字长度 > 80（快照已渲染）",
        "idleCpu": (
            "已连接、预热后连续采样的占单核百分比"
            if args.connected
            else "窗口可见、未连接、预热后连续采样的占单核百分比"
        ),
        "percentile": "最近秩法，不插值",
        "note": "文件系统缓存已预热；真正断电冷启动会更慢，两边比较请用同一口径",
    }
    (report_dir / "startup.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"summary": report["summary"], "idle": report["idle"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
