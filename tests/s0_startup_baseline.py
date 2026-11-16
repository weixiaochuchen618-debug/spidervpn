#!/usr/bin/env python3
"""Three isolated GUI startup samples plus fixed-size GDI screenshots."""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import statistics
import struct
import subprocess
import time

SOURCE = Path(__file__).resolve().parents[1]
LIVE_CONFIG = Path(r"C:\SpiderVPN\data\config.json")
u = ctypes.windll.user32
g = ctypes.windll.gdi32
psapi = ctypes.windll.psapi
kernel32 = ctypes.windll.kernel32
ENUM_PROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def _set_dpi_aware() -> str:
    """必须在任何窗口/坐标调用之前执行。

    DPI-unaware 的 Python 进程看到的全是 125% 虚拟坐标：`SetWindowPos(900,600)`
    会被系统放大成 1125x750 的窗口，而 `PrintWindow` 只覆盖 900x600 物理像素，
    窗口底部（含 `.statusbar`）整条被切掉。2026-10-30 就是这条把
    「状态条正常」误判成「状态条被裁」，进而写出一个不存在的布局缺陷。
    """
    try:
        u.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
        u.SetProcessDpiAwarenessContext.restype = ctypes.c_int
        if u.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):  # PER_MONITOR_AWARE_V2
            return "per-monitor-v2"
    except Exception:
        pass
    try:
        shcore = ctypes.windll.shcore
        if shcore.SetProcessDpiAwareness(2) == 0:
            return "per-monitor"
    except Exception:
        pass
    try:
        if u.SetProcessDPIAware():
            return "system"
    except Exception:
        pass
    return "none"


DPI_MODE = _set_dpi_aware()


def sha256(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def window_for_pid(pid: int) -> int:
    found = []
    def callback(hwnd, _):
        owner = wintypes.DWORD()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and u.IsWindowVisible(hwnd):
            length = u.GetWindowTextLengthW(hwnd)
            title = ctypes.create_unicode_buffer(length + 1)
            u.GetWindowTextW(hwnd, title, len(title))
            if title.value == "SpiderVPN":
                found.append(hwnd)
                return False
        return True
    u.EnumWindows(ENUM_PROC(callback), 0)
    return found[0] if found else 0


def webview_ready(hwnd: int) -> bool:
    found = []
    def callback(child, _):
        name = ctypes.create_unicode_buffer(256)
        u.GetClassNameW(child, name, len(name))
        if name.value.startswith("Chrome_WidgetWin_") and u.IsWindowVisible(child):
            rect = wintypes.RECT()
            u.GetClientRect(child, ctypes.byref(rect))
            if rect.right > 0 and rect.bottom > 0:
                found.append(child)
                return False
        return True
    u.EnumChildWindows(hwnd, ENUM_PROC(callback), 0)
    return bool(found)


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def working_set(pid: int) -> int | None:
    # 必须声明 64 位 HANDLE；ctypes 默认 c_int 会截断句柄，导致读取静默失败。
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        counters = PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return None
        return int(counters.WorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD), ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG), ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD),
    ]


def screenshot(hwnd: int, output: Path) -> dict:
    rect = wintypes.RECT()
    client = wintypes.RECT()
    u.GetWindowRect(hwnd, ctypes.byref(rect))
    u.GetClientRect(hwnd, ctypes.byref(client))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    hdc_window = u.GetWindowDC(hwnd)
    hdc_mem = g.CreateCompatibleDC(hdc_window)
    bitmap = g.CreateCompatibleBitmap(hdc_window, width, height)
    old = g.SelectObject(hdc_mem, bitmap)
    printed = bool(u.PrintWindow(hwnd, hdc_mem, 2))
    info = BITMAPINFOHEADER()
    info.biSize = ctypes.sizeof(info)
    info.biWidth, info.biHeight = width, -height
    info.biPlanes, info.biBitCount = 1, 32
    pixels = ctypes.create_string_buffer(width * height * 4)
    rows = g.GetDIBits(hdc_mem, bitmap, 0, height, pixels, ctypes.byref(info), 0)
    if not printed or rows != height:
        raise RuntimeError(f"GDI 抓屏失败：PrintWindow={printed}, rows={rows}/{height}")
    sampled_colors = {pixels.raw[i:i + 4] for i in range(0, len(pixels.raw), 4 * 97)}
    body = bytearray()
    stride = width * 4
    for y in range(height - 1, -1, -1):
        body.extend(pixels.raw[y * stride:(y + 1) * stride])
    header = bytearray(b"BM") + struct.pack("<IHHI", 54 + len(body), 0, 0, 54)
    header += struct.pack("<IiiHHIIiiII", 40, width, height, 1, 32, 0, len(body), 2835, 2835, 0, 0)
    output.write_bytes(header + body)
    g.SelectObject(hdc_mem, old)
    g.DeleteObject(bitmap)
    g.DeleteDC(hdc_mem)
    u.ReleaseDC(hwnd, hdc_window)
    return {
        "path": str(output), "width": width, "height": height,
        "windowRect": [rect.left, rect.top, rect.right, rect.bottom],
        "clientSize": [client.right, client.bottom],
        "clientMinusWindowHeight": height - client.bottom,
        "sampledUniqueColors": len(sampled_colors),
        "sha256": sha256(output),
    }


def prepare_root(base: Path, index: int) -> Path:
    root = base / f"run-{index}"
    data = root / "data"
    shutil.copytree(SOURCE / "fixtures" / "root-2lines" / "data" / "lines", data / "lines")
    shutil.copy2(SOURCE / "fixtures" / "root-2lines" / "data" / "config.json", data / "config.json")
    return root


def sample(exe: Path, base: Path, report_dir: Path, index: int) -> dict:
    root = prepare_root(base, index)
    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": f"Software\\SpiderVPN\\tests\\s0-startup-{os.getpid()}-{index}-proxy",
        "SPIDERVPN_RUN_KEY": f"Software\\SpiderVPN\\tests\\s0-startup-{os.getpid()}-{index}-run",
        "SPIDERVPN_FORCE_NONADMIN": "1",
    })
    started = time.perf_counter()
    # WebView2 子孙进程会继承 stdout/stderr；communicate() 等 EOF 可能越过产品自身退出时间。
    # 基线只等待产品进程，诊断输出由已有 CLI 报告负责。
    process = subprocess.Popen([str(exe)], env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    hwnd = 0
    window_ms = None
    ready_ms = None
    close_timed_out = False
    try:
        deadline = started + 15
        while time.perf_counter() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"界面进程提前退出：{process.returncode}")
            hwnd = window_for_pid(process.pid)
            if hwnd:
                if window_ms is None:
                    window_ms = (time.perf_counter() - started) * 1000
                if webview_ready(hwnd):
                    ready_ms = (time.perf_counter() - started) * 1000
                    break
            time.sleep(0.005)
        if ready_ms is None:
            raise RuntimeError("15 秒内未出现可见的 WebView 子窗口")
        time.sleep(0.2)
        memory = working_set(process.pid)
        if memory is None:
            raise RuntimeError("无法读取被测进程工作集")
        # 子窗口可见不等于 DOM 已绘制；截图单独等待，不回填或篡改上面的启动计时。
        time.sleep(2.0)
        u.SetWindowPos(hwnd, 0, 30, 30, 900, 600, 0x0014)
        time.sleep(0.5)
        shot = screenshot(hwnd, report_dir / f"s0-startup-{index}-900x600.bmp")
        if shot["sampledUniqueColors"] < 16:
            raise RuntimeError(f"截图疑似空白：仅 {shot['sampledUniqueColors']} 种抽样颜色")
        result = {
            "sample": index, "pid": process.pid, "windowMs": round(window_ms, 1),
            "webviewReadyMs": round(ready_ms, 1), "workingSetBytes": memory,
            "workingSetMiB": round(memory / 1048576, 1) if memory else None,
            "screenshot": shot, "root": str(root),
        }
    finally:
        if process.poll() is None and hwnd:
            u.PostMessageW(hwnd, 0x0010, 0, 0)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            close_timed_out = True
            process.kill()
            process.wait(timeout=3)
        if 'result' in locals():
            result.update({"exit": process.returncode, "closeTimedOut": close_timed_out})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    exe, work, report_dir = args.exe.resolve(), args.work.resolve(), args.report_dir.resolve()
    if not exe.is_file():
        raise RuntimeError(f"找不到被测程序：{exe}")
    if work.exists():
        raise RuntimeError(f"性能工作目录必须不存在：{work}")
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True)
    live_before = sha256(LIVE_CONFIG)
    results = []
    try:
        for index in range(1, 4):
            results.append(sample(exe, work, report_dir, index))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    ready = [r["webviewReadyMs"] for r in results]
    sizes = {(r["screenshot"]["width"], r["screenshot"]["height"]) for r in results}
    payload = {
        "method": "fresh root per sample; visible product window; visible Chrome_WidgetWin child; product-only working set; PrintWindow(PW_RENDERFULLCONTENT); dpi=" + DPI_MODE,
        # PrintWindow 抓不到 WebView2 里 position:fixed 的合成层（实测：状态条缺失）。
        # 它只用于「窗口有非空白内容」的证明，不得用来判断某个 fixed 元素是否可见。
        "screenshotCaveat": "PrintWindow omits WebView2 fixed/composited layers; use screen BitBlt for visibility of .statusbar",
        "exe": str(exe), "exeSha256": sha256(exe), "samples": results,
        "windowMedianMs": statistics.median(r["windowMs"] for r in results),
        "webviewReadyMedianMs": statistics.median(ready),
        "workingSetMedianMiB": statistics.median(r["workingSetMiB"] for r in results),
        "readySamplesMs": ready, "screenshotSizes": sorted(sizes),
        "allExitedCleanly": all(r["exit"] == 0 and not r["closeTimedOut"] for r in results),
        "liveConfigBefore": live_before, "liveConfigAfter": sha256(LIVE_CONFIG),
        "liveUnchanged": live_before == sha256(LIVE_CONFIG),
    }
    report = report_dir / "s0-startup-baseline-0.1.4.json"
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ("readySamplesMs", "webviewReadyMedianMs", "workingSetMedianMiB", "screenshotSizes", "allExitedCleanly", "liveUnchanged")}, ensure_ascii=False))
    ok = len(results) == 3 and len(sizes) == 1 and payload["allExitedCleanly"] and payload["liveUnchanged"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
