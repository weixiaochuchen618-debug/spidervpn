#!/usr/bin/env python3
"""T-20 取证：同一次运行里用两种 GDI 方式抓同一个窗口，判断「状态条没画」还是「没抓到」。

背景：`PrintWindow(PW_RENDERFULLCONTENT)` 抓出来的 900x600 图底部找不到 `.statusbar`，
但 DOM 探针证明它在视口内（top=420.4 / bottom=450.4，视口高 450）。
WebView2 走合成层，`PrintWindow` 有可能只拿到主内容层而漏掉 `position:fixed` 的元素；
屏幕 `BitBlt` 拿到的是 DWM 合成后的最终画面。两者不一致就说明问题在验收方法，不在产品。

所有运行都用临时数据根，不碰真实安装。
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parent.parent
PHP = ctypes.WinDLL if hasattr(ctypes, "WinDLL") else None
u = ctypes.WinDLL("user32", use_last_error=True)
g = ctypes.WinDLL("gdi32", use_last_error=True)

u.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
u.GetWindowRect.restype = wintypes.BOOL
u.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
u.GetClientRect.restype = wintypes.BOOL
u.GetWindowDC.argtypes = [wintypes.HWND]
u.GetWindowDC.restype = wintypes.HDC
u.GetDC.argtypes = [wintypes.HWND]
u.GetDC.restype = wintypes.HDC
u.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
u.ReleaseDC.restype = ctypes.c_int
u.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
u.PrintWindow.restype = wintypes.BOOL
u.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                           ctypes.c_int, ctypes.c_int, wintypes.UINT]
u.SetWindowPos.restype = wintypes.BOOL
u.SetForegroundWindow.argtypes = [wintypes.HWND]
u.SetForegroundWindow.restype = wintypes.BOOL
u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
u.PostMessageW.restype = wintypes.BOOL
u.IsWindowVisible.argtypes = [wintypes.HWND]
u.IsWindowVisible.restype = wintypes.BOOL
u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
u.GetWindowThreadProcessId.restype = wintypes.DWORD
u.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
u.GetClassNameW.restype = ctypes.c_int
u.GetSystemMetrics.argtypes = [ctypes.c_int]
u.GetSystemMetrics.restype = ctypes.c_int

ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
u.EnumWindows.argtypes = [ENUMPROC, wintypes.LPARAM]
u.EnumWindows.restype = wintypes.BOOL

g.CreateCompatibleDC.argtypes = [wintypes.HDC]
g.CreateCompatibleDC.restype = wintypes.HDC
g.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]
g.CreateCompatibleBitmap.restype = wintypes.HBITMAP
g.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
g.SelectObject.restype = wintypes.HGDIOBJ
g.BitBlt.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                     wintypes.HDC, ctypes.c_int, ctypes.c_int, wintypes.DWORD]
g.BitBlt.restype = wintypes.BOOL
g.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT,
                        ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
g.GetDIBits.restype = ctypes.c_int
g.DeleteObject.argtypes = [wintypes.HGDIOBJ]
g.DeleteObject.restype = wintypes.BOOL
g.DeleteDC.argtypes = [wintypes.HDC]
g.DeleteDC.restype = wintypes.BOOL

SRCCOPY = 0x00CC0020
PW_RENDERFULLCONTENT = 2
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040


def set_dpi_aware() -> str:
    """必须最先调用：否则本进程看到的是 125% 虚拟坐标。

    后果很具体：`SetWindowPos(900,600)` 会被系统放大成 1125x750，
    而 `PrintWindow` 只覆盖 900x600 物理像素，窗口底部（含状态条）整条被切掉，
    看起来就像「产品把状态条画丢了」。
    """
    u.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
    u.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
    try:
        if u.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):  # PER_MONITOR_AWARE_V2
            return "per-monitor-v2"
    except Exception:
        pass
    try:
        shcore = ctypes.WinDLL("shcore")
        shcore.SetProcessDpiAwareness.argtypes = [ctypes.c_int]
        shcore.SetProcessDpiAwareness.restype = ctypes.c_int
        if shcore.SetProcessDpiAwareness(2) == 0:  # PROCESS_PER_MONITOR_DPI_AWARE
            return "per-monitor"
    except Exception:
        pass
    try:
        if u.SetProcessDPIAware():
            return "system"
    except Exception:
        pass
    return "none"


DPI_MODE = set_dpi_aware()


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD), ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG), ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD),
    ]


def window_for_pid(pid: int) -> int:
    found = []

    def callback(hwnd, _lparam):
        if not u.IsWindowVisible(hwnd):
            return True
        owner = wintypes.DWORD()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            name = ctypes.create_unicode_buffer(256)
            u.GetClassNameW(hwnd, name, len(name))
            if name.value.startswith("Chrome_WidgetWin_"):
                return True
            rect = wintypes.RECT()
            u.GetWindowRect(hwnd, ctypes.byref(rect))
            if rect.right - rect.left > 200 and rect.bottom - rect.top > 200:
                found.append(hwnd)
                return False
        return True

    u.EnumWindows(ENUMPROC(callback), 0)
    return found[0] if found else 0


def webview_ready(hwnd: int) -> bool:
    state = {"ready": False}

    def callback(child, _lparam):
        name = ctypes.create_unicode_buffer(256)
        u.GetClassNameW(child, name, len(name))
        if name.value.startswith("Chrome_WidgetWin_") and u.IsWindowVisible(child):
            rect = wintypes.RECT()
            u.GetClientRect(child, ctypes.byref(rect))
            if rect.right > 0 and rect.bottom > 0:
                state["ready"] = True
                return False
        return True

    u.EnumWindows(ENUMPROC(callback), 0)
    return state["ready"]


def grab(hwnd: int, mode: str, output: Path) -> dict:
    rect = wintypes.RECT()
    client = wintypes.RECT()
    u.GetWindowRect(hwnd, ctypes.byref(rect))
    u.GetClientRect(hwnd, ctypes.byref(client))
    if mode == "fullscreen":
        width, height = u.GetSystemMetrics(0), u.GetSystemMetrics(1)
    else:
        width, height = rect.right - rect.left, rect.bottom - rect.top
    if mode == "print":
        hdc_window = u.GetWindowDC(hwnd)
        source_x = source_y = 0
    elif mode == "screen":
        hdc_window = u.GetDC(0)
        source_x, source_y = rect.left, rect.top
    else:  # fullscreen
        hdc_window = u.GetDC(0)
        source_x = source_y = 0
    hdc_mem = g.CreateCompatibleDC(hdc_window)
    bitmap = g.CreateCompatibleBitmap(hdc_window, width, height)
    old = g.SelectObject(hdc_mem, bitmap)
    try:
        if mode == "print":
            ok = bool(u.PrintWindow(hwnd, hdc_mem, PW_RENDERFULLCONTENT))
        else:
            ok = bool(g.BitBlt(hdc_mem, 0, 0, width, height, hdc_window, source_x, source_y, SRCCOPY))
        info = BITMAPINFOHEADER()
        info.biSize = ctypes.sizeof(info)
        info.biWidth, info.biHeight = width, -height
        info.biPlanes, info.biBitCount = 1, 32
        buffer = ctypes.create_string_buffer(width * height * 4)
        rows = g.GetDIBits(hdc_mem, bitmap, 0, height, buffer, ctypes.byref(info), 0)
        if not ok or rows != height:
            raise RuntimeError(f"{mode} 抓图失败：ok={ok} rows={rows}/{height}")
        pixels = buffer.raw
    finally:
        g.SelectObject(hdc_mem, old)
        g.DeleteObject(bitmap)
        g.DeleteDC(hdc_mem)
        if mode == "print":
            u.ReleaseDC(hwnd, hdc_window)
        else:
            u.ReleaseDC(0, hdc_window)

    body = bytearray()
    stride = width * 4
    for y in range(height - 1, -1, -1):  # 顶部在前的 top-down 像素 -> bottom-up BMP
        body += pixels[y * stride:(y + 1) * stride]
    dib = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 32, 0, len(body), 0, 0, 0, 0)
    header = b"BM" + struct.pack("<IHHI", 14 + len(dib) + len(body), 0, 0, 14 + len(dib))
    output.write_bytes(header + dib + bytes(body))

    # 分析：底部 130px 内找 #E5E7EB 近似分隔线、灰字、非白像素
    report = {
        "path": str(output), "mode": mode, "width": width, "height": height,
        "windowRect": [rect.left, rect.top, rect.right, rect.bottom],
        "clientSize": [client.right, client.bottom],
        "clientMinusWindowHeight": height - client.bottom,
        "separators": [], "bottom": {},
    }
    for y in range(height):
        base = y * stride
        hits = 0
        for x in range(0, width, 2):
            b, gg, r = pixels[base + x * 4], pixels[base + x * 4 + 1], pixels[base + x * 4 + 2]
            if 214 <= r <= 244 and 216 <= gg <= 246 and 220 <= b <= 250 and abs(r - gg) < 10 and abs(gg - b) < 12:
                hits += 1
        if hits > (width // 2) * 0.6 and y > 60:
            report["separators"].append(y)

    zone_start = max(0, height - 130)
    non_white = 0
    gray_text = 0
    total = 0
    for y in range(zone_start, height):
        base = y * stride
        for x in range(0, width, 2):
            b, gg, r = pixels[base + x * 4], pixels[base + x * 4 + 1], pixels[base + x * 4 + 2]
            total += 1
            if not (r > 248 and gg > 248 and b > 248):
                non_white += 1
            if 96 <= r <= 186 and 100 <= gg <= 190 and 110 <= b <= 200 and abs(r - gg) < 14:
                gray_text += 1
    report["bottom"] = {
        "zone": [zone_start, height],
        "nonWhiteRatio": round(non_white / total, 4) if total else 0,
        "grayTextPixels": gray_text,
    }

    # 状态条带：窗口最后 48px（状态条 30 CSS ≈ 37.5 物理，含 1px 上边框）。
    # 判据不是「有灰字」（卡片正文也是灰的），而是「有一条覆盖 ≥85% 宽度的浅灰横线」——
    # 那是 .statusbar 的 border-top，页面卡片宽度约 820 < 882*0.85，不会误命中。
    band_top = max(0, height - 48)
    band_gray = 0
    band_white = 0
    band_total = 0
    band_separators = []
    for y in range(band_top, height):
        base = y * stride
        sep_hits = 0
        for x in range(0, width, 2):
            b, gg, r = pixels[base + x * 4], pixels[base + x * 4 + 1], pixels[base + x * 4 + 2]
            band_total += 1
            if r > 248 and gg > 248 and b > 248:
                band_white += 1
            if 96 <= r <= 186 and 100 <= gg <= 190 and 110 <= b <= 200 and abs(r - gg) < 14:
                band_gray += 1
            if 214 <= r <= 244 and 216 <= gg <= 246 and 220 <= b <= 250 and abs(r - gg) < 10 and abs(gg - b) < 12:
                sep_hits += 1
        if sep_hits > (width // 2) * 0.60:
            band_separators.append(y)
    report["statusbarBand"] = {
        "zone": [band_top, height],
        "whiteRatio": round(band_white / band_total, 4) if band_total else 0,
        "grayTextPixels": band_gray,
        "fullWidthSeparators": band_separators,
        # 阈值说明：最大化时页面卡片会压住状态条上边框的一部分（实测约 66% 宽度可见），
        # 所以「全宽」不能按 85% 卡；没有状态条时该带是正文，whiteRatio 通常低于 0.4。
        "looksLikeStatusbar": bool(band_separators) and band_gray > 200 and (band_white / band_total if band_total else 0) > 0.4,
    }
    return report


def prepare_root(base: Path) -> Path:
    root = base / "root"
    data = root / "data"
    shutil.copytree(SOURCE / "fixtures" / "root-2lines" / "data" / "lines", data / "lines")
    shutil.copy2(SOURCE / "fixtures" / "root-2lines" / "data" / "config.json", data / "config.json")
    return root


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--width", type=int, default=900)
    parser.add_argument("--height", type=int, default=600)
    args = parser.parse_args()

    exe = Path(args.exe)
    work = Path(args.work)
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    root = prepare_root(work)

    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": f"Software\\SpiderVPN\\tests\\t20-{os.getpid()}-proxy",
        "SPIDERVPN_RUN_KEY": f"Software\\SpiderVPN\\tests\\t20-{os.getpid()}-run",
        "SPIDERVPN_FORCE_NONADMIN": "1",
    })
    process = subprocess.Popen(
        [str(exe)], env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    hwnd = 0
    result: dict = {"exe": str(exe), "size": [args.width, args.height],
                    "dpiAwareness": DPI_MODE, "shots": []}
    try:
        deadline = time.perf_counter() + 20
        while time.perf_counter() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"界面进程提前退出：{process.returncode}")
            hwnd = window_for_pid(process.pid)
            if hwnd and webview_ready(hwnd):
                break
            time.sleep(0.05)
        if not hwnd:
            raise RuntimeError("20 秒内未找到产品主窗口")
        time.sleep(2.0)
        u.SetWindowPos(hwnd, 0, 40, 40, args.width, args.height,
                       SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW)
        u.SetForegroundWindow(hwnd)
        time.sleep(1.5)
        result["shots"].append(grab(hwnd, "print", report_dir / "t20-print-900x600.bmp"))
        time.sleep(0.4)
        result["shots"].append(grab(hwnd, "screen", report_dir / "t20-screen-900x600.bmp"))
        time.sleep(0.4)
        result["shots"].append(grab(hwnd, "fullscreen", report_dir / "t20-fullscreen.bmp"))
        result["windowHandle"] = hwnd
        result["pid"] = process.pid
    finally:
        if process.poll() is None and hwnd:
            u.PostMessageW(hwnd, 0x0010, 0, 0)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        result["exit"] = process.returncode

    print_report = result["shots"][0] if len(result["shots"]) > 0 else {}
    screen_report = result["shots"][1] if len(result["shots"]) > 1 else {}
    verdict = {
        "printHasSeparatorNearBottom": any(y > print_report.get("clientSize", [0, 0])[1] * 0.86
                                          for y in print_report.get("separators", [])),
        "screenHasSeparatorNearBottom": any(y > screen_report.get("clientSize", [0, 0])[1] * 0.86
                                           for y in screen_report.get("separators", [])),
        "printGrayTextPixels": print_report.get("bottom", {}).get("grayTextPixels"),
        "screenGrayTextPixels": screen_report.get("bottom", {}).get("grayTextPixels"),
    }
    result["verdict"] = verdict
    out = report_dir / "t20-capture-compare.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"verdict": verdict, "print": print_report, "screen": screen_report},
                     ensure_ascii=False)[:1600])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
