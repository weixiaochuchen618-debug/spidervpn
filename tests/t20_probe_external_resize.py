#!/usr/bin/env python3
"""复现路径实验：用外部 SetWindowPos 改探针窗口尺寸，量视口是否还等于客户区。

产品窗口就是被外部脚本 SetWindowPos 改到 900x600 的；而探针此前用 tao 的
set_inner_size 改尺寸时视口完全正确。若这里能复现「视口比客户区高」，
根因就锁定在外部改尺寸这条路，而不是 wry 的常规布局。
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time

u = ctypes.WinDLL("user32", use_last_error=True)
u.IsWindowVisible.argtypes = [wintypes.HWND]
u.IsWindowVisible.restype = wintypes.BOOL
u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
u.GetWindowThreadProcessId.restype = wintypes.DWORD
u.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
u.GetClassNameW.restype = ctypes.c_int
u.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
u.GetWindowRect.restype = wintypes.BOOL
u.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
u.GetClientRect.restype = wintypes.BOOL
u.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                           ctypes.c_int, ctypes.c_int, wintypes.UINT]
u.SetWindowPos.restype = wintypes.BOOL
u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
u.PostMessageW.restype = wintypes.BOOL

ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
u.EnumWindows.argtypes = [ENUMPROC, wintypes.LPARAM]
u.EnumWindows.restype = wintypes.BOOL


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


def main() -> int:
    exe, out, page, state = sys.argv[1:5]
    work = Path(out).parent
    work.mkdir(parents=True, exist_ok=True)
    process = subprocess.Popen(
        [exe, out, page, state], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    hwnd = 0
    try:
        deadline = time.perf_counter() + 20
        while time.perf_counter() < deadline:
            hwnd = window_for_pid(process.pid)
            if hwnd:
                break
            time.sleep(0.05)
        if not hwnd:
            raise RuntimeError("未找到探针窗口")
        time.sleep(3.0)  # 等首个 load 报告落盘
        rect = wintypes.RECT()
        client = wintypes.RECT()
        u.GetWindowRect(hwnd, ctypes.byref(rect))
        u.GetClientRect(hwnd, ctypes.byref(client))
        before = {"windowRect": [rect.left, rect.top, rect.right, rect.bottom],
                  "clientSize": [client.right, client.bottom]}
        u.SetWindowPos(hwnd, 0, 40, 40, 900, 600, 0x0004 | 0x0010 | 0x0040)
        time.sleep(3.0)
        u.GetWindowRect(hwnd, ctypes.byref(rect))
        u.GetClientRect(hwnd, ctypes.byref(client))
        after = {"windowRect": [rect.left, rect.top, rect.right, rect.bottom],
                 "clientSize": [client.right, client.bottom]}
        report = json.loads(Path(out).read_text(encoding="utf-8"))
        print(json.dumps({"before": before, "after": after,
                          "reports": [json.loads(r)["probe"] for r in report["reports"]]},
                         ensure_ascii=False, indent=2))
        return 0
    finally:
        if hwnd:
            u.PostMessageW(hwnd, 0x0010, 0, 0)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
