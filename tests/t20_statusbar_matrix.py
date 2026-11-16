#!/usr/bin/env python3
"""T-20 状态条可见性三档验收：900x600 / 最大化 / 从最大化还原。

结论（2026-10-30 实测）：状态条本来是可见的。此前「被 WebView 越界裁掉」是两处
测量缺陷叠加造成的误判：
  1. Python 进程 DPI-unaware：`SetWindowPos(900,600)` 被系统按 125% 放大成
     1125x750，截图只覆盖左上角 900x600 物理像素，底部连同状态条被切掉；
  2. `PrintWindow(PW_RENDERFULLCONTENT)` 不绘制 WebView2 的 `position:fixed`
     合成层（同一窗口屏幕 BitBlt 有状态条、PrintWindow 没有）。
本脚本用 per-monitor-v2 + 屏幕 BitBlt，按「覆盖 ≥85% 宽度的浅灰上边框 + 灰字」
判定状态条，不用「看起来白不白」这种会误判的松散条件。
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import t20_capture_compare as cap  # 导入即完成 DPI 感知设置

u = cap.u
u.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
u.ShowWindow.restype = wintypes.BOOL
SOURCE = Path(__file__).resolve().parents[1]

SW_MAXIMIZE = 3
SW_RESTORE = 9


def prepare_root(base: Path) -> Path:
    root = base / "root"
    data = root / "data"
    shutil.copytree(SOURCE / "fixtures" / "root-2lines" / "data" / "lines", data / "lines")
    shutil.copy2(SOURCE / "fixtures" / "root-2lines" / "data" / "config.json", data / "config.json")
    return root


def main() -> int:
    exe = Path(sys.argv[1])
    report_dir = Path(sys.argv[2])
    work = Path(sys.argv[3])
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    root = prepare_root(work)

    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": f"Software\\SpiderVPN\\tests\\t20m-{os.getpid()}-proxy",
        "SPIDERVPN_RUN_KEY": f"Software\\SpiderVPN\\tests\\t20m-{os.getpid()}-run",
        "SPIDERVPN_FORCE_NONADMIN": "1",
    })
    process = subprocess.Popen([str(exe)], env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    hwnd = 0
    steps = []
    result = {"exe": str(exe), "dpiAwareness": cap.DPI_MODE, "steps": steps,
              "exeSha256": cap.__dict__.get("sha256", lambda p: None)(exe) if hasattr(cap, "sha256") else None}
    try:
        deadline = time.perf_counter() + 20
        while time.perf_counter() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"界面进程提前退出：{process.returncode}")
            hwnd = cap.window_for_pid(process.pid)
            if hwnd and cap.webview_ready(hwnd):
                break
            time.sleep(0.05)
        if not hwnd:
            raise RuntimeError("20 秒内未找到产品窗口")
        time.sleep(2.0)

        def shoot(name: str, action) -> None:
            action()
            time.sleep(1.2)
            path = report_dir / f"t20-statusbar-{name}.bmp"
            shot = cap.grab(hwnd, "screen", path)
            band = shot.get("statusbarBand", {})
            steps.append({
                "name": name,
                "clientSize": shot["clientSize"],
                "windowSize": [shot["width"], shot["height"]],
                "band": band,
                "ok": bool(band.get("looksLikeStatusbar")),
                "path": str(path),
            })

        shoot("900x600", lambda: u.SetWindowPos(
            hwnd, 0, 40, 40, 900, 600,
            cap.SWP_NOZORDER | cap.SWP_NOACTIVATE | cap.SWP_SHOWWINDOW))
        shoot("maximized", lambda: u.ShowWindow(hwnd, SW_MAXIMIZE))
        shoot("restored", lambda: u.ShowWindow(hwnd, SW_RESTORE))

        result["allVisible"] = all(s["ok"] for s in steps)
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

    out = report_dir / "t20-statusbar-matrix.json"
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for step in steps:
        print(step["name"], "ok=", step["ok"], "client=", step["clientSize"],
              "band=", step["band"])
    print("allVisible=", result.get("allVisible"), "report=", out)
    return 0 if result.get("allVisible") else 1


if __name__ == "__main__":
    raise SystemExit(main())
