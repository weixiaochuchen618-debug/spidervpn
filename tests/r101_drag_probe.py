#!/usr/bin/env python3
"""r101 诊断：真拖放能不能落到「交易程序」输入框。

用户报「拖动程序无法识别」。CDP 的 `Input.dispatchDragEvent` 只走渲染进程，
测不到宿主（wry / WebView2）的 OS 级 IDropTarget，所以这里用**真实的 OLE 拖放源**
（`tools\\drag-file.ps1`：WinForms DataObject + DoDragDrop + 注入鼠标）把文件拖到
`#wf-program-path` 上，然后读回输入框的值，判断拖放到底断在哪一段。

用法：
  python tests/r101_drag_probe.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r101-drag --work D:\\vpn构建\\reports-tmp\\r101-drag\\root \\
      --file C:\\Windows\\System32\\notepad.exe
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import json
import shutil
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(r"D:\vpn构建\tools")))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")
r87 = importlib.import_module("r87_history_ui")

Checker = helpers.Checker
DRAG_PS1 = Path(r"D:\vpn构建\tools\drag-file.ps1")
INPUT = "#wf-program-path"

user32 = ctypes.windll.user32
user32.ClientToScreen.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.POINT)]
user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
user32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
user32.mouse_event.argtypes = [
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.DWORD,
    ctypes.c_void_p,
]


def seed(work: Path) -> None:
    data = work / "data"
    data.mkdir(parents=True, exist_ok=True)
    config = {
        "schema": 2,
        "selected": "L1",
        "lines": [{"id": "L1", "name": "线路甲", "proxy_endpoint": "127.0.0.1:17901"}],
        "split": {
            "processes": [],
            "domains": [{"value": "tradingview.com", "target": "trade"}],
        },
    }
    (data / "config.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def fingerprint(path: Path) -> tuple[str, int]:
    """被测二进制的身份：交付报告里必须带上，否则「跑在哪个 build 上」只能靠猜。

    同一个路径前后放过不同 build 是常态（`C:\\tc-rs-build\\release\\` 就换过两次），
    只记路径等于没记。
    """
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def main_window(pid: int) -> int:
    for handle in helpers.windows_of(pid):
        length = user32.GetWindowTextLengthW(handle)
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(handle, buffer, length + 1)
        if "TradeChannel" in buffer.value:
            return handle
    return 0


def client_origin(hwnd: int) -> tuple[int, int]:
    rect = wintypes.RECT()
    user32.GetClientRect(hwnd, ctypes.byref(rect))
    point = wintypes.POINT(0, 0)
    user32.ClientToScreen(hwnd, ctypes.byref(point))
    return point.x, point.y


SRC_POINT = (110, 60)


def _mouse(flags: int) -> None:
    user32.mouse_event(flags, 0, 0, 0, None)


def drag(ps1: Path, path: Path, x: int, y: int) -> tuple[bool, str]:
    """真 OLE 拖放：脚本出窗口并 DoDragDrop，鼠标动作在这里发（脚本内部松手会卡在模态循环）。"""
    process = subprocess.Popen(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ps1),
            "-Path",
            str(path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    log: list[str] = []

    def pump(seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            sleep_for = min(0.1, max(0.0, deadline - time.monotonic()))
            time.sleep(sleep_for)

    try:
        # 等窗口起来：脚本在这里之后才有控件可点。
        started = time.monotonic()
        while time.monotonic() - started < 15:
            line = process.stdout.readline() if process.stdout else ""
            if line:
                log.append(line.strip())
                if line.strip() == "READY":
                    break
            else:
                time.sleep(0.1)

        user32.SetCursorPos(*SRC_POINT)
        time.sleep(0.25)
        _mouse(0x0002)  # LEFTDOWN → 触发 DoDragDrop
        time.sleep(0.35)

        # 分几步移动：OLE 靠鼠标移动算 DRAGOVER，一步跳过去有些实现收不到。
        sx, sy = SRC_POINT
        for step in range(1, 13):
            user32.SetCursorPos(int(sx + (x - sx) * step / 12), int(sy + (y - sy) * step / 12))
            time.sleep(0.06)
        time.sleep(0.45)
        user32.SetCursorPos(x, y)
        time.sleep(0.25)
        _mouse(0x0004)  # LEFTUP → Drop

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            line = process.stdout.readline() if process.stdout else ""
            if line:
                log.append(line.strip())
                if line.startswith("EFFECT") or line.startswith("WATCHDOG"):
                    break
            else:
                time.sleep(0.1)
    finally:
        try:
            process.wait(timeout=6)
        except Exception:  # noqa: BLE001
            process.kill()
    joined = " | ".join(item for item in log if item)
    return "EFFECT=Copy" in joined.replace(" ", ""), joined


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--file", default=r"C:\Windows\System32\notepad.exe")
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    checker = Checker()
    report: dict = {"mode": "drag", "exe": str(exe), "file": args.file, "checks": []}
    # 跑前指纹：报告里必须有它，否则「这批证据跑在哪个 build 上」无从分辨。
    before_sha, before_bytes = fingerprint(exe)
    report["exeSha256"] = before_sha
    report["exeBytes"] = before_bytes
    process = None
    ws = None
    code = 0
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "drag")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            "",
        )
        checker.check("进应用", r87.click_when_enabled(ws, pump, "nav [data-page=apps]") == "ok", "")
        checker.check(
            "打开交易软件名单",
            r87.click_when_enabled(ws, pump, "#main [data-action=domains]") == "ok"
            and helpers.wait_js(ws, f"!!document.querySelector('{INPUT}')", 20, "输入框", pump),
            r87.body_text(ws)[-200:],
        )

        hwnd = main_window(process.pid)
        ox, oy = client_origin(hwnd)
        rect = ws.evaluate(
            "(()=>{const e=document.querySelector('" + INPUT + "');"
            "if(!e)return null;const r=e.getBoundingClientRect();"
            "return {x:r.left+r.width/2,y:r.top+r.height/2,dpr:window.devicePixelRatio||1};})()"
        )
        print(f"[probe] hwnd=0x{hwnd:X} client=({ox},{oy}) rect={rect}", flush=True)
        if not rect:
            raise RuntimeError("输入框不在页面上")
        x = int(ox + float(rect["x"]) * float(rect["dpr"]))
        y = int(oy + float(rect["y"]) * float(rect["dpr"]))
        print(f"[probe] drop point=({x},{y})", flush=True)

        ok, output = drag(DRAG_PS1, Path(args.file), x, y)
        print(f"[probe] drag source rc={ok} out={output.strip()}", flush=True)

        deadline = time.monotonic() + 6
        value = ""
        while time.monotonic() < deadline:
            value = str(ws.evaluate("document.querySelector('" + INPUT + "').value") or "")
            if value:
                break
            time.sleep(0.3)
        text = r87.body_text(ws)
        checker.check("输入框被拖放填上路径", bool(value), f"value={value!r}")
        checker.check("出现「已选择」提示", "已选择" in text, text[-300:])
        shots: list[str] = []
        helpers.screenshot(ws, report_dir / "01-after-drag.png", shots)
        report["checks"] = checker.checks
        report["shots"] = shots
        report["value"] = value
        code = 0 if checker.all_passed else 1
    except Exception as error:  # noqa: BLE001
        print(f"[probe] 失败：{error}", flush=True)
        code = 2
    finally:
        if process and not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        after_sha, after_bytes = fingerprint(exe)
        report["exeSha256After"] = after_sha
        report["exeBytesAfter"] = after_bytes
        checker.check(
            "被测二进制跑前跑后一致",
            (before_sha, before_bytes) == (after_sha, after_bytes),
            f"before={before_sha}/{before_bytes}B after={after_sha}/{after_bytes}B",
        )
        if not checker.all_passed:
            code = code or 1
        report["checks"] = checker.checks
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(report.get("checks", []), ensure_ascii=False, indent=2), flush=True)
        print(f"[probe] exit={code}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
