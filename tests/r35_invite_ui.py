#!/usr/bin/env python3
"""r35/r36 界面验收：真实宿主 + 真实 WebView2 + 真实服务器，走完邀请码从生成到作废。

与 `m1_page_behaviors.py` 的分工：

- 那边是 headless Edge + 手写快照，验的是「这份 app.js 认不认宿主产出的节点树」；
- 这边是**装好的 exe**（真实数据根、真实线路、真实 SSH 到 203.0.113.10），
  验的是「点下去真的会生成一张码，显示/复制拿到的是完整码，作废后码立刻失效」。

驱动方式用 CDP（`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=N`），
不依赖鼠标坐标：布局一改坐标就废，选择器才是宿主与页面之间的契约。

两个必须做的环境处理（都是真机上踩到的）：

1. **窗口要置前**。Windows 对后台进程做计时器限流：窗口在后台时，宿主的
   1 秒节拍不跑，长命令完成事件也压在队列里，页面就一直停在「正在生成邀请码」。
2. **等待期间要泵消息**。置前后仍然周期性发一个无害的 `WM_MOUSEMOVE`，
   让 tao 事件循环转起来；这不是模拟用户操作，点击仍然走选择器。

前置：数据根里已有一条线路（`outbounds[].server` == 服务器记录 `Host`），
否则邀请入口是灰的——脚本会如实报「入口不可点」而不是假装通过。

用法：
  python tests/r35_invite_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \
      --report-dir C:\\tc-rs-build\\r36-invite-ui
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s0_page_fixtures import WebSocket, free_port  # noqa: E402

ALLOWED_WORK = Path(r"C:\tc-rs-build")
CDP_READY_SECONDS = 40.0
CREATE_SECONDS = 300.0
WM_MOUSEMOVE = 0x0200
user32 = ctypes.windll.user32


class Checker:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def check(self, label: str, ok: bool, detail: object = None) -> None:
        self.checks.append({"label": label, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} {label}" + ("" if ok else f" | {detail}"), flush=True)

    @property
    def all_passed(self) -> bool:
        return all(item["ok"] for item in self.checks)


def js(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def windows_of(pid: int) -> list[int]:
    found: list[int] = []

    @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
    def callback(hwnd, _):
        owner = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
        return True

    user32.EnumWindows(callback, None)
    return found


class Pump:
    """让 tao 事件循环转起来：置前 + 周期性发一个无害消息。"""

    def __init__(self, pid: int) -> None:
        self.handles = windows_of(pid)
        self.foreground = False
        for handle in self.handles:
            user32.ShowWindow(handle, 9)  # SW_RESTORE
            if user32.SetForegroundWindow(handle):
                self.foreground = True

    def tick(self) -> None:
        for handle in self.handles:
            user32.PostMessageW(handle, WM_MOUSEMOVE, 0, 0)


def click(ws: WebSocket, selector: str) -> bool:
    return bool(
        ws.evaluate(
            f"(()=>{{const e=document.querySelector({js(selector)});"
            "if(!e||e.disabled)return false;e.click();return true;})()"
        )
    )


def wait_js(ws: WebSocket, expression: str, seconds: float, label: str, pump: Pump | None = None) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if ws.evaluate(expression):
                return True
        except Exception:
            pass
        if pump is not None:
            pump.tick()
        time.sleep(0.4)
    print(f"  （等待超时：{label}）", flush=True)
    return False


def wait_cdp(port: int, seconds: float) -> dict:
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as reply:
                targets = json.loads(reply.read().decode("utf-8"))
            for target in targets:
                if target.get("type") == "page" and target.get("webSocketDebuggerUrl"):
                    return target
            last = f"targets={targets}"
        except Exception as error:  # noqa: BLE001
            last = repr(error)
        time.sleep(0.3)
    raise TimeoutError(f"CDP 在 {seconds} 秒内没有就绪：{last}")


def screenshot(ws: WebSocket, path: Path, shots: list[str]) -> None:
    try:
        result = ws.call("Page.captureScreenshot", {"format": "png"})
        path.write_bytes(base64.b64decode(result["data"]))
        shots.append(str(path))
    except Exception as error:  # noqa: BLE001
        print(f"  （截图失败：{error}）", flush=True)


CF_UNICODETEXT = 13


def read_clipboard() -> str:
    """读当前剪贴板文本（与被测程序同一个会话，CF_UNICODETEXT）。"""
    kernel32 = ctypes.windll.kernel32
    # 64 位下必须显式声明指针类型：默认 c_int 会把 HANDLE 截成 32 位，
    # GlobalLock 返回的地址一读就 access violation。
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    if not user32.OpenClipboard(None):
        return ""
    try:
        handle = user32.GetClipboardData(CF_UNICODETEXT)
        if not handle:
            return ""
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            return ""
        try:
            return ctypes.wstring_at(pointer)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true", help="验收后不关闭程序（留给人看）")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    if ALLOWED_WORK not in report_dir.parents and report_dir != ALLOWED_WORK:
        raise SystemExit(f"只能写在 {ALLOWED_WORK} 下：{report_dir}")
    report_dir.mkdir(parents=True, exist_ok=True)

    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    # 真实数据根：不设 SPIDERVPN_ROOT，走 C:\SpiderVPN\data
    env.pop("SPIDERVPN_ROOT", None)
    log = (report_dir / "host.log").open("wb")
    process = subprocess.Popen(
        [args.exe],
        cwd=str(Path(args.exe).parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] host pid={process.pid} cdp={port}", flush=True)

    checker = Checker()
    report: dict = {"exe": args.exe, "cdpPort": port, "shots": [], "checks": []}
    ws: WebSocket | None = None
    try:
        target = wait_cdp(port, CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(process.pid)
        print(f"[probe] windows={pump.handles} foreground={pump.foreground}", flush=True)

        checker.check(
            "真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                20,
                "页面初始化",
                pump,
            ),
        )
        screenshot(ws, report_dir / "01-home.png", report["shots"])

        checker.check("导航到线路页", click(ws, "[data-page=lines]"))
        checker.check(
            "线路页出现「邀请其他电脑」入口",
            wait_js(ws, "!!document.querySelector('[data-invite=Choose]')", 20, "邀请入口", pump),
        )
        enabled = ws.evaluate(
            "(()=>{const e=document.querySelector('[data-invite=Choose]');"
            "return !!e && !e.disabled;})()"
        )
        hint = ws.evaluate(
            "(()=>{const e=document.querySelector('[data-testid=invite-unavailable]');"
            "return e?e.textContent:'-';})()"
        )
        checker.check("邀请入口可点击（线路已归属到服务器）", bool(enabled), hint)
        screenshot(ws, report_dir / "02-lines.png", report["shots"])
        if not enabled:
            raise SystemExit("邀请入口不可点，后面的流程没有意义")

        checker.check("点「邀请其他电脑」", click(ws, "#main [data-invite=Choose]"))
        # 单条线路直接进设置页；多条线路先出选择页。
        if wait_js(ws, "!!document.querySelector('#main .pair-choice')", 3, "选择页", pump):
            print("[probe] 多服务器：先选第一台", flush=True)
            checker.check(
                "选择页点第一台服务器",
                click(ws, "#main .pair-choice [data-invite=Target]"),
            )
        checker.check(
            "进入生成邀请码设置页",
            wait_js(ws, "!!document.querySelector('[data-invite=CreateNew]')", 25, "设置页", pump),
        )
        line_text = ws.evaluate(
            "(()=>{const e=document.querySelector('[data-testid=invite-line]');"
            "return e?e.textContent:'';})()"
        )
        checker.check("设置页带上了这条线路", "自建" in (line_text or ""), line_text)

        # r37：进页面会先量一次 18443。检查结束后阶段条消失、生成按钮才可用；
        # 通了就不显示横幅（页面只在不通时说话）。
        checker.check(
            "18443 可达性自检完成",
            wait_js(
                ws,
                "!document.querySelector('[data-testid=invite-stage]')",
                30,
                "自检完成",
                pump,
            ),
        )
        reach_text = ws.evaluate(
            "(()=>{const e=document.querySelector('[data-testid=invite-reach]');"
            "return e?e.textContent:'';})()"
        )
        checker.check("自检结论：18443 可达（没有告警横幅）", (reach_text or "").strip() == "", reach_text)
        checker.check(
            "自检结束后「生成邀请码」可点",
            wait_js(
                ws,
                "(()=>{const e=document.querySelector('[data-invite=CreateNew]');"
                "return !!e && !e.disabled;})()",
                15,
                "生成按钮可用",
                pump,
            ),
        )
        screenshot(ws, report_dir / "03-setup.png", report["shots"])

        checker.check("点「生成邀请码」", click(ws, "#main [data-invite=CreateNew]"))
        got_code = wait_js(
            ws,
            "(()=>{const e=document.querySelector('[data-testid=invite-code]');"
            "return !!e && /^TCI1\\./.test(e.value);})()",
            CREATE_SECONDS,
            "邀请码",
            pump,
        )
        checker.check("拿到邀请码（预览态）", got_code)
        if not got_code:
            body = ws.evaluate("(document.querySelector('#main')||{textContent:''}).textContent")
            print(f"[probe] 页面文本：{str(body)[:400]}", flush=True)
            screenshot(ws, report_dir / "04-failed.png", report["shots"])
            raise SystemExit("没有拿到邀请码")

        preview = ws.evaluate("document.querySelector('[data-testid=invite-code]').value")
        preview_ok = (
            isinstance(preview, str)
            and preview.startswith("TCI1.")
            and "共" in preview
            and len(preview) < 120
        )
        checker.check("预览只给开头一小段（不是完整码）", preview_ok, preview)
        screenshot(ws, report_dir / "04-code-preview.png", report["shots"])

        checker.check("点「显示」", click(ws, "#main [data-invite=Reveal]"))
        checker.check(
            "显示后输入框是完整码",
            wait_js(
                ws,
                "(()=>{const e=document.querySelector('[data-testid=invite-code]');"
                "return !!e && e.value.length > 120 && /^TCI1\\./.test(e.value);})()",
                15,
                "完整码",
                pump,
            ),
        )
        full = ws.evaluate("document.querySelector('[data-testid=invite-code]').value")
        checker.check(
            "完整码明显长于预览",
            isinstance(full, str) and len(full) > len(preview or ""),
            len(full or ""),
        )
        screenshot(ws, report_dir / "05-code-revealed.png", report["shots"])

        checker.check("点「复制邀请码」", click(ws, "#main [data-invite=Copy]"))
        time.sleep(0.8)
        clip = read_clipboard()
        checker.check("剪贴板里是完整邀请码", clip.strip() == (full or "").strip(), clip[:40])

        checker.check("点「隐藏」", click(ws, "#main [data-invite=Reveal]"))
        checker.check(
            "隐藏后回到预览",
            wait_js(
                ws,
                "(()=>{const e=document.querySelector('[data-testid=invite-code]');"
                "return !!e && e.value.length < 120;})()",
                10,
                "回到预览",
                pump,
            ),
        )

        checker.check("点「取消邀请码」", click(ws, "#main [data-invite=CancelConfirm]"))
        checker.check(
            "出现作废确认",
            wait_js(
                ws,
                "!!document.querySelector('[data-testid=invite-cancel-confirm]')",
                10,
                "作废确认",
                pump,
            ),
        )
        checker.check("确认作废", click(ws, "#main [data-invite=Cancel]"))
        checker.check(
            "作废后页面显示已结束",
            wait_js(
                ws,
                "(()=>{const t=document.querySelector('#main');"
                "return !!t && (t.textContent.includes('邀请已结束')||t.textContent.includes('已作废'));})()",
                CREATE_SECONDS,
                "作废结果",
                pump,
            ),
        )
        leaked = ws.evaluate(
            "(()=>{const e=document.querySelector('[data-testid=invite-code]');"
            "return e?e.value:'';})()"
        )
        checker.check(
            "作废后页面不再持有完整码",
            not (isinstance(leaked, str) and leaked == full),
            str(leaked)[:40],
        )
        screenshot(ws, report_dir / "06-cancelled.png", report["shots"])

        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for c in checker.checks if c["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        return 0 if checker.all_passed else 1
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
