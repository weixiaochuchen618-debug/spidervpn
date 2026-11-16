#!/usr/bin/env python3
"""r50 界面验收：退出守卫（T09）。

验的是「有部署在跑时，点 X 会不会把部署打断」：

1. 真实的部署在跑（一个只 accept、不发 banner 的本地 TCP 监听器把 Step0 卡在
   握手阶段约 15 秒——这是真实的上游超时，不是桩）；
2. 点 X（`WM_CLOSE` 打到主窗口，与鼠标点关闭等价）→ **窗口必须藏起来、进程必须
   还在**，而且部署要继续跑；
3. 藏起来之后，那条记录必须**真的往前走到结论**（`NeedsAttention` + Step0 `Failed`）。
   这一条同时证明两件事：关窗没把 pass 掐断，且它也不是被我们改判成「被打断」的；
4. 部署跑完之后**再关一次** → 进程正常退出（现场的 `close_to_tray=false`，
   空闲时的老规则是「断开并退出」）。这条证明闸门会松开，不是永久锁死。

## 为什么「窗口藏起来」这本身就证明了托盘在

现场配置 `close_to_tray=false`。`tray::close_decision(close_to_tray=false,
tray_available, deploying=true)` 的两条分支是互斥的：

- 托盘可用 → `HideToTray`（窗口消失、进程还在）；
- 托盘不可用 → `RefuseAndShowDialog`（**窗口留在屏幕上**、弹对话框）。

所以「窗口真的消失了而且进程没退」只可能来自第一条 ⇒ 托盘确实起来了。
这条推理写在这里，是因为托盘图标没法从 CDP 里点、也不该去翻 Explorer 的
通知区实现（Windows 10/11 两套）。

不碰任何真实服务器：目标是一个本地端口，且只做 TCP 握手。
"""
from __future__ import annotations

import argparse
import ctypes
import importlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
click = helpers.click
free_port = helpers.free_port
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

user32 = ctypes.windll.user32
WM_CLOSE = 0x0010

DATA_ROOT = Path(r"C:\SpiderVPN\data")
RUNS_DIR = DATA_ROOT / "deployments" / "runs"


def pipe_name() -> str:
    import glob

    for candidate in glob.glob(r"\\.\pipe\SpiderVPN.*"):
        with open(candidate, "r+b", buffering=0) as handle:
            handle.write(b'{"cmd":"ping"}\n')
            reply = b""
            while not reply.endswith(b"\n"):
                chunk = handle.read(4096)
                if not chunk:
                    break
                reply += chunk
        if b'"ok": true' in reply or b'"ok":true' in reply:
            return candidate
    raise RuntimeError("找不到能应答的命名管道")


def ask(name: str, command: dict) -> dict:
    with open(name, "r+b", buffering=0) as handle:
        handle.write((json.dumps(command, ensure_ascii=False) + "\n").encode("utf-8"))
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = handle.read(65536)
            if not chunk:
                break
            reply += chunk
    return json.loads(reply.decode("utf-8"))


def window_title(handle: int) -> str:
    length = user32.GetWindowTextLengthW(handle)
    buffer = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(handle, buffer, length + 1)
    return buffer.value


def main_window(pid: int) -> int:
    handles = helpers.windows_of(pid)
    for handle in handles:
        if "TradeChannel" in window_title(handle):
            return handle
    return handles[0] if handles else 0


def visible_windows(pid: int) -> list[int]:
    return helpers.windows_of(pid)


def silent_listener() -> tuple[socket.socket, int, list[socket.socket]]:
    """一个只握手、不说话的服务端。

    SSH 客户端连上之后要等版本 banner；对面永远不发，它就卡在那儿——
    `servercmd::resolve_identity` 的 `probe_host_key` 给了 15 秒超时，
    于是我们拿到一个**真实**的、约 15 秒的部署窗口。
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]
    held: list[socket.socket] = []

    def serve() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            held.append(conn)  # 不发任何字节

    threading.Thread(target=serve, daemon=True).start()
    return server, port, held


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    try:
        pipe_name()
    except Exception:  # noqa: BLE001
        pass
    else:
        raise SystemExit("已经有一个 SpiderVPN 在运行，请先关掉它再跑这条验收。")

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    before_files = sorted(item.name for item in RUNS_DIR.iterdir())

    server, listen_port, held = silent_listener()
    print(f"[probe] 静默 SSH 监听器 127.0.0.1:{listen_port}", flush=True)

    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
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
    run_id = ""
    ws = None
    exited_at_end = False
    try:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(process.pid)
        text_now = lambda: ws.evaluate("document.body.innerText") or ""

        checker.check(
            "真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                30,
                "页面初始化",
                pump,
            ),
        )
        checker.check("导航到线路页", click(ws, "[data-page=lines]"))

        # ---- 起一个真的会跑一阵的部署 ----
        name = pipe_name()
        started = ask(
            name,
            {
                "cmd": "deployment-start",
                "spec": f"root@127.0.0.1:{listen_port}",
                "fingerprint": "SHA256:smoke",
                "password": "x",
                "label": "冒烟 · 退出守卫",
            },
        )
        run_id = started.get("deployment", {}).get("RunId", "")
        checker.check(
            "deployment-start 受理",
            bool(run_id),
            json.dumps(started, ensure_ascii=False)[:160],
        )

        def record() -> dict:
            return (
                ask(name, {"cmd": "deployment-get", "runId": run_id})
                .get("deployment", {})
                .get("Run", {})
            )

        deadline = time.monotonic() + 10
        state = ""
        while time.monotonic() < deadline:
            state = record().get("State", "")
            if state == "Running":
                break
            time.sleep(0.2)
        checker.check("部署真的在跑（State=Running）", state == "Running", state)
        revision_before = record().get("Revision", 0)

        handle = main_window(process.pid)
        checker.check("找到主窗口", bool(handle) and bool(window_title(handle)), window_title(handle))
        screenshot(ws, report_dir / "01-before-close.png", report["shots"])

        # ---- 点 X ----
        checker.check(
            "发送 WM_CLOSE（等价于点关闭按钮）",
            bool(user32.PostMessageW(handle, WM_CLOSE, 0, 0)),
        )
        hidden = False
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if not user32.IsWindowVisible(handle):
                hidden = True
                break
            time.sleep(0.2)
        checker.check("窗口藏起来了（不是退出）", hidden, f"visible={bool(user32.IsWindowVisible(handle))}")
        checker.check(
            "进程还活着",
            process.poll() is None,
            f"exit={process.poll()}",
        )
        checker.check(
            "网页还活着（CDP 仍可求值）",
            ws.evaluate("document.readyState") == "complete",
        )
        # 托盘提示由宿主设置，页面看不到；这里验的是宿主推给页面的那句 toast——
        # 它只在「缩到托盘」这条分支里写，是这条分支的**独有**证据。
        # 用 textContent 而不是 innerText：toast 4.2 秒后会被隐藏，innerText 会变空。
        # 而且必须**等**：关窗那一帧先写 toast，快照要等下一拍（有部署在跑时 1 秒）
        # 才推给页面——r48 学到的同一条：断言页面前先等页面追上宿主。
        checker.check(
            "页面记着「已缩到托盘继续」",
            wait_js(
                ws,
                "(()=>{const t=document.getElementById('toast');"
                "return !!t&&(t.textContent||'').includes('已缩到托盘继续');})()",
                10,
                "toast 出现",
                pump,
            ),
            ws.evaluate("document.getElementById('toast')?.textContent || ''") or "",
        )

        # ---- 藏着的时候，部署必须继续跑到结论 ----
        deadline = time.monotonic() + 90
        final = {}
        while time.monotonic() < deadline:
            final = record()
            if final.get("State") in ("NeedsAttention", "Complete", "Cancelled"):
                break
            time.sleep(1)
        checker.check(
            "藏着期间部署跑到了结论（没有被关窗掐断）",
            final.get("State") == "NeedsAttention",
            str(final.get("State")),
        )
        checker.check(
            "Revision 往前走了",
            final.get("Revision", 0) > revision_before,
            f"{revision_before} → {final.get('Revision')}",
        )
        step0 = (final.get("Steps") or [{}])[0]
        checker.check(
            "Step0 是「失败」而不是「未核实」",
            step0.get("Status") == "Failed",
            json.dumps(step0, ensure_ascii=False)[:200],
        )
        reason = final.get("Reason") or {}
        checker.check(
            "原因是上游超时（不是「被打断」）",
            reason.get("Category") == "Failed",
            json.dumps(reason, ensure_ascii=False)[:200],
        )
        checker.check(
            "没有新增任务记录（同一条 RunId）",
            sorted(item.name for item in RUNS_DIR.iterdir())
            == sorted(before_files + [f"{run_id}.json"]),
            str(sorted(item.name for item in RUNS_DIR.iterdir())[:6]),
        )

        # ---- 没有部署在跑了，再关一次：闸门必须松开 ----
        checker.check(
            "再次发送 WM_CLOSE",
            bool(user32.PostMessageW(handle, WM_CLOSE, 0, 0)),
        )
        try:
            code = process.wait(timeout=30)
            exited_at_end = True
        except subprocess.TimeoutExpired:
            code = None
        checker.check(
            "空闲后关窗会正常退出（close_to_tray=false → 断开并退出）",
            exited_at_end,
            f"exit={code}",
        )

        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
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
        if not args.keep_open and not exited_at_end:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
            time.sleep(1)
        log.close()
        for conn in held:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        server.close()
        if run_id and len(run_id) == 36:
            target_file = RUNS_DIR / f"{run_id}.json"
            if target_file.is_file():
                target_file.unlink()
                print(f"[probe] 已删除冒烟记录 {target_file.name}", flush=True)
        print(f"[probe] runs is dir: {RUNS_DIR.is_dir()}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
