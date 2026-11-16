#!/usr/bin/env python3
"""r56 界面验收：D 协议层门控——长度上限、Sequence 单调、页面重载后恢复。

改动前：`uiweb::route` 解析完 JSON 直接分发，**不校验**任何东西——同一条消息
重放一次就再执行一次，页面重载后序号错乱也没人管。旧版的
`InvokeTCWebMessage`（`ui/WebShell.ps1:927-945`）有这套闸。

本脚本验的是宿主真的挡住了（判据是**落盘的操作记录条数**，不是读源码）：

1. 发一条 connect（`Sequence 1`）→ 操作记录出现 1 条「连接」；
2. 原样重放同一条（还是 `Sequence 1`）→ 3 秒内记录仍是 1 条（重放不执行）；
3. 发一条 `Sequence 1000` 的无害消息把水位线推高 → 页面**真的重载**（CDP `Page.reload`）
   → 重载后发 `Sequence 2` 仍能生效（记录变 2 条）。
   这一条同时证明两件事：`ready` 把入站序号归零了；不归零的话 `2 <= 1000` 会被挡死。
4. 发一条 5 KiB 的消息 → 不执行（记录仍是 2 条）。
5. 收尾：用户配置 md5 不变、无残留进程。

## 为什么判据用「连接记录条数」

连接在隔离根里必然失败（没有引擎），但**每次执行都会写一条 `operations.jsonl`**。
条数 = 执行次数，比读快照 `Busy` 可靠：连接 1 秒内就结束，快照 2 秒一帧，轮询必然漏。

## 用法

  python tests/r56_protocol_gate_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r56-protocol-gate

  # 反向对照（r55 装机版：没有门控，重放会真的再执行一次）
  python tests/r56_protocol_gate_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r56-protocol-gate-negative --mode old
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
free_port = helpers.free_port
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

HOOK = r54.HOOK
RUNTIME = r54.RUNTIME
USER_CONFIG = r54.USER_CONFIG
ask = r54.ask
md5_of = r54.md5_of
pipe_name = r54.pipe_name
prepare_root = r54.prepare_root
processes_of = r54.processes_of
responsive_pipe = r54.responsive_pipe
snapshot = r54.snapshot
wait_snapshot = r54.wait_snapshot


def post_raw(ws: WebSocket, payload: dict) -> None:
    """绕过页面自己的 `post()`，原样发一条 JSON。

    页面那条会给每条消息自增 `Sequence`，而本脚本要验的正是**序号本身**。
    """
    body = json.dumps(payload, ensure_ascii=False)
    ws.evaluate(
        "(()=>{window.chrome.webview.postMessage(" + json.dumps(body, ensure_ascii=False) + ");return true;})()"
    )


def connect_count(log_path: Path) -> int:
    if not log_path.is_file():
        return 0
    total = 0
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("action") == "连接":
            total += 1
    return total


def wait_count(log_path: Path, target: int, seconds: float) -> int:
    deadline = time.time() + seconds
    last = connect_count(log_path)
    while time.time() < deadline:
        last = connect_count(log_path)
        if last >= target:
            return last
        time.sleep(0.2)
    return last


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--mode", choices=["new", "old"], default="new")
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    exe = Path(args.exe).resolve()
    root = report_dir / "root"

    live = responsive_pipe()
    if live:
        raise SystemExit(f"已经有一个 SpiderVPN 在跑（{live}），请先关掉它再跑这条验收。")
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    user_config_md5 = md5_of(USER_CONFIG)
    root_info = prepare_root(root)
    # 隔离根是脚本自己的：上一轮的操作记录必须清掉，否则「重放不执行」会被
    # 上一次的记录条数假绿。
    ops_log = root / "data" / "logs" / "operations.jsonl"
    if ops_log.is_file():
        ops_log.unlink()

    checker = Checker()
    report: dict = {
        "mode": args.mode,
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "dataRoot": root_info,
        "shots": [],
        "checks": [],
        "notes": [],
    }

    port = free_port()
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(root)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log_path = report_dir / "host.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] mode={args.mode} host pid={process.pid} cdp={port} root={root}", flush=True)

    ws: WebSocket | None = None
    try:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(process.pid)

        checker.check(
            "0 真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                30,
                "页面初始化",
                pump,
            ),
        )
        checker.check("0 已挂钩宿主推送入口", ws.evaluate(HOOK) in ("hooked", "already"))
        checker.check("0 拿到了第一份快照", wait_js(ws, "!!window.__tcProbe", 25, "首份快照", pump))
        name = pipe_name()

        lines = ask(name, {"cmd": "lines"})
        first = (lines.get("lines") or [{}])[0]
        line_id = str(first.get("id") or "")
        checker.check("0 隔离根里有一条线路可用", bool(line_id), repr(lines.get("lines"))[:200])
        checker.check("0 基线：没有连接记录", connect_count(ops_log) == 0, str(connect_count(ops_log)))
        screenshot(ws, report_dir / "01-baseline.png", report["shots"])

        # ---------- 场景 1：第一次执行 ----------
        # 序号从 100 起：页面启动时自己已经发过 `theme` / `ready`（Sequence 1、2…），
        # 水位线不是 0。用 1 会被自己的门控挡掉——那是脚本写错，不是宿主出错。
        post_raw(ws, {"Type": "connect", "Id": line_id, "Sequence": 100})
        first_count = wait_count(ops_log, 1, 30)
        checker.check("1 第一条 connect 真的执行了", first_count == 1, f"count={first_count}")
        # 等它落定（隔离根没有引擎，必然失败）再重放：连接还在跑的时候，
        # 第二次会被**长命令去重**挡掉——那样验的就不是 `Sequence` 门控了，
        # 反向对照也会假绿（旧版同样 PASS）。
        settled = wait_snapshot(ws, lambda s: not s.get("Busy"), 90, "第一次连接落定", pump)
        checker.check("1 第一次连接落定（失败也算）", settled, repr(snapshot(ws).get("Busy")))

        # ---------- 场景 2：原样重放 ----------
        post_raw(ws, {"Type": "connect", "Id": line_id, "Sequence": 100})
        time.sleep(3.5)
        after_replay = connect_count(ops_log)
        checker.check(
            "2 同一条消息重放不执行第二次",
            after_replay == first_count,
            f"{first_count} -> {after_replay}",
        )
        screenshot(ws, report_dir / "02-after-replay.png", report["shots"])

        # ---------- 场景 3：页面真的重载 ----------
        # 先把水位线推到 1000：不归零的话，重载后页面自己的 `theme`（Sequence 1）
        # 与脚本发的 Sequence 2 都会被 `2 <= 1000` 挡死。
        post_raw(ws, {"Type": "theme", "Value": "dark", "Sequence": 1000})
        time.sleep(0.5)
        ws.call("Page.reload")
        reloaded = wait_js(
            ws,
            "document.readyState==='complete'&&!!document.querySelector('#main')",
            30,
            "重载后页面就绪",
            pump,
        )
        checker.check("3 页面真的重载了", reloaded)
        # 重载会清掉挂钩：重新挂，等宿主推第一帧。
        checker.check("3 重载后重新挂钩", ws.evaluate(HOOK) in ("hooked", "already"))
        checker.check(
            "3 重载后拿到快照（页面没死）",
            wait_js(ws, "!!window.__tcProbe", 25, "重载后首份快照", pump),
        )
        # 发 10 而不是 2：页面重载后自己会发 `theme`(1) 与 `ready`(2)，
        # 水位线已经到 2；10 仍远小于重载前的 1000，判据不变。
        post_raw(ws, {"Type": "connect", "Id": line_id, "Sequence": 10})
        after_reload = wait_count(ops_log, first_count + 1, 30)
        checker.check(
            "3 重载后小序号仍能生效（ready 把水位线归零）",
            after_reload == first_count + 1,
            f"期望 {first_count + 1}，实得 {after_reload}",
        )
        screenshot(ws, report_dir / "03-after-reload.png", report["shots"])

        # ---------- 场景 4：超大消息 ----------
        before_big = connect_count(ops_log)
        post_raw(
            ws,
            {"Type": "connect", "Id": line_id, "Sequence": 11, "Value": "x" * 5000},
        )
        time.sleep(3.5)
        after_big = connect_count(ops_log)
        checker.check(
            "4 超过 4 KiB 的非 form 消息不执行",
            after_big == before_big,
            f"{before_big} -> {after_big}",
        )
        screenshot(ws, report_dir / "04-after-oversized.png", report["shots"])

        # ---------- 收尾 ----------
        checker.check("8 用户配置没被改过（config.json md5 一致）", md5_of(USER_CONFIG) == user_config_md5)
        checker.check("8 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check("8 收尾时没有残留的 spidervpn 进程", len(processes_of("spidervpn.exe")) <= 1)

    finally:
        try:
            if ws is not None:
                ws.close()
        except Exception:  # noqa: BLE001
            pass
        if not args.keep_open:
            try:
                process.terminate()
                process.wait(timeout=15)
            except Exception:  # noqa: BLE001
                try:
                    process.kill()
                except Exception:  # noqa: BLE001
                    pass
        log.close()

    report["checks"] = checker.checks
    (report_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    passed = sum(1 for item in checker.checks if item["ok"])
    total = len(checker.checks)
    print(f"\n合计 {passed}/{total}；证据 {report_dir}")
    return 0 if checker.all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
