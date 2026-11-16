#!/usr/bin/env python3
"""r47 界面验收：部署任务详情页（T07）。

验的是「记录驱动的那一页」在**装好的 exe** 上的真实行为，不是部署本身：

1. 起真实宿主（真实 WebView2 + 真实数据根），CDP 驱动；
2. 管道发 `deployment-start root@127.0.0.1:9`（必然连接被拒），让记录落到
   `NeedsAttention`；
3. 在线路页点任务行的「继续」→ 详情页必须出现：状态词、四步清单、失败原因、
   唯一主按钮「重试这一步」；
4. 点「重试这一步」→ 引擎真的又被驱动了一次（记录的 `Revision` 增加），
   页面不崩、状态仍然是 NeedsAttention；
5. 点「取消这次部署」→ **只有确认条，磁盘记录不变**；再点「确认取消」才落
   `Cancelled`，页面转成只读；
6. 收尾按 RunId 精确删除这条冒烟记录。

不碰任何真实服务器。
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import subprocess
import sys
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


def run_of(name: str, run_id: str) -> dict:
    return ask(name, {"cmd": "deployment-get", "runId": run_id}).get("deployment", {}).get("Run", {})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

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
    body_text = ""
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
            "真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                20,
                "页面初始化",
                pump,
            ),
        )
        checker.check("导航到线路页", click(ws, "[data-page=lines]"))

        name = pipe_name()
        print(f"[probe] pipe={name}", flush=True)
        started = ask(
            name,
            {
                "cmd": "deployment-start",
                "spec": "root@127.0.0.1:9",
                "fingerprint": "SHA256:smoke",
                "password": "x",
                "label": "冒烟 · 部署详情",
            },
        )
        run_id = started.get("deployment", {}).get("RunId", "")
        checker.check("deployment-start 受理", bool(run_id), json.dumps(started, ensure_ascii=False)[:120])

        # 引擎真去连 127.0.0.1:9；被拒之后落 NeedsAttention。
        final_state = ""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and run_id:
            run = run_of(name, run_id)
            final_state = run.get("State", "")
            if final_state in ("NeedsAttention", "Complete", "Cancelled"):
                print(f"[probe] final={final_state} label={run.get('Label','')}", flush=True)
                break
            time.sleep(1)
        checker.check("记录落到 NeedsAttention", final_state == "NeedsAttention", final_state)
        revision_before = int(run_of(name, run_id).get("Revision") or 0)

        row_selector = f'[data-action=resume][data-id="{run_id}"]'
        checker.check(
            "线路页出现这条任务",
            wait_js(ws, f"!!document.querySelector('{row_selector}')", 20, "任务行出现", pump),
        )

        # ---- 详情页 ----
        checker.check("点「继续」", click(ws, row_selector))
        opened = wait_js(
            ws,
            "!!document.querySelector('[data-wf=run-go]')",
            15,
            "详情页打开",
            pump,
        )
        checker.check("详情页打开（有主按钮）", opened)
        body_text = ws.evaluate("document.body.innerText") or ""
        print(f"[probe] detail={body_text[:400]!r}", flush=True)

        checker.check("详情页显示状态词", "需要处理" in body_text, body_text[:120])
        steps = len(re.findall(r"[1-4]\. .+ · (已完成|失败|进行中|待开始|已跳过|未核实)", body_text))
        checker.check("详情页显示四步清单", steps == 4, f"匹配到 {steps} 行")
        checker.check("详情页显示失败原因", "连不上服务器" in body_text, body_text[:200])
        checker.check("详情页只有一个主动作", (body_text.count("重试这一步") >= 1) and ("补齐兼容连接" not in body_text))
        screenshot(ws, report_dir / "01-detail.png", report["shots"])

        # ---- 重试：引擎必须真的又被驱动一次 ----
        checker.check("点「重试这一步」", click(ws, "[data-wf=run-go]"))
        retried = False
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            current = run_of(name, run_id)
            if int(current.get("Revision") or 0) > revision_before:
                retried = True
                print(f"[probe] retried revision={current.get('Revision')} state={current.get('State')}", flush=True)
                break
            time.sleep(1)
        checker.check("重试真的驱动了引擎（Revision 增加）", retried)
        checker.check(
            "重试之后仍是「需要处理」（不会假完成）",
            run_of(name, run_id).get("State") == "NeedsAttention",
            run_of(name, run_id).get("State", ""),
        )

        # ---- 取消：第一下只亮确认条，磁盘不动 ----
        checker.check(
            "点「取消这次部署」",
            click(ws, "[data-wf=run-cancel]"),
        )
        confirm_shown = wait_js(
            ws,
            "!!document.querySelector('[data-wf=run-cancel-confirm]')",
            10,
            "确认条出现",
            pump,
        )
        checker.check("第一次点取消只亮确认条", confirm_shown)
        checker.check(
            "确认之前记录没有变 Cancelled",
            run_of(name, run_id).get("State") != "Cancelled",
            run_of(name, run_id).get("State", ""),
        )
        screenshot(ws, report_dir / "02-cancel-confirm.png", report["shots"])

        # ---- 不取消：确认条收回 ----
        checker.check("点「不取消」", click(ws, "[data-wf=run-cancel-back]"))
        checker.check(
            "确认条收回",
            wait_js(
                ws,
                "!document.querySelector('[data-wf=run-cancel-confirm]')",
                10,
                "确认条收回",
                pump,
            ),
        )

        # ---- 再来一次并确认 ----
        click(ws, "[data-wf=run-cancel]")
        wait_js(ws, "!!document.querySelector('[data-wf=run-cancel-confirm]')", 10, "确认条回来", pump)
        checker.check("点「确认取消」", click(ws, "[data-wf=run-cancel-confirm]"))
        cancelled = False
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if run_of(name, run_id).get("State") == "Cancelled":
                cancelled = True
                break
            time.sleep(1)
        checker.check("记录落 Cancelled", cancelled, run_of(name, run_id).get("State", ""))

        read_only = wait_js(
            ws,
            "(document.body.innerText||'').includes('只能查看')",
            20,
            "页面转只读",
            pump,
        )
        checker.check("页面转成只读", read_only, (ws.evaluate("document.body.innerText") or "")[:160])
        screenshot(ws, report_dir / "03-cancelled.png", report["shots"])

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
        if not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
            time.sleep(1)
        log.close()
        if run_id and re.fullmatch(r"[0-9a-f-]{36}", run_id):
            target_file = RUNS_DIR / f"{run_id}.json"
            if target_file.is_file():
                target_file.unlink()
                print(f"[probe] 已删除冒烟记录 {target_file.name}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
