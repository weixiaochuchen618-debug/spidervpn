#!/usr/bin/env python3
"""r46 界面验收：部署任务真的出现在线路页「未完成的添加」里。

验的是 T06 的接线（快照投影 → 页面渲染），不是部署本身：

1. 起真实宿主（装好的 exe + 真实 WebView2 + 真实数据根），走 CDP 驱动；
2. 通过命名管道发 `deployment-start` 指向 `127.0.0.1:9`（必然连接被拒），
   让记录真的落到 `NeedsAttention`；
3. 回到页面看：任务行出现、标题是 `0/4 · 检查服务器环境与身份：连不上服务器…`、
   底部任务条出现同一条记录；
4. 收尾删掉这条冒烟记录（按 RunId 精确删除，不碰别的记录）。

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
import urllib.request
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
    """数据根派生的管道名。枚举一遍并选真的能应答 ping 的那个。"""
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
        # 起始状态：任务行的数量和「未完成的添加」标题是否出现，都要先记下来。
        before = ws.evaluate(
            "(()=>({rows:document.querySelectorAll('[data-action=resume]').length,"
            "head:!!Array.from(document.querySelectorAll('h2')).find(h=>h.textContent.includes('未完成的添加'))}))()"
        )
        print(f"[probe] before={before}", flush=True)

        name = pipe_name()
        print(f"[probe] pipe={name}", flush=True)
        started = ask(
            name,
            {
                "cmd": "deployment-start",
                "spec": "root@127.0.0.1:9",
                "fingerprint": "SHA256:smoke",
                "password": "x",
                "label": "冒烟 · 任务卡",
            },
        )
        run_id = started.get("deployment", {}).get("RunId", "")
        checker.check("deployment-start 受理", bool(run_id), json.dumps(started, ensure_ascii=False)[:120])

        # 引擎会真的去连 127.0.0.1:9；被拒之后落 NeedsAttention。
        final_state = ""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and run_id:
            run = ask(name, {"cmd": "deployment-get", "runId": run_id}).get("deployment", {}).get("Run", {})
            final_state = run.get("State", "")
            if final_state in ("NeedsAttention", "Complete", "Cancelled"):
                print(f"[probe] final={final_state} label={run.get('Label','')}", flush=True)
                break
            time.sleep(1)
        checker.check("记录落到 NeedsAttention", final_state == "NeedsAttention", final_state)

        # 页面必须自己长出这一行（不是靠我们手动刷新：宿主每秒推快照）。
        selector = f"[data-action=resume][data-id=\"{run_id}\"]"
        appeared = wait_js(
            ws,
            f"!!document.querySelector('{selector}')",
            20,
            "任务行出现",
            pump,
        )
        checker.check("线路页出现这条任务", appeared, selector)
        if appeared:
            row = ws.evaluate(
                "(()=>{const b=document.querySelector('%s');"
                "return b?b.closest('.task-row').innerText:'';})()" % selector
            )
            print(f"[probe] row={row!r}", flush=True)
            checker.check("任务行显示进度", bool(re.search(r"\b0/4\b", row or "")), str(row)[:80])
            checker.check(
                "任务行显示原因",
                "连不上服务器" in (row or ""),
                str(row)[:120],
            )
            checker.check("任务行有名字", "冒烟 · 任务卡" in (row or ""), str(row)[:80])

        checker.check(
            "底部任务条也指向这条记录",
            wait_js(
                ws,
                f"!!document.querySelector('#mini-status [data-action=resumeDeployment][data-id=\"{run_id}\"]')",
                15,
                "底部任务条",
                pump,
            ),
        )
        checker.check(
            "页面没有把草稿之外的东西当成任务（行数 +1）",
            ws.evaluate("document.querySelectorAll('[data-action=resume]').length")
            == (before.get("rows", 0) if isinstance(before, dict) else 0) + 1,
            str(ws.evaluate("document.querySelectorAll('[data-action=resume]').length")),
        )
        screenshot(ws, report_dir / "01-task-row.png", report["shots"])

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
        # 冒烟记录只删这一条（按 RunId 精确删除），不碰别的记录。
        if run_id and re.fullmatch(r"[0-9a-f-]{36}", run_id):
            target_file = RUNS_DIR / f"{run_id}.json"
            if target_file.is_file():
                target_file.unlink()
                print(f"[probe] 已删除冒烟记录 {target_file.name}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
