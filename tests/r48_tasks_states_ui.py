#!/usr/bin/env python3
"""r48 界面验收：部署任务卡的三种读取状态（T08）。

验的是「页面在三种读取结论下说什么」，不是部署本身：

1. 起真实宿主（真实 WebView2 + 真实数据根），CDP 驱动；
2. **partial**：往 `deployments/runs` 放一份坏 JSON → 页面必须出现「有 N 条
   任务记录读不出来」，而不是把这一块当成「没有任务」；
3. 同时造一条真记录（`deployment-start root@127.0.0.1:9`）→ 任务行照常出现，
   按钮文案来自记录的 `ActionLabel`（不是硬编码「继续」）；
4. **failed**：把 `runs` 目录换成一个同名文件 → 页面必须出现「任务记录暂时
   无法读取」+ 刷新按钮；
5. 恢复目录 → 错误卡消失，任务行回来；
6. 点「刷新任务记录」→ 页面不崩、任务行还在。

收尾：删坏文件、删冒烟记录、确保 `runs` 目录恢复成目录。

不碰任何真实服务器。
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import shutil
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
RUNS_BAK = DATA_ROOT / "deployments" / "runs.bak-r48"
DAMAGED = RUNS_DIR / "zz-damaged-r48.json"


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    # 前置清理：上次跑挂了可能留下文件形态的 runs 或 .bak。
    if RUNS_BAK.is_dir() and not RUNS_DIR.exists():
        RUNS_BAK.rename(RUNS_DIR)
    if RUNS_DIR.exists() and RUNS_DIR.is_file():
        RUNS_DIR.unlink()
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    if RUNS_BAK.exists():
        shutil.rmtree(RUNS_BAK, ignore_errors=True)

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
    runs_is_file = False
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
        text_now = lambda: ws.evaluate("document.body.innerText") or ""
        print(f"[probe] before={(text_now())[:120]!r}", flush=True)

        # ---- partial：一份坏 JSON ----
        DAMAGED.write_text('{"Kind":"SpiderVPN.DeploymentRun","RunId":"not-a-uuid"\n', encoding="utf-8")
        checker.check(
            "partial：页面说「读不出来」",
            wait_js(
                ws,
                "(()=>{const t=document.body.innerText||'';return t.includes('读不出来');})()",
                20,
                "partial 提示出现",
                pump,
            ),
            text_now()[:200],
        )
        partial_text = text_now()
        checker.check(
            "partial：说清了几条",
            bool(re.search(r"\d+\s*条", partial_text)),
            partial_text[:200],
        )
        checker.check(
            "partial：没有把这一块当成「没有任务」",
            "未完成的添加" in partial_text,
            partial_text[:200],
        )

        # ---- 同时造一条真记录：任务行必须照常出现 ----
        name = pipe_name()
        started = ask(
            name,
            {
                "cmd": "deployment-start",
                "spec": "root@127.0.0.1:9",
                "fingerprint": "SHA256:smoke",
                "password": "x",
                "label": "冒烟 · 任务卡状态",
            },
        )
        run_id = started.get("deployment", {}).get("RunId", "")
        checker.check("deployment-start 受理", bool(run_id), json.dumps(started, ensure_ascii=False)[:120])

        deadline = time.monotonic() + 90
        final_state = ""
        while time.monotonic() < deadline and run_id:
            run = ask(name, {"cmd": "deployment-get", "runId": run_id}).get("deployment", {}).get("Run", {})
            final_state = run.get("State", "")
            if final_state in ("NeedsAttention", "Complete", "Cancelled"):
                break
            time.sleep(1)
        checker.check("记录落到 NeedsAttention", final_state == "NeedsAttention", final_state)

        row_selector = f'[data-action=resume][data-id="{run_id}"]'
        checker.check(
            "partial 下任务行照常出现",
            wait_js(ws, f"!!document.querySelector('{row_selector}')", 20, "任务行出现", pump),
        )
        # 页面快照每秒推一次：管道已经读到 `NeedsAttention`，页面可能还停在 `Queued`
        # （那一帧的按钮是「查看」、标签里没有原因）。等它追上来再断言，否则测的是上一帧。
        checker.check(
            "页面追上记录状态（按钮变「重试本步骤」）",
            wait_js(
                ws,
                "(()=>{const b=document.querySelector('%s');"
                "return !!b&&b.textContent.includes('重试本步骤');})()" % row_selector,
                30,
                "任务行追上 NeedsAttention",
                pump,
            ),
            (ws.evaluate("document.body.innerText") or "")[:200],
        )
        row_text = ws.evaluate(
            "(()=>{const b=document.querySelector('%s');"
            "return b?b.closest('.task-row').innerText:'';})()" % row_selector
        ) or ""
        print(f"[probe] row={row_text!r}", flush=True)
        checker.check("任务行显示目标 host:port", "127.0.0.1:9" in row_text, row_text[:120])
        checker.check("任务行显示进度", bool(re.search(r"\b0/4\b", row_text)), row_text[:120])
        checker.check("任务行显示原因", "连不上服务器" in row_text, row_text[:160])
        # 按钮文案来自记录的 ActionLabel（NeedsAttention + RetryStep → 「重试本步骤」），
        # 不能是硬编码的「继续」。
        checker.check(
            "按钮文案来自记录的 ActionLabel",
            "重试本步骤" in row_text and "继续" not in row_text,
            row_text[:160],
        )
        checker.check("任务行显示相对时间", "前" in row_text or "刚刚" in row_text, row_text[:160])
        screenshot(ws, report_dir / "01-partial.png", report["shots"])

        # ---- failed：runs 变成同名文件 ----
        DAMAGED.unlink(missing_ok=True)
        if RUNS_BAK.exists():
            shutil.rmtree(RUNS_BAK, ignore_errors=True)
        RUNS_DIR.rename(RUNS_BAK)
        RUNS_DIR.write_text("not a directory\n", encoding="utf-8")
        runs_is_file = True
        checker.check(
            "failed：页面说「暂时无法读取」",
            wait_js(
                ws,
                "(()=>{const t=document.body.innerText||'';return t.includes('暂时无法读取');})()",
                25,
                "failed 错误卡出现",
                pump,
            ),
            text_now()[:240],
        )
        failed_text = text_now()
        checker.check(
            "failed：给了刷新入口",
            ws.evaluate("!!document.querySelector('[data-action=deploymentList]')"),
            failed_text[:200],
        )
        checker.check(
            "failed：没有渲染成空列表，也没有任务行",
            # 第一版这条是 `"尚未接入" not in t or "未完成的添加" in t`——右半边恒为真
            # （failed 分支一定会渲染这个标题），整条必然 PASS。改成同时要求：
            # 有标题、没有空态措辞、任务行一个都不剩。
            ("未完成的添加" in failed_text)
            and not any(
                phrase in failed_text
                for phrase in ("没有任务", "暂无任务", "任务记录为空", "没有任何未完成")
            )
            and ws.evaluate("document.querySelectorAll('[data-action=resume]').length") == 0,
            failed_text[:200],
        )
        # 刷新按钮**只在读不出来时存在**（`ok` + 有任务时这一块只有标题和任务行），
        # 所以必须在这里点：这时它真的在页面上。
        checker.check("failed：点「刷新任务记录」", click(ws, "[data-action=deploymentList]"))
        checker.check(
            "failed：刷新后仍是错误卡（读不出来就是读不出来）",
            wait_js(
                ws,
                "(()=>{const t=document.body.innerText||'';return t.includes('暂时无法读取');})()",
                15,
                "刷新后仍是 failed",
                pump,
            ),
            text_now()[:200],
        )
        screenshot(ws, report_dir / "02-failed.png", report["shots"])

        # ---- 恢复目录 ----
        RUNS_DIR.unlink()
        RUNS_BAK.rename(RUNS_DIR)
        runs_is_file = False
        checker.check(
            "恢复后错误卡消失",
            wait_js(
                ws,
                "(()=>{const t=document.body.innerText||'';return !t.includes('暂时无法读取');})()",
                25,
                "错误卡消失",
                pump,
            ),
            text_now()[:200],
        )
        checker.check(
            "恢复后任务行回来",
            wait_js(ws, f"!!document.querySelector('{row_selector}')", 20, "任务行回来", pump),
        )

        # ---- 刷新按钮已经在上一步（failed 态）点过：正常态本来就没有这颗按钮，
        # 这里只确认恢复后页面仍是可用的（任务行还在、不是一片空白）。
        checker.check(
            "恢复后页面可用（任务行还在）",
            wait_js(ws, f"!!document.querySelector('{row_selector}')", 15, "恢复后任务行仍可读", pump),
        )
        screenshot(ws, report_dir / "03-after-refresh.png", report["shots"])

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
        # 先把目录恢复成目录（否则后续所有批次都读不到任务）。
        if runs_is_file or (RUNS_DIR.exists() and RUNS_DIR.is_file()):
            RUNS_DIR.unlink(missing_ok=True)
        if RUNS_BAK.is_dir() and not RUNS_DIR.exists():
            RUNS_BAK.rename(RUNS_DIR)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        DAMAGED.unlink(missing_ok=True)
        if run_id and re.fullmatch(r"[0-9a-f-]{36}", run_id):
            target_file = RUNS_DIR / f"{run_id}.json"
            if target_file.is_file():
                target_file.unlink()
                print(f"[probe] 已删除冒烟记录 {target_file.name}", flush=True)
        print(f"[probe] runs is dir: {RUNS_DIR.is_dir()}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
