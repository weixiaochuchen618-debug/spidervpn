#!/usr/bin/env python3
"""r63 界面验收：部署任务暂停与继续（A2/A3 P1-1）。

r63 之前，部署只能在页面里看进度 / 取消：引擎与 `deployment-pause` 命令都在，
但页面上没有入口。r63 起：

- 只有**真的有一步在跑**（记录 Running 且引擎里活着）才给「暂停部署」；
- 暂停只在步骤边界落地：已经发出的写命令不会被打断，页面说
  「已请求暂停：当前步骤做完之后生效」；
- 记录进入 `Paused` 后，主按钮变成「继续部署」，继续会重新排队，从下一步接着做；
- 暂停记录上若还挂着没核对的写，主按钮仍是「核对原操作」，绝不复述写命令。

本脚本全程点真实页面（CDP + 宿主推送 + 隔离数据根 + 临时代理键），对真服务器
做一次完整部署：开工后点暂停 → 等记录 `Paused` → 核实六秒内不自动续跑 →
点「继续部署」→ 跑到 4/4。密码只从环境变量取。

用法：

  set TC_SSH_PASSWORD=...
  python tests/r63_deploy_pause_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r63-deploy-pause\\acceptance \\
      --work C:\\tc-rs-build\\r63\\root --host 203.0.113.25
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass
helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker
PAUSED_TEXT = "状态：已暂停"


def page_text(ws) -> str:
    return t11.body_text(ws)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--host", default="203.0.113.25")
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="TC_SSH_PASSWORD")
    args = parser.parse_args()

    password = os.environ.get(args.password_env, "")
    if not password:
        raise SystemExit(f"没有设置 {args.password_env}：拒绝在不知道密码的情况下启动")
    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    t11.no_running_host()
    if work.exists() and any((work / "data" / "deployments" / "runs").glob("*.json")):
        raise SystemExit(f"数据根里已经有部署记录，拒绝复用：{work}（换一个空目录）")

    spec = f"{args.user}@{args.host}"
    checker = Checker()
    report: dict = {
        "mode": "pause-resume",
        "exe": str(exe),
        "host": args.host,
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    ws = None
    try:
        process, _port, ws = t11.launch(exe, work, report_dir, "pause")
        pump = t11.Pump(process.pid)
        # 冷启动时首页先渲染、`Busy` 稍后才放行按钮：等它真的可点再进入，
        # 否则 `drive_to_start` 的第一下点击会被 `entryBusy()` 吞掉。
        if not t11.wait_js(
            ws,
            "document.readyState==='complete'"
            "&&!!document.querySelector('#main [data-action=add]:not([disabled])')",
            30,
            "首页可点",
            pump,
        ):
            raise RuntimeError("首页「自己搭服务器」没有变成可点")
        run_id = t11.drive_to_start(ws, pump, work, spec, password)
        report["runId"] = run_id
        name = t11.pipe_name()

        checker.check(
            "部署已经在跑：页面上出现「暂停部署」",
            t11.wait_js(
                ws,
                "!!document.querySelector('[data-wf=run-pause]')",
                120,
                "暂停按钮出现",
                pump,
            ),
            page_text(ws)[-400:],
        )
        helpers.screenshot(ws, report_dir / "01-running.png", report["shots"])

        before = t11.run_of(name, run_id)
        checker.check(
            "暂停前：记录是 Running 且引擎真的在跑",
            before.get("State") == "Running" and before.get("Running") is True,
            {"State": before.get("State"), "Running": before.get("Running")},
        )
        done_before = int(before.get("StepsDone") or 0)
        started_before = {
            step.get("Index"): step.get("StartedAtUtc")
            for step in before.get("Steps") or []
            if step.get("Status") == "Done"
        }
        report["beforePause"] = {
            "State": before.get("State"),
            "StepsDone": done_before,
            "Steps": before.get("Steps"),
            "PendingOperation": before.get("PendingOperation"),
        }

        checker.check(
            "点得动「暂停部署」",
            helpers.click(ws, "[data-wf=run-pause]"),
            page_text(ws)[-400:],
        )
        checker.check(
            "点暂停后页面说清「做完这步再停」或已暂停",
            t11.wait_js(
                ws,
                "(()=>{const t=document.body.innerText||'';"
                "return t.includes('已请求暂停：当前步骤做完之后生效')"
                "|| t.includes('状态：已暂停');})()",
                45,
                "暂停受理提示",
                pump,
            ),
            page_text(ws)[-500:],
        )
        helpers.screenshot(ws, report_dir / "02-pause-requested.png", report["shots"])

        run = t11.wait_state(name, run_id, "Paused", 900)
        checker.check(
            "当前步骤做完之后记录进入 Paused",
            run.get("State") == "Paused",
            {"State": run.get("State"), "StepsDone": run.get("StepsDone")},
        )
        checker.check(
            "暂停后 Running=false（没有在跑）",
            run.get("Running") is False,
            run.get("Running"),
        )
        checker.check(
            "暂停没有伪造完成（StepsDone<4）",
            int(run.get("StepsDone") or 0) < 4,
            run.get("StepsDone"),
        )
        pending = run.get("PendingOperation")
        checker.check(
            "暂停时没有未核对的写",
            not pending or pending.get("Outcome") != "Pending",
            pending,
        )
        checker.check(
            "页面追上记录：状态：已暂停 + 继续部署",
            t11.wait_js(
                ws,
                "(()=>{const t=document.body.innerText||'';"
                f"return t.includes('{PAUSED_TEXT}') && t.includes('继续部署');}})()",
                30,
                "页面显示已暂停",
                pump,
            ),
            page_text(ws)[-500:],
        )
        helpers.screenshot(ws, report_dir / "03-paused.png", report["shots"])

        revision_paused = run.get("Revision")
        time.sleep(6)
        still = t11.run_of(name, run_id)
        checker.check(
            "暂停后 6 秒内不会自动续跑",
            still.get("State") == "Paused"
            and still.get("Revision") == revision_paused
            and still.get("Running") is False,
            {
                "State": still.get("State"),
                "Revision": still.get("Revision"),
                "was": revision_paused,
            },
        )

        checker.check(
            "点得动「继续部署」",
            helpers.click(ws, "[data-wf=run-go]"),
            page_text(ws)[-400:],
        )
        run2 = t11.wait_state(name, run_id, "Complete", t11.DEPLOY_SECONDS)
        checker.check(
            "继续之后跑到 4/4",
            run2.get("State") == "Complete" and int(run2.get("StepsDone") or 0) == 4,
            {"State": run2.get("State"), "StepsDone": run2.get("StepsDone")},
        )
        started_after = {
            step.get("Index"): step.get("StartedAtUtc")
            for step in run2.get("Steps") or []
        }
        checker.check(
            "暂停前做完的步骤没有被重跑（开始时间没变）",
            all(
                started_after.get(index) == stamp
                for index, stamp in started_before.items()
            ),
            {
                "before": started_before,
                "after": {index: started_after.get(index) for index in started_before},
            },
        )
        checker.check(
            "页面显示 已完成 4/4",
            t11.wait_js(
                ws,
                "(document.body.innerText||'').includes('状态：已完成')"
                "&&(document.body.innerText||'').includes('4/4')",
                30,
                "页面追上完成",
                pump,
            ),
            page_text(ws)[-400:],
        )
        checker.check(
            "完成后不再给「暂停部署」",
            ws.evaluate("!document.querySelector('[data-wf=run-pause]')") is True,
            page_text(ws)[-400:],
        )
        helpers.screenshot(ws, report_dir / "04-complete.png", report["shots"])

        helpers.click(ws, "[data-wf=done]")
        helpers.click(ws, "[data-page=lines]")
        time.sleep(1.5)
        checker.check(
            "线路页出现两条自建线路",
            page_text(ws).count("自建 ·") >= 2,
            page_text(ws)[:300],
        )
        helpers.screenshot(ws, report_dir / "05-lines.png", report["shots"])
        report["run"] = run2
        report["afterPause"] = {
            "State": still.get("State"),
            "StepsDone": still.get("StepsDone"),
            "PendingOperation": still.get("PendingOperation"),
        }
    except Exception as error:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        checker.check(f"用例没有走完：{error}", False)
        code = 1
    finally:
        run_id = report.get("runId", "")
        if run_id and t11.UUID_RE.fullmatch(run_id):
            source = work / "data" / "deployments" / "runs" / f"{run_id}.json"
            if source.is_file():
                (report_dir / f"run-{run_id}.json").write_bytes(source.read_bytes())
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        if report.get("runId"):
            print(f"RUN_ID={report['runId']}", flush=True)
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
