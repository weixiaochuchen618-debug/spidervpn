#!/usr/bin/env python3
"""r98 界面验收：部署详情页的四步横排（对齐 旧版的`DeployFourSteps`）。

旧版把四步放在**一行** WrapPanel 里（`1 检查…  2 标准连接…  3 兼容连接…  4 登记…`），
本版原来是竖排四行。r98 改成同一行；状态仍必须有文字（颜色只做辅助）。

本脚本只验页面（隔离数据根，不需要真服务器）：

1. 预置一条「第二步失败」的部署记录；
2. 线路页出现任务行 → 打开详情；
3. 详情页的四步在**同一个 `.wf-row`** 里，四格都是文字，顺序与状态词正确；
4. 不再出现旧版竖排的「1. 」写法。

用法：

  python tests/r98_deploy_steps_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r98-deploy-steps \\
      --work C:\\tc-rs-build\\r98\\root
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")
r87 = importlib.import_module("r87_history_ui")

Checker = helpers.Checker

RUN_ID = "8b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
STEP_NAMES = [
    "检查服务器环境与身份",
    "准备标准连接",
    "准备兼容连接",
    "接入本机并登记线路",
]


def stamp(minutes_ago: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def seed(work: Path) -> None:
    data = work / "data"
    runs = data / "deployments" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (data / "config.json").write_text(
        json.dumps(
            {
                "schema": 2,
                "selected": "L1",
                "lines": [{"id": "L1", "name": "线路甲", "proxy_endpoint": "127.0.0.1:17901"}],
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    steps = []
    for index, name in enumerate(STEP_NAMES):
        if index == 0:
            status, started, finished = "Done", stamp(31), stamp(30)
        elif index == 1:
            status, started, finished = "Failed", stamp(29), stamp(28)
        else:
            status, started, finished = "Pending", None, None
        steps.append(
            {
                "Index": index,
                "Name": name,
                "Status": status,
                "StartedAtUtc": started,
                "FinishedAtUtc": finished,
                "Evidence": {} if status == "Done" else {},
                "Error": "ListenFailed" if status == "Failed" else None,
            }
        )
    run = {
        "SchemaVersion": 1,
        "Kind": "SpiderVPN.DeploymentRun",
        "RunId": RUN_ID,
        "AttemptNo": 1,
        "Label": "自建 · 203.0.113.10",
        "Name": "自建 · 203.0.113.10",
        "Target": {"Host": "203.0.113.10", "Port": 22, "User": "root", "ServerRecordId": None},
        "Identity": {"Fingerprint": "SHA256:AAAA", "AutoTrusted": False},
        "Plan": {"Interface": "tc1a2b3c4d", "UdpPort": 51820, "Subnet": "10.66.0.0/24", "Mtu": 1420},
        "State": "NeedsAttention",
        "Step": 1,
        "StepsDone": 1,
        "Reason": {"Category": "Failed", "Code": "ListenFailed", "Text": "端口被占用"},
        "NextAction": "RetryStep",
        "Steps": steps,
        "PendingOperation": None,
        "Attempts": [],
        "Executor": None,
        "CreatedAtUtc": stamp(32),
        "StartedAtUtc": stamp(31),
        "UpdatedAtUtc": stamp(28),
        "FinishedAtUtc": None,
        "Revision": 4,
    }
    (runs / f"{RUN_ID}.json").write_text(
        json.dumps(run, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    parser.add_argument("--allow-running", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    if args.allow_running:
        print("[warn] --allow-running：不检查已有实例（独立数据根，互不干扰）", flush=True)
    else:
        t11.no_running_host()

    checker = Checker()
    report = {"mode": "deploy-steps", "exe": str(exe), "work": str(work), "checks": []}
    code = 0
    process = None
    ws = None
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "deploy-steps")
        pump = t11.Pump(process.pid)

        row = f'[data-id="{RUN_ID}"]'
        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ),
            r87.body_text(ws)[-200:],
        )
        checker.check("进线路页", r87.click_when_enabled(ws, pump, "[data-page=lines]") == "ok", "")
        checker.check(
            "任务行出现",
            helpers.wait_js(ws, f"!!document.querySelector('{row}')", 25, "任务行", pump),
            r87.body_text(ws)[-500:],
        )
        checker.check(
            "打开部署详情",
            r87.click_when_enabled(ws, pump, row) == "ok"
            and helpers.wait_js(
                ws,
                "(()=>{const t=document.querySelector('#main').innerText||'';"
                "return t.includes('四')||t.includes('部署');})()",
                20,
                "详情页",
                pump,
            ),
            r87.body_text(ws)[-400:],
        )

        steps_row_js = (
            "(()=>{const rows=[...document.querySelectorAll('#main .wf-row')];"
            "return rows.some(row=>{const cells=[...row.children].filter(e=>e.classList.contains('wf-text'));"
            "const t=cells.map(e=>e.textContent);"
            "return t.length===4"
            "&&t[0].includes('1 检查服务器环境与身份')&&t[0].includes('已完成')"
            "&&t[1].includes('2 准备标准连接')&&t[1].includes('失败')"
            "&&t[2].includes('3 准备兼容连接')&&t[2].includes('待开始')"
            "&&t[3].includes('4 接入本机并登记线路');});})()"
        )
        checker.check(
            "四步在同一行且状态词齐全",
            helpers.wait_js(ws, steps_row_js, 20, "四步横排", pump),
            r87.body_text(ws)[-800:],
        )
        checker.check(
            "不再出现竖排的「1. 」写法",
            "1. 检查服务器环境与身份" not in r87.body_text(ws),
            r87.body_text(ws)[-600:],
        )
        checker.check(
            "失败那格带状态色（bad）",
            bool(
                ws.evaluate(
                    "(()=>{const rows=[...document.querySelectorAll('#main .wf-row')];"
                    "return rows.some(row=>[...row.children].some(e=>"
                    "e.classList.contains('wf-text')&&e.classList.contains('bad-text')"
                    "&&e.textContent.includes('准备标准连接')));})()"
                )
            ),
            r87.body_text(ws)[-500:],
        )
        helpers.screenshot(ws, report_dir / "01-deploy-steps.png", report.get("shots", []))
    except Exception as error:  # noqa: BLE001
        code = 1
        report["error"] = f"{type(error).__name__}: {error}"
        print(f"脚本异常：{report['error']}", flush=True)
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    process.kill()
                except Exception:  # noqa: BLE001
                    pass
        print(
            f"残留进程：{'有' if process is not None and process.poll() is None else '无'}",
            flush=True,
        )
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
