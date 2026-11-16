#!/usr/bin/env python3
"""r71 界面验收：部署结果提醒（A2/A3 P1-3）。

r71 之前，一条部署在后台跑完之后，如果用户不在电脑前，结论只会留在任务列表里
——而任务列表只列「未完成」的，完成态最多在底部队列里待 24 小时。结果就是
「关掉窗口 → 跑完了 → 回来什么都没看到」。

r71 起：结果（Complete / NeedsAttention / Paused / Cancelled）在磁盘上留一条
未读提醒；线路页顶部出现「部署结果」块；打开那条任务即标记已读，重启也不会复活。

本脚本验页面（CDP + 隔离数据根，不需要真服务器）：

1. 预置一条 `Complete` 记录 + 一条未读提醒 → 线路页出现「部署结果」块（名字/状态/原因/查看）；
2. 点「查看」→ 进的是那条任务的详情页（`进度：4/4 步`）；
3. 回线路页 → 「部署结果」块消失，磁盘上的 `ReadAtUtc` 已写入；
4. 杀掉宿主、同根重启 → 块仍然不出现（已读状态活过重启）；
5. 收尾无残留进程。

用法：

  python tests/r71_reminder_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r71-reminder\\acceptance \\
      --work C:\\tc-rs-build\\r71\\root
"""
from __future__ import annotations

import argparse
import importlib
import json
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

RUN_ID = "a7100000-1111-4111-8111-111111111111"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "deployment-runs" / "complete.json"

BLOCK = "部署结果"
NAME = "自建 · 203.0.113.10"
STATE_WORD = "已完成"
TEXT = "部署完成"


def body_text(ws) -> str:
    return t11.body_text(ws)


def deploy_dir(work: Path) -> Path:
    return work / "data" / "deployments"


def write_fixtures(work: Path) -> None:
    record = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record["RunId"] = RUN_ID
    record["Label"] = NAME
    record["UpdatedAtUtc"] = "2026-11-12T11:00:00Z"
    runs = deploy_dir(work) / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / f"{RUN_ID}.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    reminders = {
        "Schema": 1,
        "Kind": "TradeChannel.DeployReminders",
        "Reminders": [
            {
                "Id": "r-1",
                "RunId": RUN_ID,
                "Name": NAME,
                "State": "Complete",
                "Step": 4,
                "Code": "",
                "Text": TEXT,
                "CreatedAtUtc": "2026-11-12T11:00:00Z",
                "ReadAtUtc": None,
            }
        ],
    }
    (deploy_dir(work) / "reminders.json").write_text(
        json.dumps(reminders, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def reminder_read_at(work: Path) -> str:
    try:
        data = json.loads((deploy_dir(work) / "reminders.json").read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return ""
    for item in data.get("Reminders") or []:
        if item.get("RunId") == RUN_ID:
            return str(item.get("ReadAtUtc") or "")
    return ""


def goto_lines(ws, pump, seconds: float = 25.0) -> bool:
    if not helpers.click(ws, "nav [data-page=lines]"):
        return False
    return helpers.wait_js(
        ws,
        "!!document.querySelector('#main .task-row')"
        "||(document.body.innerText||'').includes('未完成的添加')"
        "||!!document.querySelector('#main [data-action=pairStart]')",
        seconds,
        "线路页",
        pump,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    t11.no_running_host()
    if not FIXTURE.is_file():
        raise SystemExit(f"缺夹具：{FIXTURE}")

    checker = Checker()
    report: dict = {
        "mode": "deploy-reminder",
        "exe": str(exe),
        "runId": RUN_ID,
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    process2 = None
    ws = None
    ws2 = None
    try:
        write_fixtures(work)
        checker.check("预置：一条完成记录 + 一条未读提醒", True, str(deploy_dir(work)))

        process, _port, ws = t11.launch(exe, work, report_dir, "reminder")
        pump = t11.Pump(process.pid)
        checker.check(
            "首页可点",
            helpers.wait_js(
                ws,
                "document.readyState==='complete'"
                "&&!!document.querySelector('#main [data-action=add]:not([disabled])')",
                40,
                "首页",
                pump,
            ),
            body_text(ws)[-300:],
        )
        checker.check("回到线路页", goto_lines(ws, pump), body_text(ws)[:300])
        checker.check(
            "线路页出现「部署结果」块",
            helpers.wait_js(
                ws,
                f"(document.body.innerText||'').includes({json.dumps(BLOCK, ensure_ascii=False)})",
                25,
                "部署结果块",
                pump,
            ),
            body_text(ws)[:500],
        )
        text = body_text(ws)
        report["body"] = text[-1200:]
        checker.check("提醒里带任务名", NAME in text, text[-400:])
        checker.check("提醒里带状态词", STATE_WORD in text, text[-400:])
        checker.check("提醒里带原因/结论", TEXT in text, text[-400:])
        checker.check(
            "提醒有「查看」入口",
            helpers.wait_js(
                ws,
                f"!!document.querySelector('#main [data-action=resume][data-id=\"{RUN_ID}\"]')",
                15,
                "查看按钮",
                pump,
            ),
            body_text(ws)[:400],
        )
        helpers.screenshot(ws, report_dir / "01-reminder.png", report["shots"])

        checker.check(
            "点「查看」打开那条任务",
            helpers.click(ws, f'#main [data-action=resume][data-id="{RUN_ID}"]'),
            body_text(ws)[:300],
        )
        checker.check(
            "进的是详情页（进度 4/4）",
            helpers.wait_js(
                ws,
                "(document.body.innerText||'').includes('进度：4/4')",
                20,
                "详情页",
                pump,
            ),
            body_text(ws)[-400:],
        )
        read_at = ""
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            read_at = reminder_read_at(work)
            if read_at:
                break
            time.sleep(0.2)
        checker.check(
            "打开任务后磁盘上的提醒被标记已读",
            bool(read_at),
            read_at or "ReadAtUtc 还是空的",
        )
        # 详情页是一个打开着的表单：导航点不动（既有行为），先点「完成」关掉它。
        checker.check(
            "退出详情页（完成）",
            helpers.click(ws, "#main [data-wf=done]"),
            body_text(ws)[:300],
        )
        checker.check("回到线路页（已读后）", goto_lines(ws, pump), body_text(ws)[:300])
        checker.check(
            "「部署结果」块消失",
            helpers.wait_js(
                ws,
                f"!(document.body.innerText||'').includes({json.dumps(BLOCK, ensure_ascii=False)})",
                20,
                "块消失",
                pump,
            ),
            body_text(ws)[:500],
        )
        helpers.screenshot(ws, report_dir / "02-read.png", report["shots"])

        # ---- 重启：已读状态必须活过重启 ----
        process.kill()
        process.wait(timeout=15)
        process2, _port2, ws2 = t11.launch(exe, work, report_dir, "reminder-restart")
        pump2 = t11.Pump(process2.pid)
        checker.check(
            "重启后首页可点",
            helpers.wait_js(
                ws2,
                "document.readyState==='complete'"
                "&&!!document.querySelector('#main [data-action=add]:not([disabled])')",
                40,
                "首页",
                pump2,
            ),
            body_text(ws2)[-300:],
        )
        checker.check("重启后回到线路页", goto_lines(ws2, pump2), body_text(ws2)[:300])
        checker.check(
            "重启后「部署结果」块仍然不出现",
            helpers.wait_js(
                ws2,
                f"document.readyState==='complete'&&!!document.querySelector('#main')"
                f"&&!(document.body.innerText||'').includes({json.dumps(BLOCK, ensure_ascii=False)})",
                20,
                "块不出现",
                pump2,
            ),
            body_text(ws2)[:500],
        )
        helpers.screenshot(ws2, report_dir / "03-after-restart.png", report["shots"])
    except Exception as error:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        checker.check(f"用例没有走完：{error}", False)
        code = 1
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        for opened in (ws, ws2):
            if opened is not None:
                try:
                    opened.close()
                except Exception:  # noqa: BLE001
                    pass
        if not args.keep_open:
            for started in (process, process2):
                if started is not None and started.poll() is None:
                    started.terminate()
                    try:
                        started.wait(timeout=10)
                    except Exception:  # noqa: BLE001
                        started.kill()
        leftovers = [
            item.pid
            for item in (process, process2)
            if item is not None and item.poll() is None
        ]
        print(f"残留进程：{leftovers or '无'}", flush=True)
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
