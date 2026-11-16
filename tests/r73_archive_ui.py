#!/usr/bin/env python3
"""r73 界面验收：归档与恢复（A2/A3 P2-2）。

任务列表会越用越长，但「删记录」是不可逆的。归档是第三种状态：从列表里消失、
**文件一直在**、随时可恢复。

本脚本验页面（CDP + 隔离数据根，不需要真服务器）：

1. 预置一条 24 小时内的 `Complete` 记录 → 底部队列里看得到它；
2. 点进去 → 详情页有「归档」；点它 → 页面提示「已归档」；
3. 回线路页：底部队列**没有**它了，但「已归档」一栏里有它（名字 + 已归档时间）；
4. 从「已归档」点「查看」→ 详情页给「恢复这条记录」；点它 → 提示「已恢复」；
5. 回线路页：它回到底部队列，「已归档」一栏消失；
6. **磁盘上的记录文件从头到尾都在**（归档不是删除）。

用法：

  python tests/r73_archive_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r73-archive\\acceptance \\
      --work C:\\tc-rs-build\\r73\\root
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
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

RUN_ID = "a7300000-1111-4111-8111-111111111111"
NAME = "自建 · 203.0.113.10"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "deployment-runs" / "complete.json"

ARCHIVE_BLOCK = "已归档"
ARCHIVE_BUTTON = "归档"
RESTORE_BUTTON = "恢复这条记录"


def body_text(ws) -> str:
    return t11.body_text(ws)


def deploy_dir(work: Path) -> Path:
    return work / "data" / "deployments"


def write_record(work: Path) -> Path:
    record = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record["RunId"] = RUN_ID
    record["Label"] = NAME
    # 24 小时内：底部队列只列最近 24 小时的终态。
    record["UpdatedAtUtc"] = "2026-11-12T12:00:00Z"
    record["FinishedAtUtc"] = "2026-11-12T12:00:00Z"
    runs = deploy_dir(work) / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    target = runs / f"{RUN_ID}.json"
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def archived_at(work: Path) -> str:
    try:
        data = json.loads(
            (deploy_dir(work) / "runs" / f"{RUN_ID}.json").read_text(encoding="utf-8")
        )
    except Exception:  # noqa: BLE001
        return ""
    return str(data.get("ArchivedAtUtc") or "")


def goto_lines(ws, pump, seconds: float = 25.0) -> bool:
    if not helpers.click(ws, "nav [data-page=lines]"):
        return False
    return helpers.wait_js(
        ws,
        "!!document.querySelector('#main .task-row')"
        "||(document.body.innerText||'').includes('未完成的添加')"
        "||(document.body.innerText||'').includes('还没有线路')",
        seconds,
        "线路页",
        pump,
    )


def queue_has(ws, run_id: str) -> bool:
    return bool(
        ws.evaluate(
            "(()=>!!document.querySelector("
            f"'#mini-status [data-action=resumeDeployment][data-id=\"{run_id}\"]'))()"
        )
    )


def leave_detail(ws) -> bool:
    return helpers.click(ws, "#main [data-wf=done]")


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
        "mode": "deploy-archive",
        "exe": str(exe),
        "runId": RUN_ID,
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    ws = None
    try:
        record_path = write_record(work)
        checker.check("预置：一条 24 小时内的完成记录", record_path.is_file(), str(record_path))

        process, _port, ws = t11.launch(exe, work, report_dir, "archive")
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
            "底部队列里看得到这条完成记录",
            helpers.wait_js(
                ws,
                "(()=>!!document.querySelector("
                f"'#mini-status [data-action=resumeDeployment][data-id=\"{RUN_ID}\"]'))()",
                25,
                "底部队列",
                pump,
            ),
            body_text(ws)[-400:],
        )
        checker.check(
            "点底部队列这条记录进详情",
            helpers.click(
                ws, f'#mini-status [data-action=resumeDeployment][data-id="{RUN_ID}"]'
            ),
            body_text(ws)[:300],
        )
        checker.check(
            "详情页有「归档」",
            helpers.wait_js(
                ws,
                f"!!document.querySelector('#main [data-wf=run-archive]')",
                20,
                "归档按钮",
                pump,
            ),
            body_text(ws)[-400:],
        )
        helpers.screenshot(ws, report_dir / "01-before-archive.png", report["shots"])

        checker.check(
            "点「归档」",
            helpers.click(ws, "#main [data-wf=run-archive]"),
            body_text(ws)[-300:],
        )
        checker.check(
            "页面提示已归档",
            helpers.wait_js(
                ws,
                "(document.body.innerText||'').includes('已归档：列表里不再显示')",
                20,
                "归档提示",
                pump,
            ),
            body_text(ws)[-400:],
        )
        checker.check("磁盘上写入 ArchivedAtUtc", bool(archived_at(work)), archived_at(work))
        checker.check("记录文件还在（归档不是删除）", record_path.is_file(), str(record_path))
        checker.check("退出详情页", leave_detail(ws), body_text(ws)[:200])
        checker.check("回到线路页（归档后）", goto_lines(ws, pump), body_text(ws)[:300])

        checker.check(
            "底部队列里没有它了",
            helpers.wait_js(
                ws,
                "(()=>!document.querySelector("
                f"'#mini-status [data-action=resumeDeployment][data-id=\"{RUN_ID}\"]'))()",
                20,
                "底部队列移除",
                pump,
            ),
            body_text(ws)[-400:],
        )
        checker.check(
            "线路页出现「已归档」一栏",
            helpers.wait_js(
                ws,
                f"(document.body.innerText||'').includes({json.dumps(ARCHIVE_BLOCK, ensure_ascii=False)})",
                20,
                "已归档一栏",
                pump,
            ),
            body_text(ws)[:500],
        )
        checker.check("「已归档」里有这条记录", NAME in body_text(ws), body_text(ws)[:500])
        helpers.screenshot(ws, report_dir / "02-archived.png", report["shots"])

        checker.check(
            "从「已归档」点「查看」",
            helpers.click(ws, f'#main [data-action=resume][data-id="{RUN_ID}"]'),
            body_text(ws)[:300],
        )
        checker.check(
            "详情页给「恢复这条记录」",
            helpers.wait_js(
                ws,
                f"!!document.querySelector('#main [data-wf=run-unarchive]')",
                20,
                "恢复按钮",
                pump,
            ),
            body_text(ws)[-400:],
        )
        checker.check(
            "点「恢复这条记录」",
            helpers.click(ws, "#main [data-wf=run-unarchive]"),
            body_text(ws)[-300:],
        )
        checker.check(
            "页面提示已恢复",
            helpers.wait_js(
                ws,
                "(document.body.innerText||'').includes('已恢复：这条任务回到列表')",
                20,
                "恢复提示",
                pump,
            ),
            body_text(ws)[-400:],
        )
        checker.check("磁盘上的 ArchivedAtUtc 清空", not archived_at(work), archived_at(work))
        checker.check("退出详情页（恢复后）", leave_detail(ws), body_text(ws)[:200])
        checker.check("回到线路页（恢复后）", goto_lines(ws, pump), body_text(ws)[:300])
        checker.check(
            "它回到底部队列",
            helpers.wait_js(
                ws,
                "(()=>!!document.querySelector("
                f"'#mini-status [data-action=resumeDeployment][data-id=\"{RUN_ID}\"]'))()",
                20,
                "回到队列",
                pump,
            ),
            body_text(ws)[-400:],
        )
        checker.check("记录文件一直在", record_path.is_file(), str(record_path))
        helpers.screenshot(ws, report_dir / "03-restored.png", report["shots"])
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
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if not args.keep_open and process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        leftovers = process is not None and process.poll() is None
        print(f"残留进程：{'有' if leftovers else '无'}", flush=True)
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
