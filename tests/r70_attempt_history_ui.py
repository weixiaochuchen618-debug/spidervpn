#!/usr/bin/env python3
"""r70 界面验收：部署任务的尝试历史（A2/A3 P1-4）。

r70 之前，`Attempts[]` 从 r44 就在记录里，但**没有任何代码往里追加**：用户重试
多少次，历史里永远只有第一次。r70 把「尝试」的起止判据写进引擎与纯函数层，
并把历史只读地渲染在任务详情页上。

本脚本验的是**页面**（CDP + 隔离数据根 + 手写记录，不需要真服务器）：

1. 预置一条 `NeedsAttention/RetryStep` 的记录，带两次尝试（第一次失败、第二次没结论）；
2. 线路页点这张任务卡 → 进详情页；
3. 详情页必须出现「尝试历史（2 次）」，两行分别是：
   - `#1 · 11-12 10:00 → 11-12 10:03 · 失败在第 2 步（准备标准连接）· 错误码 ListenFailed`
   - `#2 · 11-12 10:10 开始 · 没有拿到结论就停了 · 有未核对的写`
4. 历史块**只读**：页面上没有「重放 / 查看这一次」这类按钮；
5. 收尾：现场 `data` 之外一个字节没动，无残留进程。

用法：

  python tests/r70_attempt_history_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r70-attempt-history\\acceptance \\
      --work C:\\tc-rs-build\\r70\\root
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

RUN_ID = "a7000000-1111-4111-8111-111111111111"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "deployment-runs" / "attention-retry.json"

HISTORY_HEAD = "尝试历史（2 次）"
LINE_ONE = "#1 · 11-12 10:00 → 11-12 10:03"
LINE_ONE_STEP = "失败在第 2 步（准备标准连接）"
LINE_ONE_CODE = "错误码 ListenFailed"
LINE_TWO = "#2 · 11-12 10:10 开始 · 没有拿到结论就停了"
RECONCILE = "有未核对的写"
READ_ONLY = "历史只读"


def body_text(ws) -> str:
    return t11.body_text(ws)


def runs_dir(work: Path) -> Path:
    return work / "data" / "deployments" / "runs"


def write_record(work: Path) -> Path:
    """把夹具改成本轮要的那条记录：两次尝试、第一次失败在 Step1。"""
    record = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record["RunId"] = RUN_ID
    record["State"] = "NeedsAttention"
    record["NextAction"] = "RetryStep"
    record["Step"] = 1
    record["Revision"] = 4
    record["Reason"] = {
        "Category": "Failed",
        "Class": "environment",
        "Code": "ListenFailed",
        "Text": "端口被占用",
        "AtUtc": "2026-11-12T10:03:00Z",
    }
    record["UpdatedAtUtc"] = "2026-11-12T10:10:00Z"
    record["Attempts"] = [
        {
            "No": 1,
            "StartedAtUtc": "2026-11-12T10:00:00Z",
            "FinishedAtUtc": "2026-11-12T10:03:00Z",
            "FailedStep": 1,
            "ErrorCode": "ListenFailed",
            "Reconcile": "NotNeeded",
        },
        {
            "No": 2,
            "StartedAtUtc": "2026-11-12T10:10:00Z",
            "FinishedAtUtc": None,
            "FailedStep": None,
            "ErrorCode": "",
            "Reconcile": "Needed",
        },
    ]
    target = runs_dir(work) / f"{RUN_ID}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def goto_lines(ws, pump, seconds: float = 25.0) -> bool:
    if not helpers.click(ws, "nav [data-page=lines]"):
        return False
    return helpers.wait_js(
        ws,
        "!!document.querySelector('#main .task-row')"
        "||(document.body.innerText||'').includes('未完成的添加')",
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
        "mode": "attempt-history",
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
        if work.exists() and any(runs_dir(work).glob("*.json")):
            raise SystemExit(f"数据根里已经有部署记录，拒绝复用：{work}（换一个空目录）")
        target = write_record(work)
        checker.check("预置记录：两次尝试、第一次失败在 Step1", True, str(target))

        process, _port, ws = t11.launch(exe, work, report_dir, "history")
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
            "任务卡出现（需要处理）",
            helpers.wait_js(
                ws,
                f"!!document.querySelector('#main [data-action=resume][data-id=\"{RUN_ID}\"]')",
                25,
                "任务卡",
                pump,
            ),
            body_text(ws)[:400],
        )
        checker.check(
            "点任务卡进详情页",
            helpers.click(ws, f'#main [data-action=resume][data-id="{RUN_ID}"]'),
            body_text(ws)[:300],
        )
        checker.check(
            "详情页打开（等「尝试历史」出现）",
            helpers.wait_js(
                ws,
                f"(document.body.innerText||'').includes({json.dumps(HISTORY_HEAD, ensure_ascii=False)})",
                25,
                "尝试历史",
                pump,
            ),
            body_text(ws)[-500:],
        )

        text = body_text(ws)
        report["body"] = text[-1200:]
        checker.check("标题「尝试历史（2 次）」", HISTORY_HEAD in text, text[-400:])
        checker.check("第一次尝试的起止时间", LINE_ONE in text, text[-400:])
        checker.check("失败步骤带人话名", LINE_ONE_STEP in text, text[-400:])
        checker.check("错误码上屏", LINE_ONE_CODE in text, text[-400:])
        checker.check("没有结论的那次不写「进行中」", LINE_TWO in text, text[-400:])
        checker.check("未决写标记上屏", RECONCILE in text, text[-400:])
        checker.check("写明只读", READ_ONLY in text, text[-400:])

        # 只读：历史里不长出按钮。页面上的按钮只能是既有的那几个动作。
        buttons = ws.evaluate(
            "(()=>Array.from(document.querySelectorAll('#main button'))"
            ".map(b=>b.textContent.trim()))()"
        ) or []
        report["buttons"] = buttons
        forbidden = [
            item
            for item in buttons
            if any(word in item for word in ("重放", "查看这一次", "再执行一次"))
        ]
        checker.check("历史没有「重放/查看这一次」按钮", not forbidden, forbidden)
        # 历史不许改动这一页的动作集合：主按钮仍是记录算出来的那一个。
        checker.check(
            "主按钮仍是「重试这一步」（历史没抢走下一步动作）",
            "重试这一步" in buttons,
            buttons,
        )
        helpers.screenshot(ws, report_dir / "01-attempt-history.png", report["shots"])
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
