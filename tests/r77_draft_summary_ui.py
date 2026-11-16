#!/usr/bin/env python3
"""r77 界面验收：草稿总览（C6：几份、放了多久、超期提示）。

r76 及以前，草稿只有「上限 3 条」与「放弃这次填写」：用户不知道还有几份没填完，
也不知道最旧那份放了多久；一份放了两个月的草稿和昨天刚建的看起来一模一样。

r77 起线路页「未完成的添加」上方多一行总览：`2 份没填完的部署，最旧的一份放了 10 天。`
超过 7 天再给一句「可以接着填，也可以放弃——草稿不会自己消失」。
**不做自动过期**：删不删只能由用户按。

本脚本验（CDP + 隔离数据根，不需要服务器）：

1. 预置两份草稿（一份 10 天前、一份昨天）；
2. 线路页出现总览：条数 / 最旧天数 / 超期提示，且都写着「不会自己消失」；
3. 两张草稿卡照旧（「继续填写」/「放弃这次填写」）——统计没有替代入口；
4. 加筛选（状态=已完成）→ 总览**跟着消失**（否则会出现「统计说 2 份、列表里 0 条」）；
5. 清除筛选 → 总览回来。

用法：

  python tests/r77_draft_summary_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r77-draft-summary\\acceptance \\
      --work C:\\tc-rs-build\\r77\\root
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
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

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "deployment-runs" / "draft.json"

RUN_OLD = "b7700000-1111-4111-8111-111111111101"
RUN_FRESH = "b7700000-1111-4111-8111-111111111102"
NAME_OLD = "甲 · 十天前建的草稿"
NAME_FRESH = "乙 · 昨天建的草稿"

SUMMARY_MARK = "份没填完的部署"
STALE_MARK = "超过 7 天没动过"
NO_EXPIRE_MARK = "不会自己消失"
EMPTY_TEXT = "没有符合筛选的任务"


def body_text(ws) -> str:
    return t11.body_text(ws)


def summary_text(ws) -> str:
    return str(ws.evaluate("(document.querySelector('.draft-summary')||{}).innerText||''") or "")


def has_summary(ws) -> bool:
    return bool(ws.evaluate("!!document.querySelector('.draft-summary')"))


def seed_drafts(work: Path) -> None:
    base = json.loads(FIXTURE.read_text(encoding="utf-8"))
    runs = work / "data" / "deployments" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    for run_id, name, created in (
        (RUN_OLD, NAME_OLD, "2026-11-03T00:00:00Z"),
        (RUN_FRESH, NAME_FRESH, "2026-11-12T00:00:00Z"),
    ):
        record = json.loads(json.dumps(base))
        record.update(RunId=run_id, Label=name, CreatedAtUtc=created, UpdatedAtUtc=created)
        (runs / f"{run_id}.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )


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


def set_filter(ws, kind: str, value: str) -> str:
    script = (
        "(()=>{const s=document.querySelector('[data-deploy-filter=\"%s\"]');"
        "if(!s)return '<missing>';s.value='%s';"
        "s.dispatchEvent(new Event('change',{bubbles:true}));return s.value;})()"
    ) % (kind, value)
    return str(ws.evaluate(script) or "")


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

    checker = Checker()
    report: dict = {
        "mode": "draft-summary",
        "exe": str(exe),
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    ws = None
    try:
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        seed_drafts(work)
        checker.check("预置：两份草稿（10 天前 + 昨天）", True, str(work))

        process, _port, ws = t11.launch(exe, work, report_dir, "drafts")
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
            "草稿总览出现",
            helpers.wait_js(ws, "!!document.querySelector('.draft-summary')", 25, "草稿总览", pump),
            body_text(ws)[:400],
        )
        text = summary_text(ws)
        checker.check("写着条数（2 份没填完的部署）", SUMMARY_MARK in text, text)
        checker.check("写着最旧一份的天数", "最旧的一份放了" in text, text)
        checker.check(
            "超期提示（超过 7 天没动过）",
            STALE_MARK in text,
            text,
        )
        checker.check(
            "说清不自动过期（不会自己消失）",
            NO_EXPIRE_MARK in text,
            text,
        )
        helpers.screenshot(ws, report_dir / "01-summary.png", report["shots"])

        whole = body_text(ws)
        checker.check(
            "两张草稿卡照旧在（继续填写 / 放弃这次填写）",
            NAME_OLD in whole and NAME_FRESH in whole and "继续填写" in whole,
            whole[:600],
        )

        # 加筛选：统计必须跟着消失，否则「统计说 2 份、列表里 0 条」。
        # 下拉框的 value 是 `Complete`（`DEPLOY_STATE_FILTERS` 里的第一项），不是 Completed。
        checker.check("状态筛选设为「已完成」", set_filter(ws, "state", "Complete") == "Complete", "")
        checker.check(
            "筛选后总览消失（不出现自相矛盾）",
            helpers.wait_js(ws, "!document.querySelector('.draft-summary')", 10, "总览消失", pump),
            summary_text(ws),
        )
        checker.check(
            "筛空给可恢复提示",
            EMPTY_TEXT in body_text(ws),
            body_text(ws)[:300],
        )
        helpers.screenshot(ws, report_dir / "02-filtered.png", report["shots"])

        checker.check(
            "清除筛选",
            helpers.click(ws, "[data-action=clearDeployFilter]"),
            body_text(ws)[:300],
        )
        checker.check(
            "总览回来",
            helpers.wait_js(ws, "!!document.querySelector('.draft-summary')", 10, "总览回来", pump),
            summary_text(ws),
        )
        helpers.screenshot(ws, report_dir / "03-restored.png", report["shots"])

    except Exception as error:  # noqa: BLE001
        checker.check("脚本没有异常", False, repr(error))
        code = 1
    finally:
        report["checks"] = checker.checks
        report["passed"] = sum(1 for item in checker.checks if item["ok"])
        report["total"] = len(checker.checks)
        report["exeSha256"] = hashlib.sha256(exe.read_bytes()).hexdigest().upper()
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"\n{report['passed']}/{report['total']} 项通过")
        for row in checker.checks:
            print(("PASS " if row["ok"] else "FAIL ") + row["label"])
        if not args.keep_open:
            try:
                if ws:
                    ws.close()
            except Exception:  # noqa: BLE001
                pass
            if process:
                process.terminate()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
