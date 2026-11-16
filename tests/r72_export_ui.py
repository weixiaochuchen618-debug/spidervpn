#!/usr/bin/env python3
"""r72 界面验收：单任务诊断摘要导出（A2/A3 P2-3）。

部署失败时最有用的信息散在记录的五六个字段里。r72 之前，用户只能自己去翻
`deployments\\runs\\<RunId>.json` 或者截图。r72 起详情页多一颗「导出诊断摘要」：
点一下，`logs\\exports\\` 下出现一份 Markdown（或 JSON），内容说清状态、原因码、
哪一步失败、尝试历史与未决写，且**不含秘密**。

本脚本验页面 + 真实文件（CDP + 隔离数据根，不需要真服务器）：

1. 预置一条 `NeedsAttention/RetryStep` 记录 → 线路页点进详情；
2. 详情页有「导出诊断摘要」；点它 → 页面提示「已导出诊断摘要」；
3. `logs\\exports\\` 下真的出现以 RunId 短码命名的 `.md`，内容有标题/编号/错误码，且不含 `password`；
4. 再点一次 → 第二份文件，**不覆盖**第一份；
5. 收尾无残留进程。

用法：

  python tests/r72_export_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r72-export\\acceptance \\
      --work C:\\tc-rs-build\\r72\\root
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

RUN_ID = "a7200000-1111-4111-8111-111111111111"
SHORT = RUN_ID[:8]
HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "deployment-runs" / "attention-retry.json"

BUTTON = "导出诊断摘要"
NOTICE = "已导出诊断摘要"


def body_text(ws) -> str:
    return t11.body_text(ws)


def data_root(work: Path) -> Path:
    return work / "data"


def write_record(work: Path) -> None:
    record = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record["RunId"] = RUN_ID
    record["State"] = "NeedsAttention"
    record["NextAction"] = "RetryStep"
    record["Step"] = 1
    record["Revision"] = 3
    record["Reason"] = {
        "Category": "Failed",
        "Class": "environment",
        "Code": "ListenFailed",
        "Text": "端口被占用",
        "AtUtc": "2026-11-12T11:03:00Z",
    }
    record["UpdatedAtUtc"] = "2026-11-12T11:03:00Z"
    runs = data_root(work) / "deployments" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / f"{RUN_ID}.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def exports(work: Path) -> list[Path]:
    folder = data_root(work) / "logs" / "exports"
    if not folder.is_dir():
        return []
    return sorted(folder.glob("*.md"))


def wait_exports(work: Path, want: int, seconds: float = 20.0) -> list[Path]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        items = exports(work)
        if len(items) >= want:
            return items
        time.sleep(0.2)
    return exports(work)


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
        "mode": "deploy-export",
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
        write_record(work)
        checker.check("预置：一条停在失败处的记录", True, str(data_root(work)))

        process, _port, ws = t11.launch(exe, work, report_dir, "export")
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
            "点任务卡进详情页",
            helpers.click(ws, f'#main [data-action=resume][data-id="{RUN_ID}"]'),
            body_text(ws)[:300],
        )
        checker.check(
            "详情页有「导出诊断摘要」",
            helpers.wait_js(
                ws,
                f"(document.body.innerText||'').includes({json.dumps(BUTTON, ensure_ascii=False)})",
                25,
                "导出按钮",
                pump,
            ),
            body_text(ws)[-400:],
        )
        helpers.screenshot(ws, report_dir / "01-detail.png", report["shots"])

        checker.check(
            "点「导出诊断摘要」",
            helpers.click(ws, "#main [data-wf=run-export]"),
            body_text(ws)[-300:],
        )
        checker.check(
            "页面提示已导出",
            helpers.wait_js(
                ws,
                f"(document.body.innerText||'').includes({json.dumps(NOTICE, ensure_ascii=False)})",
                20,
                "导出提示",
                pump,
            ),
            body_text(ws)[-400:],
        )
        first = wait_exports(work, 1)
        checker.check("logs\\exports 下出现一份 .md", len(first) == 1, [str(p) for p in first])
        if not first:
            raise RuntimeError("导出文件没有出现")
        text = first[0].read_text(encoding="utf-8")
        report["file"] = str(first[0])
        report["head"] = text[:800]
        checker.check("文件名带任务短码", SHORT in first[0].name, first[0].name)
        for needle in ["# 部署诊断摘要", RUN_ID, "ListenFailed", "端口被占用"]:
            checker.check(f"摘要里写清了「{needle}」", needle in text, text[:200])
        lowered = text.lower()
        for forbidden in ("password", "private key", "private_key"):
            checker.check(f"摘要里没有 {forbidden}", forbidden not in lowered, "出现了秘密字段")
        helpers.screenshot(ws, report_dir / "02-exported.png", report["shots"])

        # 再点一次：第二份文件，不覆盖第一份。
        checker.check(
            "再点一次导出",
            helpers.click(ws, "#main [data-wf=run-export]"),
            body_text(ws)[-300:],
        )
        second = wait_exports(work, 2)
        checker.check("第二份文件出现", len(second) == 2, [str(p) for p in second])
        checker.check(
            "两份文件名不同（没有互相覆盖）",
            len(second) >= 2 and second[0].name != second[1].name,
            [p.name for p in second],
        )
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
