#!/usr/bin/env python3
"""r83 界面验收：详情页与诊断摘要要说清「这一次的指纹是自动记住的」。

背景：`Identity.AutoTrusted` 从 A9 起就写进部署记录了，但**没有任何页面读它**——
TOFU（没人工核对、按设置自动记住）替用户做了一次身份决定，用户看到的却只有
「部署完成」，像是核对过一样。

本脚本验页面 + 真实文件（CDP + 隔离数据根，不需要真服务器）：

1. 预置一条 24 小时内的完成记录，`Identity.AutoTrusted=true` + 一枚指纹；
2. 线路页底部队列点进详情 → 页面出现「自动记住」+ 那枚指纹 + 「下次连接会按它核对」；
3. 点「导出诊断摘要」→ `logs\\exports\\` 下的 `.md` 里写着「这一次是自动记住的，没有人工核对」；
4. 关掉详情，把记录改回 `AutoTrusted=false`，再点进去 → **一个字都不出现**；
5. 再导一份 → 新文件里也没有这句话（不能因为上一份有就当成有）。

用法：

  python tests/r83_autotrust_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r83-autotrust\\acceptance \\
      --work C:\\tc-rs-build\\r83\\root
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
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

RUN_ID = "a8300000-1111-4111-8111-111111111111"
NAME = "自建 · 203.0.113.10"
FINGERPRINT = "SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDEFG"
HERE = Path(__file__).resolve().parent
FIXTURE = HERE.parent / "fixtures" / "deployment-runs" / "complete.json"

AUTO_WORD = "自动记住"
NEXT_WORD = "下次连接会按它核对"
EXPORT_WORD = "这一次是自动记住的，没有人工核对"


def data_root(work: Path) -> Path:
    return work / "data"


def write_record(work: Path, auto_trusted: bool) -> Path:
    record = json.loads(FIXTURE.read_text(encoding="utf-8"))
    record["RunId"] = RUN_ID
    record["Label"] = NAME
    # 24 小时内：底部队列只列最近 24 小时的终态。
    record["UpdatedAtUtc"] = "2026-11-12T12:00:00Z"
    record["FinishedAtUtc"] = "2026-11-12T12:00:00Z"
    record["Identity"] = {
        "Fingerprint": FINGERPRINT,
        "AutoTrusted": auto_trusted,
    }
    runs = data_root(work) / "deployments" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    target = runs / f"{RUN_ID}.json"
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def exports(work: Path) -> list[Path]:
    folder = data_root(work) / "logs" / "exports"
    if not folder.is_dir():
        return []
    return sorted(folder.glob("*.md"))


def wait_exports(work: Path, want: int, seconds: float = 25.0) -> list[Path]:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        items = exports(work)
        if len(items) >= want:
            return items
        time.sleep(0.2)
    return exports(work)


def body_text(ws) -> str:
    return t11.body_text(ws)


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


def queue_has(ws) -> bool:
    return bool(
        ws.evaluate(
            "(()=>!!document.querySelector("
            f"'#mini-status [data-action=resumeDeployment][data-id=\"{RUN_ID}\"]'))()"
        )
    )


def open_detail(ws, pump, seconds: float = 20.0) -> bool:
    # 先确认真的回到了线路页：只是点了「完成」不够——表单还在时点队列行，
    # 页面会留在旧详情上（旧数据、旧导出），后面几条断言就会看着「没生效」。
    if not helpers.wait_js(
        ws,
        "(()=>!document.querySelector('#main [data-wf=done]')"
        f"&&!!document.querySelector('#mini-status [data-action=resumeDeployment][data-id=\"{RUN_ID}\"]'))()",
        seconds,
        "回到线路页（队列可见）",
        pump,
    ):
        return False
    clicked = ws.evaluate(
        "(()=>{const e=document.querySelector("
        f"'#mini-status [data-action=resumeDeployment][data-id=\"{RUN_ID}\"]');"
        "if(!e)return 'missing';e.click();return 'ok';})()"
    )
    if str(clicked) != "ok":
        return False
    return helpers.wait_js(
        ws,
        # 表单里的按钮挂 `data-wf`；`data-action` 是页面级动作（导航/队列行）。
        "!!document.querySelector('#main [data-wf=run-export]')",
        seconds,
        "部署详情页",
        pump,
    )


def leave_detail(ws) -> bool:
    return helpers.click(ws, "#main [data-wf=done]")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    # 用户开着自己那台窗口时也能跑：独立数据根（互斥名不同）+ 独立代理键 + 空闲端口。
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
    if not FIXTURE.is_file():
        raise SystemExit(f"缺夹具：{FIXTURE}")

    checker = Checker()
    report: dict = {
        "mode": "deploy-autotrust",
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
        record = write_record(work, True)
        checker.check("预置：一条完成记录（这次指纹是自动记住的）", record.is_file(), str(record))

        process, _port, ws = t11.launch(exe, work, report_dir, "autotrust")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪（导航与主内容都在）",
            helpers.wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ),
            body_text(ws)[-300:],
        )
        checker.check("回到线路页", goto_lines(ws, pump), body_text(ws)[:300])
        checker.check("底部队列里看得到这条记录", queue_has(ws), body_text(ws)[:400])
        checker.check("打开部署详情", open_detail(ws, pump), body_text(ws)[:400])

        text = body_text(ws)
        checker.check("详情页说「这一次的指纹是自动记住的」", AUTO_WORD in text, text[-600:])
        checker.check("详情页带着记下的那枚指纹", FINGERPRINT in text, text[-600:])
        checker.check("详情页说清下次怎么用这枚指纹", NEXT_WORD in text, text[-600:])
        helpers.screenshot(ws, report_dir / "01-detail-auto.png", report["shots"])

        # 导出诊断摘要：同一个事实也要出现在能贴给别人的那份里。
        helpers.click(ws, "#main [data-wf=run-export]")
        first = wait_exports(work, 1)
        checker.check("导出摘要真的落盘", len(first) >= 1, [str(p) for p in first])
        first_text = first[-1].read_text(encoding="utf-8") if first else ""
        checker.check("摘要里写着「没有人工核对」", EXPORT_WORD in first_text, first_text[:600])
        checker.check("摘要里带着那枚指纹", FINGERPRINT in first_text, first_text[:600])

        # 换成「人工核对过」的记录：这句话必须消失（否则会退化成噪音）。
        checker.check("退出详情页", leave_detail(ws), body_text(ws)[:300])
        write_record(work, False)
        checker.check("重新打开详情（这次是人工核对过的）", open_detail(ws, pump), body_text(ws)[:400])
        text = body_text(ws)
        checker.check("人工核对过的记录**不出现**「自动记住」", AUTO_WORD not in text, text[-600:])

        helpers.click(ws, "#main [data-wf=run-export]")
        both = wait_exports(work, 2)
        checker.check("第二份摘要也落盘（不覆盖第一份）", len(both) >= 2, [str(p) for p in both])
        second_text = both[-1].read_text(encoding="utf-8") if len(both) >= 2 else ""
        checker.check("第二份里没有那句「自动记住」", EXPORT_WORD not in second_text, second_text[:600])
        helpers.screenshot(ws, report_dir / "02-detail-manual.png", report["shots"])
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
