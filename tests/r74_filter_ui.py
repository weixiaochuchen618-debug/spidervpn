#!/usr/bin/env python3
"""r74 界面验收：任务列表筛选（A2/A3 P2-1）。

列表越用越长之后，「哪一条是失败、哪一条是今天的」只能靠肉眼扫。r74 起线路页的
任务面板顶部有三个下拉框：状态、时间、原因类别；筛空时给一句「没有符合筛选的任务」
和一颗「清除筛选」。筛选是**页面状态**：不发命令、不改记录。

本脚本验页面（CDP + 隔离数据根，不需要真服务器）：

1. 预置四条记录 + 一条提醒：需要处理(失败,今天) / 排队中(今天) / 已暂停(凭据,10 天前) / 已归档(完成,今天)；
2. 筛选条出现（三个下拉框）；
3. 状态 = 需要处理 → 只剩那一条；
4. 原因 = 失败 → 只剩失败的那条（提醒也按类别筛）；
5. 时间 = 今天 → 10 天前那条消失；
6. 状态 = 已完成 + 原因 = 失败 → 三块全空，出现「没有符合筛选的任务」+「清除筛选」；
7. 点「清除筛选」→ 四条都回来，三个下拉框回到「全部」。

用法：

  python tests/r74_filter_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r74-filter\\acceptance \\
      --work C:\\tc-rs-build\\r74\\root
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

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "deployment-runs"

NAME_ATTENTION = "甲 · 需要处理"
NAME_QUEUED = "乙 · 待确认"
NAME_OLD = "丙 · 旧暂停"
NAME_ARCHIVED = "丁 · 已归档"

RUN_ATTENTION = "a7400000-1111-4111-8111-111111111101"
RUN_QUEUED = "a7400000-1111-4111-8111-111111111102"
RUN_OLD = "a7400000-1111-4111-8111-111111111103"
RUN_ARCHIVED = "a7400000-1111-4111-8111-111111111104"

EMPTY_TEXT = "没有符合筛选的任务"


def body_text(ws) -> str:
    return t11.body_text(ws)


def main_text(ws) -> str:
    """只看主内容区：顶部状态条会显示「正在跑/排队中」那条任务的名字，
    它不属于被筛选的列表——用整页文本会把那条误判成「没被筛掉」。"""
    return str(ws.evaluate("document.querySelector('#main').innerText") or "")


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def reason(category: str, cls: str, code: str, text: str, at: str) -> dict:
    return {"Category": category, "Class": cls, "Code": code, "Text": text, "AtUtc": at}


def write_records(work: Path) -> None:
    runs = work / "data" / "deployments" / "runs"
    runs.mkdir(parents=True, exist_ok=True)

    attention = load("attention-retry.json")
    attention.update(
        RunId=RUN_ATTENTION,
        Label=NAME_ATTENTION,
        State="NeedsAttention",
        NextAction="RetryStep",
        Step=1,
        Revision=3,
        UpdatedAtUtc="2026-11-12T12:00:00Z",
        Reason=reason("Failed", "environment", "ListenFailed", "端口被占用", "2026-11-12T12:00:00Z"),
    )
    attention["Steps"][1]["Status"] = "Failed"
    attention["Steps"][1]["Error"] = attention["Reason"]

    # 用「等人确认」而不是「排队中」：排队中的记录在启动时会被恢复逻辑改判成
    # 「上次没有跑完」（那是另一条正确路径），隔离根里看不到真正的 Queued。
    # `WaitingUser` 与 `Queued`/`Running` 对外同属「进行中」，筛选口径一样。
    queued = load("waiting-user.json")
    queued.update(
        RunId=RUN_QUEUED,
        Label=NAME_QUEUED,
        State="WaitingUser",
        NextAction="EnterCredentials",
        Revision=2,
        UpdatedAtUtc="2026-11-12T11:00:00Z",
        Reason=None,
        # 排队中的记录不带执行者：带了外来的 Executor，启动恢复会把它改判成
        # 「上次没有跑完」——那是另一条路径（它是对的），但不该混进这一轮筛选验收。
        Executor=None,
        StartedAtUtc=None,
    )

    old = load("paused.json")
    old.update(
        RunId=RUN_OLD,
        Label=NAME_OLD,
        State="Paused",
        NextAction="None",
        Revision=2,
        UpdatedAtUtc="2026-11-02T09:00:00Z",
        FinishedAtUtc=None,
        Reason=reason("AccessRequired", "auth", "AccessRequired", "登录凭据不可用", "2026-11-02T09:00:00Z"),
    )

    archived = load("complete.json")
    archived.update(
        RunId=RUN_ARCHIVED,
        Label=NAME_ARCHIVED,
        State="Complete",
        NextAction="ViewLine",
        Revision=5,
        UpdatedAtUtc="2026-11-12T10:00:00Z",
        FinishedAtUtc="2026-11-12T10:00:00Z",
        ArchivedAtUtc="2026-11-12T10:30:00Z",
        Reason=None,
    )

    for record in (attention, queued, old, archived):
        (runs / f"{record['RunId']}.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    reminders = {
        "Schema": 1,
        "Kind": "TradeChannel.DeployReminders",
        "Reminders": [
            {
                "Id": "r-1",
                "RunId": RUN_ATTENTION,
                "Name": NAME_ATTENTION,
                "State": "NeedsAttention",
                "Step": 1,
                "Category": "Failed",
                "Code": "ListenFailed",
                "Text": "端口被占用",
                "CreatedAtUtc": "2026-11-12T12:00:00Z",
                "ReadAtUtc": None,
            }
        ],
    }
    (work / "data" / "deployments" / "reminders.json").write_text(
        json.dumps(reminders, ensure_ascii=False, indent=2), encoding="utf-8"
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


def filter_value(ws, kind: str) -> str:
    return str(
        ws.evaluate(
            "(()=>{const s=document.querySelector('[data-deploy-filter=\"%s\"]');"
            "return s?s.value:'<missing>';})()" % kind
        )
        or ""
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

    checker = Checker()
    report: dict = {
        "mode": "deploy-filter",
        "exe": str(exe),
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    ws = None
    try:
        write_records(work)
        checker.check("预置：四条记录（含 10 天前那条）+ 一条提醒", True, str(work))

        process, _port, ws = t11.launch(exe, work, report_dir, "filter")
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
            "筛选条出现（三个下拉框）",
            helpers.wait_js(
                ws,
                "document.querySelectorAll('[data-deploy-filter]').length===3",
                25,
                "筛选条",
                pump,
            ),
            body_text(ws)[:400],
        )
        text = main_text(ws)
        checker.check("四条记录都在", all(name in text for name in (NAME_ATTENTION, NAME_QUEUED, NAME_OLD, NAME_ARCHIVED)), text[:400])
        helpers.screenshot(ws, report_dir / "01-all.png", report["shots"])

        # ① 状态 = 需要处理
        checker.check("状态选「需要处理」", set_filter(ws, "state", "NeedsAttention") == "NeedsAttention", "下拉框没有接受")
        helpers.wait_js(ws, "true", 1, "等一下重画", pump)
        text = main_text(ws)
        checker.check("只剩需要处理的那条", NAME_ATTENTION in text, text[:400])
        checker.check("待确认的（进行中）被筛掉", NAME_QUEUED not in text, text[:400])
        checker.check("旧暂停的被筛掉", NAME_OLD not in text, text[:400])
        checker.check("已归档的也被筛掉", NAME_ARCHIVED not in text, text[:400])
        helpers.screenshot(ws, report_dir / "02-state.png", report["shots"])

        # ①' 状态 = 进行中：排队/在跑/等人确认是同一个桶
        checker.check("状态选「进行中」", set_filter(ws, "state", "Active") == "Active", "")
        helpers.wait_js(ws, "true", 1, "等一下重画", pump)
        text = main_text(ws)
        checker.check("「进行中」能看到待确认那条", NAME_QUEUED in text, text[:400])
        checker.check("「进行中」看不到需要处理那条", NAME_ATTENTION not in text, text[:400])

        # ② 状态回全部，原因 = 失败
        checker.check("状态回「全部」", set_filter(ws, "state", "all") == "all", "")
        checker.check("原因选「失败」", set_filter(ws, "error", "Failed") == "Failed", "")
        helpers.wait_js(ws, "true", 1, "等一下重画", pump)
        text = main_text(ws)
        checker.check("失败的那条还在", NAME_ATTENTION in text, text[:400])
        checker.check("待确认的（没有失败原因）被筛掉", NAME_QUEUED not in text, text[:400])
        checker.check("旧的（凭据原因）被筛掉", NAME_OLD not in text, text[:400])

        # ③ 原因回全部，时间 = 今天
        checker.check("原因回「全部」", set_filter(ws, "error", "all") == "all", "")
        checker.check("时间选「今天」", set_filter(ws, "time", "day") == "day", "")
        helpers.wait_js(ws, "true", 1, "等一下重画", pump)
        text = main_text(ws)
        checker.check("今天的还在", NAME_ATTENTION in text and NAME_QUEUED in text, text[:400])
        checker.check("10 天前那条消失", NAME_OLD not in text, text[:400])

        # ④ 筛空：已完成 + 失败
        checker.check("时间回「全部」", set_filter(ws, "time", "all") == "all", "")
        checker.check("状态选「已完成」", set_filter(ws, "state", "Complete") == "Complete", "")
        checker.check("原因选「失败」", set_filter(ws, "error", "Failed") == "Failed", "")
        checker.check(
            "筛空时给出可恢复的提示",
            helpers.wait_js(
                ws,
                f"(document.body.innerText||'').includes({json.dumps(EMPTY_TEXT, ensure_ascii=False)})",
                20,
                "空筛选提示",
                pump,
            ),
            body_text(ws)[:400],
        )
        checker.check(
            "空筛选时有「清除筛选」",
            bool(ws.evaluate("(()=>!!document.querySelector('[data-action=clearDeployFilter]'))()")),
            body_text(ws)[:300],
        )
        helpers.screenshot(ws, report_dir / "03-empty.png", report["shots"])

        # ⑤ 清除
        checker.check(
            "点「清除筛选」",
            helpers.click(ws, "#main [data-action=clearDeployFilter]"),
            body_text(ws)[:200],
        )
        helpers.wait_js(ws, "true", 1, "等一下重画", pump)
        text = main_text(ws)
        checker.check("四条都回来了", all(name in text for name in (NAME_ATTENTION, NAME_QUEUED, NAME_OLD, NAME_ARCHIVED)), text[:400])
        checker.check(
            "三个下拉框都回到「全部」",
            filter_value(ws, "state") == "all"
            and filter_value(ws, "time") == "all"
            and filter_value(ws, "error") == "all",
            (filter_value(ws, "state"), filter_value(ws, "time"), filter_value(ws, "error")),
        )
        helpers.screenshot(ws, report_dir / "04-cleared.png", report["shots"])
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
