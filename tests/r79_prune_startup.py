#!/usr/bin/env python3
"""r79 真机验收：启动时的部署记录裁剪（三条护栏）。

`prune_terminal` 以前**从没被调用过**：终态记录只增不减，而快照每 1–2 秒要把
`runs\\` 下所有 JSON 读一遍。r79 把它接到启动流程，但加了三条护栏——

1. 归档的不删（用户按过「留着」）；
2. **还有未读提醒的不删**（提醒里存着 RunId，删了「查看」指向空）；
3. **读不到提醒就整轮不裁**（不知道谁被引用时宁可不删）。

被删的只有「已完成 / 已取消 + 超过 7 天 + 没提醒 + 没归档」那一批。界面本来就
看不到它们（底部队列只留 24 小时，也没有记录页），所以这一批**用户无感**。

本脚本用真宿主（不是界面点击）验：

1. 预置 5 条记录：普通旧完成（该删）/ 有未读提醒的旧完成（不删）/
   归档的旧完成（不删）/ 刚完成（不删）/ 旧的「需要处理」（不删，非终态）；
2. 启动宿主 → 等它就绪 → 关掉；
3. 断言：只有第一条消失；其余四条都还在（逐条按 RunId 看文件）；
4. 断言：`logs/operations.jsonl` 里有「清理部署记录」，并写着清了几条。

用法：

  python tests/r79_prune_startup.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r79-prune\\acceptance \\
      --work C:\\tc-rs-build\\r79\\root
"""
from __future__ import annotations

import argparse
import hashlib
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

Checker = helpers.Checker

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "deployment-runs" / "complete.json"
ATTENTION_FIXTURE = (
    Path(__file__).resolve().parent.parent / "fixtures" / "deployment-runs" / "attention-retry.json"
)
ACTION = "清理部署记录"

RUN_PLAIN = "d7900000-1111-4111-8111-111111111101"
RUN_REMINDED = "d7900000-1111-4111-8111-111111111102"
RUN_ARCHIVED = "d7900000-1111-4111-8111-111111111103"
RUN_FRESH = "d7900000-1111-4111-8111-111111111104"
RUN_ATTENTION = "d7900000-1111-4111-8111-111111111105"


def utc(days_ago: int = 0) -> str:
    at = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return at.strftime("%Y-%m-%dT%H:%M:%SZ")


def seed(work: Path) -> dict:
    """造 5 条记录 + 1 条未读提醒；返回 RunId → 是否应被删。"""
    runs = work / "data" / "deployments" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    base = json.loads(FIXTURE.read_text(encoding="utf-8"))
    attention_base = json.loads(ATTENTION_FIXTURE.read_text(encoding="utf-8"))
    old = utc(30)

    def write(record: dict, run_id: str, label: str, finished: str, extra: dict | None = None) -> None:
        record = json.loads(json.dumps(record))
        record.update(
            RunId=run_id,
            Label=label,
            CreatedAtUtc=finished,
            UpdatedAtUtc=finished,
            FinishedAtUtc=finished,
        )
        if extra:
            record.update(extra)
        (runs / f"{run_id}.json").write_text(
            json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    write(base, RUN_PLAIN, "普通旧完成", old)
    write(base, RUN_REMINDED, "有未读提醒的旧完成", old)
    write(base, RUN_ARCHIVED, "归档过的旧完成", old, {"ArchivedAtUtc": utc(1)})
    write(base, RUN_FRESH, "刚完成的记录", utc(0))
    write(attention_base, RUN_ATTENTION, "旧的待处理", old, {"State": "NeedsAttention"})

    # 未读提醒：指向 RUN_REMINDED。
    reminders = {
        "Schema": 1,
        "Kind": "TradeChannel.DeployReminders",
        "Reminders": [
            {
                "Id": "r-79",
                "RunId": RUN_REMINDED,
                "Name": "有未读提醒的旧完成",
                "State": "Complete",
                "Step": 4,
                "Category": "",
                "Code": "",
                "Text": "部署完成",
                "CreatedAtUtc": old,
                "ReadAtUtc": None,
            }
        ],
    }
    (work / "data" / "deployments" / "reminders.json").write_text(
        json.dumps(reminders, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {
        RUN_PLAIN: True,
        RUN_REMINDED: False,
        RUN_ARCHIVED: False,
        RUN_FRESH: False,
        RUN_ATTENTION: False,
    }


def exists(work: Path, run_id: str) -> bool:
    return (work / "data" / "deployments" / "runs" / f"{run_id}.json").is_file()


def prune_events(work: Path) -> list:
    path = work / "data" / "logs" / "operations.jsonl"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("action") == ACTION:
            rows.append(item)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    t11.no_running_host()

    checker = Checker()
    report: dict = {
        "mode": "prune-startup",
        "exe": str(exe),
        "work": str(work),
        "checks": [],
        "shots": [],
    }
    process = None
    ws = None
    try:
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True, exist_ok=True)
        expected = seed(work)
        checker.check("预置：5 条记录（1 条该删、4 条该留）+ 1 条未读提醒", True, str(work))
        before_events = prune_events(work)
        checker.check("启动前没有「清理部署记录」的旧账", not before_events, before_events)

        process, _port, ws = t11.launch(exe, work, report_dir, "prune")
        pump = t11.Pump(process.pid)
        helpers.wait_js(ws, "document.readyState==='complete'", 40, "宿主就绪", pump)

        # 宿主的裁剪在 UI 起来之前就跑完了；给磁盘一点余量再核。
        import time

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and exists(work, RUN_PLAIN):
            time.sleep(0.2)

        checker.check(
            "普通旧完成（超 7 天、没提醒、没归档）被删",
            not exists(work, RUN_PLAIN),
            "文件还在",
        )
        checker.check(
            "有未读提醒的旧完成被保住",
            exists(work, RUN_REMINDED),
            "文件不见了：提醒里的「查看」会指向空",
        )
        checker.check("归档的旧完成被保住", exists(work, RUN_ARCHIVED), "文件不见了")
        checker.check("刚完成的记录被保住（没超 7 天）", exists(work, RUN_FRESH), "文件不见了")
        checker.check(
            "「需要处理」的旧记录被保住（不是终态）",
            exists(work, RUN_ATTENTION),
            "文件不见了",
        )

        events = prune_events(work)
        checker.check("记了一笔「清理部署记录」", bool(events), events)
        if events:
            detail = str(events[-1].get("detail") or "")
            checker.check(
                "记录写着清了几条、留了几条",
                "清理 1 条" in detail and "保留 1 条" in detail,
                detail,
            )
            checker.check(
                "记录标成成功",
                events[-1].get("ok") is True,
                events[-1],
            )
        else:
            checker.check("记录写着清了几条、留了几条", False, "没有记录")
            checker.check("记录标成成功", False, "没有记录")

        # 再启一次：没有可删的了，不该重复记账。
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        ws = None
        process.terminate()
        process.wait(timeout=15)
        time.sleep(1.0)

        process, _port, ws = t11.launch(exe, work, report_dir, "prune2")
        pump = t11.Pump(process.pid)
        helpers.wait_js(ws, "document.readyState==='complete'", 40, "第二次就绪", pump)
        again = prune_events(work)
        checker.check(
            "第二次启动没有可删的记录，不重复记账",
            len(again) == len(events),
            again,
        )
        checker.check(
            "第二轮也没有误删（四条仍在）",
            all(
                exists(work, run_id)
                for run_id in (RUN_REMINDED, RUN_ARCHIVED, RUN_FRESH, RUN_ATTENTION)
            ),
            "有文件不见了",
        )
    except Exception as error:  # noqa: BLE001
        checker.check("脚本没有异常", False, repr(error))
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
        try:
            if ws:
                ws.close()
        except Exception:  # noqa: BLE001
            pass
        if process:
            process.terminate()
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
