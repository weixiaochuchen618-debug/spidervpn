#!/usr/bin/env python3
"""r96 界面验收：「显示旧版隐藏记录」与软删除（对齐 旧版的`ShowClearedHistory`）。

旧版的「删除所选」实际是**隐藏**：记录行留在本机审计文件里，页面上消失；
勾上「显示旧版隐藏记录」会以「已隐藏（旧版）」重新出现，并可逐条「恢复显示」。

本脚本只验页面（CDP + 隔离数据根，不需要真服务器）：

1. 预置 3 条记录 + 1 行坏数据，其中一条已经在 `operations.hidden.json` 里；
2. 默认不显示预隐藏的那条，开关存在且未勾选；
3. 全选当前结果 → 只选中看得见的两条；
4. 「删除所选」→ 确认框是「隐藏」，确认后审计文件**一行没少**、隐藏键 +2；
5. 勾上开关 → 三条都以「已隐藏（旧版）」出现；
6. 点一条「恢复显示」→ 隐藏键 -1，那行回到普通列表；
7. 关掉开关再重进页面 → 恢复的那条仍在，其余两条仍隐藏（持久化）。

用法：

  python tests/r96_history_hidden_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r96-history-hidden\\
      --work C:\\tc-rs-build\\r96\\root
"""
from __future__ import annotations

import argparse
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
r87 = importlib.import_module("r87_history_ui")

Checker = helpers.Checker

VISIBLE_A = "甲线路连接成功"
VISIBLE_B = "乙线路连接成功"
HIDDEN_OLD = "旧版留下的记录"
BAD_LINE = "这一行不是 JSON（必须原样保留）"


def key_of(row: dict) -> str:
    return f"{row['ts']}\x01{row['action']}\x01{row['detail']}"


def seed(work: Path) -> None:
    logs = work / "data" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    rows = [
        {"ts": "2026-11-13T02:00:00Z", "action": "连接", "ok": True, "detail": VISIBLE_A, "src": "ui"},
        {"ts": "2026-11-13T01:59:00Z", "action": "连接", "ok": True, "detail": VISIBLE_B, "src": "ui"},
        {"ts": "2026-11-13T01:00:00Z", "action": "导入配置", "ok": False, "detail": HIDDEN_OLD, "src": "cli"},
    ]
    body = "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n" + BAD_LINE + "\n"
    (logs / "operations.jsonl").write_text(body, encoding="utf-8")
    (logs / "operations.hidden.json").write_text(
        json.dumps([key_of(rows[2])], ensure_ascii=False), encoding="utf-8"
    )


def hidden_keys(work: Path) -> list:
    path = work / "data" / "logs" / "operations.hidden.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def audit_lines(work: Path) -> int:
    text = (work / "data" / "logs" / "operations.jsonl").read_text(encoding="utf-8")
    return len(text.rstrip("\n").splitlines())


def marker_count(ws) -> int:
    return int(
        ws.evaluate(
            "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
            "return (t.match(/已隐藏（旧版）/g)||[]).length;})()"
        )
        or 0
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
    report = {"mode": "history-hidden", "exe": str(exe), "work": str(work), "checks": []}
    code = 0
    process = None
    ws = None
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "history-hidden")
        pump = t11.Pump(process.pid)

        def open_history() -> bool:
            if not helpers.wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ):
                return False
            if r87.click_when_enabled(ws, pump, "nav [data-page=settings]") != "ok":
                return False
            return r87.click_when_enabled(ws, pump, "#main [data-action=history]") == "ok" and helpers.wait_js(
                ws, "!!document.querySelector('#wf-history-search')", 20, "操作记录", pump
            )

        checker.check("进操作记录", open_history(), r87.body_text(ws)[-300:])
        text = r87.body_text(ws)
        checker.check(
            "预隐藏的记录默认不显示",
            VISIBLE_A in text and VISIBLE_B in text and HIDDEN_OLD not in text,
            text[:600],
        )
        checker.check(
            "「显示旧版隐藏记录」存在且默认不勾",
            str(
                ws.evaluate(
                    "(()=>{const e=document.querySelector('#wf-history-show-hidden');"
                    "return e?String(e.checked):'missing';})()"
                )
            )
            == "false",
            "",
        )

        checker.check(
            "点「全选当前结果」",
            r87.click_when_enabled(ws, pump, "[data-wf=history-all]") == "ok",
            "",
        )
        checker.check(
            "只选中看得见的两条",
            helpers.wait_js(
                ws,
                "((document.querySelector('[data-wf=history-delete]')||{}).innerText||'').includes('删除所选（2）')",
                8,
                "选中计数",
                pump,
            ),
            r87.body_text(ws)[-300:],
        )
        checker.check(
            "点「删除所选」",
            r87.click_when_enabled(ws, pump, "[data-wf=history-delete]") == "ok",
            "",
        )
        checker.check(
            "确认框说的是「隐藏」",
            helpers.wait_js(
                ws,
                "((document.querySelector('#dialog-root')||{}).innerText||'').includes('隐藏这些操作记录')",
                8,
                "确认框",
                pump,
            ),
            r87.body_text(ws)[-300:],
        )
        checker.check(
            "确认隐藏",
            r87.click_when_enabled(ws, pump, "#dialog-root [data-action=confirmDialog]") == "ok",
            "",
        )
        checker.check(
            "提示说「已隐藏 2 条」",
            helpers.wait_js(
                ws,
                "((document.querySelector('#toast')||{}).innerText||'').includes('已隐藏 2 条')",
                8,
                "隐藏提示",
                pump,
            ),
            r87.body_text(ws)[-300:],
        )
        checker.check(
            "列表里三条都不在（默认不显示隐藏）",
            r87.wait_list(ws, pump, must_not=(VISIBLE_A, VISIBLE_B, HIDDEN_OLD), seconds=12),
            r87.body_text(ws)[-400:],
        )
        checker.check("审计文件一行没少（3 条 + 1 行坏数据）", audit_lines(work) == 4, str(audit_lines(work)))
        checker.check(
            "隐藏键 +2（预隐藏的那条仍在）",
            len(hidden_keys(work)) == 3,
            json.dumps(hidden_keys(work), ensure_ascii=False),
        )

        checker.check(
            "勾「显示旧版隐藏记录」",
            r87.click_when_enabled(ws, pump, "[data-wf=history-show-hidden]") == "ok",
            "",
        )
        checker.check(
            "三条都回来并带「已隐藏（旧版）」",
            r87.wait_list(
                ws, pump, must=(VISIBLE_A, VISIBLE_B, HIDDEN_OLD), seconds=12
            )
            and helpers.wait_js(ws, "true", 1, "重画", pump)
            and marker_count(ws) == 3,
            f"markers={marker_count(ws)} {r87.body_text(ws)[-400:]}",
        )
        checker.check(
            "点一条「恢复显示」",
            r87.click_when_enabled(ws, pump, "[data-wf^='history-restore:']") == "ok",
            "",
        )
        checker.check(
            "隐藏键 -1",
            helpers.wait_js(ws, "true", 1, "恢复", pump)
            and len(hidden_keys(work)) == 2,
            json.dumps(hidden_keys(work), ensure_ascii=False),
        )
        checker.check(
            "提示说「已恢复显示 1 条」",
            helpers.wait_js(
                ws,
                "((document.querySelector('#toast')||{}).innerText||'').includes('已恢复显示 1 条')",
                8,
                "恢复提示",
                pump,
            ),
            r87.body_text(ws)[-300:],
        )
        checker.check(
            "只剩两条隐藏标记",
            helpers.wait_js(
                ws,
                "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
                "return (t.match(/已隐藏（旧版）/g)||[]).length===2;})()",
                12,
                "恢复后标记数",
                pump,
            ),
            f"markers={marker_count(ws)} {r87.body_text(ws)[-400:]}",
        )

        # 关掉开关再重进：恢复的那条要还在，另外两条仍隐藏。
        checker.check(
            "取消勾选开关",
            r87.click_when_enabled(ws, pump, "[data-wf=history-show-hidden]") == "ok",
            "",
        )
        checker.check(
            "重进操作记录",
            r87.click_when_enabled(ws, pump, "[data-wf=back]") == "ok" and open_history(),
            r87.body_text(ws)[-300:],
        )
        text = r87.body_text(ws)
        restored = [name for name in (VISIBLE_A, VISIBLE_B, HIDDEN_OLD) if name in text]
        checker.check(
            "恢复的那条持久回到列表，其余仍隐藏",
            len(restored) == 1,
            f"visible={restored} {text[:500]}",
        )
        checker.check(
            "隐藏键仍是 2 条",
            len(hidden_keys(work)) == 2,
            json.dumps(hidden_keys(work), ensure_ascii=False),
        )
        helpers.screenshot(ws, report_dir / "01-history-hidden.png", report.get("shots", []))
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
        if process is not None:
            try:
                process.terminate()
            except Exception:  # noqa: BLE001
                pass
        if process is not None and args.keep_open:
            input("按回车关闭…")
        return code if report.get("allPassed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
