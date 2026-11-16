#!/usr/bin/env python3
"""r87 界面验收：操作记录页的「搜索 + 来源 + 结果」筛选（对齐 旧版）。

旧版的 `OperationHistoryPages.ps1` 这一页有：搜索框（按服务器名称或操作名称）、
来源下拉、状态下拉、一颗「筛选」，外加导出。我们原来只有「全部 / 只看失败」两个 tap。

本脚本验页面（CDP + 隔离数据根，不需要真服务器）：

1. 预置 3 条操作记录（界面成功 / 命令行失败 / 自动成功）；
2. 设置 → 操作记录：搜索框、来源下拉、结果下拉、筛选按钮都在；
3. 搜「导入」→ 只剩命令行那条；
4. 清空搜索、来源选「命令行」→ 仍只剩那条；
5. 来源选「自动」→ 只剩自动那条；
6. 点「导出当前筛选」→ 真的写出一个文件。

用法：

  python tests/r87_history_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r87-history\\
      --work C:\\tc-rs-build\\r87\\root
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

UI_DETAIL = "自建 · 甲线路"
CLI_DETAIL = "端口被占用"
AUTO_DETAIL = "切到 · 乙线路"


def body_text(ws) -> str:
    return t11.body_text(ws)


def click(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


def click_when_enabled(ws, pump, selector: str, seconds: float = 25.0) -> str:
    ok = helpers.wait_js(
        ws,
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return !!e&&!e.disabled;})()",
        seconds,
        f"{selector} 可点",
        pump,
    )
    if not ok:
        return "not-ready"
    return click(ws, selector)


def choose(ws, pump, selector: str, index: int) -> bool:
    """把下拉选到第 index 项并派发 change（页面靠 change 记筛选）。"""
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + f");if(!e)return 'missing';e.value={json.dumps(str(index))};"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 1, "重画", pump)
    return ok


def wait_list(ws, pump, must=(), must_not=(), seconds: float = 8.0) -> bool:
    """等列表变成预期再断言。

    筛选是「发事件 → 宿主下一帧快照重画」，中间最多隔一秒；`set_value` 之后立刻
    读页面只会读到旧列表（r87 第一版脚本就栽在这里）。
    """
    cond = "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
    for item in must:
        cond += f"if(!t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    for item in must_not:
        cond += f"if(t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    cond += "return true;})()"
    return helpers.wait_js(ws, cond, seconds, "列表筛选", pump)


def seed(work: Path) -> None:
    logs = work / "data" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    rows = [
        {"ts": "2026-11-13T02:00:00Z", "action": "连接", "ok": True, "detail": UI_DETAIL, "src": "ui"},
        {"ts": "2026-11-13T01:59:00Z", "action": "导入配置", "ok": False, "detail": CLI_DETAIL, "src": "cli"},
        {"ts": "2026-11-13T01:00:00Z", "action": "自动切换", "ok": True, "detail": AUTO_DETAIL, "src": "auto"},
    ]
    (logs / "operations.jsonl").write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def exports(work: Path) -> list:
    folder = work / "data" / "logs" / "exports"
    if not folder.is_dir():
        return []
    return sorted(folder.rglob("*"))


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
    report = {"mode": "history-filters", "exe": str(exe), "work": str(work), "checks": []}
    code = 0
    process = None
    ws = None
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "history")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ),
            body_text(ws)[-200:],
        )
        checker.check("进设置", click_when_enabled(ws, pump, "nav [data-page=settings]") == "ok", "")
        checker.check(
            "打开操作记录",
            click_when_enabled(ws, pump, "#main [data-action=history]") == "ok"
            and helpers.wait_js(ws, "!!document.querySelector('#wf-history-search')", 20, "操作记录", pump),
            body_text(ws)[-300:],
        )

        text = body_text(ws)
        checker.check("三条记录默认都在", all(x in text for x in (UI_DETAIL, CLI_DETAIL, AUTO_DETAIL)), text[:500])
        checker.check(
            "筛选控件齐：搜索 + 来源 + 结果 + 筛选按钮",
            bool(ws.evaluate("!!document.querySelector('#wf-history-search')"))
            and bool(ws.evaluate("!!document.querySelector('#wf-history-src')"))
            and bool(ws.evaluate("!!document.querySelector('#wf-history-result')"))
            and bool(ws.evaluate("!!document.querySelector('[data-wf=apply-history]')")),
            "",
        )

        # 搜索
        checker.check("填搜索「导入」", t11.set_value(ws, "#wf-history-search", "导入"), "")
        checker.check(
            "搜索后只剩命令行那条",
            wait_list(ws, pump, must=(CLI_DETAIL,), must_not=(UI_DETAIL, AUTO_DETAIL)),
            body_text(ws)[:400],
        )

        # 清空搜索 + 来源=命令行（下标 2）
        t11.set_value(ws, "#wf-history-search", "")
        checker.check("来源选「命令行」", choose(ws, pump, "#wf-history-src", 2), "")
        checker.check(
            "只剩命令行那条",
            wait_list(ws, pump, must=(CLI_DETAIL,), must_not=(UI_DETAIL, AUTO_DETAIL)),
            body_text(ws)[:400],
        )

        # 来源=自动（下标 3）
        checker.check("来源选「自动」", choose(ws, pump, "#wf-history-src", 3), "")
        checker.check(
            "只剩自动那条",
            wait_list(ws, pump, must=(AUTO_DETAIL,), must_not=(CLI_DETAIL,)),
            body_text(ws)[:400],
        )

        # 导出当前筛选
        checker.check("点「导出当前筛选」", click_when_enabled(ws, pump, "[data-wf=export-history]") == "ok", "")
        deadline = time.monotonic() + 20
        files = []
        while time.monotonic() < deadline:
            files = exports(work)
            if files:
                break
            time.sleep(0.2)
        checker.check("导出真的写出文件", bool(files), [str(p) for p in files])

        # ---- 批量选择与删除（r88）----
        # 现在筛选是「来源=自动」，只剩一条。
        checker.check("点「全选当前结果」", click_when_enabled(ws, pump, "[data-wf=history-all]") == "ok", "")
        checker.check(
            "按钮变成「删除所选（1）」",
            helpers.wait_js(
                ws,
                "((document.querySelector('[data-wf=history-delete]')||{}).innerText||'').includes('删除所选（1）')",
                8,
                "选中计数",
                pump,
            ),
            body_text(ws)[-300:],
        )
        checker.check("点「删除所选」", click_when_enabled(ws, pump, "[data-wf=history-delete]") == "ok", "")
        checker.check(
            "先弹确认框（还没隐藏）",
            helpers.wait_js(
                ws,
                "((document.querySelector('#dialog-root')||{}).innerText||'').includes('隐藏这些操作记录')",
                8,
                "确认框",
                pump,
            ),
            body_text(ws)[-300:],
        )
        checker.check(
            "记录文件此刻没有减少",
            len((work / "data" / "logs" / "operations.jsonl").read_text(encoding="utf-8").strip().splitlines()) == 3,
            "",
        )
        checker.check(
            "确认隐藏",
            click_when_enabled(ws, pump, "#dialog-root [data-action=confirmDialog]") == "ok",
            "",
        )
        checker.check(
            "列表里那条没了",
            wait_list(ws, pump, must_not=(AUTO_DETAIL,), seconds=12),
            body_text(ws)[-400:],
        )
        # r96：旧版的「删除所选」是隐藏，不是销毁审计行。
        checker.check(
            "文件里一行没少（删除=隐藏）",
            len((work / "data" / "logs" / "operations.jsonl").read_text(encoding="utf-8").strip().splitlines()) == 3,
            (work / "data" / "logs" / "operations.jsonl").read_text(encoding="utf-8")[:400],
        )
        hidden_file = work / "data" / "logs" / "operations.hidden.json"
        checker.check(
            "写了隐藏键集合",
            hidden_file.exists() and len(json.loads(hidden_file.read_text(encoding="utf-8"))) == 1,
            hidden_file.read_text(encoding="utf-8") if hidden_file.exists() else "missing",
        )
        # r96：勾上「显示旧版隐藏记录」→ 那行以「已隐藏（旧版）」回来，可逐条恢复。
        checker.check(
            "勾「显示旧版隐藏记录」",
            click_when_enabled(ws, pump, "[data-wf=history-show-hidden]") == "ok",
            "",
        )
        checker.check(
            "隐藏行重新出现并带标记",
            wait_list(ws, pump, must=("已隐藏（旧版）", AUTO_DETAIL), seconds=12),
            body_text(ws)[-400:],
        )
        checker.check(
            "点「恢复显示」",
            click_when_enabled(ws, pump, "[data-wf^='history-restore:']") == "ok",
            "",
        )
        checker.check(
            "恢复后不再有隐藏标记",
            wait_list(ws, pump, must=(AUTO_DETAIL,), must_not=("已隐藏（旧版）",), seconds=12),
            body_text(ws)[-400:],
        )
        checker.check(
            "隐藏键集合清空",
            json.loads(hidden_file.read_text(encoding="utf-8")) == [],
            hidden_file.read_text(encoding="utf-8"),
        )
        helpers.screenshot(ws, report_dir / "01-history-filters.png", report.get("shots", []))
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
        print(f"残留进程：{'有' if process is not None and process.poll() is None else '无'}", flush=True)
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
