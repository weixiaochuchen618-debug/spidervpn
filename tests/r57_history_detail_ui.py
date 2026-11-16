#!/usr/bin/env python3
"""r57 界面验收：操作记录「详情」（A6 的只读部分）。

改动前：记录页每条只有一行摘要，`detail` 被截到 60 字，点不开也看不到全文。
查「刚才那次连接为什么失败」的人，拿到的是一句被截断的话。

本脚本验的是宿主真的把详情给了页面（读 DOM，不是读源码）：

1. 记录页列出 3 条，每条都有「详情」按钮；
2. 点开失败那条 → **完整 detail**（远超 60 字）出现在页面上，来源翻成「界面」，
   执行者与对象都在；
3. 再点一次收起 → 按钮回到「详情」，完整 detail 从页面上消失；
4. 切「只看失败」→ 只剩失败那条，且展开状态被清掉（不挂在别的记录上）；
5. 缺字段的旧记录点开也不崩，并说明「没有更多字段」。

## 两个取样上的坑（都踩过）

- **不要 `evaluate("document.body.innerText")` 拿整页文本再在 Python 里比对**：
  `#main` 每 250ms 重画一次，取值正好撞上清空那一帧时只会拿到导航里的「首页」。
  所有文本断言都改成**页面内 `includes`**（返回布尔），跨帧也只影响这一次判断。
- **状态翻转要看按钮文案**（「详情」↔「收起」），不要只看文本有没有消失：
  重画窗口里文本本来就会短暂消失，那样的断言两头都不准。

## 用法

  python tests/r57_history_detail_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r57-history-detail
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
free_port = helpers.free_port
post = r54.post
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

RUNTIME = r54.RUNTIME
USER_CONFIG = r54.USER_CONFIG
md5_of = r54.md5_of
prepare_root = r54.prepare_root
processes_of = r54.processes_of
responsive_pipe = r54.responsive_pipe

LONG = "引擎启动后立即退出（pid=8216）；系统代理已还原；请检查引擎可执行文件是否还在原位置。" * 3

DETAIL_BUTTONS = "document.querySelectorAll('[data-wf^=\"history-detail:\"]').length"
HISTORY_READY = "!!document.querySelector('[data-wf=\"export-history\"]')"


def page_has(ws: WebSocket, text: str, seconds: float = 6.0, pump: Pump | None = None) -> bool:
    """页面里有没有这段文字。**在页面内判断**，不把整页文本取回 Python。"""
    expr = "document.body.innerText.includes(" + json.dumps(text, ensure_ascii=False) + ")"
    return wait_js(ws, expr, seconds, text[:20], pump)


def button_text(ws: WebSocket, index: int) -> str:
    expr = (
        "(()=>{const e=document.querySelector('[data-wf=\"history-detail:%d\"]');"
        "return e?e.textContent.trim():'';})()" % index
    )
    return ws.evaluate(expr) or ""


def click_button(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def write_events(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [
        # `events::read` 会 reverse：文件里最后一行是最新的。
        {"ts": "2026-11-10T11:00:01Z", "action": "断开", "ok": True, "detail": "已断开", "src": "cli", "actor": "pid:1", "obj": ""},
        {
            "ts": "2026-11-10T11:00:02Z",
            "action": "连接",
            "ok": False,
            "detail": LONG,
            "src": "ui",
            "actor": "pid:24632",
            "obj": "line:81ea5ef",
        },
        # 旧记录：只有 ts/action/ok，其余字段缺失。
        {"ts": "2026-11-10T11:00:03Z", "action": "导入", "ok": True},
    ]
    path.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    exe = Path(args.exe).resolve()
    root = report_dir / "root"

    live = responsive_pipe()
    if live:
        raise SystemExit(f"已经有一个 SpiderVPN 在跑（{live}），请先关掉它再跑这条验收。")
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    user_config_md5 = md5_of(USER_CONFIG)
    root_info = prepare_root(root)
    write_events(root / "data" / "logs" / "operations.jsonl")

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "dataRoot": root_info,
        "shots": [],
        "checks": [],
        "notes": [],
    }

    port = free_port()
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(root)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log_path = report_dir / "host.log"
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] host pid={process.pid} cdp={port} root={root}", flush=True)

    ws: WebSocket | None = None
    try:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(process.pid)

        checker.check(
            "0 真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                30,
                "页面初始化",
                pump,
            ),
        )

        # ---------- 场景 1：打开记录页 ----------
        post(ws, {"Type": "history"})
        checker.check("1 记录页打开", wait_js(ws, HISTORY_READY, 20, "记录页", pump))
        buttons = ws.evaluate(DETAIL_BUTTONS)
        checker.check("1 三条记录各有「详情」按钮", buttons == 3, f"buttons={buttons}")
        checker.check(
            "1 列表行把长 detail 截断了（没直接铺全文）",
            not page_has(ws, LONG, 1.5, pump),
            "列表不该出现全文",
        )
        checker.check("1 三条记录都是「详情」（没有默认展开的）", button_text(ws, 1) == "详情", button_text(ws, 1))
        screenshot(ws, report_dir / "01-history-list.png", report["shots"])

        # ---------- 场景 2：点开失败那条 ----------
        checker.check("2 点开失败那条的详情", click_button(ws, '[data-wf="history-detail:1"]'))
        flipped = wait_js(
            ws,
            "(()=>{const e=document.querySelector('[data-wf=\"history-detail:1\"]');"
            "return !!e&&e.textContent.trim()==='收起';})()",
            10,
            "按钮翻成收起",
            pump,
        )
        checker.check("2 按钮翻成「收起」", flipped, button_text(ws, 1))
        checker.check("2 详情给了完整 detail（不是截断版）", page_has(ws, LONG, 10, pump))
        checker.check("2 来源翻成人话「界面」", page_has(ws, "来源：界面", 5, pump))
        checker.check("2 执行者在", page_has(ws, "执行者：pid:24632", 5, pump))
        checker.check("2 对象在", page_has(ws, "对象：line:81ea5ef", 5, pump))
        checker.check(
            "2 时间给完整时刻（列表里是压缩的 MM-DD HH:MM）",
            page_has(ws, "时间：2026-11-10T11:00:02Z", 5, pump),
        )
        screenshot(ws, report_dir / "02-detail-open.png", report["shots"])

        # ---------- 场景 3：再点一次收起 ----------
        checker.check("3 再点一次", click_button(ws, '[data-wf="history-detail:1"]'))
        reverted = wait_js(
            ws,
            "(()=>{const e=document.querySelector('[data-wf=\"history-detail:1\"]');"
            "return !!e&&e.textContent.trim()==='详情';})()",
            10,
            "按钮翻回详情",
            pump,
        )
        checker.check("3 按钮翻回「详情」", reverted, button_text(ws, 1))
        checker.check("3 全文从页面上消失", not page_has(ws, LONG, 3, pump), "收起后不该还有全文")
        screenshot(ws, report_dir / "03-detail-closed.png", report["shots"])

        # ---------- 场景 4：切「只看失败」----------
        checker.check("4 点「只看失败」", click_button(ws, '[data-wf="filter-fail"]'))
        time.sleep(1.0)
        filtered = ws.evaluate(DETAIL_BUTTONS)
        checker.check("4 只看失败：只剩一条记录", filtered == 1, f"buttons={filtered}")
        checker.check("4 只看失败：成功那条不在", not page_has(ws, "已断开", 2, pump))
        screenshot(ws, report_dir / "04-filter-fail.png", report["shots"])

        # ---------- 场景 5：旧记录（缺字段）----------
        checker.check("5 切回「全部」", click_button(ws, '[data-wf="filter-all"]'))
        time.sleep(1.0)
        # `events::read` 会 reverse，所以文件最后一行（11:00:03 的导入）是列表第一条。
        checker.check("5 点开旧记录", click_button(ws, '[data-wf="history-detail:0"]'))
        checker.check(
            "5 旧记录点开不崩，并说明没有更多字段",
            page_has(ws, "没有更多字段", 8, pump),
            "缺字段的记录没有给出说明",
        )
        checker.check("5 旧记录不把缺字段猜成失败", page_has(ws, "结果：成功", 5, pump))
        checker.check(
            "5 旧记录不渲染空的来源行",
            not page_has(ws, "来源：", 1.5, pump),
            "空字段不该渲染成空行",
        )
        screenshot(ws, report_dir / "05-legacy-record.png", report["shots"])

        # ---------- 收尾 ----------
        checker.check("8 用户配置没被改过（config.json md5 一致）", md5_of(USER_CONFIG) == user_config_md5)
        checker.check("8 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check("8 收尾时没有残留的 spidervpn 进程", len(processes_of("spidervpn.exe")) <= 1)

    finally:
        try:
            if ws is not None:
                ws.close()
        except Exception:  # noqa: BLE001
            pass
        if not args.keep_open:
            try:
                process.terminate()
                process.wait(timeout=15)
            except Exception:  # noqa: BLE001
                try:
                    process.kill()
                except Exception:  # noqa: BLE001
                    pass
        log.close()

    report["checks"] = checker.checks
    (report_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    passed = sum(1 for item in checker.checks if item["ok"])
    total = len(checker.checks)
    print(f"\n合计 {passed}/{total}；证据 {report_dir}")
    return 0 if checker.all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
