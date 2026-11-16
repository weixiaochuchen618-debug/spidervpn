#!/usr/bin/env python3
"""r58 界面验收：C7「服务器」一览（只读）。

改动前：设置页只有「运行诊断 / 操作记录 / 维护与恢复」三张卡；这台电脑记录过的
服务器只能「从某条线路进去」看——换了线路就找不到了。

本脚本验的是入口真的接上了、页面真的显示了记录（读 DOM，不是读源码）：

1. 设置页出现「服务器」卡片；
2. 点开 → 页面标题「服务器」，列出这台电脑记录过的服务器（名称 + 地址）；
3. 隔离根里没有 `lines/`，所以每台服务器都显示「还没有线路用到它」——
   **0 条线路不是错**，刚部署完还没接入时就是这样；
4. 点「返回」回到设置页；
5. 收尾：用户配置 md5 不变、无残留进程。

## 数据来源

把**现场**的 `servers/` 目录复制进隔离根（只读复制，不动现场）。现场没有记录时
只验空态文案——两种都能跑，脚本不假设现场一定有服务器。

## 用法

  python tests/r58_servers_page_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r58-servers-page
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
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

LIVE_SERVERS = Path(r"C:\SpiderVPN\data\servers")
SETTINGS_CARD = '[data-action="servers"]'
FORM_READY = "!!document.querySelector('[data-wf=\"back\"]')"


def page_has(ws: WebSocket, text: str, seconds: float = 6.0, pump: Pump | None = None) -> bool:
    expr = "document.body.innerText.includes(" + json.dumps(text, ensure_ascii=False) + ")"
    return wait_js(ws, expr, seconds, text[:20], pump)


def click(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


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
    # 只读复制现场的服务器记录（不动现场）：有就验「能列出真实记录」，没有就验空态。
    copied = 0
    if LIVE_SERVERS.is_dir():
        for entry in LIVE_SERVERS.iterdir():
            if entry.is_dir() and (entry / "record.json").is_file():
                shutil.copytree(entry, root / "data" / "servers" / entry.name, dirs_exist_ok=True)
                copied += 1

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "dataRoot": root_info,
        "copiedServers": copied,
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
    print(f"[probe] host pid={process.pid} cdp={port} root={root} copied={copied}", flush=True)

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

        # ---------- 场景 1：设置页有入口 ----------
        post(ws, {"Type": "navigate", "Page": "settings"})
        checker.check(
            "1 设置页出现「服务器」卡片",
            wait_js(ws, f"!!document.querySelector('{SETTINGS_CARD}')", 15, "服务器卡片", pump),
        )
        checker.check("1 卡片文案是「服务器」", page_has(ws, "服务器", 3, pump))
        screenshot(ws, report_dir / "01-settings.png", report["shots"])

        # ---------- 场景 2：点开 ----------
        checker.check("2 点开「服务器」", click(ws, SETTINGS_CARD))
        checker.check("2 表单页出现（有返回按钮）", wait_js(ws, FORM_READY, 15, "服务器页", pump))
        checker.check("2 标题是「服务器」", page_has(ws, "这台电脑记录过的服务器", 8, pump))
        screenshot(ws, report_dir / "02-servers.png", report["shots"])

        # ---------- 场景 3：内容 ----------
        if copied:
            names = []
            for entry in (root / "data" / "servers").iterdir():
                record = entry / "record.json"
                if record.is_file():
                    try:
                        names.append(json.loads(record.read_text(encoding="utf-8")))
                    except json.JSONDecodeError:
                        continue
            checker.check("3 复制到了真实服务器记录", len(names) == copied, f"{len(names)}/{copied}")
            for record in names[:3]:
                name = str(record.get("Name") or "")
                host = str(record.get("Host") or "")
                checker.check(f"3 列出了「{name or host}」", page_has(ws, name or host, 6, pump))
                checker.check(f"3 给出了地址 {host}", page_has(ws, host, 6, pump))
            checker.check(
                "3 没有线路时显示「还没有线路用到它」（0 条不是错）",
                page_has(ws, "还没有线路用到它", 6, pump),
                "隔离根没有 lines/，关联数必然是 0",
            )
        else:
            checker.check(
                "3 没有记录时说明怎么才会有",
                page_has(ws, "还没有记录任何服务器", 6, pump),
            )

        # ---------- 场景 4：返回 ----------
        checker.check("4 点「返回」", click(ws, '[data-wf="back"]'))
        checker.check(
            "4 回到设置页（服务器卡片还在）",
            wait_js(ws, f"!!document.querySelector('{SETTINGS_CARD}')", 10, "回到设置页", pump),
        )
        screenshot(ws, report_dir / "03-back.png", report["shots"])

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
