#!/usr/bin/env python3
"""r66 界面验收：删除本机服务器记录（C7）。

- 还有线路用到它时：确认卡只说明「先删线路」，**不给确认按钮**；
- 线路删掉后重开页面：确认删除 → 记录目录消失、页面提示已删除；
- 全程用户 config.json 一个字节不动。

用法：

  python tests/r66_server_remove_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir C:\\tc-rs-build\\r66\\server-remove
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")
r65 = importlib.import_module("r65_servers_rename_ui")

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
page_has = r65.page_has
click = r65.click

SERVER_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"


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
    server_dir = root / "data" / "servers" / SERVER_ID
    server_dir.mkdir(parents=True, exist_ok=True)
    (server_dir / "record.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ServerRecord",
                "Id": SERVER_ID,
                "Name": "东京节点",
                "Host": "203.0.113.10",
                "Port": 22,
                "User": "root",
                "Fingerprint": "SHA256:abcdefghijkl",
                "CreatedAtUtc": "2026-11-11T10:00:00Z",
                "UpdatedAtUtc": "2026-11-11T10:00:00Z",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    lines_dir = root / "data" / "lines"
    lines_dir.mkdir(parents=True, exist_ok=True)
    line_path = lines_dir / "L1.json"
    line_path.write_text(
        json.dumps({"outbounds": [{"type": "wireguard", "server": "203.0.113.10"}]}),
        encoding="utf-8",
    )

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "dataRoot": root_info,
        "shots": [],
        "checks": [],
    }
    port = free_port()
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(root)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log = (report_dir / "host.log").open("wb")
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
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
        post(ws, {"Type": "navigate", "Page": "settings"})
        checker.check(
            "1 设置页出现「服务器」卡片",
            wait_js(ws, '!!document.querySelector(\'[data-action="servers"]\')', 15, "服务器卡片", pump),
        )
        checker.check("1 点开「服务器」", click(ws, '[data-action="servers"]'))
        checker.check(
            "1 服务器页出现",
            wait_js(ws, "!!document.querySelector('[data-wf=\"back\"]')", 15, "服务器页", pump),
        )
        checker.check("1 列出记录", page_has(ws, "东京节点", 8, pump))

        checker.check(
            "2 点「删除记录」",
            click(ws, f'[data-wf="server-remove:{SERVER_ID}"]'),
        )
        checker.check(
            "2 有线路时说明要先删线路",
            page_has(ws, "还有 1 条线路用到它", 8, pump),
        )
        checker.check(
            "2 有线路时不给确认按钮",
            not bool(ws.evaluate("!!document.querySelector('[data-wf=\"confirm-server-remove\"]')")),
        )
        checker.check(
            "2 点「取消」回到列表",
            click(ws, '[data-wf="cancel-server-remove"]')
            and wait_js(ws, "!document.querySelector('[data-wf=\"confirm-server-remove\"]')", 8, "取消", pump),
        )
        checker.check("2 记录还在", server_dir.is_dir())
        screenshot(ws, report_dir / "01-blocked.png", report["shots"])

        # 删掉线路文件后重开页面：服务器页重新查一次归属，才能给出确认。
        line_path.unlink()
        checker.check("3 返回设置页", click(ws, '[data-wf="back"]'))
        checker.check(
            "3 重新打开「服务器」",
            wait_js(ws, '!!document.querySelector(\'[data-action="servers"]\')', 10, "设置页", pump)
            and click(ws, '[data-action="servers"]'),
        )
        checker.check(
            "3 页面重新列出记录",
            wait_js(ws, "!!document.querySelector('[data-wf=\"back\"]')", 15, "服务器页", pump)
            and page_has(ws, "东京节点", 8, pump),
        )
        checker.check(
            "3 点「删除记录」",
            click(ws, f'[data-wf="server-remove:{SERVER_ID}"]'),
        )
        checker.check(
            "3 无线路时给确认按钮",
            wait_js(ws, "!!document.querySelector('[data-wf=\"confirm-server-remove\"]')", 8, "确认按钮", pump),
        )
        checker.check("3 点「删除记录」确认", click(ws, '[data-wf="confirm-server-remove"]'))
        checker.check(
            "3 页面说已删除",
            page_has(ws, "已删除服务器记录", 15, pump),
        )
        checker.check("3 磁盘记录目录真的删了", not server_dir.exists())
        screenshot(ws, report_dir / "02-deleted.png", report["shots"])

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
