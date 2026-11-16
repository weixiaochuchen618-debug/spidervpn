#!/usr/bin/env python3
"""r109 真机界面：线路页底部的「交易名单」摘要 + 「管理交易域名…」入口。

对齐 旧版的`Pages.ps1:398`：只读三组（程序 / 网站 / 辅助解析）+ 一颗进名单页的按钮。
本机现有名单正好可当夹具：1 个程序（Mirasim.exe，带完整路径）+ 7 个交易域名，`aux` 为空。

用法：python tests/r109_tradelist_ui.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s0_page_fixtures import WebSocket, free_port  # noqa: E402

EXE = Path(r"C:\SpiderVPN\bin\spidervpn.exe")


def find_page(port: int, timeout: float = 25.0) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as response:
                targets = json.loads(response.read().decode("utf-8"))
            for target in targets:
                if target.get("type") == "page" and "tc.ui" in (target.get("url") or ""):
                    return target
            last = targets
        except Exception as error:  # noqa: BLE001
            last = str(error)
        time.sleep(0.5)
    raise SystemExit(f"等不到界面目标：{last}")


def main() -> int:
    subprocess.run(["taskkill", "/IM", "spidervpn.exe", "/F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    proc = subprocess.Popen([str(EXE)], cwd=str(EXE.parent), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    checks: list[tuple[str, bool, object]] = []
    try:
        target = find_page(port)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not ws.evaluate("!!document.querySelector('[data-page=\"lines\"]')"):
            time.sleep(0.2)
        ws.evaluate("(document.querySelector('[data-page=\"lines\"]')||{click(){}}).click(); true")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and "交易名单" not in (ws.evaluate("(document.querySelector('#main')||document.body).innerText") or ""):
            time.sleep(0.3)
        body = ws.evaluate("(document.querySelector('#main')||document.body).innerText") or ""
        checks.append(("线路页有「交易名单」", "交易名单" in body, body[-600:]))
        checks.append(("副标题在", "这些流量始终走交易线路" in body, body[-400:]))
        checks.append(("有「管理交易域名…」按钮", "管理交易域名" in body, body[-400:]))

        # 程序组：正文是名字，完整路径在 title
        chip = ws.evaluate(
            "(() => { const s=[...document.querySelectorAll('#main .badge')]"
            ".find(x => (x.textContent||'').trim() === 'Mirasim.exe');"
            "return s ? JSON.stringify({text:s.textContent.trim(), title:s.getAttribute('title')||''}) : ''; })()"
        )
        chip = json.loads(chip) if chip else {}
        checks.append(("程序 chip 显示名字", chip.get("text") == "Mirasim.exe", chip))
        checks.append(("程序 chip 的 title 是完整路径",
                       str(chip.get("title", "")).lower().endswith("mirasim.exe"), chip))

        # 网站组
        domains = ws.evaluate(
            "[...document.querySelectorAll('#main .badge')].map(x => (x.textContent||'').trim())"
        ) or []
        checks.append(("网站 chip 有 tradingview.com", "tradingview.com" in domains, domains))
        checks.append(("网站 chip 有 ninjatrader.com", "ninjatrader.com" in domains, domains))

        # 辅助解析：本版恒空，整行不该出现
        checks.append(("空组（辅助解析）整行不显示", "辅助解析" not in body, body[-600:]))

        # 入口动作名：与应用页那颗是同一个 `domains`
        actions = ws.evaluate(
            "[...document.querySelectorAll('#main button[data-action=\"domains\"]')]"
            ".map(b => (b.textContent||'').trim())"
        ) or []
        checks.append(("按钮动作是 domains", "管理交易域名…" in actions, actions))

        # 点进去：同一页名单（标题「交易软件名单」）
        ws.evaluate("(document.querySelector('#main button[data-action=\"domains\"]')||{click(){}}).click(); true")
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline and "交易软件名单" not in (ws.evaluate("(document.querySelector('#main')||document.body).innerText") or ""):
            time.sleep(0.3)
        after = ws.evaluate("(document.querySelector('#main')||document.body).innerText") or ""
        checks.append(("按钮打开名单页", "交易软件名单" in after, after[:300]))
        checks.append(("名单页有交易网站卡", "交易网站" in after, after[:400]))
    finally:
        try:
            proc.terminate()
        except Exception:  # noqa: BLE001
            pass
        time.sleep(1.0)
        subprocess.run(["taskkill", "/IM", "spidervpn.exe", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    failed = [name for name, ok, _ in checks if not ok]
    for name, ok, detail in checks:
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  → {detail}"))
    print(f"\n{len(checks) - len(failed)}/{len(checks)} 通过")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
