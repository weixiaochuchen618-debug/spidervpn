#!/usr/bin/env python3
"""r107 真机界面：装好的 exe 上，「日常上网」下拉不可用的走向是不是真的置灰。

判据在宿主（`uiweb::daily_choices`），这里只看**用户屏幕上那一个控件**：
  - 现在已经登记的服务商为 0（`status.exitDailyMembers` 只有 direct + 一条交易线），
    所以「使用代理软件」必须 `disabled` 且文案里带「还没有登记代理软件」；
  - 「本地直连」「使用交易线路」可选，当前值被选中。

驱动方式与其它真机脚本一致：`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=N`
拉起装好的 exe，再用 CDP 点导航、读 DOM。**不靠坐标**。

用法：python tests/r107_daily_ui.py
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
READ = r"""
JSON.stringify([...document.querySelectorAll('#daily option')].map(o => ({
  value: o.value, text: o.textContent, disabled: o.disabled, selected: o.selected
})))
"""


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
        except Exception as error:  # noqa: BLE001 - 端口还没起来
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
        while time.monotonic() < deadline and not ws.evaluate("!!document.querySelector('[data-page=\"apps\"]')"):
            time.sleep(0.2)
        time.sleep(1.0)
        # 点侧栏「应用」（不靠坐标，走 DOM）
        ws.evaluate("(document.querySelector('[data-page=\"apps\"]')||{click(){}}).click(); true")
        time.sleep(1.2)
        raw = ws.evaluate(READ)
        opts = json.loads(raw) if isinstance(raw, str) else []
        by_value = {item["value"]: item for item in opts}
        checks.append(("下拉存在", bool(opts), opts))
        checks.append((
            "代理项置灰",
            by_value.get("Provider", {}).get("disabled") is True,
            by_value.get("Provider"),
        ))
        checks.append((
            "代理项写明原因",
            "还没有登记代理软件" in (by_value.get("Provider", {}).get("text") or ""),
            by_value.get("Provider"),
        ))
        checks.append(("本地直连可选", by_value.get("Direct", {}).get("disabled") is False, opts))
        checks.append(("交易线路可选", by_value.get("Trade", {}).get("disabled") is False,
                       by_value.get("Trade")))
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
