#!/usr/bin/env python3
"""r108 真机界面：线路设置页要有「补一条兼容连接」，点一下必须先问再发。

驱动方式与其它真机脚本一致（CDP，不靠坐标）。这里**不点确认**——真发命令会再去
SSH 一次；命令本身在 `line-add-compatible` 的冒烟里已经验过，这一支只验页面。

用法：python tests/r108_compat_ui.py
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
# 标准线路（部署出来的那条）——ID 与本机数据根里的线路文件一致。
STANDARD_LINE = "81ea5efab719222985100"


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
        while time.monotonic() < deadline and not ws.evaluate("!!document.querySelector('#main')"):
            time.sleep(0.2)
        time.sleep(1.0)
        # 打开「连接方式与网络…」（走宿主的 lineSettings 事件，不靠坐标）
        payload = json.dumps({"Type": "lineSettings", "Id": STANDARD_LINE}, ensure_ascii=False)
        ws.evaluate("window.chrome.webview.postMessage(" + json.dumps(payload) + "); true")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and "兼容连接（TCP）" not in (ws.evaluate("document.body.innerText") or ""):
            time.sleep(0.3)
        body = ws.evaluate("document.body.innerText") or ""
        checks.append(("页面有「兼容连接（TCP）」这一节", "兼容连接（TCP）" in body, body[-400:]))
        checks.append(("说明里写了前提", "本机保存着这台服务器的登录资料" in body, body[-400:]))
        add = ws.evaluate("!!document.querySelector('[data-wf=\"compat-add\"]')")
        checks.append(("有「补一条兼容连接…」按钮", bool(add), add))
        label = ws.evaluate(
            "(document.querySelector('[data-wf=\"compat-add\"]')||{}).innerText || ''"
        )
        checks.append(("按钮文案对得上", "补一条兼容连接" in (label or ""), label))

        ws.evaluate("(document.querySelector('[data-wf=\"compat-add\"]')||{click(){}}).click(); true")
        time.sleep(0.8)
        body = ws.evaluate("document.body.innerText") or ""
        checks.append(("点一下先问", "会改服务器配置" in body, body[-400:]))
        checks.append((
            "确认与取消都在",
            bool(ws.evaluate("!!document.querySelector('[data-wf=\"compat-yes\"]')"))
            and bool(ws.evaluate("!!document.querySelector('[data-wf=\"compat-no\"]')")),
            body[-400:],
        ))
        # 取消掉，别把页面留在确认态
        ws.evaluate("(document.querySelector('[data-wf=\"compat-no\"]')||{click(){}}).click(); true")
        time.sleep(0.5)
        checks.append((
            "取消后回到入口",
            bool(ws.evaluate("!!document.querySelector('[data-wf=\"compat-add\"]')"))
            and not ws.evaluate("!!document.querySelector('[data-wf=\"compat-yes\"]')"),
            None,
        ))
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
