"""r67 界面验收：离线入口、按记录重试、自动选路投影。

真机上的离线交接与候选探测需要一台可登录的服务器；这条脚本用隔离根覆盖**界面这一侧**
能独立验证的部分：

1. 线路卡显示 `AutoRoute.Summary`（来自手写的 `autoroute.json` 证据）；
2. 首页「重试连接」真的发 `operation-retry`，并写出一条新记录（没有引擎时失败也可）；
3. 「添加线路 → 我有邀请码」里有「连不上 18443？用离线邀请」，切过去能看到邀请输入框；
4. 线路抽屉在非固定档显示「自动选择连接方式」，并显示证据摘要。

用法：

  python tests/r67_offline_retry_autoroute_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r67-ui
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import socket
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
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js
screenshot = helpers.screenshot
RUNTIME = r54.RUNTIME
md5_of = r54.md5_of
responsive_pipe = r54.responsive_pipe

LINE_ID = "L1"
OP_ID = "op-failed-connect"
NOW = "2026-11-11T00:00:00Z"


def click(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def page_has(ws: WebSocket, text: str, seconds: float = 8.0, pump: Pump | None = None) -> bool:
    expr = "document.body.innerText.includes(" + json.dumps(text, ensure_ascii=False) + ")"
    return wait_js(ws, expr, seconds, text[:24], pump)


def local_ipv4() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return ""
    finally:
        sock.close()


def prepare_root(root: Path) -> None:
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    config = {
        "schema": 2,
        "selected": LINE_ID,
        "lines": [
            {
                "id": LINE_ID,
                "name": "测试线路",
                "proxy_endpoint": "127.0.0.1:17901",
            }
        ],
    }
    (data / "config.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    logs = data / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "ui-operations.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.UiOperations",
                "Records": [
                    {
                        "Id": OP_ID,
                        "Kind": "Connect",
                        "Phase": "Failed",
                        "Message": "引擎没起来",
                        "Code": "EngineStartFailed",
                        "StartedAtUtc": NOW,
                        "StartedAtUnix": 1,
                        "FinishedAtUtc": NOW,
                        "Origin": "ui",
                    }
                ],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    fingerprint = local_ipv4()
    (data / "autoroute.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.AutoRoute",
                "Lines": {
                    LINE_ID: {
                        "NetworkFingerprint": fingerprint,
                        "CheckedAtUnix": int(time.time()),
                        "ExpiresAtUnix": int(time.time()) + 1800,
                        "Winner": "tcp",
                        "Candidates": [
                            {"Transport": "udp", "Reachable": True, "LatencyMs": 80,
                             "Error": "", "CheckedAtUnix": int(time.time())},
                            {"Transport": "tcp", "Reachable": True, "LatencyMs": 40,
                             "Error": "", "CheckedAtUnix": int(time.time())},
                        ],
                    }
                },
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def operation_records(root: Path) -> list[dict]:
    path = root / "data" / "logs" / "ui-operations.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    return value.get("Records", [])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    exe = Path(args.exe).resolve()
    root = report_dir / "root"
    prepare_root(root)

    live = responsive_pipe()
    if live:
        raise SystemExit(f"已经有一个 SpiderVPN 在跑（{live}），请先关掉它再跑这条验收。")
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    config_path = root / "data" / "config.json"
    before_config = md5_of(config_path)
    checker = Checker()
    report = {"exe": str(exe), "exeMd5": md5_of(exe), "shots": [], "checks": []}

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
    print(f"[probe] host pid={process.pid} cdp={port} root={root}", flush=True)
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
        checker.check("1 线路卡显示自动选路摘要", page_has(ws, "自动：兼容连接（40 ms）", 20, pump))
        checker.check(
            "2 首页出现「重试连接」",
            wait_js(ws, '!!document.querySelector(\'[data-action="retryOperation"][data-id="%s"]\')' % OP_ID, 10, "重试按钮", pump),
        )
        screenshot(ws, report_dir / "01-home.png", report["shots"])

        checker.check(
            "3 点「重试连接」",
            click(ws, '[data-action="retryOperation"][data-id="%s"]' % OP_ID),
        )
        # 没有引擎：重试会失败，但必须写出一条新记录（旧记录保持不变）。
        deadline = time.time() + 20
        records = operation_records(root)
        connects = [r for r in records if r.get("Kind") == "Connect"]
        def concluded(items: list[dict]) -> bool:
            return any(
                item.get("Id") != OP_ID and item.get("Phase") in ("Failed", "Succeeded")
                for item in items
            )
        while time.time() < deadline and not concluded(connects):
            time.sleep(0.2)
            records = operation_records(root)
            connects = [r for r in records if r.get("Kind") == "Connect"]
        checker.check(
            "3 重试写了一条新记录",
            any(r.get("Id") != OP_ID for r in connects),
        )
        checker.check("3 重试有结论（没有引擎时是 Failed）", concluded(connects))
        screenshot(ws, report_dir / "02-retry.png", report["shots"])

        # 线路抽屉：摘要 + 「自动选择连接方式」按钮都存在。
        checker.check("4 点开线路抽屉", click(ws, ".name-button"))
        checker.check(
            "4 抽屉显示自动选路摘要",
            wait_js(ws, '!!document.querySelector(\'[data-testid="auto-route-summary"]\')', 8, "摘要", pump),
        )
        checker.check(
            "4 抽屉有「自动选择连接方式」",
            bool(ws.evaluate('!!document.querySelector(\'[data-action="autoRoute"][data-id="L1"]\')')),
        )
        screenshot(ws, report_dir / "03-drawer.png", report["shots"])
        click(ws, "[data-close=drawer]")

        # 离线入口：添加线路 → 我有邀请码 → 连不上 18443？用离线邀请。
        click(ws, '[data-page="lines"]')
        checker.check(
            "5 线路页有「用邀请码加入」",
            wait_js(ws, '!!document.querySelector(\'[data-action="pairStart"]\')', 10, "加入入口", pump),
        )
        click(ws, '[data-action="pairStart"]')
        checker.check(
            "5 出现离线入口",
            wait_js(ws, '!!document.querySelector(\'[data-testid="pair-offline-entry"]\')', 10, "离线入口", pump),
        )
        checker.check(
            "6 切到离线交接",
            click(ws, '[data-testid="pair-offline-entry"]'),
        )
        checker.check(
            "6 离线邀请输入框与「读取邀请」都在",
            wait_js(
                ws,
                "!!document.getElementById('pair-offline-invite')&&document.body.innerText.includes('读取邀请')",
                10,
                "离线表单",
                pump,
            ),
        )
        screenshot(ws, report_dir / "04-offline.png", report["shots"])

        checker.check("7 配置没被改过", md5_of(config_path) == before_config)
        checker.check("7 没有新增 runtime.json", not RUNTIME.is_file())

        report["checks"] = checker.checks
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        passed = sum(1 for item in checker.checks if item["ok"])
        total = len(checker.checks)
        print(f"\n合计 {passed}/{total}；证据 {report_dir}")
        return 0 if passed == total else 1
    finally:
        try:
            process.terminate()
            process.wait(timeout=10)
        except Exception:  # noqa: BLE001
            process.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
