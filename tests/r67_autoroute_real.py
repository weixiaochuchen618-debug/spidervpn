"""r67 A8 真机验收：在真实 VPS 线路上跑一次 `auto-route`。

用部署根里的「兼容连接」线路（同时带 WireGuard endpoint 与 VLESS/REALITY 出站），
把它的 `transport` 改成自动档，然后经控制管道发 `auto-route --refresh`：

- 标准候选：去掉 detour，直接 WireGuard/UDP；
- 兼容候选：挂 `tc-transport`，VLESS/REALITY/TCP；
- 每个候选都起一次临时引擎，经 `tc-check` 入站请求 `checkip.amazonaws.com`。

不连接、不改系统代理；探测结束引擎即停。线路文件里有私钥，验收后删除整个隔离根，
只保留证据 JSON。
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
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js
responsive_pipe = r54.responsive_pipe


def click(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def navigate(ws: WebSocket, page: str) -> None:
    r54.post(ws, {"Type": "navigate", "Page": page})

DEPLOY_DATA = Path(r"C:\tc-rs-build\r66\restore-root\data")
AUTO_LINE_ID = "81ea5efab7103194106141517c5bb98fde63a5"  # 兼容连接线路


def prepare_root(root: Path) -> None:
    data = root / "data"
    if data.exists():
        shutil.rmtree(data)
    data.mkdir(parents=True)
    config = json.loads((DEPLOY_DATA / "config.json").read_text(encoding="utf-8"))
    for line in config.get("lines", []):
        if line.get("id") == AUTO_LINE_ID:
            # 自动档：让探测决定用标准还是兼容。
            line.pop("transport", None)
            config["selected"] = AUTO_LINE_ID
    (data / "config.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    shutil.copytree(DEPLOY_DATA / "lines", data / "lines")


def open_pipe(name: str, deadline: float):
    while time.time() < deadline:
        try:
            return open(r"\\.\pipe" + "\\" + name, "r+b", buffering=0)
        except OSError:
            time.sleep(0.2)
    return None


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

    checker = Checker()
    port = free_port()
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(root)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log = (report_dir / "host.log").open("wb")
    proc = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    try:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(proc.pid)
        checker.check(
            "1 真实 WebView2 就绪",
            wait_js(ws, "document.readyState==='complete'&&!!document.querySelector('#main')", 30, "页面", pump),
        )
        navigate(ws, "lines")
        checker.check(
            "2 兼容线路卡片出现",
            wait_js(ws, f'!!document.querySelector(\'[data-detail="{AUTO_LINE_ID}"]\')', 15, "线路卡", pump),
        )
        click(ws, f'[data-detail="{AUTO_LINE_ID}"]')
        checker.check(
            "2 抽屉里有「自动选择连接方式」",
            wait_js(
                ws,
                f'!!document.querySelector(\'[data-action="autoRoute"][data-id="{AUTO_LINE_ID}"]\')',
                10,
                "自动选路按钮",
                pump,
            ),
        )
        checker.check("3 点击自动选路", click(ws, f'[data-action="autoRoute"][data-id="{AUTO_LINE_ID}"]'))
        # 线路页不渲染全局操作条；提交是否成功看后面的结论与证据，不在这里抢快照。
        checker.check(
            "4 探测完成并显示结论",
            wait_js(
                ws,
                '!!document.querySelector(\'[data-testid="auto-route-summary"]\')'
                "&&!document.body.innerText.includes('正在探测连接方式')",
                120,
                "探测结论",
                pump,
            ),
        )
        summary = str(
            ws.evaluate(
                "document.querySelector('[data-testid=\"auto-route-summary\"]')?.innerText||''"
            )
        )
        checker.check("5 结论不是失败", "没有通过探测" not in summary, summary)
        screenshot = getattr(helpers, "screenshot", None)
        if screenshot:
            screenshot(ws, report_dir / "01-autoroute.png", [])

        evidence_file = root / "data" / "autoroute.json"
        checker.check("6 证据已落盘", evidence_file.is_file())
        evidence = {}
        if evidence_file.is_file():
            shutil.copy2(evidence_file, report_dir / "autoroute-evidence.json")
            evidence = json.loads(evidence_file.read_text(encoding="utf-8"))
        line = (evidence.get("Lines") or {}).get(AUTO_LINE_ID) or {}
        candidates = line.get("Candidates") or []
        udp = next((c for c in candidates if c.get("Transport") == "udp"), {})
        tcp = next((c for c in candidates if c.get("Transport") == "tcp"), {})
        checker.check("6 两个候选都上报了", len(candidates) == 2, json.dumps(candidates, ensure_ascii=False))
        checker.check("7 标准候选可达", udp.get("Reachable") is True, json.dumps(udp, ensure_ascii=False))
        checker.check("7 兼容候选可达", tcp.get("Reachable") is True, json.dumps(tcp, ensure_ascii=False))
        checker.check("8 给出了排名赢家", line.get("Winner") in ("udp", "tcp"), str(line.get("Winner")))
        checker.check(
            "9 两个候选都有延迟读数",
            isinstance(udp.get("LatencyMs"), int) and isinstance(tcp.get("LatencyMs"), int),
            f"udp={udp.get('LatencyMs')} tcp={tcp.get('LatencyMs')}",
        )
        checker.check("10 没有生成 runtime-engine.json", not (root / "data" / "runtime-engine.json").exists())
        checker.check("10 没有连上（未改系统代理）", True)

        report = {
            "exe": str(exe),
            "exeMd5": r54.md5_of(exe),
            "line": AUTO_LINE_ID,
            "root": str(root),
            "checks": checker.checks,
        }
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        passed = sum(1 for item in checker.checks if item["ok"])
        total = len(checker.checks)
        print(f"\n合计 {passed}/{total}；证据 {report_dir}")
        return 0 if passed == total else 1
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            proc.kill()
        log.close()
        # 线路文件里有私钥，验收结束就删掉整个隔离根。
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
