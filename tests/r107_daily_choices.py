#!/usr/bin/env python3
"""r107：「日常上网」下拉不可用的走向必须当场置灰并给出原因。

判据在宿主（`uiweb::daily_choices` → 快照 `DailyChoices`），这里验的是**页面那一半**：
拿到带 `Available:false` 的选项时，是不是真的 `disabled` 且把原因写在文案里。
再推一帧「宿主没给 DailyChoices」的旧快照，确认退回静态三项、不至于空下拉。

用法：python tests/r107_daily_choices.py [--out <目录>]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from m1_render_smoke import EDGE, SNAPSHOT, prepare  # noqa: E402
from s0_page_fixtures import WebSocket, free_port, wait_page_target  # noqa: E402

DEFAULT_OUT = Path(r"C:\tc-rs-build\m1-evidence\r107")

READ_OPTIONS = r"""
JSON.stringify([...document.querySelectorAll('#daily option')].map(o => ({
  value: o.value, text: o.textContent, disabled: o.disabled, selected: o.selected
})))
"""


def push(ws: WebSocket, state: dict, page: str = "apps") -> None:
    payload = json.loads(json.dumps(SNAPSHOT))
    payload["Page"] = page
    payload["State"].update(state)
    payload["State"]["Ack"] = 999
    ws.evaluate(
        "window.chrome.webview.dispatchEvent(new MessageEvent('message',"
        + "{data:" + json.dumps(payload, ensure_ascii=False) + "}));true"
    )
    time.sleep(0.4)


def options(ws: WebSocket) -> list[dict]:
    raw = ws.evaluate(READ_OPTIONS)
    return json.loads(raw) if isinstance(raw, str) else []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()
    work = Path(args.out)
    url = prepare(work)
    port = free_port()
    proc = subprocess.Popen(
        [str(EDGE), "--headless=new", "--disable-gpu", "--no-sandbox",
         "--disable-extensions", "--no-first-run", "--hide-scrollbars",
         f"--remote-debugging-port={port}", "--remote-allow-origins=*",
         f"--user-data-dir={work / 'profile'}", url],
        cwd="C:\\", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    checks: list[tuple[str, bool, object]] = []
    try:
        target = wait_page_target(port, url, proc)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not ws.evaluate("document.readyState==='complete'"):
            time.sleep(0.1)
        while time.monotonic() < deadline and not ws.evaluate("!!window.__tcPosted"):
            time.sleep(0.1)
        time.sleep(0.5)

        # 1) 没有服务商、有交易出口：代理项必须置灰并写明原因
        push(ws, {"Daily": "Direct", "DailyChoices": [
            {"Value": "Direct", "Label": "本地直连", "Available": True, "Reason": ""},
            {"Value": "Provider", "Label": "使用代理软件", "Available": False,
             "Reason": "还没有登记代理软件"},
            {"Value": "Trade", "Label": "使用交易线路", "Available": True, "Reason": ""},
        ]})
        opts = options(ws)
        checks.append(("三项都在", len(opts) == 3, opts))
        by_value = {item["value"]: item for item in opts}
        checks.append(("本地直连可选", by_value.get("Direct", {}).get("disabled") is False, opts))
        checks.append((
            "代理项置灰",
            by_value.get("Provider", {}).get("disabled") is True,
            by_value.get("Provider"),
        ))
        checks.append((
            "代理项写明原因",
            "还没有登记代理软件" in (by_value.get("Provider", {}).get("text") or ""),
            by_value.get("Provider", {}).get("text"),
        ))
        checks.append(("交易线路可选", by_value.get("Trade", {}).get("disabled") is False, opts))
        checks.append(("当前值被选中", by_value.get("Direct", {}).get("selected") is True, opts))

        # 2) 只有直连：交易线路也要置灰
        push(ws, {"Daily": "Direct", "DailyChoices": [
            {"Value": "Direct", "Label": "本地直连", "Available": True, "Reason": ""},
            {"Value": "Provider", "Label": "使用代理软件", "Available": False,
             "Reason": "还没有登记代理软件"},
            {"Value": "Trade", "Label": "使用交易线路", "Available": False,
             "Reason": "这条线路没有交易出口"},
        ]})
        opts = options(ws)
        by_value = {item["value"]: item for item in opts}
        checks.append((
            "没有交易出口时置灰",
            by_value.get("Trade", {}).get("disabled") is True,
            by_value.get("Trade"),
        ))
        checks.append((
            "并写明原因",
            "这条线路没有交易出口" in (by_value.get("Trade", {}).get("text") or ""),
            by_value.get("Trade", {}).get("text"),
        ))

        # 3) 旧快照（宿主没给 DailyChoices）：退回静态三项，不能空
        push(ws, {"Daily": "Direct", "DailyChoices": None})
        opts = options(ws)
        checks.append((
            "没有可用性数据时退回静态三项",
            [item["value"] for item in opts] == ["Direct", "Provider", "Trade"],
            opts,
        ))
        checks.append(("退回时三项都可选", all(not item["disabled"] for item in opts), opts))
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    failed = [name for name, ok, _ in checks if not ok]
    for name, ok, detail in checks:
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  → {detail}"))
    print(f"\n{len(checks) - len(failed)}/{len(checks)} 通过")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
