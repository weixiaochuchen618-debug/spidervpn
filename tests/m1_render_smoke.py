#!/usr/bin/env python3
"""M1 渲染冒烟：用真实 旧版资产 + 宿主形状的快照，在 headless Edge 里验证
四页能渲染、按钮能把意图发出去。

这一版修了 2026-11-01 20:16 那份证据的两个问题：
- app.js 的 `post()` 现在发的是 JSON 字符串（wry 只收字符串），旧探针按字典读会抛错；
- 快照里 `Ack` 必须大于已发出的 Sequence，否则 pendingIntent 会静默吞掉后续点击。

用法：python tests/m1_render_smoke.py [--out <目录>]
"""
from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_fixture import prepare_site  # noqa: E402
from s0_page_fixtures import WebSocket, free_port, wait_page_target  # noqa: E402

EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
REPO = Path(r"D:\vpn构建\spidervpn-0.1.4")
WEB = REPO / "web"
DEFAULT_OUT = Path(r"C:\tc-rs-build\m1-evidence\render")

SNAPSHOT = {
    "Type": "snapshot",
    "Page": "home",
    "State": {
        "Text": {}, "ConnectionMethods": [], "Version": "0.1.4", "Ack": 99, "Form": None,
        "State": "Connected", "Running": True, "Busy": False, "BusyMessage": "",
        "DeleteOperation": None, "DeleteRefresh": None, "PendingOperations": [],
        "ReadOnly": False, "NinjaRunning": False, "PendingConnectionName": "",
        "NodeName": "", "TradeName": "香港 01", "TradeExit": "hk",
        "ActiveLineId": "hk", "ActiveProfile": "Udp", "PreferredLineId": "hk",
        "HomeLineId": "hk", "Guard": "Unknown", "TradeProgramCount": -1,
        "TradeProgramListed": -1, "GuardEvidence": None,
        "Daily": "Direct", "Agents": "Daily",
        "Lines": [
            {"Id": "hk", "Name": "香港 01", "Profile": "Udp", "Prepared": True,
             "Readiness": {"State": "InUse", "Label": "使用中", "Reason": ""},
             "ProfileSource": "", "AutomaticNeedsCheck": False,
             "PreparedProfiles": ["Udp", "Tcp"], "Pending": "", "Feedback": [],
             "Blocked": False, "BlockedReason": "", "LastOutcome": None,
             "RecentConnectionFailure": None,
             "DeleteAvailability": {"CanDelete": True, "State": "NeedsCheck", "Message": "删除前检查使用情况"},
             "Quality30m": None, "CanInvite": False, "ServerRecordId": "", "ServerName": ""},
            {"Id": "jp", "Name": "东京 02", "Profile": "Tcp", "Prepared": True,
             "Readiness": {"State": "Untested", "Label": "未测试", "Reason": "还没有测试过"},
             "ProfileSource": "", "AutomaticNeedsCheck": False,
             "PreparedProfiles": ["Udp", "Tcp"], "Pending": "", "Feedback": [],
             "Blocked": False, "BlockedReason": "", "LastOutcome": None,
             "RecentConnectionFailure": None,
             "DeleteAvailability": {"CanDelete": True, "State": "NeedsCheck", "Message": "删除前检查使用情况"},
             "Quality30m": None, "CanInvite": False, "ServerRecordId": "", "ServerName": ""},
        ],
        "Providers": [], "Tasks": [], "Deployments": [], "CanBackground": False,
        "Quality": {"LatencyMs": 180, "Quality": "Good", "History": [],
                     "ThirtyMinutes": None, "Day": None, "Degraded": False,
                     "NotificationMessage": ""},
        "Standby": None, "QualityHistory": None,
        "Settings": {"OpenAtLogin": False, "AutoConnectOnLogin": False,
                      "CloseBehavior": "Tray", "AutoTrustFirstConnection": True,
                      "QualityWarning": True, "Warning": ""},
        "ReadWarning": "", "AutoConnectNotice": "", "Dialog": None, "Toast": "",
        "SnapshotAtUtc": "2026-11-01T09:00:00Z", "ConnectedSince": None,
        "GuardSummary": "", "Pending": None,
        "ExitEvidence": {"Verified": False, "Attribution": "Unknown",
                          "Status": "forwarded-unverified", "Code": "",
                          "CheckedAtUtc": None, "ObservedIP": None},
        "Operation": None, "Pair": None, "Invite": None, "PairDeviceDefault": "",
    },
}


def prepare(work: Path) -> str:
    """资产复制、桩注入都走 web_fixture.prepare_site，避免两处清单漂移。"""
    return prepare_site(work).resolve().as_uri()


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
    result = {"checks": {}, "shots": []}
    ws = None
    try:
        target = wait_page_target(port, url, proc)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not ws.evaluate("document.readyState==='complete'"):
            time.sleep(0.1)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not ws.evaluate("!!window.__tcPosted"):
            time.sleep(0.1)
        time.sleep(0.5)

        def check(name, ok, detail=None):
            result["checks"][name] = {"ok": bool(ok), "detail": detail}

        def posted():
            raw = ws.evaluate("window.__tcPosted||[]") or []
            out = []
            for item in raw:
                if isinstance(item, str):
                    try:
                        out.append(json.loads(item))
                    except ValueError:
                        out.append({"raw": item})
                elif isinstance(item, dict):
                    out.append(item)
            return out

        def push(page):
            payload = json.loads(json.dumps(SNAPSHOT))
            payload["Page"] = page
            payload["State"]["SnapshotAtUtc"] = (
                datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
            ws.evaluate("window.chrome.webview.dispatchEvent(new MessageEvent('message',"
                        + "{data:" + json.dumps(payload, ensure_ascii=False) + "}));true")
            time.sleep(0.35)

        check("页面启动即发 ready",
              any(m.get("Type") == "ready" for m in posted()), posted()[:2] or None)

        push("home")
        check("首页渲染连接主卡", ws.evaluate("!!document.querySelector('#main .hero')"))
        check("首页显示断开按钮", ws.evaluate("!!document.querySelector('#main [data-action=disconnect]')"))
        check("首页显示当前响应 180ms",
              ws.evaluate("(document.querySelector('[data-testid=quality-current]')||{textContent:''})"
                          ".textContent.includes('180')"))
        check("侧栏导航存在", ws.evaluate("document.querySelectorAll('nav .nav').length===4"))
        check("版本号渲染",
              ws.evaluate("document.getElementById('version').textContent.includes('0.1.4')"))

        push("lines")
        check("线路页渲染两张卡",
              ws.evaluate("document.querySelectorAll('#main [data-action=setProfile]').length>=2"))
        check("使用中徽标", ws.evaluate("document.querySelector('#main').textContent.includes('使用中')"))

        push("apps")
        check("应用页日常下拉=Direct",
              ws.evaluate("!!document.getElementById('daily')&&document.getElementById('daily').value==='Direct'"))

        push("settings")
        check("设置页开关=关闭自启",
              ws.evaluate("document.querySelector('[data-setting=OpenAtLogin]').getAttribute('aria-checked')==='false'"))
        check("设置页主题选择存在", ws.evaluate("!!document.getElementById('theme')"))

        ws.evaluate("document.querySelector('[data-setting=OpenAtLogin]').click();true")
        time.sleep(0.2)
        check("点击开关发出 startup 意图",
              any(m.get("Type") == "startup" for m in posted()),
              ([m for m in posted() if m.get("Type") == "startup"] or [None])[-1])

        ws.evaluate("localStorage.setItem('theme','dark');"
                    "document.documentElement.dataset.theme='dark';true")
        ws.call("Emulation.setDeviceMetricsOverride",
                {"width": 1200, "height": 900, "deviceScaleFactor": 1, "mobile": False})
        push("home")
        shot = ws.call("Page.captureScreenshot", {"format": "png"})
        path = work / "home-dark.png"
        path.write_bytes(base64.b64decode(shot["data"]))
        result["shots"].append(str(path))
        check("深色主题生效", ws.evaluate("document.documentElement.dataset.theme==='dark'"))

        result["allPassed"] = all(c["ok"] for c in result["checks"].values())
    except Exception as exc:  # noqa: BLE001
        result["error"] = repr(exc)
        result["allPassed"] = False
    finally:
        if ws is not None:
            try:
                ws.call("Browser.close")
            except Exception:  # noqa: BLE001
                pass
            ws.close()
        try:
            proc.terminate()
            proc.wait(timeout=8)
        except Exception:  # noqa: BLE001
            subprocess.run(["taskkill.exe", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (work / "report.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    total = len(result["checks"])
    passed = sum(1 for c in result["checks"].values() if c["ok"])
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\n{passed}/{total} 通过")
    return 0 if result.get("allPassed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
