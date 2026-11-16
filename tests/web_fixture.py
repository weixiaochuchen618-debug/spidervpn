#!/usr/bin/env python3
"""把 `web/` 变成可驱动的站点：真实资产 + `chrome.webview` 桩 + 快照注入。

新前端（旧版的`web/`）的页面只认 `chrome.webview` 的 message 事件，不认旧自建页面的
`__tcApply`。所以夹具要：
1. 复制 `web/` 真实资产到临时目录（CSP `script-src 'self'` 要求每个文件都是独立路径）；
2. 在 `app.js` 之前插一个 `stub.js`，提供 `postMessage` 与 `EventTarget`；
3. 用 CDP 往页面里 dispatch `{Type:'snapshot', Page, State}`。

`Ack` 必须大于页面已发出的 Sequence，否则 app.js 的 `pendingIntent` 会静默吞掉后续
点击（真宿主每处理一条就递增 Ack）。这里的 `push()` 统一填一个足够大的值。
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from s0_page_fixtures import WebSocket, free_port, wait_page_target

EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "web"

STUB = (
    "window.chrome={webview:Object.assign(new EventTarget(),{"
    "postMessage:function(m){(window.__tcPosted=window.__tcPosted||[]).push(m);},"
    "postMessageWithAdditionalObjects:function(m,o){(window.__tcPosted=window.__tcPosted||[]).push(m);}})};"
)


def prepare_site(work: Path) -> Path:
    """复制资产并注入桩，返回 index.html 路径。"""
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    for item in sorted(WEB.iterdir()):
        if item.is_file():
            shutil.copy2(item, work / item.name)
    (work / "stub.js").write_text(STUB, encoding="utf-8")
    index = (work / "index.html").read_text(encoding="utf-8")
    marker = '<script src="theme-boot.js"></script>'
    assert marker in index, "index.html 里找不到 theme-boot 引用"
    index = index.replace(marker, marker + '\n  <script src="stub.js"></script>')
    (work / "index.html").write_text(index, encoding="utf-8")
    return work / "index.html"


def make_state(**overrides) -> dict:
    """一份完整的 旧版State。用例用 `make_state(Running=False)` 覆盖需要的字段。"""
    state = {
        "Text": {}, "ConnectionMethods": [], "Version": "0.1.4", "Ack": 999, "Form": None,
        "State": "Connected", "Running": True, "Busy": False, "BusyMessage": "",
        "DeleteOperation": None, "DeleteRefresh": None, "PendingOperations": [],
        "ReadOnly": False, "NinjaRunning": False, "PendingConnectionName": "",
        "NodeName": "", "TradeName": "香港 01", "TradeExit": "hk",
        "ActiveLineId": "hk", "ActiveProfile": "Udp", "PreferredLineId": "hk",
        "HomeLineId": "hk", "Guard": "Unknown", "TradeProgramCount": -1,
        "TradeProgramListed": -1, "GuardEvidence": None,
        # `Agents` = 实际生效的走向，`AgentsStored` = 配置里存的值（宿主两个都给）。
        "Daily": "Direct", "Agents": "Daily", "AgentsStored": "Daily",
        "Lines": [
            {"Id": "hk", "Name": "香港 01", "Profile": "Udp", "Prepared": True,
             "Readiness": {"State": "InUse", "Label": "使用中", "Reason": ""},
             "ProfileSource": "", "AutomaticNeedsCheck": False,
             "PreparedProfiles": ["Udp", "Tcp"], "Pending": "", "Feedback": [],
             "Blocked": False, "BlockedReason": "", "LastOutcome": None,
             "RecentConnectionFailure": None,
             "DeleteAvailability": {"CanDelete": True, "State": "NeedsCheck",
                                    "Message": "删除前检查使用情况"},
             "Quality30m": None, "CanInvite": False, "ServerRecordId": "", "ServerName": ""},
            {"Id": "jp", "Name": "东京 02", "Profile": "Tcp", "Prepared": True,
             "Readiness": {"State": "Untested", "Label": "未测试", "Reason": "还没有测试过"},
             "ProfileSource": "", "AutomaticNeedsCheck": False,
             "PreparedProfiles": ["Udp", "Tcp"], "Pending": "", "Feedback": [],
             "Blocked": False, "BlockedReason": "", "LastOutcome": None,
             "RecentConnectionFailure": None,
             "DeleteAvailability": {"CanDelete": True, "State": "NeedsCheck",
                                    "Message": "删除前检查使用情况"},
             "Quality30m": None, "CanInvite": False, "ServerRecordId": "", "ServerName": ""},
        ],
        "Providers": [], "Tasks": [], "Deployments": [], "CanBackground": False,
        "Quality": {"LatencyMs": 180, "Quality": "Good", "History": [],
                    "ThirtyMinutes": None, "Day": None, "Degraded": False,
                    "NotificationMessage": ""},
        "Standby": None, "QualityHistory": None,
        "Settings": {"OpenAtLogin": False, "AutoConnectOnLogin": False,
                     "CloseBehavior": "Tray", "AutoTrustFirstConnection": True,
                     "QualityWarning": True, "Warning": "",
                     # 引擎程序：默认「已配置」，否则每个场景顶部都会多一条
                     # 「还没有选择引擎程序」横幅，把别的场景的排版断言带偏。
                     # 要测那条横幅的场景自己把它置 True（见 m1_page_behaviors 的 engine 场景）。
                     "EngineBinary": r"C:\SpiderVPN\bin\sing-box.exe",
                     "EngineMissing": False},
        "ReadWarning": "", "AutoConnectNotice": "", "Dialog": None, "Toast": "",
        "SnapshotAtUtc": "", "ConnectedSince": None,
        "GuardSummary": "", "Pending": None,
        # 交易保护的展示字段（宿主 `GuardStatus::to_json` 原样带出）。
        # 默认给「空/无」，与 `Guard=Unknown` 一致：没有证据就没有时间、没有待办、没有视角说明。
        "GuardEvidenceAge": "", "GuardEvidenceAgeSeconds": None,
        "GuardVerifiedAtUtc": None, "GuardVerifyPending": "None",
        "GuardPerspectiveNote": "",
        "ExitEvidence": {"Verified": False, "Attribution": "Unknown",
                         "Status": "forwarded-unverified", "Code": "",
                         "CheckedAtUtc": None, "ObservedIP": None},
        "Operation": None, "Pair": None, "Invite": None, "PairDeviceDefault": "",
    }
    merged = dict(state)
    merged.update(overrides)
    return merged


from form_fixtures import FORM_RENAME, FORM_SETTINGS  # noqa: E402,F401


class WebSession:
    """一个 headless Edge + 一份站点。`push()` 推快照，`posted()` 读页面发出去的意图。"""

    def __init__(self, site: Path, work: Path) -> None:
        self.site = site
        self.work = work
        self.port = free_port()
        self.process: subprocess.Popen | None = None
        self.ws: WebSocket | None = None
        self.url = site.resolve().as_uri()

    def __enter__(self) -> "WebSession":
        profile = self.work / "profile"
        # 浏览器用户目录必须每次清空：它带着上一轮的 localStorage（主题），
        # 留着会让「浅色首帧」之类的断言凭空变色。
        if profile.exists():
            shutil.rmtree(profile)
        self._out = (self.work / "edge.stdout.txt").open("wb")
        self._err = (self.work / "edge.stderr.txt").open("wb")
        self.process = subprocess.Popen(
            [str(EDGE), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--disable-extensions", "--disable-background-networking", "--no-first-run",
             "--hide-scrollbars", f"--remote-debugging-port={self.port}",
             "--remote-allow-origins=*", f"--user-data-dir={profile}", self.url],
            cwd="C:\\", stdin=subprocess.DEVNULL, stdout=self._out, stderr=self._err)
        target = wait_page_target(self.port, self.url, self.process)
        self.ws = WebSocket(target["webSocketDebuggerUrl"])
        self.wait_ready()
        # 视口按真实窗口来（宿主窗口是 1116×900、客户区 1098×853）。默认的 headless
        # 窗口只有 800×440，长表单会被裁掉，截图和「按钮是否可见」的断言都会失真。
        self.ws.call("Emulation.setDeviceMetricsOverride",
                     {"width": 1200, "height": 900, "deviceScaleFactor": 1, "mobile": False})
        time.sleep(0.2)
        return self

    def wait_ready(self, timeout: float = 15.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if self.eval_bool("document.readyState==='complete'&&!!window.__tcPosted"):
                    return
            except Exception:
                pass
            time.sleep(0.05)
        raise TimeoutError("页面未完成初始化")

    def eval(self, expression: str):
        assert self.ws is not None
        return self.ws.evaluate(expression)

    def eval_bool(self, expression: str) -> bool:
        return bool(self.eval(expression))

    def push(self, page: str, state: dict, settle: float = 0.25) -> None:
        state = dict(state)
        state["SnapshotAtUtc"] = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
        payload = {"Type": "snapshot", "Page": page, "State": state}
        self.eval("window.chrome.webview.dispatchEvent(new MessageEvent('message',"
                  "{data:" + json.dumps(payload, ensure_ascii=False) + "}));true")
        time.sleep(settle)

    def posted(self) -> list[dict]:
        raw = self.eval("window.__tcPosted||[]") or []
        out: list[dict] = []
        for item in raw:
            if isinstance(item, str):
                try:
                    out.append(json.loads(item))
                except ValueError:
                    out.append({"raw": item})
            elif isinstance(item, dict):
                out.append(item)
        return out

    def intents(self, kind: str) -> list[dict]:
        return [m for m in self.posted() if m.get("Type") == kind]

    def clear(self) -> None:
        self.eval("window.__tcPosted=[];true")

    def click(self, selector: str, settle: float = 0.25) -> bool:
        ok = self.eval_bool(
            "(()=>{const e=document.querySelector(%s);if(!e)return false;e.click();return true;})()"
            % json.dumps(selector))
        time.sleep(settle)
        return ok

    def text(self, selector: str) -> str:
        return str(self.eval(
            "(document.querySelector(%s)||{textContent:''}).textContent"
            % json.dumps(selector)) or "")

    def exists(self, selector: str) -> bool:
        return self.eval_bool("!!document.querySelector(%s)" % json.dumps(selector))

    def attr(self, selector: str, name: str) -> str | None:
        """元素上的属性值；元素不存在时返回 None（与「属性为空串」区分开）。"""
        value = self.eval(
            "(()=>{const e=document.querySelector(%s);return e?e.getAttribute(%s):null;})()"
            % (json.dumps(selector), json.dumps(name)))
        return None if value is None else str(value)

    def set_value(self, selector: str, value: str) -> None:
        self.eval(
            "(()=>{const e=document.querySelector(%s);if(!e)return;e.value=%s;"
            "e.dispatchEvent(new Event('input',{bubbles:true}));"
            "e.dispatchEvent(new Event('change',{bubbles:true}));})()"
            % (json.dumps(selector), json.dumps(value)))
        time.sleep(0.2)

    def reload(self) -> None:
        assert self.ws is not None
        self.ws.call("Page.reload", {"ignoreCache": True})
        time.sleep(0.4)
        self.wait_ready()

    def theme_set_before_body(self) -> str | None:
        """document-start 探针：data-theme 被设置时 <body> 还不存在 → 首帧无闪。"""
        assert self.ws is not None
        probe = (
            "window.__tcThemeBeforeBody=null;"
            "try{var o=Element.prototype.setAttribute;"
            "Element.prototype.setAttribute=function(n,v){"
            "try{if(n==='data-theme'&&this===document.documentElement&&!document.body){"
            "window.__tcThemeBeforeBody=String(v);}}catch(e){}"
            "return o.apply(this,arguments);};}catch(e){}"
        )
        self.ws.call("Page.enable", {})
        self.ws.call("Page.addScriptToEvaluateOnNewDocument", {"source": probe})
        self.reload()
        return self.eval("window.__tcThemeBeforeBody||null")

    def shot(self, path: Path) -> str:
        import base64
        assert self.ws is not None
        data = self.ws.call("Page.captureScreenshot", {"format": "png"})["data"]
        path.write_bytes(base64.b64decode(data))
        return str(path)

    def __exit__(self, *exc) -> None:
        if self.ws is not None:
            try:
                self.ws.call("Browser.close")
            except Exception:
                pass
            self.ws.close()
        if self.process is not None:
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                subprocess.run(["taskkill.exe", "/PID", str(self.process.pid), "/T", "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)
        for handle in (getattr(self, "_out", None), getattr(self, "_err", None)):
            if handle is not None:
                handle.close()
