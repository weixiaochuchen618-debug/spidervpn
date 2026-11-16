#!/usr/bin/env python3
"""M1 表单工作流的前端验收：用真实 旧版资产 + 宿主下发的 Form 快照，
在 headless Edge 里验证「重命名」与「连接方式」两张表单能渲染、能回传事件。

Form 夹具按 Rust 侧 `FormState::render()` 的实测输出手写，形状由 `uiweb_form.rs` 的
`rename_form_carries_the_current_name_and_closes_on_success` 与
`line_settings_switches_transport_and_reads_back_the_real_value` 钉住：两侧任何一方
改了字段名，这里或那里必然失败。

用法：python tests/m1_form_render.py [--out <目录>]
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
from s0_page_fixtures import WebSocket, free_port, wait_page_target  # noqa: E402

EDGE = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
REPO = Path(r"D:\vpn构建\spidervpn-0.1.4")
WEB = REPO / "web"
DEFAULT_OUT = Path(r"C:\tc-rs-build\m1-evidence\form")

from form_fixtures import FORM_RENAME, FORM_SETTINGS  # noqa: E402
from web_fixture import make_state, prepare_site  # noqa: E402


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
        ws.call("Emulation.setDeviceMetricsOverride",
                {"width": 1200, "height": 900, "deviceScaleFactor": 1, "mobile": False})
        time.sleep(0.4)

        def check(name, ok, detail=None):
            result["checks"][name] = {"ok": bool(ok), "detail": detail}

        def push(page, form):
            state = make_state(Form=form)
            # 快照时间必须是「现在」：app.js 会按它判数据过期，写死会让每条断言都顶着
            # 一条「数据过期」横幅（真宿主每次推送都填当前时刻）。
            state["SnapshotAtUtc"] = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            payload = {"Type": "snapshot", "Page": page, "State": state}
            ws.evaluate("window.chrome.webview.dispatchEvent(new MessageEvent('message',"
                        + "{data:" + json.dumps(payload, ensure_ascii=False) + "}));true")
            time.sleep(0.35)

        def posted():
            # app.js 的 post() 发的是 JSON 字符串（wry 只收字符串），这里要解析回来。
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

        def last_form_message():
            items = [m for m in posted() if m.get("Type") == "form"]
            return items[-1] if items else None

        def shot(name):
            data = ws.call("Page.captureScreenshot", {"format": "png"})["data"]
            path = work / name
            path.write_bytes(base64.b64decode(data))
            result["shots"].append(str(path))

        push("lines", FORM_RENAME)
        check("标题是「重命名线路」",
              ws.evaluate("(document.querySelector('#main h1,#main h2')||{textContent:''})"
                          ".textContent.includes('重命名线路')"))
        check("输入框带当前名称",
              ws.evaluate("(document.getElementById('wf-name')||{value:null}).value==='东京 02'"))
        check("输入框有可读标签",
              ws.evaluate("(document.getElementById('wf-name')||{}).getAttribute"
                          "&&document.getElementById('wf-name').getAttribute('aria-label')==='线路名称'"))
        check("两个动作按钮都在",
              ws.evaluate("document.querySelectorAll('#main .workflow-actions button').length===2"))
        check("面包屑可以回线路页",
              ws.evaluate("!!document.querySelector('#main .breadcrumb button[data-page=lines]')"))
        check("说明文字是宿主下发的原话",
              ws.evaluate("document.querySelector('#main .workflow').textContent.includes('连接记录都不变')"))
        check("字段包在卡片里（旧版版式）",
              ws.evaluate("!!document.querySelector('#main .workflow .wf-card')"))
        shot("rename.png")

        ws.evaluate("const i=document.getElementById('wf-name');i.value='东京 03';"
                    "i.dispatchEvent(new Event('input',{bubbles:true}));true")
        time.sleep(0.25)
        msg = last_form_message() or {}
        check("改名称回传 form/change",
              msg.get("Type") == "form" and msg.get("Id") == "name"
              and msg.get("Event") == "change" and msg.get("Value") == "东京 03", msg)

        ws.evaluate("(document.querySelector('#main .workflow-actions [data-wf=save-rename]')||{click(){}})"
                    ".click();true")
        time.sleep(0.25)
        msg = last_form_message() or {}
        check("点保存回传 form/click",
              msg.get("Type") == "form" and msg.get("Id") == "save-rename"
              and msg.get("Event") == "click", msg)

        push("lines", FORM_SETTINGS)
        check("设置页当前档位标为主按钮",
              ws.evaluate("(document.querySelector('#main [data-wf=method-udp]')||{className:''})"
                          ".className.includes('primary')"))
        check("另一档是普通按钮",
              ws.evaluate("(document.querySelector('#main [data-wf=method-tcp]')||{className:'x'})"
                          ".className.indexOf('primary')<0"))
        check("端点来自宿主",
              ws.evaluate("document.querySelector('#main .workflow').textContent.includes('1.2.3.4:443')"))
        shot("line-settings.png")

        ws.evaluate("(document.querySelector('#main [data-wf=method-tcp]')||{click(){}}).click();true")
        time.sleep(0.25)
        msg = last_form_message() or {}
        check("点兼容回传 method-tcp",
              msg.get("Type") == "form" and msg.get("Id") == "method-tcp", msg)

        push("lines", None)
        check("表单关闭回到线路页",
              ws.evaluate("!document.querySelector('#main .workflow')&&"
                          "document.querySelectorAll('#main [data-action=setProfile]').length>=2"))

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
