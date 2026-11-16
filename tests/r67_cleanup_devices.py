"""清理 r67 真机验收在服务器上留下的 `r67离线验收` 设备。

只动名字匹配的设备；本机设备与其它设备不碰。使用验收用的管理端隔离根。
"""
import importlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")
Pump = helpers.Pump
WebSocket = helpers.WebSocket
free_port = helpers.free_port
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

ROOT = Path(r"D:\vpn构建\deliverables\software-company\tcrs-r67-real-offline\manager")
EXE = Path(r"C:\SpiderVPN\bin\spidervpn.exe")
NAME = "r67离线验收"


def click(ws, selector):
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def main():
    if not os.environ.get("TC_SSH_PASSWORD"):
        raise SystemExit("缺少 TC_SSH_PASSWORD")
    port = free_port()
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(ROOT)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log = (ROOT.parent / "cleanup.log").open("wb")
    proc = subprocess.Popen([str(EXE)], cwd=str(EXE.parent), env=env,
                            stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
    try:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        pump = Pump(proc.pid)
        wait_js(ws, "document.readyState==='complete'&&!!document.querySelector('#main')", 30, "页面", pump)
        r54.post(ws, {"Type": "navigate", "Page": "lines"})
        wait_js(ws, '!!document.querySelector(\'[data-action="details"]\')', 15, "线路", pump)
        click(ws, '[data-action="details"]')
        wait_js(ws, '!!document.querySelector(\'[data-action="lineServer"]\')', 15, "服务器入口", pump)
        click(ws, '[data-action="lineServer"]')
        wait_js(ws, '!!document.querySelector(\'[data-wf^="revoke-"]\')', 90, "设备列表", pump)
        print("DEVICE PAGE:\n" + str(ws.evaluate("document.body.innerText")))
        removed = 0
        # 验收设备没有写进 device-names.json（只有显式改名才会写），所以按隧道地址认：
        # 10.66.0.2 是本机，.3/.4/.5 是三次验收留下的。
        for address in ("10.66.0.3", "10.66.0.4", "10.66.0.5"):
            expr = (
                "(()=>{const rows=[...document.querySelectorAll('[data-wf^=\"revoke-\"]')];"
                "const hit=rows.find(b=>(b.closest('.card')||document.body).innerText.includes(%s));"
                "if(!hit)return '';const id=hit.getAttribute('data-wf');hit.click();return id;})()"
                % json.dumps(address, ensure_ascii=False)
            )
            hit = ws.evaluate(expr)
            if not hit:
                print("not found", address)
                continue
            wait_js(ws, '!!document.querySelector(\'[data-wf="revoke-confirm"]\')', 15, "确认撤权", pump)
            click(ws, '[data-wf="revoke-confirm"]')
            time.sleep(3)
            removed += 1
        print("removed", removed)
        time.sleep(2)
        text = str(ws.evaluate("document.body.innerText"))
        left = any(address in text for address in ("10.66.0.3", "10.66.0.4", "10.66.0.5"))
        print("still visible:", left)
        return 0 if not left else 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
        log.close()


if __name__ == "__main__":
    raise SystemExit(main())
