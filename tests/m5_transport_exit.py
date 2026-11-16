#!/usr/bin/env python3
"""兼容连接（TCP/REALITY）的真实出口验收：连上之后，经代理出去的 IP 必须是对端服务器。

为什么单独做这一条：`docs/baseline-0.1.4.md` 里「身份恢复」那一段只验到「服务在听」，
没有验「真的能出网」。而恢复身份、重装组件、改端口这类动作，最后的用户可见结果就是这一条。

前置：数据根里 `selected` 指向兼容连接那条线路，且已配好引擎程序。
判据两条：
  1. 经本地代理端口请求 `http://api.ipify.org`，返回的 IP == `--expect-ip`；
  2. 不走代理直连同一地址，返回的 IP != `--expect-ip`（对照，避免「本来就是本机 IP」的假通过）。

用法：
  python tests/m5_transport_exit.py --exe <exe> --work <根> --report-dir <目录> --expect-ip 203.0.113.10
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s0_page_fixtures import WebSocket, free_port  # noqa: E402

ALLOWED_WORK = Path(r"C:\tc-rs-build")
CDP_READY_SECONDS = 30.0
CONNECT_SECONDS = 120.0
PROBE_URL = "http://api.ipify.org"


class Checker:
    def __init__(self) -> None:
        self.checks: list[dict] = []

    def check(self, label: str, ok: bool, detail: object = None) -> None:
        self.checks.append({"label": label, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} {label}" + ("" if ok else f" | {detail}"))

    @property
    def all_passed(self) -> bool:
        return all(item["ok"] for item in self.checks)


def js(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def click(ws: WebSocket, selector: str) -> bool:
    return bool(
        ws.evaluate(
            f"(()=>{{const e=document.querySelector({js(selector)});"
            "if(!e||e.disabled)return false;e.click();return true;})()"
        )
    )


def wait_js(ws: WebSocket, expression: str, seconds: float, label: str) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if ws.evaluate(expression):
                return True
        except Exception:
            pass
        time.sleep(0.3)
    print(f"  （等待超时：{label}）")
    return False


def wait_cdp(port: int, seconds: float) -> dict:
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        try:
            raw = urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=3).read()
            for item in json.loads(raw or b"[]"):
                if item.get("type") == "page" and "tc.ui" in (item.get("url") or ""):
                    return item
        except Exception as error:
            last = str(error)
        time.sleep(0.3)
    raise TimeoutError(f"CDP 在 {seconds} 秒内没有就绪：{last}")


def prepare_proxy_key(key: str) -> None:
    """宿主连接前要读得到「当前系统代理」；隔离键默认不存在，读不到就拒绝接管。"""
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as handle:
        winreg.SetValueEx(handle, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(handle, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:7897")
        winreg.SetValueEx(handle, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*")


def fetch_ip(proxy: str | None) -> str:
    handler = urllib.request.ProxyHandler(
        {"http": proxy, "https": proxy} if proxy else {}
    )
    opener = urllib.request.build_opener(handler)
    with opener.open(PROBE_URL, timeout=25) as response:
        return response.read().decode("ascii", "replace").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--expect-ip", required=True)
    parser.add_argument("--proxy-port", type=int, default=17891)
    parser.add_argument("--line-name", default="兼容连接")
    args = parser.parse_args()

    work = Path(args.work).resolve()
    report_dir = Path(args.report_dir).resolve()
    for path in (work, report_dir):
        if ALLOWED_WORK not in path.parents and path != ALLOWED_WORK:
            raise SystemExit(f"只能写在 {ALLOWED_WORK} 下：{path}")
    report_dir.mkdir(parents=True, exist_ok=True)

    port = free_port()
    proxy_key = r"Software\SpiderVPN\tests\m5-transport-exit"
    prepare_proxy_key(proxy_key)
    env = dict(os.environ)
    env.update(
        {
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={port} --remote-allow-origins=*",
            "SPIDERVPN_ROOT": str(work),
            "SPIDERVPN_PROXY_KEY": proxy_key,
            "SPIDERVPN_RUN_KEY": r"Software\SpiderVPN\tests\m5-transport-exit-run",
        }
    )
    log = (report_dir / "host.log").open("wb")
    process = subprocess.Popen(
        [args.exe],
        cwd=str(ALLOWED_WORK),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] host pid={process.pid} cdp={port}", flush=True)

    checker = Checker()
    report: dict = {"expectIp": args.expect_ip, "proxyPort": args.proxy_port, "checks": []}
    ws: WebSocket | None = None
    try:
        target = wait_cdp(port, CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        checker.check(
            "真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main [data-action=connect]')",
                20,
                "页面初始化",
            ),
        )
        # 连接**指定线路**：首页主按钮连的是「下次连接」那条（可能是标准线路），
        # 这个探针要验兼容连接，必须从线路页点那一条。
        checker.check("导航到线路页", click(ws, "[data-page=lines]"))
        checker.check(
            "找到目标线路",
            wait_js(
                ws,
                "Array.from(document.querySelectorAll('[data-testid=line-card]'))"
                f".some(c=>c.textContent.includes({js(args.line_name)}))",
                15,
                "线路卡片",
            ),
        )
        # 卡片上的主按钮只出现在「下次连接」那条线；其它线路要从抽屉里连。
        clicked_line = ws.evaluate(
            "(()=>{const name=" + js(args.line_name) + ";"
            "const card=Array.from(document.querySelectorAll('[data-testid=line-card]'))"
            ".find(c=>c.textContent.includes(name));"
            "if(!card)return false;const b=card.querySelector('.name-button');"
            "if(!b)return false;b.click();return true;})()"
        )
        checker.check("打开这条线路的抽屉", bool(clicked_line))
        checker.check(
            "抽屉里有「连接这条线路」",
            wait_js(ws, "!!document.querySelector('#drawer [data-action=connect]')", 10, "抽屉"),
        )
        checker.check("点「连接这条线路」", click(ws, "#drawer [data-action=connect]"))
        # 回首页再看：断开按钮在首页与「下次连接」那张卡上，线路页的卡片不一定挂它。
        click(ws, "[data-page=home]")
        connected = wait_js(
            ws, "!!document.querySelector('[data-action=disconnect]')", CONNECT_SECONDS, "连接建立"
        )
        checker.check("连接建立（出现「断开连接」）", connected, report["checks"])
        if connected:
            time.sleep(2.0)  # 让引擎完成首次出网握手
            try:
                proxied = fetch_ip(f"http://127.0.0.1:{args.proxy_port}")
            except Exception as error:
                proxied = f"<失败：{error}>"
            report["proxiedIp"] = proxied
            checker.check(
                f"经兼容连接的出口是服务器（{args.expect_ip}）",
                proxied == args.expect_ip,
                proxied,
            )
            try:
                direct = fetch_ip(None)
            except Exception as error:
                direct = f"<失败：{error}>"
            report["directIp"] = direct
            checker.check(
                "直连出口与服务器不同（对照组）",
                direct != args.expect_ip,
                direct,
            )

            # 断开：先点按钮，再点确认（产品要求断开必须先问一次）。
            click(ws, "[data-action=disconnect]")
            wait_js(ws, "!!document.querySelector('#dialog-root .dialog')", 10, "断开确认层")
            clicked = click(ws, "#dialog-root [data-action=confirmDialog]")
            checker.check("断开确认层可以点确认", clicked)
            checker.check(
                "断开完成",
                wait_js(
                    ws,
                    "!document.querySelector('[data-action=disconnect]')",
                    60,
                    "回到未连接",
                ),
            )
        report["finalText"] = str(
            ws.evaluate("(document.querySelector('#main')||{textContent:''}).textContent") or ""
        )[-300:]
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()

    (report_dir / "m5-transport-exit.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps({"allPassed": report["allPassed"], "checks": len(checker.checks)}))
    return 0 if report["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
