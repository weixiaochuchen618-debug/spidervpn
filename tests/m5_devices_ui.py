#!/usr/bin/env python3
"""「服务器与设备」的真实 WebView2 走查：线路抽屉 → 设备页 → 刷新。

与 `m1_page_behaviors.py` 的 `devices` 场景分工：

- 那边是 headless Edge + 夹具快照，验的是「这份 app.js 认不认宿主产出的节点树」；
- 这边是**真实宿主 + 真实 WebView2 + 真实 SSH**，验的是「点下去真的会去读服务器」。

前置：数据根里已有服务器记录与封存凭据（`serverstore`），线路名能对回记录。
页面是只读的：只跑 `wg show dump` 一类的读命令，不改服务器、不动当前连接。

用法：
  python tests/m5_devices_ui.py --exe <exe> --work <数据根> --report-dir <目录>
"""
from __future__ import annotations

import argparse
import base64
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
READ_SECONDS = 90.0


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
            "if(!e)return false;e.click();return true;})()"
        )
    )


def text_of(ws: WebSocket, selector: str) -> str:
    return str(
        ws.evaluate(f"(document.querySelector({js(selector)})||{{textContent:''}}).textContent")
        or ""
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
            targets = json.loads(raw or b"[]")
            pages = [
                item
                for item in targets
                if item.get("type") == "page" and item.get("webSocketDebuggerUrl")
            ]
            for item in pages:
                if "tc.ui" in (item.get("url") or ""):
                    return item
            if pages:
                last = pages[0].get("url") or last
        except Exception as error:
            last = str(error)
        time.sleep(0.4)
    raise TimeoutError(f"CDP 在 {seconds} 秒内没有就绪：{last}")


def screenshot(ws: WebSocket, path: Path) -> None:
    try:
        result = ws.call("Page.captureScreenshot", {"format": "png"})
        path.write_bytes(base64.b64decode(result["data"]))
    except Exception as error:
        print(f"  （截图失败：{error}）")


def first_record(work: Path) -> dict:
    roots = sorted((work / "data" / "servers").glob("*/record.json"))
    if not roots:
        raise SystemExit(f"{work} 里没有服务器记录，这个探针需要一个真服务器")
    return json.loads(roots[0].read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args()

    work = Path(args.work).resolve()
    report_dir = Path(args.report_dir).resolve()
    for path in (work, report_dir):
        if ALLOWED_WORK not in path.parents and path != ALLOWED_WORK:
            raise SystemExit(f"只能写在 {ALLOWED_WORK} 下：{path}")
    report_dir.mkdir(parents=True, exist_ok=True)

    record = first_record(work)
    host = str(record.get("Host") or record.get("host") or "")
    if not host:
        raise SystemExit("服务器记录里没有主机地址")
    print(f"[probe] exe={args.exe} host={host}", flush=True)

    port = free_port()
    env = dict(os.environ)
    env.update(
        {
            "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={port} --remote-allow-origins=*",
            "SPIDERVPN_ROOT": str(work),
            "SPIDERVPN_PROXY_KEY": r"Software\SpiderVPN\tests\m5-devices-ui",
            "SPIDERVPN_RUN_KEY": r"Software\SpiderVPN\tests\m5-devices-ui-run",
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
    report: dict = {"host": host, "cdpPort": port, "shots": [], "checks": []}
    ws: WebSocket | None = None
    try:
        target = wait_cdp(port, CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        checker.check(
            "真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                20,
                "页面初始化",
            ),
        )

        checker.check("导航到线路页", click(ws, "[data-page=lines]"))
        checker.check(
            "线路卡片出现",
            wait_js(ws, "!!document.querySelector('#main [data-action=details]')", 15, "线路卡片"),
        )
        checker.check("打开线路抽屉", click(ws, "#main [data-action=details]"))
        checker.check(
            "抽屉里有「服务器与设备」",
            wait_js(ws, "!!document.querySelector('#drawer [data-action=lineServer]')", 10, "入口"),
        )
        checker.check("点「服务器与设备」", click(ws, "#drawer [data-action=lineServer]"))
        checker.check(
            "设备页打开",
            wait_js(ws, "!!document.querySelector('#main .workflow')", 10, "表单出现"),
        )

        finished = wait_js(
            ws,
            "(document.querySelector('#main .workflow')||{textContent:''})"
            ".textContent.includes('服务器：')"
            "||(document.querySelector('#main .workflow')||{textContent:''})"
            ".textContent.includes('读不到设备列表')",
            READ_SECONDS,
            "设备列表回包",
        )
        page = text_of(ws, "#main .workflow")
        checker.check("设备页拿到回包", finished, page[-300:])
        checker.check("没有停在「正在读取」", "正在读取服务器与设备…" not in page, page[:200])
        checker.check("服务器行是真的", f"服务器：{record.get('User', record.get('user', 'root'))}@{host}:" in page, page[:400])
        checker.check("主机指纹在", "SHA256:" in page, page[:400])
        checker.check("网段是 10.66.0.0/24", "10.66.0.0/24" in page, page[:400])
        checker.check("隧道状态有一句人话", ("隧道：运行中" in page) or ("接口不存在" in page), page[:400])
        checker.check(
            "设备清单有结论（台数或读不到）",
            ("已登记的设备（" in page) or ("读不到设备清单" in page),
            page[-400:],
        )
        # 真服务器上至少有一台（本机）在隧道里；服务没起来时不强求。
        if "隧道：运行中" in page:
            checker.check("运行中的隧道至少列出一台设备", "（本机）" in page or "设备 10.66." in page, page[-400:])

        screenshot(ws, report_dir / "devices.png")
        report["shots"].append(str(report_dir / "devices.png"))

        # 刷新：必须重新发命令并回到同一页，而不是关掉表单。
        checker.check("点「刷新」", click(ws, "#main [data-wf=refresh]"))
        checker.check(
            "刷新后仍在设备页",
            wait_js(
                ws,
                "(document.querySelector('#main .workflow')||{textContent:''})"
                ".textContent.includes('服务器：')",
                READ_SECONDS,
                "刷新回包",
            ),
        )
        report["finalText"] = text_of(ws, "#main .workflow")
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["exeSha256"] = _sha256(Path(args.exe))
        (report_dir / "m5-devices-ui.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
        log.close()

    print(json.dumps({"allPassed": report["allPassed"], "checks": len(checker.checks)}))
    return 0 if report["allPassed"] else 1


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
