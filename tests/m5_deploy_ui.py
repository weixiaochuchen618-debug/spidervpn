#!/usr/bin/env python3
"""「自己搭服务器」的真实 WebView2 端到端：点按钮 → 填地址 → 读指纹 → 部署 → 完成。

与 `m1_page_behaviors.py` 的分工：

- 那边是 headless Edge + 手写快照，验的是「这份 app.js 认不认宿主产出的节点树」；
- 这边是**真实宿主 + 真实 WebView2 + 真实 SSH**，验的是「点下去真的会发生」。

驱动方式用 CDP（`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=N`），
**不依赖鼠标坐标**：布局一改坐标就废，而选择器是宿主与页面之间的契约。

前置：数据根里已有这台服务器的记录（凭据在 DPAPI 里），所以这一步走「跳过密码」分支；
密码框那条路由 `m1_page_behaviors.py` 的 `deploy` 场景与 Rust 单测覆盖。

用法：
  python tests/m5_deploy_ui.py --exe <exe> --work <空目录> --report-dir <目录> --spec root@1.2.3.4
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s0_page_fixtures import WebSocket, free_port  # noqa: E402

ALLOWED_WORK = Path(r"C:\tc-rs-build")
CDP_READY_SECONDS = 30.0
PROBE_SECONDS = 90.0
DEPLOY_SECONDS = 600.0


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
    """把 python 字符串安全地塞进 JS 表达式。"""
    return json.dumps(value, ensure_ascii=False)


def click(ws: WebSocket, selector: str) -> bool:
    return bool(
        ws.evaluate(
            f"(()=>{{const e=document.querySelector({js(selector)});"
            "if(!e)return false;e.click();return true;})()"
        )
    )


def set_value(ws: WebSocket, selector: str, value: str) -> bool:
    return bool(
        ws.evaluate(
            f"(()=>{{const e=document.querySelector({js(selector)});"
            f"if(!e)return false;e.value={js(value)};"
            # app.js 的输入框监听的是 `input`（`document.addEventListener('input')`），
            # `change` 只处理 checkbox/radio/select。派发错事件时页面看着像「没反应」。
            "e.dispatchEvent(new Event('input',{bubbles:true}));return true;})()"
        )
    )


def text_of(ws: WebSocket, selector: str) -> str:
    return str(
        ws.evaluate(f"(document.querySelector({js(selector)})||{{textContent:''}}).textContent")
        or ""
    )


def wait_js(ws: WebSocket, expression: str, seconds: float, label: str) -> bool:
    """轮询一个布尔表达式。返回是否在超时前成立。"""
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
            # 初始 target 是 about:blank，等它导航到真实页面再连，免得连上一个空壳。
            for item in pages:
                if "tc.ui" in (item.get("url") or ""):
                    return item
            if pages:
                last = pages[0].get("url") or last
        except Exception as error:  # 端口还没起、或端点还没就绪
            last = str(error)
        time.sleep(0.4)
    raise TimeoutError(f"CDP 在 {seconds} 秒内没有就绪：{last}")


def screenshot(ws: WebSocket, path: Path) -> None:
    try:
        result = ws.call("Page.captureScreenshot", {"format": "png"})
        import base64

        path.write_bytes(base64.b64decode(result["data"]))
    except Exception as error:
        print(f"  （截图失败：{error}）")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--spec", required=True, help="用户名@主机[:端口]")
    parser.add_argument(
        "--entry",
        choices=("empty", "lines"),
        default="empty",
        help="empty=首页空态的「自己搭服务器」；lines=线路页的「＋ 添加线路」（有线路时）",
    )
    parser.add_argument(
        "--stop-at-form",
        action="store_true",
        help="只验到部署表单出现就结束（用于「有线路」入口，避免重复部署）",
    )
    args = parser.parse_args()

    print(f"[probe] exe={args.exe} spec={args.spec}", flush=True)
    work = Path(args.work).resolve()
    report_dir = Path(args.report_dir).resolve()
    for path in (work, report_dir):
        if ALLOWED_WORK not in path.parents and path != ALLOWED_WORK:
            raise SystemExit(f"只能写在 {ALLOWED_WORK} 下：{path}")
    work.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    port = free_port()
    print(f"[probe] cdp port={port}", flush=True)
    env = {
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={port} --remote-allow-origins=*",
        "SPIDERVPN_ROOT": str(work),
        "SPIDERVPN_PROXY_KEY": r"Software\SpiderVPN\tests\m5-deploy-ui",
        "SPIDERVPN_RUN_KEY": r"Software\SpiderVPN\tests\m5-deploy-ui-run",
        # 调度 trace：只在隔离根里写，用来回答「事件到底有没有回到 UI 线程」。
        "SPIDERVPN_TEST_HOST_TRACE": "1",
    }
    import os

    full_env = dict(os.environ)
    full_env.update(env)
    log = (report_dir / "host.log").open("wb")
    process = subprocess.Popen(
        [args.exe],
        cwd=str(ALLOWED_WORK),
        env=full_env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )

    print(f"[probe] host pid={process.pid}", flush=True)
    checker = Checker()
    report: dict = {"spec": args.spec, "cdpPort": port, "shots": [], "checks": []}
    ws: WebSocket | None = None
    try:
        target = wait_cdp(port, CDP_READY_SECONDS)
        print(f"[probe] cdp target={target.get('url')}", flush=True)
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

        # 1) 入口。两条路都要能走到同一个表单：
        #    - 空态：首页的「自己搭服务器」直接发 `add`；
        #    - 有线路：线路页的「＋ 添加线路」→ 选择页 → 「自己搭一台服务器」（旧版的入口）。
        if args.entry == "empty":
            checker.check(
                "空态首页有「自己搭服务器」",
                bool(
                    ws.evaluate(
                        "Array.from(document.querySelectorAll('[data-action=add]'))"
                        ".some(e=>e.textContent.includes('自己搭服务器'))"
                    )
                ),
            )
            checker.check("点「自己搭服务器」", click(ws, "#main [data-action=add]"))
        else:
            checker.check(
                "导航到线路页",
                click(ws, "[data-page=lines]"),
            )
            checker.check(
                "线路页有「＋ 添加线路」",
                wait_js(
                    ws,
                    "!!document.querySelector('[data-action=pairBeginChoose]')",
                    10,
                    "添加入口",
                ),
            )
            checker.check(
                "点「＋ 添加线路」",
                click(ws, "[data-action=pairBeginChoose]"),
            )
            checker.check(
                "进入「选择方式」页",
                wait_js(
                    ws,
                    "!!document.querySelector('[data-action=pairChooseBuild]')",
                    10,
                    "选择方式",
                ),
            )
            checker.check(
                "点「自己搭一台服务器」",
                click(ws, "[data-action=pairChooseBuild]"),
            )

        checker.check(
            "部署表单出现",
            wait_js(ws, "!!document.querySelector('#main .workflow')", 10, "表单出现"),
        )
        checker.check("地址框在", bool(ws.evaluate("!!document.getElementById('wf-spec')")))
        if args.stop_at_form:
            screenshot(ws, report_dir / f"entry-{args.entry}.png")
            report["shots"].append(str(report_dir / f"entry-{args.entry}.png"))
            # 走 finally 写报告 + 收进程；退出码仍按断言结果。
            raise SystemExit(0 if checker.all_passed else 1)

        # 2) 填地址 → 读指纹（真 SSH，不送密码）。
        checker.check(
            "填地址回传", set_value(ws, "#wf-spec", args.spec), args.spec
        )
        checker.check("点「读取指纹并继续」", click(ws, "#main [data-wf=probe]"))
        got = wait_js(
            ws,
            "(document.querySelector('#main .workflow')||{textContent:''})"
            ".textContent.includes('SHA256:')",
            PROBE_SECONDS,
            "主机指纹",
        )
        checker.check("读到主机指纹", got, text_of(ws, "#main .workflow")[-200:])
        # 已有记录 → 走 DPAPI 凭据，不该再要密码。
        checker.check(
            "有凭据时不出现密码框",
            not bool(ws.evaluate("!!document.getElementById('wf-password')")),
        )
        screenshot(ws, report_dir / "1-verify.png")
        report["shots"].append(str(report_dir / "1-verify.png"))

        # 3) 开始部署（真 SSH：检查 → 跳过已装 → 复用兼容连接 → 加 peer → 登记线路）。
        checker.check("点「开始部署」", click(ws, "#main [data-wf=start]"))
        checker.check(
            "进入部署中",
            wait_js(
                ws,
                "(document.querySelector('#main .workflow')||{textContent:''})"
                ".textContent.includes('正在部署')",
                15,
                "部署中",
            ),
        )
        done = wait_js(
            ws,
            "(document.querySelector('#main .workflow')||{textContent:''})"
            ".textContent.includes('部署完成')",
            DEPLOY_SECONDS,
            "部署完成",
        )
        final = text_of(ws, "#main .workflow")
        checker.check("部署完成", done, final[-400:])
        if done:
            checker.check("结果里有服务器地址", args.spec.split("@")[-1].split(":")[0] in final, final[-300:])
            checker.check("结果里有两条线路", final.count("自建 ·") >= 2, final[-300:])
            checker.check("结果里有兼容连接", "兼容连接" in final, final[-300:])
        screenshot(ws, report_dir / "2-done.png")
        report["shots"].append(str(report_dir / "2-done.png"))
        report["finalText"] = final

        # 4) 关窗：宿主必须真的退出（引擎没起，但要确认没有僵尸）。
        click(ws, "#main [data-wf=done]")
        time.sleep(1.0)
        checker.check(
            "点「完成」后回到首页",
            not bool(ws.evaluate("!!document.querySelector('#main .workflow')")),
        )
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["exeSha256"] = _sha256(Path(args.exe))
        (report_dir / "m5-deploy-ui.json").write_text(
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
