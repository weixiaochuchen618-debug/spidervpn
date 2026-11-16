#!/usr/bin/env python3
"""r93 界面验收：部署页的兼容连接选择（旧版的 `DeployTransport` / `DeployTcpPort` / `DeployServerName`）。

改动前：这一页只有「标准连接」——没有默认连接方式、没有 TCP 首选端口、没有握手域名，
用户选了「兼容连接」也无处可表达。

本脚本验的是宿主真的把这三格做成了可用的表单状态（读 DOM + 读落盘草稿，不是读源码）：

1. 高级部署设置里有三格，选项文案与旧版逐字一致；
2. 三个控件改值后**页面不重绘**（值还在，且能继续输入）；
3. 点「开始部署」后落盘的草稿里带着这次选择（Transport=Tcp / TcpPort=2443 / ServerName）；
4. 收尾：现场（真实数据根）的 config.json 一个字节没动。

用法：
  python tests/r93_transport_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r93-transport \\
      --work D:\\vpn构建\\reports-tmp\\r93-work [--allow-running]
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker
USER_CONFIG = r54.USER_CONFIG
md5_of = r54.md5_of

SPEC = "root@203.0.113.10"
PASSWORD = "r93-password"
TRANSPORT = "#wf-transport"
TCP_PORT = "#wf-tcp-port"
SERVER_NAME = "#wf-server-name"
TICK = "#wf-deploy-cloud"
START = "[data-wf=start]"


def body_text(ws) -> str:
    return t11.body_text(ws)


def _keys(value) -> list[str]:
    """递归收集 JSON 里所有对象的键名（判「记录里有没有秘密字段」）。"""
    keys: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            keys.append(str(key))
            keys.extend(_keys(item))
    elif isinstance(value, list):
        for item in value:
            keys.extend(_keys(item))
    return keys


def labels(ws, selector: str) -> list[str]:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return e?Array.from(e.options).map(o=>o.textContent):[];})()"
    )
    value = ws.evaluate(expr)
    return [str(item) for item in (value or [])]


def selected(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return e?String(e.value):'missing';})()"
    )
    return str(ws.evaluate(expr) or "")


def change_select(ws, pump, selector: str, value: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';e.value="
        + json.dumps(value)
        + ";e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 0.4, "事件送达", pump)
    return ok


def click_when_enabled(ws, pump, selector: str, seconds: float = 25.0) -> str:
    ok = helpers.wait_js(
        ws,
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return !!e&&!e.disabled;})()",
        seconds,
        f"{selector} 可点",
        pump,
    )
    if not ok:
        return "not-ready"
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


def tick(ws, pump) -> bool:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(TICK)
        + ");if(!e)return 'missing';e.checked=true;"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 0.4, "勾选送达", pump)
    return ok


def wait_draft(work: Path, seconds: float = 20.0) -> Path | None:
    import time

    runs = work / "data" / "deployments" / "runs"
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if runs.is_dir():
            for path in sorted(runs.glob("*.json")):
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except Exception:  # noqa: BLE001
                    continue
                plan = value.get("Plan") or {}
                if plan.get("Transport"):
                    return path
        time.sleep(0.3)
    return None


def wait_page(ws, pump, must=(), must_not=(), seconds: float = 12.0) -> bool:
    cond = "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
    for item in must:
        cond += f"if(!t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    for item in must_not:
        cond += f"if(t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    cond += "return true;})()"
    return helpers.wait_js(ws, cond, seconds, "页面文案", pump)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    parser.add_argument("--allow-running", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)
    (work / "data").mkdir(parents=True, exist_ok=True)

    if args.allow_running:
        print("[warn] --allow-running：不检查已有实例（独立数据根，互不干扰）", flush=True)
    else:
        t11.no_running_host()

    checker = Checker()
    report = {"mode": "deploy-transport", "exe": str(exe), "work": str(work), "checks": []}
    user_config_before = md5_of(USER_CONFIG)
    code = 0
    process = None
    ws = None
    try:
        process, _port, ws = t11.launch(exe, work, report_dir, "transport")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            body_text(ws)[-200:],
        )
        checker.check(
            "进部署向导",
            click_when_enabled(ws, pump, "#main [data-action=add]") == "ok"
            and helpers.wait_js(ws, "!!document.querySelector('#wf-spec')", 20, "向导", pump),
            body_text(ws)[-300:],
        )
        checker.check(
            "高级设置里有「默认连接方式」，三项原文与旧版一致",
            labels(ws, TRANSPORT) == ["自动选择（推荐）", "标准连接", "兼容连接"],
            str(labels(ws, TRANSPORT)),
        )
        checker.check("默认是自动选择", selected(ws, TRANSPORT) == "0", selected(ws, TRANSPORT))
        checker.check(
            "有「TCP 首选端口」，候选 443 / 8443 / 2443",
            labels(ws, TCP_PORT) == ["443", "8443", "2443"],
            str(labels(ws, TCP_PORT)),
        )
        checker.check("默认端口是 443", selected(ws, TCP_PORT) == "0", selected(ws, TCP_PORT))
        checker.check(
            "有「TCP 握手目标」，默认 www.bing.com",
            str(ws.evaluate(f"(document.querySelector('{SERVER_NAME}')||{{}}).value")) == "www.bing.com",
            str(ws.evaluate(f"(document.querySelector('{SERVER_NAME}')||{{}}).value")),
        )

        checker.check("选「兼容连接」", change_select(ws, pump, TRANSPORT, "2"), selected(ws, TRANSPORT))
        checker.check("选 TCP 端口 2443", change_select(ws, pump, TCP_PORT, "2"), selected(ws, TCP_PORT))
        checker.check(
            "填握手目标 www.example.com",
            t11.set_value(ws, SERVER_NAME, "www.example.com"),
            "",
        )
        # 三个 change 都不该重绘：值还在（重绘会把页面打回默认值）。
        checker.check(
            "改完三格后值没有被重绘吃掉",
            selected(ws, TRANSPORT) == "2"
            and selected(ws, TCP_PORT) == "2"
            and str(ws.evaluate(f"(document.querySelector('{SERVER_NAME}')||{{}}).value"))
            == "www.example.com",
            f"{selected(ws, TRANSPORT)}/{selected(ws, TCP_PORT)}/"
            f"{ws.evaluate(f'(document.querySelector({json.dumps(SERVER_NAME)})||{{}}).value')}",
        )

        checker.check("填进地址", t11.set_value(ws, "#wf-spec", SPEC), "")
        checker.check("填进密码", t11.set_value(ws, "#wf-password", PASSWORD), "")
        checker.check("勾上「已核对云端放行」", tick(ws, pump), "")
        # 折叠区默认收起，innerText 读不到里面的说明；用 textContent 判（内容在 DOM 里）。
        checker.check(
            "页面说清了标准与兼容连接都会准备",
            helpers.wait_js(
                ws,
                "(()=>{const e=document.querySelector('[data-wf=deploy-advanced]');"
                "return !!e&&e.textContent.includes('标准与兼容连接都会准备');})()",
                8,
                "高级设置说明",
                pump,
            ),
            "",
        )

        clicked = click_when_enabled(ws, pump, START) == "ok"
        draft = wait_draft(work) if clicked else None
        checker.check("点「开始部署」→ 落下一份带兼容连接选择的草稿", clicked and draft is not None, str(draft))
        if draft is not None:
            value = json.loads(draft.read_text(encoding="utf-8"))
            plan = value.get("Plan") or {}
            checker.check(
                "草稿里 Transport=Tcp / TcpPort=2443 / ServerName=www.example.com",
                plan.get("Transport") == "Tcp"
                and plan.get("TcpPort") == 2443
                and plan.get("ServerName") == "www.example.com",
                json.dumps(plan, ensure_ascii=False),
            )
            text = json.dumps(value, ensure_ascii=False)
            forbidden = ("password", "passwd", "pwd", "credential", "privatekey", "secret", "passphrase")
            leaked = sorted(
                {
                    key
                    for key in _keys(value)
                    if any(word in key.lower() for word in forbidden)
                }
            )
            checker.check(
                "草稿里没有任何凭据字段（LoginMethod 的取值不算）",
                not leaked and "BEGIN OPENSSH PRIVATE KEY" not in text,
                str(leaked),
            )
        checker.check("真实数据根的 config.json 未被改动", md5_of(USER_CONFIG) == user_config_before)
        helpers.screenshot(ws, report_dir / "01-deploy-transport.png", report.get("shots", []))
    except Exception as error:  # noqa: BLE001
        code = 1
        report["error"] = f"{type(error).__name__}: {error}"
        print(f"脚本异常：{report['error']}", flush=True)
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        if not args.keep_open and process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        print(
            f"残留进程：{'有' if process is not None and process.poll() is None else '无'}",
            flush=True,
        )
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
