#!/usr/bin/env python3
"""r91 界面验收：部署向导的「云端放行确认」（旧版的 `LinuxCloudConfirmed`）。

改动前：填完地址和密码就能点「开始部署」，程序直接去连服务器。云端安全组没放行
UDP 时，第一步会以「连不上服务器」结束——用户会以为是密码或程序错了。

本脚本验的是宿主真的把这一步做成了前置（读 DOM，不是读源码）：

1. 向导里有「已核对云端…」勾选，且**默认不勾**；
2. 不勾就点「开始部署」→ 页面说明原因，**不进入**「正在核对服务器身份」；
3. 勾上再点 → 才进入读指纹等待态；
4. 收尾：现场（真实数据根）的 config.json 一个字节没动。

用法：
  python tests/r91_cloud_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r91-cloud \\
      --work D:\\vpn构建\\reports-tmp\\r91-work [--allow-running]
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
PASSWORD = "r91-password"
TICK = "#wf-deploy-cloud"
START = "[data-wf=start]"


def body_text(ws) -> str:
    return t11.body_text(ws)


def click(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


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
    return click(ws, selector)


def settle(ws, pump, seconds: float = 3.0) -> None:
    """等页面追上宿主的新代数。

    拦下来那一帧宿主会 `restructure()`（提示要重绘才看得见），页面还拿着上一代；
    此时发出的 `change` 会被 `Generation` 闸门静默丢掉（r87 的同一课）。
    """
    import time

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pump.tick()
        time.sleep(0.2)


def tick(ws, pump) -> bool:
    """勾上（dispatche change：宿主靠 change 记状态）。"""
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(TICK)
        + ");if(!e)return 'missing';e.checked=true;"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 1, "重画", pump)
    return ok


def wait_draft(work: Path, seconds: float = 20.0) -> bool:
    """等那次点击真的落了草稿。

    点击之后宿主先存草稿、再读指纹；对着 203.0.113.10（TEST-NET）读指纹会很快失败，
    「正在核对服务器身份…」这句可能只活一帧。**草稿文件是硬证据**：它只在这道闸放行后
    才会产生，所以用它证明「勾了才动手」。
    """
    import time

    runs = work / "data" / "deployments" / "runs"
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if runs.is_dir() and any(runs.glob("*.json")):
            return True
        time.sleep(0.3)
    return False


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
    report = {"mode": "deploy-cloud", "exe": str(exe), "work": str(work), "checks": []}
    user_config_before = md5_of(USER_CONFIG)
    code = 0
    process = None
    ws = None
    try:
        process, _port, ws = t11.launch(exe, work, report_dir, "cloud")
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
            "勾选在，且默认不勾",
            str(ws.evaluate(f"(document.querySelector('{TICK}')||{{}}).checked")).lower() == "false",
            str(ws.evaluate(f"!!document.querySelector('{TICK}')")),
        )
        # r105：标题只留「已核对」，放行什么、端口号、没放行会怎样都进了 ⓘ。
        checker.check(
            "勾选标题只说核对，细节在 ⓘ 里",
            wait_page(ws, pump, must=("已核对云端安全组与防火墙",)),
            body_text(ws)[-300:],
        )
        checker.check(
            "ⓘ 里说清要核对的端口与入口",
            helpers.wait_js(
                ws,
                "(()=>{const h=Array.from(document.querySelectorAll('#main [data-hint]'))"
                ".map(e=>e.dataset.hint).join('|');"
                "return h.includes('UDP 端口入站')&&h.includes('SSH 入口')"
                "&&h.includes('UDP 51820');})()",
                12.0,
                "云端 ⓘ 文案",
                pump,
            ),
            str(ws.evaluate(
                "Array.from(document.querySelectorAll('#main [data-hint]'))"
                ".map(e=>e.dataset.hint).join('|')"
            ))[-300:],
        )

        checker.check("填进地址", t11.set_value(ws, "#wf-spec", SPEC), "")
        checker.check("填进密码", t11.set_value(ws, "#wf-password", PASSWORD), "")

        # 不勾就点：拦下来，且**不许**进入读指纹
        checker.check("不勾就点「开始部署」", click_when_enabled(ws, pump, START) == "ok", "")
        checker.check(
            "页面说明要先核对云端",
            wait_page(ws, pump, must=("请先核对云端",), must_not=("正在核对服务器身份",)),
            body_text(ws)[-400:],
        )
        # 拦下来那一帧宿主重绘过：等页面拿到新代数，否则下面这次 change 会被闸门吞掉。
        # 空闲快照最多 2 秒一拍、且「内容变了才推」，所以要等够两拍。
        settle(ws, pump, 3.2)

        # 勾上再点：才放行
        checker.check("勾上「已核对云端放行」", tick(ws, pump), "")
        settle(ws, pump, 0.8)
        clicked = click_when_enabled(ws, pump, START) == "ok"
        checker.check(
            "再点「开始部署」→ 真的动手（先落草稿）",
            clicked and wait_draft(work),
            f"clicked={clicked} runs={sorted(p.name for p in (work / 'data' / 'deployments' / 'runs').glob('*.json')) if (work / 'data' / 'deployments' / 'runs').is_dir() else []}",
        )
        # 不再断言「提示消失」：读指纹是对着 TEST-NET 走的，失败回包会把那句换掉，
        # 而换新的那一帧什么时候推过来不由脚本决定（页面可能还停在上一次重绘）。
        # 判据用硬证据：草稿文件只在这道闸放行后才会被写出来。
        checker.check("真实数据根的 config.json 未被改动", md5_of(USER_CONFIG) == user_config_before)
        helpers.screenshot(ws, report_dir / "01-deploy-cloud.png", report.get("shots", []))
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
