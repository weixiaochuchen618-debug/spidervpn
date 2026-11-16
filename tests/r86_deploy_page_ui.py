#!/usr/bin/env python3
"""r86 界面验收：「自己搭服务器」按旧版单页复刻。

基准：`C:\\tradechannel\\ui\\DeploymentPages.ps1`（旧版字段与文案）。
这一页以前被我改成两步（先地址 → 再指纹+密码），用户明确要求改回旧版单页。

本脚本验页面（CDP + 隔离数据根，不需要真服务器）：

1. 进向导 → **一页**里同时有：服务器地址、密码、两个勾选、三个折叠区、开始部署 / 返回上一页；
2. 折叠区「登录账户、密钥与名称」展开后有 线路名称 / 登录账户 / SSH 端口；
3. 密码框带「显示」切换；
4. 填地址 + 密码 → 点「开始部署」→ 进入读指纹等待态（不是立刻报格式错）；
5. 探测失败后退回第 0 步、按钮恢复可点，且**不是**「地址要写成」那种格式错误；
6. 点「返回上一页」→ 回首页。

（指纹未知时弹「确认首次服务器身份」那条路，由单元用例守：
 `uiweb::tests::` 里断言了对话框 Body 含目标与指纹、Scope=deploy-identity、
 取消不发命令、确认才走 `deploy_start_steps()`。这里没有真服务器，造不出成功握手。）

用法：

  python tests/r86_deploy_page_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r86-deploy-page\\acceptance \\
      --work C:\\tc-rs-build\\r86\\root
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker

# 192.0.2.0/24 是 TEST-NET-1，保证不可达：探测会失败，但失败原因必须是网络，不是地址格式。
SPEC = "192.0.2.10"
PASSWORD = "Test-Passw0rd"

SINGLE_PAGE = [
    "服务器地址",
    "在这台电脑记住登录资料",
    # r105：这两句解释进了 ⓘ（正文只留动作），标题也缩短了。
    "中断后可用这份资料继续",
    "高级部署设置",
    "服务器要求与购买建议",
    "开始部署",
    "返回上一页",
]
ACCOUNT_FIELDS = ["线路名称", "登录账户", "SSH 端口"]


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

    if args.allow_running:
        print("[warn] --allow-running：不检查已有实例（独立数据根，互不干扰）", flush=True)
    else:
        t11.no_running_host()

    checker = Checker()
    report: dict = {
        "mode": "deploy-page-single",
        "exe": str(exe),
        "work": str(work),
        "spec": SPEC,
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    ws = None
    try:
        process, _port, ws = t11.launch(exe, work, report_dir, "deploypage")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪（导航与主内容都在）",
            helpers.wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ),
            body_text(ws)[-300:],
        )
        checker.check(
            "进入自己搭服务器向导",
            click_when_enabled(ws, pump, "#main [data-action=add]") == "ok"
            and helpers.wait_js(ws, "!!document.querySelector('#wf-spec')", 20, "向导", pump),
            body_text(ws)[:300],
        )

        text = body_text(ws)
        missing = [item for item in SINGLE_PAGE if item not in text]
        checker.check("一页收完：八处关键文字都在", not missing, f"缺：{missing}｜{text[:600]}")

        # 折叠区里的账户三字段：默认收起，展开后必须都在。
        checker.check(
            "折叠区「登录账户、密钥与名称」存在",
            "登录账户、密钥与名称" in text and bool(ws.evaluate("!!document.querySelector('#main details[data-wf=deploy-access]')")),
            text[:400],
        )
        click(ws, "#main details[data-wf=deploy-access] summary")
        helpers.wait_js(ws, "true", 1, "展开", pump)
        opened = body_text(ws)
        missing = [item for item in ACCOUNT_FIELDS if item not in opened]
        checker.check("展开后三个账户字段都在", not missing, f"缺：{missing}｜{opened[:600]}")

        checker.check(
            "密码框带「显示」切换",
            bool(
                ws.evaluate(
                    "(()=>{const p=document.querySelector('#wf-password');"
                    "const t=document.querySelector('#main [data-password-toggle=wf-password]');"
                    "return !!p&&p.type==='password'&&!!t;})()"
                )
            ),
            "",
        )

        checker.check("填进地址", t11.set_value(ws, "#wf-spec", SPEC), "")
        checker.check("填进密码", t11.set_value(ws, "#wf-password", PASSWORD), "")

        checker.check("点「开始部署」", click_when_enabled(ws, pump, "[data-wf=start]") == "ok", "")
        started = helpers.wait_js(
            ws,
            "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
            "const b=document.querySelector('[data-wf=start]');"
            "return t.includes('正在读取主机指纹')||(!!b&&b.disabled);})()",
            10,
            "进入读指纹等待态",
            pump,
        )
        checker.check("真的开始读指纹（不是立刻报格式错）", started, body_text(ws)[-400:])
        checker.check("不出现「地址要写成」", "地址要写成" not in body_text(ws), body_text(ws)[-300:])

        # 探测必然失败（TEST-NET）。等它退回，按钮恢复可点。
        back = helpers.wait_js(
            ws,
            "(()=>{const b=document.querySelector('[data-wf=start]');"
            "return !!b&&!b.disabled;})()",
            40,
            "探测失败后退回",
            pump,
        )
        text = body_text(ws)
        checker.check("探测失败后退回第 0 步", back, text[-400:])
        checker.check(
            "失败原因是网络/指纹，不是地址格式",
            back and "地址要写成" not in text and (SPEC in text or "指纹" in text or "连接" in text),
            text[-500:],
        )
        helpers.screenshot(ws, report_dir / "01-single-page.png", report["shots"])

        checker.check("点「返回上一页」", click_when_enabled(ws, pump, "[data-wf=back]") == "ok", "")
        checker.check(
            "返回后回到首页（向导消失）",
            helpers.wait_js(
                ws,
                "!document.querySelector('#wf-spec')"
                "&&!!document.querySelector('#main [data-action=add]')",
                20,
                "回首页",
                pump,
            ),
            body_text(ws)[-400:],
        )
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
            except Exception:  # noqa: BLE001
                pass
        if not args.keep_open and process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        leftovers = process is not None and process.poll() is None
        print(f"残留进程：{'有' if leftovers else '无'}", flush=True)
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
