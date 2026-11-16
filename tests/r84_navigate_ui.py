#!/usr/bin/env python3
"""r84 界面验收：表单页必须走得掉（导航 / 面包屑都要真的生效）。

现场（用户实测）：「自己搭服务器」向导第 0 步点「← 返回首页」没反应，点左侧
「线路 / 应用 / 设置」也没反应——被关在向导里。

根因：面包屑是 `workflow()` 按 `ParentPage` 自动生成的 `data-page` 按钮 → 发 `navigate`；
而宿主对 `navigate` **无条件保留表单**，前端又按 `state.Form` 优先渲染，于是页面照旧
画着向导。第 0 步没有「关闭」按钮，就彻底没有出口。

修法：`navigate` 关掉「没有未保存改动」的表单（有改动的仍保留，A9 离页保护不动）。

本脚本验页面（CDP + 隔离数据根，不需要真服务器）：

1. 空数据根 → 首页空态有「自己搭服务器」；
2. 点它 → 进入向导；
3. 点面包屑「← 返回首页」→ 首页（向导消失、导航回到首页 active）；
4. 再进向导 → 点左侧「线路」→ 线路页；
5. 再进向导 → 点左侧「应用」→ 应用页；
6. 再进向导 → 点左侧「设置」→ 设置页。

判据用 `nav` 的 active 类：宿主渲染时 `active = state.Form ? ParentPage : page`，
所以「目标页变成 active」同时证明了两件事——表单已关、页面已切。

用法：

  python tests/r84_navigate_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r84-form-exit\\acceptance \\
      --work C:\\tc-rs-build\\r84\\root
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
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

# 判「在向导里」只看地址框在不在：按钮文案随版式变（r86 起是「开始部署」），
# 拿文案当判据会在正常的版式调整时变成假红。
WIZARD_SELECTOR = "#wf-spec"


def body_text(ws) -> str:
    return t11.body_text(ws)


def click(ws, selector: str) -> str:
    """按选择器点一个元素；返回 ok / missing / disabled（比坐标点击稳）。"""
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


def click_when_enabled(ws, pump, selector: str, seconds: float = 25.0) -> str:
    """等到按钮真的可点再点。

    刚启动那几秒宿主在做自检，首页与导航会短暂 `disabled`（`entryBusy()`）；
    直接点会拿到 `disabled`，看起来像「按钮坏了」——其实只是没等。
    """
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


def in_wizard(ws, pump, seconds: float = 20.0) -> bool:
    return helpers.wait_js(
        ws,
        f"!!document.querySelector({json.dumps(WIZARD_SELECTOR)})",
        seconds,
        "自己搭服务器向导",
        pump,
    )


def left_wizard(ws, pump, page: str, seconds: float = 20.0) -> bool:
    """等向导消失、并且导航真的切到了目标页（active 类）。"""
    return helpers.wait_js(
        ws,
        "(()=>{"
        f"if(document.querySelector({json.dumps(WIZARD_SELECTOR)}))return false;"
        "const item=document.querySelector(" + json.dumps(f"nav [data-page={page}]") + ");"
        "return !!item&&item.classList.contains('active');})()",
        seconds,
        f"离开向导并切到「{page}」",
        pump,
    )


def open_wizard_from_home(ws, pump) -> str:
    """回首页 → 点「自己搭服务器」。任何页面上都能用（先回首页）。"""
    if click_when_enabled(ws, pump, "nav [data-page=home]") != "ok":
        return "no-home-nav"
    if not helpers.wait_js(
        ws,
        "!!document.querySelector('#main [data-action=add]')",
        20,
        "首页空态",
        pump,
    ):
        return "no-add-button"
    return click_when_enabled(ws, pump, "#main [data-action=add]")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    # 默认拒绝「已有实例在跑」（与其它验收脚本一致）。加这个开关才放行：
    # 本脚本用**独立数据根**（互斥名按数据根哈希，不同）、独立代理键、空闲 CDP 端口，
    # 与用户自己开着的窗口互不干扰。用户开着窗口时也能跑，不必让他先关掉。
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
        "mode": "form-exit",
        "exe": str(exe),
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    ws = None
    try:
        process, _port, ws = t11.launch(exe, work, report_dir, "exit")
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

        # ① 面包屑
        checker.check("进入自己搭服务器向导", open_wizard_from_home(ws, pump) == "ok", body_text(ws)[:300])
        checker.check("向导页有「读取指纹并继续」", in_wizard(ws, pump), body_text(ws)[:400])
        helpers.screenshot(ws, report_dir / "01-wizard.png", report["shots"])
        checker.check(
            "面包屑存在且可点",
            click_when_enabled(ws, pump, "#main .breadcrumb button") == "ok",
            "",
        )
        checker.check("面包屑真的回到了首页（向导消失）", left_wizard(ws, pump, "home"), body_text(ws)[:400])

        # ② 左侧导航三条
        for page in ("lines", "apps", "settings"):
            checker.check(f"回首页并进入向导（测「{page}」）", open_wizard_from_home(ws, pump) == "ok", "")
            checker.check(f"已进入向导（{page}）", in_wizard(ws, pump), body_text(ws)[:300])
            checker.check(
                f"点左侧「{page}」",
                click_when_enabled(ws, pump, f"nav [data-page={page}]") == "ok",
                "",
            )
            checker.check(
                f"导航真的切到「{page}」（向导消失）",
                left_wizard(ws, pump, page),
                body_text(ws)[:400],
            )
        helpers.screenshot(ws, report_dir / "02-after-nav.png", report["shots"])
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
