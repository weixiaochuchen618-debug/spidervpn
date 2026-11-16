#!/usr/bin/env python3
"""r85 界面验收：只填 IP 也能继续（不再要求写 用户名@主机）。

现场（用户实测）：在「自己搭服务器」只填 `192.168.1.1`，页面报
「地址要写成 用户名@主机，例如 root@203.0.113.10」，不给继续。

真相：后台解析器（`ipc::deploy_target`）本来就允许只填 IP——用户名缺省 `root`、
端口缺省 `22`；命令行 `--server-setup 192.168.1.1` 一直是能跑的。是**界面自己**
多拦了一道 `!spec.contains('@')`，于是同一串地址两条入口两种结果。

修法：删掉界面那道检查（解析规则只留一处），并把提示写清缺省。

本脚本验页面（CDP + 隔离数据根，不需要真服务器）：

1. 进向导 → 提示里说清「只写 IP 或域名时用 root 账号、22 端口登录」；
2. 输入 `192.168.1.1` → 点「读取指纹并继续」；
3. **不出现**「地址要写成」那句话；
4. 页面进入「正在读取主机指纹…」（证明真的去读了，不是原地卡住）。

用法：

  python tests/r85_bare_address_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r85-bare-address\\acceptance \\
      --work C:\\tc-rs-build\\r85\\root
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

SPEC = "192.168.1.1"
OLD_WORD = "地址要写成"
WAIT_WORD = "正在读取主机指纹"  # 也可能是按钮变灰，见下面的判据


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
        "mode": "bare-address",
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
        process, _port, ws = t11.launch(exe, work, report_dir, "bare")
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

        # r105：这句解释从正文挪进了地址标签的 ⓘ（正文只留动作）。
        hint = body_text(ws)
        hint_node = bool(
            ws.evaluate(
                "!!document.querySelector('#main [data-hint*=\"可以粘贴完整登录地址\"]')"
            )
        )
        checker.check(
            "地址提示说清可以只填地址（在 ⓘ 里，不在正文）",
            hint_node and "支持粘贴 IP 或完整登录地址" not in hint,
            {"hintNode": hint_node, "body": hint[:300]},
        )
        # r86 起缺省值落在两个字段上（旧版版式）：登录账户 root、SSH 端口 22。
        checker.check(
            "缺省账户是 root、端口是 22",
            str(ws.evaluate("(document.querySelector('#wf-user')||{}).value||''")) == "root"
            and str(ws.evaluate("(document.querySelector('#wf-port')||{}).value||''")) == "22",
            str(ws.evaluate("[document.querySelector('#wf-user'),document.querySelector('#wf-port')].map(e=>e&&e.value)")),
        )

        checker.check("填进地址（只写 IP）", t11.set_value(ws, "#wf-spec", SPEC), "")
        checker.check("点「开始部署」", click_when_enabled(ws, pump, "[data-wf=start]") == "ok", "")

        # 等待态的两种表现都算数：出现「正在读取主机指纹」文案，或按钮变灰（在跑）。
        started = helpers.wait_js(
            ws,
            "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
            "const b=document.querySelector('[data-wf=start]');"
            f"return t.includes({json.dumps(WAIT_WORD, ensure_ascii=False)})||(!!b&&b.disabled);}})()",
            20,
            "进入读指纹等待态",
            pump,
        )
        text = body_text(ws)
        checker.check("真的开始读指纹（不是原地卡住）", started, text[-400:])
        checker.check("不再出现「地址要写成」", OLD_WORD not in text, text[-400:])
        helpers.screenshot(ws, report_dir / "01-probing.png", report["shots"])
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
