#!/usr/bin/env python3
"""r94 界面验收：管理恢复包（旧版的`ShowManagementRecovery`）。

改动前：服务器页没有「管理恢复资料」入口，换电脑后无法把「这台服务器是谁、
怎么登录」带走。

本脚本做一次**真的换电脑**：
1. 在数据根 A 里铺一条服务器记录，启动程序，从「设置 → 服务器」导出加密恢复包；
2. 关掉 A，用**全新的数据根 B** 启动，把恢复包粘贴进去导入；
3. 断言 B 的 `servers\\<id>\\record.json` 里出现同一台服务器（名字/地址/指纹），
   并且页面说的是「已登记，仍待核验」——不是「已连接/已启用」。

用法：
  python tests/r94_recovery_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r94-recovery \\
      --work D:\\vpn构建\\reports-tmp\\r94-work [--allow-running]
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
helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker

SERVER_ID = "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b"
SERVER_NAME = "恢复测试服务器"
HOST = "203.0.113.10"
FINGERPRINT = "SHA256:" + "A" * 43
PASSWORD = "r94-recovery-pass"


def body_text(ws) -> str:
    return t11.body_text(ws)


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


def value_of(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return e?String(e.value):'';})()"
    )
    return str(ws.evaluate(expr) or "")


def wait_page(ws, pump, must=(), must_not=(), seconds: float = 15.0) -> bool:
    cond = "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
    for item in must:
        cond += f"if(!t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    for item in must_not:
        cond += f"if(t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    cond += "return true;})()"
    return helpers.wait_js(ws, cond, seconds, "页面文案", pump)


def seed_server(work: Path) -> None:
    directory = work / "data" / "servers" / SERVER_ID
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "record.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ServerRecord",
                "Id": SERVER_ID,
                "Name": SERVER_NAME,
                "Host": HOST,
                "Port": 22,
                "User": "root",
                "Fingerprint": FINGERPRINT,
                "CreatedAtUtc": "2026-11-14T00:00:00.000000Z",
                "UpdatedAtUtc": "2026-11-14T00:00:00.000000Z",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def open_servers_page(ws, pump) -> bool:
    return (
        click_when_enabled(ws, pump, "nav [data-page=settings]") == "ok"
        and helpers.wait_js(
            ws, "!!document.querySelector('[data-action=servers]')", 20, "设置页工具", pump
        )
        and click_when_enabled(ws, pump, "[data-action=servers]") == "ok"
        and helpers.wait_js(
            ws, "!!document.querySelector('[data-wf=recovery-import-open]')", 20, "服务器页", pump
        )
    )


def stop(process, ws) -> None:
    if ws is not None:
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except Exception:  # noqa: BLE001
            process.kill()


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
    work_a = work / "a"
    work_b = work / "b"
    (work_a / "data").mkdir(parents=True, exist_ok=True)
    (work_b / "data").mkdir(parents=True, exist_ok=True)
    seed_server(work_a)

    if args.allow_running:
        print("[warn] --allow-running：不检查已有实例（独立数据根，互不干扰）", flush=True)
    else:
        t11.no_running_host()

    checker = Checker()
    report = {"mode": "management-recovery", "exe": str(exe), "work": str(work), "checks": []}
    code = 0
    process_a = process_b = None
    ws_a = ws_b = None
    try:
        # ---- 第一段：数据根 A 导出 ----
        process_a, _port, ws_a = t11.launch(exe, work_a, report_dir, "recovery-a")
        pump = t11.Pump(process_a.pid)
        checker.check(
            "A：页面就绪",
            helpers.wait_js(
                ws_a, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            body_text(ws_a)[-200:],
        )
        checker.check("A：进「设置 → 服务器」", open_servers_page(ws_a, pump), body_text(ws_a)[-400:])
        checker.check(
            "A：服务器页有导入入口与这条记录的导出入口",
            helpers.wait_js(
                ws_a,
                "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
                "return t.includes('导入管理恢复资料') && t.includes('导出管理恢复包')"
                " && t.includes(" + json.dumps(SERVER_NAME, ensure_ascii=False) + ");})()",
                15,
                "恢复入口",
                pump,
            ),
            body_text(ws_a)[-500:],
        )

        export_selector = f'[data-wf="recovery-export:{SERVER_ID}"]'
        checker.check(
            "A：进导出页",
            click_when_enabled(ws_a, pump, export_selector) == "ok"
            and helpers.wait_js(
                ws_a, "!!document.querySelector('#wf-recovery-password')", 15, "导出表单", pump
            ),
            body_text(ws_a)[-400:],
        )
        checker.check(
            "A：目标、密码长度与「包含凭据」勾都在",
            wait_page(
                ws_a,
                pump,
                must=("导出当前服务器的管理恢复包", f"目标：{SERVER_NAME}", "至少 12 个字符"),
            )
            and str(ws_a.evaluate("!!document.querySelector('#wf-recovery-include')")).lower()
            == "true",
            body_text(ws_a)[-400:],
        )
        checker.check(
            "A：默认不含凭据（私钥/口令两格不出现）",
            str(ws_a.evaluate("!document.querySelector('#wf-recovery-key-path')")).lower() == "true",
            "",
        )

        checker.check(
            "A：填恢复包密码",
            t11.set_value(ws_a, "#wf-recovery-password", PASSWORD),
            "",
        )
        checker.check(
            "A：点「加密导出并保存…」",
            click_when_enabled(ws_a, pump, "[data-wf=recovery-export]") == "ok",
            "",
        )
        checker.check(
            "A：页面出现加密后的恢复包",
            helpers.wait_js(
                ws_a,
                "(()=>{const e=document.querySelector('#wf-recovery-package');"
                "return !!e&&e.value.length>100;})()",
                25,
                "恢复包文本",
                pump,
            ),
            body_text(ws_a)[-400:],
        )
        package = value_of(ws_a, "#wf-recovery-package")
        checker.check("A：恢复包不含服务器地址（内层已加密）", HOST not in package, package[:200])
        checker.check(
            "A：有「保存到文件…」按钮",
            str(ws_a.evaluate("!!document.querySelector('[data-wf=recovery-save]')")).lower()
            == "true",
            "",
        )

        helpers.screenshot(ws_a, report_dir / "01-recovery-export.png", report.get("shots", []))
        stop(process_a, ws_a)
        process_a, ws_a = None, None
        package_file = work / "exported.tcrecovery"
        package_file.write_text(package, encoding="utf-8")

        # ---- 第二段：全新数据根 B 导入 ----
        process_b, _port, ws_b = t11.launch(exe, work_b, report_dir, "recovery-b")
        pump = t11.Pump(process_b.pid)
        checker.check(
            "B：页面就绪",
            helpers.wait_js(
                ws_b, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            body_text(ws_b)[-200:],
        )
        checker.check("B：进「设置 → 服务器」", open_servers_page(ws_b, pump), body_text(ws_b)[-400:])
        checker.check(
            "B：全新数据根里没有任何服务器记录",
            wait_page(ws_b, pump, must=("还没有记录任何服务器",)),
            body_text(ws_b)[-400:],
        )
        checker.check(
            "B：进导入页",
            click_when_enabled(ws_b, pump, "[data-wf=recovery-import-open]") == "ok"
            and helpers.wait_js(
                ws_b, "!!document.querySelector('#wf-recovery-text')", 15, "导入表单", pump
            ),
            body_text(ws_b)[-400:],
        )
        checker.check(
            "B：导入页文案与旧版一致",
            wait_page(
                ws_b,
                pump,
                must=("导入已有加密恢复包", "解密并登记待核验服务器", "不会启用线路"),
            ),
            body_text(ws_b)[-400:],
        )
        checker.check(
            "B：粘贴恢复包并填密码",
            t11.set_value(ws_b, "#wf-recovery-text", package)
            and t11.set_value(ws_b, "#wf-recovery-password", PASSWORD),
            "",
        )
        checker.check(
            "B：点「解密并登记待核验服务器」",
            click_when_enabled(ws_b, pump, "[data-wf=recovery-import]") == "ok",
            "",
        )
        checker.check(
            "B：页面说「已登记，仍待核验」",
            wait_page(ws_b, pump, must=("管理资料已登记", "仍待核验")),
            body_text(ws_b)[-500:],
        )

        records = sorted((work_b / "data" / "servers").glob("*/record.json"))
        checker.check("B：磁盘上出现一条服务器记录", len(records) == 1, str(records))
        if records:
            stored = json.loads(records[0].read_text(encoding="utf-8"))
            checker.check(
                "B：记录里的名字/地址/指纹与原服务器一致",
                stored.get("Name") == SERVER_NAME
                and stored.get("Host") == HOST
                and stored.get("Port") == 22
                and stored.get("User") == "root"
                and stored.get("Fingerprint") == FINGERPRINT,
                json.dumps(stored, ensure_ascii=False),
            )
        helpers.screenshot(ws_b, report_dir / "02-recovery-import.png", report.get("shots", []))
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
        if not args.keep_open:
            stop(process_b if process_b is not None else process_a, ws_b if ws_b is not None else ws_a)
        print(
            f"残留进程：{'有' if any(p is not None and p.poll() is None for p in (process_a, process_b)) else '无'}",
            flush=True,
        )
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
