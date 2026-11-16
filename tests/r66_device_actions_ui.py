#!/usr/bin/env python3
"""r66 真机验收：设备改名 + 卸载服务器通道服务（C1）。

前置：一个**已完整部署**的隔离数据根（`t11_real_deploy_ui.py --mode complete`
或 r63 的暂停用例留下的根）。本脚本不部署、不输密码、不 ssh 改服务器——
所有写操作都从页面按钮发起，脚本只做两件事：点界面、读结果。

验的顺序：

1. 线路抽屉 →「服务器与设备」，设备清单里有本机（`（本机）`）；
2. 点本机的「改名」→ 输入框出现 → 保存 → 页面显示新名字（名字来自服务器）；
3. 点「卸载这台服务器的通道服务…」→ 预览写出影响设备数与「不退订云服务器」；
4. 点「确认卸载」→ 页面说「通道服务已卸载，云服务器未释放」；
5. 关掉宿主，用同数据根跑 `--server-inspect`：隧道必须报「接口不存在」，
   而本机服务器记录仍在（卸载不删记录）。

用法（不需要 TC_SSH_PASSWORD：凭据已在数据根里）：

  python tests/r66_device_actions_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir C:\\tc-rs-build\\r66\\device-actions \\
      --work C:\\tc-rs-build\\r63\\r64-root --host 203.0.113.25
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
t11 = importlib.import_module("t11_real_deploy_ui")
r54 = importlib.import_module("r54_p013_guard_ui")
helpers = t11.helpers

Checker = helpers.Checker
Pump = helpers.Pump
click = helpers.click
post = r54.post
screenshot = helpers.screenshot
wait_js = helpers.wait_js

PAGE_TEXT = "(document.querySelector('#main')||{innerText:''}).innerText"


def page_has(ws, text: str, seconds: float, pump) -> bool:
    return wait_js(ws, f"{PAGE_TEXT}.includes({json.dumps(text, ensure_ascii=False)})", seconds, text[:20], pump)


def type_name(ws, value: str) -> bool:
    expr = (
        "(()=>{const e=document.getElementById('wf-name');if(!e)return false;"
        "e.focus();e.value=%s;"
        "e.dispatchEvent(new Event('input',{bubbles:true}));"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"
        % json.dumps(value, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--host", default="203.0.113.25")
    parser.add_argument("--user", default="root")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    records = sorted((work / "data" / "servers").glob("*/record.json"))
    if not records:
        raise SystemExit(f"这个数据根里没有服务器记录，先做一次完整部署：{work}")
    before_record = records[0].read_bytes()

    t11.no_running_host()
    checker = Checker()
    report: dict = {
        "mode": "device-actions",
        "exe": str(exe),
        "work": str(work),
        "host": args.host,
        "shots": [],
        "checks": [],
    }
    process = None
    code = 0
    try:
        process, _port, ws = t11.launch(exe, work, report_dir, "r66")
        pump = Pump(process.pid)

        checker.check("真实 WebView2 就绪", wait_js(
            ws,
            "document.readyState==='complete'&&!!document.querySelector('#main')",
            30,
            "页面初始化",
            pump,
        ))
        post(ws, {"Type": "navigate", "Page": "lines"})
        checker.check(
            "线路卡片出现",
            wait_js(ws, "!!document.querySelector('#main [data-action=details]')", 20, "线路卡片", pump),
        )
        checker.check("打开线路抽屉", click(ws, "#main [data-action=details]"))
        checker.check(
            "抽屉里有「服务器与设备」",
            wait_js(ws, "!!document.querySelector('#drawer [data-action=lineServer]')", 15, "入口", pump),
        )
        checker.check("点「服务器与设备」", click(ws, "#drawer [data-action=lineServer]"))
        checker.check(
            "设备页拿到回包",
            wait_js(
                ws,
                f"{PAGE_TEXT}.includes('已登记的设备')||{PAGE_TEXT}.includes('读不到设备列表')",
                120,
                "设备列表",
                pump,
            ),
        )
        checker.check("设备清单里有本机", page_has(ws, "（本机）", 10, pump))
        screenshot(ws, report_dir / "01-devices.png", report["shots"])

        checker.check(
            "本机有「改名」按钮",
            wait_js(ws, "!!document.querySelector('[data-wf^=\"device-rename:\"]')", 15, "改名按钮", pump),
        )
        checker.check("点「改名」", click(ws, '[data-wf^="device-rename:"]'))
        checker.check(
            "改名输入框出现",
            wait_js(ws, "!!document.getElementById('wf-name')", 15, "改名输入框", pump),
        )
        checker.check("输入新名字", type_name(ws, "验收设备"))
        checker.check("点「保存名称」", click(ws, '[data-wf="save-device-rename"]'))
        checker.check(
            "页面说名称已更新",
            page_has(ws, "设备名称已更新", 120, pump),
            page_has(ws, "设备 验收设备", 10, pump),
        )
        checker.check("设备行显示新名字", page_has(ws, "设备 验收设备", 10, pump))
        screenshot(ws, report_dir / "02-renamed.png", report["shots"])

        checker.check(
            "有「卸载这台服务器的通道服务…」入口",
            wait_js(ws, "!!document.querySelector('[data-wf=\"uninstall-preview\"]')", 10, "卸载入口", pump),
        )
        checker.check("点卸载预览", click(ws, '[data-wf="uninstall-preview"]'))
        checker.check(
            "预览给出影响设备数",
            page_has(ws, "影响设备：", 120, pump),
        )
        checker.check(
            "预览说明不释放云服务器",
            page_has(ws, "不会退订云服务器", 10, pump),
        )
        checker.check("有「确认卸载」", wait_js(ws, "!!document.querySelector('[data-wf=\"uninstall-confirm\"]')", 10, "确认卸载", pump))
        screenshot(ws, report_dir / "03-preview.png", report["shots"])

        checker.check("点「确认卸载」", click(ws, '[data-wf="uninstall-confirm"]'))
        checker.check(
            "页面说通道服务已卸载",
            page_has(ws, "通道服务已卸载，云服务器未释放", 180, pump),
        )
        checker.check("过期设备列表已收掉", page_has(ws, "重新部署后才能再次读取设备状态", 10, pump))
        screenshot(ws, report_dir / "04-uninstalled.png", report["shots"])

        # 收尾：先关宿主，再用同一数据根做只读检查。
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        process = None

        env = dict(os.environ)
        env["SPIDERVPN_ROOT"] = str(work)
        env.pop("SPIDERVPN_PROXY_KEY", None)
        inspected = subprocess.run(
            [str(exe), "--server-inspect", f"{args.user}@{args.host}"],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
        )
        report["inspect"] = inspected.stdout
        (report_dir / "server-inspect.txt").write_text(inspected.stdout, encoding="utf-8")
        checker.check(
            "服务器上隧道已不存在（接口不存在/未部署）",
            inspected.returncode == 0
            and ("接口不存在" in inspected.stdout or "还没有对应接口" in inspected.stdout),
            inspected.stdout[-500:],
        )
        checker.check(
            "服务器记录仍然保留（卸载不删记录）",
            records[0].is_file() and records[0].read_bytes() == before_record,
        )
    finally:
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    process.kill()
                except Exception:  # noqa: BLE001
                    pass

    report["checks"] = checker.checks
    (report_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    passed = sum(1 for item in checker.checks if item["ok"])
    total = len(checker.checks)
    print(f"\n合计 {passed}/{total}；证据 {report_dir}")
    return 0 if checker.all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
