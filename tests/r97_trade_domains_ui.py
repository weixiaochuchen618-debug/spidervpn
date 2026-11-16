#!/usr/bin/env python3
"""r97 界面验收：交易名单的「恢复默认网站」（对齐 旧版的`ResetTradeDomains`）。

旧版的「交易软件名单」页有「恢复默认网站」：把交易网站名单恢复成出厂那一份
（tradingview / tradovate / ninjatrader 等 7 个）。本版对应 `split-reset-trade-domains`，
并且**只替换走「交易出口」的那一组**——程序名单与直连/日常域名规则必须原样保留。

本脚本只验页面与落盘（隔离数据根，不需要真服务器）：

1. 预置配置：一个自定义交易网站、一个直连网站、一个交易程序；
2. 应用页 →「管理交易名单」→ 页面有「恢复默认网站」；
3. 点它 → 页面提示「已恢复默认交易网站（7 条）」；
4. 列表里 7 个默认网站都在，自定义交易网站消失，直连网站还在；
5. `data\\config.json` 落盘一致，程序名单没动；
6. 再点一次 → 提示「已经是默认名单，未变化」（重复点击不写盘）。

用法：

  python tests/r97_trade_domains_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r97-trade-domains \\
      --work C:\\tc-rs-build\\r97\\root
"""
from __future__ import annotations

import argparse
import ctypes
import importlib
import json
import shutil
import sys
import time
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")
r87 = importlib.import_module("r87_history_ui")

Checker = helpers.Checker

CUSTOM_TRADE = "custom-trade.example"
DIRECT_SITE = "bilibili.com"
DEFAULTS = [
    "tradingview.com",
    "tradingview-widget.com",
    "tradingviewusercontent.com",
    "tvc-cdn.com",
    "tradovate.com",
    "tradovateapi.com",
    "ninjatrader.com",
]


def seed(work: Path) -> None:
    data = work / "data"
    data.mkdir(parents=True, exist_ok=True)
    config = {
        "schema": 2,
        "selected": "L1",
        "lines": [
            {"id": "L1", "name": "线路甲", "proxy_endpoint": "127.0.0.1:17901"},
        ],
        "split": {
            "processes": [{"value": "TDXW.exe", "target": "trade"}],
            "domains": [
                {"value": CUSTOM_TRADE, "target": "trade"},
                {"value": DIRECT_SITE, "target": "direct"},
            ],
        },
    }
    (data / "config.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def read_domains(work: Path):
    config = json.loads((work / "data" / "config.json").read_text(encoding="utf-8"))
    return config.get("split", {}).get("domains", [])


def picker_windows(pid: int) -> list:
    """枚举本进程里标题带「选择交易程序」的顶层窗口：(hwnd, 标题, 是否无响应)。"""
    user32 = ctypes.windll.user32
    result = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def enum_proc(hwnd, _lparam):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid:
            length = user32.GetWindowTextLengthW(hwnd)
            if length:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if "选择交易程序" in buf.value:
                    result.append((hwnd, buf.value, bool(user32.IsHungAppWindow(hwnd))))
        return True

    user32.EnumWindows(enum_proc, 0)
    return result


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
    report = {"mode": "trade-domains", "exe": str(exe), "work": str(work), "checks": []}
    code = 0
    process = None
    ws = None
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "trade-domains")
        pump = t11.Pump(process.pid)

        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ),
            r87.body_text(ws)[-200:],
        )
        checker.check(
            "进应用",
            r87.click_when_enabled(ws, pump, "nav [data-page=apps]") == "ok",
            "",
        )
        checker.check(
            "打开交易名单",
            r87.click_when_enabled(ws, pump, "#main [data-action=domains]") == "ok"
            and helpers.wait_js(
                ws, "!!document.querySelector('[data-wf=reset-trade-domains]')", 20, "交易名单", pump
            ),
            r87.body_text(ws)[-300:],
        )
        text = r87.body_text(ws)
        checker.check(
            "页面标题与两张卡（程序 / 交易网站）",
            "交易软件名单" in text and "程序" in text and "交易网站" in text,
            text[:600],
        )
        checker.check(
            "两个输入框与各自按钮都在",
            all(
                bool(ws.evaluate("!!document.querySelector(" + json.dumps(sel) + ")"))
                for sel in (
                    "#wf-program-path",
                    "[data-wf=pick-program]",
                    "[data-wf=add-program]",
                    "#wf-site-domain",
                    "[data-wf=add-site]",
                )
            ),
            "",
        )

        # r100：浏览对话框必须在独立线程上打开，否则整个窗口连同对话框都会被标「未响应」。
        checker.check(
            "点「浏览…」",
            r87.click_when_enabled(ws, pump, "[data-wf=pick-program]") == "ok",
            "",
        )
        dialog = []
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            dialog = picker_windows(process.pid)
            if dialog and not dialog[0][2] and "未响应" not in dialog[0][1]:
                break
            time.sleep(0.2)
        checker.check("选择器窗口出现", bool(dialog), str(dialog))
        if dialog:
            hwnd, title, hung = dialog[0]
            checker.check("标题是「选择交易程序」", "选择交易程序" in title, title)
            checker.check("选择器没有「未响应」", "未响应" not in title, title)
            checker.check("选择器线程有响应", not hung, f"hung={hung} title={title}")
            ctypes.windll.user32.PostMessageW(hwnd, 0x0010, 0, 0)  # WM_CLOSE
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and picker_windows(process.pid):
            time.sleep(0.2)
        checker.check(
            "关闭选择器后页面恢复",
            helpers.wait_js(ws, "document.readyState==='complete'", 10, "页面恢复", pump),
            "",
        )
        checker.check(
            "初始自定义交易规则都在（直连规则不在这页显示）",
            CUSTOM_TRADE in text and "TDXW.exe · 位置未确认" in text and DIRECT_SITE not in text,
            text[:600],
        )

        # 程序：输入完整路径 → 添加程序（旧版两步：浏览只回填，添加才写）。
        checker.check(
            "填程序路径",
            t11.set_value(ws, "#wf-program-path", r"C:\Windows\System32\notepad.exe"),
            "",
        )
        checker.check(
            "点「添加程序」",
            r87.click_when_enabled(ws, pump, "[data-wf=add-program]") == "ok",
            "",
        )
        checker.check(
            "程序行出现名字、路径与状态",
            helpers.wait_js(
                ws,
                "(()=>{const t=document.querySelector('#main').innerText;"
                "return t.includes('notepad.exe · ')&&t.includes("
                + json.dumps(r"C:\Windows\System32\notepad.exe")
                + ");})()",
                12,
                "程序行",
                pump,
            ),
            r87.body_text(ws)[-600:],
        )

        # 网站：独立输入框 → 添加网站。
        checker.check("填网站域名", t11.set_value(ws, "#wf-site-domain", "qq.com"), "")
        checker.check(
            "点「添加网站」",
            r87.click_when_enabled(ws, pump, "[data-wf=add-site]") == "ok",
            "",
        )
        checker.check(
            "网站行出现",
            helpers.wait_js(
                ws,
                "document.querySelector('#main').innerText.includes('qq.com')",
                12,
                "网站行",
                pump,
            ),
            r87.body_text(ws)[-600:],
        )
        config_after_add = json.loads((work / "data" / "config.json").read_text(encoding="utf-8"))
        processes = config_after_add["split"]["processes"]
        checker.check(
            "程序落盘带路径且只存文件名",
            any(
                item["value"] == "notepad.exe"
                and item["target"] == "trade"
                and item.get("path") == r"C:\Windows\System32\notepad.exe"
                for item in processes
            ),
            json.dumps(processes, ensure_ascii=False),
        )
        checker.check(
            "网站落盘为交易出口",
            any(
                item["value"] == "qq.com" and item["target"] == "trade"
                for item in config_after_add["split"]["domains"]
            ),
            json.dumps(config_after_add["split"]["domains"], ensure_ascii=False),
        )

        checker.check(
            "点「恢复默认网站」",
            r87.click_when_enabled(ws, pump, "[data-wf=reset-trade-domains]") == "ok",
            "",
        )
        checker.check(
            "提示说恢复了 7 条",
            helpers.wait_js(
                ws,
                "document.querySelector('#main').innerText.includes('已恢复默认交易网站（7 条）')",
                12,
                "恢复提示",
                pump,
            ),
            r87.body_text(ws)[-500:],
        )
        default_cond = (
            "(()=>{const t=document.querySelector('#main').innerText;return "
            + "&&".join(f"t.includes({json.dumps(name)})" for name in DEFAULTS)
            + ";})()"
        )
        checker.check(
            "7 个默认网站都进列表",
            helpers.wait_js(ws, default_cond, 12, "默认网站", pump),
            r87.body_text(ws)[-800:],
        )
        checker.check(
            "自定义交易网站被替换，直连网站不在这页显示",
            CUSTOM_TRADE not in r87.body_text(ws) and DIRECT_SITE not in r87.body_text(ws),
            r87.body_text(ws)[-600:],
        )

        domains = read_domains(work)
        by_value = {item["value"]: item["target"] for item in domains}
        checker.check(
            "落盘：默认值全部指向交易出口",
            all(by_value.get(name) == "trade" for name in DEFAULTS),
            json.dumps(by_value, ensure_ascii=False),
        )
        checker.check(
            "落盘：自定义交易网站已移除、直连规则保留",
            CUSTOM_TRADE not in by_value and by_value.get(DIRECT_SITE) == "direct",
            json.dumps(by_value, ensure_ascii=False),
        )
        config = json.loads((work / "data" / "config.json").read_text(encoding="utf-8"))
        process_values = [item["value"] for item in config["split"]["processes"]]
        checker.check(
            "落盘：程序名单只增不减（恢复默认网站不碰程序）",
            "TDXW.exe" in process_values and "notepad.exe" in process_values,
            json.dumps(config["split"]["processes"], ensure_ascii=False),
        )

        checker.check(
            "再点一次",
            r87.click_when_enabled(ws, pump, "[data-wf=reset-trade-domains]") == "ok",
            "",
        )
        checker.check(
            "重复点击说「已经是默认名单」",
            helpers.wait_js(
                ws,
                "document.querySelector('#main').innerText.includes('交易网站已经是默认名单，未变化')",
                12,
                "未变化提示",
                pump,
            ),
            r87.body_text(ws)[-500:],
        )
        checker.check(
            "重复点击不改落盘",
            {item["value"]: item["target"] for item in read_domains(work)} == by_value,
            json.dumps(read_domains(work), ensure_ascii=False),
        )
        helpers.screenshot(ws, report_dir / "01-trade-domains.png", report.get("shots", []))
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
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                try:
                    process.kill()
                except Exception:  # noqa: BLE001
                    pass
        print(
            f"残留进程：{'有' if process is not None and process.poll() is None else '无'}",
            flush=True,
        )
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
