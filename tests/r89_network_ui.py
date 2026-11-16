#!/usr/bin/env python3
"""r89 界面验收：线路「出口网卡」绑定（A 组网卡绑定，对齐 旧版的 LineNetworkInterfaces）。

改动前：线路页只有「标准（UDP）/兼容（TCP）」两档，绑网卡是连接时按**系统默认**
自动决定的——用户没法让交易线路只走网线，也没法发现「我指定的那块网卡不在了」。

本脚本全部点真实界面（CDP 驱动装好的 exe），并且**以磁盘上的
`data/line-network.json` 为最终判据**：页面上说「已保存」不算数，写进去才算。

覆盖：
1. 打开「连接方式与网络」→ 出现出口网卡下拉，第一项是「跟随系统默认（当前：X）」；
2. 选一张真实网卡 → 保存 → 磁盘上落下这条绑定，且下拉保持选中；
3. 改回「跟随系统默认」→ 保存 → 磁盘上那条被删掉（只剩它时文件本身消失）；
4. 绑定了一块**这台电脑没有**的网卡 → 页面直接说「现在不在这台电脑上」，
   选项上标「这台电脑上没有」，并说明连接会被拒绝；
5. 收尾：现场（真实数据根）的 config.json 一个字节没动。

用法：
  python tests/r89_network_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r89-network \\
      --work D:\\vpn构建\\reports-tmp\\r89-work [--allow-running]
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
r54 = importlib.import_module("r54_p013_guard_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker
USER_CONFIG = r54.USER_CONFIG
md5_of = r54.md5_of

STALE = "雷雳网桥-不存在"


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


def choose(ws, pump, selector: str, index: int) -> bool:
    """把下拉选到第 index 项并派发 change（页面靠 change 记选择）。"""
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + f");if(!e)return 'missing';e.value={json.dumps(str(index))};"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 1, "重画", pump)
    return ok


def settle(ws, pump, seconds: float = 1.4) -> None:
    """等页面追上宿主的新代数。

    宿主处理完表单事件会 `restructure()`（`Generation` +1）；页面拿到新代之前发出的
    下一次 `form` 事件会被 `Generation` 闸门**静默丢掉**（r87 真机验收的同一课）。
    `wait_js("true", ...)` 会立刻返回，所以这里必须真的等够一帧。
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pump.tick()
        time.sleep(0.2)


def wait_page(ws, pump, must=(), seconds: float = 10.0) -> bool:
    """等页面出现某句文案（宿主改判/落盘后由下一帧快照重画）。"""
    cond = "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
    for item in must:
        cond += f"if(!t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    cond += "return true;})()"
    return helpers.wait_js(ws, cond, seconds, "页面文案", pump)


def bindings(work: Path) -> dict:
    path = work / "data" / "line-network.json"
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return dict(raw.get("bindings") or {})


def write_binding(work: Path, line_id: str, name: str) -> None:
    path = work / "data" / "line-network.json"
    path.write_text(
        json.dumps({"schema": 1, "bindings": {line_id: name}}, ensure_ascii=False),
        encoding="utf-8",
    )


def seed(work: Path) -> None:
    data = work / "data"
    data.mkdir(parents=True, exist_ok=True)
    cfg = {
        "schema": 2,
        "selected": "hk",
        "lines": [
            {"id": "hk", "name": "香港 01", "proxy_endpoint": "127.0.0.1:17901"},
            {"id": "jp", "name": "东京 02", "proxy_endpoint": "127.0.0.1:17902"},
        ],
    }
    (data / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def open_line_settings(ws, pump) -> bool:
    """线路页 → 线路抽屉 → 「连接方式与网络…」。"""
    if click_when_enabled(ws, pump, "nav [data-page=lines]") != "ok":
        return False
    if not helpers.wait_js(
        ws, "document.querySelectorAll('#main [data-action=details]').length>0", 20, "线路卡", pump
    ):
        return False
    if click_when_enabled(ws, pump, "#main [data-action=details]") != "ok":
        return False
    if not helpers.wait_js(
        ws, "!!document.querySelector('#drawer [data-action=lineSettings]')", 15, "线路抽屉", pump
    ):
        return False
    if click_when_enabled(ws, pump, "#drawer [data-action=lineSettings]") != "ok":
        return False
    return helpers.wait_js(
        ws, "!!document.querySelector('#wf-net-interface')", 20, "出口网卡下拉", pump
    )


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
    report = {"mode": "line-network", "exe": str(exe), "work": str(work), "checks": []}
    user_config_before = md5_of(USER_CONFIG)
    code = 0
    process = None
    ws = None
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "network")
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
            body_text(ws)[-200:],
        )

        # 1. 打开「连接方式与网络」→ 下拉在，第一项是「跟随系统默认（当前：X）」
        opened = open_line_settings(ws, pump)
        checker.check("打开线路的「连接方式与网络」", opened, body_text(ws)[-300:])
        # 打开会重绘一次（列表是现读的）。等页面拿到新代数再动手：
        # `change` 事件要过宿主的 `Generation` 闸门，抢在前一代就会被静默丢掉。
        settle(ws, pump, 1.6)
        first_label = str(
            ws.evaluate(
                "(()=>{const e=document.querySelector('#wf-net-interface');"
                "return e&&e.options.length?e.options[0].textContent:'';})()"
            )
            or ""
        )
        option_count = int(
            ws.evaluate(
                "(()=>{const e=document.querySelector('#wf-net-interface');return e?e.options.length:0;})()"
            )
            or 0
        )
        checker.check(
            "第一项是「跟随系统默认」且说明当前默认网卡",
            first_label.startswith("跟随系统默认") and "当前" in first_label,
            first_label,
        )
        checker.check("下拉里还有本机真实网卡", option_count >= 2, f"options={option_count}")

        # 2. 选第一张真实网卡 → 保存 → 磁盘出现这条绑定
        real_interface = str(
            ws.evaluate(
                "(()=>{const e=document.querySelector('#wf-net-interface');"
                "return e&&e.options.length>1?e.options[1].value:'';})()"
            )
            or ""
        )
        real_label = str(
            ws.evaluate(
                "(()=>{const e=document.querySelector('#wf-net-interface');"
                "return e&&e.options.length>1?e.options[1].textContent:'';})()"
            )
            or ""
        )
        checker.check("选一张真实网卡", choose(ws, pump, "#wf-net-interface", 1), real_label)
        checker.check(
            "点「保存出口网卡」",
            click_when_enabled(ws, pump, "[data-wf=save-net]") == "ok",
            "",
        )
        checker.check(
            "页面显示「当前绑定：选中的那张」（这条只认磁盘回读，不认一句提示）",
            wait_page(ws, pump, must=(f"当前绑定：{real_label}",)),
            body_text(ws)[-300:],
        )
        settle(ws, pump)
        stored = bindings(work)
        checker.check(
            "磁盘上真的写进了这条绑定",
            stored.get("hk") == real_label,
            f"bound={stored.get('hk')!r} 期望 {real_label!r}",
        )
        checker.check(
            "保存后下拉仍选着它（照着回包里的绑定值重画）",
            int(
                ws.evaluate(
                    "(()=>{const e=document.querySelector('#wf-net-interface');return e?e.value:-1;})()"
                )
                or -1
            )
            == 1,
            str(
                ws.evaluate(
                    "(()=>{const e=document.querySelector('#wf-net-interface');return e?e.value:'missing';})()"
                )
            ),
        )

        # 3. 改回「跟随系统默认」→ 保存 → 绑定被删、文件消失
        checker.check("改回「跟随系统默认」", choose(ws, pump, "#wf-net-interface", 0), "")
        settle(ws, pump)
        checker.check(
            "再次保存", click_when_enabled(ws, pump, "[data-wf=save-net]") == "ok", ""
        )
        checker.check(
            "页面显示「当前绑定：跟随系统默认」",
            wait_page(ws, pump, must=("当前绑定：跟随系统默认",)),
            body_text(ws)[-300:],
        )
        settle(ws, pump)
        checker.check("磁盘上那条绑定没了", bindings(work).get("hk") is None, str(bindings(work)))
        checker.check(
            "只剩一条时文件本身也不留",
            not (work / "data" / "line-network.json").exists(),
            "line-network.json 还在",
        )

        # 4. 指定了一块这台电脑没有的网卡：页面必须直说，并说清后果
        write_binding(work, "hk", STALE)
        open_line_settings(ws, pump)
        checker.check(
            "不存在的网卡：页面说「现在不在这台电脑上」",
            wait_page(ws, pump, must=(STALE, "不在这台电脑上"), seconds=15),
            body_text(ws)[-400:],
        )
        checker.check(
            "并且说清后果（连接会被拒绝）",
            wait_page(ws, pump, must=("连接会被拒绝",)),
            body_text(ws)[-400:],
        )
        stale_label = str(
            ws.evaluate(
                "(()=>{const e=document.querySelector('#wf-net-interface');if(!e)return '';"
                "for(const o of e.options){if(o.textContent.includes('这台电脑上没有'))return o.textContent;}"
                "return '';})()"
            )
            or ""
        )
        checker.check(
            "下拉里那一项标着「这台电脑上没有」",
            STALE in stale_label and "这台电脑上没有" in stale_label,
            stale_label,
        )
        checker.check(
            "选中的就是那一项（不许显示成「跟随默认」）",
            str(
                ws.evaluate(
                    "(()=>{const e=document.querySelector('#wf-net-interface');"
                    "return e?e.options[e.selectedIndex].textContent:'';})()"
                )
                or ""
            ).startswith(STALE),
            str(
                ws.evaluate(
                    "(()=>{const e=document.querySelector('#wf-net-interface');"
                    "return e?e.options[e.selectedIndex].textContent:'';})()"
                )
                or ""
            ),
        )

        # 5. 现场配置一个字节没动
        checker.check("真实数据根的 config.json 未被改动", md5_of(USER_CONFIG) == user_config_before)
        helpers.screenshot(ws, report_dir / "01-line-network.png", report.get("shots", []))
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
        print(
            f"残留进程：{'有' if process is not None and process.poll() is None else '无'}",
            flush=True,
        )
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
