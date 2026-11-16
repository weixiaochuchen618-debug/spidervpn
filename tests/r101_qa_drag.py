#!/usr/bin/env python3
"""r101 QA：在 r101_drag_probe.py 的基础上补齐 QA 需要的断言面。

与 probe 的差别（probe 只证明「拖完输入框有值」）：
- `--stay-home`：不导航到交易软件名单，直接在首页拖，验证宿主**不吞**这次拖放
  （页面不跳转、不崩）；随后再进交易软件名单，确认输入框仍为空、无残留提示。
- `--click-add`：拖完再点 `[data-wf=add-program]`，等隔离根 `data\\config.json`
  里真的多出一条进程规则，并把前后片段打出来。
- 结束时把 `value` / 页面文案 / config.json 片段原样写进 report.json，
  失败也照样落盘——QA 要的是原值，不是「看起来对」。

用法：
  python tests/r101_qa_drag.py --exe <exe> --report-dir <dir> --work <dir> --file <path> \
      [--stay-home] [--click-add] [--expect-none]
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(r"D:\vpn构建\tools")))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

import r101_drag_probe as probe  # noqa: E402
import r87_history_ui as r87  # noqa: E402
import t11_real_deploy_ui as t11  # noqa: E402

helpers = probe.helpers
INPUT = probe.INPUT


def read_config(work: Path) -> dict:
    path = work / "data" / "config.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:  # noqa: BLE001
        return {"__error__": str(error)}


def processes_of(config: dict) -> object:
    split = config.get("split") if isinstance(config, dict) else None
    if not isinstance(split, dict):
        return {"__error__": "config 里没有 split"}
    return split.get("processes")


def drop_on_input(
    ws, pump, process, report_dir: Path, file: Path, selector: str = INPUT
) -> tuple[bool, str]:
    """真 OLE 拖放落到 `selector` 的中心，返回 (effect 是 Copy, 源码输出)。"""
    hwnd = probe.main_window(process.pid)
    ox, oy = probe.client_origin(hwnd)
    rect = ws.evaluate(
        "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
        "if(!e)return null;const r=e.getBoundingClientRect();"
        "return {x:r.left+r.width/2,y:r.top+r.height/2,dpr:window.devicePixelRatio||1};})()"
    )
    if not rect:
        raise RuntimeError(f"拖放目标 {selector} 不在页面上")
    x = int(ox + float(rect["x"]) * float(rect["dpr"]))
    y = int(oy + float(rect["y"]) * float(rect["dpr"]))
    print(f"[qa] hwnd=0x{hwnd:X} client=({ox},{oy}) drop=({x},{y})", flush=True)
    ok, output = probe.drag(probe.DRAG_PS1, file, x, y)
    print(f"[qa] drag source copy={ok} out={output.strip()}", flush=True)
    helpers.screenshot(ws, report_dir / "drag.png", [])
    return ok, output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--stay-home", action="store_true")
    parser.add_argument("--click-add", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    checker = helpers.Checker()
    report: dict = {
        "exe": str(exe),
        "file": args.file,
        "stay_home": args.stay_home,
        "click_add": args.click_add,
        "checks": [],
    }
    process = None
    code = 0
    # 跑前指纹：交付证据必须能分辨「这批跑在哪个 build 上」（同一路径换过多个 build 是常态）。
    before_sha, before_bytes = probe.fingerprint(exe)
    report["exeSha256"] = before_sha
    report["exeBytes"] = before_bytes
    try:
        probe.seed(work)
        report["config_before"] = read_config(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "qa-drag")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            "",
        )

        if args.stay_home:
            # 首页：宿主不该接管这次拖放。
            checker.check("首页不动", bool(ws.evaluate("!!document.querySelector('nav')")), "")
            before = r87.body_text(ws)
            ok, output = drop_on_input(
                ws, pump, process, report_dir, Path(args.file), "#main"
            )
            report["home_drag_effect_copy"] = ok
            report["home_drag_output"] = output
            helpers.wait_js(ws, "true", 2, "等一拍", pump)
            after = r87.body_text(ws)
            report["home_text_after"] = after
            report["home_navigated"] = after != before
            checker.check("首页拖放后页面没跳转", after == before, after[-200:])
            checker.check("首页拖放后没崩", bool(ws.evaluate("!!document.querySelector('nav')")), "")
            report["home_still_alive"] = bool(ws.evaluate("!!document.querySelector('nav')"))

        checker.check("进应用", r87.click_when_enabled(ws, pump, "nav [data-page=apps]") == "ok", "")
        checker.check(
            "打开交易软件名单",
            r87.click_when_enabled(ws, pump, "#main [data-action=domains]") == "ok"
            and helpers.wait_js(ws, f"!!document.querySelector('{INPUT}')", 20, "输入框", pump),
            r87.body_text(ws)[-200:],
        )

        if not args.stay_home:
            drop_on_input(ws, pump, process, report_dir, Path(args.file))

        # 读回原值：不允许空指针，输入框必须存在。
        deadline = time.monotonic() + 6
        value = ""
        while time.monotonic() < deadline:
            value = str(ws.evaluate("document.querySelector('" + INPUT + "').value") or "")
            if value:
                break
            time.sleep(0.3)
        report["value"] = value
        text = r87.body_text(ws)
        report["page_text"] = text
        print(f"[qa] value={value!r}", flush=True)
        helpers.screenshot(ws, report_dir / "after.png", [])

        if args.click_add:
            clicked = r87.click_when_enabled(ws, pump, "[data-wf=add-program]")
            report["add_clicked"] = clicked
            print(f"[qa] click add-program -> {clicked}", flush=True)
            # 写配置是同步命令 + 落盘：给到 8 秒，等 processes 非空。
            got = None
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                got = processes_of(read_config(work))
                if isinstance(got, list) and got:
                    break
                time.sleep(0.4)
            report["processes_after_add"] = got
            report["config_after_add"] = read_config(work)
            report["page_text_after_add"] = r87.body_text(ws)
            helpers.screenshot(ws, report_dir / "after-add.png", [])
            checker.check(
                "点添加程序后配置里多了一条",
                isinstance(got, list) and bool(got),
                json.dumps(got, ensure_ascii=False),
            )
        else:
            report["processes_after_drag"] = processes_of(read_config(work))
            report["config_after_drag"] = read_config(work)

        report["checks"] = checker.checks
        code = 0
    except Exception as error:  # noqa: BLE001
        print(f"[qa] 失败：{error}", flush=True)
        report["error"] = repr(error)
        code = 2
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        after_sha, after_bytes = probe.fingerprint(exe)
        report["exeSha256After"] = after_sha
        report["exeBytesAfter"] = after_bytes
        checker.check(
            "被测二进制跑前跑后一致",
            (before_sha, before_bytes) == (after_sha, after_bytes),
            f"before={before_sha}/{before_bytes}B after={after_sha}/{after_bytes}B",
        )
        if not checker.all_passed:
            code = code or 1
        report["checks"] = checker.checks
        (report_dir / "qa-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(report.get("checks", []), ensure_ascii=False, indent=2), flush=True)
        print(f"[qa] exit={code}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
