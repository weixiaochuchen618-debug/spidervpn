#!/usr/bin/env python3
"""r65 界面验收：C7 服务器记录改名 + 身份查看。

r65 之前，「设置 → 服务器」只能看名称与地址；改名要手改 `record.json`，
指纹/记录时间这些身份事实也不上屏。r65 起：

- 每条记录显示登录目标、指纹、记录时间（都是公开字段，不含密码）；
- 「改名」只把那一张卡换成输入框，保存时才发 `server-rename`；
- 改名只动本机 `record.json` 的 `Name` 与 `UpdatedAtUtc`：地址、指纹、
  登录凭据都不变（凭据熵不含 Name，所以不会要求重新输密码）；
- 空名/超长/控制字符在页面就挡下，一条命令都不发。

用法：

  python tests/r65_servers_rename_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir C:\\tc-rs-build\\r65-servers
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
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
free_port = helpers.free_port
post = r54.post
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

RUNTIME = r54.RUNTIME
USER_CONFIG = r54.USER_CONFIG
md5_of = r54.md5_of
prepare_root = r54.prepare_root
processes_of = r54.processes_of
responsive_pipe = r54.responsive_pipe

SERVER_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
FINGERPRINT = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCD"
CREATED = "2026-11-11T10:00:00Z"
ORIGINAL = "东京节点"
RENAMED = "东京主力"


def page_has(ws: WebSocket, text: str, seconds: float = 6.0, pump: Pump | None = None) -> bool:
    expr = "document.body.innerText.includes(" + json.dumps(text, ensure_ascii=False) + ")"
    return wait_js(ws, expr, seconds, text[:20], pump)


def click(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def type_name(ws: WebSocket, value: str) -> bool:
    expr = (
        "(()=>{const e=document.getElementById('wf-name');if(!e)return false;"
        "e.focus();e.value=%s;"
        "e.dispatchEvent(new Event('input',{bubbles:true}));"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"
        % json.dumps(value, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def record_path(root: Path) -> Path:
    return root / "data" / "servers" / SERVER_ID / "record.json"


def read_record(root: Path) -> dict:
    return json.loads(record_path(root).read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    exe = Path(args.exe).resolve()
    root = report_dir / "root"

    live = responsive_pipe()
    if live:
        raise SystemExit(f"已经有一个 SpiderVPN 在跑（{live}），请先关掉它再跑这条验收。")
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    user_config_md5 = md5_of(USER_CONFIG)
    root_info = prepare_root(root)
    # 手写一条形状完整的记录：身份字段可控，断言不依赖现场有没有服务器。
    dir_path = root / "data" / "servers" / SERVER_ID
    dir_path.mkdir(parents=True, exist_ok=True)
    dir_path.joinpath("record.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ServerRecord",
                "Id": SERVER_ID,
                "Name": ORIGINAL,
                "Host": "203.0.113.10",
                "Port": 22,
                "User": "root",
                "Fingerprint": FINGERPRINT,
                "CreatedAtUtc": CREATED,
                "UpdatedAtUtc": CREATED,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    before = record_path(root).read_bytes()

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "dataRoot": root_info,
        "shots": [],
        "checks": [],
    }

    port = free_port()
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(root)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log = (report_dir / "host.log").open("wb")
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] host pid={process.pid} cdp={port} root={root}", flush=True)

    ws: WebSocket | None = None
    try:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(process.pid)

        checker.check(
            "0 真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                30,
                "页面初始化",
                pump,
            ),
        )

        # ---------- 1：入口 ----------
        post(ws, {"Type": "navigate", "Page": "settings"})
        checker.check(
            "1 设置页出现「服务器」卡片",
            wait_js(ws, '!!document.querySelector(\'[data-action="servers"]\')', 15, "服务器卡片", pump),
        )
        checker.check("1 点开「服务器」", click(ws, '[data-action="servers"]'))
        checker.check(
            "1 服务器页出现（有返回按钮）",
            wait_js(ws, "!!document.querySelector('[data-wf=\"back\"]')", 15, "服务器页", pump),
        )
        checker.check("1 列出这台服务器", page_has(ws, ORIGINAL, 8, pump))

        # ---------- 2：身份事实 ----------
        checker.check("2 登录目标带端口", page_has(ws, "root@203.0.113.10:22", 6, pump))
        checker.check("2 指纹上屏", page_has(ws, f"指纹 {FINGERPRINT}", 6, pump))
        checker.check("2 记录时间上屏", page_has(ws, f"记录于 {CREATED}", 6, pump))
        screenshot(ws, report_dir / "01-identity.png", report["shots"])

        # ---------- 3：点改名只开输入框，不写盘 ----------
        checker.check(
            "3 点「改名」",
            click(ws, f'[data-wf="server-rename:{SERVER_ID}"]'),
        )
        checker.check(
            "3 出现输入框且带当前名称",
            wait_js(
                ws,
                "(()=>{const e=document.getElementById('wf-name');"
                f"return !!e && e.value==={json.dumps(ORIGINAL, ensure_ascii=False)};}})()",
                10,
                "改名输入框",
                pump,
            ),
        )
        checker.check(
            "3 打开改名没有写盘",
            record_path(root).read_bytes() == before,
            "点一下按钮就落盘是回归",
        )
        screenshot(ws, report_dir / "02-editing.png", report["shots"])

        # ---------- 4：保存 ----------
        checker.check("4 输入新名称", type_name(ws, RENAMED))
        checker.check("4 点「保存名称」", click(ws, '[data-wf="save-server-rename"]'))
        checker.check("4 页面提示已改名", page_has(ws, f"已改名为「{RENAMED}」", 10, pump))
        checker.check("4 列表显示新名称", page_has(ws, RENAMED, 6, pump))
        after = read_record(root)
        checker.check("4 磁盘记录真的改了", after.get("Name") == RENAMED, after.get("Name"))
        checker.check("4 指纹没变", after.get("Fingerprint") == FINGERPRINT, after.get("Fingerprint"))
        checker.check("4 地址没变", after.get("Host") == "203.0.113.10", after.get("Host"))
        checker.check("4 创建时间没变", after.get("CreatedAtUtc") == CREATED, after.get("CreatedAtUtc"))
        checker.check("4 输入框收起", not bool(ws.evaluate("!!document.getElementById('wf-name')")))
        screenshot(ws, report_dir / "03-renamed.png", report["shots"])

        # ---------- 5：取消不改盘 ----------
        checker.check("5 再点「改名」", click(ws, f'[data-wf="server-rename:{SERVER_ID}"]'))
        checker.check(
            "5 输入框又出现",
            wait_js(ws, "!!document.getElementById('wf-name')", 10, "再次改名", pump),
        )
        checker.check("5 输入一个不保存的名字", type_name(ws, "不要保存"))
        md5_before_cancel = md5_of(record_path(root))
        checker.check("5 点「取消」", click(ws, '[data-wf="cancel-server-rename"]'))
        checker.check(
            "5 取消后回到列表",
            wait_js(ws, "!document.getElementById('wf-name')", 10, "取消改名", pump),
        )
        checker.check("5 取消没有写盘", md5_of(record_path(root)) == md5_before_cancel)
        checker.check("5 列表仍是已保存的名字", page_has(ws, RENAMED, 6, pump))

        # ---------- 6：空名称在页面挡下 ----------
        checker.check("6 再点「改名」", click(ws, f'[data-wf="server-rename:{SERVER_ID}"]'))
        checker.check(
            "6 输入框出现",
            wait_js(ws, "!!document.getElementById('wf-name')", 10, "第三次改名", pump),
        )
        checker.check("6 清空名称", type_name(ws, ""))
        md5_before_invalid = md5_of(record_path(root))
        checker.check("6 点「保存名称」", click(ws, '[data-wf="save-server-rename"]'))
        checker.check("6 页面说明原因", page_has(ws, "1–120", 6, pump))
        checker.check("6 空名称没有写盘", md5_of(record_path(root)) == md5_before_invalid)
        checker.check("6 输入框仍留着", bool(ws.evaluate("!!document.getElementById('wf-name')")))
        checker.check("6 点「取消」收尾", click(ws, '[data-wf="cancel-server-rename"]'))
        screenshot(ws, report_dir / "04-invalid.png", report["shots"])

        # ---------- 收尾 ----------
        checker.check("8 用户配置没被改过（config.json md5 一致）", md5_of(USER_CONFIG) == user_config_md5)
        checker.check("8 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check("8 收尾时没有残留的 spidervpn 进程", len(processes_of("spidervpn.exe")) <= 1)

    finally:
        try:
            if ws is not None:
                ws.close()
        except Exception:  # noqa: BLE001
            pass
        if not args.keep_open:
            try:
                process.terminate()
                process.wait(timeout=15)
            except Exception:  # noqa: BLE001
                try:
                    process.kill()
                except Exception:  # noqa: BLE001
                    pass
        log.close()

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
