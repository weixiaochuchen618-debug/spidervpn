#!/usr/bin/env python3
"""r59 界面验收：A4 第一轮「删除线路只读预览」。

改动前：点「删除」直接弹一个含糊的确认框，写着「本机的线路配置与记录会一并移除」，
连接中也能点，确认后才发现被拒。改动后：宿主先跑一次只读预览，按三种结论给三种框：

1. **可删**：详情列出「将删除」（config 条目 + 引擎配置/私钥文件）与「将保留」
   （服务器记录与凭据、服务端服务与设备授权、其他线路与记录）；
2. **连接中不可删**：只给「知道了」，没有删除按钮；
3. **最后一条线路**：仍然可删，但要说清删完没有可用的。

本脚本只读 DOM 与隔离数据根，全部点真实界面。收尾核对：现场 config.json 的 md5
不变、现场没有 runtime.json、无残留进程。

用法：

  python tests/r59_delete_preview_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r59-delete-preview
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
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
processes_of = r54.processes_of
responsive_pipe = r54.responsive_pipe

SERVER_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
SERVER_HOST = "203.0.113.10"
SERVER_NAME = "root@203.0.113.10"
DELETE_JP = '[data-action="delete"]'


def write_fixture(root: Path) -> None:
    """两线路；jp 有引擎配置并归属到一台服务器记录，hk 没有。"""
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    cfg = {
        "schema": 2,
        "selected": "jp",
        "lines": [
            {"id": "jp", "name": "东京 02", "proxy_endpoint": "127.0.0.1:17901"},
            {"id": "hk", "name": "香港 01", "proxy_endpoint": "127.0.0.1:17902"},
        ],
    }
    (data / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (data / "lines").mkdir(exist_ok=True)
    # 引擎配置里含隧道私钥的形状：预览要把它列进「将删除」。
    (data / "lines" / "jp.json").write_text(
        json.dumps(
            {
                "outbounds": [
                    {"type": "wireguard", "server": SERVER_HOST, "private_key": "FAKE-PRIVATE-KEY"}
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    server_dir = data / "servers" / SERVER_ID
    server_dir.mkdir(parents=True, exist_ok=True)
    (server_dir / "record.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ServerRecord",
                "Id": SERVER_ID,
                "Name": SERVER_NAME,
                "Host": SERVER_HOST,
                "Port": 22,
                "User": "root",
                "Fingerprint": "SHA256:abcdefghijkl",
                "CreatedAtUtc": "2026-11-10T00:00:00Z",
                "UpdatedAtUtc": "2026-11-10T00:00:00Z",
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def click(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def dialog_info(ws: WebSocket) -> dict | None:
    expr = r"""
(()=>{const d=document.querySelector('#dialog-root [role=alertdialog]');
 if(!d) return null;
 const title=d.querySelector('#dialog-title'), body=d.querySelector('#dialog-body');
 const pre=d.querySelector('.dialog-details pre'), note=d.querySelector('.note');
 const confirm=d.querySelector('[data-action=confirmDialog]');
 const cancel=d.querySelector('[data-action=cancelDialog]');
 return {title:title?title.textContent:'', body:body?body.textContent:'',
         note:note?note.textContent:'', details:pre?pre.textContent:'',
         confirm:confirm?confirm.textContent:'', cancel:cancel?cancel.textContent:'',
         danger:confirm?confirm.className.includes('danger'):false};})()
"""
    return ws.evaluate(expr)


def wait_dialog(ws: WebSocket, title: str, seconds: float, pump: Pump) -> bool:
    expr = (
        "(()=>{const d=document.querySelector('#dialog-root [role=alertdialog]');"
        "const t=d&&d.querySelector('#dialog-title');return !!t&&t.textContent===%s;})()"
        % json.dumps(title, ensure_ascii=False)
    )
    return wait_js(ws, expr, seconds, f"对话框「{title}」", pump)


def wait_gone(ws: WebSocket, selector: str, seconds: float, pump: Pump) -> bool:
    expr = "!document.querySelector(%s)" % json.dumps(selector, ensure_ascii=False)
    return wait_js(ws, expr, seconds, f"消失 {selector}", pump)


def open_delete(ws: WebSocket, line_id: str, pump: Pump) -> bool:
    """打开某条线路的抽屉并点删除。

    上一步的确认框刚关时，宿主快照还没推回来，`pendingIntent` 仍会让页面的
    `busy()` 为真——抽屉里的删除按钮是 `disabled`。点 disabled 按钮等于没点，
    所以要等按钮真正可点，别用「点到了就算」。
    """
    if not click(ws, f'#main [data-action=details][data-id={line_id}]'):
        return False
    if not wait_js(
        ws,
        f"!!document.querySelector('#drawer {DELETE_JP}:not([disabled])')",
        8,
        f"{line_id} 的删除按钮可点",
        pump,
    ):
        return False
    return click(ws, f"#drawer {DELETE_JP}")


def read_cfg(root: Path) -> dict:
    return json.loads((root / "data" / "config.json").read_text(encoding="utf-8"))


def wait_cfg(root: Path, predicate, seconds: float, label: str, pump: Pump) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate(read_cfg(root)):
                return True
        except Exception:  # noqa: BLE001
            pass
        pump.tick()
        time.sleep(0.3)
    print(f"  （等待超时：{label}）", flush=True)
    return False


def page_has(ws: WebSocket, text: str, seconds: float = 6.0, pump: Pump | None = None) -> bool:
    expr = "document.body.innerText.includes(" + json.dumps(text, ensure_ascii=False) + ")"
    return wait_js(ws, expr, seconds, text[:20], pump)


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
    shutil.rmtree(root, ignore_errors=True)
    write_fixture(root)

    live = responsive_pipe()
    if live:
        raise SystemExit(f"已经有一个 SpiderVPN 在跑（{live}），请先关掉它再跑这条验收。")
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    user_config_md5 = md5_of(USER_CONFIG)
    isolated_config = root / "data" / "config.json"
    isolated_before = md5_of(isolated_config)

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "root": str(root),
        "shots": [],
        "checks": [],
        "notes": [],
    }

    port = free_port()
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(root)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log_path = report_dir / "host.log"
    log = log_path.open("wb")
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

        # ---------- 场景 1：可删（预览列删除/保留）----------
        post(ws, {"Type": "navigate", "Page": "lines"})
        checker.check(
            "1 线路页出现 jp 的详情入口",
            wait_js(
                ws,
                "!!document.querySelector('#main [data-action=details][data-id=jp]')",
                15,
                "线路卡",
                pump,
            ),
        )
        checker.check("1 点开 jp 抽屉", click(ws, "#main [data-action=details][data-id=jp]"))
        checker.check(
            "1 抽屉里有删除按钮",
            wait_js(ws, f"!!document.querySelector('#drawer {DELETE_JP}')", 8, "删除按钮", pump),
        )
        checker.check("1 点删除", click(ws, f"#drawer {DELETE_JP}"))
        checker.check("1 弹出删除确认", wait_dialog(ws, "删除线路", 12, pump))
        info = dialog_info(ws) or {}
        report["notes"].append({"dialogEligible": info})
        checker.check(
            "1 正文说清私钥文件会删、服务端不受影响",
            "隧道私钥文件" in info.get("body", "")
            and "服务器上的服务与设备授权不受影响" in info.get("body", ""),
            info,
        )
        details = info.get("details", "")
        checker.check("1 详情含「将删除」与 jp 引擎文件", "将删除" in details and "lines\\jp.json" in details, details)
        checker.check("1 详情含「将保留」", "将保留" in details, details)
        checker.check(
            "1 保留项点名服务器记录与凭据",
            "服务器记录与登录凭据" in details and SERVER_NAME in details,
            details,
        )
        checker.check("1 破坏性按钮是危险样式", bool(info.get("danger")), info)
        checker.check(
            "1 有取消、确认文案是删除",
            info.get("cancel") == "取消" and info.get("confirm") == "删除",
            info,
        )
        screenshot(ws, report_dir / "01-eligible.png", report["shots"])

        # 取消：不发 remove，配置与文件都不动。
        checker.check("1 点取消", click(ws, "#dialog-root [data-action=cancelDialog]"))
        checker.check("1 取消后对话框消失", wait_gone(ws, "#dialog-root [role=alertdialog]", 8, pump))
        checker.check("1 取消后隔离配置一字节没变", md5_of(isolated_config) == isolated_before)
        checker.check("1 取消后引擎文件还在", (root / "data" / "lines" / "jp.json").is_file())

        # ---------- 场景 2：连接中不可删 ----------
        (root / "data" / "proxy-journal.json").write_text("{}", encoding="utf-8")
        checker.check("2 再点删除", open_delete(ws, "jp", pump))
        checker.check("2 给出阻塞结论", wait_dialog(ws, "暂时无法删除线路", 12, pump))
        info = dialog_info(ws) or {}
        report["notes"].append({"dialogBlocked": info})
        checker.check(
            "2 只给「知道了」、没有取消/删除",
            info.get("confirm") == "知道了" and info.get("cancel") == "" and not info.get("danger"),
            info,
        )
        checker.check("2 正文给出路（先断开）", "先断开" in info.get("body", ""), info)
        screenshot(ws, report_dir / "02-blocked.png", report["shots"])
        checker.check("2 点「知道了」", click(ws, "#dialog-root [data-action=confirmDialog]"))
        checker.check("2 阻塞结论关掉后配置没变", md5_of(isolated_config) == isolated_before)
        checker.check(
            "2 阻塞结论没有发删除（线路仍两条）",
            len(read_cfg(root).get("lines", [])) == 2,
            read_cfg(root).get("lines"),
        )

        # ---------- 场景 3：确认删除 jp，核对真实结果 ----------
        (root / "data" / "proxy-journal.json").unlink()
        checker.check("3 再打开 jp 删除", open_delete(ws, "jp", pump))
        checker.check("3 弹出删除确认", wait_dialog(ws, "删除线路", 12, pump))
        screenshot(ws, report_dir / "03-confirm.png", report["shots"])
        checker.check("3 点确认删除", click(ws, "#dialog-root [data-action=confirmDialog]"))
        checker.check(
            "3 config.json 里 jp 被移除",
            wait_cfg(root, lambda c: all(l["id"] != "jp" for l in c["lines"]), 15, "jp 移除", pump),
            read_cfg(root).get("lines"),
        )
        checker.check("3 引擎配置文件被删", not (root / "data" / "lines" / "jp.json").exists())
        checker.check(
            "3 服务器记录与凭据仍在（只删线路，不动服务器）",
            (root / "data" / "servers" / SERVER_ID / "record.json").is_file(),
        )
        # 「不见了」不能只看一帧：`#main` 每 250ms 重画，撞上清空那一帧会假过。
        # 要求连续两次采样（间隔 700ms）都不含它。
        gone_expr = "!document.body.innerText.includes('东京 02')"
        gone = wait_js(ws, gone_expr, 10, "界面刷新", pump)
        if gone:
            time.sleep(0.7)
            gone = bool(ws.evaluate(gone_expr))
        checker.check("3 界面不再列出东京 02", gone)
        checker.check("3 香港 01 仍在", page_has(ws, "香港 01", 6, pump))
        history = root / "data" / "logs" / "operations.jsonl"
        rows = []
        if history.is_file():
            for line in history.read_text(encoding="utf-8").splitlines():
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        removed = [row for row in rows if row.get("action") == "删除线路"]
        report["notes"].append({"historyDelete": removed})
        checker.check("3 操作记录里有一条「删除线路」", len(removed) == 1, rows)
        checker.check(
            "3 记录来源是界面、对象是 line:jp",
            bool(removed) and removed[0].get("src") == "ui" and removed[0].get("obj") == "line:jp",
            removed,
        )
        screenshot(ws, report_dir / "04-after-delete.png", report["shots"])

        # ---------- 场景 4：最后一条线路（现在只剩 hk）如实提示 ----------
        checker.check("4 点开 hk 并点删除", open_delete(ws, "hk", pump))
        checker.check("4 弹出删除确认", wait_dialog(ws, "删除线路", 12, pump))
        info = dialog_info(ws) or {}
        report["notes"].append({"dialogLastLine": info})
        checker.check(
            "4 提示最后一条线路",
            "最后一条线路" in info.get("note", ""),
            info,
        )
        checker.check(
            "4 提示没有引擎配置（只说会删 config 条目）",
            "没有找到这条线路的引擎配置文件" in info.get("note", ""),
            info,
        )
        checker.check("4 取消掉", click(ws, "#dialog-root [data-action=cancelDialog]"))
        checker.check(
            "4 取消后 hk 还在",
            wait_cfg(root, lambda c: any(l["id"] == "hk" for l in c["lines"]), 5, "hk 还在", pump),
        )

        # ---------- 收尾 ----------
        checker.check("5 用户配置没被改过（config.json md5 一致）", md5_of(USER_CONFIG) == user_config_md5)
        checker.check("5 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check("5 收尾时没有残留的 spidervpn 进程", len(processes_of("spidervpn.exe")) <= 1)

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
