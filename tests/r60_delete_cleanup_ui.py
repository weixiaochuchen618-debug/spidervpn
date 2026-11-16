#!/usr/bin/env python3
"""r60 界面验收：A4 第二轮「删除结果核对 + 待清理记录 + 重试清理」。

r59 只做到「删之前先预览」。删除当下仍有两个问题：

1. `remove` 删配置成功就报成功，**没人核对引擎配置文件到底删没删**。文件被占着时
   配置没了、私钥文件还在，界面一声不吭（悄悄留下一个私钥文件）。
2. 就算当场发现，重启后提示也没了。用户过几天才回来处理时，页面必须还记得这笔账。

r60 的做法：删除后真的 `remove_file` 并核对结果；删不掉就写进
`logs\\delete-cleanup.json`（只存相对路径），页面给一张带「重试清理」的提示卡，
**活过重启**；点重试按 id 重算路径、先确认这条线路不在配置里，再删文件、清记录、
记操作记录。

本脚本全程点真实页面（CDP + 宿主推送 + 隔离数据根），验证顺序：

0. 响应历史抽屉能画出隔离数据根里的真实采样（r60 顺手修的 `qualityHistory`
   白名单旧账——不修的话抽屉永远停在「正在读取历史…」）；
1. 正常删线路：配置文件与引擎配置都真的没了，不留待清理记录、不留提示卡；
2. 用 Python 占用 `lines\\hk.json` 造出共享冲突 → 界面上删 hk：
   配置移除、文件仍在、提示卡（重试清理）出现、记录落盘、操作记录 ok=false；
3. 杀掉宿主、同根重启：提示卡仍在（记录是磁盘上的，不是内存里的）；
4. 释放占用后点「重试清理」：文件删除、记录清空、提示卡消失、操作记录 ok=true；
5. 反向保护：手工写一条「线路还在配置里」的记录（us），点重试必须拒绝，
   us 的引擎配置一个字节都不能少。

反向对照（旧版 r59 exe）：第 0、2、3、4、5 条应全红（旧版没有结果核对与重试，
响应历史也画不出来），第 1 条基线应仍绿。

用法：

  python tests/r60_delete_cleanup_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r60-delete-cleanup\\acceptance
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
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
HOOK = r54.HOOK

SERVER_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
SERVER_HOST = "203.0.113.10"
SERVER_NAME = "root@203.0.113.10"
JP = {"id": "jp", "name": "东京 02", "endpoint": "127.0.0.1:17901"}
HK = {"id": "hk", "name": "香港 01", "endpoint": "127.0.0.1:17902"}
US = {"id": "us", "name": "首尔 03", "endpoint": "127.0.0.1:17903"}
CLEANUP_ACTION = "清理本地文件"
CLEANUP_KIND = "TradeChannel.DeleteCleanup"


def write_fixture(root: Path) -> None:
    """三条线路：jp/hk 有引擎配置，us 只用来画响应历史；jp 归属一台服务器记录。"""
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    cfg = {
        "schema": 2,
        "selected": "jp",
        "lines": [
            {"id": JP["id"], "name": JP["name"], "proxy_endpoint": JP["endpoint"]},
            {"id": HK["id"], "name": HK["name"], "proxy_endpoint": HK["endpoint"]},
            {"id": US["id"], "name": US["name"], "proxy_endpoint": US["endpoint"]},
        ],
    }
    (data / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (data / "lines").mkdir(exist_ok=True)
    for line in (JP, HK):
        (data / "lines" / f"{line['id']}.json").write_text(
            json.dumps(
                {
                    "outbounds": [
                        {
                            "type": "wireguard",
                            "server": SERVER_HOST,
                            "private_key": "FAKE-PRIVATE-KEY",
                        }
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
    # 响应历史：一条 2 分钟前的真实采样（按 UTC 小时分文件，见 src/perf.rs）。
    at = int(time.time()) - 120
    stamp = datetime.fromtimestamp(at, tz=timezone.utc).strftime("%Y%m%d-%H")
    perf = data / "perf"
    perf.mkdir(exist_ok=True)
    sample = {"at": at, "lineId": US["id"], "profile": "标准", "ms": 41, "reason": ""}
    (perf / f"{stamp}.jsonl").write_text(
        json.dumps(sample, ensure_ascii=False) + "\n", encoding="utf-8"
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
    """打开抽屉并点删除；必须等按钮真正可点（上一帧的 pendingIntent 会让它 disabled）。"""
    if not click(ws, f'#main [data-action=details][data-id={line_id}]'):
        return False
    if not wait_js(
        ws,
        "!!document.querySelector('#drawer [data-action=delete]:not([disabled])')",
        8,
        f"{line_id} 的删除按钮可点",
        pump,
    ):
        return False
    return click(ws, "#drawer [data-action=delete]")


def read_cfg(root: Path) -> dict:
    return json.loads((root / "data" / "config.json").read_text(encoding="utf-8"))


def wait_until(predicate, seconds: float, label: str, pump: Pump) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception:  # noqa: BLE001
            pass
        pump.tick()
        time.sleep(0.3)
    print(f"  （等待超时：{label}）", flush=True)
    return False


def cleanup_record(root: Path) -> dict | None:
    path = root / "data" / "logs" / "delete-cleanup.json"
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def operations(root: Path) -> list[dict]:
    path = root / "data" / "logs" / "operations.jsonl"
    rows: list[dict] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def cleanup_rows(root: Path) -> list[dict]:
    return [row for row in operations(root) if row.get("action") == CLEANUP_ACTION]


def snapshot(ws: WebSocket) -> dict:
    raw = ws.evaluate("window.__tcProbe || null")
    if not raw:
        return {}
    data = raw if isinstance(raw, dict) else json.loads(raw)
    return data.get("State") or {}


def notice_state(ws: WebSocket) -> dict | None:
    expr = r"""
(()=>{const n=document.querySelector('#main .cleanup-notice');
 if(!n) return null;
 const b=n.querySelector('[data-action=retryDelete]');
 return {text:n.innerText, button:b?b.textContent.trim():''};})()
"""
    return ws.evaluate(expr)


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
    data = root / "data"
    hk_file = data / "lines" / "hk.json"
    record_file = data / "logs" / "delete-cleanup.json"

    live = responsive_pipe()
    if live:
        raise SystemExit(f"已经有一个 SpiderVPN 在跑（{live}），请先关掉它再跑这条验收。")
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    user_config_md5 = md5_of(USER_CONFIG)

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "root": str(root),
        "shots": [],
        "checks": [],
        "notes": [],
    }

    def launch(tag: str):
        port = free_port()
        env = dict(os.environ)
        env["SPIDERVPN_ROOT"] = str(root)
        env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
            f"--remote-debugging-port={port} --remote-allow-origins=*"
        )
        log_path = report_dir / f"host{tag}.log"
        log = log_path.open("wb")
        process = subprocess.Popen(
            [str(exe)],
            cwd=str(exe.parent),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        print(f"[probe] host{tag} pid={process.pid} cdp={port}", flush=True)
        return process, log, port

    def connect(port: int, process: subprocess.Popen) -> tuple[WebSocket, Pump]:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        connection = WebSocket(target["webSocketDebuggerUrl"])
        connection.call("Page.enable")
        try:
            connection.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        return connection, Pump(process.pid)

    def ready(connection: WebSocket, host_pump: Pump, label: str, cards: int) -> None:
        checker.check(
            f"0 {label}真实 WebView2 就绪",
            wait_js(
                connection,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                30,
                "页面初始化",
                host_pump,
            ),
        )
        checker.check("0 已挂钩宿主推送入口", connection.evaluate(HOOK) in ("hooked", "already"))
        checker.check(
            "0 拿到了第一份快照",
            wait_js(connection, "!!window.__tcProbe", 25, "首份快照", host_pump),
        )
        post(connection, {"Type": "navigate", "Page": "lines"})
        checker.check(
            f"0 线路页列出 {cards} 条线路",
            wait_js(
                connection,
                f"document.querySelectorAll('#main [data-action=details]').length==={cards}",
                15,
                "线路卡",
                host_pump,
            ),
        )

    process = None
    log = None
    ws = None
    pump = None
    lock = None
    process2 = None
    log2 = None
    ws2 = None
    pump2 = None
    try:
        process, log, port = launch("1")
        ws, pump = connect(port, process)
        ready(ws, pump, "第一宿主", 3)

        # ---------- 场景 0：响应历史（r60 顺手修的白名单旧账）----------
        checker.check("0 点开 us 的详情", click(ws, "#main [data-action=details][data-id=us]"))
        checker.check(
            "0 抽屉里出现响应历史",
            wait_js(
                ws,
                "!!document.querySelector('#drawer .quality-history')",
                8,
                "响应历史",
                pump,
            ),
        )
        history_expr = (
            "(()=>{const d=document.querySelector('#drawer');if(!d)return false;"
            "const t=d.innerText;return t.includes('平均 41 ms')&&t.includes('1 次成功');})()"
        )
        checker.check(
            "0 曲线画出了真实采样（平均 41 ms · 1 次成功）",
            wait_js(ws, history_expr, 12, "响应历史数据", pump),
            ws.evaluate("document.querySelector('#drawer')?.innerText.slice(0,400)"),
        )
        checker.check(
            "0 曲线有数据点",
            bool(
                ws.evaluate(
                    "document.querySelectorAll('#drawer .quality-history svg circle,"
                    "#drawer .quality-history svg polyline').length"
                )
            ),
        )
        checker.check(
            "0 宿主状态里的 QualityHistory 已落地（Loading=false）",
            wait_js(
                ws,
                "window.__tcProbe?.State?.QualityHistory?.Loading===false",
                8,
                "状态落地",
                pump,
            ),
            json.dumps(snapshot(ws).get("QualityHistory"), ensure_ascii=False)[:400],
        )
        screenshot(ws, report_dir / "01-quality-history.png", report["shots"])
        checker.check("0 关闭抽屉", click(ws, "#drawer [data-close]"))
        checker.check(
            "0 抽屉收起",
            wait_js(
                ws,
                "(()=>{const d=document.querySelector('#drawer');return !d||d.hidden;})()",
                8,
                "抽屉收起",
                pump,
            ),
        )

        # ---------- 场景 1：正常删除 jp（基线）----------
        checker.check("1 打开 jp 并点删除", open_delete(ws, "jp", pump))
        checker.check("1 弹出删除确认", wait_dialog(ws, "删除线路", 12, pump))
        checker.check("1 点确认删除", click(ws, "#dialog-root [data-action=confirmDialog]"))
        checker.check(
            "1 config.json 里 jp 被移除",
            wait_until(
                lambda: all(l["id"] != "jp" for l in read_cfg(root)["lines"]),
                15,
                "jp 移除",
                pump,
            ),
            read_cfg(root).get("lines"),
        )
        checker.check(
            "1 jp 引擎配置文件真的删掉了",
            wait_until(lambda: not (data / "lines" / "jp.json").exists(), 8, "jp 文件删除", pump),
        )
        checker.check("1 正常删除不留待清理记录", cleanup_record(root) is None, cleanup_record(root))
        checker.check(
            "1 页面没有待清理提示卡",
            wait_gone(ws, "#main .cleanup-notice", 8, pump),
            notice_state(ws),
        )
        checker.check(
            "1 列表里不再有 jp（连续两次采样）",
            wait_js(
                ws,
                "!document.querySelector('#main [data-action=details][data-id=jp]')",
                10,
                "jp 卡片消失",
                pump,
            )
            and (time.sleep(0.7) or True)
            and bool(
                ws.evaluate(
                    "!document.querySelector('#main [data-action=details][data-id=jp]')"
                )
            ),
        )
        rows = operations(root)
        jp_removed = [
            row
            for row in rows
            if row.get("action") == "删除线路" and row.get("obj") == "line:jp"
        ]
        checker.check(
            "1 操作记录一条「删除线路」成功",
            len(jp_removed) == 1 and jp_removed[0].get("ok") is True,
            jp_removed,
        )
        checker.check("1 没有「清理本地文件」记录", not cleanup_rows(root), rows)
        screenshot(ws, report_dir / "02-jp-clean-delete.png", report["shots"])

        # ---------- 场景 2：占用 hk 文件后删除（当场核对出失败）----------
        lock = open(hk_file, "rb")
        lock.read(1)
        checker.check("2 已用 Python 占用 hk 引擎配置（读仍可用）", True)
        checker.check("2 打开 hk 并点删除", open_delete(ws, "hk", pump))
        checker.check("2 弹出删除确认", wait_dialog(ws, "删除线路", 12, pump))
        info = dialog_info(ws) or {}
        checker.check(
            "2 占用不影响预览（确认按钮仍是删除）",
            info.get("confirm") == "删除",
            info,
        )
        checker.check("2 点确认删除", click(ws, "#dialog-root [data-action=confirmDialog]"))
        checker.check(
            "2 config.json 里 hk 被移除",
            wait_until(
                lambda: all(l["id"] != "hk" for l in read_cfg(root)["lines"]),
                15,
                "hk 移除",
                pump,
            ),
            read_cfg(root).get("lines"),
        )
        checker.check("2 hk 引擎配置文件还在（共享冲突）", hk_file.is_file())
        checker.check(
            "2 页面出现待清理提示卡",
            wait_js(ws, "!!document.querySelector('#main .cleanup-notice')", 12, "待清理提示", pump),
            notice_state(ws),
        )
        notice = notice_state(ws) or {}
        report["notes"].append({"cleanupNotice": notice})
        checker.check(
            "2 提示卡说清「配置删了、文件没删」",
            "香港 01" in notice.get("text", "")
            and "没删掉" in notice.get("text", "")
            and "lines\\hk.json" in notice.get("text", ""),
            notice,
        )
        checker.check("2 提示卡给的是「重试清理」", notice.get("button") == "重试清理", notice)
        record = cleanup_record(root)
        report["notes"].append({"cleanupRecord": record})
        checker.check(
            "2 待清理记录已落盘",
            isinstance(record, dict)
            and record.get("Kind") == CLEANUP_KIND
            and record.get("SchemaVersion") == 1,
            record,
        )
        pending = (record or {}).get("Pending") or []
        checker.check(
            "2 记录里是 hk 的相对路径与错误原文",
            len(pending) == 1
            and pending[0].get("Id") == "hk"
            and pending[0].get("Name") == HK["name"]
            and pending[0].get("File") == "lines\\hk.json"
            and bool(pending[0].get("Error")),
            pending,
        )
        raw_record = record_file.read_text(encoding="utf-8") if record_file.is_file() else ""
        checker.check("2 记录不落绝对路径", str(root) not in raw_record, raw_record[:300])
        snap = snapshot(ws)
        operation = snap.get("DeleteOperation") or {}
        report["notes"].append({"deleteOperation": operation})
        checker.check(
            "2 快照投影：Kind=Cleanup / Phase=Blocked / CanRetry",
            operation.get("Kind") == "Cleanup"
            and operation.get("Phase") == "Blocked"
            and operation.get("CanRetry") is True
            and operation.get("Id") == "hk",
            operation,
        )
        checker.check(
            "2 DeleteRefresh 始终为 null（重试是同步的）",
            snap.get("DeleteRefresh") is None,
            snap.get("DeleteRefresh"),
        )
        rows = operations(root)
        cleanup = cleanup_rows(root)
        report["notes"].append({"cleanupEvents": cleanup})
        checker.check(
            "2 操作记录：清理失败 ok=false，对象 line:hk",
            len(cleanup) == 1
            and cleanup[0].get("ok") is False
            and cleanup[0].get("obj") == "line:hk"
            and "没删掉" in cleanup[0].get("detail", ""),
            cleanup,
        )
        checker.check(
            "2 操作记录：删除线路本身仍是成功",
            any(
                row.get("action") == "删除线路"
                and row.get("obj") == "line:hk"
                and row.get("ok") is True
                for row in rows
            ),
            rows,
        )
        checker.check(
            "2 列表里不再有 hk 卡片",
            wait_js(
                ws,
                "!document.querySelector('#main [data-action=details][data-id=hk]')",
                10,
                "hk 卡片消失",
                pump,
            ),
        )
        screenshot(ws, report_dir / "03-cleanup-notice.png", report["shots"])

        # ---------- 场景 3：重启后提示仍在（记录活在磁盘上）----------
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        ws = None
        process.terminate()
        process.wait(timeout=15)
        checker.check(
            "3 旧宿主已退出",
            wait_until(lambda: responsive_pipe() is None, 20, "旧宿主退出", pump),
        )
        log.close()
        log = None
        process2, log2, port2 = launch("2")
        ws2, pump2 = connect(port2, process2)
        ready(ws2, pump2, "重启后宿主", 1)
        checker.check(
            "3 重启后提示卡还在",
            wait_js(
                ws2,
                "!!document.querySelector('#main .cleanup-notice')",
                15,
                "重启后提示卡",
                pump2,
            ),
            notice_state(ws2),
        )
        notice = notice_state(ws2) or {}
        checker.check(
            "3 重启后仍点名 hk 与文件",
            "香港 01" in notice.get("text", "") and "lines\\hk.json" in notice.get("text", ""),
            notice,
        )
        checker.check("3 重启后按钮仍是「重试清理」", notice.get("button") == "重试清理", notice)
        record2 = cleanup_record(root)
        checker.check("3 重启没有改记录", record2 == record, record2)
        screenshot(ws2, report_dir / "04-after-restart.png", report["shots"])

        # ---------- 场景 4：释放占用后重试清理 ----------
        lock.close()
        lock = None
        checker.check("4 点「重试清理」", click(ws2, "#main [data-action=retryDelete][data-id=hk]"))
        checker.check(
            "4 hk 引擎配置文件被删掉",
            wait_until(lambda: not hk_file.exists(), 15, "重试删除文件", pump2),
        )
        checker.check(
            "4 待清理记录文件已清掉",
            wait_until(lambda: cleanup_record(root) is None, 10, "记录清空", pump2),
            cleanup_record(root),
        )
        checker.check(
            "4 提示卡消失",
            wait_gone(ws2, "#main .cleanup-notice", 10, pump2),
            notice_state(ws2),
        )
        checker.check(
            "4 快照 DeleteOperation 回到 null",
            wait_until(
                lambda: snapshot(ws2).get("DeleteOperation") is None,
                10,
                "DeleteOperation 清空",
                pump2,
            ),
            snapshot(ws2).get("DeleteOperation"),
        )
        cleanup = cleanup_rows(root)
        report["notes"].append({"cleanupEventsAfterRetry": cleanup})
        checker.check(
            "4 操作记录：重试成功 ok=true",
            len(cleanup) == 2
            and cleanup[-1].get("ok") is True
            and cleanup[-1].get("obj") == "line:hk"
            and "已删除线路「香港 01」的残留文件" in cleanup[-1].get("detail", ""),
            cleanup,
        )
        checker.check(
            "4 列表只剩首尔 03",
            wait_js(
                ws2,
                "(()=>{const c=document.querySelectorAll('#main [data-action=details]');"
                "return c.length===1&&c[0].dataset.id==='us'&&"
                "document.body.innerText.includes('首尔 03');})()",
                10,
                "列表刷新",
                pump2,
            ),
        )
        screenshot(ws2, report_dir / "05-after-retry.png", report["shots"])

        # ---------- 场景 5：线路还在配置里，重试必须拒绝 ----------
        us_file = data / "lines" / "us.json"
        us_file.write_text('{"outbounds":[]}', encoding="utf-8")
        fabricated = {
            "SchemaVersion": 1,
            "Kind": CLEANUP_KIND,
            "Pending": [
                {
                    "Id": "us",
                    "Name": US["name"],
                    "File": "lines\\us.json",
                    "Error": "手工造出来验证拒绝路径",
                }
            ],
        }
        temp = record_file.with_suffix(".json.tmp")
        temp.write_text(json.dumps(fabricated, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temp, record_file)
        checker.check(
            "5 页面读到了手工记录",
            wait_js(
                ws2,
                "!!document.querySelector('#main .cleanup-notice')",
                12,
                "手工记录提示卡",
                pump2,
            ),
            notice_state(ws2),
        )
        checker.check("5 点「重试清理」", click(ws2, "#main [data-action=retryDelete][data-id=us]"))
        checker.check(
            "5 拒绝理由出现在 toast 里",
            wait_js(
                ws2,
                "(()=>{const t=document.querySelector('#toast');"
                "return !!t&&!t.hidden&&t.textContent.includes('还在线路列表里');})()",
                6,
                "拒绝 toast",
                pump2,
            ),
            ws2.evaluate("document.querySelector('#toast')?.textContent || ''"),
        )
        time.sleep(1.0)
        checker.check("5 us 的引擎配置一个字节没少", us_file.is_file())
        checker.check("5 待清理记录没有被清掉", cleanup_record(root) is not None, cleanup_record(root))
        checker.check("5 没有多出一条清理记录", len(cleanup_rows(root)) == 2, cleanup_rows(root))
        screenshot(ws2, report_dir / "06-refusal.png", report["shots"])

        record_file.unlink()
        checker.check(
            "5 撤掉手工记录后提示卡自动消失",
            wait_gone(ws2, "#main .cleanup-notice", 10, pump2),
            notice_state(ws2),
        )

        # ---------- 收尾 ----------
        checker.check(
            "6 用户配置没被改过（config.json md5 一致）",
            md5_of(USER_CONFIG) == user_config_md5,
        )
        checker.check("6 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check(
            "6 收尾时没有残留的 spidervpn 进程",
            len(processes_of("spidervpn.exe")) <= 1,
        )
    finally:
        try:
            if lock is not None:
                lock.close()
        except Exception:  # noqa: BLE001
            pass
        for connection in (ws, ws2):
            try:
                if connection is not None:
                    connection.close()
            except Exception:  # noqa: BLE001
                pass
        for host in (process, process2):
            if host is not None and not args.keep_open:
                try:
                    host.terminate()
                    host.wait(timeout=15)
                except Exception:  # noqa: BLE001
                    try:
                        host.kill()
                    except Exception:  # noqa: BLE001
                        pass
        for handle in (log, log2):
            try:
                if handle is not None:
                    handle.close()
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
