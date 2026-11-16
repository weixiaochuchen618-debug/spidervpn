#!/usr/bin/env python3
"""r61 界面验收：A6 第二轮「线路动作反馈 + 中断后核对 + 重试」。

r60 之前，界面上的「测速」与「保存连接方式」点完就忘：进程在中间被杀掉，
用户既不知道那次动作做没做成，也没有任何入口去核对。r61 把动作在**开始时**
写进 `logs\\line-actions.json`（Pending），有结论再改写；启动时把遗留的 Pending
改判 `NeedsReview`，首页给「待处理」提示卡，线路卡片给反馈条：

- 失败 → 「重新测试 / 重试保存」（真的重新提交原命令）；
- 被中断 → 「检查测试结果 / 确认保存结果」（`line-action-review`，只查已有证据，
  绝不重新提交原操作）。

本脚本全程点真实页面（CDP + 宿主推送 + 隔离数据根），验证顺序：

0. 三条线路；`sg` 先带一条已失败的测速记录；`hk` 有一条**被中断的保存**
   （Pending，请求 tcp），`jp` 有一条**被中断的测速**（Pending，窗口里有一条
   41 ms 的真实采样）；
1. 启动：两条 Pending 被改判 NeedsReview；首页出两张提示卡，文案点名线路与动作，
   且不说「当前线路仍在使用」（那不是本地清理类动作）；
2. `sg` 卡片直接显示失败反馈、可「重新测试」、可「运行诊断」；
3. 核对 `hk` 的保存：配置里仍是自动 → 结论「没有落地」（NotApplied）、
   配置一个字节不动、提示卡消失、卡片出现「重试保存」；
4. 点「重试保存」：真命令 `set-transport`（带 source），配置固定为兼容连接，
   记录变成功；抽屉里反馈条显示 旧版的原话；
5. 核对 `jp` 的测速：窗口里有 41 ms 采样 → 成功，Toast 与记录都带这个读数；
6. 断开状态下点「测试这条线路」：真发测量、失败如实落盘（连接后测量），
   反馈条给「重新测试 / 运行诊断」；点「重新测试」确实再发一次；
7. 抽屉里点「标准」保存连接方式：记录成功，配置落盘；
8. 重启前把记录文件写坏：页面必须说「读不出来」，不能当成「没有记录」，
   线路页照常可用。

反向对照（旧版 r60 exe）：第 1、3、4、5、6、7、8 条应全红（旧版不记录动作、
也不投影反馈）；第 0 条基线与第 2 条（记录是我们手工造的）应仍绿。

用法：

  python tests/r61_line_actions_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r61-line-actions\\acceptance
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

HK = {"id": "hk", "name": "香港 01", "endpoint": "127.0.0.1:17901"}
JP = {"id": "jp", "name": "东京 02", "endpoint": "127.0.0.1:17902"}
SG = {"id": "sg", "name": "新加坡 03", "endpoint": "127.0.0.1:17903"}

STORE_KIND = "TradeChannel.LineActions"
HK_PREF_ID = "11111111-1111-4111-8111-111111111111"
JP_CHECK_ID = "22222222-2222-4222-8222-222222222222"
SG_CHECK_ID = "33333333-3333-4333-8333-333333333333"
SAMPLE_MS = 41


def rfc3339(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def engine_body() -> str:
    """带兼容连接参数的线路文件（与 ipc 测试同一份形状）。

    `check_transport(Tcp)` 要求线路文件自己就能派生出中转；没有它，
    保存兼容连接必然被拒，第 4 步就证明不了「重试真的落地」。
    """
    return json.dumps(
        {
            "endpoints": [{"type": "wireguard", "tag": "hk"}],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "provider-a",
                    "server": "203.0.113.7",
                    "server_port": 443,
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "tls": {
                        "enabled": True,
                        "server_name": "cdn.example.com",
                        "reality": {
                            "enabled": True,
                            "public_key": "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0Uv1",
                            "short_id": "ab12",
                        },
                    },
                },
                {"type": "selector", "tag": "trade-exit", "outbounds": ["hk"], "default": "hk"},
                {"type": "direct", "tag": "direct"},
            ],
        },
        ensure_ascii=False,
    )


def write_fixture(root: Path) -> dict:
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    cfg = {
        "schema": 2,
        "selected": HK["id"],
        "lines": [
            {"id": HK["id"], "name": HK["name"], "proxy_endpoint": HK["endpoint"]},
            {"id": JP["id"], "name": JP["name"], "proxy_endpoint": JP["endpoint"]},
            {"id": SG["id"], "name": SG["name"], "proxy_endpoint": SG["endpoint"]},
        ],
    }
    (data / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (data / "lines").mkdir(exist_ok=True)
    (data / "lines" / "hk.json").write_text(engine_body(), encoding="utf-8")

    now = int(time.time())
    sample_at = now - 10
    stamp = datetime.fromtimestamp(sample_at, tz=timezone.utc).strftime("%Y%m%d-%H")
    perf = data / "perf"
    perf.mkdir(exist_ok=True)
    (perf / f"{stamp}.jsonl").write_text(
        json.dumps(
            {"at": sample_at, "lineId": JP["id"], "profile": "标准", "ms": SAMPLE_MS, "reason": ""},
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    actions = {
        "SchemaVersion": 1,
        "Kind": STORE_KIND,
        "Actions": [
            {
                "Id": HK_PREF_ID,
                "LineId": HK["id"],
                "LineName": HK["name"],
                "Kind": "Preference",
                "ProfileId": "Tcp",
                "Requested": "tcp",
                "Phase": "Pending",
                "Message": "",
                "Code": "",
                "AtUtc": rfc3339(now),
                "AtUnix": now,
                "FinishedAtUtc": "",
                "LatencyMs": None,
            },
            {
                "Id": JP_CHECK_ID,
                "LineId": JP["id"],
                "LineName": JP["name"],
                "Kind": "Check",
                "ProfileId": "Udp",
                "Requested": "",
                "Phase": "Pending",
                "Message": "",
                "Code": "",
                "AtUtc": rfc3339(sample_at),
                "AtUnix": sample_at,
                "FinishedAtUtc": "",
                "LatencyMs": None,
            },
            {
                "Id": SG_CHECK_ID,
                "LineId": SG["id"],
                "LineName": SG["name"],
                "Kind": "Check",
                "ProfileId": "Udp",
                "Requested": "",
                "Phase": "Failed",
                "Message": "上次测速没有通过（MeasurementTimeout）；可以重新测速。",
                "Code": "MeasurementTimeout",
                "AtUtc": rfc3339(now - 300),
                "AtUnix": now - 300,
                "FinishedAtUtc": rfc3339(now - 299),
                "LatencyMs": None,
            },
        ],
    }
    logs = data / "logs"
    logs.mkdir(exist_ok=True)
    (logs / "line-actions.json").write_text(
        json.dumps(actions, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return {"sampleAt": sample_at, "now": now}


def read_cfg(root: Path) -> dict:
    return json.loads((root / "data" / "config.json").read_text(encoding="utf-8"))


def read_store(root: Path) -> dict:
    path = root / "data" / "logs" / "line-actions.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def records(root: Path) -> dict:
    return {item.get("Id"): item for item in read_store(root).get("Actions", [])}


def find_record(root: Path, line_id: str, kind: str) -> dict:
    return next(
        (
            rec
            for rec in records(root).values()
            if rec.get("LineId") == line_id and rec.get("Kind") == kind
        ),
        {},
    )


def click(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def wait_click(ws: WebSocket, selector: str, seconds: float, label: str, pump: Pump) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);return !!e&&!e.disabled;})()"
        % json.dumps(selector, ensure_ascii=False)
    )
    if not wait_js(ws, expr, seconds, label, pump):
        return False
    return click(ws, selector)


def goto(ws: WebSocket, page: str, pump: Pump) -> bool:
    """发导航并等页面标题真的换了。

    只等「3 张卡片」这类跨页共有的节点会让截图和断言停在上一页（r61 首次运行
    就踩到：首页/线路都有线路卡与提示卡，提示卡检查在上一页也能通过）。
    """
    post(ws, {"Type": "navigate", "Page": page})
    title = {"home": "首页", "lines": "线路"}[page]
    expr = (
        "(()=>{const h=document.querySelector('#main .page-head h1');"
        "return !!h&&h.textContent===%s;})()" % json.dumps(title, ensure_ascii=False)
    )
    return wait_js(ws, expr, 10, f"切到「{title}」", pump)


def line_card_text(ws: WebSocket, line_id: str) -> str:
    """整张线路卡的可见文字；卡片不在时返回空串（不让证据求值把整轮打断）。"""
    expr = (
        "(()=>{const e=document.querySelector('#main [data-action=details][data-id=%s]');"
        "const c=e&&e.closest('.line-card');return c?c.innerText:'';})()"
        % json.dumps(line_id, ensure_ascii=False)
    )
    return ws.evaluate(expr) or ""


def wait_toast(ws: WebSocket, text: str, seconds: float, pump: Pump) -> bool:
    expr = (
        "(()=>{const t=document.querySelector('#toast');"
        "return !!t&&!t.hidden&&t.textContent.includes(%s);})()"
        % json.dumps(text, ensure_ascii=False)
    )
    return wait_js(ws, expr, seconds, f"toast「{text}」", pump)


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


def snapshot(ws: WebSocket) -> dict:
    raw = ws.evaluate("window.__tcProbe || null")
    if not raw:
        return {}
    data = raw if isinstance(raw, dict) else json.loads(raw)
    return data.get("State") or {}


def pending_notices(ws: WebSocket) -> list[dict]:
    expr = r"""
(()=>{return Array.from(document.querySelectorAll('#main .cleanup-notice'))
  .filter(n=>n.innerText.includes('尚未确认'))
  .map(n=>({text:n.innerText, ids:Array.from(n.querySelectorAll('[data-action=reviewOperation]'))
    .map(b=>({id:b.dataset.id, label:b.textContent.trim()}))}));})()
"""
    return ws.evaluate(expr) or []


def feedback_state(ws: WebSocket, root_selector: str = "#main") -> list[dict]:
    expr = (
        "(()=>{return Array.from(document.querySelectorAll(%s))"
        ".map(n=>({id:n.dataset.feedback||'', text:n.innerText,"
        " retry:!!n.querySelector('[data-action=retryLineAction]'),"
        " review:!!n.querySelector('[data-action=reviewLineAction]'),"
        " diagnose:!!n.querySelector('[data-action=diagnostics]'),"
        " retryLabel:(n.querySelector('[data-action=retryLineAction]')||{}).textContent||'',"
        " reviewLabel:(n.querySelector('[data-action=reviewLineAction]')||{}).textContent||''}));})()"
        % json.dumps(root_selector + " .line-feedback", ensure_ascii=False)
    )
    return ws.evaluate(expr) or []


def drawer_feedback(ws: WebSocket) -> list[dict]:
    return feedback_state(ws, "#drawer")


def open_drawer(ws: WebSocket, line_id: str, pump: Pump) -> bool:
    if not click(ws, f'#main [data-action=details][data-id={line_id}]'):
        return False
    return wait_js(ws, "!!document.querySelector('#drawer [role=dialog]')", 8, "抽屉", pump)


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
    fixture = write_fixture(root)
    data = root / "data"
    store_file = data / "logs" / "line-actions.json"
    config_file = data / "config.json"

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

    def connect(port: int, process: subprocess.Popen):
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
                "(()=>{const h=document.querySelector('#main .page-head h1');"
                "return !!h&&h.textContent==='线路';})()"
                f"&&document.querySelectorAll('#main [data-action=details]').length==={cards}",
                15,
                "线路卡",
                host_pump,
            ),
        )

    process = None
    log = None
    ws = None
    pump = None
    process2 = None
    log2 = None
    ws2 = None
    pump2 = None
    try:
        process, log, port = launch("1")
        ws, pump = connect(port, process)
        ready(ws, pump, "第一宿主", 3)

        # ---------- 场景 1：启动把两条 Pending 改判 NeedsReview ----------
        flipped = wait_until(
            lambda: records(root).get(HK_PREF_ID, {}).get("Phase") == "NeedsReview"
            and records(root).get(JP_CHECK_ID, {}).get("Phase") == "NeedsReview",
            15,
            "启动恢复",
            pump,
        )
        store_now = records(root)
        report["notes"].append({"afterRestart": store_now})
        checker.check("1 两条被中断的动作都改判为 NeedsReview", flipped, store_now)
        hk_rec = store_now.get(HK_PREF_ID, {})
        checker.check(
            "1 保存记录带上「程序退出」的原话与 Interrupted 码",
            hk_rec.get("Code") == "Interrupted" and "程序就退出" in hk_rec.get("Message", ""),
            hk_rec,
        )
        jp_rec = store_now.get(JP_CHECK_ID, {})
        checker.check(
            "1 测速记录也开始时间保持原样（核对窗口靠它）",
            jp_rec.get("AtUnix") == fixture["sampleAt"],
            jp_rec,
        )
        checker.check(
            "1 明确的失败记录没有被改写",
            store_now.get(SG_CHECK_ID, {}).get("Phase") == "Failed",
            store_now.get(SG_CHECK_ID),
        )

        checker.check("1 切到首页", goto(ws, "home", pump))
        checker.check(
            "1 首页出现两张「待处理」提示卡",
            wait_js(ws, "(()=>{return Array.from(document.querySelectorAll('#main .cleanup-notice'))"
                        ".filter(n=>n.innerText.includes('尚未确认')).length===2;})()",
                    15, "两张待处理提示", pump),
            pending_notices(ws),
        )
        notices = pending_notices(ws)
        hk_notice = next(
            (n for n in notices if any(b["id"] == HK_PREF_ID for b in n["ids"])), {}
        )
        jp_notice = next(
            (n for n in notices if any(b["id"] == JP_CHECK_ID for b in n["ids"])), {}
        )
        checker.check(
            "1 hk 提示卡点名「香港 01 · 兼容连接保存」并说尚未确认",
            "香港 01" in hk_notice.get("text", "")
            and "兼容连接保存" in hk_notice.get("text", "")
            and "尚未确认" in hk_notice.get("text", ""),
            hk_notice,
        )
        checker.check(
            "1 jp 提示卡点名「东京 02 · 标准连接测试」",
            "东京 02" in jp_notice.get("text", "")
            and "标准连接测试" in jp_notice.get("text", ""),
            jp_notice,
        )
        checker.check(
            "1 提示卡不说「当前线路仍在使用」（这不是本地清理类动作）",
            "仍在使用" not in hk_notice.get("text", "")
            and "仍在使用" not in jp_notice.get("text", ""),
            [hk_notice, jp_notice],
        )
        checker.check(
            "1 两张卡都给「查看并处理」",
            all(
                len(n.get("ids", [])) == 1 and n["ids"][0]["label"] == "查看并处理"
                for n in (hk_notice, jp_notice)
            ),
            [hk_notice, jp_notice],
        )
        screenshot(ws, report_dir / "01-pending-notices.png", report["shots"])

        # ---------- 场景 2：既有的失败反馈直接显示在卡片上 ----------
        checker.check("2 切到线路页", goto(ws, "lines", pump))
        checker.check(
            "2 sg 卡片显示失败反馈",
            wait_js(
                ws,
                "(()=>{const c=document.querySelector('#main [data-action=details][data-id=sg]')"
                ".closest('.line-card');return !!c&&c.innerText.includes('标准连接测试 · 未完成')"
                "&&c.innerText.includes('上次测速没有通过');})()",
                12,
                "sg 失败反馈",
                pump,
            ),
            line_card_text(ws, "sg"),
        )
        sg_buttons = ws.evaluate(
            "(()=>{const c=document.querySelector('#main [data-action=details][data-id=sg]')"
            ".closest('.line-card');return c?{retry:!!c.querySelector('[data-action=retryLineAction]'),"
            "diagnose:!!c.querySelector('[data-action=diagnostics]')}:null;})()"
        ) or {}
        checker.check(
            "2 失败反馈可重新测试、可运行诊断",
            sg_buttons.get("retry") and sg_buttons.get("diagnose"),
            sg_buttons,
        )
        screenshot(ws, report_dir / "02-failed-feedback.png", report["shots"])

        # ---------- 场景 3：核对 hk 的保存（只看证据，不重跑）----------
        cfg_before = config_file.read_bytes()
        checker.check("3 切到首页", goto(ws, "home", pump))
        checker.check(
            "3 点 hk 提示卡上的「查看并处理」",
            wait_click(
                ws,
                f'#main [data-action=reviewOperation][data-id="{HK_PREF_ID}"]',
                10,
                "核对按钮",
                pump,
            ),
        )
        checker.check(
            "3 核对结论：上次保存没有落地",
            wait_toast(ws, "上次保存没有落地", 12, pump),
            ws.evaluate("document.querySelector('#toast')?.textContent || ''"),
        )
        reviewed = wait_until(
            lambda: records(root).get(HK_PREF_ID, {}).get("Phase") == "Failed",
            10,
            "核对结论落盘",
            pump,
        )
        hk_rec = records(root).get(HK_PREF_ID, {})
        report["notes"].append({"reviewedPreference": hk_rec})
        checker.check(
            "3 记录改判 Failed / NotApplied",
            reviewed and hk_rec.get("Phase") == "Failed" and hk_rec.get("Code") == "NotApplied",
            hk_rec,
        )
        checker.check(
            "3 记录里是「现在仍是自动选择」的原话",
            "现在仍是自动选择" in hk_rec.get("Message", ""),
            hk_rec,
        )
        checker.check(
            "3 核对没有改配置（一个字节不差）",
            config_file.read_bytes() == cfg_before,
        )
        checker.check(
            "3 提示卡只剩 jp 一张",
            wait_js(
                ws,
                "(()=>{return Array.from(document.querySelectorAll('#main .cleanup-notice'))"
                ".filter(n=>n.innerText.includes('尚未确认')).length===1;})()",
                10,
                "提示卡减少",
                pump,
            ),
            pending_notices(ws),
        )
        screenshot(ws, report_dir / "03-preference-reviewed.png", report["shots"])

        # ---------- 场景 4：卡片上的「重试保存」真的落地 ----------
        checker.check("4 切到线路页", goto(ws, "lines", pump))
        checker.check(
            "4 hk 卡片出现「重试保存」",
            wait_js(
                ws,
                "(()=>{const c=document.querySelector('#main [data-action=details][data-id=hk]')"
                ".closest('.line-card');const b=c&&c.querySelector('[data-action=retryLineAction]');"
                "return !!b&&b.textContent.trim()==='重试保存';})()",
                10,
                "重试保存按钮",
                pump,
            ),
            line_card_text(ws, "hk"),
        )
        checker.check(
            "4 点「重试保存」",
            wait_click(ws, "#main [data-action=retryLineAction][data-id=hk]", 8, "点重试", pump),
        )
        retried = wait_until(
            lambda: find_record(root, HK["id"], "Preference").get("Phase") == "Succeeded",
            20,
            "重试保存完成",
            pump,
        )
        hk_rec = find_record(root, HK["id"], "Preference")
        report["notes"].append({"retriedPreference": hk_rec})
        checker.check(
            "4 记录变成功，且是 旧版的卡片原话",
            retried
            and hk_rec.get("Message") == "已固定为兼容连接，下次连接生效。"
            and hk_rec.get("Code") == "",
            hk_rec,
        )
        cfg_now = read_cfg(root)
        hk_line = next(l for l in cfg_now["lines"] if l["id"] == HK["id"])
        checker.check(
            "4 配置真的固定为兼容连接",
            hk_line.get("transport") == "tcp",
            hk_line,
        )
        checker.check(
            "4 抽屉里反馈条显示「兼容连接保存 · 已完成」",
            open_drawer(ws, "hk", pump)
            and wait_js(
                ws,
                "(()=>{const n=document.querySelector('#drawer .line-feedback');"
                "return !!n&&n.innerText.includes('兼容连接保存 · 已完成')"
                "&&n.innerText.includes('已固定为兼容连接，下次连接生效。');})()",
                10,
                "hk 成功反馈",
                pump,
            ),
            drawer_feedback(ws),
        )
        checker.check(
            "4 成功反馈不再给「重试保存」",
            all(not f["retry"] for f in drawer_feedback(ws)),
            drawer_feedback(ws),
        )
        screenshot(ws, report_dir / "04-preference-retried.png", report["shots"])
        click(ws, "#drawer [data-close]")

        # ---------- 场景 5：核对 jp 的测速（读采样窗口，不重新发请求）----------
        checker.check("5 切到首页", goto(ws, "home", pump))
        checker.check(
            "5 点 jp 提示卡上的「查看并处理」",
            wait_click(
                ws,
                f'#main [data-action=reviewOperation][data-id="{JP_CHECK_ID}"]',
                10,
                "核对测速",
                pump,
            ),
        )
        checker.check(
            "5 核对结论带窗口里的真实采样（41 ms）",
            wait_toast(ws, f"已确认上次测速完成：{SAMPLE_MS} ms", 12, pump),
            ws.evaluate("document.querySelector('#toast')?.textContent || ''"),
        )
        jp_rec = records(root).get(JP_CHECK_ID, {})
        report["notes"].append({"reviewedCheck": jp_rec})
        checker.check(
            "5 记录变成功并保存同一读数",
            jp_rec.get("Phase") == "Succeeded" and jp_rec.get("LatencyMs") == SAMPLE_MS,
            jp_rec,
        )
        checker.check(
            "5 待处理提示卡全部消失",
            wait_js(
                ws,
                "(()=>{return Array.from(document.querySelectorAll('#main .cleanup-notice'))"
                ".filter(n=>n.innerText.includes('尚未确认')).length===0;})()",
                10,
                "提示卡消失",
                pump,
            ),
            pending_notices(ws),
        )
        checker.check("5 切到线路页", goto(ws, "lines", pump))
        checker.check(
            "5 jp 抽屉里显示「标准测试 · 已完成」",
            open_drawer(ws, "jp", pump)
            and wait_js(
                ws,
                "(()=>{const ns=Array.from(document.querySelectorAll('#drawer .line-feedback'));"
                "return ns.some(n=>n.innerText.includes('标准连接测试 · 已完成')"
                "&&n.innerText.includes(%s));})()"
                % json.dumps(f"已确认上次测速完成：{SAMPLE_MS} ms", ensure_ascii=False),
                10,
                "jp 成功反馈",
                pump,
            ),
            drawer_feedback(ws),
        )
        screenshot(ws, report_dir / "05-check-reviewed.png", report["shots"])

        # ---------- 场景 6：断开状态下真点测速 → 失败如实落盘 + 可重试 ----------
        checker.check(
            "6 点抽屉里的「测试这条线路」",
            wait_click(ws, "#drawer [data-action=testLine]", 10, "测速按钮", pump),
        )
        checker.check(
            "6 失败反馈如实说「连接后测量」",
            wait_js(
                ws,
                "(()=>{const ns=Array.from(document.querySelectorAll('#drawer .line-feedback'));"
                "return ns.some(n=>n.innerText.includes('标准连接测试 · 未完成')"
                "&&n.innerText.includes('连接后测量'));})()",
                20,
                "断开测速反馈",
                pump,
            ),
            drawer_feedback(ws),
        )
        first_id = find_record(root, JP["id"], "Check").get("Id", "")
        jp_rec = records(root).get(first_id, {})
        report["notes"].append({"offlineCheck": jp_rec})
        checker.check(
            "6 记录是 Failed / environment，测速确实发生了",
            jp_rec.get("Phase") == "Failed"
            and jp_rec.get("Code") == "environment"
            and jp_rec.get("Message") == "连接后测量",
            jp_rec,
        )
        buttons = drawer_feedback(ws)
        report["notes"].append({"offlineFeedback": buttons})
        checker.check(
            "6 反馈条给「重新测试」与「运行诊断」",
            any(f["retry"] and f["retryLabel"] == "重新测试" and f["diagnose"] for f in buttons),
            buttons,
        )
        checker.check(
            "6 点「重新测试」",
            wait_click(
                ws,
                f"#drawer [data-action=retryLineAction][data-id=jp]",
                8,
                "重新测试",
                pump,
            ),
        )
        checker.check(
            "6 重试确实生成了新的记录 id",
            wait_until(
                lambda: any(
                    rec.get("LineId") == JP["id"]
                    and rec.get("Kind") == "Check"
                    and rec.get("Id") not in ("", JP_CHECK_ID, first_id)
                    for rec in records(root).values()
                ),
                20,
                "新测速记录",
                pump,
            ),
            records(root),
        )
        screenshot(ws, report_dir / "06-offline-test-retry.png", report["shots"])
        click(ws, "#drawer [data-close]")

        # ---------- 场景 7：抽屉里保存连接方式也留反馈 ----------
        checker.check("7 打开 sg 抽屉", open_drawer(ws, "sg", pump))
        checker.check(
            "7 点「标准」",
            wait_click(
                ws,
                f"#drawer [data-action=setProfile][data-value=Udp][data-id={SG['id']}]",
                10,
                "标准档",
                pump,
            ),
        )
        sg_saved = wait_until(
            lambda: any(
                rec.get("LineId") == SG["id"]
                and rec.get("Kind") == "Preference"
                and rec.get("Phase") == "Succeeded"
                for rec in records(root).values()
            ),
            20,
            "sg 保存记录",
            pump,
        )
        sg_pref = next(
            (rec for rec in records(root).values()
             if rec.get("LineId") == SG["id"] and rec.get("Kind") == "Preference"),
            {},
        )
        report["notes"].append({"drawerPreference": sg_pref})
        checker.check(
            "7 保存记录成功且原话与旧版一致",
            sg_saved and sg_pref.get("Message") == "已固定为标准连接，下次连接生效。",
            sg_pref,
        )
        sg_line = next(l for l in read_cfg(root)["lines"] if l["id"] == SG["id"])
        checker.check("7 配置里 sg 固定为标准连接", sg_line.get("transport") == "udp", sg_line)
        checker.check(
            "7 抽屉反馈条显示「标准连接保存 · 已完成」",
            wait_js(
                ws,
                "(()=>{const ns=Array.from(document.querySelectorAll('#drawer .line-feedback'));"
                "return ns.some(n=>n.innerText.includes('标准连接保存 · 已完成')"
                "&&n.innerText.includes('已固定为标准连接，下次连接生效。'));})()",
                10,
                "sg 成功反馈",
                pump,
            ),
            drawer_feedback(ws),
        )
        screenshot(ws, report_dir / "07-drawer-preference.png", report["shots"])

        # ---------- 场景 8：记录文件坏掉 → 说「读不出来」，线路页照常 ----------
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        ws = None
        process.terminate()
        process.wait(timeout=15)
        checker.check(
            "8 旧宿主已退出",
            wait_until(lambda: responsive_pipe() is None, 20, "旧宿主退出", pump),
        )
        log.close()
        log = None
        store_file.write_text("{broken", encoding="utf-8")
        process2, log2, port2 = launch("2")
        ws2, pump2 = connect(port2, process2)
        ready(ws2, pump2, "坏记录宿主", 3)
        checker.check("8 切到首页", goto(ws2, "home", pump2))
        checker.check(
            "8 首页明说「线路操作记录读不出来」",
            wait_js(
                ws2,
                "(()=>{return Array.from(document.querySelectorAll('#main .notice'))"
                ".some(n=>n.innerText.includes('线路操作记录读不出来'));})()",
                20,
                "读错误提示",
                pump2,
            ),
            ws2.evaluate("document.querySelector('#main')?.innerText.slice(0,800)"),
        )
        checker.check(
            "8 快照里的 LineActionsReadError 非空",
            wait_until(
                lambda: bool(snapshot(ws2).get("LineActionsReadError")),
                10,
                "快照读错误",
                pump2,
            ),
            snapshot(ws2).get("LineActionsReadError"),
        )
        screenshot(ws2, report_dir / "08-broken-store.png", report["shots"])

        # ---------- 收尾 ----------
        checker.check(
            "9 用户配置没被改过（config.json md5 一致）",
            md5_of(USER_CONFIG) == user_config_md5,
        )
        checker.check("9 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check(
            "9 收尾时没有残留的 spidervpn 进程",
            len(processes_of("spidervpn.exe")) <= 1,
        )
    finally:
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
