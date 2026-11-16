#!/usr/bin/env python3
"""r62 界面验收：A5/A6 通用操作记录 —— 连接/断开被中断后的「待核对」。

r62 之前，连接/断开只在成功或失败时留痕；进程在动作中途被杀掉，用户既不知道
那次动作做没做成，也没有入口核对。r62 起：动作**开始时**先写 `logs\\ui-operations.json`
（Pending），有结论再改写；启动时把遗留的 Pending 改判 `NeedsReview`，首页给
「待处理」提示卡，点「查看并处理」只查现场证据（运行中的引擎配置、系统代理还原
凭据），绝不重跑原操作：

- 连接被中断、现在引擎在跑 → 确认「已生效」；
- 断开被中断、连接还在跑 → 「可以再断开一次」（真的再点一次断开）；
- 记录文件读不出来 → 明确说「读不出来」，不当成「没有记录」。

本脚本全程点真实页面（CDP + 宿主推送 + 隔离数据根 + 临时代理键），真实进程
被强杀，验证顺序：

0. 一条线路；引擎是 PING（`-n 300`，会稳稳活着）；系统代理指向临时注册表键；
1. 点「连接」→ 记录先落 Pending → **强杀宿主**；
2. 重启：Pending 改判 NeedsReview，首页提示卡点名「连接」；核对 → 现状是
   「连接正在运行」→ 记录改判成功，且核对前后引擎配置/还原凭据一个字节不差；
3. 正常断开收尾：引擎真的死了、临时代理值还原；
4. 再连接 → 点「断开」→ 记录先落 Pending → 强杀宿主（此时引擎还在停）；
5. 重启：提示卡点名「断开」；核对 → 「可以再断开一次」，记录改判失败，
   核对本身没有杀引擎；再点一次断开 → 真正收尾；
6. 把记录文件写坏：首页说「连接与断开记录读不出来」，线路页照常可用。

反向对照（旧版 r61 exe）：第 1、2、5、6 条应全红（旧版不记录连接/断开、
没有待核对入口、也没有读错误提示）。

用法：

  python tests/r62_operation_review_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r62-operation-review\\acceptance
"""
from __future__ import annotations

import argparse
import ctypes
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
import winreg
from ctypes import wintypes
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# 断言明细里会带页面原文（含 ⓘ 这类符号）；GBK 控制台不能因此把验收崩掉。
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
free_port = helpers.free_port
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

md5_of = r54.md5_of
processes_of = r54.processes_of
responsive_pipe = r54.responsive_pipe
post = r54.post
HOOK = r54.HOOK
USER_CONFIG = r54.USER_CONFIG
RUNTIME = r54.RUNTIME

PING = Path(r"C:\Windows\System32\PING.EXE")
ENGINE_ARGS = "-n 300 127.0.0.1"
KIND = "TradeChannel.UiOperations"

KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)


def pid_alive(pid: int) -> bool:
    handle = KERNEL32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        return bool(KERNEL32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
    finally:
        KERNEL32.CloseHandle(handle)


# ---------------------------------------------------------------------------
# 临时系统代理键（绝不碰真实 WinINET 设置）
# ---------------------------------------------------------------------------
def proxy_snapshot(key_path: str) -> dict:
    values: dict = {}
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                try:
                    values[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    values[name] = None
    except OSError:
        values = {"ProxyEnable": None, "ProxyServer": None, "ProxyOverride": None}
    return values


def seed_proxy(key_path: str) -> dict:
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "127.0.0.1:7000")
        winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "localhost;127.*")
    return proxy_snapshot(key_path)


def delete_key(key_path: str) -> None:
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 夹具
# ---------------------------------------------------------------------------
def write_fixture(root: Path, endpoint_port: int) -> dict:
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    cfg = {
        "schema": 2,
        "selected": "hk",
        "lines": [
            {"id": "hk", "name": "香港 01", "proxy_endpoint": f"127.0.0.1:{endpoint_port}"}
        ],
        # 假引擎：真机验收只关心记录/核对，不关心引擎本身；PING 会稳稳活着。
        "engine": {"binary": str(PING)},
    }
    (data / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = data / "lines"
    lines.mkdir(exist_ok=True)
    # 形状贴近真实线路：有 trade-exit 与 tc-mixed，连接时 prepare 才会补 tc-check
    # 探测入站并**真的写出** runtime-engine.json（核对「连接是否在跑」靠的就是它）。
    body = {
        "inbounds": [
            {"type": "mixed", "tag": "tc-mixed", "listen": "127.0.0.1", "listen_port": endpoint_port}
        ],
        "outbounds": [
            {"type": "selector", "tag": "trade-exit", "outbounds": ["direct"], "default": "direct"},
            {"type": "direct", "tag": "direct"},
        ],
        "route": {
            "rules": [
                {"action": "route", "inbound": ["tc-mixed"], "outbound": "trade-exit"}
            ],
            "final": "trade-exit",
        },
    }
    (lines / "hk.json").write_text(
        json.dumps(body, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return cfg


def store_path(root: Path) -> Path:
    return root / "data" / "logs" / "ui-operations.json"


def records(root: Path) -> list[dict]:
    path = store_path(root)
    if not path.is_file():
        return []
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    items = value.get("Records") if isinstance(value, dict) else None
    return items if isinstance(items, list) else []


def find_record(root: Path, kind: str, pick=lambda rec: True) -> dict:
    for record in reversed(records(root)):
        if record.get("Kind") == kind and pick(record):
            return record
    return {}


def wait_for(predicate, seconds: float, label: str, pump: Pump | None = None) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except Exception:  # noqa: BLE001
            pass
        if pump is not None:
            pump.tick()
        time.sleep(0.05)
    print(f"  （等待超时：{label}）", flush=True)
    return False


def snapshot(ws: WebSocket) -> dict:
    raw = ws.evaluate("window.__tcProbe || null")
    if not raw:
        return {}
    data = raw if isinstance(raw, dict) else json.loads(raw)
    return data.get("State") or {}


def pending_ops(ws: WebSocket) -> list[dict]:
    return snapshot(ws).get("PendingOperations") or []


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
    post(ws, {"Type": "navigate", "Page": page})
    title = {"home": "首页", "lines": "线路"}[page]
    expr = (
        "(()=>{const h=document.querySelector('#main .page-head h1');"
        "return !!h&&h.textContent===%s;})()" % json.dumps(title, ensure_ascii=False)
    )
    return wait_js(ws, expr, 10, f"切到「{title}」", pump)


def wait_toast(ws: WebSocket, text: str, seconds: float, pump: Pump) -> bool:
    expr = (
        "(()=>{const t=document.querySelector('#toast');"
        "return !!t&&!t.hidden&&t.textContent.includes(%s);})()"
        % json.dumps(text, ensure_ascii=False)
    )
    return wait_js(ws, expr, seconds, f"toast「{text}」", pump)


def review_notice(ws: WebSocket, keyword: str) -> dict:
    expr = r"""
(()=>{const n=Array.from(document.querySelectorAll('#main .cleanup-notice'))
  .find(n=>n.innerText.includes(%s));
  if(!n)return {text:'',id:''};
  const b=n.querySelector('[data-action=reviewOperation]');
  return {text:n.innerText, id:b?b.dataset.id:''};})()
""" % json.dumps(keyword, ensure_ascii=False)
    return ws.evaluate(expr) or {"text": "", "id": ""}


def read_runtime(root: Path) -> dict:
    path = root / "data" / "runtime.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def engine_pid(root: Path) -> int:
    value = read_runtime(root).get("EnginePid")
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def kill_process(process: subprocess.Popen) -> None:
    try:
        process.kill()
    except Exception:  # noqa: BLE001
        pass
    try:
        process.wait(timeout=10)
    except Exception:  # noqa: BLE001
        pass


def interrupt_operation(
    ws: WebSocket,
    selector: str,
    root: Path,
    process: subprocess.Popen,
    kind: str,
    pump: Pump,
    label: str,
    exclude_ids: set[str] | None = None,
    evidence=None,
    confirm_selector: str | None = None,
) -> dict:
    """点按钮 → 一看到**新**记录就强杀宿主 → 返回盘上留下的那条记录。

    连接在工作线程里至少活 800 ms（引擎宽限窗），断开要等引擎停（最多 3 s），
    所以「看到记录 → 立即杀」落在 Pending 窗口内。杀完再读盘，看到的才是事实。

    `confirm_selector` 用于还要过一层确认框的动作（断开）：先点主按钮，再点确认，
    记录是在确认之后才写的。

    `exclude_ids` 是点击前就存在的同类记录：同类新操作开始时旧结论会被替换，
    但在点击被分发之前旧记录还在盘上；不排除它就会「看到旧记录」提前杀人。
    """
    if not wait_click(ws, selector, 10, label, pump):
        # 点不到也必须杀：留下在跑的宿主，下一段会被单实例挡住。
        kill_process(process)
        return {"clicked": False}
    if confirm_selector is not None and not wait_click(
        ws, confirm_selector, 10, f"{label}确认", pump
    ):
        kill_process(process)
        return {"clicked": True, "confirmed": False}
    excluded = exclude_ids or set()

    def fresh(record: dict) -> bool:
        return record.get("Id") not in excluded

    deadline = time.monotonic() + 8
    seen: dict = {}
    evidence_ok = evidence is None
    while time.monotonic() < deadline:
        candidate = find_record(root, kind, fresh)
        if candidate:
            seen = candidate
            if evidence is None or evidence():
                evidence_ok = True
                break
        pump.tick()
        time.sleep(0.005)
    # 无论看到没看到都杀：没杀就会留下一个还在跑的动作，下一段验收无法从干净现场开始。
    kill_process(process)
    after = find_record(root, kind, fresh)
    return {"clicked": True, "seen": seen, "afterKill": after, "evidence": evidence_ok}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    exe = Path(args.exe).resolve()
    if not exe.is_file():
        raise SystemExit(f"被测程序不存在：{exe}")
    if not PING.is_file():
        raise SystemExit(f"假引擎不存在：{PING}")

    root = report_dir / "root"
    shutil.rmtree(root, ignore_errors=True)
    endpoint_port = free_port()
    write_fixture(root, endpoint_port)
    proxy_key = f"Software\\SpiderVPN\\tests\\r62-operation-review-{os.getpid()}-proxy"
    seed = seed_proxy(proxy_key)

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
        "endpoint": f"127.0.0.1:{endpoint_port}",
        "proxyKey": proxy_key,
        "proxySeed": seed,
        "shots": [],
        "checks": [],
        "notes": [],
    }

    hosts: list[subprocess.Popen] = []
    logs: list = []
    sockets: list[WebSocket] = []
    engines: set[int] = set()

    def launch(tag: str):
        port = free_port()
        env = dict(os.environ)
        env["SPIDERVPN_ROOT"] = str(root)
        env["SPIDERVPN_PROXY_KEY"] = proxy_key
        env["SPIDERVPN_ENGINE_ARGS"] = ENGINE_ARGS
        env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
            f"--remote-debugging-port={port} --remote-allow-origins=*"
        )
        log = (report_dir / f"host{tag}.log").open("wb")
        process = subprocess.Popen(
            [str(exe)],
            cwd=str(exe.parent),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        hosts.append(process)
        logs.append(log)
        print(f"[probe] host{tag} pid={process.pid} cdp={port}", flush=True)
        return process, port

    def attach(process: subprocess.Popen, port: int):
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        connection = WebSocket(target["webSocketDebuggerUrl"])
        sockets.append(connection)
        connection.call("Page.enable")
        try:
            connection.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        return connection, Pump(process.pid)

    def ready(connection: WebSocket, host_pump: Pump, label: str) -> None:
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

    process = None
    process2 = None
    process3 = None
    process4 = None
    try:
        # ---------- 场景 1：点「连接」→ 强杀 → 重启改判待核对 ----------
        process, port = launch("1")
        ws, pump = attach(process, port)
        ready(ws, pump, "第一宿主")
        checker.check("1 切到线路页", goto(ws, "lines", pump))
        # 未测速线路在线路页的主按钮是「测速」——连接在首页的主动作上点。
        checker.check("1 回到首页", goto(ws, "home", pump))
        result = interrupt_operation(
            ws,
            "#main [data-action=connect][data-id=hk]",
            root,
            process,
            "Connect",
            pump,
            "点「连接」并强杀",
            evidence=lambda: (root / "data" / "runtime.json").is_file(),
        )
        reported = result.get("seen") or {}
        after_kill = result.get("afterKill") or {}
        report["notes"].append({"interruptedConnect": result})
        checker.check(
            "1 点「连接」后记录先落 Pending",
            reported.get("Phase") == "Pending",
            reported,
        )
        checker.check(
            "1 强杀前连接真的已经开始（运行时记录在）",
            bool(result.get("evidence")),
            result,
        )
        checker.check(
            "1 宿主被强杀后记录仍是 Pending（没有假装有结论）",
            after_kill.get("Phase") == "Pending",
            after_kill,
        )
        connect_id = after_kill.get("Id", "")
        started_at = after_kill.get("StartedAtUtc", "")
        checker.check(
            "1 宿主真的退出了",
            wait_for(lambda: not pid_alive(process.pid) and responsive_pipe() is None, 15, "旧宿主退出"),
        )

        process2, port2 = launch("2")
        ws2, pump2 = attach(process2, port2)
        ready(ws2, pump2, "重启后宿主")
        flipped = wait_for(
            lambda: find_record(root, "Connect").get("Phase") == "NeedsReview",
            15,
            "启动改判",
            pump2,
        )
        record_now = find_record(root, "Connect")
        report["notes"].append({"afterRestartConnect": record_now})
        checker.check("1 启动把 Pending 连接改判 NeedsReview", flipped, record_now)
        checker.check(
            "1 改判带「程序退出」原话与 Interrupted 码",
            record_now.get("Code") == "Interrupted"
            and "程序就退出" in record_now.get("Message", ""),
            record_now,
        )
        checker.check(
            "1 开始时间保持原样（核对的依据）",
            record_now.get("StartedAtUtc") == started_at,
            {"before": started_at, "after": record_now.get("StartedAtUtc")},
        )
        checker.check("1 切到首页", goto(ws2, "home", pump2))
        checker.check(
            "1 首页提示卡点名「连接」",
            wait_js(
                ws2,
                "(()=>{return Array.from(document.querySelectorAll('#main .cleanup-notice'))"
                ".some(n=>n.innerText.includes('上次「连接」没有拿到结果'));})()",
                15,
                "连接待核对提示",
                pump2,
            ),
            ws2.evaluate("document.querySelector('#main')?.innerText.slice(0,900)"),
        )
        notice = review_notice(ws2, "上次「连接」没有拿到结果")
        report["notes"].append({"connectNotice": notice})
        checker.check(
            "1 提示卡带「查看并处理」且 id 就是那条记录",
            notice.get("id") == connect_id,
            notice,
        )
        checker.check(
            "1 快照里的待处理是「连接」",
            any(op.get("Label") == "连接" and op.get("Id") == connect_id for op in pending_ops(ws2)),
            pending_ops(ws2),
        )
        checker.check(
            "1 快照的读错误为空（这次是「有待核对」，不是「读不出来」）",
            snapshot(ws2).get("OperationsReadError") == "",
            snapshot(ws2).get("OperationsReadError"),
        )
        screenshot(ws2, report_dir / "01-connect-pending.png", report["shots"])

        runtime_engine = root / "data" / "runtime-engine.json"
        journal = root / "data" / "proxy-journal.json"
        engine = engine_pid(root)
        if engine:
            engines.add(engine)
        checker.check(
            "1 现场证据：引擎配置与还原凭据都在，引擎还活着",
            runtime_engine.is_file() and journal.is_file() and pid_alive(engine),
            {"runtimeEngine": runtime_engine.is_file(), "journal": journal.is_file(), "pid": engine},
        )
        engine_md5 = md5_of(runtime_engine) if runtime_engine.is_file() else ""
        journal_md5 = md5_of(journal) if journal.is_file() else ""
        checker.check(
            "1 点「查看并处理」",
            wait_click(
                ws2,
                f'#main [data-action=reviewOperation][data-id="{connect_id}"]',
                10,
                "核对连接",
                pump2,
            ),
        )
        checker.check(
            "1 核对结论：上次连接已经生效",
            wait_toast(ws2, "上次连接已经生效：当前连接正在运行。", 15, pump2),
            ws2.evaluate("document.querySelector('#toast')?.textContent || ''"),
        )
        settled = wait_for(
            lambda: find_record(root, "Connect").get("Phase") == "Succeeded",
            10,
            "连接核对落盘",
            pump2,
        )
        record_now = find_record(root, "Connect")
        report["notes"].append({"reviewedConnect": record_now})
        checker.check(
            "1 记录改判 Succeeded / ReviewedApplied",
            settled
            and record_now.get("Phase") == "Succeeded"
            and record_now.get("Code") == "ReviewedApplied",
            record_now,
        )
        checker.check(
            "1 核对只读：引擎配置一个字节不差",
            runtime_engine.is_file() and md5_of(runtime_engine) == engine_md5,
        )
        checker.check(
            "1 核对只读：还原凭据一个字节不差",
            journal.is_file() and md5_of(journal) == journal_md5,
        )
        checker.check("1 核对没有杀引擎", pid_alive(engine), engine)
        checker.check(
            "1 提示卡消失",
            wait_js(
                ws2,
                "(()=>{return !Array.from(document.querySelectorAll('#main .cleanup-notice'))"
                ".some(n=>n.innerText.includes('上次「连接」没有拿到结果'));})()",
                10,
                "连接提示消失",
                pump2,
            ),
        )
        checker.check(
            "1 快照里不再有待处理",
            wait_for(lambda: not pending_ops(ws2), 10, "待处理清空", pump2),
            pending_ops(ws2),
        )
        screenshot(ws2, report_dir / "02-connect-reviewed.png", report["shots"])

        # ---------- 场景 2：正常断开收尾（真的还原）----------
        checker.check(
            "2 点「断开」",
            wait_click(ws2, "#main [data-action=disconnect]", 10, "断开", pump2),
        )
        checker.check(
            "2 确认断开（断开必须先问一次）",
            wait_click(
                ws2,
                "#dialog-root [data-action=confirmDialog]",
                10,
                "确认断开",
                pump2,
            ),
        )
        checker.check(
            "2 断开记录成功且原话是「断开完成」",
            wait_for(
                lambda: find_record(root, "Disconnect").get("Phase") == "Succeeded",
                30,
                "断开完成",
                pump2,
            )
            and find_record(root, "Disconnect").get("Message") == "断开完成",
            find_record(root, "Disconnect"),
        )
        checker.check(
            "2 运行时记录与引擎配置都清掉了",
            wait_for(
                lambda: not (root / "data" / "runtime.json").is_file()
                and not runtime_engine.is_file(),
                10,
                "运行时清空",
            ),
        )
        checker.check("2 引擎进程真的死了", wait_for(lambda: not pid_alive(engine), 10, "引擎退出"))
        checker.check(
            "2 临时系统代理还原成验收前的值",
            wait_for(lambda: proxy_snapshot(proxy_key) == seed, 10, "代理还原"),
            proxy_snapshot(proxy_key),
        )
        checker.check(
            "2 断开记录不冒充连接记录",
            find_record(root, "Connect").get("Phase") == "Succeeded"
            and find_record(root, "Disconnect").get("Kind") == "Disconnect",
            records(root),
        )
        screenshot(ws2, report_dir / "03-cleanup-disconnect.png", report["shots"])

        # ---------- 场景 3：连接后点断开 → 强杀 → 重启核对「可再断开」----------
        old_connect_id = find_record(root, "Connect").get("Id", "")
        checker.check(
            "3 再次连接",
            wait_click(ws2, "#main [data-action=connect][data-id=hk]", 10, "再连接", pump2),
        )
        checker.check(
            "3 连接成功落盘（必须是这一次的新记录）",
            wait_for(
                lambda: find_record(
                    root, "Connect", lambda rec: rec.get("Id") != old_connect_id
                ).get("Phase")
                == "Succeeded",
                30,
                "再次连接完成",
                pump2,
            ),
            find_record(root, "Connect"),
        )
        engine2 = engine_pid(root)
        if engine2:
            engines.add(engine2)
        checker.check(
            "3 连接后引擎在跑、代理已接管",
            bool(engine2) and pid_alive(engine2) and (root / "data" / "proxy-journal.json").is_file(),
            {"pid": engine2, "journal": (root / "data" / "proxy-journal.json").is_file()},
        )
        checker.check("3 切到首页", goto(ws2, "home", pump2))
        old_disconnect_id = find_record(root, "Disconnect").get("Id", "")
        down = interrupt_operation(
            ws2,
            "#main [data-action=disconnect]",
            root,
            process2,
            "Disconnect",
            pump2,
            "点「断开」并强杀",
            {old_disconnect_id} if old_disconnect_id else set(),
            confirm_selector="#dialog-root [data-action=confirmDialog]",
        )
        report["notes"].append({"interruptedDisconnect": down})
        seen_down = down.get("seen") or {}
        after_down = down.get("afterKill") or {}
        checker.check(
            "3 点「断开」后记录先落 Pending",
            seen_down.get("Phase") == "Pending",
            seen_down,
        )
        checker.check(
            "3 宿主被强杀后断开记录仍是 Pending",
            after_down.get("Phase") == "Pending",
            after_down,
        )
        checker.check(
            "3 被杀时引擎还在（这正是需要核对的事实）",
            bool(engine2) and pid_alive(engine2) and (root / "data" / "runtime.json").is_file(),
            {"pid": engine2},
        )
        checker.check(
            "3 旧宿主真的退出了",
            wait_for(
                lambda: not pid_alive(process2.pid) and responsive_pipe() is None,
                15,
                "第二宿主退出",
            ),
        )

        process3, port3 = launch("3")
        ws3, pump3 = attach(process3, port3)
        ready(ws3, pump3, "断开核对宿主")
        flipped = wait_for(
            lambda: find_record(root, "Disconnect").get("Phase") == "NeedsReview",
            15,
            "断开改判",
            pump3,
        )
        down_now = find_record(root, "Disconnect")
        report["notes"].append({"afterRestartDisconnect": down_now})
        checker.check("3 启动把 Pending 断开改判 NeedsReview", flipped, down_now)
        checker.check(
            "3 断开记录点名「断开」且带 Interrupted",
            down_now.get("Code") == "Interrupted"
            and "「断开」" in down_now.get("Message", ""),
            down_now,
        )
        checker.check("3 切到首页", goto(ws3, "home", pump3))
        checker.check(
            "3 首页提示卡点名「断开」",
            wait_js(
                ws3,
                "(()=>{return Array.from(document.querySelectorAll('#main .cleanup-notice'))"
                ".some(n=>n.innerText.includes('上次「断开」没有拿到结果'));})()",
                15,
                "断开待核对提示",
                pump3,
            ),
            ws3.evaluate("document.querySelector('#main')?.innerText.slice(0,900)"),
        )
        notice = review_notice(ws3, "上次「断开」没有拿到结果")
        report["notes"].append({"disconnectNotice": notice})
        checker.check(
            "3 提示卡带「查看并处理」且 id 对得上",
            notice.get("id") == after_down.get("Id"),
            notice,
        )
        checker.check(
            "3 快照里的待处理是「断开」",
            any(op.get("Label") == "断开" for op in pending_ops(ws3)),
            pending_ops(ws3),
        )
        screenshot(ws3, report_dir / "04-disconnect-pending.png", report["shots"])

        runtime_engine3 = root / "data" / "runtime-engine.json"
        engine_md5 = md5_of(runtime_engine3) if runtime_engine3.is_file() else ""
        checker.check(
            "3 点「查看并处理」",
            wait_click(
                ws3,
                f'#main [data-action=reviewOperation][data-id="{after_down.get("Id")}"]',
                10,
                "核对断开",
                pump3,
            ),
        )
        checker.check(
            "3 核对结论：连接还在，可以再断开一次",
            wait_toast(ws3, "上次断开没有完成：当前连接还在运行。可以再断开一次。", 15, pump3),
            ws3.evaluate("document.querySelector('#toast')?.textContent || ''"),
        )
        settled = wait_for(
            lambda: find_record(root, "Disconnect").get("Phase") == "Failed",
            10,
            "断开核对落盘",
            pump3,
        )
        down_now = find_record(root, "Disconnect")
        report["notes"].append({"reviewedDisconnect": down_now})
        checker.check(
            "3 记录改判 Failed / ReviewedNotApplied",
            settled
            and down_now.get("Phase") == "Failed"
            and down_now.get("Code") == "ReviewedNotApplied",
            down_now,
        )
        checker.check(
            "3 核对本身没有动引擎配置",
            runtime_engine3.is_file() and md5_of(runtime_engine3) == engine_md5,
        )
        checker.check("3 核对本身没有杀引擎", pid_alive(engine2), engine2)
        checker.check(
            "3 提示卡消失",
            wait_js(
                ws3,
                "(()=>{return !Array.from(document.querySelectorAll('#main .cleanup-notice'))"
                ".some(n=>n.innerText.includes('上次「断开」没有拿到结果'));})()",
                10,
                "断开提示消失",
                pump3,
            ),
        )
        screenshot(ws3, report_dir / "05-disconnect-reviewed.png", report["shots"])

        reviewed_down_id = down_now.get("Id", "")
        checker.check(
            "3 按结论「再断开一次」",
            wait_click(ws3, "#main [data-action=disconnect]", 10, "再断开", pump3),
        )
        checker.check(
            "3 确认再断开",
            wait_click(
                ws3,
                "#dialog-root [data-action=confirmDialog]",
                10,
                "确认再断开",
                pump3,
            ),
        )
        checker.check(
            "3 这次断开真的完成",
            wait_for(
                lambda: find_record(
                    root, "Disconnect", lambda rec: rec.get("Id") != reviewed_down_id
                ).get("Phase")
                == "Succeeded",
                30,
                "再断开完成",
                pump3,
            )
            and find_record(
                root, "Disconnect", lambda rec: rec.get("Id") != reviewed_down_id
            ).get("Message")
            == "断开完成",
            find_record(root, "Disconnect"),
        )
        checker.check(
            "3 收尾干净：运行时清空、引擎退出、代理还原",
            wait_for(
                lambda: not (root / "data" / "runtime.json").is_file()
                and not runtime_engine3.is_file()
                and not pid_alive(engine2)
                and proxy_snapshot(proxy_key) == seed,
                20,
                "断开收尾",
            ),
            {
                "runtime": (root / "data" / "runtime.json").is_file(),
                "engineAlive": pid_alive(engine2),
                "proxy": proxy_snapshot(proxy_key),
            },
        )
        screenshot(ws3, report_dir / "06-disconnect-retried.png", report["shots"])

        # ---------- 场景 4：记录文件坏掉 → 说「读不出来」，页面照常 ----------
        checker.check("4 先让旧宿主退出", ready_clean_exit(ws3, process3, pump3))
        store_path(root).write_text("{broken", encoding="utf-8")
        process4, port4 = launch("4")
        ws4, pump4 = attach(process4, port4)
        ready(ws4, pump4, "坏记录宿主")
        checker.check("4 切到首页", goto(ws4, "home", pump4))
        checker.check(
            "4 首页明说「连接与断开记录读不出来」",
            wait_js(
                ws4,
                "(()=>{return Array.from(document.querySelectorAll('#main .notice'))"
                ".some(n=>n.innerText.includes('连接与断开记录读不出来'));})()",
                20,
                "读错误提示",
                pump4,
            ),
            ws4.evaluate("document.querySelector('#main')?.innerText.slice(0,900)"),
        )
        checker.check(
            "4 快照里的 OperationsReadError 非空",
            wait_for(
                lambda: bool(snapshot(ws4).get("OperationsReadError")),
                10,
                "快照读错误",
                pump4,
            ),
            snapshot(ws4).get("OperationsReadError"),
        )
        checker.check("4 切到线路页", goto(ws4, "lines", pump4))
        checker.check(
            "4 记录坏了线路页照常可用",
            wait_js(
                ws4,
                "document.querySelectorAll('#main [data-action=details]').length===1",
                10,
                "线路卡仍在",
                pump4,
            ),
        )
        screenshot(ws4, report_dir / "07-broken-store.png", report["shots"])

        # ---------- 收尾 ----------
        checker.check("9 关掉坏记录宿主", ready_clean_exit(ws4, process4, pump4))
        checker.check(
            "9 用户配置没被改过（config.json md5 一致）",
            md5_of(USER_CONFIG) == user_config_md5,
        )
        checker.check("9 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check(
            "9 收尾时没有残留的 spidervpn 进程",
            len(processes_of("spidervpn.exe")) == 0,
            processes_of("spidervpn.exe"),
        )
        checker.check(
            "9 验收产生的引擎都退出了",
            all(not pid_alive(pid) for pid in engines),
            [{"pid": pid, "alive": pid_alive(pid)} for pid in engines],
        )
        checker.check(
            "9 临时系统代理值还原（真实 WinINET 从未被碰）",
            proxy_snapshot(proxy_key) == seed,
            proxy_snapshot(proxy_key),
        )
    finally:
        for pid in engines:
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
            except Exception:  # noqa: BLE001
                pass
        for connection in sockets:
            try:
                connection.close()
            except Exception:  # noqa: BLE001
                pass
        for host in hosts:
            if host is not None and not args.keep_open:
                kill_process(host)
        for handle in logs:
            try:
                handle.close()
            except Exception:  # noqa: BLE001
                pass
        # 只删我们自己的临时键：真实代理设置从来没写进去过。
        delete_key(proxy_key)

    report["checks"] = checker.checks
    (report_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    passed = sum(1 for item in checker.checks if item["ok"])
    total = len(checker.checks)
    print(f"\n合计 {passed}/{total}；证据 {report_dir}")
    return 0 if checker.all_passed else 1


def ready_clean_exit(ws: WebSocket, process: subprocess.Popen, pump: Pump) -> bool:
    try:
        ws.close()
    except Exception:  # noqa: BLE001
        pass
    kill_process(process)
    return wait_for(
        lambda: not pid_alive(process.pid) and responsive_pipe() is None,
        15,
        "宿主退出",
        pump,
    )


if __name__ == "__main__":
    raise SystemExit(main())
