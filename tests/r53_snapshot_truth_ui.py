#!/usr/bin/env python3
"""r53 界面验收：快照里的三个假字段换成真值（B2/B8/B9）。

验的是「页面上的事实是不是宿主真给的那一份」：

1. 没有运行记录时：`ConnectedSince` 必须是 `null`，首页**不许**出现「引擎已运行」那一行
   （宁可没有，也不要一个编出来的时长）；
2. 手写一条**真的连上**的运行记录（`State=Running`、`EnginePid` 指向一个活着的进程、
   `StartedAt` 是 65 分钟前）→ 宿主下一帧就投影成 `Connected`：
   - 快照 `ConnectedSince` 与记录里的 `StartedAt` 逐字一致；
   - 首页那一行真的算出「引擎已运行 1 小时 N 分」，且分钟数与 65 分钟对得上；
3. 把记录删掉 → 快照立刻回到 `null`、那一行消失。
   这条挡的是「缓存一个旧起点」：没有它，上面那条只能证明「能显示」，不能证明「会收回去」；
4. `TradeExit` 是配置里的实际 tag（现场是 `hk`），不是常量；
5. 空闲时 `BusyMessage` 是空串——不许留一句过期的「正在连接」。

快照本身通过挂钩 `window.__tcPush` 抓（宿主每秒推一次），读的是**宿主真正发给页面的
那份 JSON**，不是从 DOM 反推；DOM 那条单独断言，因为用户看的是它。

不连任何服务器：只写/删一个 `runtime.json`，代理与配置一概不动。
"""
from __future__ import annotations

import argparse
import glob
import importlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
free_port = helpers.free_port
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

DATA_ROOT = Path(r"C:\SpiderVPN\data")
RUNTIME = DATA_ROOT / "runtime.json"

# 挂钩宿主的推送入口：保住最新一份快照，再原样转给页面。
# 放在页面里跑，不改产品代码——验收读的是宿主真发出去的那份 JSON。
HOOK = """
(() => {
  if (window.__tcProbe) return 'already';
  const original = window.__tcPush;
  window.__tcProbe = null;
  window.__tcPush = function (snapshot) {
    window.__tcProbe = snapshot;
    return original.apply(this, arguments);
  };
  return 'hooked';
})()
"""


def pipe_name() -> str:
    for candidate in glob.glob(r"\\.\pipe\SpiderVPN.*"):
        with open(candidate, "r+b", buffering=0) as handle:
            handle.write(b'{"cmd":"ping"}\n')
            reply = b""
            while not reply.endswith(b"\n"):
                chunk = handle.read(4096)
                if not chunk:
                    break
                reply += chunk
        if b'"ok": true' in reply or b'"ok":true' in reply:
            return candidate
    raise RuntimeError("找不到能应答的命名管道")


def ask(name: str, command: dict) -> dict:
    with open(name, "r+b", buffering=0) as handle:
        handle.write((json.dumps(command, ensure_ascii=False) + "\n").encode("utf-8"))
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = handle.read(65536)
            if not chunk:
                break
            reply += chunk
    return json.loads(reply.decode("utf-8"))


def snapshot(ws: WebSocket) -> dict:
    """最新一份宿主推给页面的快照；`State` 才是业务状态那一层。

    宿主是用 `__tcPush(<对象字面量>)` 推的，所以 `returnByValue` 回来的是**对象**
    （不是 JSON 字符串）；也接受字符串，免得以后推送方式变了这条断言突然读不到。
    """
    raw = ws.evaluate("window.__tcProbe || null")
    if not raw:
        return {}
    data = raw if isinstance(raw, dict) else json.loads(raw)
    return data.get("State") or {}


def started_like(minutes_ago: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def connected_record(pid: int, started: str) -> dict:
    """一条「正在连」的运行记录。

    形状与真实 `runtime.json` 逐字一致：`SupervisorPid`/`EnginePid` 都指向宿主自己
    ——它是一个活着的进程，所以 `probe::pid_alive` 为真，投影就是 `Connected`。
    这里不装引擎：本批验的是「起点怎么显示」，不是引擎行为。
    """
    return {
        "SchemaVersion": 1,
        "SupervisorPid": pid,
        "EnginePid": pid,
        "StartedAt": started,
        "State": "Running",
        "Error": None,
    }


def wait_snapshot(ws: WebSocket, predicate, seconds: float, label: str, pump: Pump) -> bool:
    """等页面拿到一份**满足条件**的快照。快照每秒才推一次，不能按「读一次就断言」。"""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate(snapshot(ws)):
                return True
        except Exception:  # noqa: BLE001
            pass
        pump.tick()
        time.sleep(0.35)
    print(f"  （等待超时：{label}）", flush=True)
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    try:
        pipe_name()
    except Exception:  # noqa: BLE001
        pass
    else:
        raise SystemExit("已经有一个 SpiderVPN 在运行，请先关掉它再跑这条验收。")

    # 前置：现场不能本来就有连接记录（有的话下面「没有记录」那一档就不是事实了）。
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log = (report_dir / "host.log").open("wb")
    process = subprocess.Popen(
        [args.exe],
        cwd=str(Path(args.exe).parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] host pid={process.pid} cdp={port}", flush=True)

    checker = Checker()
    report: dict = {"exe": args.exe, "cdpPort": port, "shots": [], "checks": []}
    ws = None
    created = False
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
            "真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                30,
                "页面初始化",
                pump,
            ),
        )
        checker.check("已挂钩宿主推送入口", ws.evaluate(HOOK) in ("hooked", "already"))
        checker.check(
            "拿到了第一份快照",
            wait_js(ws, "!!window.__tcProbe", 25, "首份快照", pump),
        )

        # ---------- 场景 A：没有连接记录 ----------
        snap = snapshot(ws)
        checker.check(
            "A 快照：未连接",
            snap.get("State") != "Connected",
            str(snap.get("State")),
        )
        checker.check(
            "A 快照：ConnectedSince 是 null（不是空串、不是旧时间）",
            "ConnectedSince" in snap and snap.get("ConnectedSince") is None,
            json.dumps(snap.get("ConnectedSince"), ensure_ascii=False),
        )
        checker.check(
            "A 快照：TradeExit 是实际 tag",
            snap.get("TradeExit") == "hk",
            repr(snap.get("TradeExit")),
        )
        checker.check(
            "A 快照：空闲时 BusyMessage 是空串",
            snap.get("BusyMessage") == "",
            repr(snap.get("BusyMessage")),
        )
        checker.check(
            "A 页面：没有「引擎已运行」那一行",
            ws.evaluate("!document.querySelector('[data-testid=engine-runtime]')"),
        )
        checker.check(
            "A 管道：status 不给起点",
            ask(pipe_name(), {"cmd": "status"}).get("startedAt") == "",
        )
        screenshot(ws, report_dir / "01-disconnected.png", report["shots"])

        # ---------- 场景 B：手写一条「真的连上」的记录 ----------
        started = started_like(65)
        RUNTIME.write_text(
            json.dumps(connected_record(process.pid, started), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        created = True
        print(f"[probe] 已写运行记录 StartedAt={started}", flush=True)

        checker.check(
            "B 快照：下一帧就投影成 Connected",
            wait_snapshot(
                ws,
                lambda s: s.get("State") == "Connected",
                30,
                "投影成 Connected",
                pump,
            ),
            str(snapshot(ws).get("State")),
        )
        snap = snapshot(ws)
        checker.check(
            "B 快照：ConnectedSince 与记录里的 StartedAt 逐字一致",
            snap.get("ConnectedSince") == started,
            json.dumps(snap.get("ConnectedSince"), ensure_ascii=False) + f" 期望 {started}",
        )
        checker.check(
            "B 管道：status 也给同一个起点",
            ask(pipe_name(), {"cmd": "status"}).get("startedAt") == started,
            str(ask(pipe_name(), {"cmd": "status"}).get("startedAt")),
        )

        # 时长必须是**算出来的**，不是占位符：65 分钟前 → 「1 小时 N 分」。
        # 页面把分钟写成**余数**（65 分钟 = 「1 小时 5 分」），所以按总分钟判，
        # 不要按「64~67 分」去比字面量——那是把页面的人话当成了数字。
        text = ws.evaluate(
            "(()=>{const e=document.querySelector('[data-testid=engine-runtime]');"
            "return e?e.textContent:'';})()"
        ) or ""
        checker.check(
            "B 页面：出现「引擎已运行」那一行",
            "引擎已运行" in text,
            text[:120],
        )
        hours = re.search(r"(\d+)\s*小时", text)
        minutes = re.search(r"(\d+)\s*分", text)
        total = (
            int(hours.group(1)) * 60 + int(minutes.group(1))
            if hours and minutes
            else (-1 if hours is None else int(hours.group(1)) * 60)
        )
        checker.check(
            "B 页面：时长真的按起点算（65 分钟 ±3）",
            62 <= total <= 68,
            f"{text[:60]} → 折合 {total} 分钟",
        )
        checker.check(
            "B 页面：不是占位符「—」",
            "—" not in text,
            text[:120],
        )
        checker.check(
            "B 快照：占据快照里的起点后，TradeExit 仍是实际 tag",
            snap.get("TradeExit") == "hk",
            repr(snap.get("TradeExit")),
        )
        screenshot(ws, report_dir / "02-connected.png", report["shots"])

        # ---------- 场景 C：记录消失 → 一切收回去 ----------
        RUNTIME.unlink()
        created = False
        checker.check(
            "C 快照：记录没了就回到 null（不缓存旧起点）",
            wait_snapshot(
                ws,
                lambda s: s.get("State") != "Connected" and s.get("ConnectedSince") is None,
                30,
                "起点被撤回",
                pump,
            ),
            json.dumps(snapshot(ws).get("ConnectedSince"), ensure_ascii=False),
        )
        checker.check(
            "C 页面：那一行消失",
            wait_js(
                ws,
                "!document.querySelector('[data-testid=engine-runtime]')",
                20,
                "运行行消失",
                pump,
            ),
            ws.evaluate("document.body.innerText") or "",
        )
        screenshot(ws, report_dir / "03-revoked.png", report["shots"])

        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        return 0 if checker.all_passed else 1
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        # **先删记录再结束进程**：留着它，用户下次开机会看到一个假的「已连接」，
        # 而且宿主退出路径会拿那个 pid 去停「引擎」（其实就是它自己）。
        if created and RUNTIME.is_file():
            RUNTIME.unlink()
            print(f"[probe] 已删除运行记录 {RUNTIME}", flush=True)
        if not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
            time.sleep(1)
        log.close()
        print(f"[probe] runtime.json 存在：{RUNTIME.is_file()}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
