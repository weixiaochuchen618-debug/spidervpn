#!/usr/bin/env python3
"""r55 界面验收：A5 连接等待态——「先退出程序」之后真的等、真的连。

改动前的缺陷：点连接发现名单程序在跑 → 弹确认框；点「先退出程序」只把框收起来，
**什么都不发生**。而页面的等待条（`.wait-notice`）与快照字段 `PendingConnectionName`
一直都在，只是宿主从来没给过真值——用户以为「它会在程序退出后连上」，其实不会。

本脚本验的是**宿主真的这么做了**（读宿主推给页面的快照 + 页面 DOM + 真进程表）：

1. 基线：没有等待态（`PendingConnectionName` 空、`Pending` 是 null、页面无 `.wait-notice`）；
2. 名单程序在跑时点连接 → 弹确认框（r54 的连接侧，本轮不改）；
3. 点「先退出程序」→ **等待条出现**：文案含「退出交易软件后会连接」+ 线路名、
   带「取消等待」按钮；快照 `PendingConnectionName` / `Pending.Name` / `Pending.DeadlineUtc`
   同时给真值；
4. 程序还在跑 → 6 秒内不发起连接（`Busy` 仍 false、`Operation` 仍 null、等待态还在）；
5. 关掉程序 → 自动发起连接（`Busy` 或 `Operation.Kind=Connect`），等待条自己消失、
   等待态被消费（不会连第二次）；等连接落定（失败也算落定）；
6. 取消等待：再走一遍，点「取消等待」→ 等待条消失、快照清空、toast「已取消等待」；
   再关掉程序，10 秒内不许自动连。

反向对照（`--mode old`，跑 r54 装机版）：第 3 步必须红——旧版点「先退出程序」
不会进等待态，`PendingConnectionName` 恒空、页面永远没有等待条。

## 环境事实

- `wfp_win::running_programs` 按**完整路径**比对，而 Win11 的 `System32\\notepad.exe`
  只是个启动器，所以用 `PING.EXE` 造「名单程序在跑」（与 r54 同一套做法）。
- 脚本用隔离数据根（`SPIDERVPN_ROOT`），从现场 `config.json` 复制一份、
  只把名单换成 PING。用户的 `C:\\SpiderVPN\\data` 一个字节都不动（前后比对 md5）。
- 自动连接用的是现场那条真实线路（当前 `203.0.113.10` 不可达）：本脚本只验
  「宿主发起了连接」，不验「连得上」——后者是 T11 的事。

## 用法

  python tests/r55_wait_connect_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r55-wait-connect

  # 反向对照（r54 装机版，点「先退出程序」什么都不发生）
  python tests/r55_wait_connect_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r55-wait-connect-negative --mode old
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
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
click = helpers.click
free_port = helpers.free_port
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

HOOK = r54.HOOK
PING = r54.PING
RUNTIME = r54.RUNTIME
USER_CONFIG = r54.USER_CONFIG
ask = r54.ask
md5_of = r54.md5_of
pipe_name = r54.pipe_name
post = r54.post
prepare_root = r54.prepare_root
processes_of = r54.processes_of
responsive_pipe = r54.responsive_pipe
snapshot = r54.snapshot
wait_snapshot = r54.wait_snapshot

WAIT_NOTICE = """
(() => {
  const el = document.querySelector('.wait-notice');
  if (!el) return null;
  return {
    text: el.textContent.replace(/\\s+/g, ' ').trim(),
    cancel: !!el.querySelector('[data-action="cancelWaiting"]'),
  };
})()
"""


def state_of(snap: dict) -> dict:
    """`r54.snapshot()` 已经把快照里的 `State` 取出来了，这里只做空值兜底。

    注意别写成 `snap.get("State")`：`State` 里本来就有个同名字段（连接状态词
    `"Connected"` 之类），那样取到的是字符串，后续 `.get()` 直接炸。
    """
    return snap or {}


def start_ping() -> subprocess.Popen:
    return subprocess.Popen(
        [str(PING), "-n", "900", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def stop_ping(ping: subprocess.Popen | None) -> None:
    if ping is None:
        return
    try:
        ping.terminate()
        ping.wait(timeout=10)
    except Exception:  # noqa: BLE001
        try:
            ping.kill()
        except Exception:  # noqa: BLE001
            pass


def connect_started(ws: WebSocket, seconds: float, pump: Pump) -> tuple[bool, dict]:
    """等宿主自己发起连接：`Busy` 或 `Operation.Kind=Connect` 出现即算。

    不验「连得上」——现场那条线路当前不可达，本脚本只证明**宿主真的去连了**。
    """
    deadline = time.time() + seconds
    last: dict = {}
    while time.time() < deadline:
        last = state_of(snapshot(ws))
        operation = last.get("Operation") or {}
        if last.get("Busy") or operation.get("Kind") == "Connect":
            return True, last
        pump.tick()
        time.sleep(0.2)
    return False, last


def wait_connect_record(log_path: Path, line_id: str, seconds: float) -> dict | None:
    """等操作记录里出现一条**界面发起**的「连接」，且指向等待时那条线路。

    为什么不靠快照的 `Busy`：连接可能在两帧之间就失败结束了（隔离根里没有引擎，
    实测 1 秒内落定），而快照是 2 秒一帧——轮询捕不到不代表没发生。
    `operations.jsonl` 是落盘的，漏不掉。
    """
    deadline = time.time() + seconds
    while time.time() < deadline:
        if log_path.is_file():
            for line in log_path.read_text(encoding="utf-8").splitlines():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if item.get("action") == "连接" and f"line:{line_id}" in str(item.get("obj") or ""):
                    return item
        time.sleep(0.2)
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--mode", choices=["new", "old"], default="new")
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
    if not PING.is_file():
        raise SystemExit(f"找不到 {PING}，无法造出「名单程序正在运行」")

    user_config_md5 = md5_of(USER_CONFIG)
    root_info = prepare_root(root)
    # 隔离根是我们自己的：上一轮的操作记录必须清掉，否则「自动连接」会被
    # 上一次那条同名线路的记录假绿掉（同一 line_id，字符串完全一样）。
    stale_ops = root / "data" / "logs" / "operations.jsonl"
    if stale_ops.is_file():
        stale_ops.unlink()

    checker = Checker()
    report: dict = {
        "mode": args.mode,
        "exe": str(exe),
        "exeMd5": md5_of(exe),
        "dataRoot": root_info,
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
    print(f"[probe] mode={args.mode} host pid={process.pid} cdp={port} root={root}", flush=True)

    ws: WebSocket | None = None
    ping: subprocess.Popen | None = None
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
        checker.check("0 已挂钩宿主推送入口", ws.evaluate(HOOK) in ("hooked", "already"))
        checker.check("0 拿到了第一份快照", wait_js(ws, "!!window.__tcProbe", 25, "首份快照", pump))
        name = pipe_name()
        print(f"[probe] pipe={name}", flush=True)

        lines = ask(name, {"cmd": "lines"})
        first = (lines.get("lines") or [{}])[0]
        line_id = str(first.get("id") or "")
        line_name = str(first.get("name") or "")
        checker.check("0 隔离根里有一条线路可用", bool(line_id), repr(lines.get("lines"))[:200])

        # ---------- 场景 1：基线 ----------
        base = state_of(snapshot(ws))
        checker.check(
            "1 基线：PendingConnectionName 是空串",
            base.get("PendingConnectionName") == "",
            repr(base.get("PendingConnectionName")),
        )
        checker.check(
            "1 基线：Pending 是 null",
            base.get("Pending") in (None, {}),
            repr(base.get("Pending")),
        )
        checker.check(
            "1 基线：页面没有等待条",
            ws.evaluate(WAIT_NOTICE) is None,
            repr(ws.evaluate(WAIT_NOTICE)),
        )
        screenshot(ws, report_dir / "01-baseline.png", report["shots"])

        # ---------- 场景 2：名单程序在跑，点连接先弹框 ----------
        ping = start_ping()
        time.sleep(1.2)
        checker.check("2 名单程序真的在跑", len(processes_of("PING.EXE")) > 0)
        post(ws, {"Type": "connect", "Id": line_id})
        appeared = wait_snapshot(
            ws,
            lambda s: (state_of(s).get("Dialog") or {}).get("Scope") == "guard-running",
            10,
            "连接确认框",
            pump,
        )
        checker.check("2 点连接先弹确认框", appeared, repr(state_of(snapshot(ws)).get("Dialog")))
        screenshot(ws, report_dir / "02-connect-dialog.png", report["shots"])

        if args.mode == "old":
            # 旧版：点「先退出程序」只收框，什么都不发生——下面两条必须红。
            click(ws, '#dialog-root [data-action="cancelDialog"]')
            time.sleep(2.0)
            notice = ws.evaluate(WAIT_NOTICE)
            st = state_of(snapshot(ws))
            checker.check("3 旧版：点「先退出程序」后出现等待条", notice is not None, repr(notice))
            checker.check(
                "3 旧版：快照给出 PendingConnectionName",
                st.get("PendingConnectionName") not in ("", None),
                repr(st.get("PendingConnectionName")),
            )
            checker.check(
                "3 旧版：点完不是什么都不做（对话框已收起）",
                st.get("Dialog") in (None, {}),
                repr(st.get("Dialog")),
            )
            screenshot(ws, report_dir / "03-old-after-cancel.png", report["shots"])
            # 旧版分支到此为止：把 PING 停掉，否则下面「没有残留进程」那条会红在
            # 脚本自己身上（旧版没有等待态，也就没有场景 5 去停它）。
            stop_ping(ping)
            ping = None
            time.sleep(0.5)
        else:
            # ---------- 场景 3：点「先退出程序」→ 等待条 ----------
            checker.check(
                "3 点「先退出程序」",
                click(ws, '#dialog-root [data-action="cancelDialog"]'),
            )
            shown = wait_js(ws, "!!document.querySelector('.wait-notice')", 10, "等待条", pump)
            checker.check("3 等待条出现", shown, repr(ws.evaluate(WAIT_NOTICE)))
            notice = ws.evaluate(WAIT_NOTICE) or {}
            text = notice.get("text") or ""
            checker.check("3 等待条说「退出交易软件后会连接」", "退出交易软件后会连接" in text, text)
            checker.check(
                "3 等待条带线路名",
                (line_name in text) if line_name else True,
                f"{text} / line={line_name}",
            )
            checker.check("3 等待条有「取消等待」", notice.get("cancel") is True, repr(notice))
            screenshot(ws, report_dir / "03-waiting.png", report["shots"])

            st = state_of(snapshot(ws))
            checker.check(
                "3 快照 PendingConnectionName 是真值",
                st.get("PendingConnectionName") == line_name,
                f"{st.get('PendingConnectionName')!r} != {line_name!r}",
            )
            pending = st.get("Pending") or {}
            checker.check(
                "3 快照 Pending.Name 是真值",
                pending.get("Name") == line_name,
                repr(pending),
            )
            deadline = pending.get("DeadlineUtc")
            checker.check(
                "3 快照 Pending.DeadlineUtc 是可解析的时刻",
                isinstance(deadline, str) and len(deadline) > 10,
                repr(deadline),
            )

            # ---------- 场景 4：程序还在跑，不许自己连 ----------
            time.sleep(6)
            st = state_of(snapshot(ws))
            checker.check("4 程序还在跑：Busy 仍是 false", st.get("Busy") is False, repr(st.get("Busy")))
            checker.check(
                "4 程序还在跑：Operation 仍是 null",
                st.get("Operation") in (None, {}),
                repr(st.get("Operation")),
            )
            checker.check(
                "4 程序还在跑：等待态还在",
                st.get("PendingConnectionName") == line_name,
                repr(st.get("PendingConnectionName")),
            )

            # ---------- 场景 5：关掉程序 → 自动连接 ----------
            stop_ping(ping)
            ping = None
            time.sleep(1.0)
            ops_log = root / "data" / "logs" / "operations.jsonl"
            record = wait_connect_record(ops_log, line_id, 30)
            checker.check(
                "5 程序退出后自动发起连接（操作记录有界面发起的「连接」）",
                record is not None,
                f"ops={ops_log} 不存在或无匹配记录",
            )
            checker.check(
                "5 连接指向等待时那条线路",
                bool(record) and f"line:{line_id}" in str((record or {}).get("obj") or ""),
                repr((record or {}).get("obj")),
            )
            checker.check(
                "5 连接来自界面路径（src=ui），不是命令行",
                (record or {}).get("src") == "ui",
                repr((record or {}).get("src")),
            )
            if record:
                # 结局（引擎不在隔离根里 → 启动后立即退出）不是本脚本要验的，
                # 但如实记下来，免得以后有人把它当成「连接成功」。
                report["notes"].append(f"自动连接的结局：{record.get('detail')}")
            screenshot(ws, report_dir / "04-autoconnect.png", report["shots"])

            consumed = wait_snapshot(
                ws,
                lambda s: state_of(s).get("PendingConnectionName") in ("", None),
                10,
                "等待态被消费",
                pump,
            )
            checker.check("5 等待态被消费（不会连第二次）", consumed, repr(state_of(snapshot(ws)).get("PendingConnectionName")))
            checker.check(
                "5 等待条自己消失",
                ws.evaluate(WAIT_NOTICE) is None,
                repr(ws.evaluate(WAIT_NOTICE)),
            )
            settled = wait_snapshot(ws, lambda s: not state_of(s).get("Busy"), 120, "连接落定", pump)
            checker.check("5 连接真的跑完（不是卡在 Busy）", settled, repr(state_of(snapshot(ws)).get("Busy")))

            # ---------- 场景 6：取消等待 ----------
            ping = start_ping()
            time.sleep(1.2)
            post(ws, {"Type": "connect", "Id": line_id})
            appeared = wait_snapshot(
                ws,
                lambda s: (state_of(s).get("Dialog") or {}).get("Scope") == "guard-running",
                10,
                "第二次确认框",
                pump,
            )
            checker.check("6 第二次点连接仍先弹框", appeared)
            click(ws, '#dialog-root [data-action="cancelDialog"]')
            checker.check(
                "6 第二次进入等待态",
                wait_js(ws, "!!document.querySelector('.wait-notice')", 10, "第二次等待条", pump),
            )
            checker.check(
                "6 点「取消等待」",
                click(ws, '.wait-notice [data-action="cancelWaiting"]'),
            )
            checker.check(
                "6 等待条消失",
                wait_js(ws, "!document.querySelector('.wait-notice')", 10, "等待条消失", pump),
            )
            st = state_of(snapshot(ws))
            checker.check(
                "6 快照清空等待态",
                st.get("PendingConnectionName") in ("", None),
                repr(st.get("PendingConnectionName")),
            )
            checker.check(
                "6 toast 说「已取消等待」",
                st.get("Toast") == "已取消等待",
                repr(st.get("Toast")),
            )
            screenshot(ws, report_dir / "05-cancelled.png", report["shots"])

            stop_ping(ping)
            ping = None
            time.sleep(1.0)

            def connect_count() -> int:
                if not ops_log.is_file():
                    return 0
                total = 0
                for line in ops_log.read_text(encoding="utf-8").splitlines():
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if item.get("action") == "连接":
                        total += 1
                return total

            before = connect_count()
            time.sleep(10)
            after = connect_count()
            checker.check(
                "6 取消之后关程序也不许自动连（没有新的「连接」记录）",
                after == before,
                f"{before} -> {after}",
            )

        # ---------- 收尾核对 ----------
        checker.check("8 用户配置没被改过（config.json md5 一致）", md5_of(USER_CONFIG) == user_config_md5)
        checker.check("8 用户数据根没有新增 runtime.json", not RUNTIME.is_file())
        checker.check("8 收尾时没有残留的 PING 进程", len(processes_of("PING.EXE")) == 0)

    finally:
        stop_ping(ping)
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
