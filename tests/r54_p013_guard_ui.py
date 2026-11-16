#!/usr/bin/env python3
"""r54 界面验收：P0-13 的**启用侧**——名单内交易程序正在运行时，「现在重新启用」必须先提示。

改动前的缺陷：点「现在重新启用」直接进 UAC/装规则，用户会以为「一装就立刻生效」，
但规则只拦**新**连接，已经建立的连接照旧。PRD P0-13 要求先把这句话说出来。

本脚本验的是**宿主真的这么做了**（读宿主推给页面的那份 JSON + 页面 DOM + 真进程表），
不是读源码：

1. 基线（名单程序没在跑）：`guard-precheck` 的 `RunningPrograms` 必须是空数组；
2. 名单程序在跑：`RunningPrograms` 必须真的报出它（这条同时证明第 1 条不是恒真）；
3. 发 `guardEnable` → 页面弹确认框（标题/正文/那句安全说明/两个按钮逐字）；
4. **没有 UAC、没有命令发出**：框出现后 3 秒，`Busy` 仍是 false、`Operation` 仍是 null、
   `spidervpn.exe` 进程数没有增加（没有起提权助手）；
5. 点「先退出程序」→ 框收起，仍然什么都没发；
6. 撤回：关掉程序后 `RunningPrograms` 回到空数组；
7. 命令行侧（真跑装好的 exe）：`--guard-install` 默认拒绝、5 秒内自己退出、
   输出里带「请先退出交易软件」与那句安全说明，且**没有**走到提权那一步。

## 两个必须说明的环境事实（我核实过，与任务书给的不一样）

- **`C:\\WINDOWS\\System32\\notepad.exe` 在这台 Win11 上只是个启动器**：真正常驻的进程
  镜像路径是 `C:\\Program Files\\WindowsApps\\Microsoft.WindowsNotepad_…\\Notepad.exe`。
  而 `wfp_win::running_programs` 是**按完整路径**比对的（`src/guard/wfp_win.rs:968-1002`），
  所以「起一个记事本」造不出「名单程序正在运行」（实测 `RunningPrograms` 仍是 `[]`）。
- 所以本脚本**不改用户配置**，而是另起一个**隔离数据根**（`SPIDERVPN_ROOT`，
  见 `src/isolation.rs:32-47`），从现场 `config.json` 复制一份、只把名单换成
  一个我能真正跑起来并保持存活的 `C:\\WINDOWS\\System32\\PING.EXE`。
  用户的 `C:\\SpiderVPN\\data` 一个字节都不动（脚本前后比对 md5）。

## 用法

  python tests/r54_p013_guard_ui.py --exe D:\\tc-rs-build\\r54-new\\bin\\spidervpn.exe \\
      --report-dir D:\\tc-rs-build\\r54-p013-ui
  # 反向对照（旧装机版）：加 --mode old，命令行那条会被跳过（会真的提权，不许跑）
  python tests/r54_p013_guard_ui.py --exe D:\\tc-rs-build\\r54-negative\\old-bin\\spidervpn.exe \\
      --report-dir D:\\tc-rs-build\\r54-p013-ui-negative --mode old
"""
from __future__ import annotations

import argparse
import base64
import ctypes
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

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
click = helpers.click
free_port = helpers.free_port
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

USER_DATA = Path(r"C:\SpiderVPN\data")
USER_CONFIG = USER_DATA / "config.json"
RUNTIME = USER_DATA / "runtime.json"
PING = Path(r"C:\WINDOWS\System32\PING.EXE")
BACKSLASH = chr(92)

# 挂钩宿主的推送入口：留住最新一份快照，再原样转给页面（不改产品代码）。
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

DIALOG = """
(() => {
  const root = document.querySelector('#dialog-root');
  if (!root || root.hidden) return null;
  const box = root.querySelector('.dialog');
  if (!box) return null;
  const pick = (sel) => { const e = root.querySelector(sel); return e ? e.textContent.trim() : ''; };
  return {
    title: pick('#dialog-title'),
    body: pick('#dialog-body'),
    note: pick('.note'),
    confirm: pick('[data-action="confirmDialog"]'),
    cancel: pick('[data-action="cancelDialog"]'),
  };
})()
"""

# 截获「旧通道」的状态落地函数：`{"cmd":…}` 这类消息宿主会回一份**状态包**，
# 由它在页面里落地。`uiweb::route` 的 `fetch` 拿到的就是**同一份**东西
# （`src/ui.rs:476-478` → `main.rs:2418-2492`），所以这里截到的东西
# 就是 `running_programs_from()` 真正看到的输入。
CAPTURE_APPLY = """
(() => {
  window.__tcApplied = null;
  const original = window.__tcApply;
  window.__tcApply = function (state) {
    window.__tcApplied = state;
    if (typeof original === 'function') return original.apply(this, arguments);
    return undefined;
  };
  return 'hooked';
})()
"""


# ---------------------------------------------------------------------------
# 命名管道（与 r49 同一套探测：只有一个能应答 ping 的才算活着的宿主）
# ---------------------------------------------------------------------------
def responsive_pipe() -> str | None:
    import glob

    for candidate in glob.glob(r"\\.\pipe\SpiderVPN.*"):
        try:
            with open(candidate, "r+b", buffering=0) as handle:
                handle.write(b'{"cmd":"ping"}\n')
                reply = b""
                while not reply.endswith(b"\n"):
                    chunk = handle.read(4096)
                    if not chunk:
                        break
                    reply += chunk
        except Exception:  # noqa: BLE001
            continue
        if b'"ok": true' in reply or b'"ok":true' in reply:
            return candidate
    return None


def pipe_name(timeout: float = 40.0) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        found = responsive_pipe()
        if found:
            return found
        time.sleep(0.4)
    raise RuntimeError("宿主的命名管道没有就绪")


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


def precheck(name: str) -> dict:
    return ask(name, {"cmd": "guard-precheck"})


# ---------------------------------------------------------------------------
# 页面 / 快照
# ---------------------------------------------------------------------------
def snapshot(ws: WebSocket) -> dict:
    raw = ws.evaluate("window.__tcProbe || null")
    if not raw:
        return {}
    data = raw if isinstance(raw, dict) else json.loads(raw)
    return data.get("State") or {}


def wait_snapshot(ws: WebSocket, predicate, seconds: float, label: str, pump: Pump) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if predicate(snapshot(ws)):
                return True
        except Exception:  # noqa: BLE001
            pass
        pump.tick()
        time.sleep(0.3)
    print(f"  （等待超时：{label}）", flush=True)
    return False


def dialog_of(ws: WebSocket) -> dict | None:
    return ws.evaluate(DIALOG)


def post(ws: WebSocket, payload: dict) -> None:
    """照页面自己的通道发一条消息。

    **不带 `Sequence`**：页面用 `State.Ack >= Sequence` 判等待态，塞一个页面没发过的
    序号会让按钮一直转圈（而 `Ack` 是宿主的自增计数，不会追上一个大数）。
    """
    body = json.dumps(payload, ensure_ascii=False)
    ws.evaluate(
        "(()=>{window.chrome.webview.postMessage("
        + json.dumps(body, ensure_ascii=False)
        + ");return true;})()"
    )


def processes_of(image: str) -> list[int]:
    """`tasklist` 拿指定镜像名的 pid 列表（提权助手与名单程序都靠它判）。"""
    try:
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=20,
        ).stdout
    except Exception:  # noqa: BLE001
        return []
    pids: list[int] = []
    for line in out.splitlines():
        cells = [c.strip('"') for c in line.split('","')]
        if len(cells) >= 2 and cells[0].lower() == image.lower():
            try:
                pids.append(int(cells[1]))
            except ValueError:
                pass
    return pids


# ---------------------------------------------------------------------------
# 隔离数据根：不动用户配置
# ---------------------------------------------------------------------------
def prepare_root(root: Path) -> dict:
    data = root / "data"
    data.mkdir(parents=True, exist_ok=True)
    cfg = json.loads(USER_CONFIG.read_text(encoding="utf-8"))
    ping = BACKSLASH.join(["C:", "WINDOWS", "System32", "PING.EXE"])
    cfg["split"]["processes"] = [{"value": "ping.exe", "target": "trade", "path": ping}]
    (data / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return {"root": str(root), "data": str(data), "processes": cfg["split"]["processes"]}


def md5_of(path: Path) -> str:
    return hashlib.md5(path.read_bytes()).hexdigest()


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
    root_cli = report_dir / "root-cli"
    prepare_root(root_cli)

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

        # ---------- 场景 1：基线（没有名单程序在跑） ----------
        # 只断言预检，不发 guardEnable：那会真的发 guard-install 并进入提权。
        base = precheck(name)
        checker.check(
            "1 基线 guard-precheck：RunningPrograms 是空数组",
            base.get("RunningPrograms") == [],
            json.dumps(base.get("RunningPrograms"), ensure_ascii=False),
        )
        checker.check(
            "1 基线 guard-precheck：名单里有 1 条（预检不是空转）",
            base.get("TradeProgramCount") == 1,
            str(base.get("TradeProgramCount")),
        )
        snap = snapshot(ws)
        checker.check("1 基线快照：没有对话框", snap.get("Dialog") in (None, {}), repr(snap.get("Dialog")))
        checker.check("1 基线快照：Busy 是 false", snap.get("Busy") is False, repr(snap.get("Busy")))
        checker.check(
            "1 基线页面：没有对话框 DOM",
            ws.evaluate("(()=>{const r=document.querySelector('#dialog-root');return !r||r.hidden;})()"),
        )
        screenshot(ws, report_dir / "01-baseline.png", report["shots"])

        # ---------- 场景 2：让名单里的程序跑起来 ----------
        ping = subprocess.Popen(
            [str(PING), "-t", "127.0.0.1"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print(f"[probe] ping pid={ping.pid}", flush=True)
        time.sleep(2.0)
        running = precheck(name).get("RunningPrograms")
        report["runningPrograms"] = running
        checker.check(
            "2 有程序在跑：RunningPrograms 真的报出它",
            isinstance(running, list) and any("ping" in str(x).lower() for x in running),
            json.dumps(running, ensure_ascii=False),
        )
        checker.check(
            "2 有程序在跑：RunningPrograms 恰好一条（不是把整机进程都列进来）",
            isinstance(running, list) and len(running) == 1,
            json.dumps(running, ensure_ascii=False),
        )

        # ---------- 场景 2b：宿主回给页面的那份 precheck 里到底有什么 ----------
        # `uiweb::route` 读的是 `fetch("guard-precheck")`；`fetch` 走的是
        # `main.rs` 的 `ui_handler`（返回**状态包**，不是命令原始回包）。
        # 这里把同一份回包截下来：如果里面没有 `RunningPrograms`，
        # 那么 `running_programs_from()` 无论真机有没有程序在跑都只能得到空数组。
        checker.check("2b 已截获宿主回给页面的状态包", ws.evaluate(CAPTURE_APPLY) == "hooked")
        post(ws, {"cmd": "guard-precheck"})
        captured = wait_js(ws, "!!window.__tcApplied", 15, "状态包", pump)
        bundle_keys = ws.evaluate(
            "(()=>{const s=window.__tcApplied;return s?Object.keys(s).sort():[];})()"
        ) or []
        report["precheckBundleKeys"] = bundle_keys
        checker.check(
            "2b 宿主回包里有 RunningPrograms（fetch 的契约）",
            captured and "RunningPrograms" in bundle_keys,
            "回包顶部键：" + ", ".join(bundle_keys),
        )

        # ---------- 场景 3：guardEnable 必须先弹确认框 ----------
        children_before = len(processes_of("spidervpn.exe"))
        log_mark = log_path.stat().st_size if log_path.exists() else 0
        post(ws, {"Type": "guardEnable"})
        appeared = wait_js(ws, f"!!({DIALOG})", 12, "启用侧确认框", pump)
        checker.check("3 发 guardEnable 后出现确认框", appeared, ws.evaluate(DIALOG))
        dialog = dialog_of(ws) or {}
        report["dialog"] = dialog
        checker.check("3 标题：交易程序正在运行", dialog.get("title") == "交易程序正在运行", dialog.get("title"))
        checker.check(
            "3 正文列出了正在运行的程序名",
            "ping.exe" in (dialog.get("body") or "").lower(),
            dialog.get("body"),
        )
        checker.check("3 正文说「请先退出」", "请先退出" in (dialog.get("body") or ""), dialog.get("body"))
        checker.check(
            "3 说明含「已建立的连接不会被切断」（逐字）",
            "已建立的连接不会被切断" in (dialog.get("note") or ""),
            dialog.get("note"),
        )
        checker.check(
            "3 说明含「只有新连接会被阻止」（逐字）",
            "只有新连接会被阻止" in (dialog.get("note") or ""),
            dialog.get("note"),
        )
        checker.check("3 主按钮文案：仍要启用", dialog.get("confirm") == "仍要启用", dialog.get("confirm"))
        checker.check("3 次按钮文案：先退出程序", dialog.get("cancel") == "先退出程序", dialog.get("cancel"))
        checker.check(
            "3 宿主快照里的 Dialog 与 DOM 是同一份（Scope=guard-enable）",
            (snapshot(ws).get("Dialog") or {}).get("Scope") == "guard-enable",
            json.dumps((snapshot(ws).get("Dialog") or {}).get("Scope"), ensure_ascii=False),
        )
        screenshot(ws, report_dir / "02-guard-enable-dialog.png", report["shots"])

        # ---------- 场景 4：框还在的时候，什么都不许发 ----------
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            pump.tick()
            time.sleep(0.3)
        snap = snapshot(ws)
        checker.check("4 等 3 秒：Busy 仍是 false", snap.get("Busy") is False, repr(snap.get("Busy")))
        checker.check("4 等 3 秒：Operation 仍是 null", snap.get("Operation") in (None, {}), repr(snap.get("Operation")))
        checker.check("4 等 3 秒：BusyMessage 仍是空串", snap.get("BusyMessage") == "", repr(snap.get("BusyMessage")))
        children_after = len(processes_of("spidervpn.exe"))
        checker.check(
            "4 没有起提权助手（spidervpn.exe 进程数没增加）",
            children_after <= children_before,
            f"{children_before} → {children_after}",
        )
        new_log = ""
        if log_path.exists():
            with log_path.open("rb") as handle:
                handle.seek(log_mark)
                new_log = handle.read().decode("utf-8", "replace")
        report["hostLogAfterEnable"] = new_log[-2000:]
        checker.check(
            "4 host.log 没有新增 guard-install / 提权相关行",
            not any(k in new_log for k in ("guard-install", "guard-apply", "提权", "elevate")),
            new_log[-400:] or "（无新增输出）",
        )
        checker.check(
            "4 对话框仍在（上面这些不是在框消失后测的）",
            bool(dialog_of(ws)),
            ws.evaluate(DIALOG),
        )

        # ---------- 场景 5：点「先退出程序」 ----------
        checker.check("5 点「先退出程序」", click(ws, '#dialog-root [data-action="cancelDialog"]'))
        gone = wait_js(
            ws,
            "(()=>{const r=document.querySelector('#dialog-root');return !r||r.hidden;})()",
            12,
            "确认框收起",
            pump,
        )
        checker.check("5 确认框消失", gone, bool(dialog_of(ws)))
        snap = wait_snapshot(ws, lambda s: s.get("Dialog") in (None, {}), 15, "快照里的 Dialog 清空", pump)
        checker.check("5 快照里的 Dialog 也清空", snap, json.dumps(snapshot(ws).get("Dialog"), ensure_ascii=False))
        snap = snapshot(ws)
        checker.check("5 取消后 Busy 仍是 false", snap.get("Busy") is False, repr(snap.get("Busy")))
        checker.check("5 取消后 Operation 仍是 null", snap.get("Operation") in (None, {}), repr(snap.get("Operation")))
        checker.check(
            "5 取消没有起提权助手",
            len(processes_of("spidervpn.exe")) <= children_before,
            str(len(processes_of("spidervpn.exe"))),
        )
        new_log = ""
        if log_path.exists():
            with log_path.open("rb") as handle:
                handle.seek(log_mark)
                new_log = handle.read().decode("utf-8", "replace")
        checker.check(
            "5 取消后 host.log 仍没有 guard-install / 提权相关行",
            not any(k in new_log for k in ("guard-install", "guard-apply", "提权", "elevate")),
            new_log[-400:] or "（无新增输出）",
        )
        checker.check(
            "5 取消没有写证据（隔离根里没有 guard 证据文件）",
            not (root / "data" / "guard").exists(),
            str(root / "data" / "guard"),
        )
        screenshot(ws, report_dir / "03-after-cancel.png", report["shots"])

        # ---------- 场景 7：命令行侧（真跑 exe，默认必须拒绝） ----------
        # 前置：闸门只在「名单程序在跑」时才拦，所以先确认它真的在跑。
        still_running = precheck(name).get("RunningPrograms") or []
        cli_probe_ok = bool(still_running)
        if args.mode == "old":
            report["notes"].append(
                "旧版没有闸门：命令行 --guard-install 会直达提权，按纪律**未执行**（会弹 UAC）。"
            )
            print("[probe] 旧版模式：跳过命令行探针（会真的提权）", flush=True)
        elif not cli_probe_ok:
            report["notes"].append("命令行探针未执行：预检没有报出在跑的程序，闸门不会拦，跑下去会真的提权。")
        else:
            consent_before = len(processes_of("consent.exe"))
            cli_env = dict(os.environ)
            # 命令行探针必须用**另一个**隔离根：单实例/管道是按数据根哈希的，
            # 拿正在跑界面的那个根去跑 CLI 会直接得到「已经有一个在运行了」，
            # 那样验的就不是闸门了。
            cli_env["SPIDERVPN_ROOT"] = str(root_cli)
            started = time.monotonic()
            timed_out = False
            stdout = ""
            code = None
            try:
                done = subprocess.run(
                    [str(exe), "--guard-install"],
                    cwd=str(exe.parent), env=cli_env,
                    capture_output=True, timeout=5,
                )
                stdout = (done.stdout or b"").decode("utf-8", "replace") + (
                    done.stderr or b""
                ).decode("utf-8", "replace")
                code = done.returncode
            except subprocess.TimeoutExpired as expired:
                timed_out = True
                stdout = (expired.stdout or b"").decode("utf-8", "replace") if expired.stdout else ""
            elapsed = time.monotonic() - started
            report["cli"] = {"returncode": code, "elapsedSeconds": round(elapsed, 2), "output": stdout[-3000:]}
            checker.check(
                "7a --guard-install 在 5 秒内自己结束（没有卡在 UAC）",
                not timed_out,
                f"耗时 {elapsed:.2f}s，退出码 {code}",
            )
            checker.check("7b 退出码非 0（拒绝不是成功）", code not in (None, 0), str(code))
            checker.check(
                "7c 输出含「请先退出交易软件」",
                "请先退出交易软件" in stdout,
                stdout[-600:],
            )
            checker.check(
                "7d 输出里报出了正在运行的程序名",
                "ping.exe" in stdout.lower(),
                stdout[-600:],
            )
            checker.check(
                "7e 输出含「已建立的连接不会被切断，只有新连接会被阻止。」",
                "已建立的连接不会被切断" in stdout and "只有新连接会被阻止" in stdout,
                stdout[-600:],
            )
            checker.check(
                "7f 输出里没有「提权助手」（拒绝早于提权）",
                "提权助手" not in stdout,
                stdout[-600:],
            )
            checker.check(
                "7g 没有新的 consent.exe（没有弹 UAC）",
                len(processes_of("consent.exe")) <= consent_before,
                f"{consent_before} → {len(processes_of('consent.exe'))}",
            )
            checker.check(
                "7h 命令行也提示了 --acknowledge-running",
                "--acknowledge-running" in stdout,
                stdout[-600:],
            )
            checker.check(
                "7i 被拒的那次没有写证据（隔离根里没有 guard 证据目录）",
                not (root_cli / "data" / "guard").exists(),
                str(root_cli / "data" / "guard"),
            )

        # ---------- 场景 6：撤回 —— 关掉程序后必须回到空 ----------
        if ping is not None:
            ping.kill()
            ping.wait(timeout=10)
            ping = None
        time.sleep(1.5)
        cleared = precheck(name).get("RunningPrograms")
        checker.check(
            "6 关掉程序后 RunningPrograms 回到空数组（第 2 条不是恒真）",
            cleared == [],
            json.dumps(cleared, ensure_ascii=False),
        )

        # ---------- 场景 8：收尾（不碰用户现场） ----------
        checker.check(
            "8 用户配置没被改过（config.json md5 一致）",
            md5_of(USER_CONFIG) == user_config_md5,
            md5_of(USER_CONFIG),
        )
        checker.check("8 用户数据根没有新增 runtime.json", not RUNTIME.is_file(), str(RUNTIME))
        checker.check("8 隔离根也没有 runtime.json", not (root / "data" / "runtime.json").is_file())
        checker.check(
            "8 收尾时没有残留的 PING 进程",
            len(processes_of("PING.EXE")) == 0,
            str(processes_of("PING.EXE")),
        )

        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        # 主机日志另存一份可读的，便于人工核对「没有新命令」。
        if log_path.exists():
            (report_dir / "host.log.txt").write_bytes(log_path.read_bytes())
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        return 0 if checker.all_passed else 1
    finally:
        if ping is not None:
            try:
                ping.kill()
                ping.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        log.close()
        # 万一留下子进程（提权助手），一并按镜像名清掉本脚本可能起的那些。
        leftovers = processes_of("PING.EXE")
        if leftovers:
            subprocess.run(["taskkill", "/F", "/IM", "PING.EXE"], capture_output=True, timeout=20)
            print(f"[probe] 清掉了残留 PING：{leftovers}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
