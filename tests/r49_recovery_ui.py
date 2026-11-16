#!/usr/bin/env python3
"""r49 界面验收：重启后的启动恢复（T04）。

验的是「进程死过一次之后，页面还说不说『正在部署』」：

1. 先在真实数据根里手写一条**上个进程跑到一半就死了**的记录
   （`State=Running`、`Executor.Pid=999999`、心跳是 10 分钟前、第 3 步 `Running`）；
2. 再起真实宿主（WebView2 + 真实数据根，CDP 驱动）——启动扫描必须在页面出现之前
   把它改判；
3. 断言页面：任务行有原因、打开详情页是「需要处理 / 2/4 步 / 未核实 /
   唯一按钮『重试这一步』」，**任何地方都不出现「正在部署」**；
4. 断言磁盘：`State=NeedsAttention`、原因类别 `Interrupted`、`Revision` 只涨一次；
5. 等 8 秒再看一遍：状态、`Revision`、`Attempts` 都没动 —— **不许自动续跑**
   （这条是「永不自动入队」的真机版本：真跑起来会变 Queued/Running 且 Revision 一直涨）；
6. `operations.jsonl` 里有且只有一条「部署恢复」，带 RunId 短码。

不碰任何真实服务器：整条链路只读记录、只改记录。
"""
from __future__ import annotations

import argparse
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
click = helpers.click
free_port = helpers.free_port
screenshot = helpers.screenshot
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js

DATA_ROOT = Path(r"C:\SpiderVPN\data")
RUNS_DIR = DATA_ROOT / "deployments" / "runs"
EVENTS = DATA_ROOT / "logs" / "operations.jsonl"

# 固定 UUID：重跑会被前置清理覆盖，不会堆积。
RUN_ID = "7a1d0c33-9b2e-4f61-8c55-0d1e2f3a4b5c"
SHORT = RUN_ID[:8]


def pipe_name() -> str:
    import glob

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


def stamp(minutes_ago: int) -> str:
    moment = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def dead_record() -> dict:
    """一条「跑到第三步、进程没了」的记录。

    字段形状与 `fixtures/deployment-runs/running.json` 一致（那是磁盘契约），
    只把执行者换成一个必然不存在的 pid、心跳推到 10 分钟前。
    """
    names = [
        "检查服务器环境与身份",
        "准备标准连接",
        "准备兼容连接",
        "接入本机并登记线路",
    ]
    steps = []
    for index, name in enumerate(names):
        if index < 2:
            status, started, finished = "Done", stamp(30), stamp(29)
        elif index == 2:
            status, started, finished = "Running", stamp(28), None
        else:
            status, started, finished = "Pending", None, None
        steps.append(
            {
                "Index": index,
                "Name": name,
                "Status": status,
                "StartedAtUtc": started,
                "FinishedAtUtc": finished,
                "Evidence": {} if status != "Done" else {"arch": "x86_64"},
                "Error": None,
            }
        )
    return {
        "SchemaVersion": 1,
        "Kind": "SpiderVPN.DeploymentRun",
        "RunId": RUN_ID,
        "AttemptNo": 1,
        "Label": "自建 · 203.0.113.10",
        "Target": {
            "Host": "203.0.113.10",
            "Port": 22,
            "User": "root",
            "ServerRecordId": None,
        },
        "Identity": {"Fingerprint": "SHA256:AAAA", "AutoTrusted": False},
        "Plan": {
            "Interface": "tc1a2b3c4d",
            "UdpPort": 51820,
            "Subnet": "10.66.0.0/24",
            "Mtu": 1420,
            "ClientPublicKey": "CLIENT-PUBLIC-KEY",
        },
        "PlanDigest": "sha256:9f1c",
        "State": "Running",
        "Step": 2,
        "Reason": None,
        "NextAction": "None",
        "Steps": steps,
        "PendingOperation": None,
        "Attempts": [],
        "Executor": {
            "InstanceId": "8f14e45f-ceea-4f7a-9a5f-2b3c4d5e6f70",
            "Pid": 999999,
            "HeartbeatAtUtc": stamp(10),
            "Background": False,
        },
        "CreatedAtUtc": stamp(31),
        "StartedAtUtc": stamp(30),
        "UpdatedAtUtc": stamp(10),
        "FinishedAtUtc": None,
        "Revision": 7,
    }


def read_record() -> dict:
    return json.loads((RUNS_DIR / f"{RUN_ID}.json").read_text(encoding="utf-8-sig"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    # 前置：单实例锁。上一个宿主还活着，我们起来的这个会直接退出（退出码 4），
    # CDP 永远等不到——与其等 90 秒，不如立刻说清楚。
    try:
        pipe_name()
    except Exception:  # noqa: BLE001
        pass
    else:
        raise SystemExit("已经有一个 SpiderVPN 在运行，请先关掉它再跑这条验收。")

    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    # 只清自己那条，别人的记录一概不碰。
    for leftover in RUNS_DIR.glob(f"{RUN_ID}.json"):
        leftover.unlink()
    before_files = sorted(item.name for item in RUNS_DIR.iterdir())
    (RUNS_DIR / f"{RUN_ID}.json").write_text(
        json.dumps(dead_record(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[probe] 已手写死记录 {RUN_ID}（State=Running，心跳 10 分钟前）", flush=True)

    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    env.pop("SPIDERVPN_ROOT", None)
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
    try:
        target = wait_cdp(port, helpers.CDP_READY_SECONDS)
        ws = WebSocket(target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(process.pid)
        text_now = lambda: ws.evaluate("document.body.innerText") or ""

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

        # ---- 磁盘：启动扫描已经改判 ----
        # 页面起来时恢复早就跑完了（它在 UI 之前）。这里读的是落盘事实。
        disk = read_record()
        checker.check(
            "磁盘：状态改成 NeedsAttention",
            disk.get("State") == "NeedsAttention",
            disk.get("State", ""),
        )
        reason = disk.get("Reason") or {}
        checker.check(
            "磁盘：原因类别是 Interrupted",
            reason.get("Category") == "Interrupted",
            json.dumps(reason, ensure_ascii=False)[:160],
        )
        checker.check(
            "磁盘：原因是一句人话",
            "上次没有跑完" in (reason.get("Text") or ""),
            reason.get("Text", ""),
        )
        checker.check(
            "磁盘：下一步是重试本步骤",
            disk.get("NextAction") == "RetryStep",
            disk.get("NextAction", ""),
        )
        checker.check(
            "磁盘：Revision 只涨了一次（7 → 8）",
            disk.get("Revision") == 8,
            str(disk.get("Revision")),
        )
        checker.check(
            "磁盘：没新增任何任务记录",
            sorted(item.name for item in RUNS_DIR.iterdir()) == sorted(
                before_files + [f"{RUN_ID}.json"]
            ),
            str(sorted(item.name for item in RUNS_DIR.iterdir())[:6]),
        )
        checker.check(
            "磁盘：执行者作为证据留着",
            (disk.get("Executor") or {}).get("Pid") == 999999,
            json.dumps(disk.get("Executor") or {}, ensure_ascii=False)[:120],
        )

        # ---- 页面：任务行 ----
        checker.check("导航到线路页", click(ws, "[data-page=lines]"))
        row_selector = f'[data-action=resume][data-id="{RUN_ID}"]'
        checker.check(
            "任务行出现（同一条记录，不是新任务）",
            wait_js(ws, f"!!document.querySelector('{row_selector}')", 25, "任务行出现", pump),
            text_now()[:200],
        )
        checker.check(
            "任务行文案追上改判（按钮变「重试本步骤」）",
            wait_js(
                ws,
                "(()=>{const b=document.querySelector('%s');"
                "return !!b&&b.textContent.includes('重试本步骤');})()" % row_selector,
                30,
                "任务行追上 NeedsAttention",
                pump,
            ),
            text_now()[:200],
        )
        row_text = ws.evaluate(
            "(()=>{const b=document.querySelector('%s');"
            "return b?b.closest('.task-row').innerText:'';})()" % row_selector
        ) or ""
        print(f"[probe] row={row_text!r}", flush=True)
        checker.check("任务行：目标 host:port", "203.0.113.10:22" in row_text, row_text[:160])
        checker.check("任务行：进度 2/4", "2/4" in row_text, row_text[:160])
        checker.check("任务行：带原因", "上次没有跑完" in row_text, row_text[:200])
        checker.check(
            "任务行：没有任何「正在部署」",
            "正在部署" not in row_text and "进行中" not in row_text,
            row_text[:200],
        )
        screenshot(ws, report_dir / "01-list.png", report["shots"])

        # ---- 页面：详情页 ----
        checker.check("点任务行打开详情", click(ws, row_selector))
        checker.check(
            "详情页：状态需要处理",
            wait_js(
                ws,
                "(()=>{const t=document.body.innerText||'';return t.includes('状态：需要处理');})()",
                25,
                "详情页出现",
                pump,
            ),
            text_now()[:240],
        )
        detail = text_now()
        print(f"[probe] detail={detail[:400]!r}", flush=True)
        checker.check("详情页：2/4 步", "2/4 步" in detail, detail[:240])
        checker.check(
            "详情页：被打断的那一步标「未核实」",
            "准备兼容连接 · 未核实" in detail,
            detail[:400],
        )
        checker.check(
            "详情页：原因那一行在",
            "上次没有跑完" in detail,
            detail[:400],
        )
        checker.check(
            "详情页：唯一主动作是「重试这一步」",
            "重试这一步" in detail and "核对原操作" not in detail,
            detail[:400],
        )
        checker.check(
            "详情页：没有「正在部署」",
            "正在部署" not in detail and "（正在跑）" not in detail,
            detail[:400],
        )
        checker.check(
            "详情页：取消入口还在（不是终态）",
            "取消这次部署" in detail,
            detail[:400],
        )
        screenshot(ws, report_dir / "02-detail.png", report["shots"])

        # ---- 不许自动续跑：等 8 秒再读一遍 ----
        name = pipe_name()
        first = ask(name, {"cmd": "deployment-get", "runId": RUN_ID}).get("deployment", {}).get("Run", {})
        time.sleep(8)
        second = ask(name, {"cmd": "deployment-get", "runId": RUN_ID}).get("deployment", {}).get("Run", {})
        checker.check(
            "8 秒内状态没被推进（不自动续跑）",
            second.get("State") == "NeedsAttention",
            str(second.get("State")),
        )
        checker.check(
            "8 秒内 Revision 没再涨（没有任何后台动作）",
            second.get("Revision") == first.get("Revision") == 8,
            f"{first.get('Revision')} → {second.get('Revision')}",
        )
        checker.check(
            "8 秒内没有新增尝试（不重放写命令）",
            second.get("Attempts") == first.get("Attempts"),
            json.dumps(second.get("Attempts"), ensure_ascii=False)[:120],
        )
        checker.check(
            "8 秒内页面仍是「需要处理」",
            "状态：需要处理" in text_now(),
            text_now()[:200],
        )

        # ---- 操作记录 ----
        log_text = EVENTS.read_text(encoding="utf-8", errors="replace") if EVENTS.is_file() else ""
        lines = [
            line
            for line in log_text.splitlines()
            if '"部署恢复"' in line and SHORT in line
        ]
        checker.check(
            "operations.jsonl 留了一条「部署恢复」",
            len(lines) >= 1,
            (lines[-1] if lines else log_text[-200:]),
        )
        if lines:
            event = json.loads(lines[-1])
            checker.check(
                "操作记录：ok=true 且不带服务器地址",
                event.get("ok") is True and "203.0.113.10" not in json.dumps(event, ensure_ascii=False),
                json.dumps(event, ensure_ascii=False)[:240],
            )

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
        if not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
            time.sleep(1)
        log.close()
        # 收尾：删掉自己那条记录，其余一概不动。
        target_file = RUNS_DIR / f"{RUN_ID}.json"
        if target_file.is_file():
            target_file.unlink()
            print(f"[probe] 已删除冒烟记录 {target_file.name}", flush=True)
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        print(f"[probe] runs is dir: {RUNS_DIR.is_dir()}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
