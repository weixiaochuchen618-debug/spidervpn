#!/usr/bin/env python3
"""T11 真机三条：完整部署 / 中途关窗转托盘 / 强杀重启核对。

验的是「真实服务器 + 真实 WebView2 + 装好的 exe」上部署中心的三条人工用例：

- `complete`：从界面填地址 → 读指纹 → 输密码 → 开始部署，跑到四步全完成；
- `tray`：部署进行中发 `WM_CLOSE`（等价于点 X），窗口必须藏起来、进程必须还在，
  部署在后台跑到完成，窗口恢复后仍是同一条已完成任务；
- `kill`：部署进行中直接终止宿主（等价于 `Stop-Process`），等心跳过期后重启；
  原任务必须还在、`Running=false`、`State=NeedsAttention`、`NextAction=Reconcile`，
  且 10 秒内没有任何自动续跑（`Revision`/`StepsDone` 不变）。

密码**只从环境变量**读（默认 `TC_SSH_PASSWORD`），不进命令行、不写文件、不进日志。

用法：
  set TC_SSH_PASSWORD=...
  python tests/t11_real_deploy_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \
      --mode complete --report-dir C:\\tc-rs-build\\t11\\complete \
      --work C:\\tc-rs-build\\t11\\complete-root --host 203.0.113.25
"""
from __future__ import annotations

import argparse
import ctypes
import glob
import importlib
import json
import os
import re
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

user32 = ctypes.windll.user32
WM_CLOSE = 0x0010
SW_SHOW = 5
UUID_RE = re.compile(r"[0-9a-f-]{36}")

DEPLOY_SECONDS = 900.0
HEARTBEAT_STALE_SECONDS = 20.0
QUIET_AFTER_RESTART_SECONDS = 10.0


def js(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def set_value(ws: WebSocket, selector: str, value: str) -> bool:
    return bool(
        ws.evaluate(
            f"(()=>{{const e=document.querySelector({js(selector)});"
            f"if(!e)return false;e.value={js(value)};"
            "e.dispatchEvent(new Event('input',{bubbles:true}));return true;})()"
        )
    )


def body_text(ws: WebSocket) -> str:
    return str(ws.evaluate("document.body.innerText") or "")


def pipe_name(seconds: float = 30.0) -> str:
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
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
                if b'"ok": true' in reply or b'"ok":true' in reply:
                    return candidate
            except Exception as error:  # noqa: BLE001
                last = str(error)
        time.sleep(0.3)
    raise RuntimeError(f"找不到能应答的命名管道：{last}")


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


def run_of(name: str, run_id: str) -> dict:
    return ask(name, {"cmd": "deployment-get", "runId": run_id}).get("deployment", {}).get("Run", {})


def latest_run_id(work: Path, seconds: float = 30.0) -> str:
    runs = work / "data" / "deployments" / "runs"
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        files = sorted(
            (item for item in runs.glob("*.json") if UUID_RE.fullmatch(item.stem)),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        for item in files:
            try:
                record = json.loads(item.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                continue
            run_id = record.get("RunId") or item.stem
            if UUID_RE.fullmatch(str(run_id)):
                return str(run_id)
        time.sleep(0.3)
    raise RuntimeError("部署任务已经受理，但找不到它的记录文件")


def main_window(pid: int) -> int:
    handles = helpers.windows_of(pid)
    for handle in handles:
        length = user32.GetWindowTextLengthW(handle)
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(handle, buffer, length + 1)
        if "TradeChannel" in buffer.value:
            return handle
    return handles[0] if handles else 0


def no_running_host() -> None:
    output = subprocess.run(
        ["powershell", "-NoProfile", "-Command", "Get-Process spidervpn -ErrorAction SilentlyContinue"],
        capture_output=True,
        text=True,
        timeout=20,
    ).stdout.strip()
    if output:
        raise SystemExit("已经有一个 spidervpn 在运行，请先退出它（含托盘）。")


def launch(exe: Path, work: Path, report_dir: Path, tag: str) -> tuple[subprocess.Popen, int, object]:
    work.mkdir(parents=True, exist_ok=True)
    port = free_port()
    env = dict(os.environ)
    env.pop("SPIDERVPN_ROOT", None)
    env["SPIDERVPN_ROOT"] = str(work)
    env["SPIDERVPN_PROXY_KEY"] = rf"Software\SpiderVPN\tests\t11-real-{tag}"
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log = (report_dir / f"host-{tag}.log").open("wb")
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] {tag} host pid={process.pid} cdp={port} root={work}", flush=True)
    target = wait_cdp(port, helpers.CDP_READY_SECONDS)
    ws = WebSocket(target["webSocketDebuggerUrl"])
    ws.call("Page.enable")
    try:
        ws.call("Page.bringToFront")
    except Exception:  # noqa: BLE001
        pass
    return process, port, ws


def drive_to_start(
    ws: WebSocket, pump: Pump, work: Path, spec: str, password: str
) -> str:
    if not wait_js(
        ws,
        "document.readyState==='complete'&&!!document.querySelector('#main')",
        30,
        "页面初始化",
        pump,
    ):
        raise RuntimeError("页面没有初始化")
    if not click(ws, "#main [data-action=add]"):
        raise RuntimeError("首页没有「自己搭服务器」入口")
    if not wait_js(
        ws, "!!document.querySelector('#wf-spec')", 15, "部署表单出现", pump
    ):
        raise RuntimeError("部署表单没有出现")
    if not set_value(ws, "#wf-spec", spec):
        raise RuntimeError("填不进服务器地址")
    if not click(ws, "[data-wf=probe]"):
        raise RuntimeError("点不动「读取指纹并继续」")
    if not wait_js(
        ws,
        "(document.querySelector('#main .workflow')||{textContent:''}).textContent.includes('SHA256:')",
        90,
        "读到主机指纹",
        pump,
    ):
        raise RuntimeError(f"没有读到主机指纹：{body_text(ws)[-300:]}")
    if not wait_js(ws, "!!document.querySelector('#wf-password')", 10, "密码框出现", pump):
        raise RuntimeError("读到指纹后没有出现密码框（这台机器上不应该已有凭据）")
    if not set_value(ws, "#wf-password", password):
        raise RuntimeError("填不进登录密码")
    if not click(ws, "[data-wf=start]"):
        raise RuntimeError("点不动「开始部署」")
    if not wait_js(ws, "!!document.querySelector('[data-wf=run-go]')||document.body.innerText.includes('任务编号')", 30, "部署任务详情出现", pump):
        raise RuntimeError(f"部署任务详情没有出现：{body_text(ws)[-300:]}")
    run_id = latest_run_id(work, 30)
    print(f"[probe] runId={run_id}", flush=True)
    return run_id


def wait_state(
    name: str,
    run_id: str,
    want: str,
    seconds: float,
) -> dict:
    deadline = time.monotonic() + seconds
    last: dict = {}
    while time.monotonic() < deadline:
        last = run_of(name, run_id)
        if last.get("State") == want:
            return last
        time.sleep(0.5)
    return last


def wait_predicate(name: str, run_id: str, predicate, seconds: float) -> dict:
    deadline = time.monotonic() + seconds
    last: dict = {}
    while time.monotonic() < deadline:
        last = run_of(name, run_id)
        if predicate(last):
            return last
        time.sleep(0.3)
    return last


def assert_complete(checker: Checker, run: dict, shots: list[str], ws: WebSocket, label: str) -> None:
    checker.check(f"{label}状态是「已完成」", run.get("State") == "Complete", run.get("State"))
    checker.check(f"{label}进度 4/4", int(run.get("StepsDone") or 0) == 4, run.get("StepsDone"))
    checker.check(f"{label}Running=false", run.get("Running") is False, run.get("Running"))
    steps = run.get("Steps") or []
    statuses = [step.get("Status") for step in steps]
    checker.check(
        f"{label}四步全是 Done",
        len(steps) == 4 and all(status == "Done" for status in statuses),
        statuses,
    )
    evidence = steps[3].get("Evidence") if len(steps) > 3 else None
    lines = (evidence or {}).get("lines") if isinstance(evidence, dict) else None
    checker.check(
        f"{label}第 4 步登记了两条线路",
        len(lines or []) >= 2,
        json.dumps(evidence, ensure_ascii=False)[:300],
    )
    checker.check(
        f"{label}页面显示已完成与 4/4",
        "状态：已完成" in body_text(ws) and "4/4" in body_text(ws),
        body_text(ws)[-240:],
    )


def case_complete(exe: Path, work: Path, report_dir: Path, spec: str, password: str, checker: Checker, report: dict) -> str:
    process, _port, ws = launch(exe, work, report_dir, "complete")
    log = None
    try:
        pump = Pump(process.pid)
        run_id = drive_to_start(ws, pump, work, spec, password)
        screenshot(ws, report_dir / "01-started.png", report["shots"])
        name = pipe_name()
        run = wait_state(name, run_id, "Complete", DEPLOY_SECONDS)
        checker.check(
            "完整部署：页面追上记录（状态：已完成 4/4）",
            wait_js(
                ws,
                "(document.body.innerText||'').includes('状态：已完成')"
                "&&(document.body.innerText||'').includes('4/4')",
                20,
                "页面追上记录",
                pump,
            ),
            body_text(ws)[-240:],
        )
        screenshot(ws, report_dir / "02-complete.png", report["shots"])
        assert_complete(checker, run, report["shots"], ws, "完整部署：")
        checker.check(
            "完整部署：磁盘上四步都有记录",
            len(run.get("Steps") or []) == 4,
            len(run.get("Steps") or []),
        )
        report["run"] = run
        report["runId"] = run_id

        # 完成页点「完成」→ 线路页应该出现两条新线路。
        click(ws, "[data-wf=done]")
        click(ws, "[data-page=lines]")
        time.sleep(1.5)
        text = body_text(ws)
        checker.check(
            "完整部署：线路页出现两条自建线路",
            text.count("自建 ·") >= 2,
            text[:300],
        )
        screenshot(ws, report_dir / "03-lines.png", report["shots"])
        return run_id
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def case_tray(exe: Path, work: Path, report_dir: Path, spec: str, password: str, checker: Checker, report: dict) -> str:
    process, _port, ws = launch(exe, work, report_dir, "tray")
    try:
        pump = Pump(process.pid)
        run_id = drive_to_start(ws, pump, work, spec, password)
        screenshot(ws, report_dir / "01-started.png", report["shots"])
        name = pipe_name()
        in_step1 = wait_predicate(
            name,
            run_id,
            lambda run: run.get("State") == "Running"
            and any(step.get("Status") == "Running" for step in (run.get("Steps") or [])),
            DEPLOY_SECONDS,
        )
        checker.check(
            "转托盘：关窗时部署真的在跑",
            in_step1.get("State") == "Running",
            in_step1.get("State"),
        )
        handle = main_window(process.pid)
        checker.check("转托盘：找到主窗口", bool(handle))
        checker.check(
            "转托盘：发送 WM_CLOSE（等价于点关闭按钮）",
            bool(user32.PostMessageW(handle, WM_CLOSE, 0, 0)),
        )
        hidden = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if handle and not user32.IsWindowVisible(handle):
                hidden = True
                break
            time.sleep(0.2)
        checker.check("转托盘：窗口藏起来了（不是退出）", hidden, f"visible={bool(handle) and bool(user32.IsWindowVisible(handle))}")
        checker.check("转托盘：进程还活着", process.poll() is None, f"exit={process.poll()}")
        checker.check("转托盘：网页还活着（CDP 仍可求值）", ws.evaluate("document.readyState") == "complete")
        checker.check(
            "转托盘：页面记着「已缩到托盘继续」",
            wait_js(
                ws,
                "(()=>{const t=document.getElementById('toast');"
                "return !!t&&(t.textContent||'').includes('已缩到托盘继续');})()",
                12,
                "toast 出现",
                pump,
            ),
            str(ws.evaluate("document.getElementById('toast')?.textContent || ''") or ""),
        )
        screenshot(ws, report_dir / "02-hidden.png", report["shots"])

        run = wait_state(name, run_id, "Complete", DEPLOY_SECONDS)
        checker.check(
            "转托盘：藏着期间部署跑完了（没有被关窗掐断）",
            run.get("State") == "Complete",
            run.get("State"),
        )
        report["run"] = run
        report["runId"] = run_id

        if handle:
            user32.ShowWindow(handle, SW_SHOW)
            time.sleep(0.8)
            pump.tick()
        checker.check(
            "转托盘：恢复窗口后还是同一条已完成任务",
            wait_js(
                ws,
                "(document.body.innerText||'').includes('状态：已完成')"
                "&&(document.body.innerText||'').includes('4/4')"
                "&&(document.body.innerText||'').includes('任务编号')",
                20,
                "页面恢复",
                pump,
            ),
            body_text(ws)[-240:],
        )
        screenshot(ws, report_dir / "03-restored.png", report["shots"])
        assert_complete(checker, run, report["shots"], ws, "转托盘：")
        return run_id
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def case_kill(exe: Path, work: Path, report_dir: Path, spec: str, password: str, checker: Checker, report: dict) -> str:
    process, port, ws = launch(exe, work, report_dir, "kill")
    run_id = ""
    try:
        pump = Pump(process.pid)
        run_id = drive_to_start(ws, pump, work, spec, password)
        screenshot(ws, report_dir / "01-started.png", report["shots"])
        name = pipe_name()
        running = wait_predicate(
            name,
            run_id,
            lambda run: run.get("State") == "Running"
            and any(step.get("Status") == "Running" for step in (run.get("Steps") or []))
            and bool(run.get("PendingOperation")),
            DEPLOY_SECONDS,
        )
        checker.check("强杀：动手时部署真的在跑", running.get("State") == "Running", running.get("State"))
        checker.check(
            "强杀：动手时已有一条未决写",
            bool(running.get("PendingOperation")),
            json.dumps(running.get("PendingOperation"), ensure_ascii=False)[:260],
        )
        before = latest_record(work, run_id)
        checker.check("强杀：写前记录里有未决操作", bool(before.get("PendingOperation")), json.dumps(before.get("PendingOperation"), ensure_ascii=False)[:260])
        report["beforeKill"] = before

        process.kill()
        process.wait(timeout=10)
        checker.check("强杀：宿主已被终止", process.poll() is not None, process.poll())
        time.sleep(HEARTBEAT_STALE_SECONDS)

        process2, port2, ws2 = launch(exe, work, report_dir, "kill-restart")
        try:
            pump2 = Pump(process2.pid)
            name2 = pipe_name()
            recovered = wait_predicate(
                name2,
                run_id,
                lambda run: run.get("Running") is False
                and run.get("State") == "NeedsAttention",
                60,
            )
            checker.check(
                "强杀重启：原任务仍在且 Running=false",
                recovered.get("State") == "NeedsAttention" and recovered.get("Running") is False,
                f"state={recovered.get('State')} running={recovered.get('Running')}",
            )
            checker.check(
                "强杀重启：未决写被判为结果未知（NeedsAttention/OutcomeUnknown）",
                (recovered.get("Reason") or {}).get("Category") == "OutcomeUnknown",
                json.dumps(recovered.get("Reason"), ensure_ascii=False)[:260],
            )
            checker.check(
                "强杀重启：下一步只允许核对，不自动重发",
                recovered.get("NextAction") == "Reconcile",
                recovered.get("NextAction"),
            )
            steps = recovered.get("Steps") or []
            checker.check(
                "强杀重启：Step0 已完成、Step1 改成「未核实」",
                len(steps) > 1
                and steps[0].get("Status") == "Done"
                and steps[1].get("Status") == "Unknown",
                [step.get("Status") for step in steps],
            )
            revision = recovered.get("Revision")
            done = recovered.get("StepsDone")
            time.sleep(QUIET_AFTER_RESTART_SECONDS)
            after = run_of(name2, run_id)
            checker.check(
                "强杀重启：10 秒内没有任何自动续跑",
                after.get("Revision") == revision and after.get("StepsDone") == done and after.get("Running") is False,
                f"revision {revision}→{after.get('Revision')} done {done}→{after.get('StepsDone')}",
            )
            report["afterRestart"] = after

            click(ws2, "[data-page=lines]")
            row = f'[data-action=resume][data-id="{run_id}"]'
            checker.check(
                "强杀重启：线路页能看到这条待处理任务",
                wait_js(ws2, f"!!document.querySelector('{row}')", 20, "任务行出现", pump2),
            )
            checker.check("强杀重启：点「继续」打开详情", click(ws2, row))
            checker.check(
                "强杀重启：详情页说「需要处理」并给出核对动作",
                wait_js(
                    ws2,
                    "(document.body.innerText||'').includes('需要处理')"
                    "&&!!document.querySelector('[data-wf=run-go]')",
                    15,
                    "详情页打开",
                    pump2,
                ),
                body_text(ws2)[:300],
            )
            screenshot(ws2, report_dir / "02-after-restart.png", report["shots"])
            report["run"] = after
            report["runId"] = run_id
            return run_id
        finally:
            try:
                ws2.close()
            except Exception:  # noqa: BLE001
                pass
            process2.terminate()
            try:
                process2.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process2.kill()
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001
            pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


def latest_record(work: Path, run_id: str) -> dict:
    path = work / "data" / "deployments" / "runs" / f"{run_id}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--mode", choices=("complete", "tray", "kill"), required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--host", default="203.0.113.25")
    parser.add_argument("--user", default="root")
    parser.add_argument("--password-env", default="TC_SSH_PASSWORD")
    args = parser.parse_args()

    password = os.environ.get(args.password_env, "")
    if not password:
        raise SystemExit(f"没有设置 {args.password_env}：拒绝在不知道密码的情况下启动")
    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    no_running_host()
    if work.exists() and any((work / "data" / "deployments" / "runs").glob("*.json")):
        raise SystemExit(f"数据根里已经有部署记录，拒绝复用：{work}（换一个空目录）")

    spec = f"{args.user}@{args.host}"
    checker = Checker()
    report: dict = {
        "mode": args.mode,
        "exe": str(exe),
        "host": args.host,
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    try:
        if args.mode == "complete":
            case_complete(exe, work, report_dir, spec, password, checker, report)
        elif args.mode == "tray":
            case_tray(exe, work, report_dir, spec, password, checker, report)
        else:
            case_kill(exe, work, report_dir, spec, password, checker, report)
    except Exception as error:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        checker.check(f"用例没有走完：{error}", False)
        code = 1
    finally:
        run_id = report.get("runId", "")
        if run_id and UUID_RE.fullmatch(run_id):
            source = work / "data" / "deployments" / "runs" / f"{run_id}.json"
            if source.is_file():
                (report_dir / f"run-{run_id}.json").write_bytes(source.read_bytes())
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        if report.get("runId"):
            print(f"RUN_ID={report['runId']}", flush=True)
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
