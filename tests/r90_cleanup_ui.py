#!/usr/bin/env python3
"""r90 界面验收：服务器「删除本机部署资料…」（旧版的 ServerCleanup）。

改动前：「删除记录」只删 `serverstore` 那条记录本身，这台服务器在本机的
部署任务记录、结果提醒、任务级登录资料全都留在磁盘上——删了记录却留着密码信封。

本脚本全部点真实界面（CDP 驱动装好的 exe），并且**以磁盘为最终判据**：
确认框里说要删的，磁盘上必须真的没了；框里没提的（别的服务器的记录、
以地址手动创建的同主机记录），必须一个都不许少。

覆盖：
1. 服务器一览里有「删除本机部署资料…」，点开先出预览（不发写命令）；
2. 框里逐项列出：部署任务记录 2 条（含已归档 1 条）/ 结果提醒 2 条 / 任务级资料 1 份 / 长期保存的登录资料；
3. 确认后：runs 里属于它的 2 条消失、提醒只剩别人的 1 条、`.bin` 消失、服务器记录消失；
4. 同主机但 `ServerRecordId` 为空的记录**留着**（不是它的资料，不能一起烧）；
5. 有线路在用 → 拒绝，框里说明原因且没有「删除本机资料」按钮；
6. 有进行中的部署 → 同样拒绝；
7. 收尾：现场（真实数据根）的 config.json 一个字节没动。

用法：
  python tests/r90_cleanup_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r90-cleanup \\
      --work D:\\vpn构建\\reports-tmp\\r90-work [--allow-running]
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker
USER_CONFIG = r54.USER_CONFIG
md5_of = r54.md5_of

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "fixtures" / "deployment-runs"

SERVER_ID = "0f8fad5b-d9cb-469f-a165-70867728950e"
HOST = "203.0.113.10"
RUN_A = "11111111-1111-4111-8111-111111111111"
RUN_B = "22222222-2222-4222-8222-222222222222"
RUN_ORPHAN = "33333333-3333-4333-8333-333333333333"
RUN_OTHER = "44444444-4444-4444-8444-444444444444"

SETTINGS_SERVERS = '[data-action="servers"]'
CLEANUP = f'[data-wf="server-cleanup:{SERVER_ID}"]'
CONFIRM = "#dialog-root [data-action=confirmDialog]"


def body_text(ws) -> str:
    return t11.body_text(ws)


def click(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


def click_when_enabled(ws, pump, selector: str, seconds: float = 25.0) -> str:
    ok = helpers.wait_js(
        ws,
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return !!e&&!e.disabled;})()",
        seconds,
        f"{selector} 可点",
        pump,
    )
    if not ok:
        return "not-ready"
    return click(ws, selector)


def settle(ws, pump, seconds: float = 1.4) -> None:
    """等页面追上宿主的新代数（`restructure()` 之后 `change` 会被闸门挡掉）。"""
    import time

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pump.tick()
        time.sleep(0.2)


def wait_page(ws, pump, must=(), must_not=(), seconds: float = 12.0) -> bool:
    cond = "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
    for item in must:
        cond += f"if(!t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    for item in must_not:
        cond += f"if(t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    cond += "return true;})()"
    return helpers.wait_js(ws, cond, seconds, "页面文案", pump)


def wait_dialog(ws, pump, must=(), seconds: float = 15.0) -> bool:
    cond = "(()=>{const t=(document.querySelector('#dialog-root')||{}).innerText||'';"
    for item in must:
        cond += f"if(!t.includes({json.dumps(item, ensure_ascii=False)}))return false;"
    cond += "return t.length>0;})()"
    return helpers.wait_js(ws, cond, seconds, "确认框", pump)


def run_doc(fixture: str, run_id: str, *, server_id: str | None, archived: bool = False, state=None):
    """拿一份真实形状的夹具，改成我们要的那条记录。"""
    value = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))
    value["RunId"] = run_id
    value["Target"]["Host"] = HOST
    value["Target"]["Port"] = 22
    value["Target"]["User"] = "root"
    value["Target"]["ServerRecordId"] = server_id
    if state:
        value["State"] = state
        value["FinishedAtUtc"] = None
    if archived:
        value["ArchivedAtUtc"] = "2026-11-12T00:00:00Z"
    return value


def seed(work: Path, *, blocking_line: bool = False) -> None:
    data = work / "data"
    data.mkdir(parents=True, exist_ok=True)
    cfg = {"schema": 2, "selected": "hk",
           "lines": [{"id": "hk", "name": "香港 01", "proxy_endpoint": "127.0.0.1:17901"}]}
    (data / "config.json").write_text(
        json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    # 服务器记录（形状照 r59 的夹具）
    record_dir = data / "servers" / SERVER_ID
    record_dir.mkdir(parents=True, exist_ok=True)
    (record_dir / "record.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.ServerRecord",
                "Id": SERVER_ID,
                "Name": f"root@{HOST}",
                "Host": HOST,
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
    # 长期保存的登录资料（形状不重要：预览只判文件在不在）
    (record_dir / "credential.dpapi.json").write_text('{"Schema":1}', encoding="utf-8")
    if blocking_line:
        # 线路引擎配置里出现这台 server → 「还有 N 条线路用到这台服务器」
        (data / "lines").mkdir(exist_ok=True)
        (data / "lines" / "hk.json").write_text(
            json.dumps({"outbounds": [{"type": "wireguard", "server": HOST}]}, ensure_ascii=False),
            encoding="utf-8",
        )
    runs = data / "deployments" / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    (runs / f"{RUN_A}.json").write_text(
        json.dumps(run_doc("attention-retry.json", RUN_A, server_id=SERVER_ID),
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (runs / f"{RUN_B}.json").write_text(
        json.dumps(run_doc("complete.json", RUN_B, server_id=SERVER_ID, archived=True),
                   ensure_ascii=False, indent=2), encoding="utf-8")
    (runs / f"{RUN_ORPHAN}.json").write_text(
        json.dumps(run_doc("complete.json", RUN_ORPHAN, server_id=None),
                   ensure_ascii=False, indent=2), encoding="utf-8")
    # 提醒：两条属于它，一条属于别人
    reminders = [
        {"Id": "r1", "RunId": RUN_A, "Name": f"自建 · {HOST}", "State": "NeedsAttention",
         "Step": 0, "Category": "AccessRequired", "Code": "AccessRequired",
         "Text": "登录凭据不可用", "CreatedAtUtc": "2026-11-12T01:00:00Z", "ReadAtUtc": None},
        {"Id": "r2", "RunId": RUN_B, "Name": f"自建 · {HOST}", "State": "Complete",
         "Step": 4, "Category": "", "Code": "",
         "Text": "部署完成", "CreatedAtUtc": "2026-11-12T02:00:00Z", "ReadAtUtc": None},
        {"Id": "r3", "RunId": RUN_OTHER, "Name": "自建 · 198.51.100.7", "State": "Complete",
         "Step": 4, "Category": "", "Code": "",
         "Text": "别人的结果", "CreatedAtUtc": "2026-11-12T03:00:00Z", "ReadAtUtc": None},
    ]
    (data / "deployments").mkdir(parents=True, exist_ok=True)
    (data / "deployments" / "reminders.json").write_text(
        json.dumps({"Schema": 1, "Kind": "TradeChannel.DeployReminders", "Reminders": reminders},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    cred = data / "deployments" / "credentials"
    cred.mkdir(parents=True, exist_ok=True)
    (cred / f"{RUN_A}.bin").write_bytes(b"not-a-real-envelope")


def runs_on_disk(work: Path) -> list[str]:
    runs = work / "data" / "deployments" / "runs"
    if not runs.is_dir():
        return []
    return sorted(p.stem for p in runs.glob("*.json"))


def reminders_on_disk(work: Path) -> list[str]:
    path = work / "data" / "deployments" / "reminders.json"
    if not path.is_file():
        return []
    value = json.loads(path.read_text(encoding="utf-8"))
    return [item.get("RunId") for item in value.get("Reminders") or []]


def stop(process) -> None:
    """关掉上一条实例：单实例互斥是全局的，上一条没退干净，下一条根本起不来（CDP 等不到）。"""
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except Exception:  # noqa: BLE001
        process.kill()
    import time

    time.sleep(0.8)


def open_servers(ws, pump) -> bool:
    if click_when_enabled(ws, pump, "nav [data-page=settings]") != "ok":
        return False
    if click_when_enabled(ws, pump, SETTINGS_SERVERS) != "ok":
        return False
    return helpers.wait_js(
        ws, f"!!document.querySelector('{CLEANUP}')", 20, "服务器一览的删除本机资料", pump
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    parser.add_argument("--allow-running", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    if args.allow_running:
        print("[warn] --allow-running：不检查已有实例（独立数据根，互不干扰）", flush=True)
    else:
        t11.no_running_host()

    checker = Checker()
    report = {"mode": "server-cleanup", "exe": str(exe), "work": str(work), "checks": []}
    user_config_before = md5_of(USER_CONFIG)
    code = 0
    process = None
    ws = None
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "cleanup")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            body_text(ws)[-200:],
        )

        checker.check("进「设置 → 服务器」并看到这台记录", open_servers(ws, pump),
                      body_text(ws)[-300:])
        settle(ws, pump, 1.2)

        # 1) 点「删除本机部署资料…」→ 先出预览
        checker.check("点「删除本机部署资料…」", click_when_enabled(ws, pump, CLEANUP) == "ok", "")
        checker.check(
            "先出确认框（标题说清是删本机资料）",
            wait_dialog(ws, pump, must=("删除这台服务器在本机的部署资料",)),
            body_text(ws)[-300:],
        )
        checker.check(
            "框里逐项列出：2 条任务（含归档 1）、2 条提醒、1 份任务级资料、长期资料",
            wait_dialog(
                ws,
                pump,
                must=("部署任务记录 2 条", "已归档 1 条", "结果提醒 2 条", "任务级登录资料 1 份", "长期保存的登录资料"),
            ),
            str(ws.evaluate("(document.querySelector('#dialog-root')||{}).innerText||''"))[:400],
        )
        checker.check(
            "框里说清不影响服务器上的东西",
            wait_dialog(ws, pump, must=("服务器上的通道服务",)),
            "",
        )
        # 预览不许写盘
        checker.check(
            "只看一眼：磁盘上 3 条记录、3 条提醒、1 份凭据一个没少",
            runs_on_disk(work) == sorted([RUN_A, RUN_B, RUN_ORPHAN])
            and len(reminders_on_disk(work)) == 3
            and (work / "data" / "deployments" / "credentials" / f"{RUN_A}.bin").is_file(),
            f"runs={runs_on_disk(work)}",
        )

        # 2) 确认 → 真的删
        checker.check("点「删除本机资料」", click_when_enabled(ws, pump, CONFIRM) == "ok", "")
        checker.check(
            "列表里那条记录没了",
            wait_page(ws, pump, must_not=(f"root@{HOST}",), seconds=15),
            body_text(ws)[-300:],
        )
        checker.check(
            "属于它的 2 条任务记录删了，同主机但没挂记录的孤儿记录留着",
            runs_on_disk(work) == [RUN_ORPHAN],
            f"runs={runs_on_disk(work)}",
        )
        checker.check(
            "提醒只剩不属于它的那一条",
            reminders_on_disk(work) == [RUN_OTHER],
            f"reminders={reminders_on_disk(work)}",
        )
        checker.check(
            "任务级登录资料跟着删了",
            not (work / "data" / "deployments" / "credentials" / f"{RUN_A}.bin").exists(),
            "凭据文件还在",
        )
        checker.check(
            "服务器记录目录整个消失",
            not (work / "data" / "servers" / SERVER_ID).exists(),
            "记录目录还在",
        )

        # 3) 有线路在用 → 拒绝（换一个数据根重来）
        stop(process)
        shutil.rmtree(work, ignore_errors=True)
        seed(work, blocking_line=True)
        process2, _port2, ws2 = t11.launch(exe, work, report_dir, "cleanup-blocked")
        pump2 = t11.Pump(process2.pid)
        try:
            helpers.wait_js(
                ws2, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump2
            )
            checker.check("（阻断）进服务器页", open_servers(ws2, pump2), body_text(ws2)[-200:])
            settle(ws2, pump2, 1.2)
            checker.check("（阻断）点「删除本机部署资料…」",
                          click_when_enabled(ws2, pump2, CLEANUP) == "ok", "")
            checker.check(
                "（阻断）框里说清还有线路在用",
                wait_dialog(ws2, pump2, must=("还有 1 条线路用到这台服务器",)),
                str(ws2.evaluate("(document.querySelector('#dialog-root')||{}).innerText||''"))[:300],
            )
            checker.check(
                "（阻断）没有「删除本机资料」这个按钮（只有「知道了」）",
                str(
                    ws2.evaluate(
                        "(()=>{const b=document.querySelector('#dialog-root [data-action=confirmDialog]');"
                        "return b?b.textContent.trim():'none';})()"
                    )
                    or ""
                )
                != "删除本机资料",
                str(
                    ws2.evaluate(
                        "(()=>{const b=document.querySelector('#dialog-root [data-action=confirmDialog]');"
                        "return b?b.textContent.trim():'none';})()"
                    )
                ),
            )
            checker.check(
                "（阻断）一个文件都没删",
                runs_on_disk(work) == sorted([RUN_A, RUN_B, RUN_ORPHAN])
                and (work / "data" / "servers" / SERVER_ID).is_dir(),
                f"runs={runs_on_disk(work)}",
            )
        finally:
            try:
                ws2.close()
            except Exception:
                pass
            if not args.keep_open and process2.poll() is None:
                process2.terminate()

        # 4) 有进行中的部署 → 拒绝（再换一个数据根）
        stop(process2)
        shutil.rmtree(work, ignore_errors=True)
        seed(work)
        # 把 A 改成「正在跑」。**心跳要新鲜**：启动恢复（T04）会把心跳过期的
        # Running 改判成 NeedsAttention——那样测到的是「失败等处理」，不是「还在跑」。
        import datetime

        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        running = run_doc("attention-retry.json", RUN_A, server_id=SERVER_ID, state="Running")
        running["FinishedAtUtc"] = None
        running["UpdatedAtUtc"] = now
        running["Executor"] = {
            "InstanceId": "r90-accept",
            "Pid": 999999,
            "HeartbeatAtUtc": now,
            "Background": False,
        }
        (work / "data" / "deployments" / "runs" / f"{RUN_A}.json").write_text(
            json.dumps(running, ensure_ascii=False, indent=2), encoding="utf-8")
        process3, _port3, ws3 = t11.launch(exe, work, report_dir, "cleanup-active")
        pump3 = t11.Pump(process3.pid)
        try:
            helpers.wait_js(
                ws3, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump3
            )
            checker.check("（进行中）进服务器页", open_servers(ws3, pump3), body_text(ws3)[-200:])
            settle(ws3, pump3, 1.2)
            checker.check("（进行中）点「删除本机部署资料…」",
                          click_when_enabled(ws3, pump3, CLEANUP) == "ok", "")
            checker.check(
                "（进行中）框里说清还有部署没结束",
                wait_dialog(ws3, pump3, must=("还有 1 个部署没有结束",)),
                str(ws3.evaluate("(document.querySelector('#dialog-root')||{}).innerText||''"))[:300],
            )
        finally:
            try:
                ws3.close()
            except Exception:
                pass
            if not args.keep_open and process3.poll() is None:
                process3.terminate()

        checker.check("真实数据根的 config.json 未被改动", md5_of(USER_CONFIG) == user_config_before)
    except Exception as error:  # noqa: BLE001
        code = 1
        report["error"] = f"{type(error).__name__}: {error}"
        print(f"脚本异常：{report['error']}", flush=True)
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass
        if not args.keep_open and process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        print(
            f"残留进程：{'有' if process is not None and process.poll() is None else '无'}",
            flush=True,
        )
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
