#!/usr/bin/env python3
"""r69 界面验收：部署草稿的自动保存 / 继续填写 / 放弃（P1-2）。

验的是「真实 WebView2 + 装好的 exe」上的草稿链路，**不需要真服务器**：
用 `root@127.0.0.1:1`（端口 1 必然立刻被拒）造一次快速失败的读指纹，
失败之前那次点击会先把地址落成一份草稿。之后：

1. 线路页「未完成的添加」出现一张「未开始 / 继续填写」的卡，底部队列里没有它；
2. 杀掉宿主、同一个数据根重启 → 卡还在；
3. 点「继续填写」→ 进的是**向导**（不是详情页）：地址已预填、提示「已恢复上次
   没填完的地址」、没有任何密码被取回、多一颗「放弃这次填写」；
4. 点「放弃这次填写」→ 页面关闭 + toast「已放弃这份草稿，没有留下任务记录。」+
   卡消失 + 磁盘少一条记录；
5. 收尾对账：data 目录与 `config.json` 一个字节没动（前后 md5 比对），没有残留进程。

所有断言都抓**页面可见信号**（按钮文案 / 输入框 value / 卡片文本 / toast），
不用命名管道里的状态冒充页面状态；磁盘只在「记录应该/不应该存在」这类事实上用。
窗口置前 + 等待期间发 `WM_MOUSEMOVE`（照 r35/t11 的既有做法）。

用法：

  python tests/r69_draft_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r69-deploy-draft\\acceptance \\
      --work C:\\tc-rs-build\\r69\\root
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker

# 端口 1 上不会有人监听：TCP 立刻回 RST，读指纹必然快速失败，不必依赖任何真服务器。
SPEC = "root@127.0.0.1:1"
DISCARD_TOAST = "已放弃这份草稿，没有留下任务记录。"
RESTORE_NOTICE = "已恢复上次没填完的地址"
LOADING_TEXT = "正在读取主机指纹"
# 收尾对账要跳过的路径：记录目录本来就会变（这一轮建了一条又删掉），日志每秒都在变。
# `data/WebView2` 是 WebView2 自己的运行时缓存：每次启动都会新增/改一堆
# `EBWebView` 文件（History、Code Cache、Crashpad…），与产品有没有写用户数据无关。
# 不排掉它，「data 一个字节没动」这条永远红——那是脚本口径错，不是产品缺陷。
SNAPSHOT_SKIP = ("data/deployments/runs", "data/logs", "logs", "data/WebView2")


def js(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def body_text(ws) -> str:
    return t11.body_text(ws)


def runs_dir(work: Path) -> Path:
    return work / "data" / "deployments" / "runs"


def record_files(work: Path) -> list[str]:
    runs = runs_dir(work)
    if not runs.is_dir():
        return []
    return sorted(item.name for item in runs.glob("*.json") if item.is_file())


def read_record(work: Path, run_id: str) -> dict:
    path = runs_dir(work) / f"{run_id}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}


def wait_record(work: Path, seconds: float = 40.0) -> str:
    """等草稿落盘，返回它的文件名（去掉 .json）。"""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        files = record_files(work)
        if files:
            return files[0][: -len(".json")]
        time.sleep(0.2)
    raise RuntimeError(f"点了「读取指纹并继续」之后磁盘上没有出现草稿：{runs_dir(work)}")


def snapshot(work: Path) -> dict[str, str]:
    """`data\\` 与 `config.json` 的 md5 快照（记录目录与日志除外）。"""
    out: dict[str, str] = {}
    if not work.is_dir():
        return out
    for item in sorted(work.rglob("*")):
        if not item.is_file():
            continue
        relative = item.relative_to(work).as_posix()
        if any(relative == skip or relative.startswith(skip + "/") for skip in SNAPSHOT_SKIP):
            continue
        if relative.endswith(".log"):
            continue
        try:
            out[relative] = hashlib.md5(item.read_bytes()).hexdigest()
        except Exception:  # noqa: BLE001
            out[relative] = "unreadable"
    return out


def diff_snapshot(before: dict[str, str], after: dict[str, str]) -> dict:
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "changed": sorted(key for key in set(before) & set(after) if before[key] != after[key]),
    }


def wait_gone(path: Path, seconds: float = 20.0) -> bool:
    """等一个文件从磁盘上消失（放弃草稿 = 删文件，不是写 Cancelled）。"""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not path.exists():
            return True
        time.sleep(0.2)
    return False


def wait_home(ws, pump, seconds: float = 40.0) -> bool:    return helpers.wait_js(
        ws,
        "document.readyState==='complete'"
        "&&!!document.querySelector('#main')"
        "&&!!document.querySelector('#main [data-action=add]:not([disabled])')",
        seconds,
        "首页可点",
        pump,
    )


def goto_lines(ws, pump, seconds: float = 20.0) -> bool:
    if not helpers.click(ws, "nav [data-page=lines]"):
        return False
    return helpers.wait_js(
        ws,
        "!!document.querySelector('#main .task-row')"
        "||(document.body.innerText||'').includes('未完成的添加')"
        "||!!document.querySelector('#main [data-action=pairStart]')",
        seconds,
        "线路页",
        pump,
    )


def task_card_js(run_id: str) -> str:
    return (
        "(()=>{const b=document.querySelector("
        f"'#main [data-action=resume][data-id=\"{run_id}\"]');"
        "if(!b)return null;const row=b.closest('.task-row')||b.parentElement;"
        "return {action:(row.innerText||''),button:(b.textContent||'').trim()};})()"
    )


def queue_js() -> str:
    """底部队列（`Deployments[]`）里的入口：草稿一律不该出现。"""
    return (
        "(()=>({buttons:document.querySelectorAll("
        "'#mini-status [data-action=resumeDeployment]').length,"
        "tasks:document.querySelectorAll('#mini-status .background-task').length}))()"
    )


def wizard_spec(ws) -> str:
    return str(ws.evaluate("(()=>{const e=document.querySelector('#wf-spec');"
                           "return e?e.value:'<没有地址框>';})()") or "")


def password_state_js() -> str:
    """向导里有没有「已经填着」的密码：草稿**绝不**取回密码。"""
    return (
        "(()=>{const e=document.querySelector('#wf-password');"
        "if(!e)return {present:false,value:'',secretPresent:false};"
        "return {present:true,value:e.value||'',"
        "secretPresent:e.dataset.secretPresent==='true'};})()"
    )


def discard_button_js() -> str:
    return (
        "(()=>{const b=document.querySelector('[data-wf=draft-discard]');"
        "if(!b)return null;return {text:(b.textContent||'').trim(),"
        "tone:(b.className||''),disabled:!!b.disabled};})()"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true", help="验收后不关闭程序（留给人看）")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    t11.no_running_host()
    if work.exists() and record_files(work):
        raise SystemExit(f"数据根里已经有部署记录，拒绝复用：{work}（换一个空目录）")

    checker = Checker()
    report: dict = {
        "mode": "draft-save-resume-discard",
        "exe": str(exe),
        "spec": SPEC,
        "work": str(work),
        "shots": [],
        "checks": [],
    }
    code = 0
    process = None
    process2 = None
    ws = None
    ws2 = None
    try:
        # ---- 第 1 步：首页 → 填地址 → 读指纹（必然失败），失败前先落草稿 ----
        process, _port, ws = t11.launch(exe, work, report_dir, "draft")
        pump = t11.Pump(process.pid)
        if not wait_home(ws, pump):
            raise RuntimeError(f"首页「自己搭服务器」没有变成可点：{body_text(ws)[-300:]}")
        # 首页稳定之后再取基线：程序在启动期会写自己的 config.json / data 目录，
        # 那部分属于「本来就该动」，不该算进这一轮的账。
        time.sleep(1.0)
        baseline = snapshot(work)
        report["snapshotBefore"] = baseline
        helpers.screenshot(ws, report_dir / "01-home.png", report["shots"])

        if not helpers.click(ws, "#main [data-action=add]"):
            raise RuntimeError("首页没有「自己搭服务器」入口")
        if not helpers.wait_js(ws, "!!document.querySelector('#wf-spec')", 15, "部署向导", pump):
            raise RuntimeError(f"部署向导没有出现：{body_text(ws)[-300:]}")
        if not t11.set_value(ws, "#wf-spec", SPEC):
            raise RuntimeError("填不进服务器地址")
        if not helpers.click(ws, "[data-wf=probe]"):
            raise RuntimeError("点不动「读取指纹并继续」")
        helpers.screenshot(ws, report_dir / "02-probing.png", report["shots"])

        # 先看页面真的在等指纹（这一步同时证明草稿是先落的、探针是后发的）。
        checker.check(
            "点「读取指纹并继续」后页面进入「正在读取主机指纹」",
            helpers.wait_js(
                ws,
                f"(document.body.innerText||'').includes({js(LOADING_TEXT)})",
                20,
                "读取指纹中",
                pump,
            ),
            body_text(ws)[-300:],
        )

        try:
            run_id = wait_record(work)
        except RuntimeError as error:
            checker.check("点了「读取指纹并继续」之后磁盘上出现一份草稿", False, str(error))
            raise
        checker.check("点了「读取指纹并继续」之后磁盘上出现一份草稿", True, "ok")
        report["runId"] = run_id
        stored = read_record(work, run_id)
        checker.check(
            "地址在「读指纹」这一步就已经落成草稿（State=Draft）",
            stored.get("State") == "Draft",
            {"State": stored.get("State"), "RunId": run_id},
        )
        checker.check(
            "草稿记的是 127.0.0.1:1（端口 1 也照实落盘）",
            (stored.get("Target") or {}).get("Host") == "127.0.0.1"
            and int((stored.get("Target") or {}).get("Port") or 0) == 1,
            stored.get("Target"),
        )
        checker.check(
            "草稿文件里没有任何密码",
            "password" not in (runs_dir(work) / f"{run_id}.json").read_text(
                encoding="utf-8"
            ).lower(),
            "文件文本里出现了 password",
        )

        # 这里**不等**读指纹收尾。127.0.0.1:1 上没人监听，但 SSH 客户端要重试到超时
        # （实测 >120 秒），而本轮要验的是「表单填到一半就退出」——直接把宿主杀掉更接近
        # 真实场景，也把「草稿已经落盘」这件事钉死。读指纹失败的文案属于 probe 自己的
        # 行为，不在本轮范围（它在 r37 那批有自己的用例）。
        report["probeInFlight"] = body_text(ws)[-400:]
        helpers.screenshot(ws, report_dir / "03-probe-in-flight.png", report["shots"])

        # ---- 第 2 步：杀掉宿主，同根重启，草稿还在 ----
        revision_before = stored.get("Revision")
        process.kill()
        process.wait(timeout=15)
        checker.check("宿主已被终止", process.poll() is not None, process.poll())

        process2, _port2, ws2 = t11.launch(exe, work, report_dir, "draft-restart")
        pump2 = t11.Pump(process2.pid)
        checker.check("同一个数据根重启后首页可点", wait_home(ws2, pump2), body_text(ws2)[-300:])
        checker.check("重启后回到线路页", goto_lines(ws2, pump2), body_text(ws2)[:300])
        checker.check(
            "重启后任务卡还在（草稿不会被回收）",
            helpers.wait_js(
                ws2, f"!!({task_card_js(run_id)})", 25, "任务卡仍在", pump2
            ),
            body_text(ws2)[:400],
        )
        after_restart = read_record(work, run_id)
        checker.check(
            "重启恢复没有改动草稿（Revision/State 不变）",
            after_restart.get("Revision") == revision_before
            and after_restart.get("State") == "Draft",
            {
                "Revision": [revision_before, after_restart.get("Revision")],
                "State": after_restart.get("State"),
            },
        )
        helpers.screenshot(ws2, report_dir / "05-after-restart.png", report["shots"])

        # 任务卡的**可见文案**：`web/app.js` 只渲染 `Name` / `Host:Port` / `Label` / 按钮，
        # 不渲染 `StateText`——所以「未开始」必须出现在 `Label`（第二行）里，而按钮必须是
        # 「继续填写」。`0/4 · 检查服务器环境与身份` 是这一步要挡的假进度。
        card = ws2.evaluate(task_card_js(run_id)) or {}
        report["card"] = card
        checker.check(
            "卡片第二行写「未开始」",
            "未开始" in (card.get("action") or ""),
            card.get("action"),
        )
        checker.check(
            "卡片上没有假进度（不出现「0/4 · 检查服务器环境与身份」）",
            "检查服务器环境" not in (card.get("action") or ""),
            card.get("action"),
        )
        checker.check(
            "卡片上唯一的按钮是「继续填写」",
            (card.get("button") or "") == "继续填写",
            card.get("button"),
        )
        queue = ws2.evaluate(queue_js()) or {}
        report["queue"] = queue
        checker.check(
            "底部队列里没有这条草稿",
            int(queue.get("buttons") or 0) == 0 and int(queue.get("tasks") or 0) == 0,
            queue,
        )
        helpers.screenshot(ws2, report_dir / "04-task-card.png", report["shots"])

        # ---- 第 4 步：点「继续填写」→ 向导（不是详情页）----
        checker.check(
            "点「继续填写」",
            helpers.click(ws2, f'#main [data-action=resume][data-id="{run_id}"]'),
            body_text(ws2)[:300],
        )
        checker.check(
            "打开的是向导：地址框在（不是详情页）",
            helpers.wait_js(ws2, "!!document.querySelector('#wf-spec')", 20, "向导", pump2),
            body_text(ws2)[-400:],
        )
        checker.check(
            "地址已预填（含端口 1）",
            wizard_spec(ws2) == SPEC,
            {"got": wizard_spec(ws2), "want": SPEC},
        )
        checker.check(
            "顶部提示「已恢复上次没填完的地址」",
            RESTORE_NOTICE in body_text(ws2),
            body_text(ws2)[-400:],
        )
        password = ws2.evaluate(password_state_js()) or {}
        report["password"] = password
        checker.check(
            "密码没有被取回（没有密码框，有也必须为空）",
            (not password.get("present"))
            or (password.get("value") == "" and not password.get("secretPresent")),
            password,
        )
        checker.check(
            "这一页没有详情页的东西（没有任务编号 / 没有四步清单的状态行）",
            "任务编号" not in body_text(ws2) and "进度：" not in body_text(ws2),
            body_text(ws2)[-400:],
        )
        discard = ws2.evaluate(discard_button_js()) or {}
        report["discard"] = discard
        checker.check(
            "多一颗「放弃这次填写」",
            (discard.get("text") or "") == "放弃这次填写",
            discard,
        )
        checker.check(
            "「放弃这次填写」不是主按钮（ghost）",
            "ghost" in (discard.get("tone") or ""),
            discard.get("tone"),
        )
        checker.check(
            "「放弃这次填写」可点",
            discard.get("disabled") is False,
            discard,
        )
        helpers.screenshot(ws2, report_dir / "06-resumed-wizard.png", report["shots"])

        # ---- 第 5 步：放弃 → 关页 + toast + 卡消失 + 磁盘少一条 ----
        checker.check(
            "点「放弃这次填写」",
            helpers.click(ws2, "[data-wf=draft-discard]"),
            body_text(ws2)[-300:],
        )
        checker.check(
            "toast 是「已放弃这份草稿，没有留下任务记录。」",
            helpers.wait_js(
                ws2,
                "(()=>{const t=document.getElementById('toast');"
                f"return !!t&&(t.textContent||'').includes({js(DISCARD_TOAST)});}})()",
                20,
                "toast",
                pump2,
            ),
            str(ws2.evaluate("document.getElementById('toast')?.textContent || ''") or ""),
        )
        checker.check(
            "这一页关掉了（地址框消失）",
            helpers.wait_js(ws2, "!document.querySelector('#wf-spec')", 20, "页面关闭", pump2),
            body_text(ws2)[-300:],
        )
        checker.check(
            "磁盘上那条记录没了",
            wait_gone(runs_dir(work) / f"{run_id}.json"),
            record_files(work),
        )
        checker.check(
            "记录目录清空（不是写成 Cancelled 留在盘上）",
            record_files(work) == [],
            record_files(work),
        )
        helpers.screenshot(ws2, report_dir / "07-discarded.png", report["shots"])

        checker.check("放弃之后回到线路页", goto_lines(ws2, pump2), body_text(ws2)[:300])
        checker.check(
            "任务卡消失（「未完成的添加」里没有这一行）",
            helpers.wait_js(
                ws2, f"!({task_card_js(run_id)})", 20, "任务卡消失", pump2
            ),
            body_text(ws2)[:400],
        )

        # ---- 第 6 步：收尾对账 ----
        time.sleep(1.0)
        final = snapshot(work)
        report["snapshotAfter"] = final
        delta = diff_snapshot(baseline, final)
        report["snapshotDelta"] = delta
        checker.check(
            "data 目录与 `config.json` 一个字节没动（md5 前后一致）",
            delta == {"added": [], "removed": [], "changed": []},
            delta,
        )
    except Exception as error:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        checker.check(f"用例没有走完：{error}", False)
        code = 1
    finally:
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
        for opened in (ws, ws2):
            if opened is not None:
                try:
                    opened.close()
                except Exception:  # noqa: BLE001
                    pass
        if not args.keep_open:
            for started in (process, process2):
                if started is not None and started.poll() is None:
                    started.terminate()
                    try:
                        started.wait(timeout=10)
                    except Exception:  # noqa: BLE001
                        started.kill()
        leftovers = [
            item.pid
            for item in (process, process2)
            if item is not None and item.poll() is None
        ]
        print(f"残留进程：{leftovers or '无'}", flush=True)
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
