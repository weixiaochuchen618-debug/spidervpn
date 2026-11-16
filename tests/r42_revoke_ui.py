#!/usr/bin/env python3
"""r42 界面验收：在「服务器与设备」页撤掉一台测试设备（真机，真 SSH）。

验的是 A1 的最后一项：**撤设备**。与 `tests/r38_join_ui.py` 的分工正好相反——
那边验「新电脑加进来」，这边验「管理端把一台设备请出去」。

边界（写死，不靠自觉）：

* **只走产品界面**。`server-revoke` 没有 CLI 旗标，本脚本也不 ssh 去改
  `/etc/wireguard`；唯一进服务器的路径是页面上的「移除 → 确认移除」。
* **只撤你点名的那一台**。设备行按**地址**（`10.66.0.4`）定位，不按下标、不按
  坐标：下标一改就会删错人。找不到那台设备就停手，不猜。
* **确认步骤必须是两段**。点「移除」只应进入确认层，服务器上什么都不该变；
  第二段点「确认移除」才真撤。脚本先用「取消」证一次，再用「确认」走完。
* 验证的判据有两路，缺一不可：**页面列表**（撤完没有它）与
  **`--server-inspect`**（peer 数减一、其余设备的公钥前缀不变）。

驱动层复用 `tests/r38_join_ui.py` → `tests/r35_invite_ui.py`（CDP：`Page.enable` +
窗口置前 + 等待期间泵 `WM_MOUSEMOVE`）。那两条 Windows 坑是 r35 真机踩出来的：
窗口在后台会被计时器限流，长命令的完成事件压在队列里，页面看着像卡死。

选择器来自实际渲染，不是猜的：

* 表单页由 `src/uiweb_form.rs::render_devices` 下发节点树，`web/app.js::formNode`
  渲染成 `<button data-wf="revoke-2" data-control-name="RevokeDevice">移除</button>`；
* 确认层按钮是 `data-control-name="RevokeConfirm"` / `"RevokeCancel"`；
* 设备行是两段 `Kind=text`（`设备 10.66.0.4` 与 `  R6U3lFTg… · …`），
  按钮在紧随其后的 `Kind=row` 里——所以按「往前找最近的『设备 X』文本」定位。

用法：

  python tests/r42_revoke_ui.py --target 10.66.0.4 \\
      --server root@203.0.113.10 --evidence C:\\tc-rs-build\\r42-revoke-ui

退出码：0 = 全部断言通过；1 = 有断言失败（`report.json` 里 `allPassed=false`）。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# 驱动层复用：Checker / Pump / click / js / screenshot / user32 / wait_cdp / wait_js
# 来自 r35；focus（每次交互前置前）/ wait_any / read_text 来自 r38。导入只执行
# 模块级定义，不会启动任何程序。
from r35_invite_ui import (  # noqa: E402
    Checker,
    Pump,
    click,
    js,
    screenshot,
    wait_cdp,
    wait_js,
)
from r38_join_ui import focus, wait_any  # noqa: E402
from s0_page_fixtures import WebSocket, free_port  # noqa: E402

DEFAULT_EXE = r"C:\SpiderVPN\bin\spidervpn.exe"
DEFAULT_EVIDENCE = r"C:\tc-rs-build\r42-revoke-ui"
DEFAULT_SERVER = "root@203.0.113.10"

UI_READY_SECONDS = 40.0
STEP_SECONDS = 60.0
DEVICES_SECONDS = 180.0  # server-devices 是一次真 SSH + wg dump，慢的时候几十秒
POLL_SECONDS = 0.4

# 页面（表单工作流）用的选择器。
WF_READY = "#main .workflow"
REVOKE_DEVICE = "[data-control-name=RevokeDevice]"
REVOKE_CONFIRM = "[data-control-name=RevokeConfirm]"
REVOKE_CANCEL = "[data-control-name=RevokeCancel]"
DEVICES_REFRESH = "[data-control-name=DevicesRefresh]"
DETAILS_BUTTON = "#main .line-card [data-action=details]"
DRAWER = "#drawer"
SERVER_BUTTON = "#drawer [data-action=lineServer]"


# ---------------------------------------------------------------------------
# --server-inspect：这一轮唯一的「服务器那边到底怎么样」的判据
# ---------------------------------------------------------------------------

PEER_RE = re.compile(r"设备\s+(\d+\.\d+\.\d+\.\d+)：([^，,\s]+)")
COUNT_RE = re.compile(r"peer\s+(\d+)")


def inspect(exe: Path, spec: str, timeout: float = 180.0) -> tuple[str, dict]:
    """跑一次 `--server-inspect`，返回 (原文, 解析结果)。

    解析失败不抛异常：原文照留，交给断言去判——把「解析不动」当成「服务器没问题」
    是最容易出的假绿灯。
    """
    try:
        done = subprocess.run(
            [str(exe), "--server-inspect", spec],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return "(超时)", {"peers": None, "devices": {}}
    raw = ((done.stdout or "") + (done.stderr or "")).strip()
    devices = {address: prefix for address, prefix in PEER_RE.findall(raw)}
    counts = COUNT_RE.findall(raw)
    peers = int(counts[0]) if counts else None
    return raw, {"peers": peers, "devices": devices, "rc": done.returncode}


# ---------------------------------------------------------------------------
# 表单页上的小工具
# ---------------------------------------------------------------------------

ADDRESS_JS = """
(()=>{
  const out=[];
  document.querySelectorAll('#main .wf-card [data-control-name=RevokeDevice]').forEach(function(b){
    let node=b.parentElement, address='';
    while(node){
      node=node.previousElementSibling;
      if(!node) break;
      const m=(node.textContent||'').match(/设备\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)/);
      if(m){ address=m[1]; break; }
    }
    out.push({wf:b.getAttribute('data-wf')||'', address:address, label:(b.textContent||'').trim()});
  });
  return out;
})()
"""


def revoke_rows(ws: WebSocket) -> list[dict]:
    rows = ws.evaluate(ADDRESS_JS)
    return [row for row in (rows or []) if isinstance(row, dict)]


def listed_addresses(ws: WebSocket) -> list[str]:
    """页面上「设备 X」这一行出现过哪些地址（不依赖是否给了移除按钮）。

    本机那一行渲染成「设备 10.66.0.2（本机）」——只取地址那一段：后缀是给人看的，
    不是设备标识，拿它做集合比对会把「同一台设备」判成两台。
    """
    found = ws.evaluate(
        "Array.from(document.querySelectorAll('#main .wf-text')).map(function(e){"
        "return e.textContent||'';}).filter(function(t){return /^设备\\s+\\d/.test(t);})"
    ) or []
    addresses: list[str] = []
    for text in found:
        matched = re.search(r"^设备\s+(\d+\.\d+\.\d+\.\d+)", str(text))
        if matched:
            addresses.append(matched.group(1))
    return addresses


def card_text(ws: WebSocket) -> str:
    return str(ws.evaluate("(document.querySelector('#main .wf-card')||{textContent:''}).textContent") or "")


def click_wf(ws: WebSocket, wf: str) -> bool:
    return click(ws, "#main [data-wf=%s]" % json.dumps(wf))


def device_row_text(ws: WebSocket, address: str) -> str:
    """取某台设备那两行文字（确认层说的话里应带上它）。"""
    return str(
        ws.evaluate(
            "(()=>{const rows=Array.from(document.querySelectorAll('#main .wf-text'));"
            "const i=rows.findIndex(function(e){return (e.textContent||'').indexOf(%s)>=0;});"
            "return i<0?'':(rows[i].textContent||'')+' | '+((rows[i+1]||{}).textContent||'');})()"
            % js("设备 " + address)
        )
        or ""
    )


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="r42：在「服务器与设备」页撤掉一台测试设备")
    parser.add_argument("--exe", default=DEFAULT_EXE, help=f"装好的 exe（默认 {DEFAULT_EXE}）")
    parser.add_argument("--target", required=True, help="要撤掉那台设备的隧道地址，例如 10.66.0.4")
    parser.add_argument("--server", default=DEFAULT_SERVER, help=f"服务器记录（默认 {DEFAULT_SERVER}）")
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE, help="证据目录（截图与 report.json）")
    parser.add_argument(
        "--keep-address",
        default="",
        help="撤设备时**必须还在**的另一台设备地址（一般是真实设备 10.66.0.2）。"
        "不填则只按 --server-inspect 的公钥前缀核对",
    )
    parser.add_argument("--keep-open", action="store_true", help="验收后不关闭程序")
    return parser.parse_args()


def finish(checker: Checker, report: dict, evidence: Path, quiet: bool = False) -> int:
    report["checks"] = checker.checks
    report["allPassed"] = bool(checker.checks) and checker.all_passed
    report["passed"] = sum(1 for item in checker.checks if item["ok"])
    report["total"] = len(checker.checks)
    (evidence / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if quiet:
        return 0 if report["allPassed"] else 1
    print(f"\n合计 {report['passed']}/{report['total']}；证据 {evidence}", flush=True)
    if not report["allPassed"]:
        for item in checker.checks:
            if not item["ok"]:
                print(f"  失败：{item['label']} | {item['detail']}", flush=True)
    return 0 if report["allPassed"] else 1


def main() -> int:
    args = parse_args()
    exe = Path(args.exe).expanduser()
    if not exe.exists():
        raise SystemExit(f"找不到 exe：{exe}")
    target = args.target.strip()
    evidence = Path(args.evidence).expanduser().resolve()
    evidence.mkdir(parents=True, exist_ok=True)

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "target": target,
        "server": args.server,
        "shots": [],
        "checks": [],
    }
    shots = report["shots"]

    # ---- 撤之前：服务器上到底有谁（这一份原文要进报告）
    before_raw, before = inspect(exe, args.server)
    report["inspectBefore"] = before_raw
    report["peersBefore"] = before["peers"]
    print(f"[probe] 撤前：peer={before['peers']} 设备={before['devices']}", flush=True)
    checker.check(
        "撤前能读到设备清单（--server-inspect）",
        before["peers"] is not None and bool(before["devices"]),
        f"peers={before['peers']} devices={before['devices']}",
    )
    checker.check(
        "要撤的那台在服务器上确实存在",
        target in before["devices"],
        f"{target} not in {sorted(before['devices'])}",
    )
    keep_before = {address: prefix for address, prefix in before["devices"].items() if address != target}
    checker.check(
        "撤前至少还有一台别的设备（不然「没误伤别人」无从谈起）",
        bool(keep_before),
        keep_before,
    )

    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    # 真实数据根：这条线路是现场那条，设备页读的就是它。撤设备只写服务器，
    # 不改本地配置，所以这里不需要隔离根。
    report["cdpPort"] = port
    host_log = evidence / "host.log"
    log = host_log.open("wb")
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] host pid={process.pid} cdp={port}", flush=True)

    ws: WebSocket | None = None
    pump: Pump | None = None
    revoked = False  # 真按了「确认移除」吗（中途失败要能早退）
    try:
        try:
            cdp_target = wait_cdp(port, UI_READY_SECONDS)
        except TimeoutError as error:
            exited = process.poll()
            raise SystemExit(
                f"{error}\n宿主进程={'已退出（' + str(exited) + '）' if exited is not None else '还在跑'}；"
                "最常见的是托盘里已经有一个实例（单实例会把参数转交给它然后自己退出）。"
                f"\n宿主日志尾部：{(host_log.read_text(encoding='utf-8', errors='replace')[-1200:])}"
            ) from None
        ws = WebSocket(cdp_target["webSocketDebuggerUrl"])
        ws.call("Page.enable")
        try:
            ws.call("Page.bringToFront")
        except Exception:  # noqa: BLE001
            pass
        pump = Pump(process.pid)
        print(f"[probe] windows={pump.handles} foreground={pump.foreground}", flush=True)

        checker.check(
            "真实 WebView2 就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('#main')",
                25,
                "页面初始化",
                pump,
            ),
        )
        screenshot(ws, evidence / "01-start.png", shots)

        # ---- 线路页 → 线路详情 → 服务器与设备
        focus(pump)
        checker.check("导航到线路页", click(ws, "[data-page=lines]"))
        checker.check(
            "线路页有线路卡片",
            wait_js(ws, "!!document.querySelector(%s)" % js(DETAILS_BUTTON), 25, "线路卡片", pump),
        )
        screenshot(ws, evidence / "02-lines.png", shots)

        focus(pump)
        checker.check("打开第一条线路的详情", click(ws, DETAILS_BUTTON))
        checker.check(
            "详情抽屉出现「服务器与设备」",
            wait_js(ws, "!!document.querySelector(%s)" % js(SERVER_BUTTON), 20, "服务器与设备", pump),
        )
        screenshot(ws, evidence / "03-drawer.png", shots)

        focus(pump)
        checker.check("点「服务器与设备」", click(ws, SERVER_BUTTON))
        checker.check(
            "进入设备页（表单工作流）",
            wait_js(ws, "!!document.querySelector(%s)" % js(WF_READY), 25, "表单工作流", pump),
        )
        # 设备清单是长命令（SSH + wg dump）的结果：等到出现「设备 X」行或读失败横幅。
        outcome = wait_any(
            ws,
            {
                "listed": "Array.from(document.querySelectorAll('#main .wf-text'))"
                ".some(function(e){return /^设备\\s+\\d/.test(e.textContent||'');})",
                "failed": "!!Array.from(document.querySelectorAll('#main .wf-text'))"
                ".find(function(e){return (e.textContent||'').indexOf('读不到设备列表')>=0;})",
            },
            DEVICES_SECONDS,
            "设备清单",
            pump,
        )
        checker.check("设备清单有结论（不是一直「正在读取」）", outcome == "listed", outcome or card_text(ws)[:200])
        if outcome != "listed":
            raise SystemExit(f"设备清单没读出来：{card_text(ws)[:300]}")
        screenshot(ws, evidence / "04-devices.png", shots)

        listed = listed_addresses(ws)
        print(f"[probe] 页面设备：{listed}", flush=True)
        checker.check("页面列出了要撤的那台", target in listed, listed)
        checker.check(
            "页面列出的设备与服务器一致（集合相同）",
            set(listed) == set(before["devices"]),
            f"页面={sorted(listed)} 服务器={sorted(before['devices'])}",
        )
        rows = revoke_rows(ws)
        print(f"[probe] 移除按钮：{rows}", flush=True)
        checker.check(
            "要撤的那台有「移除」按钮，且按钮属于它（按地址定位）",
            any(row["address"] == target and row["label"].strip() for row in rows),
            rows,
        )
        mine = [row for row in rows if row["address"] == ""]
        checker.check("没有出现定位不到地址的「移除」按钮（否则可能点错）", not mine, mine)

        # ---- 第一段：点「移除」只进确认层，不能直接生效
        row = next((item for item in rows if item["address"] == target), None)
        if row is None:
            raise SystemExit(f"页面没有 {target} 的移除按钮：{rows}")
        focus(pump)
        checker.check("点「移除」", click_wf(ws, row["wf"]))
        checker.check(
            "先出确认层（不是直接撤）",
            wait_js(ws, "!!document.querySelector(%s)" % js(REVOKE_CONFIRM), 20, "确认层", pump),
        )
        confirm_text = card_text(ws)
        checker.check(
            "确认层点名了要撤的那台设备（%s）" % target,
            target in confirm_text,
            confirm_text[:300],
        )
        checker.check(
            "确认层说明了后果（立刻失去访问权 / 要重新加入）",
            ("立刻失去访问权" in confirm_text) or ("重新加入" in confirm_text),
            confirm_text[:300],
        )
        checker.check(
            "点「移除」这一步还没开始撤（页面没说「正在移除」）",
            "正在移除" not in confirm_text,
            confirm_text[:300],
        )
        mid_raw, mid = inspect(exe, args.server)
        report["inspectMid"] = mid_raw
        checker.check(
            "第一段点完，服务器上 peer 数没变（确认步骤是真闸门）",
            mid["peers"] == before["peers"] and target in mid["devices"],
            f"before={before['peers']} mid={mid['peers']} devices={sorted(mid['devices'])}",
        )
        screenshot(ws, evidence / "05-confirm.png", shots)

        # ---- 先按「取消」：什么都不该发生
        focus(pump)
        checker.check("点「取消」", click(ws, "#main " + REVOKE_CANCEL))
        checker.check(
            "取消后确认层消失",
            wait_js(ws, "!document.querySelector(%s)" % js(REVOKE_CONFIRM), 20, "确认层关闭", pump),
        )
        time.sleep(0.5)
        checker.check(
            "取消后那台设备还在列表里",
            target in listed_addresses(ws),
            listed_addresses(ws),
        )
        checker.check(
            "取消后页面没有说「已移除」",
            "已移除这台设备" not in card_text(ws),
            card_text(ws)[:200],
        )
        screenshot(ws, evidence / "06-cancelled.png", shots)

        # ---- 第二段：确认移除
        rows = revoke_rows(ws)
        row = next((item for item in rows if item["address"] == target), None)
        checker.check("取消后「移除」按钮回到原位（可以再来一次）", row is not None, rows)
        if row is None:
            raise SystemExit(f"取消后找不到 {target} 的移除按钮：{rows}")
        focus(pump)
        checker.check("再点「移除」", click_wf(ws, row["wf"]))
        checker.check(
            "确认层再次出现",
            wait_js(ws, "!!document.querySelector(%s)" % js(REVOKE_CONFIRM), 20, "确认层", pump),
        )
        focus(pump)
        checker.check("点「确认移除」", click(ws, "#main " + REVOKE_CONFIRM))
        revoked = True
        done = wait_any(
            ws,
            {
                "removed": "!!Array.from(document.querySelectorAll('#main .wf-text'))"
                ".find(function(e){return (e.textContent||'').indexOf('已移除这台设备')>=0;})",
                "failed": "!!Array.from(document.querySelectorAll('#main .wf-text'))"
                ".find(function(e){return (e.textContent||'').indexOf('没有移除这台设备')>=0;})",
            },
            STEP_SECONDS,
            "撤销结果",
            pump,
        )
        checker.check("撤销有结论（不一直「正在移除…」）", done != "", done)
        checker.check("服务器报告移除成功（不是失败文案）", done == "removed", done)
        page_text = card_text(ws)
        checker.check(
            "页面说还剩几台（已移除这台设备，服务器上还剩 N 台）",
            "还剩" in page_text,
            page_text[:300],
        )
        screenshot(ws, evidence / "07-revoked.png", shots)

        # ---- 页面列表：它没了，别人还在
        after_listed = listed_addresses(ws)
        checker.check("撤完列表里没有它", target not in after_listed, after_listed)
        checker.check(
            "撤完别人都还在（逐台比对）",
            set(after_listed) == set(keep_before),
            f"期望={sorted(keep_before)} 实际={sorted(after_listed)}",
        )
        if args.keep_address:
            checker.check(
                "指定的那台仍然在（%s）" % args.keep_address,
                args.keep_address in after_listed,
                after_listed,
            )

        # ---- 服务器：peer 数减一、别人的公钥前缀不变
        after_raw, after = inspect(exe, args.server)
        report["inspectAfter"] = after_raw
        report["peersAfter"] = after["peers"]
        print(f"[probe] 撤后：peer={after['peers']} 设备={after['devices']}", flush=True)
        checker.check(
            "服务器 peer 数减一",
            before["peers"] is not None
            and after["peers"] is not None
            and after["peers"] == before["peers"] - 1,
            f"撤前={before['peers']} 撤后={after['peers']}",
        )
        checker.check("服务器上已经没有它", target not in after["devices"], sorted(after["devices"]))
        unchanged = {address: after["devices"].get(address) for address in keep_before}
        checker.check(
            "其它设备的公钥前缀与基线逐台一致（没误伤）",
            unchanged == keep_before,
            f"基线={keep_before} 之后={unchanged}",
        )
        if args.keep_address:
            checker.check(
                "真实设备 %s 仍在，且前缀与基线一致" % args.keep_address,
                after["devices"].get(args.keep_address) == keep_before.get(args.keep_address),
                f"基线={keep_before.get(args.keep_address)} 之后={after['devices'].get(args.keep_address)}",
            )

        # ---- 刷新一次：页面重新读服务器，结论应与服务器一致
        # 刷新会把 devices 置空并重发长命令，页面先回到「正在读取服务器与设备…」。
        # 判据必须是「清单已经重画完」——只等「有设备行」会在旧画面上立刻成立，
        # 紧接着读到的却是加载态的空列表（第一次跑就踩了这条）。
        focus(pump)
        if click(ws, "#main " + DEVICES_REFRESH):
            reloaded = wait_js(
                ws,
                "(()=>{const t=document.querySelector('#main .wf-card');if(!t)return false;"
                "const x=t.textContent||'';"
                "return x.indexOf('已登记的设备')>=0 && x.indexOf('正在读取服务器与设备')<0;})()",
                DEVICES_SECONDS,
                "刷新后的设备清单",
                pump,
            )
            checker.check("刷新后有结论（不是一直「正在读取」）", reloaded, card_text(ws)[:200])
            refreshed: list[str] = []
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                refreshed = listed_addresses(ws)
                if set(refreshed) == set(after["devices"]):
                    break
                pump.tick()
                time.sleep(POLL_SECONDS)
            checker.check(
                "刷新后页面设备与服务器一致（撤的结果落盘了）",
                set(refreshed) == set(after["devices"]),
                f"页面={sorted(refreshed)} 服务器={sorted(after['devices'])}",
            )
            screenshot(ws, evidence / "08-refreshed.png", shots)
        return finish(checker, report, evidence)
    except BaseException as error:  # noqa: BLE001 —— SystemExit 也要留下现场
        report["error"] = f"{type(error).__name__}: {error}"
        report["revokeAttempted"] = revoked
        raise
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
        log.close()
        # 中途抛出去时也要留 report.json：撤到一半的现场比没有现场有价值。
        if "inspectAfter" not in report:
            try:
                late_raw, late = inspect(exe, args.server)
                report["inspectAfter"] = late_raw
                report["peersAfter"] = late["peers"]
            except Exception:  # noqa: BLE001
                pass
        finish(checker, report, evidence, quiet=True)


if __name__ == "__main__":
    sys.exit(main())
