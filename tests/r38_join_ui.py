#!/usr/bin/env python3
"""r38 界面验收：装好的 exe 用一张邀请码走完「加入这台电脑」。

验的是**新电脑那一头**：从「添加线路」到「线路已加入」，页面拿到的每一句话是不是
用户能照做的那一句。与 `tests/r38_qa_tests.rs` 的分工：

- 那边是 crate 内部测试（真 Rust 客户端 × 真 python 服务器），验协议与授权；
- 这边是**装好的 exe + 真 WebView2**，验页面：点得动、说得清、没有留下半成品线路。

驱动方式复用 `tests/r35_invite_ui.py`（CDP，`Page.enable` + 窗口置前 + 等待期间泵
`WM_MOUSEMOVE`）。那两条 Windows 坑是上次真机踩出来的：窗口在后台时 Windows 会做
计时器限流，长命令的完成事件压在队列里，页面看着像卡死。选择器一律用 `data-*`，
不用坐标——布局一改坐标就废。

前置与边界：

* 脚本自己**不连**任何真机、**不调用** `--invite-*`。邀请码由调用方给
  （`--code` 或 `--code-file`），所以它能对真机跑，也能对任何一张拿来试的码跑。
* 数据根：默认用现场真实数据根（验的就是用户那套）。带 `--data-root <dir>` 时设
  `SPIDERVPN_ROOT=<dir>`，把这次加入**完全关进临时根**（它覆盖的是安装目录，
  数据落在 `<dir>/data`）——真机验收必须这样跑，否则用户配置里会多出一条指向
  自己服务器的线路。
* 单实例：如果托盘里已经有一个 SpiderVPN 在跑，新进程会把参数转交给它然后
  自己退出，CDP 永远起不来——那种情况脚本会明确说是「可能已有实例」，而不是干等。

用法：

  # 正向：新码加入，应当出现「线路已加入」并在线路页看到那条线路
  python tests/r38_join_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --code "TCI1...." --expect-line-name 新电脑 --evidence C:\\tc-rs-build\\r38-join-ui

  # 反向：已作废的码，页面必须说「已被服务器主人作废」
  python tests/r38_join_ui.py --code "TCI1...." --expect-error InviteCancelled

  # 反向：旧服务器（GET 回 Open），页面必须说「重新执行一次『开启接收服务』」
  python tests/r38_join_ui.py --code "TCI1...." --expect-error InviteServerOutdated

退出码：0 = 全部断言通过；1 = 有断言失败（`report.json` 里 `allPassed` 同步为 false）。
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# 驱动层**复用 r35**，不另起一套：Checker / Pump / click / wait_js / wait_cdp /
# screenshot 都是同一个实现。导入会执行 r35 的模块级代码（只做 sys.path 处理与
# ctypes 绑定），不会启动任何程序。
from r35_invite_ui import (  # noqa: E402
    Checker,
    Pump,
    click,
    js,
    screenshot,
    user32,
    wait_cdp,
    wait_js,
)
from s0_page_fixtures import WebSocket, free_port  # noqa: E402

DEFAULT_EXE = r"C:\SpiderVPN\bin\spidervpn.exe"
DEFAULT_EVIDENCE = r"C:\tc-rs-build\r38-join-ui"

UI_READY_SECONDS = 40.0
STEP_SECONDS = 60.0
JOIN_SECONDS = 300.0
POLL = 0.4

# 错误码 → 页面上必须出现的那句话（`pairing` 的错误文案，用户照着做就行）。
EXPECTED_PHRASE = {
    "InviteServerOutdated": "开启接收服务",
    "InviteCancelled": "已被服务器主人作废",
    "InviteExpired": "已过期",
    "InviteConsumed": "已被使用",
    "InvalidOnlineResponse": "不认识的邀请状态",
    "OnlineConnectionFailed": "连不上服务器",
    "OnlineTlsPinMismatch": "证书",
}

# 错误码 → 主按钮（`src/uiweb.rs::pair_next_action` 的映射，页面按它给按钮）。
EXPECTED_PRIMARY = {
    "InviteServerOutdated": "重试",
    "InviteCancelled": "重新输入",
    "InviteExpired": "重新输入",
    "InviteConsumed": "重新输入",
    "InvalidOnlineResponse": "重新输入",
    "OnlineConnectionFailed": "重试",
}

# 「拿不到结果」时最该看的两样东西：页面自己说了什么、宿主日志尾部。
ERROR_TEXT = "[data-testid=pair-error]"
ERROR_PRIMARY = "[data-testid=pair-error-primary]"
ERROR_DETAILS = ".pair-error details"
PAIR_CODE_INPUT = "[data-testid=pair-code]"
PAIR_DEVICE_INPUT = "[data-testid=pair-device]"
PAIR_NAME_INPUT = "[data-testid=pair-name]"
PAIR_SUMMARY = "[data-testid=pair-summary]"
ADD_LINE_BUTTON = "#main [data-action=pairBeginChoose]"
CHOOSE_CODE_BUTTON = "#main [data-action=pairChooseCode]"
VERIFY_BUTTON = "#main [data-action=pairVerify]"
JOIN_BUTTON = "#main [data-action=pairJoin]"
TO_LINES_BUTTON = "#main [data-action=pairContinue]"
LINE_NAMES = "[data-testid=line-card] .line-name"


# ---------------------------------------------------------------------------
# 小工具（都在 r35 的 wait_js / click 之上，不重复实现驱动）
# ---------------------------------------------------------------------------

def focus(pump: Pump) -> None:
    """真点击前把窗口拉回前台。

    r35 的 `Pump.__init__` 只做一次置前；一轮流程要几十秒，中途窗口可能被别的
    程序抢走（构建窗口、远程桌面），抢走之后计时器就又被限流。所以每次交互前
    再叫一次，代价是两条 user32 调用。
    """
    for handle in pump.handles:
        user32.ShowWindow(handle, 9)  # SW_RESTORE
        user32.SetForegroundWindow(handle)


def set_field(ws: WebSocket, selector: str, value: str) -> bool:
    """设值并派发 input/change。

    页面的草稿（`pairDraft`）靠 `input` 事件维护：只写 `.value` 不派发，下一次
    重画（每 250ms 一次快照）会把「电脑名称」「线路名」按旧草稿覆盖回去。
    邀请码是 `data-secret` 字段，值会被保留，但同样派发一次无害。
    """
    return bool(
        ws.evaluate(
            "(()=>{const e=document.querySelector(%s);"
            "if(!e||e.disabled)return false;"
            "e.focus();e.value=%s;"
            "e.dispatchEvent(new Event('input',{bubbles:true}));"
            "e.dispatchEvent(new Event('change',{bubbles:true}));"
            "return true;})()" % (js(selector), js(value))
        )
    )


def read_value(ws: WebSocket, selector: str) -> str:
    return str(
        ws.evaluate(
            "(()=>{const e=document.querySelector(%s);return e?(e.value||''):'';})()"
            % js(selector)
        )
        or ""
    )


def read_text(ws: WebSocket, selector: str) -> str:
    return str(
        ws.evaluate(
            "(()=>{const e=document.querySelector(%s);return e?e.textContent:'';})()"
            % js(selector)
        )
        or ""
    )


def wait_any(
    ws: WebSocket,
    expressions: dict[str, str],
    seconds: float,
    label: str,
    pump: Pump | None = None,
) -> str:
    """等到**任意一个**条件成立，返回它的名字；超时返回空串。

    r35 的 `wait_js` 只等一个条件。这里需要「成功或失败先到先算」——加入这一步
    既可能出结果卡也可能出错误横幅，只等其中一个会把另一种当成超时。
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        for name, expression in expressions.items():
            try:
                if ws.evaluate(expression):
                    return name
            except Exception:  # noqa: BLE001
                pass
        if pump is not None:
            pump.tick()
        time.sleep(POLL)
    print(f"  （等待超时：{label}）", flush=True)
    return ""


def line_names(ws: WebSocket) -> list[str]:
    names = ws.evaluate(
        "Array.from(document.querySelectorAll(%s)).map(function(e){return e.textContent;})"
        % js(LINE_NAMES)
    )
    return [str(item) for item in (names or [])]


def host_log_tail(path: Path, limit: int = 1200) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "(读不到宿主日志)"
    return text[-limit:]


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="r38 界面验收：用邀请码加入这台电脑")
    parser.add_argument("--exe", default=DEFAULT_EXE, help=f"装好的 exe（默认 {DEFAULT_EXE}）")
    parser.add_argument("--code", default="", help="一次性邀请码（TCI1. 开头）")
    parser.add_argument("--code-file", default="", help="从文件读邀请码（命令行太长时用）")
    parser.add_argument(
        "--expect-error",
        default="",
        help="反向模式：期望的宿主错误码（如 InviteCancelled / InviteServerOutdated）",
    )
    parser.add_argument("--expect-text", default="", help="反向模式：错误横幅里必须出现的一句话（覆盖内置表）")
    parser.add_argument("--expect-primary", default="", help="反向模式：主按钮文案（覆盖内置表）")
    parser.add_argument("--expect-line-name", default="", help="正向模式：线路名应当是什么（一般填 create 时的 --device）")
    parser.add_argument("--device", default="", help="「这台电脑的名称」；不填则用页面默认值")
    parser.add_argument("--line-name", default="", help="线路名；不填则用页面默认值（= 服务器节点名）")
    parser.add_argument("--evidence", default=DEFAULT_EVIDENCE, help="证据目录（截图与 report.json）")
    parser.add_argument(
        "--data-root",
        default="",
        help="把这次验收关进一个临时数据根（设 SPIDERVPN_ROOT）。"
        "注意它覆盖的是**安装目录**，数据落在 <dir>\\data。不设就用现场真实数据根",
    )
    parser.add_argument("--join-timeout", type=float, default=JOIN_SECONDS, help="加入这一步最多等多少秒")
    parser.add_argument(
        "--step-timeout",
        type=float,
        default=STEP_SECONDS,
        help="「校验」这一步最多等多少秒（真机链路慢时调大；宿主的网络超时是 30 秒一轮）",
    )
    parser.add_argument("--keep-open", action="store_true", help="验收后不关闭程序（留给人看）")
    parser.add_argument(
        "--no-precheck",
        action="store_true",
        help="跳过起界面前的 --invite-check 预检（默认开着；只在调试预检本身时才关掉）",
    )
    return parser.parse_args()


def load_code(args: argparse.Namespace) -> str:
    code = (args.code or "").strip()
    if not code and args.code_file:
        code = Path(args.code_file).read_text(encoding="utf-8").strip()
    if not code:
        raise SystemExit("必须给 --code 或 --code-file")
    if not code.startswith("TCI1."):
        raise SystemExit("邀请码必须以 TCI1. 开头")
    if " " in code or "\n" in code:
        raise SystemExit("邀请码里不该有空白；是不是把说明文字一起粘进来了")
    return code


def precheck(exe: Path, code: str, expect_error: str, timeout: float = 45.0) -> tuple[bool, str, str]:
    """起界面**之前**先用只读命令确认这张码能读，返回 `(ok, 说明, 原始输出)`。

    不先做这一步的代价是具体的：码有一个字符不对（368 字符经人眼或聊天转写很容易错），
    界面会照常启动、跑完 20 条断言全红，真因（`Forbidden`）埋在噪音里。r39 那次就是
    这么白跑一轮。这里拦住它，一条断言都不跑。

    正向要求服务器回 `InvitationReady`；反向（期望失败）只要求输出里出现期望的那个
    错误码——**已作废的码本来就该被拒**，不能拿「能读」当门槛。
    """
    try:
        done = subprocess.run(
            [str(exe), "--invite-check", code],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return False, f"--invite-check 超时（{timeout:.0f} 秒）", ""
    output = ((done.stdout or "") + (done.stderr or "")).strip()
    if expect_error:
        ok = expect_error in output
        detail = f"期望错误码 {expect_error}；实际输出：{output or '(空)'}"
    else:
        ok = done.returncode == 0 and "InvitationReady" in output
        detail = f"rc={done.returncode}；输出：{output or '(空)'}"
    return ok, detail, output


def shape_note(code: str) -> str:
    """形状分诊。**不是闸门**——r39 证明等长替换它抓不到（`k` 改一位它照样通过）。

    只用来在报告里留一句「这张码长什么样」，供人对照，不参与通过与否的判断。
    """
    body = code[len("TCI1."):] if code.startswith("TCI1.") else code
    padded = body + "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception as error:  # noqa: BLE001 —— 只是留个说明，不拦
        return f"载荷解不开（{type(error).__name__}）"
    fields = ",".join(sorted(payload)) if isinstance(payload, dict) else "?"
    token = payload.get("k", "") if isinstance(payload, dict) else ""
    return f"{len(code)} 字符；字段 {fields}；k {len(token)} 位（非闸门）"


def main() -> int:
    args = parse_args()
    exe = Path(args.exe).expanduser()
    if not exe.exists():
        raise SystemExit(f"找不到 exe：{exe}（先用 --exe 指到装好的那一份）")
    code = load_code(args)
    reverse = bool(args.expect_error)
    evidence = Path(args.evidence).expanduser().resolve()
    evidence.mkdir(parents=True, exist_ok=True)

    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    # 数据根：装了 r38 之后，界面加入成功会真的往**这个数据根**里加一条指向服务器的
    # 线路。落在现场就等于让用户下次误点「连接」时通过 VPN 连自己的服务器——所以
    # 验收必须能关进临时根（`SPIDERVPN_ROOT` 覆盖的是安装目录，数据在 `<dir>\data`）。
    if args.data_root:
        data_root = Path(args.data_root).expanduser().resolve()
        data_root.mkdir(parents=True, exist_ok=True)
        env["SPIDERVPN_ROOT"] = str(data_root)
        print(f"[probe] 隔离数据根 install={data_root} data={data_root / 'data'}", flush=True)
    else:
        data_root = None
        env.pop("SPIDERVPN_ROOT", None)
        print("[probe] 使用现场真实数据根（会改用户配置，只有明确要验现场时才这么做）", flush=True)
    # ---- 预检：码本身能不能用，先用只读命令问一次（不起界面）
    # 提前拦住「码有一个字符不对」这种情况：否则界面照常启动、20 条断言全红，
    # 真因（Forbidden）埋在噪音里——r39 那次就是这么白跑一轮的。
    if not args.no_precheck:
        ok, detail, raw = precheck(exe, code, args.expect_error)
        checker = Checker()
        checker.check("预检：邀请码本身可用", ok, detail)
        report = {
            "exe": str(exe),
            "mode": "expect-error" if reverse else "join",
            "expectError": args.expect_error,
            "codeLength": len(code),
            "codePreview": code[:18] + "…",
            "device": args.device,
            "expectLineName": args.expect_line_name,
            "dataRoot": str(data_root) if data_root else "(现场)",
            "cdpPort": port,
            "shape": shape_note(code),
            "precheck": raw,
            "shots": [],
        }
        if not ok:
            print(f"[probe] 预检未通过，一条界面断言都不跑：{detail}", flush=True)
            return finish(checker, report, evidence)

    host_log = evidence / "host.log"
    log = host_log.open("wb")
    print(f"[probe] exe={exe} cdp={port} mode={'expect-error:' + args.expect_error if reverse else 'join'}", flush=True)
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    print(f"[probe] host pid={process.pid}", flush=True)

    checker = Checker()
    report: dict = {
        "exe": str(exe),
        "mode": "expect-error" if reverse else "join",
        "expectError": args.expect_error,
        "codeLength": len(code),
        "codePreview": code[:18] + "…",
        "device": args.device,
        "expectLineName": args.expect_line_name,
        "dataRoot": str(data_root) if data_root else "(现场)",
        "cdpPort": port,
        "shots": [],
        "checks": [],
    }
    shots = report["shots"]
    ws: WebSocket | None = None
    pump: Pump | None = None
    try:
        # ---- 起界面
        try:
            target = wait_cdp(port, UI_READY_SECONDS)
        except TimeoutError as error:
            exited = process.poll()
            raise SystemExit(
                f"{error}\n"
                f"宿主进程={'已退出（' + str(exited) + '）' if exited is not None else '还在跑'}；"
                "最常见的原因是**已经有一个实例在托盘里**（单实例会把参数转交给它然后自己退出）。"
                f"\n宿主日志尾部：\n{host_log_tail(host_log)}"
            ) from None
        ws = WebSocket(target["webSocketDebuggerUrl"])
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

        # ---- 线路页：记下现有线路（反向模式要拿它证「没有半成品」）
        focus(pump)
        checker.check("导航到线路页", click(ws, "[data-page=lines]"))
        checker.check(
            "线路页就绪",
            wait_js(ws, "!!document.querySelector(%s)" % js(ADD_LINE_BUTTON), 25, "添加线路按钮", pump),
        )
        baseline = line_names(ws)
        print(f"[probe] 现有线路 {len(baseline)} 条：{baseline}", flush=True)
        screenshot(ws, evidence / "02-lines.png", shots)

        # ---- 步骤 1：添加线路 → 我有邀请码
        focus(pump)
        checker.check("点「添加线路」", click(ws, ADD_LINE_BUTTON))
        checker.check(
            "出现「我有邀请码」",
            wait_js(ws, "!!document.querySelector(%s)" % js(CHOOSE_CODE_BUTTON), args.step_timeout, "步骤一", pump),
        )
        focus(pump)
        checker.check("点「我有邀请码」", click(ws, CHOOSE_CODE_BUTTON))
        checker.check(
            "进入粘贴邀请码这一步",
            wait_js(
                ws,
                "!!document.querySelector('[data-testid=pair-step][data-step=\"2\"]')"
                "&&!!document.querySelector(%s)" % js(PAIR_CODE_INPUT),
                args.step_timeout,
                "步骤二",
                pump,
            ),
        )
        screenshot(ws, evidence / "03-paste.png", shots)

        # ---- 填码（粘贴在同一台机器上是真的走剪贴板；这里直接写字段，
        #      与用户粘贴的差别只在「谁写的」，页面读的是同一个 .value）
        checker.check("填入邀请码", set_field(ws, PAIR_CODE_INPUT, code))
        if args.device:
            checker.check("填入电脑名称", set_field(ws, PAIR_DEVICE_INPUT, args.device))
        time.sleep(0.3)

        # ---- 校验：成功进第 3 步，失败留在这步并出错误横幅
        focus(pump)
        checker.check("点「校验」", click(ws, VERIFY_BUTTON))
        outcome = wait_any(
            ws,
            {
                "step3": "!!document.querySelector('[data-testid=pair-step][data-step=\"3\"]')",
                "error": "!!document.querySelector(%s)" % js(ERROR_TEXT),
            },
            args.step_timeout,
            "校验结果",
            pump,
        )
        checker.check("校验有结论（不卡在「正在确认邀请码」）", outcome != "", outcome)
        screenshot(ws, evidence / "04-verified.png", shots)

        suggested = ""
        if outcome == "step3":
            # ---- 步骤 3：加入
            suggested = read_value(ws, PAIR_NAME_INPUT)
            checker.check("页面给出了线路名（默认来自服务器节点名）", bool(suggested.strip()), suggested)
            if args.line_name:
                focus(pump)
                checker.check("改线路名", set_field(ws, PAIR_NAME_INPUT, args.line_name))
                suggested = args.line_name.strip()
                time.sleep(0.3)
            screenshot(ws, evidence / "05-name.png", shots)
            focus(pump)
            checker.check("点「加入这台电脑」", click(ws, JOIN_BUTTON))
            outcome = wait_any(
                ws,
                {
                    "done": "!!document.querySelector(%s)" % js(PAIR_SUMMARY),
                    "error": "!!document.querySelector(%s)" % js(ERROR_TEXT),
                },
                args.join_timeout,
                "加入结果",
                pump,
            )
            checker.check("加入有结论（不一直转圈）", outcome != "", outcome)
            screenshot(ws, evidence / "06-joined.png", shots)

        # =============================== 反向模式 ===============================
        if reverse:
            expected = args.expect_error
            phrase = args.expect_text or EXPECTED_PHRASE.get(expected, "")
            primary = args.expect_primary or EXPECTED_PRIMARY.get(expected, "")

            error_text = read_text(ws, ERROR_TEXT).strip()
            checker.check("页面出现错误横幅", bool(error_text), error_text)
            checker.check(
                "页面说的是具体原因（含「%s」）" % phrase if phrase else "页面说的是具体原因",
                bool(phrase) and phrase in error_text,
                error_text,
            )
            if expected != "InvalidOnlineResponse":
                # 这一个码本身就是「协议不对」，所以只在别的码上才禁止这句。
                checker.check(
                    "没有退化成笼统的「服务器返回了不认识的邀请状态」",
                    "不认识的邀请状态" not in error_text,
                    error_text,
                )
            checker.check(
                "没有退化成兜底文案「这一步没有完成」",
                "这一步没有完成" not in error_text,
                error_text,
            )
            details = read_text(ws, ERROR_DETAILS).strip()
            checker.check("技术详情里的错误码就是 %s" % expected, expected in details, details)
            if primary:
                label = read_text(ws, ERROR_PRIMARY).strip()
                checker.check("主按钮是「%s」" % primary, label == primary, label)
            screenshot(ws, evidence / "07-error.png", shots)

            # 失败不许留下半成品线路
            focus(pump)
            click(ws, "[data-page=lines]")
            wait_js(
                ws,
                "!document.querySelector('[data-testid=pair-step]')"
                "&&!!document.querySelector(%s)" % js(ADD_LINE_BUTTON),
                STEP_SECONDS,
                "回到线路页",
                pump,
            )
            time.sleep(0.5)
            after = line_names(ws)
            checker.check(
                "失败没有留下半成品线路",
                after == baseline,
                f"之前={baseline} 之后={after}",
            )
            screenshot(ws, evidence / "08-lines-after.png", shots)
            return finish(checker, report, evidence)

        # =============================== 正向模式 ===============================
        error_text = read_text(ws, ERROR_TEXT).strip()
        checker.check("页面没有错误横幅", error_text == "", error_text)
        details = read_text(ws, ERROR_DETAILS).strip()
        checker.check("ErrorCode 为空（技术详情不出现）", details == "", details)

        summary = read_text(ws, PAIR_SUMMARY)
        checker.check("结果卡说的是「线路已加入」", "线路已加入" in summary, summary)
        main_text = read_text(ws, "#main")
        checker.check("页面没有「失败」字样", "失败" not in main_text, main_text[:200])

        # ---- 回线路页：新线路必须真的在列表里，名字就是刚才那个
        focus(pump)
        if not click(ws, TO_LINES_BUTTON):
            click(ws, "[data-page=lines]")
        # 判据不能只看 `[data-action=pairBeginChoose]`：**添加线路页的页脚**「再添加一条
        # 线路」用的是同一个 data-action，结果卡还没消失时它就已经匹配上了，于是紧接着
        # 读列表读到的是空数组（r39 真机实测：截图里卡片明明在，断言却是 `[]`）。
        # 步骤条只在添加线路页出现，用它把「还停在结果卡」这种情况排除掉。
        checker.check(
            "回到线路页",
            wait_js(
                ws,
                "!document.querySelector('[data-testid=pair-step]')"
                "&&!!document.querySelector(%s)" % js(ADD_LINE_BUTTON),
                STEP_SECONDS,
                "线路页",
                pump,
            ),
        )
        # 再给页面一个节拍把线路卡画出来（快照 250ms 一份）。
        wait_js(
            ws,
            "document.querySelectorAll(%s).length>%d" % (js(LINE_NAMES), len(baseline)),
            10,
            "线路卡出现",
            pump,
        )
        names = line_names(ws)
        checker.check(
            "线路列表多了正好一条",
            len(names) == len(baseline) + 1,
            f"之前={baseline} 之后={names}",
        )
        checker.check(
            "列表里的名字就是页面给的那个",
            suggested.strip() in names,
            f"期望={suggested!r} 实际={names}",
        )
        if args.expect_line_name:
            checker.check(
                "名字与调用方给的一致（服务器节点名/邀请里的设备名）",
                args.expect_line_name in names,
                f"期望={args.expect_line_name!r} 实际={names}",
            )
        screenshot(ws, evidence / "09-lines.png", shots)
        return finish(checker, report, evidence)
    except BaseException as error:  # noqa: BLE001 —— SystemExit 也要留下现场
        report["error"] = f"{type(error).__name__}: {error}"
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
        # 中途抛出去（CDP 没起来、exe 秒退）时也要留下 report.json：
        # 「没有 report.json」和「report.json 里全是红」是两种完全不同的现场。
        finish(checker, report, evidence, quiet=True)


def finish(checker: Checker, report: dict, evidence: Path, quiet: bool = False) -> int:
    """写 `report.json` 并给出退出码（与 r35 同一套字段）。

    `allPassed` 要求**至少有一条断言**：零条断言时 `all([])` 是 True，那会把
    「一条都没跑到」谎报成「全过」。
    """
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


if __name__ == "__main__":
    sys.exit(main())
