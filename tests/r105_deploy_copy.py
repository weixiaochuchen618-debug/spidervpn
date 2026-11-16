#!/usr/bin/env python3
"""r105 界面验收：「自己搭服务器」页的文案精简（正文只留标题与动作，解释进 ⓘ）。

改动前（r104）：一页表单下面铺着六句解释，勾选框标题也长（「已核对云端安全组/
防火墙，已放行 UDP 端口入站…」）。用户的原话是「提示太多」，要按产品思路精简。

改动落地（`src/uiweb_form.rs` 的 `render_deploy` + 新增 `with_hint()`）：

- 正文只留标题与动作，**六句解释一句不留**；
- 六条 Hint 分别挂在 `spec` / `password` / `remember-saved` / `remember-task` /
  `deploy-cloud` / `start` 上，前端渲染成 ⓘ（`[data-hint]` + `#hint-layer`）；
- 两个勾的文案缩短成「中断后可用这份资料继续」「已核对云端安全组与防火墙」；
- **行为零改动**：云端没勾时点「开始部署」照样拦住，提示原文一个字没动。

本脚本读的是 DOM（不是源码），验六件事：

1. **正文干净**：`#main .workflow` 的可见文本里六句旧文案逐句命中数都是 0，
   且没有 `UDP 51820` / `只在当前` 之类的残留；
2. **ⓘ 齐了**：`[data-hint]` ≥ 5，且六个控件各自相邻/所属的 `[data-hint]` 都在、
   关键短语对得上；
3. **真悬停**：`Input.dispatchMouseEvent` 把指针移到 ⓘ 上，`#hint-layer` 真的出现，
   文本是要看的那一段；
4. **行为没坏（最重要）**：不勾云端 → 点「开始部署」→ 逐字命中拦截提示、
   一个部署命令都没发（草稿目录仍是空的）、页面没进等待态；勾上云端再点 →
   真的开始读指纹（草稿落盘 + 页面/对话框出现 probe 的痕迹）；
5. **两个折叠区还在**：`高级部署设置`、`服务器要求与购买建议` 都在、默认收起、
   点开有内容；
6. **反向对照**：`--variant r104` 跑装机里的旧版 exe，同一条脚本必须红
   （六句都在正文里、ⓘ 数量少、那几条 Hint 根本没有）。

用法：

  python tests/r105_deploy_copy.py \\
      --exe C:\\tc-rs-build\\debug\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r105-deploy-copy \\
      --work D:\\vpn构建\\reports-tmp\\r105-deploy-copy\\root

  # 反向对照（期望红）
  python tests/r105_deploy_copy.py --variant r104 \\
      --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r105-deploy-copy-old \\
      --work D:\\vpn构建\\reports-tmp\\r105-deploy-copy-old\\root
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import shutil
import subprocess
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
wait_js = helpers.wait_js
screenshot = helpers.screenshot

# ---------------------------------------------------------------------------
# 契约文案（验收判据，逐字。改产品文案就要改这里，这是有意的）
# ---------------------------------------------------------------------------

# r105 之后正文里必须一句都不剩的六句。每项是（说明, 所有已知旧写法）。
# 第 3 句在 r104 装机版上写作「这台电脑**记住过**」，与设计稿的措辞略有出入——
# 两种写法都算旧文案，判据才不至于只对得上其中一份。
OLD_COPY = (
    ("粘贴地址", ("支持粘贴 IP 或完整登录地址。",)),
    (
        "密码格填什么",
        (
            "选「SSH 私钥」时，这一格填 SSH 私钥解密口令（密钥未加密时留空）；"
            "选「服务器密码」时填服务器登录密码。",
        ),
    ),
    (
        "留空的含义",
        (
            "留空则使用已保存的登录资料（这台电脑记过，或本次任务续跑用的那份）。",
            "留空则使用已保存的登录资料（这台电脑记住过，或本次任务续跑用的那份）。",
        ),
    ),
    (
        "长期保存的加密说明",
        (
            "只保存在这台电脑，用当前 Windows 用户解密。换电脑或换 Windows 用户需要重新输入。"
            "私钥内容也会这样加密保存，不会写进任务记录，也不会出现在导出文件里。",
        ),
    ),
    (
        "UDP 51820 与连不上",
        (
            "部署计划里默认用 UDP 51820（在第一步检查服务器环境时确认）。云端没放行时，"
            "第一步会以「连不上服务器」结束——那不是密码错了。",
        ),
    ),
    (
        "部署自动完成",
        ("部署会自动完成安装、配置和检查。完成后可从首页连接新线路。",),
    ),
)

# 两个勾的长标题（r105 缩短了）：旧版正文里有，新版正文里不该再有。
OLD_LABELS = (
    "本任务中断后可用这份资料继续",
    "已核对云端安全组/防火墙",
)

# 缩短后的两个标题（新版正文里必须有）。
NEW_LABELS = ("中断后可用这份资料继续", "已核对云端安全组与防火墙")

# 「只在当前」这类把解释挤进正文的残留也别回来。
RESIDUE = ("UDP 51820", "只在当前")

# 六个控件各自的 ⓘ 里必须出现的短语（控件选择器, 期望短语）。
HINT_TARGETS = (
    ("#wf-spec", "服务器地址", ("可以粘贴完整登录地址",)),
    ("#wf-password", "服务器登录密码", ("SSH 私钥方式填私钥口令",)),
    ("#wf-remember-saved", "在这台电脑记住登录资料", ("用当前 Windows 用户加密保存在本机",)),
    ("#wf-remember-task", "中断后可用这份资料继续", ("最长 24 小时",)),
    ("#wf-deploy-cloud", "已核对云端安全组与防火墙", ("并保留 SSH 入口",)),
    # 按钮没有 id（前端只给 `data-wf`），所以只能用属性选择器。
    ("#main [data-wf=start]", "开始部署", ("完成后从首页连接新线路",)),
)

# 悬停时要看到的两段（密码框那条包含私钥口令与留空语义，云端那条包含端口与后果）。
PASSWORD_HOVER = ("SSH 私钥方式填私钥口令", "留空表示沿用已保存的登录资料")
CLOUD_HOVER = ("UDP 51820", "连不上服务器")

# 云端闸门的拦截原文：r105 只改文案，这一句**一个字都不许动**。
GATE_SENTENCE = "请先核对云端已放行部署端口（UDP 入站，并保留 SSH 入口），再开始部署。"

# 本机 OpenSSH（127.0.0.1:22）：`server-probe` 只读主机公钥，不登录、不改服务器。
# 用它证明「闸门放行之后确实发起了 probe」；万一本机没开 sshd，脚本会退到不可达
# 地址，那时允许以「连不上服务器」结束——判据是「它确实动手了」。
SPEC = "root@127.0.0.1:22"

PROBE_STARTED = ("正在核对服务器身份",)
PROBE_TERMINAL = (
    "SSH 指纹：SHA256:",
    "确认首次服务器身份",
    "连不上服务器",
)

ADVANCED = "[data-wf=deploy-advanced]"
REQUIREMENTS = "[data-wf=deploy-requirements]"
START = "#main [data-wf=start]"
CLOUD = "#wf-deploy-cloud"


# ---------------------------------------------------------------------------
# 小工具
# ---------------------------------------------------------------------------

def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def body_text(ws) -> str:
    return t11.body_text(ws)


def workflow_text(ws) -> str:
    """正文可见文本：`#main .workflow` 的 innerText（不含折叠区里收起的内容、
    也不含 `#hint-layer` 里的气泡——那在 `#main` 之外）。"""
    return str(
        ws.evaluate("(()=>{const e=document.querySelector('#main .workflow');"
                    "return e?e.innerText:'';})()")
        or ""
    )


def click(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


def click_when_enabled(ws, pump, selector: str, seconds: float = 25.0) -> str:
    ok = wait_js(
        ws,
        "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
        "return !!e&&!e.disabled;})()",
        seconds,
        f"{selector} 可点",
        pump,
    )
    if not ok:
        return "not-ready"
    return click(ws, selector)


def settle(ws, pump, seconds: float = 3.2) -> None:
    """等页面拿到宿主的新代数。

    被拦下来那一帧宿主会 `restructure()`（提示要重绘才看得见），页面还拿着上一代；
    此时发出的 `change` 会被 `Generation` 闸门静默丢弃（r87/r91 的同一课）。
    空闲快照最多 2 秒一拍、且内容变了才推，所以要等够两拍。
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pump.tick()
        time.sleep(0.2)


def hint_near(ws, selector: str):
    """取某个控件「相邻/所属」的 ⓘ 文本。

    宿主把 Hint 序列化成节点自己的属性，前端在节点之后**紧跟**一个 `.hint` 按钮。
    密码框是特例：`#wf-password` 被包在 `.password-field` 里，ⓘ 是那个 div 的
    下一个兄弟。复选框同理（包在 `label.wf-check` 里）。
    """
    expr = (
        "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
        "if(!e)return null;"
        "let n=e.nextElementSibling;"
        "if(!n||!n.classList||!n.classList.contains('hint')){"
        "const holder=e.closest('.password-field')||e.closest('.wf-check');"
        "n=holder?holder.nextElementSibling:null;}"
        "if(!n||!n.classList||!n.classList.contains('hint'))return null;"
        "return n.dataset.hint||'';})()"
    )
    value = ws.evaluate(expr)
    return None if value is None else str(value)


def hint_for_label(ws, label: str):
    """按**标签文字**取它的 ⓘ。

    r105 第二版把地址与密码的解释从输入框挪到了标签上（输入框自己挂 Hint 会变成
    两个 ⓘ），所以 `hint_near("#wf-spec")` 找不到东西——ⓘ 现在跟着「服务器地址」
    这四个字，和标签同一个 `.wf-row`。
    """
    expr = (
        "(()=>{const rows=Array.from(document.querySelectorAll('#main .wf-row'));"
        "const r=rows.find(x=>(x.innerText||'').trim().startsWith("
        + json.dumps(label, ensure_ascii=False)
        + "));if(!r)return null;const h=r.querySelector('.hint');"
        "return h?(h.dataset.hint||''):null;})()"
    )
    value = ws.evaluate(expr)
    return None if value is None else str(value)


def hint_rect(ws, selector: str):
    """返回 ⓘ 在视口里的中心坐标（先滚进视口，再量）。"""
    expr = (
        "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
        "if(!e)return null;"
        "let n=e.nextElementSibling;"
        "if(!n||!n.classList||!n.classList.contains('hint')){"
        "const holder=e.closest('.password-field')||e.closest('.wf-check');"
        "n=holder?holder.nextElementSibling:null;}"
        "if(!n||!n.classList||!n.classList.contains('hint'))return null;"
        "n.scrollIntoView({block:'center',inline:'center'});"
        "const r=n.getBoundingClientRect();"
        "if(!r.width||!r.height)return null;"
        "return {x:r.left+r.width/2,y:r.top+r.height/2,"
        "x0:r.left,y0:r.top,w:r.width,h:r.height};})()"
    )
    return ws.evaluate(expr)


def hint_rect_for_label(ws, label: str):
    """标签旁边那颗 ⓘ 的坐标（和 `hint_for_label` 同一套定位）。"""
    expr = (
        "(()=>{const rows=Array.from(document.querySelectorAll('#main .wf-row'));"
        "const r=rows.find(x=>(x.innerText||'').trim().startsWith("
        + json.dumps(label, ensure_ascii=False)
        + "));if(!r)return null;const n=r.querySelector('.hint');if(!n)return null;"
        "n.scrollIntoView({block:'center',inline:'center'});"
        "const b=n.getBoundingClientRect();"
        "if(!b.width||!b.height)return null;"
        "return {x:b.left+b.width/2,y:b.top+b.height/2,"
        "x0:b.left,y0:b.top,w:b.width,h:b.height};})()"
    )
    return ws.evaluate(expr)


def move_mouse(ws, x: float, y: float) -> None:
    ws.call(
        "Input.dispatchMouseEvent",
        {"type": "mouseMoved", "x": float(x), "y": float(y), "button": "none", "clickCount": 0},
    )


def hover_hint(ws, pump, selector: str, seconds: float = 3.0) -> str:
    """把指针真的移到控件的 ⓘ 上，等到 `#hint-layer` 显形，返回它的文本。

    路线：先把指针挪到空白处（保证下一次进入会触发 `mouseover`），再进 ⓘ；
    前端有 300ms 的进入延时，所以要等。返回空串 = 气泡没出现。
    """
    # 先退出上一次悬停（150ms 后才关），否则 `open()` 会认为锚点没变。
    move_mouse(ws, 4.0, 4.0)
    time.sleep(0.25)
    rect = hint_rect(ws, selector)
    if not rect:
        return ""
    time.sleep(0.2)  # 让 scrollIntoView 的滚动落定（滚动会 maintain 气泡）
    rect = hint_rect(ws, selector) or rect
    move_mouse(ws, rect["x"], rect["y"])
    deadline = time.monotonic() + seconds
    text = ""
    while time.monotonic() < deadline:
        pump.tick()
        state = ws.evaluate(
            "(()=>{const e=document.getElementById('hint-layer');"
            "if(!e)return null;"
            "return {hidden:!!e.hidden,text:e.textContent||''};})()"
        )
        if isinstance(state, dict) and not state.get("hidden"):
            text = str(state.get("text") or "")
            if text:
                break
        time.sleep(0.1)
    return text


def hover_label_hint(ws, pump, label: str, seconds: float = 3.0) -> str:
    """把指针移到**标签**旁边那颗 ⓘ 上（地址/密码的解释跟着标签走）。"""
    move_mouse(ws, 4.0, 4.0)
    time.sleep(0.25)
    rect = hint_rect_for_label(ws, label)
    if not rect:
        return ""
    time.sleep(0.2)
    rect = hint_rect_for_label(ws, label) or rect
    move_mouse(ws, rect["x"], rect["y"])
    deadline = time.monotonic() + seconds
    text = ""
    while time.monotonic() < deadline:
        pump.tick()
        state = ws.evaluate(
            "(()=>{const e=document.getElementById('hint-layer');"
            "if(!e)return null;"
            "return {hidden:!!e.hidden,text:e.textContent||''};})()"
        )
        if isinstance(state, dict) and not state.get("hidden"):
            text = str(state.get("text") or "")
            if text:
                break
        time.sleep(0.1)
    return text


def hint_layer_text(ws) -> str:
    value = ws.evaluate(
        "(()=>{const e=document.getElementById('hint-layer');"
        "return e?(e.textContent||''):'';})()"
    )
    return str(value or "")


def hint_layer_hidden(ws) -> bool:
    value = ws.evaluate(
        "(()=>{const e=document.getElementById('hint-layer');"
        "return e?!!e.hidden:true;})()"
    )
    return bool(value)


def warn_texts(ws) -> list[str]:
    """正文里的警示句（`text_tone(..,"warn")` 渲染成 `p.wf-text.warn-text`）。"""
    value = ws.evaluate(
        "(()=>Array.from(document.querySelectorAll('#main .workflow .wf-text.warn-text'))"
        ".map(e=>(e.innerText||'').trim()))()"
    )
    return [str(item) for item in (value or [])]


def draft_files(work: Path) -> list[str]:
    runs = work / "data" / "deployments" / "runs"
    if not runs.is_dir():
        return []
    return sorted(item.name for item in runs.glob("*.json"))


def set_checked(ws, selector: str, on: bool) -> bool:
    """勾/取消勾：`change` 回传的是布尔（`target.checked`），宿主用 `as_bool()` 取。"""
    expr = (
        "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
        "if(!e)return false;e.checked=" + ("true" if on else "false") + ";"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"
    )
    return bool(ws.evaluate(expr))


def host_processes(exe: Path) -> list[int]:
    """当前用**这个 exe** 跑的进程（按路径过滤，绝不碰装机实例）。"""
    try:
        output = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process spidervpn -ErrorAction SilentlyContinue | "
                "Select-Object -ExpandProperty Path",
            ],
            capture_output=True,
            text=True,
            timeout=25,
        ).stdout
    except Exception:  # noqa: BLE001
        return []
    want = str(exe).lower()
    return [line.strip() for line in output.splitlines() if line.strip().lower() == want]


def full_page_screenshot(ws, path: Path, shots: list[str]) -> int:
    """整页截图：临时把视口拉高到文档高度，拍完立刻清掉。返回用到的像素高度。"""
    height = 0
    try:
        metrics = ws.evaluate(
            "(()=>({w:Math.max(document.documentElement.clientWidth,1024),"
            "h:Math.min(Math.max(document.documentElement.scrollHeight,"
            "document.body?document.body.scrollHeight:0),4000)}))()"
        )
        height = int((metrics or {}).get("h") or 0)
        width = int((metrics or {}).get("w") or 1024)
        if height > 0:
            ws.call(
                "Emulation.setDeviceMetricsOverride",
                {
                    "width": width,
                    "height": height,
                    "deviceScaleFactor": 1,
                    "mobile": False,
                },
            )
            time.sleep(0.5)
        screenshot(ws, path, shots)
    except Exception as error:  # noqa: BLE001
        print(f"  （整页截图失败，退回视口截图：{error}）", flush=True)
        screenshot(ws, path, shots)
    finally:
        try:
            ws.call("Emulation.clearDeviceMetricsOverride")
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.2)
    return height


# ---------------------------------------------------------------------------
# 页面事实（两个版本共用一次采集）
# ---------------------------------------------------------------------------

def old_hits(text: str) -> dict[str, dict[str, int]]:
    """六句旧文案在正文里的命中数：{说明: {写法: 命中次数}}。

    按写法分开记，报告里才能写清「到底哪一句、哪种写法还在」。
    """
    return {
        label: {form: text.count(form) for form in forms}
        for label, forms in OLD_COPY
    }


def old_total(hits: dict[str, int]) -> int:
    return sum(hits.values())


def old_matched(hits: dict[str, int]) -> list[str]:
    return [form for form, count in hits.items() if count]


def collect(ws, checker: Checker, report: dict) -> dict:
    text = workflow_text(ws)
    hints = {
        selector: (hint_for_label(ws, label) if selector in ("#wf-spec", "#wf-password")
                   else hint_near(ws, selector))
        for selector, label, _phrases in HINT_TARGETS
    }
    facts = {
        "workflowText": text,
        "workflowChars": len(text),
        "hintCount": int(
            ws.evaluate("document.querySelectorAll('#main [data-hint]').length") or 0
        ),
        "hints": hints,
        "oldHits": old_hits(text),
        "oldLabelHits": {word: text.count(word) for word in OLD_LABELS},
        "residueHits": {word: text.count(word) for word in RESIDUE},
        "checkedCloud": str(ws.evaluate(f"(document.querySelector('{CLOUD}')||{{}}).checked")).lower(),
        "specValue": str(ws.evaluate("(document.querySelector('#wf-spec')||{}).value") or ""),
        "draftsBefore": draft_files(Path(report["work"])),
    }
    return facts


# ---------------------------------------------------------------------------
# r105 断言
# ---------------------------------------------------------------------------

def assert_clean_copy(ws, pump, checker: Checker, report: dict, facts: dict) -> None:
    print("\n== 1. 正文干净 ==", flush=True)
    for label, forms in OLD_COPY:
        hits = facts["oldHits"][label]
        total = old_total(hits)
        checker.check(
            f"正文里没有旧文案「{label}」（命中 {total}）",
            total == 0,
            f"命中 {total} 次｜{old_matched(hits)}",
        )
    for word in OLD_LABELS:
        checker.check(
            f"长标题「{word}」已不在正文（命中 {facts['oldLabelHits'][word]}）",
            facts["oldLabelHits"][word] == 0,
            f"命中 {facts['oldLabelHits'][word]} 次",
        )
    for word in RESIDUE:
        hits = facts["residueHits"][word]
        checker.check(f"正文里没有残留「{word}」（命中 {hits}）", hits == 0, f"命中 {hits} 次")
    checker.check(
        "正文只剩标题与动作（没有被塞回一页说明）",
        0 < facts["workflowChars"] < 240,
        f"{facts['workflowChars']} 字：{facts['workflowText'][:300]}",
    )
    # 标题与动作本身还在（别精简成空页）。
    for want in ("服务器地址", "服务器登录密码", *NEW_LABELS, "开始部署"):
        checker.check(f"正文还留着「{want}」", want in facts["workflowText"], "")
    # 「返回上一页」不在正文里是对的：前端 `splitPageBack()` 把它提到面包屑里去了
    # （只剩返回按钮的容器整行不渲染），所以判据落在面包屑上。
    crumb = ws.evaluate(
        "(()=>{const b=document.querySelector('#main .breadcrumb');if(!b)return {missing:true};"
        "const btn=b.querySelector('button');"
        "return {text:b.innerText||'',wf:btn&&btn.dataset?(btn.dataset.wf||''):''};})()"
    ) or {}
    checker.check(
        "「返回上一页」还在（提到面包屑里，动作没丢）",
        "返回上一页" in str(crumb.get("text") or "") and crumb.get("wf") == "back",
        crumb,
    )


def assert_hints(ws, pump, checker: Checker, report: dict, facts: dict) -> None:
    print("\n== 2. ⓘ 齐了 ==", flush=True)
    checker.check(
        f"[data-hint] 数量 ≥ 5（实际 {facts['hintCount']}）",
        facts["hintCount"] >= 5,
        facts["hintCount"],
    )
    for selector, label, phrases in HINT_TARGETS:
        text = facts["hints"].get(selector)
        checker.check(
            f"「{label}」有 ⓘ",
            text is not None,
            f"{selector} 相邻没有 .hint",
        )
        if text is None:
            continue
        missing = [phrase for phrase in phrases if phrase not in text]
        checker.check(
            f"「{label}」的 ⓘ 说清了该说的（缺 {missing}）",
            not missing,
            f"实际：{text}",
        )


def assert_hover(ws, pump, checker: Checker, report: dict) -> None:
    print("\n== 3. 真悬停 ==", flush=True)
    pw = hover_label_hint(ws, pump, "服务器登录密码")
    checker.check(
        "指针移到密码框 ⓘ → #hint-layer 出现",
        bool(pw) and not hint_layer_hidden(ws),
        f"hidden={hint_layer_hidden(ws)} text={pw[:80]}",
    )
    missing = [phrase for phrase in PASSWORD_HOVER if phrase not in pw]
    checker.check(
        f"密码 ⓘ 气泡里有两层语义（缺 {missing}）",
        bool(pw) and not missing,
        pw,
    )
    report.setdefault("hover", {})["password"] = pw
    screenshot(ws, Path(report["reportDir"]) / "02-hint-password.png", report["shots"])

    cloud = hover_hint(ws, pump, CLOUD)
    checker.check(
        "指针移到云端 ⓘ → #hint-layer 换成另一段",
        bool(cloud) and not hint_layer_hidden(ws),
        f"hidden={hint_layer_hidden(ws)} text={cloud[:80]}",
    )
    missing = [phrase for phrase in CLOUD_HOVER if phrase not in cloud]
    checker.check(
        f"云端 ⓘ 气泡里说清了端口与后果（缺 {missing}）",
        bool(cloud) and not missing,
        cloud,
    )
    checker.check(
        "两次悬停的内容不是同一段（ⓘ 各挂各的）",
        bool(pw) and bool(cloud) and pw != cloud,
        f"password={pw[:40]} cloud={cloud[:40]}",
    )
    report.setdefault("hover", {})["cloud"] = cloud
    screenshot(ws, Path(report["reportDir"]) / "03-hint-cloud.png", report["shots"])

    # 指针移开 → 气泡自己收起（前端 150ms 后关）。这既是 WCAG 的「可移出」，
    # 也保证后面那张「拦截提示」的截图不被气泡盖住。
    move_mouse(ws, 3.0, 3.0)
    dismissed = wait_js(
        ws,
        "(()=>{const e=document.getElementById('hint-layer');return !e||!!e.hidden;})()",
        3,
        "气泡收起",
        pump,
    )
    checker.check("指针移开后气泡收起", dismissed, f"text={hint_layer_text(ws)[:60]}")


def assert_details(ws, pump, checker: Checker, report: dict) -> None:
    print("\n== 5. 两个折叠区还在 ==", flush=True)
    for selector, title, marker in (
        (ADVANCED, "高级部署设置", "TCP 首选端口"),
        (REQUIREMENTS, "服务器要求与购买建议", "推荐 Ubuntu 24.04"),
    ):
        exists = ws.evaluate(
            "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
            "return !!e&&e.tagName==='DETAILS';})()"
        )
        checker.check(f"「{title}」折叠区在", bool(exists), f"{selector}")
        if not exists:
            continue
        closed = ws.evaluate(
            "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
            "return {open:!!e.open,summary:(e.querySelector('summary')||{}).innerText||''};})()"
        ) or {}
        checker.check(
            f"「{title}」默认收起",
            closed.get("open") is False,
            closed,
        )
        checker.check(
            f"「{title}」的标题就是这句",
            title in str(closed.get("summary") or ""),
            closed.get("summary"),
        )
        hidden_hit = ws.evaluate(
            "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
            "return (e.innerText||'').includes(" + json.dumps(marker) + ");})()"
        )
        checker.check(
            f"「{title}」收起时内容不占正文（{marker} 不可见）",
            not hidden_hit,
            f"visible={hidden_hit}",
        )
        # 点开（原生 <details>，前端明确不同步 open 属性，不会被下一帧收回）
        checker.check(
            f"点开「{title}」",
            click(ws, f"{selector} summary") == "ok",
            "",
        )
        opened = ws.evaluate(
            "(()=>{const e=document.querySelector(" + json.dumps(selector) + ");"
            "return {open:!!e.open,text:(e.innerText||'')};})()"
        ) or {}
        checker.check(
            f"「{title}」点开后有内容",
            opened.get("open") is True and marker in str(opened.get("text") or ""),
            f"open={opened.get('open')} text={str(opened.get('text'))[:160]}",
        )
        # 收回去，保持页面初始形态（后面的截图与行为验收都要干净的一页）
        click(ws, f"{selector} summary")
        time.sleep(0.3)


def assert_gate(ws, pump, checker: Checker, report: dict, work: Path) -> None:
    print("\n== 4. 行为没坏：云端闸门 ==", flush=True)
    checker.check(
        "云端勾选默认不勾",
        str(ws.evaluate(f"(document.querySelector('{CLOUD}')||{{}}).checked")).lower() == "false",
        "",
    )
    checker.check("填进服务器地址", t11.set_value(ws, "#wf-spec", SPEC), "")
    time.sleep(0.6)  # 让 input 事件的 change 落到宿主

    before = draft_files(work)
    checker.check("动手前草稿目录是空的", before == [], before)

    checker.check("不勾云端就点「开始部署」", click_when_enabled(ws, pump, START) == "ok", "")
    got = wait_js(
        ws,
        "Array.from(document.querySelectorAll('#main .workflow .wf-text.warn-text'))"
        ".some(e=>(e.innerText||'').includes('请先核对云端'))",
        15,
        "拦截提示",
        pump,
    )
    notices = warn_texts(ws)
    checker.check("出现拦截提示", bool(got), notices)
    checker.check(
        "拦截提示逐字等于原句",
        GATE_SENTENCE in notices,
        notices,
    )
    report["gateNotice"] = notices

    time.sleep(1.5)  # 给「万一真发了命令」留出落盘时间
    after = draft_files(work)
    checker.check(
        "没有任何部署命令发出（草稿目录仍然空）",
        after == [],
        after,
    )
    busy = ws.evaluate(
        "(()=>{const w=document.querySelector('#main .workflow');"
        "return {busy:w?w.getAttribute('aria-busy'):null,"
        "text:w?w.innerText:''};})()"
    ) or {}
    checker.check(
        "页面没进等待态（没有「正在核对服务器身份」、没有 aria-busy）",
        not busy.get("busy") and "正在核对服务器身份" not in str(busy.get("text") or ""),
        f"aria-busy={busy.get('busy')}",
    )
    checker.check(
        "页面不动：地址与控件都还在，填过的值没被清掉",
        str(ws.evaluate("(document.querySelector('#wf-spec')||{}).value") or "") == SPEC
        and bool(ws.evaluate("!!document.querySelector('#wf-password')"))
        and bool(ws.evaluate("!!document.querySelector('#main [data-wf=start]')")),
        str(ws.evaluate("(document.querySelector('#wf-spec')||{}).value") or ""),
    )
    screenshot(ws, Path(report["reportDir"]) / "04-gate-blocked.png", report["shots"])

    # 拦下来那一帧宿主重绘过：等页面拿到新代数，否则下面这个 change 会被闸门吞掉。
    settle(ws, pump, 3.2)
    checker.check("勾上「已核对云端安全组与防火墙」", set_checked(ws, CLOUD, True), "")
    settle(ws, pump, 0.8)
    checker.check(
        "勾选真的记到了宿主（重绘后仍是勾上的）",
        str(ws.evaluate(f"(document.querySelector('{CLOUD}')||{{}}).checked")).lower() == "true",
        "",
    )

    clicked = click_when_enabled(ws, pump, START) == "ok"
    checker.check("勾上云端再点「开始部署」", clicked, "")
    if not clicked:
        return

    # 放行之后要看到它确实动手了：草稿落盘（命令发出去了）+ probe 的痕迹。
    started = set()
    terminal = set()
    deadline = time.monotonic() + 40.0
    drafts: list[str] = []
    while time.monotonic() < deadline:
        pump.tick()
        text = body_text(ws)
        dialog = str(
            ws.evaluate("(document.getElementById('dialog-root')||{}).innerText||''") or ""
        )
        blob = text + "\n" + dialog
        for word in PROBE_STARTED:
            if word in blob:
                started.add(word)
        for word in PROBE_TERMINAL:
            if word in blob:
                terminal.add(word)
        drafts = draft_files(work)
        if drafts and terminal:
            break
        time.sleep(0.25)

    report["probe"] = {
        "started": sorted(started),
        "terminal": sorted(terminal),
        "drafts": drafts,
        "pageTail": body_text(ws)[-400:],
    }
    checker.check(
        "放行后宿主真的开始动（草稿落盘 = server-probe 命令发出去了）",
        bool(drafts),
        drafts,
    )
    checker.check(
        "看到 probe 的过程（等待态 / 指纹 / 首次身份确认 / 连不上）",
        bool(started) or bool(terminal),
        f"started={sorted(started)} terminal={sorted(terminal)}",
    )
    checker.check(
        "probe 有明确去向（读到了指纹或明确连不上，不是卡死）",
        bool(terminal),
        f"terminal={sorted(terminal)}｜{body_text(ws)[-300:]}",
    )
    screenshot(ws, Path(report["reportDir"]) / "05-gate-open-probe.png", report["shots"])


# ---------------------------------------------------------------------------
# r104 反向对照断言（期望红）
# ---------------------------------------------------------------------------

def assert_old_copy(checker: Checker, facts: dict) -> None:
    print("\n== 反向对照：旧版应当不满足 r105 的每一条 ==", flush=True)
    for label, forms in OLD_COPY:
        hits = facts["oldHits"][label]
        total = old_total(hits)
        checker.check(
            f"[旧版] 正文里就有旧文案「{label}」（命中 {total}）——r105 的「一句都不剩」在旧版必然失败",
            total > 0,
            f"命中 {total} 次｜{old_matched(hits)}",
        )
    for word in OLD_LABELS:
        checker.check(
            f"[旧版] 长标题还在正文里（命中 {facts['oldLabelHits'][word]}）",
            facts["oldLabelHits"][word] > 0,
            f"命中 {facts['oldLabelHits'][word]} 次｜{word}",
        )
    checker.check(
        f"[旧版] ⓘ 数量少（实际 {facts['hintCount']}，r105 要求 ≥ 5）",
        facts["hintCount"] < 5,
        facts["hintCount"],
    )
    for selector, label, phrases in HINT_TARGETS:
        text = facts["hints"].get(selector)
        present = text is not None and all(phrase in text for phrase in phrases)
        checker.check(
            f"[旧版]「{label}」没有这条 ⓘ（r105 的这条判据在旧版必然失败）",
            not present,
            f"实际：{text}",
        )
    checker.check(
        "[旧版] 两个勾的短标题还没出现",
        any(word not in facts["workflowText"] for word in NEW_LABELS),
        facts["workflowText"][:200],
    )


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--variant", choices=("r105", "r104"), default="r105")
    parser.add_argument("--keep-open", action="store_true")
    parser.add_argument("--allow-running", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    if not exe.is_file():
        raise SystemExit(f"找不到被测 exe：{exe}")
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)
    (work / "data").mkdir(parents=True, exist_ok=True)

    if args.allow_running:
        print("[warn] --allow-running：不检查已有实例（独立数据根，互不干扰）", flush=True)
    else:
        t11.no_running_host()

    exe_sha_before = sha256_of(exe)
    exe_bytes_before = exe.stat().st_size
    print(f"[probe] exe sha256={exe_sha_before} bytes={exe_bytes_before}", flush=True)
    baseline = host_processes(exe)

    checker = Checker()
    report: dict = {
        "mode": f"r105-deploy-copy/{args.variant}",
        "variant": args.variant,
        "exe": str(exe),
        "exeSha256": exe_sha_before,
        "exeBytes": exe_bytes_before,
        "work": str(work),
        "reportDir": str(report_dir),
        "shots": [],
        "checks": [],
        "baselineHostProcesses": baseline,
    }
    code = 0
    process = None
    ws = None
    try:
        process, port, ws = t11.launch(exe, work, report_dir, f"copy-{args.variant}")
        report["cdpPort"] = port
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪",
            wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ),
            body_text(ws)[-200:],
        )
        checker.check(
            "进「自己搭服务器」页",
            click_when_enabled(ws, pump, "#main [data-action=add]") == "ok"
            and wait_js(ws, "!!document.querySelector('#wf-spec')", 20, "部署表单", pump),
            body_text(ws)[-300:],
        )

        facts = collect(ws, checker, report)
        report["facts"] = facts
        print(f"[probe] 正文 {facts['workflowChars']} 字｜ⓘ {facts['hintCount']} 个", flush=True)

        if args.variant == "r105":
            assert_clean_copy(ws, pump, checker, report, facts)
            assert_hints(ws, pump, checker, report, facts)
            height = full_page_screenshot(
                ws, report_dir / "01-page-full.png", report["shots"]
            )
            report["fullPageHeight"] = height
            assert_hover(ws, pump, checker, report)
            assert_details(ws, pump, checker, report)
            assert_gate(ws, pump, checker, report, work)
        else:
            assert_old_copy(checker, facts)
            screenshot(ws, report_dir / "01-old-page.png", report["shots"])
            report["oldHitsDetail"] = facts["oldHits"]
    except Exception as error:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        checker.check(f"用例没有走完：{type(error).__name__}: {error}", False)
        code = 1
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if not args.keep_open and process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=12)
            except Exception:  # noqa: BLE001
                process.kill()
        if process is not None:
            time.sleep(1.0)

        exe_sha_after = sha256_of(exe)
        exe_bytes_after = exe.stat().st_size
        leftover = host_processes(exe)
        checker.check(
            "被测 exe 跑前跑后一致（没被替换）",
            exe_sha_after == exe_sha_before and exe_bytes_after == exe_bytes_before,
            f"sha {exe_sha_before[:12]}→{exe_sha_after[:12]} bytes "
            f"{exe_bytes_before}→{exe_bytes_after}",
        )
        checker.check(
            "没有残留进程（按 exe 路径比对，不碰装机实例）",
            sorted(leftover) == sorted(baseline),
            f"跑前 {baseline}｜跑后 {leftover}",
        )
        report["exeSha256After"] = exe_sha_after
        report["exeBytesAfter"] = exe_bytes_after
        report["leftoverHostProcesses"] = leftover

        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        print(f"exeSha256={exe_sha_after} exeBytes={exe_bytes_after}", flush=True)
        print(f"残留进程：{'有' if leftover != baseline else '无'}", flush=True)
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
