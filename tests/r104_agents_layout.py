#!/usr/bin/env python3
"""r104 界面验收：AI 工具名单「只列名单 + 一台可收起的全目录」。

r104 相对 r103 的形状变化（本脚本只验 r104；r103 的形状留在 `r103_agents_rows.py`，
那份脚本刻意不再兼容，跑 r103 的装机 exe 当历史对照）：

    AI 工具名单
      选择要跟随线路的工具，改完点保存，一次生效。      ⓘ
      桌面程序                                        ← 只列「已经在名单里」的，空类别连标题都不出现
        Cursor 编辑器（运行中）              ⓘ  [移除]  ← 说明并进名称的 Hint，不再各占一行
      网页版
        模型 API 与下载平台
      添加其他工具（20）                               ← 名单外的一台折叠区（平的、默认收起）
      自定义
    保存 / 放弃修改 / 返回

三条硬要求（写死在这里，就是本脚本的存在理由）：

1. **三种状态各用一份独立种子**（空名单 / 部分在名单 / 全部在名单）。同一份种子
   来回改会把「首屏形状」和「改过之后形状」搅在一起，红条就说不清是谁的错。
2. **原文级**断言：分组标题、折叠区标题（含全角括号里的条数）、`details` 的 `open`
   都是页面上的**文本与属性**，不是宿主的中间态。
3. **点一下 = 整页重画**：每行的「添加 / 移除」会让该行在「名单内 ↔ 折叠区」之间搬家，
   所以每次点击都要求 `Generation` 自增后的整页重画，靠结构位置判定，不靠"按钮变色"。

被测对象是**真机**（exe + WebView2 + 真实 config.json + 隔离数据根）。跑前跑后各算一次
exe 的 sha256/字节数：任何一次不一致都判 FAIL（r101 的教训：验的和装的不是同一个文件）。

用法：

  python tests/r104_agents_layout.py \\
      --exe C:\\tc-rs-build\\debug\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r104-layout \\
      --work D:\\vpn构建\\reports-tmp\\r104-layout\\root

反向对照（应大面积红：r103 没有折叠区、每行有详情节、有「添加常用 AI 工具」）：

  python tests/r104_agents_layout.py \\
      --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r104-layout-r103 \\
      --work D:\\vpn构建\\reports-tmp\\r104-layout-r103\\root
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
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
r87 = importlib.import_module("r87_history_ui")

Checker = helpers.Checker

# r104 页头那一句（与 r103 相同，改动没碰它：本脚本不验它，只当"页到了"的锚点）。
HEADER = "改完点保存，一次生效"
GONE_RECOMMEND = "添加常用 AI 工具"
GONE_HEADER = "勾选要跟随线路"

# 目录 22 项（`src/agents.rs::BUILTIN` 的 id，按目录顺序）。测试里写死是故意的：
# 条数变了要有人来看一眼——「22 → 21」如果只是渲染层漏了一行，这里就是唯一会响的地方。
ALL_BUILTIN = [
    # 桌面程序（11）
    "mirasim", "claude-code", "codex", "antigravity", "cc-switch", "chatgpt-app",
    "cursor", "windsurf", "perplexity-app", "ollama", "lmstudio",
    # 网页版（9）
    "claude-web", "chatgpt-web", "gemini-web", "perplexity-web", "grok-web",
    "mistral-web", "copilot-web", "aistudio-web", "poe-web",
    # 模型 API 与下载平台（2）
    "github-copilot", "huggingface",
]

GROUP_PROGRAM = "桌面程序"
GROUP_WEB = "网页版"
GROUP_SERVICE = "模型 API 与下载平台"
GROUP_CUSTOM = "自定义"

# 三条长 detail（`src/agents.rs` 原文）：正文里一个字都不许出现，必须整体挂在 `data-hint` 上。
DETAIL_CLAUDE = "claude.exe：命令行、Mirasim 调用的助手和桌面版。"
DETAIL_ANTIGRAVITY = "安装在名为 Antigravity 的目录中即可识别，包括它的语言服务。"
DETAIL_CHATGPT_APP = "OpenAI ChatGPT 桌面程序与登录、验证、静态资源。"
DETAIL_CURSOR = "Cursor 程序、模型请求、登录和云代理。"

# ---------------------------------------------------------------------------
# 观测面：全部走 DOM。页面是宿主每帧重画出来的，源码与单测都只是旁证。
# ---------------------------------------------------------------------------
JS_SNAPSHOT = r"""
(()=>{
  const norm = s => (s||'').replace(/\s+/g,' ').trim();
  const wf = document.querySelector('#main .workflow');
  if (!wf) return JSON.stringify({ok:false, reason:'no-workflow'});
  const main = document.querySelector('#main');
  const buttons = [...wf.querySelectorAll('[data-wf^="builtin-"]')].map(b=>({
    id: b.dataset.wf, text: norm(b.textContent), inDetails: !!b.closest('details')}));
  const details = [...document.querySelectorAll('#main details')].map(d=>({
    id: d.dataset.wf || '',
    title: norm((d.querySelector('summary')||{}).textContent),
    open: d.hasAttribute('open'),
    rows: [...d.querySelectorAll('[data-wf^="builtin-"]')].map(b=>norm(b.textContent))}));
  const headings = [...wf.querySelectorAll('h3')].map(e=>norm(e.textContent));
  const hints = [...wf.querySelectorAll('[data-hint]')].map(e=>e.dataset.hint||'');
  // 顶层兄弟顺序：行是否「搬到了分组标题之后、折叠区之前」只能靠位置判。
  // 宿主把所有节点塞在一张 card（`<section class="card wf-card">`）里，所以要往里下一层。
  const stack = wf.querySelector(':scope > section.wf-card') || wf;
  const order = [...stack.children].map(el=>{
    const b = el.querySelector ? el.querySelector('[data-wf^="builtin-"]') : null;
    return {tag: el.tagName, wf: (el.dataset && el.dataset.wf) || '',
            row: b ? b.dataset.wf : '', text: norm(el.textContent).slice(0, 30)};
  });
  return JSON.stringify({
    ok: true, text: wf.innerText, body: main.innerText,
    page: document.body.innerText,
    buttons, details, headings, hints, order,
    recommend: !!document.querySelector('#main [data-wf=recommend]'),
    detailRows: wf.querySelectorAll('[data-hint^="包含的网站："]').length,
  });
})()
"""


def js_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def sha256_file(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def page_snapshot(ws) -> dict:
    raw = ws.evaluate(JS_SNAPSHOT)
    if not raw:
        return {"ok": False, "reason": "empty"}
    try:
        return json.loads(str(raw))
    except Exception as error:  # noqa: BLE001
        return {"ok": False, "reason": repr(error)}


def brief(snap: dict) -> dict:
    """报告里留证据的那一小截（全文另存，避免 report.json 变成一份 HTML 副本）。"""
    return {
        "ok": snap.get("ok"),
        "buttons": snap.get("buttons"),
        "details": snap.get("details"),
        "headings": snap.get("headings"),
        "recommend": snap.get("recommend"),
        "detailRows": snap.get("detailRows"),
        "text": (snap.get("text") or "")[:1200],
    }


def builtin_buttons(snap: dict) -> list[dict]:
    return [item for item in (snap.get("buttons") or []) if isinstance(item, dict)]


def texts(snap: dict, want: str) -> list[str]:
    return [str(b.get("text")) for b in builtin_buttons(snap) if str(b.get("text")) == want]


def headings(snap: dict) -> list[str]:
    return [str(h) for h in (snap.get("headings") or [])]


def details_of(snap: dict) -> list[dict]:
    return [d for d in (snap.get("details") or []) if isinstance(d, dict)]


def order_index(order: list[dict], pred) -> int:
    for index, entry in enumerate(order):
        if pred(entry):
            return index
    return -1


def settle(ws, pump, quiet: float = 0.6, seconds: float = 8.0) -> str:
    """等 #main 重画完，返回稳定后的 workflow 文本。

    宿主的回包到前端重画之间有几百毫秒；点完立刻读 innerText 会读到**上一版**。
    """
    last, stable_since, deadline = None, time.monotonic(), time.monotonic() + seconds
    text = ""
    while time.monotonic() < deadline:
        text = str(ws.evaluate("(document.querySelector('#main .workflow')||{}).innerText") or "")
        if text != last:
            last, stable_since = text, time.monotonic()
        elif time.monotonic() - stable_since >= quiet:
            return text
        pump.tick()
        time.sleep(0.2)
    return text


# ---------------------------------------------------------------------------
# 种子 / 配置观测
# ---------------------------------------------------------------------------
def seed(work: Path, builtin: list[str]) -> None:
    """一份种子只服务一个状态。`builtin` 就是用户在设置里上次保存的那份名单。"""
    data = work / "data"
    data.mkdir(parents=True, exist_ok=True)
    config = {
        "schema": 2,
        "selected": "L1",
        "lines": [{"id": "L1", "name": "线路甲", "proxy_endpoint": "127.0.0.1:17901"}],
        "split": {"processes": [], "domains": []},
        "agents": {"lane": "daily", "builtin": list(builtin), "programs": [], "sites": []},
    }
    (data / "config.json").write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def config_bytes(work: Path) -> bytes:
    return (work / "data" / "config.json").read_bytes()


def config_agents(work: Path) -> dict:
    try:
        return json.loads(config_bytes(work).decode("utf-8-sig")).get("agents", {})
    except Exception as error:  # noqa: BLE001
        return {"__error__": repr(error)}


def config_builtin(work: Path) -> list[str]:
    return [str(x) for x in (config_agents(work).get("builtin") or [])]


def digest(work: Path) -> dict:
    """config.json 的摘要证据：sha256 前 16 位 + 字节数 + builtin 原文。"""
    data = config_bytes(work)
    return {
        "sha256_16": hashlib.sha256(data).hexdigest()[:16],
        "bytes": len(data),
        "builtin": config_builtin(work),
    }


# ---------------------------------------------------------------------------
# 页面出来之前：拦一手页面 → 宿主的消息（`chrome.webview.postMessage`）
# ---------------------------------------------------------------------------
def wrap_post(ws) -> None:
    ws.evaluate(
        "(()=>{window.__tcPosted=[];const w=window.chrome&&window.chrome.webview;"
        "if(!w||w.__wrapped)return false;const orig=w.postMessage.bind(w);w.__wrapped=true;"
        "w.postMessage=m=>{try{window.__tcPosted.push(typeof m==='string'?m:JSON.stringify(m));}"
        "catch(_){window.__tcPosted.push('<<unserializable>>');}return orig(m);};"
        "return true;})()"
    )


def posted_mark(ws) -> int:
    return int(ws.evaluate("(window.__tcPosted||[]).length") or 0)


def posted_since(ws, mark: int) -> list[dict]:
    raw = ws.evaluate(
        "((window.__tcPosted||[]).slice(%d)).map(s=>{try{return JSON.parse(s)}catch(_){return {raw:s}}})"
        % mark
    ) or []
    return [item if isinstance(item, dict) else {"raw": str(item)} for item in raw]


def save_intents(posted: list[dict]) -> list[dict]:
    """页面点的「保存」次数。

    宿主收下这次点击后走的是 `Step::Sync("agents-save")`——命令在宿主进程内部执行
    （`src/ui.rs` 的 `Step::Sync` 分支），**不会**再回发给页面，所以页面上唯一能数到的
    是「保存意图」。一次点击 = 一条 `agents-save`，由 `render_agents` 里那一个
    `steps.push(Step::Sync(...))` 保证；本脚本按意图计数，并用落盘结果交叉核对。
    """
    return [m for m in posted if m.get("Id") == "save" and m.get("Type") == "form"]


def commandish(posted: list[dict]) -> list[dict]:
    """除 form 点击之外的任何下发（命令 / 保存 / 主题…）。"""
    return [m for m in posted if m.get("Type") != "form" or "agents-save" in json.dumps(m)]


# ---------------------------------------------------------------------------
# 悬停：真的把鼠标移到 ⓘ 上
# ---------------------------------------------------------------------------
def hint_target(ws, item_id: str) -> dict | None:
    point = ws.evaluate(
        "(()=>{const rows=[...document.querySelectorAll('#main .wf-row')];"
        "const row=rows.find(r=>r.querySelector('[data-wf=%s]'));if(!row)return null;"
        "const h=row.querySelector('.hint');if(!h)return null;"
        "h.scrollIntoView({block:'center'});const r=h.getBoundingClientRect();"
        "return {x:r.left+r.width/2,y:r.top+r.height/2,hint:h.dataset.hint||''};})()"
        % js_str(item_id)
    )
    return point if isinstance(point, dict) else None


def hover_open(ws, pump, item_id: str) -> str:
    """鼠标移到该行 ⓘ 上，返回方式 input/js/none。

    先把指针挪到别处（关掉上一颗气泡），再移到目标点并停住——`hintLayer.open`
    有 300ms 的悬停延迟，所以这里要等，不是读一下 `data-hint` 就算验完。
    """
    point = hint_target(ws, item_id)
    if not point:
        return "none"
    cx, cy = float(point["x"]), float(point["y"])
    try:
        ws.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 4, "y": 4, "buttons": 0})
        pump.tick()
        time.sleep(0.2)
        for _ in range(3):
            ws.call(
                "Input.dispatchMouseEvent",
                {"type": "mouseMoved", "x": cx, "y": cy, "buttons": 0},
            )
            pump.tick()
            time.sleep(0.25)
        if helpers.wait_js(
            ws,
            "(()=>{const l=document.getElementById('hint-layer');"
            "return !!l&&!l.hidden&&l.textContent.length>0;})()",
            3,
            "悬停出气泡",
            pump,
        ):
            return "input"
    except Exception as error:  # noqa: BLE001
        print(f"  （Input.dispatchMouseEvent 不可用：{error}）", flush=True)
    # 退路：JS 派发 mouseover 走的是同一条 `hintLayer.open` 路径（只有 300ms 定时器）。
    ws.evaluate(
        "(()=>{const rows=[...document.querySelectorAll('#main .wf-row')];"
        "const row=rows.find(r=>r.querySelector('[data-wf=%s]'));if(!row)return false;"
        "const h=row.querySelector('.hint');if(!h)return false;"
        "h.dispatchEvent(new MouseEvent('mouseover',{bubbles:true}));return true;})()"
        % js_str(item_id)
    )
    opened = helpers.wait_js(
        ws,
        "(()=>{const l=document.getElementById('hint-layer');"
        "return !!l&&!l.hidden&&l.textContent.length>0;})()",
        5,
        "悬停出气泡（JS 派发）",
        pump,
    )
    return "js" if opened else "none"


def hint_layer(ws) -> dict:
    return ws.evaluate(
        "(()=>{const l=document.getElementById('hint-layer');"
        "return l?{hidden:!!l.hidden,text:l.textContent,popover:l.getAttribute('popover')}:null;})()"
    ) or {}


def close_hints(ws) -> None:
    """走 hintLayer 自己的 150ms 收起路径。

    **不要用 Escape**：表单页上的 Esc 是「返回上一页」（app.js 把 .breadcrumb 点了），
    一整页会被关掉。
    """
    ws.evaluate(
        "(()=>{document.querySelectorAll('#main .hint').forEach(h=>"
        "h.dispatchEvent(new MouseEvent('mouseout',{bubbles:true})));return true;})()"
    )


# ---------------------------------------------------------------------------
# 「整页重画」的证据：宿主下发的 Form.Generation + 旧节点是否被换掉
# ---------------------------------------------------------------------------
def hook_snapshots(ws) -> None:
    """在 app.js 的消息监听之外再挂一个监听，把宿主快照留一份（只读，不改页面）。"""
    ws.evaluate(
        "(()=>{window.__tcMsgs=[];window.__tcMsgCount=0;const w=window.chrome&&window.chrome.webview;"
        "if(!w||w.__msgHooked)return false;w.__msgHooked=true;"
        "w.addEventListener('message',e=>{try{const d=e.data;window.__tcMsgCount++;"
        "window.__tcMsgs.push(typeof d==='string'?d:JSON.stringify(d));"
        "if(window.__tcMsgs.length>80)window.__tcMsgs.shift();}catch(_){}});return true;})()"
    )


def form_generation(ws) -> int:
    return int(
        ws.evaluate(
            "(()=>{const all=window.__tcMsgs||[];"
            "for(let i=all.length-1;i>=0;i--){let m;try{m=JSON.parse(all[i]);}catch(_){continue;}"
            "if(!(m&&m.Type==='snapshot'&&m.State&&m.State.Form))continue;"
            "if(m.State.Form.ViewKey!=='agents')continue;return m.State.Form.Generation;}"
            "return -1;})()"
        )
        or -1
    )


def mark_row(ws, item_id: str) -> bool:
    """把这一行的 DOM 节点留个句柄：重画之后它必须 `isConnected === false`。"""
    return bool(
        ws.evaluate(
            "(()=>{const b=document.querySelector('#main [data-wf=%s]');"
            "window.__tcRow=b?b.closest('.wf-row'):null;return !!window.__tcRow;})()"
            % js_str(item_id)
        )
    )


def marked_row_connected(ws) -> bool | None:
    value = ws.evaluate(
        "(()=>{const r=window.__tcRow;return r?r.isConnected:null;})()"
    )
    return None if value is None else bool(value)


# ---------------------------------------------------------------------------
# 打开「AI 工具名单」
# ---------------------------------------------------------------------------
def open_agents(ws, pump) -> tuple[bool, str]:
    if not helpers.wait_js(
        ws,
        "document.readyState==='complete'&&!!document.querySelector('nav')",
        40,
        "首页",
        pump,
    ):
        return False, "首页没起来"
    if r87.click_when_enabled(ws, pump, "nav [data-page=apps]") != "ok":
        return False, "应用页入口点不动"
    if r87.click_when_enabled(ws, pump, "#main [data-action=agentsList]") != "ok":
        return False, "「管理工具名单」点不动"
    ok = helpers.wait_js(
        ws,
        "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
        "return t.includes('AI 工具名单')&&t.includes(%s);})()" % js_str(HEADER),
        30,
        "名单页",
        pump,
    )
    return ok, "" if ok else "名单页没出现"


# ---------------------------------------------------------------------------
# 三种状态
# ---------------------------------------------------------------------------
def assert_copy(ws, snap, check) -> None:
    """说明并进 Hint：正文不许有 detail 原文，`data-hint` 里必须有；全页没有一键按钮。"""
    workflow = str(snap.get("text") or "")
    page = str(snap.get("page") or "")
    hints = [str(h) for h in (snap.get("hints") or [])]

    for label, detail in (
        ("Claude Code", DETAIL_CLAUDE),
        ("Antigravity", DETAIL_ANTIGRAVITY),
        ("ChatGPT 桌面版", DETAIL_CHATGPT_APP),
    ):
        tail = detail.rstrip("。")
        check(
            f"正文不出现「%s」的说明原文（%s…）" % (label, tail[:10]),
            tail not in workflow,
            {"inWorkflow": tail in workflow, "workflowHead": workflow[:200]},
        )
        check(
            f"「%s」的说明挂在 [data-hint] 上" % label,
            any(tail in h for h in hints),
            [h[:40] for h in hints if tail in h][:2] or hints[:3],
        )

    check(
        "全页不出现「添加常用 AI 工具」，也没有 recommend 节点",
        GONE_RECOMMEND not in page and not snap.get("recommend"),
        {"inPage": GONE_RECOMMEND in page, "recommendNode": snap.get("recommend")},
    )
    check("全页不出现「勾选要跟随线路」（r103 之前的说法）", GONE_HEADER not in page,
          {"inPage": GONE_HEADER in page})


def case_empty(ws, pump, check, report, shots, report_dir: Path) -> None:
    """状态 1：`agents.builtin=[]`。全目录自动展开，一个分组标题都不许有。"""
    snap = page_snapshot(ws)
    report["empty"] = brief(snap)
    buttons = builtin_buttons(snap)
    empty_details = details_of(snap)
    heads = headings(snap)

    check("22 颗内置项按钮（一颗不多一颗不少）", len(buttons) == 22, len(buttons))
    check(
        "22 行全写「添加」",
        len(texts(snap, "添加")) == 22 and len(texts(snap, "移除")) == 0,
        {"添加": len(texts(snap, "添加")), "移除": len(texts(snap, "移除"))},
    )
    check("#main 里恰好一台 <details>", len(empty_details) == 1, empty_details)
    only = empty_details[0] if empty_details else {}
    check("折叠区 id = more-builtin", only.get("id") == "more-builtin", only.get("id"))
    check(
        "折叠区标题 = 添加其他工具（22）",
        only.get("title") == "添加其他工具（22）",
        only.get("title"),
    )
    check("名单为空 → 折叠区自动展开（有 open）", only.get("open") is True, only.get("open"))
    check(
        "折叠区里就是那 22 行，全写「添加」",
        len(only.get("rows") or []) == 22 and all(t == "添加" for t in (only.get("rows") or [])),
        {"rows": len(only.get("rows") or [])},
    )
    check(
        "正文没有任何分组标题（只剩「自定义」）",
        heads == [GROUP_CUSTOM],
        heads,
    )
    check(
        "没有空标题、也没有「添加其他工具（0）」",
        all(h.strip() for h in heads) and "添加其他工具（0）" not in str(snap.get("body") or ""),
        heads,
    )
    assert_copy(ws, snap, check)

    helpers.screenshot(ws, report_dir / "r104-01-empty-list.png", shots)


def case_partial(ws, pump, check, report, shots, report_dir: Path, work: Path) -> None:
    """状态 2：`builtin=[claude-code, cursor]`。名单 2 行 + 折叠区 20 行、收起。"""
    snap = page_snapshot(ws)
    report["partialInitial"] = brief(snap)
    buttons = builtin_buttons(snap)
    fold = details_of(snap)
    heads = headings(snap)

    check("22 颗内置项按钮（一颗不多一颗不少）", len(buttons) == 22, len(buttons))
    check(
        "名单段 2 行写「移除」，其余 20 行写「添加」",
        len(texts(snap, "移除")) == 2 and len(texts(snap, "添加")) == 20,
        {"移除": len(texts(snap, "移除")), "添加": len(texts(snap, "添加"))},
    )
    check(
        "两台类别里只有这两项所在的「桌面程序」",
        heads == [GROUP_PROGRAM, GROUP_CUSTOM],
        heads,
    )
    check("#main 里恰好一台 <details>", len(fold) == 1, fold)
    only = fold[0] if fold else {}
    check(
        "折叠区标题 = 添加其他工具（20）", only.get("title") == "添加其他工具（20）", only.get("title")
    )
    check("折叠区默认收起（没有 open）", only.get("open") is False, only.get("open"))
    check(
        "折叠区里 20 行全写「添加」",
        len(only.get("rows") or []) == 20 and all(t == "添加" for t in (only.get("rows") or [])),
        {"rows": len(only.get("rows") or [])},
    )
    opened = ws.evaluate(
        "(()=>{const d=document.querySelector('#main details[data-wf=more-builtin]');"
        "return d?d.matches('details:not([open])'):null;})()"
    )
    check("CSS 侧也是收起：details:not([open])", opened is True, opened)

    order = snap.get("order") or []
    cursor_at = order_index(order, lambda e: e.get("row") == "builtin-cursor")
    fold_at = order_index(order, lambda e: e.get("wf") == "more-builtin")
    group_at = order_index(order, lambda e: e.get("tag") == "H3" and e.get("text") == GROUP_PROGRAM)
    check(
        "cursor 的行在「桌面程序」标题之后、折叠区之前",
        0 <= group_at < cursor_at < fold_at if fold_at >= 0 else False,
        {"group": group_at, "row": cursor_at, "details": fold_at, "order": order[:8]},
    )

    assert_copy(ws, snap, check)
    helpers.screenshot(ws, report_dir / "r104-02-partial-collapsed.png", shots)

    # ---- 交互 1：点折叠区里的「添加」→ 整行搬到名单段，条数 −1，不发任何命令 ----
    wrap_post(ws)
    hook_snapshots(ws)
    # 宿主空闲时只在内容变化或距上次推送满 6 秒才补推一份快照，所以这里要等，不能立刻读。
    helpers.wait_js(ws, "(window.__tcMsgCount||0)>0", 10, "宿主快照到达", pump)
    mark = posted_mark(ws)
    before = config_bytes(work)
    before_digest = digest(work)
    gen_before = form_generation(ws)
    row_marked = mark_row(ws, "builtin-windsurf")
    clicked = r87.click_when_enabled(ws, pump, "#main [data-wf=builtin-windsurf]")
    moved = helpers.wait_js(
        ws,
        "(()=>{const d=document.querySelector('#main details[data-wf=more-builtin]');"
        "const b=document.querySelector('#main [data-wf=builtin-windsurf]');"
        "if(!d||!b)return false;if(b.closest('details'))return false;"
        "const t=(d.querySelector('summary')||{}).textContent||'';"
        "if(!t.includes('（19）'))return false;"
        "return (b.textContent||'').trim()==='移除';})()",
        12,
        "折叠区里的添加把行搬到名单段",
        pump,
    )
    after_move = page_snapshot(ws)
    settle(ws, pump)
    time.sleep(0.4)
    gen_after = form_generation(ws)
    posted = posted_since(ws, mark)
    old_row = marked_row_connected(ws)
    order2 = after_move.get("order") or []
    row2 = order_index(order2, lambda e: e.get("row") == "builtin-windsurf")
    fold2 = order_index(order2, lambda e: e.get("wf") == "more-builtin")
    group2 = order_index(order2, lambda e: e.get("tag") == "H3" and e.get("text") == GROUP_PROGRAM)
    report["afterAdd"] = {
        "click": clicked,
        "layout": brief(after_move),
        "order": order2[:10],
        "position": {"group": group2, "row": row2, "details": fold2},
        "generation": {"before": gen_before, "after": gen_after},
        "oldRowStillConnected": old_row,
        "posted": posted,
        "config": digest(work),
        "configBefore": before_digest,
        "configUnchanged": config_bytes(work) == before,
    }
    check("点折叠区里的「添加」→ 行移出折叠区并写「移除」", clicked == "ok" and moved,
          {"click": clicked, "position": {"group": group2, "row": row2, "details": fold2}})
    check(
        "搬过去的位置在「桌面程序」标题之后、折叠区之前",
        0 <= group2 < row2 < fold2 if fold2 >= 0 else False,
        {"group": group2, "row": row2, "details": fold2},
    )
    check(
        "折叠区标题变成 添加其他工具（19）",
        (details_of(after_move)[0].get("title") if details_of(after_move) else None)
        == "添加其他工具（19）",
        [d.get("title") for d in details_of(after_move)],
    )
    check(
        "顺手一变：名单段 3 行「移除」、折叠区 19 行「添加」",
        len(texts(after_move, "移除")) == 3 and len(texts(after_move, "添加")) == 19,
        {"移除": len(texts(after_move, "移除")), "添加": len(texts(after_move, "添加"))},
    )
    check(
        "这一下只回传一条 form 点击，不是任何命令",
        len(posted) == 1 and posted[0].get("Type") == "form"
        and posted[0].get("Id") == "builtin-windsurf" and not commandish(posted),
        posted,
    )
    check(
        "此时 config.json 逐字节未变（草稿只在宿主内存）",
        config_bytes(work) == before,
        {"before": before_digest, "after": digest(work)},
    )
    check(
        "这一下是整页重画：宿主 Form.Generation 自增，旧行节点被换掉（不是就地打补丁）",
        gen_after > gen_before >= 0 and row_marked and old_row is False,
        {"generation": {"before": gen_before, "after": gen_after},
         "rowMarked": row_marked, "oldRowConnected": old_row},
    )

    # ---- 交互 2：在名单段点同一项的「移除」→ 行回到折叠区，条数回到 20 ----
    mark = posted_mark(ws)
    gen_before = form_generation(ws)
    row_marked = mark_row(ws, "builtin-windsurf")
    back_click = r87.click_when_enabled(ws, pump, "#main [data-wf=builtin-windsurf]")
    returned = helpers.wait_js(
        ws,
        "(()=>{const d=document.querySelector('#main details[data-wf=more-builtin]');"
        "const b=document.querySelector('#main [data-wf=builtin-windsurf]');"
        "if(!d||!b)return false;if(!b.closest('details'))return false;"
        "const t=(d.querySelector('summary')||{}).textContent||'';"
        "if(!t.includes('（20）'))return false;"
        "return (b.textContent||'').trim()==='添加';})()",
        12,
        "名单段的移除把行送回折叠区",
        pump,
    )
    after_back = page_snapshot(ws)
    settle(ws, pump)
    time.sleep(0.4)
    gen_back = form_generation(ws)
    report["afterRemove"] = {
        "click": back_click,
        "layout": brief(after_back),
        "generation": {"before": gen_before, "after": gen_back},
        "oldRowStillConnected": marked_row_connected(ws),
        "posted": posted_since(ws, mark),
        "configUnchanged": config_bytes(work) == before,
    }
    check("在名单段点「移除」→ 行回到折叠区并写「添加」", back_click == "ok" and returned,
          brief(after_back))
    check(
        "折叠区标题回到 添加其他工具（20）",
        (details_of(after_back)[0].get("title") if details_of(after_back) else None)
        == "添加其他工具（20）",
        [d.get("title") for d in details_of(after_back)],
    )
    check(
        "两个来回之后 config.json 仍然逐字节未变",
        config_bytes(work) == before,
        digest(work),
    )
    check(
        "回程也是整页重画（Form.Generation 再自增，旧行节点被换掉）",
        gen_back > gen_before >= 0 and marked_row_connected(ws) is False,
        {"generation": {"before": gen_before, "after": gen_back},
         "oldRowConnected": marked_row_connected(ws)},
    )

    # ---- 保存：加一项 → 保存 → 恰一次保存意图；落盘条数与页面「移除」行数一致 ----
    mark = posted_mark(ws)
    r87.click_when_enabled(ws, pump, "#main [data-wf=builtin-codex]")
    helpers.wait_js(
        ws,
        "(()=>{const b=document.querySelector('#main [data-wf=builtin-codex]');"
        "return !!b&&!b.closest('details')&&(b.textContent||'').trim()==='移除';})()",
        12,
        "加一项进草稿",
        pump,
    )
    before_save = digest(work)
    save_click = r87.click_when_enabled(ws, pump, "#main [data-wf=save]")
    helpers.wait_js(
        ws,
        "(()=>{const t=(document.querySelector('#main .workflow')||{}).innerText||'';"
        "return t.includes('已保存')||t.includes('已改');})()",
        15,
        "保存回包落地",
        pump,
    )
    settle(ws, pump)
    time.sleep(1.2)
    posted_save = posted_since(ws, mark)
    intents = save_intents(posted_save)
    saved_layout = page_snapshot(ws)
    saved = config_builtin(work)
    removed_rows = len(texts(saved_layout, "移除"))
    report["save"] = {
        "click": save_click,
        "configBefore": before_save,
        "config": digest(work),
        "posted": posted_save,
        "saveIntents": len(intents),
        "removedRowsOnPage": removed_rows,
        "layout": brief(saved_layout),
    }
    check("点「保存」", save_click == "ok", save_click)
    check("恰一条保存意图（页面上只发了一次保存点击）", len(intents) == 1, posted_save)
    check(
        "落盘 agents.builtin 就是 3 项（claude-code / cursor / codex）",
        sorted(saved) == ["claude-code", "codex", "cursor"],
        saved,
    )
    check(
        "config.json 的 builtin 条数与页面「移除」行数一致",
        len(saved) == removed_rows == 3,
        {"config": len(saved), "page移除": removed_rows},
    )

    # ---- 放弃修改：再改乱一次，必须还原成「上次保存的样子」 ----
    r87.click_when_enabled(ws, pump, "#main [data-wf=builtin-codex]")
    dirty = helpers.wait_js(
        ws,
        "(()=>{const b=document.querySelector('#main [data-wf=builtin-codex]');"
        "return !!b&&!!b.closest('details');})()",
        12,
        "改成脏的",
        pump,
    )
    before_discard = config_bytes(work)
    discard_click = r87.click_when_enabled(ws, pump, "#main [data-wf=discard]")
    restored = helpers.wait_js(
        ws,
        "(()=>{const d=document.querySelector('#main details[data-wf=more-builtin]');"
        "const b=document.querySelector('#main [data-wf=builtin-codex]');"
        "if(!d||!b)return false;const t=(d.querySelector('summary')||{}).textContent||'';"
        "return !b.closest('details')&&t.includes('（19）');})()",
        15,
        "放弃修改后还原",
        pump,
    )
    report["discard"] = {
        "dirty": dirty,
        "click": discard_click,
        "layout": brief(page_snapshot(ws)),
        "configUnchanged": config_bytes(work) == before_discard,
    }
    check("「放弃修改」把整页还原成已保存的 3 项", discard_click == "ok" and restored,
          brief(page_snapshot(ws)))
    check(
        "「放弃修改」不写配置（config.json 逐字节未变）",
        config_bytes(work) == before_discard,
        digest(work),
    )

    # ---- 悬停：鼠标真的移到 Cursor 那颗 ⓘ 上，气泡同时含 detail 与域名 ----
    way = hover_open(ws, pump, "builtin-cursor")
    layer = hint_layer(ws)
    layer_text = str(layer.get("text") or "")
    report["hover"] = {
        "method": way,
        "layer": {"hidden": layer.get("hidden"), "text": layer_text,
                  "popover": layer.get("popover")},
    }
    check(
        "鼠标移到 Cursor 的 ⓘ 上，气泡同时含说明与「包含的网站：」",
        way != "none"
        and not layer.get("hidden", True)
        and DETAIL_CURSOR in layer_text
        and "包含的网站：" in layer_text
        and "cursor.com" in layer_text,
        {"method": way, "text": layer_text[:160]},
    )
    helpers.screenshot(ws, report_dir / "r104-03-hover-merged-hint.png", shots)
    close_hints(ws)


def case_full(ws, pump, check, report, shots, report_dir: Path) -> None:
    """状态 3：22 项全在名单。没有折叠区，也没有「添加其他工具（0）」。"""
    snap = page_snapshot(ws)
    report["full"] = brief(snap)
    buttons = builtin_buttons(snap)
    fold = details_of(snap)
    heads = headings(snap)
    body = str(snap.get("body") or "")

    check("22 颗内置项按钮（一颗不多一颗不少）", len(buttons) == 22, len(buttons))
    check(
        "22 行全写「移除」",
        len(texts(snap, "移除")) == 22 and len(texts(snap, "添加")) == 0,
        {"移除": len(texts(snap, "移除")), "添加": len(texts(snap, "添加"))},
    )
    check("#main 里 details 数量为 0（不出现空折叠区）", len(fold) == 0, fold)
    check(
        "全页不出现「添加其他工具」（连「（0）」都没有）",
        "添加其他工具" not in body,
        [line for line in body.splitlines() if "添加其他工具" in line][:3],
    )
    check(
        "三个分组标题都在（桌面程序 / 网页版 / 模型 API 与下载平台）",
        heads == [GROUP_PROGRAM, GROUP_WEB, GROUP_SERVICE, GROUP_CUSTOM],
        heads,
    )
    check(
        "每一行都在分组标题之下、没有任何一行留在折叠区",
        all(not b.get("inDetails") for b in buttons),
        [b for b in buttons if b.get("inDetails")][:3],
    )
    assert_copy(ws, snap, check)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def unique_dir(base: Path, name: str) -> Path:
    """给这一轮挑一个**没人用过**的数据根。

    不用 `rmtree` 清理旧根：WebView2 的用户数据目录一次就有几百个文件，
    整树删除既慢又容易误伤别的东西（同一台机器上还装着一个用户的实例）。
    换一个名字是零风险的做法，旧证据留在原地反而好对照。
    """
    for suffix in range(1, 100):
        candidate = base / (name if suffix == 1 else f"{name}-{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"{base} 下 {name} 这一档已经用满 100 个，换一个 --work")


def run_case(
    name: str,
    exe: Path,
    builtin: list[str],
    args,
    checker: Checker,
    report: dict,
    spawned: list[int],
) -> None:
    work = unique_dir(args.work, name)
    case_dir = args.report_dir / name
    case_dir.mkdir(parents=True, exist_ok=True)
    seed(work, builtin)
    report.setdefault("workRoots", {})[name] = str(work)

    def check(label: str, ok: bool, detail: object = None) -> None:
        checker.check(f"[{name}] {label}", ok, detail)

    process = None
    ws = None
    try:
        process, _port, ws = t11.launch(exe, work, case_dir, name)
        spawned.append(process.pid)
        pump = t11.Pump(process.pid)
        opened, why = open_agents(ws, pump)
        check("打开 AI 工具名单", opened, why)
        if not opened:
            report["cases"][name] = {"error": why, "layout": brief(page_snapshot(ws))}
            return
        shots: list[str] = []
        payload = {"steps": []}
        report["cases"][name] = payload
        if name == "empty":
            case_empty(ws, pump, check, payload, shots, args.report_dir)
        elif name == "partial":
            case_partial(ws, pump, check, payload, shots, args.report_dir, work)
        else:
            case_full(ws, pump, check, payload, shots, args.report_dir)
        payload["shots"] = shots
        report["shots"].extend(shots)
    except Exception as error:  # noqa: BLE001
        print(f"[probe] {name} 失败：{error}", flush=True)
        report["cases"].setdefault(name, {})["error"] = repr(error)
        check(f"{name} 这一个状态整体跑完（无异常）", False, repr(error))
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=12)
            except Exception:  # noqa: BLE001
                process.kill()


def running_pids() -> list[int]:
    try:
        output = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-Process spidervpn -ErrorAction SilentlyContinue).Id -join ','"],
            capture_output=True,
            text=True,
            timeout=25,
        ).stdout.strip()
    except Exception:  # noqa: BLE001
        return []
    return [int(part) for part in re.findall(r"\d+", output)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    args.report_dir = Path(args.report_dir).resolve()
    args.work = Path(args.work).resolve()
    args.report_dir.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)

    exe_sha, exe_bytes = sha256_file(exe)
    checker = Checker()
    report: dict = {
        "mode": "r104-agents-layout",
        "exe": str(exe),
        "exeSha256": exe_sha,
        "exeBytes": exe_bytes,
        "shots": [],
        "cases": {},
    }
    spawned: list[int] = []
    code = 0
    try:
        # 三种状态各自一份种子、各自一次启动：状态之间没有任何继承。
        run_case("empty", exe, [], args, checker, report, spawned)
        run_case("partial", exe, ["claude-code", "cursor"], args, checker, report, spawned)
        run_case("full", exe, list(ALL_BUILTIN), args, checker, report, spawned)
    finally:
        # 跑后重新算一次被测文件：验的和报的必须是同一个 exe（r101 的教训）。
        try:
            after_sha, after_bytes = sha256_file(exe)
        except Exception as error:  # noqa: BLE001
            after_sha, after_bytes = f"<{error!r}>", -1
        report["exeSha256After"] = after_sha
        report["exeBytesAfter"] = after_bytes
        report["exeUnchanged"] = after_sha == exe_sha and after_bytes == exe_bytes
        checker.check(
            "被测 exe 跑前跑后一致",
            report["exeUnchanged"],
            {"before": exe_sha, "bytesBefore": exe_bytes,
             "after": after_sha, "bytesAfter": after_bytes},
        )

        # 只认自己 spawn 的 pid：用户装机的实例（如果开着）一概不碰。
        still = running_pids()
        leftovers = sorted(set(still) & set(spawned))
        report["spawnedPids"] = spawned
        report["residualSpawnedPids"] = leftovers
        report["otherTradeChannelPids"] = sorted(set(still) - set(spawned))
        checker.check(
            "本脚本启动的宿主进程全部退出（无残留）",
            not leftovers,
            {"leftover": leftovers, "othersStillRunning": report["otherTradeChannelPids"]},
        )

        report["checks"] = checker.checks
        report["passed"] = sum(1 for item in checker.checks if item["ok"])
        report["failed"] = sum(1 for item in checker.checks if not item["ok"])
        (args.report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(checker.checks, ensure_ascii=False, indent=2), flush=True)
        print(
            f"[probe] {report['passed']} passed / {report['failed']} failed; "
            f"exe={exe_sha[:12]}…; evidence={args.report_dir}",
            flush=True,
        )
        code = 0 if checker.all_passed else 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())
