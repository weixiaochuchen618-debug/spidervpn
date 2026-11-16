#!/usr/bin/env python3
"""r103 界面验收：AI 工具名单「每行一颗添加/移除按钮 + 域名挂 ⓘ」。

r103 相对 r102 的形状变化（本脚本只验 r103，不再兼容 r102 的复选框/抽屉）：

    选择要跟随线路的工具，改完点保存，一次生效。      ← 页头改「选择」，不再说「勾选」
    [添加常用 AI 工具]                                ← 一键按钮改名
    桌面程序 / 网页版 / 模型 API 与下载平台
        名称（运行中/已安装）  ⓘ                     ← 域名全文在 Hint 上，悬停才展开
                                          [添加/移除] ← 一行一颗按钮，没有勾选框
    自定义
        r103.example · 所有程序访问它都随名单  [移除]  ← 同一形状；行按「基线 ∪ 草稿」列出
    [添加网址] [添加程序…]
    保存 / 放弃修改 / 返回                            ← 一次保存 = 一条 agents-save（全量）

被测对象是**真机**（exe + WebView2 + 真实 config.json）。脚本在跑前跑后各算一次
exe 的 sha256/字节数：任何一次不一致都判 FAIL（r101 的教训：验的和装的不是同一个文件）。

用法：
  python tests/r103_agents_rows.py --exe C:\\tc-rs-build\\debug\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r103-agents --work D:\\vpn构建\\reports-tmp\\r103-agents\\root

反向对照（应大面积红）：
  python tests/r103_agents_rows.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r103-agents-r102 --work D:\\vpn构建\\reports-tmp\\r103-agents-r102\\root
"""
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import re
import shutil
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

HEADER = "选择要跟随线路的工具，改完点保存，一次生效。"
GONE_HEADER = "勾选要跟随线路"
CUSTOM_SITE = "r103.example"

# 计数/取文本的小工具全部走 JS：页面是宿主每帧重画出来的，
# 只有 DOM 是唯一可信的观测面（不看源码、不看单测）。
JS_BUTTONS = "Array.from(document.querySelectorAll('#main [data-wf^=\"builtin-\"]'))"
JS_COUNTS = (
    "(()=>({checkbox:document.querySelectorAll('#main input[type=checkbox]').length,"
    "details:document.querySelectorAll('#main details').length,"
    "buttons:%s.length,"
    "hints:document.querySelectorAll('#main [data-hint^=\"包含的网站：\"]').length}))()" % JS_BUTTONS
)


def sha256_file(path: Path) -> tuple[str, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data)


def js_str(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def seed(work: Path) -> None:
    data = work / "data"
    data.mkdir(parents=True, exist_ok=True)
    config = {
        "schema": 2,
        "selected": "L1",
        "lines": [{"id": "L1", "name": "线路甲", "proxy_endpoint": "127.0.0.1:17901"}],
        "split": {"processes": [], "domains": []},
        "agents": {"lane": "daily", "builtin": [], "programs": [], "sites": []},
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


def button_text(ws, control_id: str) -> str:
    return str(
        ws.evaluate(
            "(()=>{const e=document.querySelector('#main [data-wf=%s]');"
            "return e?e.textContent.trim():'';})()" % js_str(control_id)
        )
        or ""
    )


def wrap_post(ws) -> None:
    """把 `chrome.webview.postMessage` 包一层计数。

    页面自己的 `post()` 每次现取这个函数，所以包完立即生效；`postMessage` 是页面
    唯一的出口（宿主收字符串 JSON，见 app.js 顶部注释）。
    """
    ws.evaluate(
        "(()=>{window.__tcPosted=[];const w=window.chrome&&window.chrome.webview;"
        "if(!w||w.__wrapped)return false;const orig=w.postMessage.bind(w);w.__wrapped=true;"
        "w.postMessage=m=>{try{window.__tcPosted.push(typeof m==='string'?m:JSON.stringify(m));}"
        "catch(_){window.__tcPosted.push('<<unserializable>>');}return orig(m);};"
        "return true;})()"
    )


def posted_since(ws, mark: int) -> list[dict]:
    raw = ws.evaluate(
        "((window.__tcPosted||[]).slice(%d)).map(s=>{try{return JSON.parse(s)}catch(_){return {raw:s}}})"
        % mark
    ) or []
    return [item if isinstance(item, dict) else {"raw": str(item)} for item in raw]


def posted_mark(ws) -> int:
    return int(ws.evaluate("(window.__tcPosted||[]).length") or 0)


def capture_snapshots(ws) -> None:
    """在 app.js 的消息监听之外再挂一个监听，把宿主下发的快照留一份。

    只用来在报告里留「宿主真实输出」的证据（也用来核对 `form_fixtures.py` 那份静态
    快照有多旧）；不参与任何断言。
    """
    ws.evaluate(
        "(()=>{window.__tcMsgs=[];window.__tcMsgCount=0;const w=window.chrome&&window.chrome.webview;"
        "if(!w||w.__msgHooked)return false;w.__msgHooked=true;"
        "w.addEventListener('message',e=>{try{const d=e.data;window.__tcMsgCount++;"
        "window.__tcMsgs.push(typeof d==='string'?d:JSON.stringify(d));"
        "if(window.__tcMsgs.length>60)window.__tcMsgs.shift();}catch(_){}});return true;})()"
    )


def host_form_probe(ws, node_id: str) -> dict:
    """从**宿主下发的快照**里读一个节点的 Value + 当前 Form.Generation。

    这是宿主的真相，不是 DOM 的回显：输入框里留着用户敲的字，宿主草稿却可能因为
    `Generation` 闸门丢掉这条 `change`（见 `set_site_draft`）。
    """
    raw = ws.evaluate(
        "(()=>{const all=window.__tcMsgs||[];"
        "for(let i=all.length-1;i>=0;i--){let m;try{m=JSON.parse(all[i]);}catch(_){continue;}"
        "if(!(m&&m.Type==='snapshot'&&m.State&&m.State.Form))continue;"
        "const f=m.State.Form;if(f.ViewKey!=='agents')continue;"
        "const walk=n=>{if(!n||typeof n!=='object')return undefined;"
        "if(Array.isArray(n)){for(const c of n){const r=walk(c);"
        "if(r!==undefined)return r;}return undefined;}"
        "if(n.Id===%s)return n.Value;"
        "for(const k of ['Children','Nodes','PageActions']){const v=n[k];"
        "if(Array.isArray(v)){for(const c of v){const r=walk(c);"
        "if(r!==undefined)return r;}}}return undefined;};"
        "return JSON.stringify({generation:f.Generation,value:walk(f.Nodes)});}"
        "return '';})()" % js_str(node_id)
    )
    if not raw:
        return {}
    try:
        return json.loads(str(raw))
    except Exception:  # noqa: BLE001
        return {}


def settle(ws, pump, quiet: float = 0.7, seconds: float = 8.0) -> str:
    """等 #main 重画完，返回稳定后的 workflow 文本。

    宿主的回包到前端重画之间有几百毫秒；点完立刻读 innerText 会读到**上一版**，
    断言就会建立在过期文本上（r103 第一版脚本在这里把「行已消失」读成了「行还在」）。
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


def msg_count(ws) -> int:
    return int(ws.evaluate("window.__tcMsgCount||0") or 0)


def wait_new_snapshot(ws, pump, before: int, seconds: float = 4.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if msg_count(ws) > before:
            return True
        pump.tick()
        time.sleep(0.15)
    return False


def set_site_draft(ws, pump, value: str, attempts: int = 5) -> int:
    """把网址写进宿主草稿，直到宿主快照里真的出现这个值；返回尝试次数。

    为什么要重试：宿主会丢弃 `Generation` 对不上的字段编辑（`reject_inbound`）。
    保存/重画之后页面手里的那一代可能还是旧的，第一次 `change` 就被静默丢掉；
    心跳快照一到，页面拿到新一代，第二次就一定成功。真人不会踩这个窗口，
    但脚本会——这里用「宿主快照里的 Value」当验收口径，而不是 DOM 里那句回显。
    """
    for attempt in range(1, attempts + 1):
        before = msg_count(ws)
        ws.evaluate(
            "(()=>{const e=document.getElementById('wf-site');if(!e)return false;e.value=%s;"
            "e.dispatchEvent(new Event('input',{bubbles:true}));return true;})()" % js_str(value)
        )
        wait_new_snapshot(ws, pump, before)
        probe = host_form_probe(ws, "site")
        if str(probe.get("value") or "") == value:
            return attempt
    return attempts + 1


def agents_form_snapshot(ws) -> dict | None:
    raw = ws.evaluate(
        "(()=>{const all=window.__tcMsgs||[];"
        "for(let i=all.length-1;i>=0;i--){let m;try{m=JSON.parse(all[i]);}catch(_){continue;}"
        "if(m&&m.Type==='snapshot'&&m.State&&m.State.Form&&m.State.Form.ViewKey==='agents')"
        "return JSON.stringify(m.State.Form);}"
        "return '';})()"
    )
    if not raw:
        return None
    try:
        return json.loads(str(raw))
    except Exception:  # noqa: BLE001
        return None


def hint_point(ws, needle: str) -> dict | None:
    """把含 needle 的那颗 ⓘ 滚到视口中间，返回它的中心点（CSS 像素）。"""
    point = ws.evaluate(
        "(()=>{const hs=Array.from(document.querySelectorAll('#main [data-hint^=\"包含的网站：\"]'));"
        "const h=hs.find(e=>(e.dataset.hint||'').includes(%s));if(!h)return null;"
        "h.scrollIntoView({block:'center'});const r=h.getBoundingClientRect();"
        "return {x:r.left+r.width/2,y:r.top+r.height/2,w:r.width,h:r.height};})()" % js_str(needle)
    )
    return point if isinstance(point, dict) else None


def hover_open(ws, pump, needle: str) -> str:
    """真的把鼠标移到 ⓘ 上（CDP Input.dispatchMouseEvent）；返回方式是 input/js/none。

    先把指针挪到别处（关掉上一颗气泡），再移到目标点上并停住——`hintLayer.open`
    有 300ms 的悬停延迟，所以这里要等，不是读一下 `data-hint` 就算验完。
    """
    point = hint_point(ws, needle)
    if not point:
        return "none"
    cx, cy = float(point["x"]), float(point["y"])
    try:
        ws.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": 4, "y": 4, "buttons": 0})
        pump.tick()
        time.sleep(0.2)
        for step in range(3):
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
    # 退路：JS 派发 mouseover/s 走的是同一条 `hintLayer.open` 路径（只有 300ms 定时器）。
    ws.evaluate(
        "(()=>{const hs=Array.from(document.querySelectorAll('#main [data-hint^=\"包含的网站：\"]'));"
        "const h=hs.find(e=>(e.dataset.hint||'').includes(%s));if(!h)return false;"
        "h.dispatchEvent(new MouseEvent('mouseover',{bubbles:true}));return true;})()" % js_str(needle)
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    exe_sha, exe_bytes = sha256_file(exe)
    checker = Checker()
    report: dict = {
        "mode": "r103-agents-rows",
        "exe": str(exe),
        "exeSha256": exe_sha,
        "exeBytes": exe_bytes,
        "checks": [],
    }
    process = None
    code = 0
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "r103")
        pump = t11.Pump(process.pid)
        shots: list[str] = []

        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            "",
        )
        capture_snapshots(ws)
        checker.check("进应用", r87.click_when_enabled(ws, pump, "nav [data-page=apps]") == "ok", "")
        opened = r87.click_when_enabled(ws, pump, "#main [data-action=agentsList]") == "ok"
        checker.check(
            "打开 AI 工具名单",
            opened
            and helpers.wait_js(
                ws,
                "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
                "return t.includes('AI 工具名单')&&t.includes(%s);})()" % js_str("改完点保存，一次生效"),
                25,
                "名单页",
                pump,
            ),
            r87.body_text(ws)[-200:],
        )

        body = str(ws.evaluate("document.querySelector('#main').innerText") or "")
        workflow = str(ws.evaluate("document.querySelector('#main .workflow').innerText") or "")
        counts = ws.evaluate(JS_COUNTS) or {}
        report["counts"] = counts
        buttons = (
            ws.evaluate("%s.map(b=>({id:b.dataset.wf,text:b.textContent.trim()}))" % JS_BUTTONS)
            or []
        )
        report["builtinButtons"] = buttons

        # ① 没有勾选框、没有折叠抽屉
        checker.check("①-a #main 里没有复选框", int(counts.get("checkbox", -1)) == 0, counts)
        checker.check("①-b #main 里没有 <details>", int(counts.get("details", -1)) == 0, counts)

        # ② 22 行，各一颗 [data-wf^=builtin-] 按钮，初始全为「添加」
        ids = [item.get("id") for item in buttons]
        texts = [item.get("text") for item in buttons]
        checker.check(
            "②-a 22 颗内置项按钮（一颗不多一颗不少）",
            len(buttons) == 22,
            {"count": len(buttons), "ids": ids},
        )
        checker.check(
            "②-b 每颗按钮的 data-wf 都是唯一的 builtin-<id>",
            len(set(ids)) == len(ids) and all(str(i).startswith("builtin-") for i in ids),
            ids,
        )
        checker.check(
            "②-c 初始 22 行全部写「添加」",
            len(texts) == 22 and all(t == "添加" for t in texts),
            texts,
        )

        # ⑦ 页头文案
        checker.check(
            "⑦-a 页头写着「选择要跟随线路的工具，改完点保存，一次生效。」",
            HEADER in workflow,
            [line for line in workflow.splitlines() if "跟随线路" in line][:3],
        )
        checker.check(
            "⑦-b 全页不再出现「勾选要跟随线路」",
            GONE_HEADER not in body and GONE_HEADER not in workflow,
            {"body": GONE_HEADER in body, "workflow": GONE_HEADER in workflow},
        )
        checker.check(
            "⑦-c 一键按钮叫「添加常用 AI 工具」",
            "添加常用 AI 工具" in workflow and bool(ws.evaluate("!!document.querySelector('#main [data-wf=recommend]')")),
            [line for line in workflow.splitlines() if "常用 AI" in line][:3],
        )

        # ⑧ 域名在 Hint 上，正文里没有
        hints = [
            str(x)
            for x in (
                ws.evaluate(
                    "Array.from(document.querySelectorAll('#main [data-hint^=\"包含的网站：\"]'))"
                    ".map(e=>e.dataset.hint)"
                )
                or []
            )
        ]
        report["domainHints"] = hints[:4]
        checker.check("⑧-a 正文里不再有「包含的网站」", "包含的网站" not in workflow,
                      [line for line in workflow.splitlines() if "包含的网站" in line][:3])
        checker.check(
            "⑧-b [data-hint^=\"包含的网站：\"] 存在且不截断（无省略号、以完整域名收尾、含 cursor.com）",
            any(h.startswith("包含的网站：") and "cursor.com" in h for h in hints)
            and all(
                h.startswith("包含的网站：")
                and "…" not in h
                and "." in h.split("：", 1)[-1]
                # 截断会切在域名中间：完整的清单一定以「.字母」收尾
                and re.search(r"\.[a-z]{2,}$", h.strip()) is not None
                for h in hints
            ),
            hints[:3],
        )
        checker.check(
            "⑧-c 每颗 ⓘ 都挂在同一条目的名称文本行上（不是孤零零一个）",
            int(counts.get("hints", 0)) >= 10
            and bool(
                ws.evaluate(
                    "Array.from(document.querySelectorAll('#main [data-hint^=\"包含的网站：\"]'))"
                    ".every(h=>{const row=h.closest('.wf-row');"
                    "return !!row&&!!row.querySelector('.wf-text');})"
                )
            ),
            {"hints": counts.get("hints")},
        )

        # ⑨ 真的悬停：鼠标移到 ⓘ 上，#hint-layer 出现并带域名
        way = hover_open(ws, pump, "cursor.com")
        layer = ws.evaluate(
            "(()=>{const l=document.getElementById('hint-layer');"
            "return l?{hidden:!!l.hidden,text:l.textContent,popover:l.getAttribute('popover')}:null;})()"
        ) or {}
        report["hover"] = {"method": way, "layer": layer}
        checker.check(
            "⑨ 鼠标移到 ⓘ 上，气泡层出现且含域名",
            way != "none"
            and not layer.get("hidden", True)
            and "包含的网站：" in str(layer.get("text", ""))
            and "cursor.com" in str(layer.get("text", "")),
            {"method": way, "layer": layer},
        )
        helpers.screenshot(ws, report_dir / "02-hover-hint.png", shots)
        report["shots"] = shots

        # ③ 点「添加」只改草稿：文案翻成「移除」，不发命令、不写配置
        wrap_post(ws)
        mark = posted_mark(ws)
        before = config_bytes(work)
        clicked = r87.click_when_enabled(ws, pump, "#main [data-wf=builtin-cursor]")
        toggled = helpers.wait_js(
            ws,
            "(()=>{const e=document.querySelector('#main [data-wf=builtin-cursor]');"
            "return !!e&&e.textContent.trim()==='移除';})()",
            15,
            "按钮翻成移除",
            pump,
        )
        time.sleep(0.6)
        posted = posted_since(ws, mark)
        report["togglePosted"] = posted
        checker.check(
            "③-a 点「添加」后同一颗按钮变成「移除」",
            clicked == "ok" and toggled,
            {"click": clicked, "text": button_text(ws, "builtin-cursor")},
        )
        checker.check(
            "③-b 这一下只回传一条 form 点击，没有任何 save/命令",
            len(posted) == 1
            and posted[0].get("Type") == "form"
            and posted[0].get("Id") == "builtin-cursor"
            and not any(m.get("Id") == "save" or "agents-save" in json.dumps(m) for m in posted),
            posted,
        )
        checker.check(
            "③-c 此时 config.json 逐字节未变（草稿只在宿主内存）",
            config_bytes(work) == before,
            config_agents(work),
        )

        # ④ 保存：恰一条 save，落盘含该 id
        mark = posted_mark(ws)
        checker.check("④-a 点保存", r87.click_when_enabled(ws, pump, "#main [data-wf=save]") == "ok", "")
        helpers.wait_js(
            ws,
            "(document.querySelector('#main [data-wf=save]')||{disabled:true}).disabled===true",
            25,
            "保存完成",
            pump,
        )
        time.sleep(1.2)
        posted = posted_since(ws, mark)
        saves = [m for m in posted if m.get("Id") == "save"]
        agents = config_agents(work)
        report["afterFirstSave"] = agents
        checker.check("④-b 一次保存只发一条 save", len(saves) == 1, posted)
        checker.check(
            "④-c config.json 的 agents.builtin 里有 cursor",
            "cursor" in (agents.get("builtin") or []),
            agents,
        )

        # ⑤ 再加一项保存 → 两项都在；把 cursor 移除保存 → 只剩另一项
        r87.click_when_enabled(ws, pump, "#main [data-wf=builtin-claude-code]")
        helpers.wait_js(
            ws,
            "(()=>{const e=document.querySelector('#main [data-wf=builtin-claude-code]');"
            "return !!e&&e.textContent.trim()==='移除';})()",
            15,
            "第二项加进草稿",
            pump,
        )
        r87.click_when_enabled(ws, pump, "#main [data-wf=save]")
        helpers.wait_js(
            ws,
            "(document.querySelector('#main [data-wf=save]')||{disabled:true}).disabled===true",
            25,
            "第二次保存完成",
            pump,
        )
        time.sleep(1.0)
        both = config_agents(work)
        checker.check(
            "⑤-a 两项都加后保存：builtin 里 cursor 与 claude-code 都在",
            {"cursor", "claude-code"}.issubset({str(x) for x in (both.get("builtin") or [])}),
            both.get("builtin"),
        )

        clicked = r87.click_when_enabled(ws, pump, "#main [data-wf=builtin-cursor]")
        flipped = helpers.wait_js(
            ws,
            "(()=>{const e=document.querySelector('#main [data-wf=builtin-cursor]');"
            "return !!e&&e.textContent.trim()==='添加';})()",
            15,
            "按钮翻回添加",
            pump,
        )
        checker.check(
            "⑤-b 再点同一行变成「添加」",
            clicked == "ok" and flipped,
            button_text(ws, "builtin-cursor"),
        )
        mark = posted_mark(ws)
        r87.click_when_enabled(ws, pump, "#main [data-wf=save]")
        helpers.wait_js(
            ws,
            "(document.querySelector('#main [data-wf=save]')||{disabled:true}).disabled===true",
            25,
            "第三次保存完成",
            pump,
        )
        time.sleep(1.0)
        after_remove = config_agents(work)
        report["afterRemove"] = after_remove
        builtin_now = [str(x) for x in (after_remove.get("builtin") or [])]
        checker.check(
            "⑤-c 保存后 cursor 消失、claude-code 还在",
            "cursor" not in builtin_now and "claude-code" in builtin_now,
            builtin_now,
        )
        checker.check(
            "⑤-d 移除后保存同样只发一条 save",
            len([m for m in posted_since(ws, mark) if m.get("Id") == "save"]) == 1,
            posted_since(ws, mark),
        )

        # ⑥ 自定义网站
        # ⑥-1 刚加进草稿（还没保存过）的自定义网址：行出现，按钮「移除」
        attempts = set_site_draft(ws, pump, CUSTOM_SITE)
        set_ok = str(host_form_probe(ws, "site").get("value") or "")
        report["siteDraft"] = {"attempts": attempts, "hostValue": set_ok}
        checker.check("⑥-a 点「添加网址」", r87.click_when_enabled(ws, pump, "#main [data-wf=add-site]") == "ok", "")
        time.sleep(1.2)
        report["afterAddSiteText"] = str(
            ws.evaluate("document.querySelector('#main .workflow').innerText") or ""
        )[-400:]
        appeared = helpers.wait_js(
            ws,
            "(()=>{const rows=Array.from(document.querySelectorAll('#main .wf-row'));"
            "const row=rows.find(r=>r.textContent.includes(%s));"
            "if(!row)return false;const b=row.querySelector('[data-wf^=\"toggle-site-\"]');"
            "return !!b&&b.textContent.trim()==='移除';})()" % js_str(CUSTOM_SITE),
            15,
            "自定义行出现且写移除",
            pump,
        )
        checker.check(
            "⑥-b 自定义行出现，按钮是「移除」",
            appeared,
            {"input": set_ok, "tail": report["afterAddSiteText"]},
        )

        def custom_toggle_id() -> str:
            return str(
                ws.evaluate(
                    "(()=>{const rows=Array.from(document.querySelectorAll('#main .wf-row'));"
                    "const row=rows.find(r=>r.textContent.includes(%s));"
                    "const b=row&&row.querySelector('[data-wf^=\"toggle-site-\"]');"
                    "return b?b.dataset.wf:'';})()" % js_str(CUSTOM_SITE)
                )
                or ""
            )

        # ⑥-2 草稿里刚加（还没保存过）的网址再点「移除」：r103 修好后**行留在原处**，
        #      按钮翻回「添加」，还能原路加回来（`agents_seen` 记住本轮见过的值）。
        toggle_id = custom_toggle_id()
        report["customToggle"] = toggle_id
        mark = posted_mark(ws)
        if toggle_id:
            r87.click_when_enabled(ws, pump, "#main [data-wf=%s]" % toggle_id)
        flipped_back = helpers.wait_js(
            ws,
            "(()=>{const rows=Array.from(document.querySelectorAll('#main .wf-row'));"
            "const row=rows.find(r=>r.textContent.includes(%s));"
            "if(!row)return false;const b=row.querySelector('[data-wf^=\"toggle-site-\"]');"
            "return !!b&&b.textContent.trim()==='添加';})()" % js_str(CUSTOM_SITE),
            20,
            "移除后行还在且写添加",
            pump,
        )
        after_remove_draft = settle(ws, pump)
        report["customRemovePosted"] = posted_since(ws, mark)
        still_there = CUSTOM_SITE in after_remove_draft
        report["afterRemoveDraftOnly"] = after_remove_draft[-260:]
        # 截图要真的拍到那一行：先关掉上一轮还开着的 ⓘ（测试里悬停过），再把自定义行滚到中间。
        # **不要用 Escape**：表单页上的 Esc 是「返回上一页」（app.js 把 .breadcrumb 按钮点了），
        # 一整页会被关掉。用 mouseout 走 hintLayer 自己的 150ms 收起路径。
        ws.evaluate(
            "(()=>{document.querySelectorAll('#main .hint').forEach(h=>"
            "h.dispatchEvent(new MouseEvent('mouseout',{bubbles:true})));"
            "const rows=Array.from(document.querySelectorAll('#main .wf-row'));"
            "const row=rows.find(r=>r.textContent.includes(%s));"
            "if(row)row.scrollIntoView({block:'center'});return !!row;})()" % js_str(CUSTOM_SITE)
        )
        time.sleep(0.8)
        helpers.screenshot(ws, report_dir / "03-custom-after-remove.png", shots)
        checker.check(
            "⑥-c 草稿里新加的网址，点「移除」后行还在、按钮翻成「添加」",
            still_there and flipped_back,
            {
                "rowStillRendered": still_there,
                "button": button_text(ws, toggle_id) if toggle_id else "",
                "toggleId": custom_toggle_id(),
                "tail": report["afterRemoveDraftOnly"],
            },
        )

        # ⑥-3 重新加回来并保存：sites 里正好一条
        mark = posted_mark(ws)
        readd_attempts = set_site_draft(ws, pump, CUSTOM_SITE)
        readd_click = r87.click_when_enabled(ws, pump, "#main [data-wf=add-site]")
        helpers.wait_js(
            ws,
            "(()=>{const rows=Array.from(document.querySelectorAll('#main .wf-row'));"
            "const row=rows.find(r=>r.textContent.includes(%s));"
            "if(!row)return false;const b=row.querySelector('[data-wf^=\"toggle-site-\"]');"
            "return !!b&&b.textContent.trim()==='移除';})()" % js_str(CUSTOM_SITE),
            15,
            "自定义行回来且写移除",
            pump,
        )
        report["readd"] = {
            "attempts": readd_attempts,
            "click": readd_click,
            "posted": posted_since(ws, mark),
            "tail": settle(ws, pump)[-200:],
        }
        r87.click_when_enabled(ws, pump, "#main [data-wf=save]")
        helpers.wait_js(
            ws,
            "(document.querySelector('#main [data-wf=save]')||{disabled:true}).disabled===true",
            25,
            "第四次保存完成",
            pump,
        )
        time.sleep(1.0)
        saved = config_agents(work)
        sites = [str(x) for x in (saved.get("sites") or [])]
        report["afterCustomSave"] = saved
        checker.check(
            "⑥-d 保存后 agents.sites 里正好一条 %s" % CUSTOM_SITE,
            sites == [CUSTOM_SITE],
            sites,
        )

        # ⑥-4 已经在基线里的自定义网址：移除后行还在、按钮翻成「添加」，再点回来
        toggle_id = custom_toggle_id()
        report["customToggleSaved"] = toggle_id
        if toggle_id:
            r87.click_when_enabled(ws, pump, "#main [data-wf=%s]" % toggle_id)
            back = helpers.wait_js(
                ws,
                "(()=>{const e=document.querySelector('#main [data-wf=%s]');"
                "return !!e&&e.textContent.trim()==='添加';})()" % js_str(toggle_id),
                15,
                "已保存的自定义行翻成添加",
                pump,
            )
            checker.check(
                "⑥-e 已保存过的自定义网址：点「移除」→ 行还在、按钮变「添加」",
                back,
                {"id": toggle_id, "text": button_text(ws, toggle_id)},
            )
            r87.click_when_enabled(ws, pump, "#main [data-wf=%s]" % toggle_id)
            again = helpers.wait_js(
                ws,
                "(()=>{const e=document.querySelector('#main [data-wf=%s]');"
                "return !!e&&e.textContent.trim()==='移除';})()" % js_str(toggle_id),
                15,
                "自定义行翻回移除",
                pump,
            )
            checker.check("⑥-f 再点「添加」→ 按钮变回「移除」", again, button_text(ws, toggle_id))
            r87.click_when_enabled(ws, pump, "#main [data-wf=save]")
            helpers.wait_js(
                ws,
                "(document.querySelector('#main [data-wf=save]')||{disabled:true}).disabled===true",
                25,
                "第五次保存完成",
                pump,
            )
            time.sleep(1.0)
            sites_after = [str(x) for x in (config_agents(work).get("sites") or [])]
            report["afterCustomToggleSave"] = sites_after
            checker.check(
                "⑥-g 移除后加回来再保存，sites 仍然正好一条",
                sites_after == [CUSTOM_SITE],
                sites_after,
            )

            # ⑥-h 保存后不留幽灵行：把这条已保存的移除并保存，`agents_seen` 随回包清空，
            #      页面上不该再有这个域名的行（行该跟着基线一起消失，不是靠记忆撑着）。
            toggle_id = custom_toggle_id()
            r87.click_when_enabled(ws, pump, "#main [data-wf=%s]" % toggle_id)
            helpers.wait_js(
                ws,
                "(()=>{const e=document.querySelector('#main [data-wf=%s]');"
                "return !!e&&e.textContent.trim()==='添加';})()" % js_str(toggle_id),
                15,
                "幽灵行前：按钮变添加",
                pump,
            )
            r87.click_when_enabled(ws, pump, "#main [data-wf=save]")
            # 保存按钮的 disabled 既可能是「忙」（刚点下去），也可能是「已保存」：
            # 只等 disabled 会在忙态就返回，读到的是保存回包落地**之前**的页面。
            # 所以这里盯的是「那一行真的没了」，并把过程记成时间线（幽灵行会一直在）。
            timeline: list[dict] = []
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                state = ws.evaluate(
                    "(()=>{const t=(document.querySelector('#main .workflow')||{}).innerText||'';"
                    "const line=(t.split('\\n').find(s=>s.includes('已保存'))||'').slice(0,24);"
                    "return JSON.stringify({row:t.includes(%s),dirty:t.includes('已改'),"
                    "saved:!!line,note:line});})()" % js_str(CUSTOM_SITE)
                )
                entry = json.loads(str(state) or "{}")
                entry["t"] = round(time.monotonic() - (deadline - 20), 2)
                timeline.append(entry)
                if not entry.get("row") and entry.get("saved"):
                    break
                pump.tick()
                time.sleep(0.3)
            ghost_text = settle(ws, pump)
            ghost_sites = [str(x) for x in (config_agents(work).get("sites") or [])]
            report["ghostCheck"] = {
                "sites": ghost_sites,
                "tail": ghost_text[-200:],
                "rowSeenSeconds": [e["t"] for e in timeline if e.get("row")][-1:] or [],
                "timelineTail": timeline[-6:],
                "firstNoRow": next((e for e in timeline if not e.get("row")), None),
            }
            checker.check(
                "⑥-h 移除后保存：sites 里没了，页面上也没有幽灵行",
                ghost_sites == [] and CUSTOM_SITE not in ghost_text and not custom_toggle_id(),
                {"sites": ghost_sites, "row": CUSTOM_SITE in ghost_text,
                 "toggleId": custom_toggle_id(), "tail": ghost_text[-200:],
                 "timeline": timeline[-6:]},
            )
        else:
            checker.check("⑥-e 已保存过的自定义网址：点「移除」→ 行还在、按钮变「添加」", False, "找不到按钮")
            checker.check("⑥-f 再点「添加」→ 按钮变回「移除」", False, "找不到按钮")
            checker.check("⑥-g 移除后加回来再保存，sites 仍然正好一条", False, "找不到按钮")
            checker.check("⑥-h 移除后保存：sites 里没了，页面上也没有幽灵行", False, "找不到按钮")

        # ⑩ 放弃修改：把草稿改乱，再还原成「上次保存的样子」
        before_discard = config_bytes(work)
        r87.click_when_enabled(ws, pump, "#main [data-wf=recommend]")
        helpers.wait_js(
            ws,
            "%s.filter(b=>b.textContent.trim()==='移除').length===22" % JS_BUTTONS,
            20,
            "一键添加全量",
            pump,
        )
        discard_click = r87.click_when_enabled(ws, pump, "#main [data-wf=discard]")
        restored = helpers.wait_js(
            ws,
            "(()=>{const btn=Array.from(document.querySelectorAll('#main [data-wf^=\"builtin-\"]'))"
            ".map(b=>[b.dataset.wf,b.textContent.trim()]);"
            "if(btn.length!==22)return false;"
            "const removed=btn.filter(([id,t])=>t==='移除').map(([id])=>id);"
            "return removed.length===1&&removed[0]==='builtin-claude-code';})()",
            25,
            "放弃修改后按钮还原",
            pump,
        )
        final_text = ws.evaluate(
            "%s.map(b=>({id:b.dataset.wf,text:b.textContent.trim()}))" % JS_BUTTONS
        ) or []
        report["afterDiscard"] = final_text
        checker.check(
            "⑩-a 「放弃修改」把按钮文案还原（只剩已保存的 claude-code 是「移除」）",
            discard_click == "ok" and restored,
            [item for item in final_text if item.get("text") != "添加"][:3],
        )
        checker.check(
            "⑩-b 「放弃修改」不写配置（config.json 逐字节未变）",
            config_bytes(work) == before_discard,
            config_agents(work),
        )

        snapshot = agents_form_snapshot(ws)
        if snapshot:
            (report_dir / "agents-form-from-host.json").write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
            )
            report["hostFormSnapshot"] = "agents-form-from-host.json"

        helpers.screenshot(ws, report_dir / "01-agents-final.png", shots)
        report["shots"] = shots
        report["checks"] = checker.checks
        code = 0 if checker.all_passed else 1
    except Exception as error:  # noqa: BLE001
        print(f"[probe] 失败：{error}", flush=True)
        report["error"] = repr(error)
        code = 2
    finally:
        if process and not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        # 跑后重新算一次被测文件：验的和报的必须是同一个 exe（r101 的教训）。
        try:
            after_sha, after_bytes = sha256_file(exe)
        except Exception as error:  # noqa: BLE001
            after_sha, after_bytes = f"<{error!r}>", -1
        report["exeSha256After"] = after_sha
        report["exeBytesAfter"] = after_bytes
        report["exeUnchanged"] = after_sha == report["exeSha256"] and after_bytes == report["exeBytes"]
        if not report["exeUnchanged"]:
            checker.check("被测 exe 跑前跑后一致", False,
                          {"before": report["exeSha256"], "after": after_sha})
            code = 1
        else:
            checker.check("被测 exe 跑前跑后一致", True, {"sha256": after_sha, "bytes": after_bytes})
        report["checks"] = checker.checks
        report["passed"] = sum(1 for item in checker.checks if item["ok"])
        report["failed"] = sum(1 for item in checker.checks if not item["ok"])
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(report.get("checks", []), ensure_ascii=False, indent=2), flush=True)
        print(f"[probe] {report['passed']} passed / {report['failed']} failed; exit={code}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
