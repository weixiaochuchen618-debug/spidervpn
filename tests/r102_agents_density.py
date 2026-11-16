#!/usr/bin/env python3
"""r102 界面验收：AI 工具名单页「信息密度」对齐 旧版。

这一页以前把同一件事讲了三遍：页头四段说明（走交易线路 / 走向重复 / 没有交易出口）、
分组各一句 note、每个网页版条目一行「包含的网站」。旧版的 `AgentListCard` 只有：

    勾选要跟随线路的工具，改完点保存，一次生效。   ← 一行
    [添加常用 AI 工具]
    桌面程序 / 网页版 / 模型 API 与下载平台  + 条目（名称、徽标、一句 detail、ⓘ 里的「包含的网站」）
    每行右边一颗「添加 / 移除」按钮（r103 起没有勾选框、没有折叠抽屉）
    自定义 + 添加网址/添加程序…
    走向在**应用页**那一行改，这一页没有下拉。

本脚本验的就是这些「多出来的东西真的没了」，以及它们没被删坏（保存仍是一条 `agents-save`、
落盘仍是全量草稿）。

用法：
  python tests/r102_agents_density.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\reports-tmp\\r102-agents --work D:\\vpn构建\\reports-tmp\\r102-agents\\root
"""
from __future__ import annotations

import argparse
import importlib
import json
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

# 旧版那四段话里出现、而新页面正文里不该再有的句子（提示气泡里可以有）。
GONE_FROM_BODY = [
    "走向为「跟随日常上网」时，名单暂不生效",
    "这条线路没有交易出口，名单现在不会生效",
    "两处改的是同一个值",
    "日常上网走交易线路时，名单跟着交易线路走，不能单独设置",
    "它访问的网址都随之走",
    "只有浏览器访问这些网址时才走",
    "浏览器和其他程序访问这些域名都走",
    "还没有添加自己的程序或网站",
    "例如 perplexity.ai；子域名一并生效",
]
HINT_TEXT = "桌面程序按程序识别"


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

    checker = Checker()
    report: dict = {"mode": "agents-density", "exe": str(exe), "checks": []}
    process = None
    code = 0
    try:
        seed(work)
        process, _port, ws = t11.launch(exe, work, report_dir, "agents")
        pump = t11.Pump(process.pid)
        shots: list[str] = []

        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            "",
        )
        checker.check("进应用", r87.click_when_enabled(ws, pump, "nav [data-page=apps]") == "ok", "")
        checker.check(
            "打开工具名单",
            r87.click_when_enabled(ws, pump, "#main [data-action=agentsList]") == "ok"
            and helpers.wait_js(
                ws, "document.body.innerText.includes('勾选要跟随线路的工具')", 20, "名单页", pump
            ),
            r87.body_text(ws)[-200:],
        )

        body = str(ws.evaluate("document.querySelector('#main').innerText") or "")
        workflow = str(ws.evaluate("document.querySelector('#main .workflow').innerText") or "")

        # 1) 走向控件不在这页
        checker.check("这一页没有走向下拉", not ws.evaluate("!!document.getElementById('wf-lane')"), "")
        # 2) 四段说明不再占正文
        leftovers = [line for line in GONE_FROM_BODY if line in workflow]
        checker.check("旧的四段说明已从正文移除", not leftovers, leftovers)
        # 3) 长解释进了提示气泡
        hint = str(ws.evaluate(
            "(()=>{const h=document.querySelector('#main .hint');return h?(h.getAttribute('data-hint')||h.getAttribute('aria-label')||h.title||''):'';})()"
        ) or "")
        checker.check(
            "长解释在提示气泡里",
            HINT_TEXT in hint,
            hint[:120],
        )
        # 4) 只有一行「怎么用」
        instruction_lines = [line for line in workflow.splitlines() if "改完点保存，一次生效" in line]
        checker.check("正文只留一句操作说明", len(instruction_lines) == 1, instruction_lines)

        # 5) 域名清单挂在 ⓘ 上（r103：不再有折叠抽屉）
        details_count = int(ws.evaluate("document.querySelectorAll('#main details').length") or 0)
        hints = [str(x) for x in (ws.evaluate(
            "Array.from(document.querySelectorAll('#main [data-hint]')).map(e=>e.dataset.hint)") or [])]
        domain_hints = [h for h in hints if h.startswith("包含的网站：")]
        checker.check("这一页没有折叠抽屉（域名改走 ⓘ）", details_count == 0, details_count)
        checker.check("每条带域名的条目都把「包含的网站」放在 ⓘ 上",
                      len(domain_hints) >= 1
                      and all(len(h) > len("包含的网站：") for h in domain_hints),
                      domain_hints[:3])
        checker.check("正文里不再有「包含的网站」这一行", "包含的网站" not in workflow)

        # 6) 分组下没有 note 行
        checker.check("分组标题三个都在",
                      all(label in workflow for label in ("桌面程序", "网页版", "模型 API 与下载平台")))

        # 7) 自定义：加一条网址 → 一行（文字 + 右对齐按钮），不写配置
        ws.evaluate(
            "(()=>{const e=document.getElementById('wf-site');e.value='r102.example';"
            "e.dispatchEvent(new Event('input',{bubbles:true}));return true;})()"
        )
        checker.check("点「添加网址」", r87.click_when_enabled(ws, pump, "[data-wf=add-site]") == "ok", "")
        helpers.wait_js(ws, "document.body.innerText.includes('r102.example')", 10, "自定义行", pump)
        checker.check(
            "自定义行是单行（文字 + 右对齐按钮）",
            bool(ws.evaluate(
                "(()=>{const rows=[...document.querySelectorAll('#main .workflow .wf-row')];"
                "return rows.some(r=>r.textContent.includes('r102.example')&&r.querySelector('button[data-wf^=toggle-]'));})()"
            )),
        )
        config_before = json.loads((work / "data" / "config.json").read_text(encoding="utf-8-sig"))
        checker.check("拖进草稿不写配置",
                      "r102.example" not in json.dumps(config_before.get("agents", {}), ensure_ascii=False),
                      config_before.get("agents"))

        # 8) 一键添加 → 22 行全部写「移除」
        checker.check("点「添加常用 AI 工具」", r87.click_when_enabled(ws, pump, "[data-wf=recommend]") == "ok", "")
        rows_js = (
            "Array.from(document.querySelectorAll('#main .workflow [data-wf^=\"builtin-\"]'))"
            ".filter(b=>b.textContent.trim()==='移除').length"
        )
        helpers.wait_js(ws, rows_js + "===22", 10, "全加", pump)
        checker.check("一键添加 22 项（22 行都写「移除」）",
                      int(ws.evaluate(rows_js) or 0) == 22)

        # 9) 保存仍是一条 agents-save，落盘全量
        # 前端每发一条消息都走 `chrome.webview.postMessage`，这里把它包一层计数
        # （页面自己的 `post()` 每次现取这个函数，所以包完立即生效）。
        ws.evaluate(
            "(()=>{window.__tcPosted=[];const w=window.chrome&&window.chrome.webview;if(!w||w.__wrapped)return;"
            "const orig=w.postMessage.bind(w);w.__wrapped=true;"
            "w.postMessage=m=>{window.__tcPosted.push(typeof m==='string'?m:JSON.stringify(m));return orig(m);};})()"
        )
        posted_before = int(ws.evaluate("(window.__tcPosted||[]).length") or 0)
        checker.check("点保存", r87.click_when_enabled(ws, pump, "[data-wf=save]") == "ok", "")
        helpers.wait_js(ws, "(document.querySelector('#main [data-wf=save]')||{disabled:true}).disabled===true", 20, "保存完成", pump)
        time.sleep(1.2)
        saves = int(ws.evaluate(
            "((window.__tcPosted||[]).slice(%d)).filter(m=>String(m).includes('\"Id\":\"save\"')).length" % posted_before
        ) or 0)
        checker.check("一次保存 = 一条命令", saves == 1, saves)

        config_after = json.loads((work / "data" / "config.json").read_text(encoding="utf-8-sig"))
        agents = config_after.get("agents", {})
        checker.check(
            "落盘：22 项内置 + 自定义网址 + 走向仍是 Daily（这页不改走向）",
            len(agents.get("builtin", [])) == 22
            and "r102.example" in agents.get("sites", [])
            and agents.get("lane") in ("daily", "Daily"),
            {k: agents.get(k) for k in ("lane", "sites")},
        )

        helpers.screenshot(ws, report_dir / "01-agents.png", shots)
        report["shots"] = shots
        report["checks"] = checker.checks
        code = 0 if checker.all_passed else 1
    except Exception as error:  # noqa: BLE001
        print(f"[probe] 失败：{error}", flush=True)
        code = 2
    finally:
        if process and not args.keep_open:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(json.dumps(report.get("checks", []), ensure_ascii=False, indent=2), flush=True)
        print(f"[probe] exit={code}", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
