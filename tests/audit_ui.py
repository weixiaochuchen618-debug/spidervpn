"""界面审计（**WIP，尚未接入验收，会误报**）。

现状（2026-11-16）：能枚举页面与按钮、能抓「点了完全没变化」，
但对**状态相关**的按钮会误报——例如「筛选」要先展开、服务器条目是行而不是 button、
「还原系统代理」在没有待还原项时本来就该无反应。用它当线索，不当结论。

---
界面审计：逐个页面、逐个按钮点击，断言「点了必须有可见变化」。

用法：
    python tests/audit_ui.py              # 断开状态审（不碰网络）
    python tests/audit_ui.py --connected  # 先连接再审（更接近真实使用）

输出：控制台表格 + reports/ui-audit.json

判定口径（重要）：**只看 DOM 可见结果**——页面文本、抽屉、弹窗、提示条。
不看日志、不看后端回包。「点了没反应」正是这一层要抓的问题。

不点的按钮（危险或会把自动化卡住）：删除/卸载/解除/清除/重置/还原/导出/退出/断开。
它们只记录“存在”，由人工或专项用例验。
"""
import json
import os
import re
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
from s0_page_fixtures import WebSocket, free_port  # noqa: E402
from pipe_cmd import ask, find_pipe  # noqa: E402

EXE = r"C:\SpiderVPN\bin\spidervpn.exe"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_LABEL = re.compile(r"删除|卸载|解除|清除|重置|还原|导出|退出|关闭连接|断开|重启|更换引擎程序")
# ⓘ 是提示气泡（hover/aria），点它不改页面是设计如此，不算「空壳」。
SKIP_TEXT = re.compile(r"^[ⓘ\s]+$")

ROUTES = [
    ("首页", "home", None),
    ("线路", "lines", None),
    ("应用", "apps", None),
    ("设置", "settings", None),
    ("操作记录", "settings", "操作记录"),
    ("服务器", "settings", "服务器"),
    ("维护与恢复", "settings", "维护与恢复"),
    ("交易名单", "apps", "管理交易名单"),
    ("工具名单", "apps", "管理工具名单"),
]

SNAP_JS = r"""JSON.stringify({
  main: (document.querySelector('#main')||document.body).innerText,
  drawer: !!document.querySelector('.drawer'),
  dialog: (document.querySelector('.dialog, dialog[open]')||{}).innerText||'',
  notice: (document.querySelector('.notice:not(.hidden), [role="alert"]')||{}).innerText||''
})"""

BUTTONS_JS = r"""JSON.stringify([...document.querySelectorAll('#main button:not([disabled])')]
  .filter(b => b.offsetParent)
  .map((b, i) => ({i, text: (b.innerText||b.getAttribute('aria-label')||'').trim().slice(0, 20)})))"""

CLOSE_JS = r"""(() => {
  const pick = [...document.querySelectorAll('.dialog button, .drawer button, #main button')]
    .find(b => /^(取消|关闭|返回|不用了|暂不|上一步)/.test((b.innerText||'').trim()));
  if (pick) { pick.click(); return true; }
  return false;
})()"""


def launch(port):
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    return subprocess.Popen([EXE], cwd=os.path.dirname(EXE), env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def attach(port):
    page = None
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2) as resp:
                for item in json.loads(resp.read().decode()):
                    if item.get("type") == "page" and "tc.ui" in (item.get("url") or ""):
                        page = item
            if page:
                break
        except Exception:
            pass
        time.sleep(0.5)
    if not page:
        raise SystemExit("等不到界面（CDP 没找到 tc.ui 页面）")
    ws = WebSocket(page["webSocketDebuggerUrl"])
    for _ in range(80):
        if ws.evaluate("!!document.querySelector('[data-page]')"):
            break
        time.sleep(0.2)
    time.sleep(1.0)
    return ws


class Driver:
    def __init__(self, ws):
        self.ws = ws

    def goto(self, page, sub):
        self.ws.evaluate(
            f"(document.querySelector('[data-page=\"{page}\"]')||{{click(){{}}}}).click(); true")
        time.sleep(1.1)
        if sub:
            self.click_text(sub)
            time.sleep(1.6)

    def snap(self):
        return json.loads(self.ws.evaluate(SNAP_JS))

    def buttons(self):
        return json.loads(self.ws.evaluate(BUTTONS_JS) or "[]")

    def click_text(self, text):
        """按文本点第一个匹配的按钮——下标会在重绘后错位，文本稳定。"""
        import json as _json
        lit = _json.dumps(text, ensure_ascii=False)
        return self.ws.evaluate(
            "(()=>{const want=(" + lit + ");"
            "const norm=t=>(t||'').trim().split('\\n')[0].trim();"
            "const bs=[...document.querySelectorAll('#main button:not([disabled])')]"
            ".filter(b=>b.offsetParent && norm(b.innerText)===want);"
            "if(!bs.length)return false; bs[0].click(); return true})()")

    def close_overlay(self):
        self.ws.evaluate(CLOSE_JS)
        time.sleep(0.5)


def main():
    connected = "--connected" in sys.argv
    subprocess.run(["taskkill", "/IM", "spidervpn.exe", "/F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    port = free_port()
    proc = launch(port)
    ws = attach(port)
    driver = Driver(ws)

    if connected:
        name = find_pipe()
        r = json.loads(ask(name, '{"cmd":"connect"}', 180))
        print("connect:", r.get("ok"), r.get("error") or "")
        time.sleep(9)

    rows = []
    for title, page, sub in ROUTES:
        driver.goto(page, sub)
        baseline = driver.snap()
        btns = driver.buttons()
        print(f"\n=== {title} · 可点按钮 {len(btns)} ===")
        for b in btns:
            text = b["text"]
            if SKIP_TEXT.match(text):
                continue
            if SKIP_LABEL.search(text):
                rows.append({"route": title, "button": text, "skipped": True})
                print(f"  [跳过] {text}")
                continue
            driver.goto(page, sub)
            before = driver.snap()
            hit = driver.click_text(text)
            if not hit:
                rows.append({"route": title, "button": text, "changed": None, "note": "没找到可点元素"})
                print(f"  ? 未找到 {text}")
                continue
            time.sleep(2.6)
            after = driver.snap()
            changed = (after["main"] != before["main"]) or (after["drawer"] != before["drawer"]) \
                or (after["dialog"] != before["dialog"]) or (after["notice"] != before["notice"])
            rows.append({"route": title, "button": text, "changed": changed,
                         "delta": len(after["main"]) - len(before["main"]),
                         "dialog": (after["dialog"] or "")[:30]})
            print(f"  {'✓' if changed else '✗ 无变化'}  {text}")
            if after["dialog"] or after["drawer"]:
                driver.close_overlay()
            driver.close_overlay()

    dead = [r for r in rows if r.get("changed") is False]
    out = os.path.join(ROOT, "reports", "ui-audit.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump({"rows": rows, "dead": dead}, fh, ensure_ascii=False, indent=2)
    print(f"\n合计 {len([r for r in rows if 'changed' in r])} 个按钮，"
          f"其中 {len(dead)} 个点了没有任何可见变化。明细：{out}")
    for r in dead:
        print(f"  ✗ {r['route']} / {r['button']}")

    proc.terminate()
    time.sleep(0.5)
    subprocess.run(["taskkill", "/IM", "spidervpn.exe", "/F"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
