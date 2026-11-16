#!/usr/bin/env python3
"""M1 页面行为套件：按旧版的`web/app.js` 的 DOM 重写，取代 `s1_page_behaviors.py`。

覆盖范围 = M1 真正实现的那一层：四页渲染、线路抽屉、断开/删除确认层、忙碌门禁、
主题三档与首帧、两张表单（重命名/连接方式）、读取失败横幅、空态；
M2 的四个工具页（记录/维护/代理软件/交易名单）+ AI 工具名单；
M3 的响应曲线与首页统计；M4 的配对流程；M5 的部署表单与「服务器与设备」页。

**不覆盖**：文件导入（走命令行 `--import`）。邀请面板已覆盖单/多服务器入口、
目标选择回传与邀请码显示/隐藏；真实 SSH 签发仍由 Rust 契约测试和真机验收覆盖。

用法：python tests/m1_page_behaviors.py [--out <目录>]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from form_fixtures import (  # noqa: E402
    FORM_DEPLOY_ADDRESS,
    FORM_DEPLOY_DONE,
    FORM_DEPLOY_FAILED,
    FORM_DEPLOY_VERIFY,
    FORM_DEVICES_CONFIRM,
    FORM_DEVICES_DOWN,
    FORM_DEVICES_ERROR,
    FORM_DEVICES_LOADING,
    FORM_DEVICES_READY,
    FORM_DIAGNOSE,
    FORM_HISTORY,
    FORM_MAINTENANCE,
    FORM_PROVIDERS,
    FORM_RENAME,
    FORM_SETTINGS,
    FORM_SPLIT,
)
from web_fixture import WebSession, make_state, prepare_site  # noqa: E402

DEFAULT_OUT = Path(r"C:\tc-rs-build\m1-evidence\page")


class Checker:
    def __init__(self, name: str) -> None:
        self.name = name
        self.checks: list[dict] = []

    def check(self, label: str, ok: bool, detail: object = None) -> None:
        self.checks.append({"label": label, "ok": bool(ok), "detail": detail})

    @property
    def ok(self) -> bool:
        return all(c["ok"] for c in self.checks)


def scenario_home(session: WebSession, check: Checker) -> None:
    session.push("home", make_state())
    check.check("首页渲染连接主卡", session.exists("#main .hero"))
    check.check("已连接显示断开按钮", session.exists("#main [data-action=disconnect]"))
    check.check("当前响应显示 180",
                "180" in session.text("[data-testid=quality-current]"),
                session.text("[data-testid=quality-current]"))
    check.check("首页标题是已连接", "已连接" in session.text("#main"), session.text("#main")[:60])
    check.check("首页不重复显示侧栏摘要",
                session.eval_bool("document.getElementById('mini-status').hidden"))
    check.check("版本号带预览标记",
                "0.1.4" in session.text("#version") and "预览版" in session.text("#version"),
                session.text("#version"))

    session.push("home", make_state(Running=False, State="Disconnected", Quality=None,
                                    ActiveProfile="", ExitEvidence={
                                        "Verified": False, "Attribution": "Unknown",
                                        "Status": "Unknown", "Code": "",
                                        "CheckedAtUtc": None, "ObservedIP": None}))
    check.check("未连接显示连接按钮", session.exists("#main [data-action=connect]"))
    check.check("未连接标题是未连接", "未连接" in session.text("#main"),
                session.text("#main")[:60])


def scenario_lines(session: WebSession, check: Checker) -> None:
    session.push("lines", make_state())
    check.check("线路页两张卡",
                session.eval("document.querySelectorAll('#main [data-testid=line-card]').length") == 2,
                session.eval("document.querySelectorAll('#main [data-testid=line-card]').length"))
    check.check("使用中徽标", "使用中" in session.text("#main"))
    check.check("未测试徽标", "未测试" in session.text("#main"))

    opened = session.click("#main [data-action=details][data-id=jp]")
    check.check("能打开线路抽屉", opened and session.exists("#drawer [role=dialog]"))
    check.check("抽屉里有重命名", session.exists("#drawer [data-action=rename]"))
    check.check("抽屉里有连接方式", session.exists("#drawer [data-action=lineSettings]"))
    check.check("抽屉里有设为默认线路", session.exists("#drawer [data-action=setHomeLine]"))

    session.clear()
    session.click("#drawer [data-action=rename]")
    check.check("点重命名发出 rename 意图",
                any(m.get("Type") == "rename" and m.get("Id") == "jp" for m in session.posted()),
                session.posted()[-1:] or None)


def scenario_disconnect_prompt(session: WebSession, check: Checker) -> None:
    session.push("home", make_state())
    session.clear()
    session.click("#main [data-action=disconnect]")
    check.check("点断开先发意图",
                any(m.get("Type") == "disconnect" for m in session.posted()),
                session.posted()[-1:] or None)

    dialog = {
        "Id": "disconnect-confirm", "Title": "断开连接？",
        "Body": "行情与下单会立刻中断；交易保护状态无法确认；有持仓请先在交易软件处理。",
        "Note": "断开后无法确认名单程序是否仍被阻止；重新连接或运行诊断后再判断。",
        "Confirm": "断开连接", "Cancel": "继续交易",
        "Danger": True, "Details": "", "Progress": False,
    }
    session.push("home", make_state(Dialog=dialog, Busy=True))
    check.check("确认层出现", session.exists("#dialog-root [role=alertdialog]"))
    check.check("确认按钮是危险样式",
                session.eval_bool("(document.querySelector('#dialog-root [data-action=confirmDialog]')"
                                 "||{className:''}).className.includes('danger')"))
    check.check("取消文案是继续交易", "继续交易" in session.text("#dialog-root"))
    check.check("确认文案是断开连接", "断开连接" in session.text("#dialog-root"))

    session.clear()
    session.click("#dialog-root [data-action=cancelDialog]")
    check.check("取消发出 cancelDialog",
                any(m.get("Type") == "cancelDialog" for m in session.posted()),
                session.posted()[-1:] or None)


def scenario_delete_prompt(session: WebSession, check: Checker) -> None:
    session.push("lines", make_state())
    session.click("#main [data-action=details][data-id=jp]")
    session.clear()
    session.click("#drawer [data-action=delete]")
    check.check("点删除发出 delete 意图",
                any(m.get("Type") == "delete" and m.get("Id") == "jp" for m in session.posted()),
                session.posted()[-1:] or None)

    dialog = {
        "Id": "delete-jp", "Title": "删除线路",
        "Body": "确认删除「东京 02」？本机的线路配置与记录会一并移除；服务器不受影响。",
        "Note": "", "Confirm": "删除", "Cancel": "取消",
        "Danger": True, "Details": "", "Progress": False,
    }
    session.push("lines", make_state(Dialog=dialog, Busy=True))
    check.check("删除确认层出现", session.exists("#dialog-root [role=alertdialog]"))
    check.check("删除按钮带危险样式",
                session.eval_bool("(document.querySelector('#dialog-root [data-action=confirmDialog]')"
                                 "||{className:''}).className.includes('danger')"))


def scenario_busy_gates(session: WebSession, check: Checker) -> None:
    session.push("lines", make_state(Busy=True, State="Connecting", Running=False))
    pickers = session.eval(
        " [...document.querySelectorAll('#main [data-action=setProfile]')]"
        ".map(b => b.disabled).join(',')")
    check.check("连接中连接方式选择被禁用", pickers != "" and set(pickers.split(",")) == {"true"},
                pickers)
    check.check("连接中主按钮被禁用",
                session.eval_bool("(document.querySelector('#main [data-action=connect]')||{disabled:null})"
                                  ".disabled===true"))


def scenario_theme(session: WebSession, check: Checker) -> None:
    session.push("settings", make_state())
    check.check("设置页有三档主题",
                session.eval("document.querySelectorAll('#theme option').length") == 3,
                session.eval("document.querySelectorAll('#theme option').length"))
    session.clear()
    session.eval("(()=>{const t=document.getElementById('theme');t.value='dark';"
                 "t.dispatchEvent(new Event('change',{bubbles:true}));})()")
    time.sleep(0.25)
    check.check("选深色发出 theme 意图",
                any(m.get("Type") == "theme" and m.get("Value") == "dark"
                    for m in session.posted()), session.posted()[-1:] or None)
    check.check("立即切成深色",
                session.eval("document.documentElement.dataset.theme==='dark'"))
    check.check("主题写进 localStorage",
                session.eval_bool("localStorage.getItem('theme')==='dark'"))
    session.reload()
    check.check("重载后仍是深色",
                session.eval("document.documentElement.dataset.theme==='dark'"))
    before = session.theme_set_before_body()
    check.check("首帧就设主题（body 还不存在）", before == "dark", before)


def scenario_forms(session: WebSession, check: Checker) -> None:
    session.push("lines", make_state())
    session.clear()
    session.click("#main [data-action=details][data-id=jp]")
    session.click("#drawer [data-action=rename]")
    check.check("抽屉的重命名发出意图",
                any(m.get("Type") == "rename" for m in session.posted()))

    session.push("lines", make_state(Form=FORM_RENAME))
    check.check("重命名表单出现", session.exists("#main .workflow"))
    check.check("输入框带当前名称",
                session.eval("(document.getElementById('wf-name')||{value:null}).value==='东京 02'"))
    check.check("保存与取消都在",
                session.eval("document.querySelectorAll('#main .workflow-actions button').length") == 2)

    session.clear()
    session.set_value("#wf-name", "东京 03")
    check.check("改名称回传 form/change",
                any(m.get("Type") == "form" and m.get("Id") == "name"
                    and m.get("Value") == "东京 03" for m in session.posted()),
                session.posted()[-1:] or None)
    session.clear()
    session.click("#main [data-wf=save-rename]")
    check.check("点保存回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "save-rename"
                    for m in session.posted()), session.posted()[-1:] or None)

    session.push("lines", make_state(Form=FORM_SETTINGS))
    check.check("连接方式页当前档位是主按钮",
                session.eval_bool("(document.querySelector('#main [data-wf=method-udp]')"
                                  "||{className:''}).className.includes('primary')"))
    session.clear()
    session.click("#main [data-wf=method-tcp]")
    check.check("点兼容回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "method-tcp"
                    for m in session.posted()), session.posted()[-1:] or None)

    session.push("lines", make_state())
    check.check("表单关闭后回到线路页",
                not session.exists("#main .workflow")
                and session.eval("document.querySelectorAll('#main [data-testid=line-card]').length") == 2)


def scenario_deploy_form(session: WebSession, check: Checker) -> None:
    """「自己搭服务器」：宿主产出的节点树必须被这份 app.js 认得。

    夹具是从 `FormState::render_deploy()` 的真实输出导出的，所以这里验的是
    「前端认不认这套节点」；宿主侧的形状由 Rust 单测钉住。两边任何一侧改了字段名，
    总有一边会红。

    每次 click 之前都重推一次状态：点击会置 `pendingIntent` 并把按钮标成 disabled，
    而桩不会回 Ack —— 不重推的话第二次点击会被静默吞掉（这不是产品 bug，
    真实宿主会回 Ack 清掉它）。
    """
    session.push("home", make_state(Form=FORM_DEPLOY_ADDRESS))
    check.check("部署表单出现", session.exists("#main .workflow"))
    check.check("地址框在", session.eval_bool("!!document.getElementById('wf-spec')"))
    session.clear()
    session.set_value("#wf-spec", "root@203.0.113.10")
    check.check("填地址回传 form/change",
                any(m.get("Type") == "form" and m.get("Id") == "spec"
                    and m.get("Value") == "root@203.0.113.10" for m in session.posted()),
                session.posted()[-1:] or None)

    session.push("home", make_state(Form=FORM_DEPLOY_ADDRESS))
    session.clear()
    session.click("#main [data-wf=probe]")
    check.check("点「读取指纹」回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "probe" for m in session.posted()),
                session.posted()[-1:] or None)

    # 第二步：指纹 + 密码框。
    session.push("home", make_state(Form=FORM_DEPLOY_VERIFY))
    check.check("指纹显示出来",
                session.eval_bool("(document.querySelector('#main .workflow')||{textContent:''})"
                                  ".textContent.includes('SHA256:ehkYyHs')"))
    check.check("密码框是 password 类型",
                session.eval_bool("(document.getElementById('wf-password')||{type:''}).type==='password'"))
    check.check("密码框默认是空的",
                session.eval_bool("(document.getElementById('wf-password')||{value:'x'}).value===''"))
    session.clear()
    session.set_value("#wf-password", "s3cret")
    check.check("填密码回传 form/change",
                any(m.get("Type") == "form" and m.get("Id") == "password"
                    and m.get("Value") == "s3cret" for m in session.posted()),
                session.posted()[-1:] or None)

    session.push("home", make_state(Form=FORM_DEPLOY_VERIFY))
    session.clear()
    session.click("#main [data-wf=start]")
    check.check("点「开始部署」回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "start" for m in session.posted()),
                session.posted()[-1:] or None)

    session.push("home", make_state(Form=FORM_DEPLOY_VERIFY))
    session.clear()
    session.click("#main [data-wf=deploy-back]")
    check.check("「上一步」回传 form/click（不是关表单）",
                any(m.get("Type") == "form" and m.get("Id") == "deploy-back"
                    for m in session.posted()), session.posted()[-1:] or None)

    # 完成页。
    session.push("home", make_state(Form=FORM_DEPLOY_DONE))
    check.check("完成页列出两条线路",
                session.eval_bool("(document.querySelector('#main .workflow')||{textContent:''})"
                                  ".textContent.includes('兼容连接')"))
    session.clear()
    session.click("#main [data-wf=done]")
    check.check("点「完成」回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "done" for m in session.posted()),
                session.posted()[-1:] or None)

    # 失败页：进度必须还在。
    session.push("home", make_state(Form=FORM_DEPLOY_FAILED))
    check.check("失败页保留进度",
                session.eval_bool("(document.querySelector('#main .workflow')||{textContent:''})"
                                  ".textContent.includes('[3/4] 安装兼容连接')"))
    check.check("失败页有「重新开始」",
                session.eval_bool("!!document.querySelector('#main [data-wf=retry]')"))


def workflow_text(session: WebSession) -> str:
    return session.eval("(document.querySelector('#main .workflow')||{textContent:''}).textContent") or ""


def scenario_devices(session: WebSession, check: Checker) -> None:
    """「服务器与设备」：只读页。

    入口在线路抽屉（`data-action=lineServer`），旧版也是同一条路径。
    夹具从 `FormState::render_devices()` 的真实输出导出，验的是这份 app.js 认不认节点树。
    """
    session.push("lines", make_state())
    session.clear()
    session.click("#main [data-action=details][data-id=jp]")
    check.check("抽屉里有「服务器与设备」入口",
                session.eval_bool("!!document.querySelector('#drawer [data-action=lineServer]')"))
    session.clear()
    session.click("#drawer [data-action=lineServer]")
    check.check("点入口发 lineServer 意图",
                any(m.get("Type") == "lineServer" for m in session.posted()),
                session.posted()[-1:] or None)

    # 还在读：只给一句话，不先画空表。
    session.push("lines", make_state(Form=FORM_DEVICES_LOADING))
    check.check("读取中显示进度话术", "正在读取服务器与设备" in workflow_text(session))
    check.check("读取中不出现刷新按钮",
                not session.eval_bool("!!document.querySelector('#main [data-wf=refresh]')"))

    # 正常：服务器信息 + 隧道 + 逐台设备。
    session.push("lines", make_state(Form=FORM_DEVICES_READY))
    text = workflow_text(session)
    check.check("设备页出现", session.exists("#main .workflow"))
    check.check("服务器地址与网段都在",
                "root@203.0.113.10:22" in text and "网段 10.66.0.0/24" in text, text)
    check.check("隧道运行中带收发量", "隧道：运行中" in text and "收 4.50 GB" in text, text)
    check.check("本机那台被标出来", "设备 10.66.0.2（本机）" in text, text)
    check.check("没握手的设备如实写「从未握手」", "从未握手" in text, text)
    check.check("设备数写在标题里", "已登记的设备（2 台）" in text, text)
    check.check("本机那行没有「移除」",
                not session.eval_bool("!!document.querySelector('#main [data-wf=revoke-0]')"))
    check.check("别的设备有「移除」",
                session.eval_bool("!!document.querySelector('#main [data-wf=revoke-1]')"))
    session.clear()
    session.click("#main [data-wf=revoke-1]")
    check.check("点「移除」回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "revoke-1"
                    for m in session.posted()), session.posted()[-1:] or None)

    # 确认层：撤销不可逆，必须先问一次。
    session.push("lines", make_state(Form=FORM_DEVICES_CONFIRM))
    text = workflow_text(session)
    try:
        # 单独留一张确认层的截图：这一层的排版只能靠看（套件只断言文字与按钮）。
        session.shot(DEFAULT_OUT / "devices-confirm.png")
    except Exception:
        pass
    check.check("确认层说明后果",
                "确定移除设备 10.66.0.3 吗？" in text and "立刻失去访问权" in text, text)
    check.check("确认层不重复列「移除」",
                not session.eval_bool("!!document.querySelector('#main [data-wf=revoke-1]')"))
    session.clear()
    session.click("#main [data-wf=revoke-confirm]")
    check.check("点「确认移除」回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "revoke-confirm"
                    for m in session.posted()), session.posted()[-1:] or None)
    # 每次 click 之前都重推一次：桩不回 Ack，`pendingIntent` 会把按钮标成 disabled，
    # 第二次点击会被静默吞掉（真实宿主会回 Ack 清掉它）。
    session.push("lines", make_state(Form=FORM_DEVICES_CONFIRM))
    session.clear()
    session.click("#main [data-wf=revoke-cancel]")
    check.check("点「取消」回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "revoke-cancel"
                    for m in session.posted()), session.posted()[-1:] or None)

    session.push("lines", make_state(Form=FORM_DEVICES_READY))
    session.clear()
    session.click("#main [data-wf=refresh]")
    check.check("刷新回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "refresh"
                    for m in session.posted()), session.posted()[-1:] or None)

    # 服务没起来：设备清单读不到，不能写成「一台都没有」。
    session.push("lines", make_state(Form=FORM_DEVICES_DOWN))
    text = workflow_text(session)
    check.check("服务没起来时给出警告", "接口不存在（服务没起来）" in text, text)
    check.check("读不到设备时不谎称零设备",
                "读不到设备清单" in text and "还没有任何设备" not in text, text)

    # 读失败：错误原文留在页面上，并给重试。
    session.push("lines", make_state(Form=FORM_DEVICES_ERROR))
    text = workflow_text(session)
    check.check("失败标题与原因都在",
                "读不到设备列表" in text and "找不到对应的服务器记录" in text, text)
    check.check("失败时给「重新读取」", session.eval_bool("!!document.querySelector('#main [data-wf=refresh]')"))


def scenario_read_failure(session: WebSession, check: Checker) -> None:
    session.push("home", make_state(
        Lines=[], State="ReadUnknown", Running=False, Quality=None,
        ReadWarning="读不到线路列表：拒绝访问 C:\\SpiderVPN\\data\\config.json"))
    check.check("首页显示读取失败的原话",
                "读不到线路列表" in session.text("#main"), session.text("#main")[:60])
    check.check("仍然给两条出路",
                session.exists("#main [data-action=pairStart]")
                and session.exists("#main [data-action=add]"))


def scenario_empty(session: WebSession, check: Checker) -> None:
    session.push("lines", make_state(
        Lines=[], State="Disconnected", Running=False, Quality=None,
        ActiveLineId="", HomeLineId="", PreferredLineId=""))
    check.check("空态说明还没有线路", "还没有线路" in session.text("#main"),
                session.text("#main")[:60])
    session.clear()
    session.click("#main [data-action=add]")
    check.check("自己搭服务器发出 add 意图",
                any(m.get("Type") == "add" for m in session.posted()),
                session.posted()[-1:] or None)


def scenario_tools(session: WebSession, check: Checker) -> None:
    """设置页的两个工具入口：操作记录与运行诊断（M2 的前两块）。"""
    session.push("settings", make_state())
    session.clear()
    session.click("#main [data-action=history]")
    check.check("点操作记录发出 history 意图",
                any(m.get("Type") == "history" for m in session.posted()),
                session.posted()[-1:] or None)

    session.push("settings", make_state(Form=FORM_HISTORY))
    check.check("记录表单渲染成列表",
                "端口被占用" in session.text("#main .workflow")
                and "成功" in session.text("#main .workflow"),
                session.text("#main .workflow")[:80])
    session.clear()
    session.click("#main [data-wf=filter-fail]")
    check.check("只看失败回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "filter-fail"
                    for m in session.posted()), session.posted()[-1:] or None)
    # 真宿主每处理一条意图就推一份快照（Ack 递增），页面才解除 pendingIntent；
    # 这里补推一次，否则下一次点击会被 app.js 当成「还在等上一件事」而禁用。
    session.push("settings", make_state(Form=FORM_HISTORY))
    session.clear()
    session.click("#main [data-wf=export-history]")
    check.check("导出回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "export-history"
                    for m in session.posted()), session.posted()[-1:] or None)

    session.push("settings", make_state(Form=FORM_DIAGNOSE))
    check.check("诊断结果渲染结论与逐项",
                "线路端点可达" in session.text("#main .workflow")
                and "可建立连接" in session.text("#main .workflow"),
                session.text("#main .workflow")[:80])
    check.check("诊断按钮变成重新诊断",
                "重新诊断" in session.text("#main .workflow-actions"))
    session.clear()
    session.click("#main [data-wf=run-diagnose]")
    check.check("重新诊断回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "run-diagnose"
                    for m in session.posted()), session.posted()[-1:] or None)


def scenario_maintenance(session: WebSession, check: Checker) -> None:
    """维护与恢复：还原系统代理 + 显式的交易保护解除入口。"""
    session.push("settings", make_state())
    session.clear()
    session.click("#main [data-action=maintenance]")
    check.check("点维护与恢复发出 maintenance 意图",
                any(m.get("Type") == "maintenance" for m in session.posted()),
                session.posted()[-1:] or None)

    session.push("settings", make_state(Form=FORM_MAINTENANCE))
    check.check("维护页说明可还原的原因",
                "可以把系统代理改回去" in session.text("#main .workflow"),
                session.text("#main .workflow")[:60])
    check.check("维护页提供解除交易保护入口",
                "解除交易保护" in session.text("#main .workflow"),
                session.text("#main .workflow")[:80])
    check.check("维护页不再把缺失说成范围外",
                "不在预览版范围" not in session.text("#main .workflow"),
                session.text("#main .workflow")[:80])
    check.check("还原按钮可点",
                session.eval_bool("(document.querySelector('#main [data-wf=restore-proxy]')"
                                  "||{disabled:true}).disabled===false"))
    session.clear()
    session.click("#main [data-wf=restore-proxy]")
    check.check("点还原回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "restore-proxy"
                    for m in session.posted()), session.posted()[-1:] or None)
    # 点击后前端立刻进忙碌态（所有表单按钮 disabled），真实宿主会随后推一份新快照把 Busy 清掉；
    # 桩宿主不会自己推。少了这一步，下面那个按钮永远是 disabled，点击被静默丢弃
    # ——这条检查从加上起就一直红着，原因在这里，不在按钮本身。
    session.push("settings", make_state(Form=FORM_MAINTENANCE))
    session.clear()
    session.click("#main [data-wf=guard-remove]")
    check.check("点解除交易保护回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "guard-remove"
                    for m in session.posted()), session.posted()[-1:] or None)


def scenario_exit(session: WebSession, check: Checker) -> None:
    """交易出口卡（B1）：三档标签 + 观测到的端点地址。"""
    def evidence(**overrides) -> dict:
        base = {"Verified": False, "Attribution": "Unknown", "Status": "unverified",
                "Code": "", "CheckedAtUtc": None, "ObservedIP": None}
        base.update(overrides)
        return base

    # 观测到出口 IP 且归属到线路服务器：这才允许说「出口已核验」。
    session.push("home", make_state(ExitEvidence=evidence(
        Verified=True, Attribution="LineServer", Status="verified",
        CheckedAtUtc="2026-11-06T02:10:00Z", ObservedIP="203.0.113.10")))
    card = session.text("[data-testid=fact-exit]")
    check.check("归属成立时显示出口已核验", "出口已核验" in card, card)
    check.check("卡片显示观测到的端点", "203.0.113.10" in card, card)

    # 观测到了但判不了归属（服务器写的是域名 / 兼容连接中转）：说实话，不冒充已核验。
    session.push("home", make_state(ExitEvidence=evidence(
        Status="Passed", CheckedAtUtc="2026-11-06T02:10:00Z", ObservedIP="203.0.113.10")))
    card = session.text("[data-testid=fact-exit]")
    check.check("判不了归属只说转发已通", "转发已通，归属未验证" in card, card)
    check.check("归属未验证也照样显示端点", "203.0.113.10" in card, card)

    # 自检都没过：一句「尚未核验」，不显示任何地址（旧地址会被读成当前出口）。
    session.push("home", make_state(ExitEvidence=evidence()))
    card = session.text("[data-testid=fact-exit]")
    check.check("没有证据时显示尚未核验", "尚未核验" in card, card)
    check.check("没有证据时不显示端点", "端点" not in card, card)


def scenario_guard_card(session: WebSession, check: Checker) -> None:
    """交易保护卡片的三处展示修复（r25）：核验时间、被拒反馈、管理员视角说明。

    这三条都只改**展示**：三态与 `GuardSummary` 仍由宿主决定，前端只决定
    「说不说这一句」。所以断言全部落在 `[data-testid=guard-note]` 的文本上。
    """
    protected = dict(
        Guard="Protected",
        GuardSummary="交易程序 IPv4/IPv6 直连保护已启用；断开通道后仍保留。",
        TradeProgramCount=1, TradeProgramListed=1, GuardEvidence={"Reason": "Ok"})

    # R25-4：`<60s` 的时龄文案是固定串「刚刚核验」。UAC 设成「从不通知」的机器上，
    # 点一次「重新核验」会静默成功、文案前后一字不差——补绝对时间才看得出这一下生效了。
    session.push("home", make_state(
        **protected, GuardEvidenceAge="刚刚核验", GuardEvidenceAgeSeconds=10,
        GuardVerifiedAtUtc="2026-11-06T01:41:12Z"))
    expected = datetime.fromisoformat("2026-11-06T01:41:12+00:00").astimezone().strftime("%H:%M:%S")
    note = session.text("[data-testid=guard-note]")
    check.check("已保护卡片显示核验绝对时间（静默成功可感知）",
                f"（核验时间 {expected}）" in note, note)

    # 时龄进了「较旧」档就不加时间：那句话的主语已经是「多少分钟前」，再挂一个时刻是噪音。
    session.push("home", make_state(
        **protected, GuardEvidenceAge="较旧：20 分钟前核验", GuardEvidenceAgeSeconds=1200,
        GuardVerifiedAtUtc="2026-11-06T01:41:12Z"))
    note = session.text("[data-testid=guard-note]")
    check.check("较旧时不追加核验时间", "核验时间" not in note, note)

    # R25-2：重启后 `BootChanged` 走的是最后的兜底分支（不是 Protected），
    # 原先 `pendingNote` 只拼在 Protected 分支里，于是点「重新核验」再点「否」卡片毫无变化。
    session.push("home", make_state(
        Guard="Unknown", GuardSummary="交易保护状态无法确认（开机后还没有重新核验）。",
        TradeProgramCount=1, TradeProgramListed=1,
        GuardEvidence={"Reason": "BootChanged"}, GuardVerifyPending="Declined"))
    note = session.text("[data-testid=guard-note]")
    check.check("BootChanged 下被拒也要追加一句",
                "本次未能重新核验（管理员确认被取消）。" in note, note)

    # R25-1：管理员进程看到的 `EvidenceUnprotected` 是视角问题。宿主下发一句实话，
    # 前端只追加到说明里，**不许**改标题（三态不能被这句话污染）。
    session.push("home", make_state(
        Guard="Unknown", GuardSummary="交易保护状态无法确认（核验记录的存储可被普通程序改写）。",
        TradeProgramCount=1, TradeProgramListed=1,
        GuardEvidence={"Reason": "EvidenceUnprotected"},
        GuardPerspectiveNote="当前是管理员进程，可以改写核验记录；这个视角无法证明防篡改生效，请用普通权限进程复核。"))
    note = session.text("[data-testid=guard-note]")
    check.check("管理员视角说明出现在卡片说明里",
                "当前是管理员进程" in note and "请用普通权限进程复核" in note, note)
    check.check("视角说明不改标题",
                "无法确认" in session.text("#guard-title"), session.text("#guard-title"))

    # 空串 = 不追加。「管理员确认」是兜底文案本来就有的字，所以这里只能钉
    # 视角说明那句本身，不能粗暴断言「不含管理员」。
    session.push("home", make_state(
        Guard="Unknown", GuardSummary="交易保护状态无法确认（开机后还没有重新核验）。",
        TradeProgramCount=1, TradeProgramListed=1,
        GuardEvidence={"Reason": "BootChanged"}, GuardVerifyPending="None"))
    check.check("普通权限不出现视角说明",
                "当前是管理员进程" not in session.text("[data-testid=guard-note]"),
                session.text("[data-testid=guard-note]"))


def scenario_providers(session: WebSession, check: Checker) -> None:
    """代理软件：列表 + 扫描 + 添加 + 两步删除。入口在线路页「管理接入」。"""
    session.push("lines", make_state())
    session.clear()
    session.click("#main [data-action=providers]")
    check.check("点代理软件发出 providers 意图",
                any(m.get("Type") == "providers" for m in session.posted()),
                session.posted()[-1:] or None)

    session.push("lines", make_state(Form=FORM_PROVIDERS))
    check.check("列表显示槽位、名称与端口",
                "槽位 1 · 我的代理 · 日常端口 7890" in session.text("#main .workflow"),
                session.text("#main .workflow")[:80])
    check.check("未生效要写原因",
                "等待生效" in session.text("#main .workflow"))
    check.check("添加按钮在可视区内",
                session.eval_bool("(()=>{const b=document.querySelector('#main [data-wf=add-provider]');"
                                  "if(!b)return false;const r=b.getBoundingClientRect();"
                                  "return r.top>=0&&r.bottom<=innerHeight;})()"))
    session.clear()
    session.click("#main [data-wf=discover]")
    check.check("扫描本机回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "discover"
                    for m in session.posted()), session.posted()[-1:] or None)
    session.push("lines", make_state(Form=FORM_PROVIDERS))
    session.clear()
    session.click("#main [data-wf=remove-1]")
    check.check("删除第一下只进确认态",
                any(m.get("Type") == "form" and m.get("Id") == "remove-1"
                    for m in session.posted()), session.posted()[-1:] or None)
    session.push("lines", make_state(Form=FORM_PROVIDERS))
    session.clear()
    session.click("#main [data-wf=add-provider]")
    check.check("添加回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "add-provider"
                    for m in session.posted()), session.posted()[-1:] or None)


def scenario_split(session: WebSession, check: Checker) -> None:
    """交易名单：分组列表 + 选择程序 + 添加 + 移除。入口在应用页「管理交易名单」。"""
    session.push("apps", make_state())
    session.clear()
    session.click("#main [data-action=domains]")
    check.check("点管理交易名单发出 domains 意图",
                any(m.get("Type") == "domains" for m in session.posted()),
                session.posted()[-1:] or None)

    session.push("apps", make_state(Form=FORM_SPLIT))
    check.check("程序与网站两张卡都显示",
                "TradingApp.exe · 已生效" in session.text("#main .workflow")
                and "example.com" in session.text("#main .workflow"),
                session.text("#main .workflow")[:80])
    session.clear()
    session.click("#main [data-wf=pick-program]")
    check.check("选择程序回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "pick-program"
                    for m in session.posted()), session.posted()[-1:] or None)
    session.push("apps", make_state(Form=FORM_SPLIT))
    session.clear()
    session.click("#main [data-wf=remove-process-0]")
    check.check("移除按索引回传",
                any(m.get("Type") == "form" and m.get("Id") == "remove-process-0"
                    for m in session.posted()), session.posted()[-1:] or None)
    session.push("apps", make_state(Form=FORM_SPLIT))
    session.clear()
    session.click("#main [data-wf=add-program]")
    check.check("添加程序回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "add-program"
                    for m in session.posted()), session.posted()[-1:] or None)
    session.push("apps", make_state(Form=FORM_SPLIT))
    session.clear()
    session.click("#main [data-wf=add-site]")
    check.check("添加网站回传 form/click",
                any(m.get("Type") == "form" and m.get("Id") == "add-site"
                    for m in session.posted()), session.posted()[-1:] or None)


def scenario_agents(session: WebSession, check: Checker) -> None:
    """AI 工具名单：入口意图 + 应用页那一行的走向。

    r103 起，**名单页自己的形状**不在这里验。`FORM_AGENTS_*` 那五份载荷是 r102 之前
    `render_agents()` 的一次性快照（条目是勾选框、页内还有一台「走向」下拉、域名在正文
    里写成「包含的网站」），r103 的宿主一种都不再下发；拿旧载荷断言「22 个复选框」
    只是在断言一份不存在的页面，改断言改到绿就成了假绿。

    页面的真实形状改由真机用例 `tests/r103_agents_rows.py` 覆盖（真实宿主 + WebView2 +
    真实 config.json）：22 行「添加/移除」、点一下不发命令、保存只发一条 `agents-save`、
    落盘内容、域名在 ⓘ 里且悬停才展开、「放弃修改」还原。

    这里留下的是不依赖名单页载荷、只跟应用页那一行有关的部分。宿主侧的形状由 Rust 单测
    （`the_agents_page_only_uses_node_kinds_the_page_already_renders`、
    `save_submits_the_whole_draft_in_one_command`）钉住。
    """
    # 入口：应用页「管理工具名单」不再是提示语。
    session.push("apps", make_state())
    session.clear()
    session.click("#main [data-action=agentsList]")
    check.check("点管理工具名单发出 agentsList 意图",
                any(m.get("Type") == "agentsList" for m in session.posted()),
                session.posted()[-1:] or None)

    # 应用页那一行：改走向 → 一条 `agents` 意图（值只可能是 Daily/Trade）。
    session.push("apps", make_state())
    session.clear()
    session.set_value("#agents", "Trade")
    intents = [m for m in session.posted() if m.get("Type") == "agents"]
    check.check("应用页改走向发出 agents 意图",
                len(intents) == 1 and intents[0].get("Value") in ("Daily", "Trade"),
                intents or None)

    # 应用页显示的是**存储值**：存 trade 但线路没有交易出口时，下拉仍显示「使用交易线路」，
    # 并多一句说明（否则用户会以为点了没保存）。
    inactive = make_state(Agents="Daily", AgentsStored="Trade")
    session.push("apps", inactive)
    check.check("应用页下拉显示存储的走向",
                session.eval_bool("(document.getElementById('agents')||{value:''}).value==='Trade'"),
                session.eval("(document.getElementById('agents')||{value:null}).value"))
    check.check("实际不生效时应用页有一句说明",
                "没有交易出口" in session.text("#main"), session.text("#main")[:200])


CURVE = {
    "NodeId": "hk",
    "Window": "ThirtyMinutes",
    "Loading": False,
    "Reason": "",
    "Series": [{
        "Binding": {"Exit": "hk", "ProfileId": "标准"},
        "Aggregate": {
            "StartAtUtc": "2026-11-02T04:00:00Z",
            "EndAtUtc": "2026-11-02T04:30:00Z",
            "Statistics": {"MeasuredCount": 2, "UnavailableCount": 0, "AverageLatencyMs": 180},
            # 两个相邻桶才会画成一条 polyline；孤立点前端会画成 circle。
            "Buckets": (
                [{"AverageLatencyMs": None, "MeasuredCount": 0}] * 10
                + [{"AverageLatencyMs": 150, "MeasuredCount": 1}]
                + [{"AverageLatencyMs": 210, "MeasuredCount": 1}]
                + [{"AverageLatencyMs": None, "MeasuredCount": 0}] * 18
            ),
        },
    }],
}


def scenario_curve(session: WebSession, check: Checker) -> None:
    """抽屉里的响应曲线：有采样就画线，没有就明说没有记录。"""
    session.push("lines", make_state())
    session.click("#main [data-action=details][data-id=hk]")
    session.push("lines", make_state(QualityHistory=CURVE))
    check.check("曲线画出来了",
                session.eval_bool("!!document.querySelector('#drawer .quality-history svg polyline')"))
    check.check("写了平均与次数",
                "平均 180 ms" in session.text("#drawer")
                and "2 次成功" in session.text("#drawer"),
                session.text("#drawer")[-120:])

    empty = {"NodeId": "hk", "Window": "ThirtyMinutes", "Loading": False,
             "Reason": "NoSamples", "Series": []}
    session.push("lines", make_state(QualityHistory=empty))
    check.check("没有采样时说清楚",
                "尚无测量记录" in session.text("#drawer") or "暂时无法读取" in session.text("#drawer"),
                session.text("#drawer")[-120:])


def scenario_stats(session: WebSession, check: Checker) -> None:
    """首页统计卡与「线路变差」横幅：数字全部来自 Lines[].Quality30m / Standby。"""
    state = make_state()
    state["Lines"][0]["Quality30m"] = {
        "SampleCount": 3, "MeasuredCount": 2, "UnavailableCount": 1,
        "TimeoutCount": 1, "ControllerUnavailableCount": 0,
        "Samples": [150, 210, None],
        "MedianSamples": [None, 180, None], "P95Samples": [None, 210, None],
        "MedianLatencyMs": 180, "P95LatencyMs": 210,
        "LastLatencyMs": 210, "LastReason": "Measured", "Fresh": True,
        "Degraded": False, "NotificationMessage": "",
    }
    session.push("home", state)
    check.check("典型响应取中位", session.text("[data-testid=quality-median]") == "180",
                session.text("[data-testid=quality-median]"))
    check.check("最慢响应取最大", session.text("[data-testid=quality-worst]") == "210",
                session.text("[data-testid=quality-worst]"))
    # 未响应 = 没拿到读数的探测 / 有效尝试：1/3，样本不足 10 次时比例位写「样本不足」。
    check.check("未响应写 N/M", session.text("[data-testid=quality-unavailable]") == "1/3",
                session.text("[data-testid=quality-unavailable]"))
    check.check("样本不足不编百分比", session.text("[data-testid=quality-rate]") == "样本不足",
                session.text("[data-testid=quality-rate]"))
    check.check("曲线有 P50 与 P95 两条线",
                session.eval_bool("document.querySelectorAll('#main [data-testid=quality-chart] polyline').length >= 1"))

    # 一次都没测过：三个格都要说「暂无读数」，不能填 0。
    blank = make_state()
    blank["Lines"][0]["Quality30m"] = {
        "SampleCount": 0, "MeasuredCount": 0, "UnavailableCount": 0,
        "Samples": [], "Fresh": False, "Degraded": False,
        "LastLatencyMs": None, "LastReason": None,
    }
    session.push("home", blank)
    check.check("没有采样时统一说暂无读数",
                session.text("[data-testid=quality-unavailable]") == "暂无读数"
                and session.text("[data-testid=quality-median]") == "—",
                session.text("[data-testid=quality-panel]")[:120])

    # 连续三次变差：标题降级 + 横幅引用宿主原话 + 备用线路可一键切过去。
    bad = make_state()
    bad["Quality"] = {"LatencyMs": 700, "Quality": "Poor", "History": [],
                      "ThirtyMinutes": None, "Day": None, "Degraded": True,
                      "NotificationMessage": "当前交易出口连续 3 次延迟较高，请检查线路；当前线路保持。"}
    bad["Lines"][0]["Quality30m"] = dict(blank["Lines"][0]["Quality30m"],
                                         SampleCount=3, MeasuredCount=3,
                                         Samples=[600, 700, None], Fresh=True,
                                         Degraded=True, LastLatencyMs=700)
    bad["Standby"] = {
        "Items": [{"NodeId": "jp", "LatencyMs": 42, "Fresh": True, "Reason": "",
                   "Source": "TcpConnect"}],
        "Recommendation": {"NodeId": "jp", "LatencyMs": 42, "Fresh": True},
    }
    session.push("home", bad)
    check.check("变差时标题降级", "线路不稳定" in session.text("#main .signal-title"),
                session.text("#main .signal-title"))
    check.check("横幅引用宿主原话", "连续 3 次延迟较高" in session.text("#main"),
                session.text("#main")[:80])
    check.check("横幅给出备用线路读数", "42" in session.text("#main .notice")
                and "东京 02" in session.text("#main .notice"),
                session.text("#main .notice"))
    session.clear()
    session.click("#main .notice [data-action=connect]")
    check.check("检查并切换带上备用线路 id",
                any(m.get("Type") == "connect" and m.get("Id") == "jp" for m in session.posted()),
                session.posted()[-1:] or None)


def scenario_switches(session: WebSession, check: Checker) -> None:
    """设置页开关：线路变差提醒现在有后端，点了要发 setting 意图而不是弹「暂未支持」。"""
    session.push("settings", make_state())
    check.check("提醒开关默认是开的",
                session.attr("[data-setting=QualityWarning]", "aria-checked") == "true",
                session.attr("[data-setting=QualityWarning]", "aria-checked"))
    session.clear()
    session.click("#main [data-setting=QualityWarning]")
    posted = session.posted()
    check.check("点开关发出 setting 意图",
                any(m.get("Type") == "setting" and m.get("Name") == "QualityWarning"
                    for m in posted), posted[-1:] or None)
    check.check("关掉的值为 false",
                any(m.get("Type") == "setting" and m.get("Value") is False for m in posted),
                posted[-1:] or None)
    state = make_state()
    state["Settings"] = dict(state["Settings"], QualityWarning=False)
    session.push("settings", state)
    check.check("关掉后开关显示为关",
                session.attr("[data-setting=QualityWarning]", "aria-checked") == "false",
                session.attr("[data-setting=QualityWarning]", "aria-checked"))

    # 「自动记住首次服务器身份」以前是假开关：宿主硬编码 true、点了只弹「暂未支持」。
    # 现在它是真设置——界面要发的就是宿主认识的那条命令与字段名。
    check.check("自动记住首次服务器身份默认是开的",
                session.attr("[data-setting=AutoTrustFirstConnection]", "aria-checked") == "true",
                session.attr("[data-setting=AutoTrustFirstConnection]", "aria-checked"))
    session.clear()
    session.click("#main [data-setting=AutoTrustFirstConnection]")
    posted = session.posted()
    check.check("点自动记住发出 setting 意图",
                any(m.get("Type") == "setting" and m.get("Name") == "AutoTrustFirstConnection"
                    and m.get("Value") is False for m in posted), posted[-1:] or None)
    state = make_state()
    state["Settings"] = dict(state["Settings"], AutoTrustFirstConnection=False)
    session.push("settings", state)
    check.check("关掉后自动记住显示为关",
                session.attr("[data-setting=AutoTrustFirstConnection]", "aria-checked") == "false",
                session.attr("[data-setting=AutoTrustFirstConnection]", "aria-checked"))

    # A7：设置页底部「创建桌面快捷方式」现在有后端（复用安装程序生成的 lnk）。
    # 它必须发出真实动作，而不是像以前那样弹一句「后续版本开放」。
    session.clear()
    session.click("#main [data-action=desktopShortcut]")
    posted = session.posted()
    check.check("点创建桌面快捷方式发出真实动作",
                any(m.get("Type") == "desktopShortcut" for m in posted), posted[-1:] or None)


def scenario_engine(session: WebSession, check: Checker) -> None:
    """引擎程序：缺引擎时**线路页顶部**就要能看见补救入口（连接会被拒，不能让人自己去找）。"""
    state = make_state()
    state["Settings"] = dict(state["Settings"], EngineBinary="", EngineMissing=True)
    session.push("lines", state)
    check.check("缺引擎时线路页有横幅",
                "还没有选择引擎程序" in session.text("#main"), session.text("#main")[:200])
    check.check("横幅里有选择引擎按钮",
                session.exists(".engine-missing [data-action=pickEngine]"))
    session.clear()
    session.click(".engine-missing [data-action=pickEngine]")
    posted = session.posted()
    check.check("点选择引擎发出 pickEngine 意图",
                any(m.get("Type") == "pickEngine" for m in posted), posted[-1:] or None)

    # 设置页那一行：缺引擎显示「尚未选择」，配置后显示路径 + 更换。
    session.push("settings", state)
    check.check("设置页显示尚未选择",
                "尚未选择" in session.text("[data-testid=engine-binary]"),
                session.text("[data-testid=engine-binary]"))
    state["Settings"] = dict(state["Settings"],
                             EngineBinary=r"C:\SpiderVPN\bin\sing-box.exe",
                             EngineMissing=False)
    session.push("settings", state)
    check.check("已选引擎时显示路径",
                "sing-box.exe" in session.text("[data-testid=engine-binary]"),
                session.text("[data-testid=engine-binary]"))
    check.check("已选引擎时按钮变成更换",
                "更换引擎程序" in session.text("#main [data-action=pickEngine]"),
                session.text("#main [data-action=pickEngine]"))
    check.check("已配置后横幅消失", not session.exists(".engine-missing"))


def scenario_pair(session: WebSession, check: Checker) -> None:
    """用邀请码加入：入口 → 粘贴邀请码 → 校验中 → 待加入 → 加入的诚实边界。"""
    session.push("lines", make_state(PairDeviceDefault="测试电脑"))
    session.clear()
    session.click("#main [data-action=pairStart]")
    check.check("点用邀请码加入发出 BeginCode 意图",
                any(m.get("Type") == "pairOnline" and m.get("Phase") == "BeginCode"
                    for m in session.posted()), session.posted()[-1:] or None)

    # 宿主开新会话后把页面切到 add-line，且不发布 Pair：页面应显示输入框。
    session.push("add-line", make_state(PairDeviceDefault="测试电脑"))
    check.check("第 2 步有邀请码输入框", session.exists("#pair-code"))
    check.check("电脑名称预填机器名", session.attr("#pair-device", "value") == "测试电脑",
                session.attr("#pair-device", "value"))

    session.eval("document.querySelector('#pair-code').value='TCI1.abc'; true")
    session.clear()
    session.click("#main [data-action=pairVerify]")
    check.check("校验发出 Verify 意图",
                any(m.get("Type") == "pairOnline" and m.get("Phase") == "Verify"
                    and m.get("Code") == "TCI1.abc" for m in session.posted()),
                session.posted()[-1:] or None)

    # 校验中：宿主发布 Creating，页面显示进度而不是按钮。
    session.push("add-line", make_state(Pair={
        "PairId": "p1", "Phase": "Creating", "StageLabel": "正在确认邀请码",
        "StageChangedAtUtc": "", "DeviceName": "管理电脑", "LocalName": "",
        "NodeName": "", "Host": "", "ExpiresAtUtc": "", "ErrorCode": "",
        "ErrorMessage": "", "NextAction": "", "Epoch": 1,
    }))
    check.check("校验中显示进度", "正在确认邀请码" in session.text("#main"),
                session.text("#main")[:80])

    # 校验通过：宿主发布 Verified，页面进第 3 步并显示服务器入口与有效期。
    session.push("add-line", make_state(Pair={
        "PairId": "p1", "Phase": "Verified", "StageLabel": "", "StageChangedAtUtc": "",
        "DeviceName": "管理电脑", "LocalName": "", "NodeName": "香港 01",
        "Host": "203.0.113.10", "ExpiresAtUtc": "2027-01-01T00:00:00.000000Z",
        "ErrorCode": "", "ErrorMessage": "", "NextAction": "", "Epoch": 1,
    }))
    check.check("通过后显示服务器入口",
                "203.0.113.10" in session.text("#main"), session.text("#main")[:120])
    check.check("通过后有加入按钮", session.exists("#main [data-action=pairJoin]"))

    session.clear()
    session.click("#main [data-action=pairJoin]")
    check.check("加入发出 Join 意图",
                any(m.get("Type") == "pairOnline" and m.get("Phase") == "Join"
                    for m in session.posted()), session.posted()[-1:] or None)

    # 加入进行中：宿主发布 Preparing，页面显示进度与「取消」，不再给「加入这台电脑」。
    session.push("add-line", make_state(Pair={
        "PairId": "p1", "Phase": "Preparing", "StageLabel": "正在提交设备申请并生成线路",
        "StageChangedAtUtc": "", "DeviceName": "管理电脑", "LocalName": "香港 01",
        "NodeName": "香港 01", "Host": "203.0.113.10",
        "ExpiresAtUtc": "2027-01-01T00:00:00.000000Z",
        "ErrorCode": "", "ErrorMessage": "", "NextAction": "", "Epoch": 1,
    }))
    check.check("加入中显示进度", "正在提交设备申请并生成线路" in session.text("#main"),
                session.text("#main")[:120])
    check.check("加入中不再给加入按钮", not session.exists("#main [data-action=pairJoin]"))

    # 加入成功：页面显示结果卡与「去线路页」，不再显示输入框。
    session.push("add-line", make_state(Pair={
        "PairId": "p1", "Phase": "Complete", "StageLabel": "", "StageChangedAtUtc": "",
        "DeviceName": "管理电脑", "LocalName": "香港 01", "NodeName": "香港 01",
        "Host": "203.0.113.10", "ExpiresAtUtc": "2027-01-01T00:00:00.000000Z",
        "ErrorCode": "", "ErrorMessage": "", "NextAction": "", "Epoch": 1,
    }))
    check.check("成功后显示结果卡",
                "线路已加入" in session.text("#main"), session.text("#main")[-160:])
    check.check("成功后主按钮是去线路页",
                session.exists("#main [data-action=pairContinue]")
                and "去线路页" in session.text("#main [data-action=pairContinue]"),
                session.text("#main")[-160:])

    # 加入失败（本机写文件失败）：显示人话，主按钮是「重试」——这一步重来一次确实可能成功。
    session.push("add-line", make_state(Pair={
        "PairId": "p1", "Phase": "Failed", "StageLabel": "", "StageChangedAtUtc": "",
        "DeviceName": "管理电脑", "LocalName": "香港 01", "NodeName": "香港 01",
        "Host": "203.0.113.10", "ExpiresAtUtc": "2027-01-01T00:00:00.000000Z",
        "ErrorCode": "LineWriteFailed",
        "ErrorMessage": "写入线路文件失败（拒绝访问）。",
        "NextAction": "Retry", "Epoch": 1,
    }))
    check.check("失败的加入说出原因",
                "写入线路文件失败" in session.text("#main"), session.text("#main")[-160:])
    check.check("失败的加入主按钮是重试",
                session.exists("#main [data-testid=pair-error-primary]")
                and "重试" in session.text("#main [data-testid=pair-error-primary]"),
                session.text("#main [data-testid=pair-error-primary]"))


def scenario_invite(session: WebSession, check: Checker) -> None:
    """邀请入口：单服务器直进设置，多服务器必须选择且成对回传归属。"""
    def view(**overrides) -> dict:
        base = {
            "ServerId": "", "LineId": "", "Phase": "", "StageLabel": "",
            "StageChangedAtUtc": "", "InviteId": "", "State": "",
            "ExpiresAtUtc": "", "DeviceName": "新电脑", "CodePresent": False,
            "CodePreview": "", "LifetimeSeconds": 1800,
            "LifetimePresets": [600, 1800, 7200, 86400],
            "CompatNoteVisible": False, "Epoch": 1, "Origin": "line",
            "Reachability": None, "ErrorCode": "", "ErrorMessage": "",
            "NextAction": "",
        }
        base.update(overrides)
        return base

    single = make_state()
    single["Lines"] = [dict(single["Lines"][0], CanInvite=True,
                            ServerRecordId="S1", ServerName="自建 01")]
    session.push("lines", single)
    check.check("单条可邀请线路时入口可点击",
                session.eval_bool("(document.querySelector('#main [data-invite=Choose]')||{disabled:true}).disabled===false"))
    session.clear()
    session.click("#main [data-invite=Choose]")
    posted = session.posted()
    check.check("单条线路直接发 Begin 而不是先导航到选择页",
                any(m.get("Type") == "invite" and m.get("Phase") == "Begin"
                    and m.get("Id") == "hk" for m in posted)
                and not any(m.get("Type") == "navigate" for m in posted), posted)
    session.push("invite", make_state(Lines=single["Lines"], Invite=view(LineId="hk")))
    check.check("单条线路直接显示生成邀请码设置",
                session.exists("#main [data-invite=CreateNew]")
                and not session.exists("#main .pair-choice"), session.text("#main")[:160])
    check.check("设置页已经带上唯一线路", "香港 01" in session.text("[data-testid=invite-line]"),
                session.text("[data-testid=invite-line]"))

    multi = make_state()
    multi["Lines"][0].update(CanInvite=True, ServerRecordId="S1", ServerName="自建 01")
    multi["Lines"][1].update(CanInvite=True, ServerRecordId="S2", ServerName="自建 02")
    session.push("lines", multi)
    session.clear()
    session.click("#main [data-invite=Choose]")
    check.check("多台服务器进入新一轮选择",
                any(m.get("Type") == "invite" and m.get("Phase") == "Choose"
                    for m in session.posted()), session.posted())
    session.push("invite", make_state(Lines=multi["Lines"], Invite=view()))
    check.check("多台服务器显示两个选择",
                session.eval("document.querySelectorAll('#main .pair-choice [data-invite=Target]').length") == 2,
                session.text("#main")[:200])
    session.clear()
    session.click("#main [data-invite=Target][data-value=S2]")
    posted = session.posted()
    check.check("选择第二台时线路与服务器成对回传",
                any(m.get("Type") == "invite" and m.get("Phase") == "Target"
                    and m.get("Id") == "jp" and m.get("Value") == "S2" for m in posted), posted)
    session.push("invite", make_state(Lines=multi["Lines"],
                                      Invite=view(LineId="jp", ServerId="S2")))
    check.check("第二台的生成页不会显示成当前线路",
                "东京 02" in session.text("[data-testid=invite-line]")
                and session.exists("#main [data-invite=CreateNew]"),
                session.text("[data-testid=invite-line]"))

    # 显示/隐藏：完整码只由一次性 inviteCode 消息写入；隐藏不再向宿主索码。
    result = view(LineId="jp", ServerId="S2", InviteId="I2", State="Open",
                  CodePresent=True, CodePreview="TCI1.preview…", Epoch=2)
    session.push("invite", make_state(Lines=multi["Lines"], Invite=result))
    session.eval("window.chrome.webview.dispatchEvent(new MessageEvent('message',"
                 "{data:{Type:'inviteCode',Code:'TCI1.SECRET'}}));true")
    code_value = "document.querySelector('[data-testid=invite-code]').value"
    check.check("一次性消息能显示完整邀请码",
                session.eval(code_value) == "TCI1.SECRET", session.eval(code_value))
    session.clear()
    session.click("#main [data-invite=Reveal]")
    check.check("隐藏不再次请求完整码", session.posted() == [], session.posted())
    check.check("隐藏后输入框回到预览",
                session.eval(code_value) == "TCI1.preview…", session.eval(code_value))


SCENARIOS = [
    ("home", scenario_home),
    ("stats", scenario_stats),
    ("lines", scenario_lines),
    ("disconnect-prompt", scenario_disconnect_prompt),
    ("delete-prompt", scenario_delete_prompt),
    ("busy-gates", scenario_busy_gates),
    ("forms", scenario_forms),
    ("read-failure", scenario_read_failure),
    ("empty", scenario_empty),
    ("switches", scenario_switches),
    ("engine", scenario_engine),
    ("tools", scenario_tools),
    ("maintenance", scenario_maintenance),
    ("guard-card", scenario_guard_card),
    ("exit", scenario_exit),
    ("providers", scenario_providers),
    ("split", scenario_split),
    ("agents", scenario_agents),
    ("invite", scenario_invite),
    ("pair", scenario_pair),
    ("curve", scenario_curve),
    ("deploy", scenario_deploy_form),
    ("devices", scenario_devices),
    # 主题放最后：它会改 localStorage 并重载，放中间会让后面的截图全变深色。
    ("theme", scenario_theme),
]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    site = prepare_site(out / "site")
    report = {"scenarios": {}, "shots": []}
    with WebSession(site, out) as session:
        for name, runner in SCENARIOS:
            check = Checker(name)
            try:
                runner(session, check)
            except Exception as exc:  # noqa: BLE001
                check.check("场景执行未抛异常", False, repr(exc))
            shot = session.shot(out / f"{name}.png")
            report["shots"].append(shot)
            report["scenarios"][name] = {
                "checks": check.checks,
                "passed": sum(1 for c in check.checks if c["ok"]),
                "total": len(check.checks),
                "ok": check.ok,
            }
    total = sum(v["total"] for v in report["scenarios"].values())
    passed = sum(v["passed"] for v in report["scenarios"].values())
    report["passed"] = passed
    report["total"] = total
    report["allPassed"] = all(v["ok"] for v in report["scenarios"].values())
    (out / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for name, data in report["scenarios"].items():
        print(f"{name:20s} {data['passed']}/{data['total']}{'' if data['ok'] else '  <-- 失败'}")
        for c in data["checks"]:
            if not c["ok"]:
                print(f"    x {c['label']}  {c['detail']}")
    print(f"\n合计 {passed}/{total} 通过；证据 {out}")
    return 0 if report["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
