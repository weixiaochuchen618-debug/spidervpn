"""r67 真机验收：管理端离线邀请 → 新电脑申请 → 管理端批准 → 新电脑完成加入。

用的是真实 VPS（服务器记录与凭据来自已经部署过的数据根）和两个隔离数据根：
- 管理端根：复制 r66 部署根里的 `servers\`、`lines\`、`config.json`，并给线路文件补一条
  `outbounds[].server`（真实部署线路是 sing-box `endpoints` 格式，邀请判据只认
  `outbounds[].server`——r64 的同一处坑）；
- 新电脑根：空的，模拟一台全新电脑。

两次「复制/粘贴」走宿主剪贴板，与用户手工操作一致。密码只从环境变量
`TC_SSH_PASSWORD` 读取，不落盘、不进报告。
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")

Checker = helpers.Checker
Pump = helpers.Pump
WebSocket = helpers.WebSocket
free_port = helpers.free_port
wait_cdp = helpers.wait_cdp
wait_js = helpers.wait_js
screenshot = helpers.screenshot
RUNTIME = r54.RUNTIME
md5_of = r54.md5_of
responsive_pipe = r54.responsive_pipe

DEPLOY_DATA = Path(r"C:\tc-rs-build\r66\restore-root\data")
HOST = "203.0.113.25"


def click(ws: WebSocket, selector: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e||e.disabled)return false;"
        "e.click();return true;})()" % json.dumps(selector, ensure_ascii=False)
    )
    return bool(ws.evaluate(expr))


def set_value(ws: WebSocket, selector: str, value: str) -> bool:
    expr = (
        "(()=>{const e=document.querySelector(%s);if(!e)return false;e.focus();e.value=%s;"
        "e.dispatchEvent(new Event('input',{bubbles:true}));"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"
        % (json.dumps(selector, ensure_ascii=False), json.dumps(value, ensure_ascii=False))
    )
    return bool(ws.evaluate(expr))


def page_has(ws: WebSocket, text: str, seconds: float = 10.0, pump: Pump | None = None) -> bool:
    expr = "document.body.innerText.includes(" + json.dumps(text, ensure_ascii=False) + ")"
    return wait_js(ws, expr, seconds, text[:24], pump)


def clipboard_text() -> str:
    output = subprocess.check_output(
        ["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"],
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return output.strip()


def prepare_manager_root(root: Path) -> None:
    data = root / "data"
    if data.exists():
        shutil.rmtree(data)
    data.mkdir(parents=True)
    shutil.copy2(DEPLOY_DATA / "config.json", data / "config.json")
    shutil.copytree(DEPLOY_DATA / "servers", data / "servers")
    shutil.copytree(DEPLOY_DATA / "lines", data / "lines")
    # 邀请判据只认 `outbounds[].server`；真实部署线路是 endpoints 格式，补一条
    # 仅供归属判断的出站（不会拿去连接）。
    for line_file in (data / "lines").glob("*.json"):
        value = json.loads(line_file.read_text(encoding="utf-8"))
        outbounds = value.get("outbounds")
        if not isinstance(outbounds, list):
            outbounds = []
        if not any(isinstance(item, dict) and item.get("server") == HOST for item in outbounds):
            outbounds.append(
                {
                    "type": "wireguard",
                    "tag": "tc-r67-acceptance-anchor",
                    "server": HOST,
                    "server_port": 51820,
                }
            )
            value["outbounds"] = outbounds
            line_file.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def launch(exe: Path, root: Path, port: int, log_path: Path):
    env = dict(os.environ)
    env["SPIDERVPN_ROOT"] = str(root)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = (
        f"--remote-debugging-port={port} --remote-allow-origins=*"
    )
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(exe)],
        cwd=str(exe.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    target = wait_cdp(port, helpers.CDP_READY_SECONDS)
    ws = WebSocket(target["webSocketDebuggerUrl"])
    ws.call("Page.enable")
    try:
        ws.call("Page.bringToFront")
    except Exception:  # noqa: BLE001
        pass
    return process, log, ws


def navigate(ws: WebSocket, page: str) -> None:
    r54.post(ws, {"Type": "navigate", "Page": page})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args()
    if not os.environ.get("TC_SSH_PASSWORD"):
        raise SystemExit("缺少 TC_SSH_PASSWORD：请用环境变量提供，不要写进文件")

    report_dir = Path(args.report_dir).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    exe = Path(args.exe).resolve()
    manager_root = report_dir / "manager"
    client_root = report_dir / "client"
    prepare_manager_root(manager_root)
    if client_root.exists():
        shutil.rmtree(client_root)
    client_root.mkdir(parents=True)

    live = responsive_pipe()
    if live:
        raise SystemExit(f"已经有一个 SpiderVPN 在跑（{live}），请先关掉它再跑这条验收。")
    if RUNTIME.is_file():
        raise SystemExit(f"现场已有 {RUNTIME}，请先在界面上断开再跑这条验收。")

    checker = Checker()
    report = {"exe": str(exe), "exeMd5": md5_of(exe), "shots": [], "checks": []}
    manager_port = free_port()
    client_port = free_port()
    manager_proc = manager_log = manager_ws = None
    client_proc = client_log = client_ws = None
    try:
        manager_proc, manager_log, manager_ws = launch(
            exe, manager_root, manager_port, report_dir / "manager.log"
        )
        client_proc, client_log, client_ws = launch(
            exe, client_root, client_port, report_dir / "client.log"
        )
        manager_pump = Pump(manager_proc.pid)
        client_pump = Pump(client_proc.pid)

        checker.check(
            "0 管理端页面就绪",
            wait_js(manager_ws, "document.readyState==='complete'&&!!document.querySelector('#main')", 30, "管理端", manager_pump),
        )
        checker.check(
            "0 新电脑页面就绪",
            wait_js(client_ws, "document.readyState==='complete'&&!!document.querySelector('#main')", 30, "新电脑", client_pump),
        )

        # ---- 管理端：生成邀请，切到离线 ----
        navigate(manager_ws, "lines")
        checker.check(
            "1 管理端有「邀请其他电脑」",
            wait_js(manager_ws, '!!document.querySelector(\'[data-invite="Choose"]\')', 15, "邀请入口", manager_pump),
        )
        checker.check("1 点邀请", click(manager_ws, '[data-invite="Choose"]'))
        checker.check(
            "1 进入邀请设置",
            wait_js(manager_ws, '!!document.querySelector(\'[data-invite="CreateNew"]\')', 15, "邀请设置", manager_pump),
        )
        checker.check("1 生成邀请码", click(manager_ws, '[data-invite="CreateNew"]'))
        checker.check(
            "2 邀请码已生成",
            wait_js(manager_ws, '!!document.querySelector(\'[data-invite="Offline"]\')', 90, "生成结果", manager_pump),
        )
        # 「改用离线邀请」在折叠的 details 里；JS 点它不受可见性限制。
        checker.check("2 改用离线邀请", click(manager_ws, '[data-invite="Offline"]'))
        checker.check(
            "2 离线面板出现",
            wait_js(manager_ws, '!!document.querySelector(\'[data-invite="OfflineCopyInvite"]\')', 15, "离线面板", manager_pump),
        )
        checker.check("2 复制离线邀请", click(manager_ws, '[data-invite="OfflineCopyInvite"]'))
        time.sleep(0.8)
        invite = clipboard_text()
        checker.check("2 剪贴板里是完整邀请 JWS", invite.count(".") == 2 and invite.startswith("eyJ"), invite[:40])
        screenshot(manager_ws, report_dir / "01-manager-offline.png", report["shots"])

        # ---- 新电脑：读取邀请、生成申请 ----
        navigate(client_ws, "lines")
        checker.check(
            "3 新电脑有「用邀请码加入」",
            wait_js(client_ws, '!!document.querySelector(\'[data-action="pairStart"]\')', 15, "加入入口", client_pump),
        )
        checker.check("3 点加入", click(client_ws, '[data-action="pairStart"]'))
        checker.check(
            "3 有离线入口",
            wait_js(client_ws, '!!document.querySelector(\'[data-testid="pair-offline-entry"]\')', 15, "离线入口", client_pump),
        )
        checker.check("3 切到离线", click(client_ws, '[data-testid="pair-offline-entry"]'))
        checker.check(
            "3 离线表单出现",
            wait_js(client_ws, "!!document.getElementById('pair-offline-invite')", 10, "离线表单", client_pump),
        )
        checker.check("3 填入邀请", set_value(client_ws, "#pair-offline-invite", invite))
        checker.check("3 填设备名", set_value(client_ws, "#pair-device", "r67离线验收"))
        checker.check("3 读取邀请", click(client_ws, '[data-action="pairOfflineInspect"]'))
        checker.check(
            "4 指纹出现",
            wait_js(client_ws, '!!document.querySelector(\'[data-testid="pair-offline-fingerprint"]\')', 30, "指纹", client_pump),
        )
        checker.check("4 生成申请", click(client_ws, '[data-action="pairOfflineRequest"]'))
        checker.check(
            "4 申请出现",
            wait_js(client_ws, "!!document.getElementById('pair-request')", 60, "申请", client_pump),
        )
        checker.check("4 复制申请", click(client_ws, '[data-action="pairCopyRequest"]'))
        time.sleep(0.8)
        request = clipboard_text()
        checker.check("4 剪贴板里是申请 JWS", request.count(".") == 2 and request.startswith("eyJ"), request[:40])
        screenshot(client_ws, report_dir / "02-client-request.png", report["shots"])

        # ---- 管理端：批准申请 ----
        checker.check("5 管理端粘入申请", set_value(manager_ws, "#offline-request", request))
        checker.check("5 批准申请", click(manager_ws, '[data-invite="OfflineApprove"]'))
        checker.check(
            "5 授权已生成",
            wait_js(manager_ws, '!!document.querySelector(\'[data-invite="OfflineCopyGrant"]\')', 120, "授权", manager_pump),
        )
        checker.check("5 复制授权", click(manager_ws, '[data-invite="OfflineCopyGrant"]'))
        time.sleep(0.8)
        grant = clipboard_text()
        checker.check("5 剪贴板里是授权 JWE", grant.count(".") == 4, grant[:40])
        screenshot(manager_ws, report_dir / "03-manager-grant.png", report["shots"])

        # ---- 新电脑：导入授权、完成加入 ----
        checker.check("6 新电脑粘入授权", set_value(client_ws, "#pair-authorization", grant))
        checker.check("6 填线路名", set_value(client_ws, "#pair-name", "r67离线线路"))
        checker.check("6 完成加入", click(client_ws, '[data-action="pairOfflineComplete"]'))
        checker.check(
            "6 线路已加入",
            page_has(client_ws, "线路已加入", 90, client_pump),
        )
        screenshot(client_ws, report_dir / "04-client-complete.png", report["shots"])

        config = json.loads((client_root / "data" / "config.json").read_text(encoding="utf-8"))
        lines = config.get("lines", [])
        checker.check("7 新电脑配置里有一条新线路", len(lines) == 1, json.dumps(lines, ensure_ascii=False))
        checker.check(
            "7 线路名是用户填的那个",
            bool(lines) and lines[0].get("name") == "r67离线线路",
            json.dumps(lines, ensure_ascii=False),
        )
        identities = client_root / "data" / "identities"
        checker.check(
            "7 本机登记里有 client.conf",
            any((path / "client.conf").exists() for path in identities.glob("*") if path.is_dir()),
        )

        checker.check("8 管理端配置没被改过（只应是复制出来的那份）", (manager_root / "data" / "config.json").exists())
        checker.check("8 收尾时没有新增 runtime.json", not RUNTIME.is_file())

        report["checks"] = checker.checks
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        passed = sum(1 for item in checker.checks if item["ok"])
        total = len(checker.checks)
        print(f"\n合计 {passed}/{total}；证据 {report_dir}")
        return 0 if passed == total else 1
    finally:
        for process, log in ((manager_proc, manager_log), (client_proc, client_log)):
            if process is None:
                continue
            try:
                process.terminate()
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
            if log:
                log.close()


if __name__ == "__main__":
    raise SystemExit(main())
