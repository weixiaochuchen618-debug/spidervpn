#!/usr/bin/env python3
"""r92 界面验收：部署向导的「SSH 私钥登录」（旧版的 `DeployLoginMethod`/`DeployKeyPath`）。

改动前：部署向导只有「服务器密码」一条路，用私钥的用户根本进不来。

本脚本验的是宿主真的把这条路做成了（读 DOM + 读磁盘，不是读源码）：

1. 「登录方式」下拉存在，两项原文「服务器密码」「SSH 私钥」，默认密码；
2. 折叠区里有「SSH 私钥文件（密码登录留空）」输入框与「选择…」按钮；
3. 切到私钥 + 路径留空 → 点「开始部署」被拦下，**磁盘上不落草稿**（硬证据）；
4. 切到私钥 + 路径不存在 → 报「找不到这个私钥文件」，仍不落草稿；
5. 切回密码 + 密码留空 → **不被私钥检查拦住**（是否缺密码由命令层按三档凭据判；
   本机离线，读指纹会超时，所以这条只验「放行 + 草稿按 password 落盘」）；
6. 私钥 + 真实存在的密钥文件（现场用 ssh-keygen 造，带口令）→ 放行：落草稿，
   记录里 `LoginMethod == "key"`、`IdentityFile` 是那个路径，
   **记录字节里没有私钥内容、没有口令**；
7. 切换登录方式之后立刻填路径再点（不等重绘）也能被接受——这条守的是 r87 那个
   `Generation` 闸门：切模式若触发了 `restructure()`，下一次输入会被静默吞掉。

**不做**：私钥真握手（本机没有可连的 SSH 服务端，且公网 VPS 22 端口超时）。
那条路径由进程内测试服务端的单元用例守（`a_private_key_authenticates_and_runs_the_command`）。

用法：
  python tests/r92_key_ui.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r92-ssh-key \\
      --work D:\\vpn构建\\reports-tmp\\r92-work [--allow-running]
"""
from __future__ import annotations

import argparse
import importlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker

SPEC = "root@203.0.113.10"
PASSWORD = "r92-password"
PASSPHRASE = "r92-passphrase"
START = "[data-wf=start]"
METHOD = "#wf-login-method"
KEY_PATH = "#wf-key-path"
PICK = "[data-wf=pick-key]"
CLOUD = "#wf-deploy-cloud"

SSH_KEYGEN = Path(r"C:\Windows\System32\OpenSSH\ssh-keygen.exe")


def body_text(ws) -> str:
    return t11.body_text(ws)


def html_text(ws) -> str:
    return str(ws.evaluate("document.documentElement.outerHTML") or "")


def click(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


def click_when_enabled(ws, pump, selector: str, seconds: float = 25.0) -> str:
    ok = helpers.wait_js(
        ws,
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return !!e&&!e.disabled;})()",
        seconds,
        f"{selector} 可点",
        pump,
    )
    if not ok:
        return "disabled"
    return click(ws, selector)


def choose(ws, pump, selector: str, value: str) -> bool:
    """把下拉选到 value 并派发 change（页面靠 change 记选择）。"""
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + f");if(!e)return 'missing';e.value={json.dumps(value)};"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 0.6, "记下选择", pump)
    return ok


def tick(ws, pump) -> bool:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(CLOUD)
        + ");if(!e)return 'missing';e.checked=true;"
        "e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 0.6, "勾选云端", pump)
    return ok


def wait_page(ws, pump, must: tuple[str, ...] = (), must_not: tuple[str, ...] = (), seconds: float = 12.0) -> bool:
    def probe() -> bool:
        text = body_text(ws)
        return all(item in text for item in must) and not any(item in text for item in must_not)

    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pump.tick()
        if probe():
            return True
        time.sleep(0.25)
    return probe()


def runs(work: Path) -> list[Path]:
    folder = work / "data" / "deployments" / "runs"
    return sorted(folder.glob("*.json")) if folder.is_dir() else []


def wait_runs(work: Path, count: int, seconds: float = 20.0) -> list[Path]:
    """等磁盘上出现 `count` 条部署记录（草稿是同步命令，通常在一秒内落盘）。"""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if len(runs(work)) == count:
            return runs(work)
        time.sleep(0.2)
    return runs(work)


def wait_target(work: Path, key: str, value: str, seconds: float = 20.0) -> dict:
    """等那条草稿的 `Target.<key>` 变成 `value`（草稿保存先于读指纹）。"""
    deadline = time.monotonic() + seconds
    target: dict = {}
    while time.monotonic() < deadline:
        record = shipped_record(work)
        current = record.get("Target") if isinstance(record.get("Target"), dict) else {}
        if current.get(key) == value:
            return current
        target = current
        time.sleep(0.2)
    return target


def shipped_record(work: Path) -> dict:
    """读唯一那条草稿（JSON）。没有就回空字典。"""
    for path in runs(work):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
    return {}


def make_key(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    key = folder / "id_ed25519"
    for stale in (key, key.with_suffix(".pub")):
        if stale.exists():
            stale.unlink()
    subprocess.run(
        [str(SSH_KEYGEN), "-t", "ed25519", "-N", PASSPHRASE, "-f", str(key), "-q", "-C", "r92"],
        check=True,
        capture_output=True,
    )
    return key


def open_deploy(ws, pump) -> bool:
    if click_when_enabled(ws, pump, "#main [data-action=add]") != "ok":
        return False
    return helpers.wait_js(ws, "!!document.querySelector('#wf-spec')", 20, "向导", pump)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--allow-running", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)

    if not args.allow_running:
        t11.no_running_host()

    checker = Checker()
    report: dict = {
        "mode": "deploy-ssh-key",
        "exe": str(exe),
        "work": str(work),
        "spec": SPEC,
        "shots": [],
        "checks": [],
    }
    process = None
    ws = None
    try:
        key = make_key(work / "keys")
        missing_key = work / "keys" / "not-there.pem"

        process, _port, ws = t11.launch(exe, work, report_dir, "r92key")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪（导航与主内容都在）",
            helpers.wait_js(
                ws,
                "document.readyState==='complete'&&!!document.querySelector('nav')",
                40,
                "首页",
                pump,
            ),
            body_text(ws)[-300:],
        )
        checker.check("进入自己搭服务器向导", open_deploy(ws, pump), body_text(ws)[:300])

        # 1. 登录方式下拉：两项原文，默认密码。
        options = ws.evaluate(
            "(()=>{const e=document.querySelector("
            + json.dumps(METHOD)
            + ");if(!e)return null;return [e.value, Array.from(e.options).map(o=>o.textContent.trim())];})()"
        )
        checker.check(
            "「登录方式」下拉存在，两项原文是「服务器密码」「SSH 私钥」",
            isinstance(options, list) and options[1] == ["服务器密码", "SSH 私钥"],
            str(options),
        )
        checker.check(
            "默认是「服务器密码」",
            isinstance(options, list) and str(options[0]) == "0",
            str(options),
        )

        # 2. 折叠区里的私钥路径与「选择…」。
        checker.check(
            "折叠区里有私钥路径与「选择…」按钮",
            bool(
                ws.evaluate(
                    "(()=>{const k=document.querySelector("
                    + json.dumps(KEY_PATH)
                    + ");const b=document.querySelector("
                    + json.dumps(PICK)
                    + ");return !!k&&!!b;})()"
                )
            ),
            body_text(ws)[:400],
        )

        checker.check("填进地址", t11.set_value(ws, "#wf-spec", SPEC), "")
        checker.check("勾上「已核对云端放行」", tick(ws, pump), "")

        # 3. 私钥 + 空路径 → 拦下，且不落草稿。
        checker.check("切到「SSH 私钥」", choose(ws, pump, METHOD, "1"), "")
        checker.check("点「开始部署」", click_when_enabled(ws, pump, START) == "ok", "")
        checker.check(
            "私钥模式没选文件：页面说明要先选私钥",
            wait_page(ws, pump, must=("请选择 SSH 私钥文件",), must_not=("正在核对服务器身份",)),
            body_text(ws)[-300:],
        )
        checker.check("被拦时磁盘上没有草稿", runs(work) == [], str([p.name for p in runs(work)]))

        # 4. 路径不存在 → 报「找不到」，仍不落草稿。
        checker.check("填一个不存在的私钥路径", t11.set_value(ws, KEY_PATH, str(missing_key)), "")
        checker.check("再点「开始部署」", click_when_enabled(ws, pump, START) == "ok", "")
        checker.check(
            "路径不存在：页面说找不到这个私钥文件",
            wait_page(ws, pump, must=("找不到这个私钥文件",), must_not=("正在核对服务器身份",)),
            body_text(ws)[-300:],
        )
        checker.check("仍没有草稿", runs(work) == [], str([p.name for p in runs(work)]))

        # 5. 切回密码：**私钥的两条检查不许误伤密码**。
        #
        # 空密码是否可用取决于「本次输入 → 任务级信封 → 长期信封」三档，页面读不到
        # 信封，这条判据在命令层（r92 设计 §4.2 / §4.7）。所以这里验的是「放行到
        # 读指纹」，不是「页面自己报缺密码」——后者会把「已记住凭据的服务器」也拦死。
        checker.check("切回「服务器密码」", choose(ws, pump, METHOD, "0"), "")
        checker.check("清空密码", t11.set_value(ws, "#wf-password", ""), "")
        checker.check("点「开始部署」", click_when_enabled(ws, pump, START) == "ok", "")
        # 页面上的提示**不能**当判据：长命令期间宿主不推快照，旧提示会一直挂着。
        # 硬证据是磁盘：草稿落了，而且记的是 password（说明没被私钥检查拦住）。
        checker.check(
            "密码模式不会被私钥检查拦住：草稿按 password 落盘",
            len(wait_runs(work, 1)) == 1
            and wait_target(work, "LoginMethod", "password").get("LoginMethod") == "password",
            json.dumps(
                (shipped_record(work).get("Target") or {}),
                ensure_ascii=False,
            ),
        )
        # 离线环境里 203.0.113.10 不可达：等这次探测超时结束再往下走。
        # 长命令期间宿主不推快照，探测没结束时下一步的输入会被 `Generation` 闸门丢掉。
        checker.check(
            "等这次读指纹结束（离线环境会超时）",
            helpers.wait_js(
                ws,
                "(()=>{const e=document.querySelector('[data-wf=start]');return !!e&&!e.disabled;})()",
                45,
                "探测结束",
                pump,
            ),
            body_text(ws)[-300:],
        )

        # 6. 切到私钥 + 真文件 → 放行；切换后**立刻**填写（不等重绘）也必须生效。
        checker.check("再切到「SSH 私钥」", choose(ws, pump, METHOD, "1"), "")
        checker.check("填真实私钥路径（切换后立刻填）", t11.set_value(ws, KEY_PATH, str(key)), "")
        checker.check("填口令", t11.set_value(ws, "#wf-password", PASSPHRASE), "")
        checker.check("点「开始部署」", click_when_enabled(ws, pump, START) == "ok", "")
        checker.check(
            "放行：落草稿（这一步之后才可能去读指纹）",
            len(wait_runs(work, 1)) == 1,
            str([p.name for p in runs(work)]),
        )
        # 草稿保存是同步命令、读指纹是长命令：等那一条记录从「密码」改成「私钥」。
        target = wait_target(work, "LoginMethod", "key")
        checker.check(
            "记录里的登录方式是 key，且记下了私钥路径",
            target.get("LoginMethod") == "key" and target.get("IdentityFile") == str(key),
            json.dumps(target, ensure_ascii=False),
        )
        record = shipped_record(work)
        raw = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in runs(work))
        checker.check(
            "任务记录里没有私钥内容",
            "BEGIN" not in raw and "PRIVATE KEY" not in raw,
            raw[-300:],
        )
        checker.check(
            "任务记录里没有口令",
            PASSPHRASE not in raw,
            raw[-300:],
        )

        # 7. 页面本身不许把秘密带进 DOM。
        page = html_text(ws)
        checker.check(
            "页面 DOM 里没有私钥内容与口令",
            "BEGIN" not in page and PASSPHRASE not in page,
            page[-300:],
        )

        checker.check(
            "最后页面没有停在「正在核对服务器身份…」的假死状态",
            wait_page(ws, pump, must_not=("正在核对服务器身份",), seconds=25.0),
            body_text(ws)[-400:],
        )

        helpers.screenshot(ws, report_dir / "01-deploy-ssh-key.png", report["shots"])

        report["checks"] = checker.checks
        passed = sum(1 for item in checker.checks if item["ok"])
        failed = len(checker.checks) - passed
        print(f"\n合计 {len(checker.checks)} 项，PASS {passed}，FAIL {failed}", flush=True)
        return 0 if checker.all_passed else 1
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if process is not None:
            try:
                process.terminate()
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                pass
        try:
            (report_dir / "report.json").write_text(
                json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    raise SystemExit(main())
