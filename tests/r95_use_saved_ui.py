#!/usr/bin/env python3
"""r95 界面验收：部署页的「使用这台服务器保存的登录资料」勾（旧版的`DeployUseSaved`）。

不需要远程服务器：本机开着 OpenSSH（127.0.0.1:22），`server-probe` 只读主机公钥，
不登录、不改服务器。数据根里铺一条 127.0.0.1 的服务器记录 + 一份**真的 DPAPI 信封**
（Python 调 `CryptProtectData`，绑定与 Rust 侧同一串），于是：

1. 点「开始部署」→ 读指纹成功 → 页面出现 `DeployUseSaved`，默认勾上；
2. 取消勾选不重绘（其它控件与地址都还在）；
3. 没有任务级信封时 `DeployUseTaskCredential` 不出现（不画假控件）；
4. 真实数据根的 config.json 未被改动。

用法：
  python tests/r95_use_saved_ui.py --exe C:\\tc-rs-build\\release\\spidervpn.exe \\
      --report-dir D:\\vpn构建\\deliverables\\software-company\\tcrs-r95-use-saved \\
      --work D:\\vpn构建\\reports-tmp\\r95-work [--allow-running]
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import importlib
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
helpers = importlib.import_module("r35_invite_ui")
r54 = importlib.import_module("r54_p013_guard_ui")
t11 = importlib.import_module("t11_real_deploy_ui")

Checker = helpers.Checker
USER_CONFIG = r54.USER_CONFIG
md5_of = r54.md5_of

SERVER_ID = "9f1c2a44-0b7d-4c1e-9a2b-3c4d5e6f7a8b"
FINGERPRINT = "SHA256:" + "A" * 43
SPEC = "root@127.0.0.1:22"
PASSWORD = "r95-local-password"
CHECK = "#wf-use-saved"


class Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_char))]


def dpapi_protect(plain: bytes, entropy: bytes) -> str:
    """与 `pairing::dpapi::protect_with` 同参：UI_FORBIDDEN + 绑定串做熵。"""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    crypt32.CryptProtectData.restype = ctypes.c_int
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    data_buf = ctypes.create_string_buffer(plain, len(plain))
    entropy_buf = ctypes.create_string_buffer(entropy, len(entropy))
    data = Blob(len(plain), ctypes.cast(data_buf, ctypes.POINTER(ctypes.c_char)))
    salt = Blob(len(entropy), ctypes.cast(entropy_buf, ctypes.POINTER(ctypes.c_char)))
    out = Blob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(data), None, ctypes.byref(salt), None, None, 0x1, ctypes.byref(out)
    )
    if not ok:
        raise OSError("CryptProtectData 失败")
    try:
        raw = ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))
    return base64.b64encode(raw).decode("ascii")


def seed_server(work: Path) -> None:
    directory = work / "data" / "servers" / SERVER_ID
    directory.mkdir(parents=True, exist_ok=True)
    password = "s3cret-r95"
    binding = "\n".join(
        [
            "TradeChannel.Deploy.v1",
            SERVER_ID,
            "127.0.0.1",
            "22",
            "root",
            FINGERPRINT,
        ]
    )
    plain = json.dumps(
        {"Binding": binding, "Kind": "password", "Password": password},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    protected = dpapi_protect(plain, binding.encode("utf-8"))
    payload = {
        "SchemaVersion": 1,
        "Kind": "TradeChannel.ServerRecord",
        "Id": SERVER_ID,
        "Name": "本机测试服务器",
        "Host": "127.0.0.1",
        "Port": 22,
        "User": "root",
        "Fingerprint": FINGERPRINT,
        "CreatedAtUtc": "2026-11-14T00:00:00.000000Z",
        "UpdatedAtUtc": "2026-11-14T00:00:00.000000Z",
    }
    (directory / "record.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (directory / "credential.dpapi.json").write_text(
        json.dumps(
            {
                "SchemaVersion": 1,
                "Kind": "TradeChannel.DeployCredential",
                "Protected": protected,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def body_text(ws) -> str:
    return t11.body_text(ws)


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
        return "not-ready"
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return 'missing';if(e.disabled)return 'disabled';e.click();return 'ok';})()"
    )
    return str(ws.evaluate(expr) or "")


def set_checked(ws, selector: str, checked: bool) -> bool:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");if(!e)return false;e.checked="
        + ("true" if checked else "false")
        + ";e.dispatchEvent(new Event('change',{bubbles:true}));return true;})()"
    )
    return bool(ws.evaluate(expr))


def value_of(ws, selector: str) -> str:
    expr = (
        "(()=>{const e=document.querySelector("
        + json.dumps(selector)
        + ");return e?String(e.value):'';})()"
    )
    return str(ws.evaluate(expr) or "")


def tick_cloud(ws, pump) -> bool:
    expr = (
        "(()=>{const e=document.querySelector('#wf-deploy-cloud');if(!e)return 'missing';"
        "e.checked=true;e.dispatchEvent(new Event('change',{bubbles:true}));return 'ok';})()"
    )
    ok = str(ws.evaluate(expr) or "") == "ok"
    if ok:
        helpers.wait_js(ws, "true", 0.4, "勾选送达", pump)
    return ok


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--keep-open", action="store_true")
    parser.add_argument("--allow-running", action="store_true")
    args = parser.parse_args()

    exe = Path(args.exe).resolve()
    report_dir = Path(args.report_dir).resolve()
    work = Path(args.work).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(work, ignore_errors=True)
    (work / "data").mkdir(parents=True, exist_ok=True)
    seed_server(work)

    if args.allow_running:
        print("[warn] --allow-running：不检查已有实例（独立数据根，互不干扰）", flush=True)
    else:
        t11.no_running_host()

    checker = Checker()
    report = {"mode": "deploy-use-saved", "exe": str(exe), "work": str(work), "checks": []}
    user_config_before = md5_of(USER_CONFIG)
    code = 0
    process = None
    ws = None
    try:
        process, _port, ws = t11.launch(exe, work, report_dir, "use-saved")
        pump = t11.Pump(process.pid)
        checker.check(
            "页面就绪",
            helpers.wait_js(
                ws, "document.readyState==='complete'&&!!document.querySelector('nav')", 40, "首页", pump
            ),
            body_text(ws)[-200:],
        )
        checker.check(
            "进部署向导",
            click_when_enabled(ws, pump, "#main [data-action=add]") == "ok"
            and helpers.wait_js(ws, "!!document.querySelector('#wf-spec')", 20, "向导", pump),
            body_text(ws)[-300:],
        )
        checker.check("填本机 SSH 地址", t11.set_value(ws, "#wf-spec", SPEC), "")
        checker.check("勾上「已核对云端放行」", tick_cloud(ws, pump), "")
        checker.check(
            "点「开始部署」→ 读本机指纹",
            click_when_enabled(ws, pump, "[data-wf=start]") == "ok",
            "",
        )
        checker.check(
            "读指纹成功后出现「使用这台服务器保存的登录资料」",
            helpers.wait_js(
                ws,
                "!!document.querySelector(" + json.dumps(CHECK) + ")",
                25,
                "DeployUseSaved",
                pump,
            ),
            body_text(ws)[-600:],
        )
        checker.check(
            "文案与旧版一致，且默认勾上",
            helpers.wait_js(
                ws,
                "(()=>{const t=(document.querySelector('#main')||{}).innerText||'';"
                "const e=document.querySelector(" + json.dumps(CHECK) + ");"
                "return !!e&&e.checked&&t.includes('使用这台服务器保存的登录资料');})()",
                10,
                "勾选文案",
                pump,
            ),
            body_text(ws)[-500:],
        )
        checker.check(
            "没有任务级信封时「使用本任务保存的登录资料」不出现",
            str(ws.evaluate("!document.querySelector('#wf-use-task')")).lower() == "true",
            "",
        )

        checker.check("取消勾选不重绘", set_checked(ws, CHECK, False), "")
        checker.check(
            "取消后勾是 false，地址与高级设置还在",
            helpers.wait_js(
                ws,
                "(()=>{const e=document.querySelector(" + json.dumps(CHECK) + ");"
                "const spec=document.querySelector('#wf-spec');"
                "const adv=document.querySelector('[data-wf=deploy-advanced]');"
                "return !!e&&!e.checked&&!!spec&&spec.value.length>0&&!!adv;})()",
                8,
                "取消后状态",
                pump,
            ),
            f"spec={value_of(ws, '#wf-spec')}",
        )
        checker.check("真实数据根的 config.json 未被改动", md5_of(USER_CONFIG) == user_config_before)
        helpers.screenshot(ws, report_dir / "01-use-saved.png", report.get("shots", []))
    except Exception as error:  # noqa: BLE001
        code = 1
        report["error"] = f"{type(error).__name__}: {error}"
        print(f"脚本异常：{report['error']}", flush=True)
    finally:
        report["checks"] = checker.checks
        report["allPassed"] = checker.all_passed
        report["passed"] = sum(1 for check in checker.checks if check["ok"])
        report["total"] = len(checker.checks)
        (report_dir / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        print(f"\n合计 {report['passed']}/{report['total']}；证据 {report_dir}", flush=True)
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
        if not args.keep_open and process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001
                process.kill()
        print(
            f"残留进程：{'有' if process is not None and process.poll() is None else '无'}",
            flush=True,
        )
    return 0 if checker.all_passed and code == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
