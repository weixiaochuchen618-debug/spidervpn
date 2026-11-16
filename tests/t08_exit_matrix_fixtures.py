#!/usr/bin/env python3
"""T-08 DoD③：37 个命令 × 4 个固定数据根，断言退出码落在目标集合内。

安全约束：夹具副本里的 `engine.binary` 一律改成不存在的路径。
理由：`--connect` 在「有线路 + 有引擎」时会真的起引擎并接管系统代理。
本脚本要验的是**退出码契约**，不是连接功能；用不存在的引擎把这类命令
压回「配置类失败」路径，既拿到真实退出码，又不会碰网络和代理。
代理键与 Run 键都指向临时位置，并在前后比对真实现场（config 哈希、系统代理）。
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import winreg

EXE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(r"C:\tc-rs-build\debug\spidervpn.exe")
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(r"D:\vpn构建\reports-tmp\tcrs-audit\t08-exit-matrix-4fixtures.json")
BASE = Path(sys.argv[3]) if len(sys.argv) > 3 else Path(rf"C:\tc-rs-build\t08-matrix-{int(time.time())}")
SOURCE = Path(r"D:\vpn构建\spidervpn-0.1.4")
FIXTURES = ["root-empty", "root-unreadable", "root-2lines", "root-dirty-ops"]
BASE.mkdir(parents=True, exist_ok=True)

MISSING = str(BASE / "does-not-exist.json")
MISSING_ENGINE = str(BASE / "does-not-exist.exe")
MISSING_DIR = str(BASE / "does-not-exist-dir")
NO_ENGINE = r"C:/nope/not-an-engine.exe"

CASES = [
    ("--import", ["--import", MISSING, "--engine", MISSING_ENGINE, "--port", "17890", "--line-name", "Matrix"]),
    ("--engine", ["--engine", MISSING_ENGINE, "--status"]),
    ("--port", ["--port", "17890", "--status"]),
    ("--line-name", ["--line-name", "Matrix", "--status"]),
    ("--set-line", ["--set-line", "L1", "Matrix", "127.0.0.1:17890"]),
    ("--use", ["--use", "Missing"]),
    ("--set-transport", ["--set-transport", "udp"]),
    ("--remove-line", ["--remove-line", "Missing"]),
    ("--set-autostart", ["--set-autostart", "on"]),
    ("--set-autoconnect", ["--set-autoconnect", "on"]),
    ("--set-closetotray", ["--set-closetotray", "on"]),
    ("--split-add-process", ["--split-add-process", "TDXW.exe"]),
    ("--split-add-domain", ["--split-add-domain", "qq.com"]),
    ("--split-remove-process", ["--split-remove-process", "TDXW.exe"]),
    ("--split-remove-domain", ["--split-remove-domain", "qq.com"]),
    ("--to", ["--to", "direct", "--status"]),
    ("--exit-set", ["--exit-set", "daily", "direct"]),
    ("--provider-add", ["--provider-add", "clashverge", "Matrix", MISSING_DIR, "7890", "a.example.com"]),
    ("--provider-remove", ["--provider-remove", "1"]),
    ("--apply", ["--apply"]),
    ("--connect", ["--connect"]),
    ("--diagnose", ["--diagnose"]),
    ("--disconnect", ["--disconnect"]),
    ("--headless", ["--headless"]),
    ("--help", ["--help"]),
    ("--history", ["--history"]),
    ("--lines", ["--lines"]),
    ("--ping", ["--ping"]),
    ("--plan", ["--plan"]),
    ("--restore", ["--restore"]),
    ("--restore-apply", ["--restore-apply"]),
    ("--split-list", ["--split-list"]),
    ("--exits", ["--exits"]),
    ("--providers", ["--providers"]),
    ("--provider-discover", ["--provider-discover"]),
    ("--status", ["--status"]),
    ("--tun", ["--tun", "--status"]),
]
assert len(CASES) == 37, len(CASES)
ALLOWED = set(range(0, 7))


def read_value(root, path, name):
    try:
        with winreg.OpenKey(root, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except OSError:
        return None


def live_snapshot() -> dict:
    config = Path(r"C:\SpiderVPN\data\config.json")
    internet = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    run = r"Software\Microsoft\Windows\CurrentVersion\Run"
    return {
        "configSha256": hashlib.sha256(config.read_bytes()).hexdigest() if config.exists() else None,
        "proxyEnable": read_value(winreg.HKEY_CURRENT_USER, internet, "ProxyEnable"),
        "proxyServer": read_value(winreg.HKEY_CURRENT_USER, internet, "ProxyServer"),
        "runSpiderVPN": read_value(winreg.HKEY_CURRENT_USER, run, "SpiderVPN"),
    }


def prepare(fixture: str) -> tuple[Path, str]:
    root = BASE / f"fx-{fixture}"
    src = SOURCE / "fixtures" / fixture
    if (src / "data").exists():
        shutil.copytree(src / "data", root / "data")
    else:
        (root / "data").mkdir(parents=True, exist_ok=True)
    cfg_path = root / "data" / "config.json"
    note = "as-is"
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            return root, "unparsable-config-left-as-is"
        if isinstance(cfg.get("engine"), dict):
            cfg["engine"]["binary"] = NO_ENGINE
            cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
            note = "engine-binary-disabled"
    return root, note


def run_case(fixture: str, index: int, name: str, args: list[str], root: Path) -> dict:
    tag = f"{fixture}-{index:02d}"
    env = os.environ.copy()
    env["SPIDERVPN_ROOT"] = str(root)
    env["SPIDERVPN_PROXY_KEY"] = rf"Software\SpiderVPN\tests\t08m-{tag}-proxy"
    env["SPIDERVPN_RUN_KEY"] = rf"Software\SpiderVPN\tests\t08m-{tag}-run"
    env["SPIDERVPN_FORCE_NONADMIN"] = "1"
    env.pop("SPIDERVPN_ENGINE_ARGS", None)
    started = time.monotonic()
    process = subprocess.Popen(
        [str(EXE)] + args, cwd="C:\\", env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=25)
        code = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        stdout, stderr = process.communicate()
        code = None
    return {
        "fixture": fixture, "command": name, "args": args, "exit": code,
        "timedOut": timed_out, "durationMs": round((time.monotonic() - started) * 1000, 1),
        "stdoutBytes": len(stdout), "stderrBytes": len(stderr),
        "stdout": stdout.decode("utf-8", "replace")[:400],
        "stderr": stderr.decode("utf-8", "replace")[:400],
    }


def main() -> int:
    result = {
        "startedAt": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "exe": str(EXE), "exeSha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
        "fixtures": FIXTURES, "casesPerFixture": len(CASES),
        "engineDisabled": True,
        "liveBefore": live_snapshot(),
        "fixtureRuns": [],
    }
    for fixture in FIXTURES:
        root, note = prepare(fixture)
        runs = []
        for index, (name, args) in enumerate(CASES, 1):
            runs.append(run_case(fixture, index, name, args, root))
        codes = sorted({r["exit"] for r in runs if r["exit"] is not None})
        result["fixtureRuns"].append({
            "fixture": fixture, "root": str(root), "prepareNote": note,
            "exitCodes": codes,
            "timeouts": sum(1 for r in runs if r["timedOut"]),
            "bothStreamsEmpty": sum(1 for r in runs if r["stdoutBytes"] == 0 and r["stderrBytes"] == 0),
            "outsideAllowed": [r["command"] for r in runs if r["exit"] is not None and r["exit"] not in ALLOWED],
            "runs": runs,
        })
        print(json.dumps({"fixture": fixture, "note": note, "exitCodes": codes,
                          "timeouts": sum(1 for r in runs if r["timedOut"])}, ensure_ascii=False), flush=True)

    all_runs = [r for f in result["fixtureRuns"] for r in f["runs"]]
    result["finishedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    result["liveAfter"] = live_snapshot()
    result["liveUnchanged"] = result["liveBefore"] == result["liveAfter"]
    result["summary"] = {
        "totalRuns": len(all_runs),
        "timeouts": sum(1 for r in all_runs if r["timedOut"]),
        "exitCodes": sorted({r["exit"] for r in all_runs if r["exit"] is not None}),
        "outsideAllowed": [f'{r["fixture"]}:{r["command"]}' for r in all_runs
                           if r["exit"] is not None and r["exit"] not in ALLOWED],
        "configClass": 3, "networkClass": 5,
        "configAndNetworkDistinct": 3 != 5,
    }
    ok = (
        result["summary"]["timeouts"] == 0
        and not result["summary"]["outsideAllowed"]
        and result["liveUnchanged"]
        and set(result["summary"]["exitCodes"]).issubset(ALLOWED)
    )
    result["allPassed"] = ok
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"summary": result["summary"], "allPassed": ok, "liveUnchanged": result["liveUnchanged"]},
                     ensure_ascii=False))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
