#!/usr/bin/env python3
"""T-08 命令面契约自检：退出码表、--ping 文案、--diagnose 的 stderr、参数上界。

跑在临时数据根上（复制 fixtures/root-2lines），不碰真实安装。
判定标准来自实施计划 T-08 DoD：
  ① --diagnose 在未连接夹具上 stderr 非空且含目标 host:port
  ② --ping 未连接输出含「未连接」且退出码 = 4
  ⑤ --help 里 --port 上界与界面一致（65532）
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parents[1]


def prepare_root(base: Path) -> Path:
    root = base / "root"
    data = root / "data"
    shutil.copytree(SOURCE / "fixtures" / "root-2lines" / "data" / "lines", data / "lines")
    shutil.copy2(SOURCE / "fixtures" / "root-2lines" / "data" / "config.json", data / "config.json")
    # fixture-a 是标准连接（无 transport 字段），诊断没有可探的 TCP 目标；
    # fixture-b 是兼容连接（tcp），引擎配置里有 vless 中转出站 198.51.100.10:443。
    # 只有选中后者，--diagnose 才会真的去探一个 host:port——这正是 DoD① 要验的路径。
    cfg_path = data / "config.json"
    cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    cfg["selected"] = "fixture-b"
    cfg_path.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    return root


def run(exe: Path, root: Path, args: list[str], timeout: int = 30) -> dict:
    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": f"Software\\SpiderVPN\\tests\\t08-{os.getpid()}-proxy",
        "SPIDERVPN_RUN_KEY": f"Software\\SpiderVPN\\tests\\t08-{os.getpid()}-run",
        "SPIDERVPN_FORCE_NONADMIN": "1",
    })
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [str(exe), *args], env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
        return {
            "args": args,
            "exit": completed.returncode,
            "stdout": completed.stdout.decode("utf-8", "replace"),
            "stderr": completed.stderr.decode("utf-8", "replace"),
            "ms": round((time.perf_counter() - started) * 1000, 1),
            "timedOut": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "args": args, "exit": None,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace"),
            "stderr": (exc.stderr or b"").decode("utf-8", "replace"),
            "ms": round((time.perf_counter() - started) * 1000, 1), "timedOut": True,
        }


def main() -> int:
    exe = Path(sys.argv[1])
    report_dir = Path(sys.argv[2])
    work = Path(sys.argv[3])
    report_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    root = prepare_root(work)

    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    # ⑤ --help：端口上界与界面一致，且退出码表在
    help_run = run(exe, root, ["--help"])
    text = help_run["stdout"]
    check("help 退出 0", help_run["exit"] == 0, f"exit={help_run['exit']}")
    check("help 端口上界 65532", "--port <1..=65532>" in text, text[:200])
    check("help 不再写 65535", "1..=65535" not in text, "仍出现 1..=65535")
    check("help 有退出码表", "退出码：" in text and "用法错误" in text and "冲突" in text, "缺退出码段")
    check("help 说明 7/12 退役", "7（未连接）" in text and "12（配置类）" in text, "缺退役说明")

    # ② --ping：未连接时必须出现「未连接」且退出 4
    ping_run = run(exe, root, ["--ping"], timeout=15)
    check("ping 未连接退出 4", ping_run["exit"] == 4, f"exit={ping_run['exit']} out={ping_run['stdout']!r}")
    check("ping 文案含未连接", "未连接" in ping_run["stdout"], ping_run["stdout"])

    # ① --diagnose：stderr 必须非空且带目标 host:port
    diag_run = run(exe, root, ["--diagnose"], timeout=60)
    # 目标是线路引擎配置里的中转出站（fixture-b 的 vless: 198.51.100.10:443），
    # 不是本机代理端点 127.0.0.1:18020 —— 诊断探的是服务器，不是本地端口。
    endpoint = "198.51.100.10:443"
    check("diagnose 退出 5", diag_run["exit"] == 5, f"exit={diag_run['exit']}")
    check("diagnose stderr 非空", len(diag_run["stderr"].strip()) > 0, repr(diag_run["stderr"][:200]))
    check("diagnose stderr 含 host:port", endpoint in diag_run["stderr"],
          f"endpoint={endpoint} stderr={diag_run['stderr'][:200]!r}")

    # 未配置线路 → 配置类 3；未知参数 → 用法错误 2
    usage_run = run(exe, root, ["--nosuchflag"], timeout=15)
    check("未知参数退出 2", usage_run["exit"] == 2, f"exit={usage_run['exit']}")

    missing_root = work / "root-empty"
    (missing_root / "data").mkdir(parents=True, exist_ok=True)
    noline_run = run(exe, missing_root, ["--diagnose"], timeout=30)
    check("无线路诊断退出 3", noline_run["exit"] == 3, f"exit={noline_run['exit']} out={noline_run['stdout'][:120]!r}")

    passed = sum(1 for c in checks if c["ok"])
    payload = {
        "exe": str(exe),
        "exeSha256": __import__("hashlib").sha256(exe.read_bytes()).hexdigest(),
        "root": str(root),
        "endpoint": endpoint,
        "checks": checks,
        "passed": passed,
        "total": len(checks),
        "allPassed": passed == len(checks),
        "runs": {"help": help_run, "ping": ping_run, "diagnose": diag_run,
                 "unknown": usage_run, "noLine": noline_run},
    }
    out = report_dir / "t08-command-contract.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for c in checks:
        print(("PASS " if c["ok"] else "FAIL ") + c["name"] + " | " + c["detail"][:160])
    print(f"{passed}/{len(checks)} -> {out}")
    return 0 if payload["allPassed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
