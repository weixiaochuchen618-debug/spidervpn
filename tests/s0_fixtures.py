#!/usr/bin/env python3
"""Create and verify the four isolated S0 roots. Standard library only."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

SOURCE = Path(__file__).resolve().parents[1]
FIXTURES = SOURCE / "fixtures"
ROOT_NAMES = ("root-empty", "root-unreadable", "root-2lines", "root-dirty-ops")
LIVE_CONFIG = Path(r"C:\SpiderVPN\data\config.json")


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def config(lines: list[dict], selected: str = "") -> dict:
    return {
        "schema": 2,
        "mode": "proxy",
        "auto_start": False,
        "auto_connect": False,
        "close_to_tray": False,
        "selected": selected,
        "lines": lines,
        "exits": {"trade": None, "daily": None},
        "split": {"processes": [], "domains": []},
        "engine": None,
    }


def event(index: int) -> dict:
    return {
        "ts": f"2026-10-30T00:{index // 60:02d}:{index % 60:02d}Z",
        "action": "夹具记录",
        "ok": index % 7 != 0,
        "detail": f"旧格式记录 {index:03d}",
    }


def write_events(root: Path, count: int) -> None:
    path = root / "data" / "logs" / "operations.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for i in range(count):
            f.write(json.dumps(event(i), ensure_ascii=False, separators=(",", ":")) + "\n")


def create() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name in ROOT_NAMES:
        (FIXTURES / name / "data").mkdir(parents=True, exist_ok=True)

    empty_config = FIXTURES / "root-empty" / "data" / "config.json"
    if empty_config.exists():
        raise RuntimeError(f"root-empty 不应含 config.json：{empty_config}")

    (FIXTURES / "root-unreadable" / "data" / "config.json").write_text(
        '{"schema":2,"lines":[\n', encoding="utf-8"
    )

    lines = [
        {"id": "fixture-a", "name": "夹具线路 A", "proxy_endpoint": "127.0.0.1:18010"},
        {"id": "fixture-b", "name": "夹具线路 B", "proxy_endpoint": "127.0.0.1:18020", "transport": "tcp"},
    ]
    two = FIXTURES / "root-2lines"
    write_json(two / "data" / "config.json", config(lines, "fixture-a"))
    engine = json.loads((SOURCE / "tests" / "fixtures" / "engine-no-split.json").read_text(encoding="utf-8"))
    for line in lines:
        write_json(two / "data" / "lines" / f"{line['id']}.json", engine)
    write_events(two, 500)

    dirty = FIXTURES / "root-dirty-ops"
    write_json(dirty / "data" / "config.json", config([]))
    write_events(dirty, 20)

    manifest = {
        "source": str(SOURCE),
        "rootSemantics": "SPIDERVPN_ROOT=<fixture>; data root=<fixture>/data",
        "fixtures": {},
    }
    for name in ROOT_NAMES:
        root = FIXTURES / name
        files = {}
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            files[str(path.relative_to(root)).replace("\\", "/")] = {
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
        manifest["fixtures"][name] = files
    write_json(FIXTURES / "manifest.json", manifest)
    print(json.dumps({"created": list(ROOT_NAMES), "manifest": str(FIXTURES / "manifest.json")}, ensure_ascii=False))


def run_command(exe: Path, root: Path, argument: str, index: int) -> dict:
    env = os.environ.copy()
    env.update({
        "SPIDERVPN_ROOT": str(root),
        "SPIDERVPN_PROXY_KEY": f"Software\\SpiderVPN\\tests\\s0-fixtures-{index}-proxy",
        "SPIDERVPN_RUN_KEY": f"Software\\SpiderVPN\\tests\\s0-fixtures-{index}-run",
        "SPIDERVPN_FORCE_NONADMIN": "1",
    })
    before_config = sha256(root / "data" / "config.json")
    before_ops = sha256(root / "data" / "logs" / "operations.jsonl")
    started = time.perf_counter()
    try:
        p = subprocess.run([str(exe), argument], env=env, capture_output=True, timeout=20)
        result = {
            "command": argument,
            "exit": p.returncode,
            "timedOut": False,
            "durationMs": round((time.perf_counter() - started) * 1000, 1),
            "stdoutBytes": len(p.stdout),
            "stderrBytes": len(p.stderr),
            "stdout": p.stdout.decode("utf-8", errors="replace"),
            "stderr": p.stderr.decode("utf-8", errors="replace"),
        }
    except subprocess.TimeoutExpired as e:
        result = {
            "command": argument,
            "exit": None,
            "timedOut": True,
            "durationMs": round((time.perf_counter() - started) * 1000, 1),
            "stdout": (e.stdout or b"").decode("utf-8", errors="replace"),
            "stderr": (e.stderr or b"").decode("utf-8", errors="replace"),
        }
    result["root"] = str(root)
    result["expectedDataRoot"] = str(root / "data")
    result["rootShown"] = str(root / "data") in result["stdout"]
    result["configUnchanged"] = before_config == sha256(root / "data" / "config.json")
    result["operationsUnchanged"] = before_ops == sha256(root / "data" / "logs" / "operations.jsonl")
    if root.name == "root-unreadable":
        # 损坏 JSON 必须受控失败，而不是落进 GUI；0.1.4 当前返回 12，T-08 才改为目标码 3。
        result["expectedBehavior"] = "controlled-config-error"
        behavior_ok = result["exit"] != 0 and "配置不可用：" in result["stdout"]
    else:
        result["expectedBehavior"] = "success"
        behavior_ok = result["exit"] == 0
    result["passed"] = (
        not result["timedOut"] and behavior_ok and result["rootShown"]
        and result["configUnchanged"] and result["operationsUnchanged"]
    )
    return result


def verify(exe: Path, report: Path) -> bool:
    if not exe.is_file():
        raise RuntimeError(f"找不到被测程序：{exe}")
    live_before = sha256(LIVE_CONFIG)
    results = []
    for index, name in enumerate(ROOT_NAMES, 1):
        root = (FIXTURES / name).resolve()
        if FIXTURES.resolve() not in root.parents:
            raise RuntimeError("夹具根越界")
        for argument in ("--status", "--headless"):
            results.append(run_command(exe, root, argument, index))
    payload = {
        "exe": str(exe),
        "exeSha256": sha256(exe),
        "count": len(results),
        "passed": sum(bool(r["passed"]) for r in results),
        "liveConfigBefore": live_before,
        "liveConfigAfter": sha256(LIVE_CONFIG),
        "liveUnchanged": live_before == sha256(LIVE_CONFIG),
        "cases": results,
    }
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: payload[k] for k in ("count", "passed", "liveUnchanged")}, ensure_ascii=False))
    for r in results:
        print(f"{Path(r['root']).name} {r['command']}: exit={r['exit']} rootShown={r['rootShown']} unchanged={r['configUnchanged'] and r['operationsUnchanged']}")
    return payload["passed"] == payload["count"] and payload["liveUnchanged"]


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("create")
    check = sub.add_parser("verify")
    check.add_argument("--exe", type=Path, required=True)
    check.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "create":
        create()
        return 0
    return 0 if verify(args.exe.resolve(), args.report.resolve()) else 1


if __name__ == "__main__":
    sys.exit(main())
