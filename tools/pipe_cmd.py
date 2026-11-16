#!/usr/bin/env python3
"""往控制管道发一条命令，打印回包（一行 JSON）。

用法：
  python tools/pipe_cmd.py --name SpiderVPN.847b1ddd08e30882 --json '{"cmd":"ping"}'
  python tools/pipe_cmd.py --find --json '{"cmd":"status"}'     # 自动找唯一一条 SpiderVPN.* 管道
  echo '{"cmd":"deployment-list"}' | python tools/pipe_cmd.py --find

为什么单独写一个：真机冒烟要「和界面同一条协议」地发命令（r45 起就是这么做的），
而 CLI 只覆盖了其中一部分。管道一问一答、按行分帧（见 ipc.rs 的 read_line）。
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
import time


def find_pipe() -> str:
    names = [p for p in glob.glob(r"\\.\pipe\SpiderVPN.*")]
    if not names:
        raise SystemExit("没有找到 SpiderVPN.* 管道：程序没在跑？")
    if len(names) > 1:
        raise SystemExit("找到多条管道，请用 --name 指定：\n" + "\n".join(names))
    return names[0]


def ask(name: str, payload: str, timeout: float = 30.0) -> str:
    # 命名管道用普通 open 即可（Windows 会走 CreateFile），0 = 不缓冲
    with open(name, "r+b", buffering=0) as pipe:
        pipe.write((payload.rstrip("\n") + "\n").encode("utf-8"))
        deadline = time.time() + timeout
        buf = b""
        while time.time() < deadline:
            chunk = pipe.read(65536)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                break
        return buf.decode("utf-8", errors="replace").strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", help=r"完整管道名，如 \\.\pipe\SpiderVPN.xxxx")
    ap.add_argument("--find", action="store_true", help="自动找唯一一条 SpiderVPN.* 管道")
    ap.add_argument("--json", help="要发送的 JSON（缺省从 stdin 读）")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--pretty", action="store_true", help="格式化打印回包")
    args = ap.parse_args()

    name = args.name or (find_pipe() if args.find else None)
    if not name:
        raise SystemExit("要么给 --name，要么给 --find")
    if not name.startswith("\\\\.\\pipe\\"):
        name = "\\\\.\\pipe\\" + name

    payload = args.json if args.json is not None else sys.stdin.read()
    reply = ask(name, payload, args.timeout)
    if args.pretty:
        try:
            print(json.dumps(json.loads(reply), ensure_ascii=False, indent=2))
            return
        except Exception:
            pass
    print(reply)


if __name__ == "__main__":
    main()
