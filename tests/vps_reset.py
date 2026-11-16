#!/usr/bin/env python3
"""验收用 VPS 的检查与重置（只给真机部署验收用）。

重置 = 停 `wg-quick@tc*` 与 `tc*-transport`、删 `/etc/wireguard/tc*.conf`、
删 `inet tc*` 的 nft 表、删 `/etc/tradechannel`。只碰本产品自己的东西。

密码**只从环境变量** `TC_SSH_PASSWORD` 读，不进命令行、不写文件。

用法：
  set TC_SSH_PASSWORD=...
  python tests/vps_reset.py --host 203.0.113.25 --check
  python tests/vps_reset.py --host 203.0.113.25 --reset
"""
from __future__ import annotations

import argparse
import os
import sys

import paramiko

CHECK = r"""
echo "== units =="
systemctl list-units --all --plain --no-legend 'wg-quick@tc*' 'tc*-transport*' 2>/dev/null || true
systemctl list-unit-files --plain --no-legend 'wg-quick@tc*' 'tc*-transport.service' 2>/dev/null || true
echo "== files =="
ls -1 /etc/wireguard/tc*.conf 2>/dev/null || echo no-wg-conf
if [ -d /etc/tradechannel ]; then echo tradechannel-dir-present; else echo no-tradechannel-dir; fi
echo "== ports =="
ss -lun 2>/dev/null | grep ':51820 ' || echo udp-51820-free
ss -ltn 2>/dev/null | grep ':8443 ' || echo tcp-8443-free
echo "== nft =="
nft list tables 2>/dev/null | grep -E ' table inet tc' || echo no-tc-tables
"""

RESET = r"""
# `list-unit-files` 只列模板文件，不列模板实例；正在运行的 `wg-quick@tc*`
# 必须从 `list-units --all` 拿，否则重置会“成功”地把 WireGuard 留在那里。
units=$( { systemctl list-units --all --plain --no-legend 'wg-quick@tc*' 'tc*-transport*' 2>/dev/null
           systemctl list-unit-files --plain --no-legend 'wg-quick@tc*' 'tc*-transport.service' 2>/dev/null; } \
         | awk '{print $1}' | sort -u)
for unit in $units; do
  systemctl stop "$unit" 2>/dev/null || true
  systemctl disable "$unit" 2>/dev/null || true
  systemctl reset-failed "$unit" 2>/dev/null || true
done
rm -f /etc/systemd/system/tc*-transport.service
rm -f /etc/wireguard/tc*.conf /etc/wireguard/tc*.key
# 兜底：单元停止后接口还挂着（配置已删也能出现），按名字只删 tc* 虚拟接口。
for link in $(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^tc[a-z0-9]+$/ {print $2}'); do
  ip link delete "$link" 2>/dev/null || true
done
systemctl daemon-reload
for table in $(nft list tables 2>/dev/null | awk '$2 == "inet" && $3 ~ /^tc/ {print $3}'); do
  nft delete table inet "$table" 2>/dev/null || true
done
rm -rf /etc/tradechannel
echo RESET_OK
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", default="root")
    parser.add_argument("--action", choices=("check", "reset"), default="check")
    args = parser.parse_args()

    password = os.environ.get("TC_SSH_PASSWORD", "")
    if not password:
        raise SystemExit("没有设置 TC_SSH_PASSWORD")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        args.host,
        username=args.user,
        password=password,
        timeout=25,
        banner_timeout=25,
        auth_timeout=25,
    )
    try:
        script = RESET if args.action == "reset" else CHECK
        _stdin, stdout, stderr = client.exec_command(script, timeout=120)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        sys.stdout.write(out)
        if err.strip():
            sys.stderr.write(err)
        if args.action == "reset" and "RESET_OK" not in out:
            return 1
        return 0 if code == 0 else 1
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
