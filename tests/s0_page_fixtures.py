#!/usr/bin/env python3
"""Render the five embedded pages without the product host and compare two DOM dumps."""
from __future__ import annotations

import argparse
import base64
from html.parser import HTMLParser
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import tomllib
import urllib.request

SOURCE = Path(__file__).resolve().parents[1]
PAGES = ("overview", "lines", "records", "deploy", "settings")
LIVE_CONFIG = Path(r"C:\SpiderVPN\data\config.json")
PAGE_MARKERS = {
    "overview": ("夹具线路 A", "通过（HTTP 204）", "使用夹具独立入口", "连接后测量"),
    "lines": ("夹具线路 A", "127.0.0.1:18010", "TDXW.exe", "代理软件（Clash 夹具 127.0.0.1:17895）"),
    "records": ("停止夹具引擎并还原临时代理", "夹具端口已被占用", "失败", "成功"),
    "deploy": ("本版不提供部署与配对", "去线路页导入"),
    "settings": ("Clash 夹具", "当前生效：TUN", r"C:\fixtures\page-root"),
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str | None:
    return sha256_bytes(path.read_bytes()) if path.is_file() else None


class WebSocket:
    """Minimal RFC 6455 client for the local CDP endpoint; standard library only."""

    def __init__(self, url: str) -> None:
        rest = url.removeprefix("ws://")
        host_port, self.resource = rest.split("/", 1)
        self.resource = "/" + self.resource
        host, port = host_port.rsplit(":", 1)
        self.sock = socket.create_connection((host.strip("[]"), int(port)), timeout=5)
        self.sock.settimeout(10)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {self.resource} HTTP/1.1\r\nHost: {host_port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        response = self._read_until(b"\r\n\r\n").decode("latin1")
        if " 101 " not in response.split("\r\n", 1)[0]:
            raise RuntimeError(response)
        expected = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        if expected not in response:
            raise RuntimeError("WebSocket accept 校验失败")
        self.next_id = 1

    def _read_until(self, marker: bytes) -> bytes:
        data = b""
        while marker not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("WebSocket 在握手时关闭")
            data += chunk
        return data

    def _read_exact(self, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise EOFError("WebSocket 在帧中关闭")
            data += chunk
        return data

    def send(self, payload: str) -> None:
        data = payload.encode("utf-8")
        mask = os.urandom(4)
        length = len(data)
        if length < 126:
            header = bytes((0x81, 0x80 | length))
        elif length < 65536:
            header = bytes((0x81, 0x80 | 126)) + struct.pack("!H", length)
        else:
            header = bytes((0x81, 0x80 | 127)) + struct.pack("!Q", length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(data))
        self.sock.sendall(header + mask + masked)

    def recv(self) -> str:
        fragments = b""
        while True:
            first, second = self._read_exact(2)
            final = bool(first & 0x80)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if second & 0x80 else None
            payload = self._read_exact(length)
            if mask:
                payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
            if opcode == 9:
                continue
            if opcode == 8:
                raise EOFError("WebSocket 已关闭")
            fragments += payload
            if final:
                return fragments.decode("utf-8")

    def call(self, method: str, params: dict | None = None) -> dict:
        message_id = self.next_id
        self.next_id += 1
        self.send(json.dumps({"id": message_id, "method": method, "params": params or {}}))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            message = json.loads(self.recv())
            if message.get("id") == message_id:
                if "error" in message:
                    raise RuntimeError(f"{method}: {message['error']}")
                return message.get("result", {})
        raise TimeoutError(method)

    def evaluate(self, expression: str):
        result = self.call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        })
        if result.get("exceptionDetails"):
            raise RuntimeError(result["exceptionDetails"])
        return result.get("result", {}).get("value")

    def close(self) -> None:
        self.sock.close()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_page_target(port: int, expected_url: str, process: subprocess.Popen) -> dict:
    deadline = time.monotonic() + 30
    last_error = None
    direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        try:
            with direct.open(f"http://127.0.0.1:{port}/json/list", timeout=1) as response:
                targets = json.load(response)
            pages = [item for item in targets if item.get("type") == "page" and item.get("url") == expected_url]
            if pages:
                return pages[0]
        except Exception as exc:
            last_error = repr(exc)
        if process.poll() is not None and process.returncode != 0:
            raise RuntimeError(f"Edge 提前退出：{process.returncode}; {last_error}")
        time.sleep(0.1)
    raise TimeoutError(f"CDP 页面未就绪：{last_error}")
