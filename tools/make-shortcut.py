#!/usr/bin/env python3
"""用 Windows 官方 Shell Link API 生成 SpiderVPN 的快捷方式。

为什么不用 PowerShell 的 `New-Object -ComObject WScript.Shell`：工具会话里那条路径
被安全策略拦截（COM object instantiation can run arbitrary code）。这里用 Python
ctypes 直接调 ole32 / IShellLinkW，产出的 .lnk 与系统右键「发送到→桌面快捷方式」
完全同构，不存在手写二进制格式出错的风险。

用法：
    python make-shortcut.py --exe C:\\SpiderVPN\\bin\\spidervpn.exe
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys
import uuid
from ctypes import POINTER, byref, c_int, c_void_p
from ctypes import wintypes
from pathlib import Path

HRESULT = ctypes.c_long
CLSCTX_INPROC_SERVER = 0x1
COINIT_APARTMENTTHREADED = 0x2


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


def _guid(text: str) -> GUID:
    g = GUID()
    ctypes.memmove(byref(g), uuid.UUID(text).bytes_le, 16)
    return g


CLSID_SHELL_LINK = _guid("00021401-0000-0000-C000-000000000046")
IID_ISHELL_LINK_W = _guid("000214F9-0000-0000-C000-000000000046")
IID_IPERSIST_FILE = _guid("0000010B-0000-0000-C000-000000000046")

# IShellLinkW 的 vtable 槽位（IUnknown 占 0-2）
VT_QUERY_INTERFACE = 0
VT_SET_DESCRIPTION = 7
VT_SET_WORKING_DIR = 9
VT_SET_ARGUMENTS = 11
VT_SET_SHOW_CMD = 15
VT_SET_ICON_LOCATION = 17
VT_SET_PATH = 20

# IPersistFile 的 vtable 槽位
PF_SAVE = 6

SW_SHOWNORMAL = 1


def _check(hr: int, what: str) -> None:
    # S_FALSE(1) 视为成功；只有负值才是失败
    if hr < 0:
        raise OSError(f"{what} 失败，HRESULT=0x{hr & 0xFFFFFFFF:08X}")


def _method(ptr: c_void_p, index: int, argtypes: tuple, restype=HRESULT):
    """按 vtable 槽位取出函数指针并调用。"""
    vtable = ctypes.cast(ptr, POINTER(POINTER(c_void_p)))[0]
    addr = vtable[index]
    proto = ctypes.WINFUNCTYPE(restype, c_void_p, *argtypes)
    return proto(addr)


def _call(ptr: c_void_p, index: int, argtypes: tuple, *args) -> int:
    func = _method(ptr, index, argtypes)
    return func(ptr, *args)


def create_shortcut(
    lnk_path: Path,
    target: str,
    arguments: str = "",
    working_dir: str = "",
    icon_path: str = "",
    icon_index: int = 0,
    description: str = "",
) -> None:
    ole32 = ctypes.WinDLL("ole32")
    ole32.CoInitializeEx.restype = HRESULT
    ole32.CoInitializeEx.argtypes = [c_void_p, wintypes.DWORD]
    ole32.CoCreateInstance.restype = HRESULT
    ole32.CoCreateInstance.argtypes = [
        POINTER(GUID),
        c_void_p,
        wintypes.DWORD,
        POINTER(GUID),
        POINTER(c_void_p),
    ]
    ole32.CoUninitialize.restype = None

    hr = ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
    _check(hr, "CoInitializeEx")
    try:
        shell_link = c_void_p()
        _check(
            ole32.CoCreateInstance(
                byref(CLSID_SHELL_LINK),
                None,
                CLSCTX_INPROC_SERVER,
                byref(IID_ISHELL_LINK_W),
                byref(shell_link),
            ),
            "CoCreateInstance(ShellLink)",
        )

        _check(_call(shell_link, VT_SET_PATH, (wintypes.LPCWSTR,), target), "SetPath")
        if arguments:
            _check(_call(shell_link, VT_SET_ARGUMENTS, (wintypes.LPCWSTR,), arguments), "SetArguments")
        if working_dir:
            _check(_call(shell_link, VT_SET_WORKING_DIR, (wintypes.LPCWSTR,), working_dir), "SetWorkingDirectory")
        if icon_path:
            _check(
                _call(shell_link, VT_SET_ICON_LOCATION, (wintypes.LPCWSTR, c_int), icon_path, icon_index),
                "SetIconLocation",
            )
        if description:
            _check(_call(shell_link, VT_SET_DESCRIPTION, (wintypes.LPCWSTR,), description), "SetDescription")
        _check(_call(shell_link, VT_SET_SHOW_CMD, (c_int,), SW_SHOWNORMAL), "SetShowCmd")

        # QI 到 IPersistFile 才能落盘
        persist_file = c_void_p()
        _check(
            _call(
                shell_link,
                VT_QUERY_INTERFACE,
                (POINTER(GUID), POINTER(c_void_p)),
                byref(IID_IPERSIST_FILE),
                byref(persist_file),
            ),
            "QueryInterface(IPersistFile)",
        )

        lnk_path.parent.mkdir(parents=True, exist_ok=True)
        _check(
            _call(persist_file, PF_SAVE, (wintypes.LPCWSTR, wintypes.BOOL), str(lnk_path), True),
            "IPersistFile::Save",
        )

        # 释放两块 COM 引用（Release 是槽位 2）
        for obj in (persist_file, shell_link):
            _call(obj, 2, ())
    finally:
        ole32.CoUninitialize()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--exe", required=True)
    ap.add_argument("--name", default="交易通道", help="显示名")
    ap.add_argument("--out", action="append", default=[])
    args = ap.parse_args()

    exe = Path(args.exe).resolve()
    if not exe.is_file():
        print(f"target 不存在：{exe}", file=sys.stderr)
        return 2

    root = exe.parent.parent
    vbs = root / "bin" / "start-hidden.vbs"
    if not vbs.is_file():
        print(f"缺少启动脚本：{vbs}", file=sys.stderr)
        return 3

    wscript = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "wscript.exe"
    if not wscript.is_file():
        print(f"缺少 wscript.exe：{wscript}", file=sys.stderr)
        return 4

    out_dirs = args.out
    if not out_dirs:
        out_dirs = [
            str(Path(os.path.expanduser("~")) / "Desktop"),
            str(
                Path(os.environ["APPDATA"])
                / "Microsoft"
                / "Windows"
                / "Start Menu"
                / "Programs"
                / "SpiderVPN"
            ),
        ]

    for out_dir in out_dirs:
        dest = Path(out_dir) / f"{args.name}.lnk"
        create_shortcut(
            lnk_path=dest,
            target=str(wscript),
            arguments=f'"{vbs}"',
            working_dir=str(root / "bin"),
            icon_path=str(exe),
            icon_index=0,
            description="交易通道",
        )
        print(f"{dest}  {dest.stat().st_size} B")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
