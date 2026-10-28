#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HALLS 1.0.1 通关辅助（单文件版，仅依赖 Python 标准库）

原理：
    游戏在进入菜单后会把这一局的地图先生成好，地图结构里保存着
        +0x70 / +0x74  出口的世界坐标（两个 f32，world = (格+0.5) * 2.0）
        +0x58 / +0x60  出生点格子坐标
    本脚本把出口坐标改成出生点坐标，并在出生点周围挖空一片区域。
    之后你正常按 Enter 开新游戏，人一出生就站在出口上。

用法：
    1) 打开 halls.exe，停在主菜单（不用点 NEW GAME）
    2) 运行本脚本
    3) 回游戏按 Enter 开始，直接通关
"""
import ctypes
import os
import struct
import subprocess
import sys
import threading
import time
from ctypes import wintypes

APP = "HALLS 1.0.1"
TARGET = "halls.exe"
SIGNATURE_CELLS = 1024          # 256 * 256 bit
ROOM_RADIUS = 12                # 出生点周围挖空的半径（格）

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
HANDLE = ctypes.c_void_p
PROCESS_ALL = 0x0400 | 0x0010 | 0x0020 | 0x0008  # QUERY|VM_READ|VM_OPERATION|VM_WRITE

k32.OpenProcess.restype = HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.ReadProcessMemory.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CloseHandle.argtypes = [HANDLE]
k32.CreateToolhelp32Snapshot.restype = HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]


class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_char * 260)]


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_ulonglong), ("AllocationBase", ctypes.c_ulonglong),
                ("AllocationProtect", wintypes.DWORD), ("pad", wintypes.DWORD),
                ("RegionSize", ctypes.c_ulonglong), ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
                ("pad2", wintypes.DWORD)]


k32.VirtualQueryEx.argtypes = [HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]


def say(msg="", end="\n"):
    print(msg, end=end, flush=True)


# ------------------------------------------------------------------ process
def find_pid(name=TARGET):
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if not snap or snap == HANDLE(-1).value:
        return None
    e = PROCESSENTRY32()
    e.dwSize = ctypes.sizeof(e)
    pid = None
    ok = k32.Process32First(snap, ctypes.byref(e))
    while ok:
        if e.szExeFile.decode("mbcs", "ignore").lower() == name.lower():
            pid = e.th32ProcessID
            break
        ok = k32.Process32Next(snap, ctypes.byref(e))
    k32.CloseHandle(snap)
    return pid


def read(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t(0)
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return None
    return buf.raw[:got.value]


def write(h, addr, data):
    n = ctypes.c_size_t(0)
    ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), data, len(data), ctypes.byref(n))
    return bool(ok) and n.value == len(data)


# ------------------------------------------------------------- map scanning
def scan_maps(h):
    """Find Map structs: u64 1024, <ptr>, u64 1024, u64 256, u64 256."""
    found = []
    pat = struct.pack("<Q", SIGNATURE_CELLS)
    addr, mbi = 0, MBI()
    limit = 1 << 47
    scanned = 0
    while addr < limit and scanned < (2 << 30):
        if not k32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            addr += 0x1000
            continue
        base, size = mbi.BaseAddress, mbi.RegionSize
        if (mbi.State == 0x1000 and mbi.Protect in (0x04, 0x08, 0x40, 0x80, 0x02, 0x20)
                and size < (64 << 20)):
            d = read(h, base, size)
            if d:
                scanned += len(d)
                i = d.find(pat)
                while i != -1:
                    if i + 40 <= len(d):
                        q = struct.unpack_from("<5Q", d, i)
                        if (0x10000 < q[1] < 0x7FFFFFFFFFFF and q[2] == SIGNATURE_CELLS
                                and q[3] == 256 and q[4] == 256):
                            found.append((base + i, d[i:i + 0x88], q[1]))
                    i = d.find(pat, i + 8)
        addr = base + size
    return found


def map_info(buf):
    ax, ay = struct.unpack_from("<QQ", buf, 0x58)
    fx, fy = struct.unpack_from("<2f", buf, 0x70)
    sc, = struct.unpack_from("<f", buf, 0x7C)
    if not (0.5 < sc < 100):
        sc = 2.0
    ex, ey = int(round(fx / sc - 0.5)), int(round(fy / sc - 0.5))
    return ax, ay, ex, ey, sc


# ------------------------------------------------------------------- patch
def patch(h, cands, radius=ROOM_RADIUS):
    ok = 0
    for addr, buf, ptr in cands:
        ax, ay, ex, ey, sc = map_info(buf)
        if write(h, addr + 0x70, struct.pack("<2f", (ax + 0.5) * sc, (ay + 0.5) * sc)):
            ok += 1
        say("    地图结构 %#012x : 出口 (%d,%d) -> (%d,%d)   出生点 (%d,%d)"
            % (addr, ex, ey, ax, ay, ax, ay))

    if radius and cands:
        addr, buf, ptr = cands[0]
        ax, ay, _, _, _ = map_info(buf)
        words = read(h, ptr, SIGNATURE_CELLS * 8)
        if words:
            words = list(struct.unpack("<1024Q", words))
            n = 0
            for y in range(max(0, ay - radius), min(256, ay + radius + 1)):
                for x in range(max(0, ax - radius), min(256, ax + radius + 1)):
                    i = y * 256 + x
                    if (words[i >> 6] >> (i & 63)) & 1:
                        words[i >> 6] &= ~(1 << (i & 63))
                        n += 1
            write(h, ptr, struct.pack("<1024Q", *words))
            say("    已挖空出生点周围 %dx%d 的区域（%d 面墙）"
                % (2 * radius + 1, 2 * radius + 1, n))
    return ok


def guard(pid, addrs, seconds=90):
    """Keep the exit pinned to the spawn point for a while after we return."""
    h = k32.OpenProcess(PROCESS_ALL, False, pid)
    if not h:
        return
    end = time.time() + seconds
    tick = 0
    while time.time() < end:
        time.sleep(0.5)
        tick += 1
        for addr in list(addrs):
            buf = read(h, addr + 0x58, 0x30)
            if not buf or len(buf) < 0x28:
                continue
            ax, ay = struct.unpack_from("<QQ", buf, 0)
            fx, fy = struct.unpack_from("<2f", buf, 0x18)
            sc, = struct.unpack_from("<f", buf, 0x24)
            if not (0.5 < sc < 100):
                sc = 2.0
            if abs(fx - (ax + 0.5) * sc) > 0.01 or abs(fy - (ay + 0.5) * sc) > 0.01:
                write(h, addr + 0x70, struct.pack("<2f", (ax + 0.5) * sc, (ay + 0.5) * sc))
        if tick % 8 == 0:  # 每 4 秒找一次新出现的地图结构
            for addr, buf, ptr in scan_maps(h):
                if addr not in addrs:
                    addrs.append(addr)
                    patch(h, [(addr, buf, ptr)], radius=0)
    k32.CloseHandle(h)


# --------------------------------------------------------------------- main
def main():
    say("=" * 58)
    say(" %s  通关辅助" % APP)
    say("=" * 58)
    say()

    pid = find_pid()
    if not pid:
        say("[!] 没有找到正在运行的 halls.exe。")
        here = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False)
                                               else __file__))
        exe = os.path.join(here, TARGET)
        if os.path.isfile(exe):
            say("[*] 在脚本目录找到游戏，正在启动...")
            subprocess.Popen([exe], cwd=here, creationflags=0x10)
            time.sleep(3)
            pid = find_pid()
        if not pid:
            say("[!] 请先打开 halls.exe（停在主菜单即可），再运行本工具。")
            return pause(1)
    say("[*] 找到游戏进程 pid=%d" % pid)

    h = k32.OpenProcess(PROCESS_ALL, False, pid)
    if not h:
        say("[!] 打不开进程（权限不足？请用管理员身份运行）")
        return pause(1)

    say("[*] 等待游戏生成地图（停在主菜单等 5 秒左右即可）...")
    cands = []
    for i in range(30):
        cands = scan_maps(h)
        if cands:
            break
        time.sleep(1)
        say("    ...%ds" % (i + 1), end="\r")
    say()

    if not cands:
        say("[!] 30 秒内没有找到地图数据。")
        say("    请确认：游戏窗口已打开，并且停在主菜单或已经开始了一局。")
        k32.CloseHandle(h)
        return pause(1)

    say("[*] 找到 %d 份地图结构，开始写入..." % len(cands))
    ok = patch(h, cands)

    # 读回校验
    fresh = scan_maps(h)
    if fresh:
        ax, ay, ex, ey, sc = map_info(fresh[0][1])
        if (ex, ey) == (ax, ay):
            say("    校验通过：出口 (%d,%d) == 出生点 (%d,%d)" % (ex, ey, ax, ay))
    k32.CloseHandle(h)
    say()

    if ok:
        threading.Thread(target=guard, args=(pid, [c[0] for c in cands]), daemon=True).start()
        say("[√] 完成！现在回到游戏窗口，按 Enter 开始新游戏。")
        say("    你会直接出生在出口上，立刻通关。")
        say()
        say("    （后台守护 90 秒，期间地图若被重新生成会自动再补一次）")
        return pause(0)
    say("[!] 写入失败，可能是权限问题。请右键“以管理员身份运行”再试。")
    return pause(1)


def pause(code):
    say()
    try:
        if not sys.stdin or not sys.stdin.isatty():
            return code
    except Exception:
        return code
    try:
        input("按 Enter 关闭本窗口...")
    except Exception:
        time.sleep(3)
    return code


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())
