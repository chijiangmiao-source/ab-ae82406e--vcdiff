"""Minimal VCDIFF *encoder* used only by the test-suite as a differential
oracle.  It supports every address mode and the dual-instruction opcodes of
the default code table, so the strict decoder can be round-trip fuzzed.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

MAGIC = bytes((0xD6, 0xC3, 0xC4, 0x00, 0x00))
ADD, RUN, COPY = 1, 2, 3


def vint(n: int) -> bytes:
    assert n >= 0
    out = [n & 0x7F]
    n >>= 7
    while n:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    return bytes(reversed(out))


class WindowBuilder:
    def __init__(self, source_len: int):
        self.s_len = source_len
        self.data = bytearray()
        self.inst = bytearray()
        self.addr = bytearray()
        self.produced = 0
        self.near = [0, 0, 0, 0]
        self.same = [0] * (3 * 256)
        self.next_slot = 0
        self.target = bytearray()

    # -- address bookkeeping (mirror of RFC 5.2) --------------------------

    def _cache_update(self, addr: int) -> None:
        self.near[self.next_slot] = addr
        self.next_slot = (self.next_slot + 1) % 4
        self.same[addr % 768] = addr

    def valid_modes(self, size: int, addr: int) -> List[int]:
        modes = [0]
        here = self.s_len + self.produced
        if here - addr >= 0:
            modes.append(1)
        for j in range(4):
            if addr - self.near[j] >= 0 and addr > 0:
                modes.append(2 + j)
        for k in range(3):
            if 0 <= addr % 256 <= 255 and self.same[k * 256 + addr % 256] == addr:
                modes.append(6 + k)
        return modes

    def _emit_addr(self, addr: int, mode: int) -> None:
        here = self.s_len + self.produced
        if mode == 0:
            self.addr += vint(addr)
        elif mode == 1:
            self.addr += vint(here - addr)
        elif 2 <= mode <= 5:
            self.addr += vint(addr - self.near[mode - 2])
        else:
            self.addr.append(addr % 256)
        self._cache_update(addr)

    # -- instructions ------------------------------------------------------

    def add(self, payload: bytes) -> None:
        size = len(payload)
        if size <= 17:
            self.inst.append(1 + size)
        else:
            self.inst.append(1)
            self.inst += vint(size)
        self.data += payload
        self.target += payload
        self.produced += size

    def run(self, size: int, byte: int) -> None:
        self.inst.append(0)
        self.inst += vint(size)
        self.data.append(byte)
        self.target += bytes([byte]) * size
        self.produced += size

    def _copy_opcode(self, size: int, mode: int) -> None:
        implicit = {0: 0, 4: 1, 5: 2, 6: 3, 7: 4, 8: 5, 9: 6, 10: 7,
                    11: 8, 12: 9, 13: 10, 14: 11, 15: 12, 16: 13, 17: 14,
                    18: 15}
        base = 19 + mode * 16
        if size in implicit:
            self.inst.append(base + implicit[size])
        else:
            self.inst.append(base)
            self.inst += vint(size)

    def do_copy(self, size: int, addr: int, u_source: bytes,
                mode: Optional[int] = None) -> None:
        m = mode if mode is not None else 0
        self._copy_opcode(size, m)
        self._emit_addr(addr, m)
        for k in range(size):
            p = addr + k
            if p < self.s_len:
                self.target.append(u_source[p])
            else:
                self.target.append(self.target[p - self.s_len])
        self.produced += size

    # -- dual instruction opcodes ------------------------------------------

    def add_copy_pair(self, add_payload: bytes, copy_size: int,
                      copy_addr: int, copy_mode: int,
                      u_source: bytes = b"") -> None:
        a = len(add_payload)
        assert 1 <= a <= 4
        if copy_mode <= 5:
            assert 4 <= copy_size <= 6
            idx = 163 + copy_mode * 12 + (a - 1) * 3 + (copy_size - 4)
        else:
            assert copy_size == 4
            idx = 235 + (copy_mode - 6) * 4 + (a - 1)
        self.inst.append(idx)
        self.data += add_payload
        self.target += add_payload
        self.produced += a
        self._emit_addr(copy_addr, copy_mode)
        for k in range(copy_size):
            p = copy_addr + k
            if p < self.s_len:
                self.target.append(u_source[p])
            else:
                self.target.append(self.target[p - self.s_len])
        self.produced += copy_size

    def copy_add_pair(self, copy_size: int, copy_mode: int, copy_addr: int,
                      add_payload: bytes, u_source: bytes) -> None:
        assert copy_size == 4 and len(add_payload) == 1
        idx = 247 + copy_mode
        self.inst.append(idx)
        self._emit_addr(copy_addr, copy_mode)
        for k in range(copy_size):
            p = copy_addr + k
            if p < self.s_len:
                self.target.append(u_source[p])
            else:
                self.target.append(self.target[p - self.s_len])
        self.produced += copy_size
        self.data += add_payload
        self.target += add_payload
        self.produced += 1

    # -- assembly ----------------------------------------------------------

    def window_bytes(self, indicator: int = 0, seg_size: int = 0,
                     seg_pos: int = 0, target_len: Optional[int] = None,
                     data: Optional[bytes] = None,
                     inst: Optional[bytes] = None,
                     addr: Optional[bytes] = None,
                     win_indicator: Optional[int] = None) -> bytes:
        d = bytes(self.data if data is None else data)
        i = bytes(self.inst if inst is None else inst)
        a = bytes(self.addr if addr is None else addr)
        tlen = self.produced if target_len is None else target_len
        body = vint(tlen) + b"\x00" + vint(len(d)) + vint(len(i)) + vint(len(a)) + d + i + a
        ind = indicator if win_indicator is None else win_indicator
        if ind == 0:
            head = b"\x00"
        else:
            head = bytes([ind]) + vint(seg_size) + vint(seg_pos)
        return head + vint(len(body)) + body


def stream(*windows: bytes) -> bytes:
    return MAGIC + b"".join(windows)
