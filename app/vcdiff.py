"""Strict decoder for the VCDIFF delta format (RFC 3284), basic format only.

Acceptance policy of this checker (deliberately narrow):

* the RFC 3284 default instruction code table must be in effect
  (``VCD_CODETABLE`` must be clear);
* secondary compression must be disabled (``VCD_DECOMPRESS`` in the header
  must be clear, and every window ``Delta_Indicator`` must be zero);
* at most 8 windows per stream;
* decoded output is capped at 512 KiB.

Every parse error reports the *first* raw (file) byte offset at which the
input became invalid.  When an error is raised no partial target output is
retained by :func:`decode`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

MAGIC = b"\xd6\xc3\xc4"

VCD_DECOMPRESS = 0x01
VCD_CODETABLE = 0x02

VCD_SOURCE = 0x01
VCD_TARGET = 0x02

VCD_DATACOMP = 0x01
VCD_INSTCOMP = 0x02
VCD_ADDRCOMP = 0x04

NOOP = 0
ADD = 1
RUN = 2
COPY = 3

MAX_WINDOWS = 8
MAX_TARGET_BYTES = 512 * 1024

MODE_NAMES = ("SELF", "HERE", "NEAR0", "NEAR1", "NEAR2", "NEAR3",
              "SAME0", "SAME1", "SAME2")


class VcdiffError(ValueError):
    """A malformed or unsupported VCDIFF stream.

    ``offset`` is the first raw byte position where decoding failed;
    ``window_index`` is the 0-based window being decoded, if applicable.
    """

    def __init__(self, message: str, offset: int, window_index: int = -1):
        super().__init__(message)
        self.message = message
        self.offset = offset
        self.window_index = window_index

    def __str__(self) -> str:  # pragma: no cover - trivial
        if self.window_index >= 0:
            return "%s (window %d, raw offset %d)" % (
                self.message, self.window_index, self.offset)
        return "%s (raw offset %d)" % (self.message, self.offset)


# ---------------------------------------------------------------------------
# Default instruction code table (RFC 3284 section 5.6)
# ---------------------------------------------------------------------------

def _build_default_code_table() -> Tuple[Tuple[int, int, int, int, int, int], ...]:
    # Each entry: (inst1, size1, mode1, inst2, size2, mode2)
    t: List[List[int]] = [[NOOP, 0, 0, NOOP, 0, 0] for _ in range(256)]

    t[0] = [RUN, 0, 0, NOOP, 0, 0]                       # index 0
    for size in range(0, 18):                            # indices 1..18
        t[1 + size] = [ADD, size, 0, NOOP, 0, 0]

    idx = 19
    for mode in range(9):                                # 9 * 16 = 144 entries
        for size in (0,) + tuple(range(4, 19)):          # size 0, 4..18
            t[idx] = [COPY, size, mode, NOOP, 0, 0]
            idx += 1
    assert idx == 163

    for mode in range(6):                                # lines 12..17
        for a_size in range(1, 5):
            for c_size in range(4, 7):
                t[idx] = [ADD, a_size, 0, COPY, c_size, mode]
                idx += 1
    for mode in (6, 7, 8):                               # lines 18..20
        for a_size in range(1, 5):
            t[idx] = [ADD, a_size, 0, COPY, 4, mode]
            idx += 1
    assert idx == 247
    for mode in range(9):                                # line 21
        t[idx] = [COPY, 4, mode, ADD, 1, 0]
        idx += 1
    assert idx == 256
    return tuple(tuple(row) for row in t)  # type: ignore[return-value]


DEFAULT_CODE_TABLE = _build_default_code_table()

# ---------------------------------------------------------------------------
# Evidence records
# ---------------------------------------------------------------------------


@dataclass
class InstructionEvidence:
    order: int                 # global instruction order across all windows
    window: int                # 0-based window index
    kind: str                  # "ADD" | "RUN" | "COPY"
    size: int
    # ADD: payload bytes; RUN: the repeated byte; COPY: resolved source bytes
    data: bytes = b""
    run_byte: Optional[int] = None
    # COPY-only evidence:
    mode: Optional[str] = None
    encoded_address: Optional[int] = None  # raw value taken from the addr section
    address: Optional[int] = None          # address inside U (source+target)
    u_offset: Optional[int] = None         # start of the copied run inside U
    target_offset: Optional[int] = None    # target-relative start (== "here")
    source: Optional[str] = None           # U-region: "SOURCE" segment | "TARGET"
    origin: Optional[str] = None           # "DICTIONARY" | "PRIOR_TARGET" |
    #                                      # "CURRENT_TARGET"
    overlap: bool = False                  # copy runs into bytes produced
    #                                      # by the same instruction

    def to_json(self) -> dict:
        d = {
            "order": self.order,
            "window": self.window,
            "kind": self.kind,
            "size": self.size,
        }
        if self.kind == "ADD":
            d["data_hex"] = self.data.hex()
        elif self.kind == "RUN":
            d["byte"] = self.run_byte
            d["byte_hex"] = ("%02x" % self.run_byte) if self.run_byte is not None else None
        else:
            d["mode"] = self.mode
            d["encoded_address"] = self.encoded_address
            d["address"] = self.address
            d["u_offset"] = self.u_offset
            d["target_offset"] = self.target_offset
            d["source"] = self.source
            d["data_hex"] = self.data.hex()
            d["origin"] = self.origin
            d["overlap"] = self.overlap
        return d


@dataclass
class WindowEvidence:
    index: int
    win_indicator: int
    source_kind: Optional[str]          # "SOURCE" / "TARGET" / None
    source_segment_size: int
    source_segment_position: int
    target_window_length: int
    # Absolute coordinates inside the final reconstructed target file:
    src_abs_start: int = 0
    src_abs_end: int = 0
    target_abs_start: int = 0
    target_abs_end: int = 0
    u_size: int = 0
    raw_start: int = 0
    raw_end: int = 0

    def to_json(self) -> dict:
        seg = None
        if self.source_kind is not None:
            seg = {
                "kind": self.source_kind,
                "segment_size": self.source_segment_size,
                "segment_position": self.source_segment_position,
                "absolute_range": [self.src_abs_start, self.src_abs_end],
            }
        return {
            "index": self.index,
            "source": seg,
            "target_range": [self.target_abs_start, self.target_abs_end],
            "target_window_length": self.target_window_length,
            "raw_window_range": [self.raw_start, self.raw_end],
        }


# ---------------------------------------------------------------------------
# Byte reader
# ---------------------------------------------------------------------------


class _Reader:
    """Cursor over the raw delta stream (or a bounded window of it).

    All readers share the full buffer so that ``pos`` is always a global
    raw-file offset; ``end`` bounds a window or a single section so that
    truncation inside a section is detected precisely.
    """

    __slots__ = ("buf", "pos", "end", "window_index")

    def __init__(self, buf: bytes, start: int = 0, end: Optional[int] = None):
        self.buf = buf
        self.pos = start
        self.end = len(buf) if end is None else end
        self.window_index = -1

    def eof(self) -> bool:
        return self.pos >= self.end

    def remaining(self) -> int:
        return self.end - self.pos

    def byte(self) -> int:
        if self.pos >= self.end:
            raise VcdiffError("unexpected end of stream while reading a byte",
                              self.end, self.window_index)
        v = self.buf[self.pos]
        self.pos += 1
        return v

    def take(self, n: int, what: str) -> bytes:
        if n < 0:
            raise VcdiffError("%s has negative length %d" % (what, n),
                              self.pos, self.window_index)
        if n > self.remaining():
            raise VcdiffError(
                "unexpected end of stream while reading %s: need %d byte(s), "
                "%d remain" % (what, n, self.remaining()),
                self.end, self.window_index)
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def integer(self, what: str = "integer") -> int:
        """Read one RFC 3284 variable-length unsigned integer.

        Non-minimal encodings (leading zero groups, trailing ``0x80`` bytes)
        are rejected, as are encodings that overflow 64 bits.
        """
        start = self.pos
        value = 0
        digits = 0
        while True:
            if self.pos >= self.end:
                raise VcdiffError(
                    "unexpected end of stream while reading %s" % what,
                    self.end, self.window_index)
            b = self.buf[self.pos]
            self.pos += 1
            digits += 1
            value = (value << 7) | (b & 0x7F)
            if value > 0xFFFFFFFFFFFFFFFF:
                raise VcdiffError(
                    "%s exceeds 64-bit range" % what, start, self.window_index)
            if not (b & 0x80):
                break
            if digits > 10:
                raise VcdiffError(
                    "%s exceeds 64-bit range" % what, start, self.window_index)

        # Minimal-encoding check.  Digits are big-endian base-128, so a
        # redundant leading digit must carry payload zero (e.g. 0x80 0x01
        # encodes 1, which must be the single byte 0x01).  A non-zero first
        # payload digit already forces value >= 128**(digits-1), so no
        # other non-canonical form exists.
        if digits >= 2 and (self.buf[start] & 0x7F) == 0:
            raise VcdiffError(
                "non-minimal encoding of %s (leading zero digit)" % what,
                start, self.window_index)
        return value


# ---------------------------------------------------------------------------
# Address cache (per window)
# ---------------------------------------------------------------------------


class _AddressCache:
    def __init__(self, s_near: int = 4, s_same: int = 3):
        self.s_near = s_near
        self.s_same = s_same
        self.near = [0] * s_near
        self.same = [0] * (s_same * 256)
        self.next_slot = 0

    def update(self, addr: int) -> None:
        if self.s_near > 0:
            self.near[self.next_slot] = addr
            self.next_slot = (self.next_slot + 1) % self.s_near
        if self.s_same > 0:
            self.same[addr % (self.s_same * 256)] = addr

    def decode(self, mode: int, here: int, encoded: int) -> int:
        if mode == 0:
            return encoded
        if mode == 1:
            return here - encoded
        if 2 <= mode <= 1 + self.s_near:
            return self.near[mode - 2] + encoded
        # same modes
        m = mode - (2 + self.s_near)
        if not (0 <= m < self.s_same) or not (0 <= encoded <= 255):
            raise AssertionError("invalid same-cache mode")
        return self.same[m * 256 + encoded]


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


@dataclass
class DecodeResult:
    target: bytes
    windows: List[WindowEvidence] = field(default_factory=list)
    instructions: List[InstructionEvidence] = field(default_factory=list)
    sha256_hex: str = ""
    raw_length: int = 0


def _check(cond: bool, msg: str, r: _Reader) -> None:
    if not cond:
        raise VcdiffError(msg, r.pos, r.window_index)


def decode(delta: bytes, dictionary: bytes = b"") -> DecodeResult:
    """Decode a basic-format VCDIFF ``delta`` against ``dictionary``.

    Raises :class:`VcdiffError` on any invalid, unsupported or truncated
    input.  The returned evidence describes every window and instruction.
    """
    r = _Reader(delta)

    magic = r.take(3, "magic bytes")
    if magic != MAGIC:
        raise VcdiffError("bad VCDIFF magic bytes; expected D6 C3 C4", 0)
    header4 = r.byte()
    _check(header4 == 0, "unsupported header version byte %d (expected 0)"
           % header4, r)
    hdr = r.byte()
    _check((hdr & 0xFC) == 0,
           "reserved Hdr_Indicator bits 2-7 must be zero", r)
    if hdr & VCD_DECOMPRESS:
        raise VcdiffError(
            "secondary compression is not supported (VCD_DECOMPRESS set)",
            r.pos, r.window_index)
    if hdr & VCD_CODETABLE:
        raise VcdiffError(
            "application-defined code tables are not supported; only the "
            "RFC 3284 default code table is accepted",
            r.pos, r.window_index)

    target = bytearray()
    windows: List[WindowEvidence] = []
    instructions: List[InstructionEvidence] = []
    instr_order = 0

    win_count = 0
    while not r.eof():
        win_count += 1
        r.window_index = win_count - 1
        if win_count > MAX_WINDOWS:
            raise VcdiffError(
                "stream contains more than %d windows" % MAX_WINDOWS,
                r.pos, r.window_index)
        instr_order = _decode_window(
            r, dictionary, target, windows, instructions, instr_order)

    if not windows:
        raise VcdiffError("delta contains no windows", r.pos)

    import hashlib
    out = bytes(target)
    return DecodeResult(
        target=out,
        windows=windows,
        instructions=instructions,
        sha256_hex=hashlib.sha256(out).hexdigest(),
        raw_length=len(delta),
    )


def _decode_window(r: _Reader, dictionary: bytes, target: bytearray,
                   windows: List[WindowEvidence],
                   instructions: List[InstructionEvidence],
                   instr_order: int) -> int:
    wi = r.window_index
    win_raw_start = r.pos

    indicator = r.byte()
    _check((indicator & 0xFC) == 0,
           "reserved Win_Indicator bits 2-7 must be zero", r)
    _check((indicator & (VCD_SOURCE | VCD_TARGET)) !=
           (VCD_SOURCE | VCD_TARGET),
           "Win_Indicator must not set both VCD_SOURCE and VCD_TARGET", r)

    source_kind: Optional[str]
    src_seg_size = src_seg_pos = 0
    src_abs_start = src_abs_end = 0
    u_source = b""
    segment_origin: Optional[str] = None

    if indicator & VCD_SOURCE:
        source_kind = "SOURCE"
        segment_origin = "DICTIONARY"
        src_seg_size = r.integer("source segment size")
        src_seg_pos = r.integer("source segment position")
        _check(src_seg_size <= len(dictionary),
               "source segment size %d exceeds dictionary length %d"
               % (src_seg_size, len(dictionary)), r)
        _check(src_seg_pos + src_seg_size <= len(dictionary),
               "source segment [%d,%d) lies outside the %d-byte dictionary"
               % (src_seg_pos, src_seg_pos + src_seg_size, len(dictionary)), r)
        u_source = dictionary[src_seg_pos:src_seg_pos + src_seg_size]
        src_abs_start = src_seg_pos
        src_abs_end = src_seg_pos + src_seg_size
    elif indicator & VCD_TARGET:
        source_kind = "TARGET"
        segment_origin = "PRIOR_TARGET"
        src_seg_size = r.integer("source segment size")
        src_seg_pos = r.integer("source segment position")
        _check(src_seg_pos + src_seg_size <= len(target),
               "TARGET source segment [%d,%d) lies outside the %d bytes "
               "reconstructed from earlier windows"
               % (src_seg_pos, src_seg_pos + src_seg_size, len(target)), r)
        u_source = bytes(target[src_seg_pos:src_seg_pos + src_seg_size])
        src_abs_start = src_seg_pos
        src_abs_end = src_seg_pos + src_seg_size
    else:
        source_kind = None

    delta_len_pos = r.pos
    delta_len = r.integer("length of delta encoding")
    win_raw_end = delta_len_pos  # overwritten after bounds check
    _check(delta_len <= r.remaining(),
           "delta encoding length %d exceeds remaining stream (%d bytes)"
           % (delta_len, r.remaining()), r)
    win_end = r.pos + delta_len
    win_raw_end = win_end

    win = _Reader(r.buf, r.pos, win_end)
    win.window_index = wi
    target_len = win.integer("target window length")
    _check(win.remaining() >= 1,
           "unexpected end of window: missing Delta_Indicator", win)
    delta_indicator = win.byte()
    if delta_indicator != 0:
        bits = []
        if delta_indicator & VCD_DATACOMP:
            bits.append("VCD_DATACOMP")
        if delta_indicator & VCD_INSTCOMP:
            bits.append("VCD_INSTCOMP")
        if delta_indicator & VCD_ADDRCOMP:
            bits.append("VCD_ADDRCOMP")
        if delta_indicator & 0xF8:
            bits.append("reserved")
        raise VcdiffError(
            "secondary compression not supported (Delta_Indicator bits: %s)"
            % ",".join(bits),
            win.pos, wi)

    data_len = win.integer("length of data for ADDs and RUNs")
    inst_len = win.integer("length of instructions section")
    addr_len = win.integer("length of addresses for COPYs")
    sections_total = data_len + inst_len + addr_len
    _check(sections_total <= win.remaining(),
           "declared section lengths (%d data + %d instructions + %d "
           "addresses) exceed the %d byte(s) left in the window"
           % (data_len, inst_len, addr_len, win.remaining()), win)
    _check(sections_total == win.remaining(),
           "window has %d trailing byte(s) after its three sections"
           % (win.remaining() - sections_total), win)

    # Bounded, global-offset views of each section (error offsets stay
    # absolute positions in the raw stream).
    data_base = win.pos
    inst_base = data_base + data_len
    addr_base = inst_base + inst_len
    sections_end = addr_base + addr_len

    target_abs_start = len(target)
    _check(target_abs_start + target_len <= MAX_TARGET_BYTES,
           "decoded output would exceed the %d-byte limit (window requests "
           "%d more byte(s) at target offset %d)"
           % (MAX_TARGET_BYTES, target_len, target_abs_start), win)

    evidence = WindowEvidence(
        index=wi,
        win_indicator=indicator,
        source_kind=source_kind,
        source_segment_size=src_seg_size,
        source_segment_position=src_seg_pos,
        target_window_length=target_len,
        src_abs_start=src_abs_start,
        src_abs_end=src_abs_end,
        target_abs_start=target_abs_start,
        target_abs_end=target_abs_start + target_len,
        u_size=len(u_source),
        raw_start=win_raw_start,
        raw_end=win_raw_end,
    )

    # Build U only conceptually: COPYs are resolved against either the
    # source segment bytes or the window-local target bytes.
    t = bytearray()                       # window-local target
    cache = _AddressCache(4, 3)

    # Bounded global-offset cursors for each of the three sections, so any
    # error offset is an absolute position in the raw stream.
    dr = _Reader(r.buf, data_base, inst_base)
    dr.window_index = wi
    ir = _Reader(r.buf, inst_base, addr_base)
    ir.window_index = wi
    ar = _Reader(r.buf, addr_base, sections_end)
    ar.window_index = wi

    s_len = len(u_source)

    produced = 0
    while not ir.eof():
        opcode = ir.byte()
        entry = DEFAULT_CODE_TABLE[opcode]
        i1, sz1, md1, i2, sz2, md2 = entry

        # Reject code table entries that would be invalid to execute. The
        # default table itself is valid, but an explicit guard keeps the
        # "illegal code table index" requirement enforceable.
        if opcode >= len(DEFAULT_CODE_TABLE):  # pragma: no cover - byte range
            raise VcdiffError("illegal code table index %d" % opcode,
                              inst_base + ir.pos - 1, wi)

        for (inst_type, size, mode) in ((i1, sz1, md1), (i2, sz2, md2)):
            if inst_type == NOOP:
                if size != 0 or mode != 0:
                    raise VcdiffError(
                        "code index %d has malformed NOOP slot" % opcode,
                        inst_base + ir.pos - 1, wi)
                continue

            if size == 0:
                size = ir.integer("instruction size")
                _check(size > 0,
                       "instruction size must be positive (got %d)" % size,
                       ir)
            _check(size <= MAX_TARGET_BYTES,
                   "instruction size %d exceeds output limit" % size, ir)

            if inst_type == ADD:
                payload = dr.take(size, "ADD data")
                _check(produced + size <= target_len,
                       "ADD of %d byte(s) overflows declared target window "
                       "length %d" % (size, target_len), dr)
                t.extend(payload)
                instructions.append(InstructionEvidence(
                    order=instr_order, window=wi, kind="ADD", size=size,
                    data=bytes(payload), target_offset=produced))
                instr_order += 1
                produced += size

            elif inst_type == RUN:
                bval = dr.byte()
                _check(produced + size <= target_len,
                       "RUN of %d byte(s) overflows declared target window "
                       "length %d" % (size, target_len), dr)
                t.extend(bytes([bval]) * size)
                instructions.append(InstructionEvidence(
                    order=instr_order, window=wi, kind="RUN", size=size,
                    run_byte=bval, target_offset=produced))
                instr_order += 1
                produced += size

            elif inst_type == COPY:
                _check(0 <= mode <= 8,
                       "illegal COPY address mode %d (default table allows "
                       "0..8)" % mode, ir)
                here = s_len + produced
                addr_field_start = ar.pos
                if mode == 0:
                    encoded = ar.integer("COPY address")
                elif mode == 1:
                    encoded = ar.integer("HERE-relative COPY address")
                elif 2 <= mode <= 5:
                    encoded = ar.integer("near-cache COPY address")
                else:
                    if ar.eof():
                        raise VcdiffError(
                            "unexpected end of addresses section while "
                            "reading same-cache address byte", ar.end, wi)
                    encoded = ar.byte()

                if mode == 0:
                    u_addr = encoded
                elif mode == 1:
                    u_addr = here - encoded
                elif 2 <= mode <= 5:
                    u_addr = cache.near[mode - 2] + encoded
                else:
                    m = mode - 6
                    u_addr = cache.same[m * 256 + encoded]

                # Validate BEFORE cache update so a bad address never
                # pollutes the per-window cache.  "here" is the address of
                # the first byte about to be produced in U.  Semantic COPY
                # failures are attributed to the first raw byte of the
                # encoded address field.
                def fail_addr(msg: str):
                    raise VcdiffError(msg, addr_field_start, wi)

                if u_addr < 0:
                    fail_addr(
                        "COPY address resolves to %d, a negative offset "
                        "(mode %s, encoded %d, here %d)"
                        % (u_addr, MODE_NAMES[mode], encoded, here))
                if produced + size > target_len:
                    fail_addr(
                        "COPY of %d byte(s) overflows declared target window "
                        "length %d" % (size, target_len))
                if u_addr < s_len:
                    # Entirely within S (RFC 3284 section 3: a copied run
                    # must be fully contained in S or in T, never straddling).
                    if u_addr + size > s_len:
                        fail_addr(
                            "COPY of %d byte(s) at U offset %d straddles the "
                            "source/target boundary (source segment is %d "
                            "byte(s))" % (size, u_addr, s_len))
                else:
                    # Starts inside T: the start byte itself must already
                    # exist.  Forward overlap (the run extending up to the
                    # current output point and beyond) is legal and is
                    # resolved byte-by-byte, as in RFC's COPY 12,24 example.
                    if u_addr >= here:
                        fail_addr(
                            "COPY with mode %s points at U offset %d, a byte "
                            "that has not been generated yet (here=%d)"
                            % (MODE_NAMES[mode], u_addr, here))

                copy_start = len(t)
                if u_addr < s_len:
                    t.extend(u_source[u_addr:u_addr + size])
                else:
                    base = u_addr - s_len
                    for k in range(size):
                        # Forward overlap: later iterations read bytes
                        # appended by earlier ones.
                        t.append(t[base + k])
                copied = bytes(t[copy_start:copy_start + size])
                if u_addr < s_len:
                    source_kind_copy = "SOURCE"
                    origin = segment_origin  # DICTIONARY or PRIOR_TARGET
                else:
                    source_kind_copy = "TARGET"
                    origin = "CURRENT_TARGET"
                overlap = (u_addr >= s_len and
                           u_addr + size > s_len + produced)

                cache.update(u_addr)
                instructions.append(InstructionEvidence(
                    order=instr_order, window=wi, kind="COPY", size=size,
                    data=copied, mode=MODE_NAMES[mode],
                    encoded_address=encoded, address=u_addr,
                    u_offset=u_addr, target_offset=produced,
                    source=source_kind_copy, origin=origin,
                    overlap=overlap))
                instr_order += 1
                produced += size
            else:
                raise VcdiffError(
                    "illegal instruction type %d in code table" % inst_type,
                    inst_base, wi)

    _check(dr.eof(),
           "ADD/RUN data section has %d unconsumed trailing byte(s)"
           % dr.remaining(), dr)
    _check(ar.eof(),
           "COPY address section has %d unconsumed trailing byte(s)"
           % ar.remaining(), ar)
    _check(produced == target_len,
           "instruction sequence produced %d byte(s) but target window "
           "length was declared as %d" % (produced, target_len), ir)

    target.extend(t)
    windows.append(evidence)

    r.pos = win_end
    return instr_order
