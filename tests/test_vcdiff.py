"""Unit tests for the strict RFC 3284 decoder."""

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, os.path.dirname(__file__))

from vcdiff import (DEFAULT_CODE_TABLE, MAX_TARGET_BYTES, VcdiffError, decode)
from venc import MAGIC, WindowBuilder, stream, vint


# ---------------------------------------------------------------------------
# Integer encoding
# ---------------------------------------------------------------------------

class TestVarint:
    def test_roundtrip_lengths(self):
        for n in [0, 1, 127, 128, 16383, 16384, 2097151, 2097152,
                  (1 << 32) - 1, 1 << 32, (1 << 64) - 1]:
            assert vint(n) is not None

    def test_nonminimal_leading_zero_rejected_with_offset(self):
        # 0x80 0x01 encodes 1, but 1's minimal form is the single byte 0x01.
        body = b"\x80\x01" + b"\x00" + vint(0) * 3
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        # raw layout: 5 header + 1 indicator + 1 delta-len = 7, target int at 7
        assert ei.value.offset == 7

    def test_truncated_varint_reports_end_offset(self):
        body = b"\x81\x80"                # target-length int never terminates
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert ei.value.offset == len(MAGIC + win)

    def test_64bit_overflow_rejected(self):
        body = b"\x00" + vint(0) * 3 + b"\x81" + b"\x80" * 9 + b"\x01"
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError):
            decode(MAGIC + win)

    def test_nonminimal_integer_in_section_length_rejected(self):
        # body: target_len=0, Delta_Indicator=0, data-length then encoded
        # as 0x80 0x00 (= 0, non-minimal).
        body = vint(0) + b"\x00" + b"\x80\x00" + vint(0) + vint(0)
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "non-minimal" in ei.value.message

    def test_nonminimal_integer_in_address_rejected(self):
        src = b"abcd"
        inst = bytes([20])                  # COPY size 4 SELF implicit
        addr = b"\x80\x00"                  # address 0, non-minimal
        body = vint(4) + b"\x00" + vint(0) + vint(len(inst)) + vint(len(addr))
        body += inst + addr
        win = b"\x01" + vint(4) + vint(0) + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win, src)
        assert "non-minimal" in ei.value.message

    def test_explicit_zero_instruction_size_rejected(self):
        # Opcode 19 = COPY size-coded; follow with size int 0.
        inst = bytes([19, 0])
        body = vint(4) + b"\x00" + vint(0) + vint(len(inst)) + vint(0) + inst
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "positive" in ei.value.message

    def test_here_encoded_zero_points_at_here_rejected(self):
        src = b"abcd"
        wb = WindowBuilder(len(src))
        wb.add(b"XY")                      # here = 6
        wb.inst.append(35)                 # COPY size-coded mode HERE
        wb.inst += vint(2)
        wb.addr += vint(0)                 # addr = here - 0 = 6 == here
        with pytest.raises(VcdiffError) as ei:
            decode(stream(wb.window_bytes(1, len(src), 0, target_len=4)), src)
        assert "has not been generated" in ei.value.message

    def test_source_segment_at_nonzero_position(self):
        src = b"..abcdef.."
        wb = WindowBuilder(6)
        wb.do_copy(4, 2, src[2:8], mode=0)
        res = decode(stream(wb.window_bytes(1, 6, 2)), src)
        assert res.target == b"cdef"
        seg = res.windows[0].to_json()["source"]
        assert seg["absolute_range"] == [2, 8]


# ---------------------------------------------------------------------------
# Default code table
# ---------------------------------------------------------------------------

class TestCodeTable:
    def test_known_entries(self):
        assert DEFAULT_CODE_TABLE[0] == (2, 0, 0, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[1] == (1, 0, 0, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[2] == (1, 1, 0, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[18] == (1, 17, 0, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[19] == (3, 0, 0, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[20] == (3, 4, 0, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[34] == (3, 18, 0, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[35] == (3, 0, 1, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[147] == (3, 0, 8, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[162] == (3, 18, 8, 0, 0, 0)
        assert DEFAULT_CODE_TABLE[163] == (1, 1, 0, 3, 4, 0)
        assert DEFAULT_CODE_TABLE[165] == (1, 1, 0, 3, 6, 0)
        assert DEFAULT_CODE_TABLE[246] == (1, 4, 0, 3, 4, 8)
        assert DEFAULT_CODE_TABLE[247] == (3, 4, 0, 1, 1, 0)
        assert DEFAULT_CODE_TABLE[255] == (3, 4, 8, 1, 1, 0)

    def test_no_unused_holes_in_default_table(self):
        # Every index 0..255 executes at least one real instruction.
        for idx, entry in enumerate(DEFAULT_CODE_TABLE):
            assert entry[0] in (1, 2, 3), idx


# ---------------------------------------------------------------------------
# RFC 3284 section 3 worked example (hand-built golden bytes)
# ---------------------------------------------------------------------------

def test_rfc_worked_example():
    src = b"abcdefghijklmnop"
    tgt = b"abcdwxyz" + b"efgh" * 4 + b"zzzz"
    inst = bytes([20, 5, 20, 19]) + vint(12) + bytes([0]) + vint(4)
    data = b"wxyz" + b"z"
    addr = vint(0) + vint(4) + vint(24)
    body = vint(len(tgt)) + b"\x00" + vint(len(data)) + vint(len(inst)) + vint(len(addr))
    body += data + inst + addr
    win = b"\x01" + vint(len(src)) + vint(0) + vint(len(body)) + body
    res = decode(MAGIC + win, src)
    assert res.target == tgt
    kinds = [(i.kind, i.size) for i in res.instructions]
    assert kinds == [("COPY", 4), ("ADD", 4), ("COPY", 4), ("COPY", 12), ("RUN", 4)]
    overlap = res.instructions[3]
    assert overlap.mode == "SELF" and overlap.address == 24 and overlap.overlap is True
    assert res.instructions[2].source == "SOURCE"
    assert res.instructions[3].source == "TARGET"
    assert res.windows[0].to_json()["source"]["kind"] == "SOURCE"


# ---------------------------------------------------------------------------
# Address modes
# ---------------------------------------------------------------------------

class TestAddressModes:
    def _decode(self, wb, source=b""):
        return decode(stream(wb.window_bytes(1, len(source), 0)), source)

    def test_self_mode(self):
        src = bytes(range(16))
        wb = WindowBuilder(len(src))
        wb.do_copy(8, 2, src, mode=0)
        res = self._decode(wb, src)
        assert res.target == src[2:10]

    def test_here_mode(self):
        src = bytes(range(10))
        wb = WindowBuilder(len(src))
        wb.add(b"AB")                        # here = 12 for next COPY
        wb.do_copy(4, 6, src, mode=1)        # encoded here-addr = 12-6 = 6
        res = self._decode(wb, src)
        assert res.target == b"AB" + src[6:10]
        assert res.instructions[1].mode == "HERE"

    def test_all_four_near_modes(self):
        src = b"Z" * 32
        wb = WindowBuilder(len(src))
        # Seed near cache with addresses 1, 2, 3, 4 via SELF copies.
        for a in (1, 2, 3, 4):
            wb.do_copy(1, a, src, mode=0)
        wb.do_copy(1, 5, src, mode=2)        # near[0]=1 -> encoded 4
        wb.do_copy(1, 9, src, mode=3)        # near[1]=2 -> encoded 7
        wb.do_copy(1, 6, src, mode=4)        # near[2]=3 -> encoded 3
        wb.do_copy(1, 8, src, mode=5)        # near[3]=4 -> encoded 4
        res = self._decode(wb, src)
        assert res.target == b"Z" * 8
        assert [i.mode for i in res.instructions[4:]] == [
            "NEAR0", "NEAR1", "NEAR2", "NEAR3"]

    def test_all_three_same_modes(self):
        src = b"Q" * 768
        wb = WindowBuilder(len(src))
        wb.do_copy(1, 10, src, mode=0)       # bucket k=0
        wb.do_copy(1, 300, src, mode=0)      # bucket k=1 (300//256)
        wb.do_copy(1, 600, src, mode=0)      # bucket k=2
        wb.do_copy(1, 10, src, mode=6)
        wb.do_copy(1, 300, src, mode=7)
        wb.do_copy(1, 600, src, mode=8)
        res = self._decode(wb, src)
        assert res.target == b"Q" * 6
        assert [i.encoded_address for i in res.instructions[3:]] == [10, 44, 88]
        assert [i.mode for i in res.instructions[3:]] == [
            "SAME0", "SAME1", "SAME2"]

    def test_same_mode_miss_rejected(self):
        # SAME byte 5 in bucket k=0 while slot 5 holds 0 -> addr 0 in a
        # source-less window; copy start at here=0 is ungrown.
        inst = bytes([19]) + vint(4)
        addr = bytes([5])
        body = vint(4) + b"\x00" + vint(0) + vint(len(inst)) + vint(len(addr))
        body += inst + addr
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "has not been generated" in ei.value.message

    def test_near_negative_result_rejected(self):
        # near[0] is 0; HERE/NEAR can only produce nonnegative via valid
        # encoded values, but HERE encoded > here yields a negative address.
        src = b"abc"
        wb = WindowBuilder(len(src))
        wb.do_copy(2, 0, src, mode=0)        # produces 2 bytes; here=5
        # Manually force encoded HERE delta 9 (> here) using mode-1 opcode
        # index 35 (COPY size0 mode1) + size int.
        wb.inst.append(35)
        wb.inst += vint(2)
        wb.addr += vint(9)
        with pytest.raises(VcdiffError) as ei:
            decode(stream(wb.window_bytes(1, len(src), 0)), src)
        assert "negative" in ei.value.message


# ---------------------------------------------------------------------------
# Dual-instruction opcodes
# ---------------------------------------------------------------------------

class TestDualOpcodes:
    def test_add_copy_pair_sizes4to6(self):
        src = b"".join(bytes([x]) * 8 for x in range(8))
        for csize in (4, 5, 6):
            wb = WindowBuilder(len(src))
            wb.add_copy_pair(b"XY", csize, 0, 0, u_source=src)
            res = decode(stream(wb.window_bytes(1, len(src), 0)), src)
            assert res.target == b"XY" + src[:csize]
            kinds = [i.kind for i in res.instructions]
            assert kinds == ["ADD", "COPY"]

    def test_add_copy_pair_all_here_near_modes(self):
        src = b"S" * 64
        for mode in range(6):
            wb = WindowBuilder(len(src))
            wb.do_copy(4, 8, src, mode=0)    # prime caches / produced bytes
            wb.add_copy_pair(b"Z", 4, 8, mode, u_source=src)
            res = decode(stream(wb.window_bytes(1, len(src), 0)), src)
            assert res.target == b"S" * 4 + b"Z" + b"S" * 4

    def test_add_copy_pair_same_modes(self):
        src = b"S" * 768
        wb = WindowBuilder(len(src))
        wb.do_copy(4, 10, src, mode=0)       # bucket 0
        wb.do_copy(4, 300, src, mode=0)      # bucket 1
        wb.do_copy(4, 600, src, mode=0)      # bucket 2
        wb.add_copy_pair(b"Q", 4, 10, 6, u_source=src)
        wb.add_copy_pair(b"Q", 4, 300, 7, u_source=src)
        wb.add_copy_pair(b"Q", 4, 600, 8, u_source=src)
        res = decode(stream(wb.window_bytes(1, len(src), 0)), src)
        assert res.target == b"S" * 12 + (b"Q" + b"S" * 4) * 3

    def test_copy_add_pair_all_modes(self):
        src = bytes(range(32))
        for mode in range(6):
            wb = WindowBuilder(len(src))
            wb.copy_add_pair(4, mode, 4, b"!", src)
            res = decode(stream(wb.window_bytes(1, len(src), 0)), src)
            assert res.target == src[4:8] + b"!"

    def test_copy_add_pair_same_modes(self):
        src = bytes(range(256)) * 3       # 768 bytes
        wb = WindowBuilder(len(src))
        # Prime the three SAME buckets: 10->bucket0, 300->bucket1, 600->bucket2
        wb.do_copy(1, 10, src, mode=0)
        wb.do_copy(1, 300, src, mode=0)
        wb.do_copy(1, 600, src, mode=0)
        wb.copy_add_pair(4, 6, 10, b"!", src)
        wb.copy_add_pair(4, 7, 300, b"?", src)
        wb.copy_add_pair(4, 8, 600, b"*", src)
        res = decode(stream(wb.window_bytes(1, len(src), 0)), src)
        expected = (src[10:11] + src[300:301] + src[600:601]
                    + src[10:14] + b"!" + src[300:304] + b"?"
                    + src[600:604] + b"*")
        assert res.target == expected
        assert [i.mode for i in (res.instructions[3],
                                 res.instructions[5],
                                 res.instructions[7])] == [
            "SAME0", "SAME1", "SAME2"]
        assert [i.kind for i in res.instructions] == [
            "COPY", "COPY", "COPY", "COPY", "ADD", "COPY", "ADD", "COPY", "ADD"]


# ---------------------------------------------------------------------------
# Overlapping copies
# ---------------------------------------------------------------------------

def test_forward_overlap_must_copy_byte_by_byte():
    src = b""
    wb = WindowBuilder(0)
    wb.add(b"ab")
    wb.do_copy(6, 0, b"", mode=0)           # addr 0 in T == "ab", grow
    res = decode(stream(wb.window_bytes(0)), src)
    assert res.target == b"abababab"        # period-2 expansion


def test_copy_start_at_here_rejected():
    # Source-less window: COPY size 4 SELF address 0; here==0, so the
    # start byte itself has not been generated.  The error offset is the
    # first raw byte of the encoded address field.
    inst = bytes([19]) + vint(4)
    addr = vint(0)
    body = vint(4) + b"\x00" + vint(0) + vint(len(inst)) + vint(len(addr))
    body += inst + addr
    win = b"\x00" + vint(len(body)) + body
    with pytest.raises(VcdiffError) as ei:
        decode(MAGIC + win)
    assert ei.value.offset == len(MAGIC + win) - 1
    assert "has not been generated" in ei.value.message


def test_copy_straddling_source_target_boundary_rejected():
    src = b"abcdef"
    # COPY size 4 at U offset 4: 2 bytes in S, 2 in (empty) T.
    inst = bytes([20])                    # implicit COPY size 4 SELF
    addr = vint(4)
    body = vint(4) + b"\x00" + vint(0) + vint(len(inst)) + vint(len(addr))
    body += inst + addr
    win = b"\x01" + vint(6) + vint(0) + vint(len(body)) + body
    with pytest.raises(VcdiffError) as ei:
        decode(MAGIC + win, src)
    assert "straddles" in ei.value.message
    assert ei.value.offset == len(MAGIC + win) - 1


# ---------------------------------------------------------------------------
# Multi-window scenarios: TARGET source + address caches per window
# ---------------------------------------------------------------------------

def test_two_windows_target_source_with_here_copy():
    # Window 0 creates "HELLO WORLD!!"; window 1 uses VCD_TARGET segment
    # [0:11) ("HELLO WORLD") and copies within that TARGET segment.
    w0 = WindowBuilder(0)
    w0.add(b"HELLO WORLD!!")
    w1 = WindowBuilder(11)
    w1.do_copy(5, 6, b"HELLO WORLD", mode=0)   # "WORLD" from TARGET seg
    res = decode(stream(w0.window_bytes(0),
                        w1.window_bytes(2, 11, 0)), b"")
    assert res.target == b"HELLO WORLD!!" + b"WORLD"
    assert res.windows[1].to_json()["source"] == {
        "kind": "TARGET", "segment_size": 11, "segment_position": 0,
        "absolute_range": [0, 11]}
    # U-region label is SOURCE (the segment side of U); origin says it came
    # from the bytes reconstructed by an earlier window.
    assert res.instructions[1].source == "SOURCE"
    assert res.instructions[1].origin == "PRIOR_TARGET"


def test_target_segment_beyond_reconstructed_bytes_rejected():
    w0 = WindowBuilder(0)
    w0.add(b"XY")
    w1 = WindowBuilder(4)
    w1.do_copy(4, 0, b"XY??", mode=0)
    with pytest.raises(VcdiffError) as ei:
        decode(stream(w0.window_bytes(0),
                      w1.window_bytes(2, 4, 0)), b"")
    assert "lies outside" in ei.value.message
    assert ei.value.window_index == 1


def test_address_cache_resets_per_window():
    # Same raw HERE/near encoding in two windows must decode independently.
    src = b"abcdefgh"
    w0 = WindowBuilder(len(src))
    w0.do_copy(4, 0, src, mode=0)
    w0.do_copy(4, 0, src, mode=0)
    w1 = WindowBuilder(len(src))
    w1.do_copy(4, 0, src, mode=0)
    res = decode(stream(w0.window_bytes(1, len(src), 0),
                        w1.window_bytes(1, len(src), 0)), src)
    assert res.target == b"abcd" * 3


# ---------------------------------------------------------------------------
# Feature sample: prior-window TARGET COPY + near cache + failure offset
# ---------------------------------------------------------------------------

def test_feature_sample_prior_target_copy_near_cache_and_failure():
    # Window 0 emits a 16-byte prefix using an overlapping TARGET copy.
    w0 = WindowBuilder(0)
    w0.add(b"abc")
    w0.do_copy(13, 0, b"", mode=0)           # TARGET COPY, overlap
    prefix = w0.target
    assert prefix == b"abc" + b"abc" * 4 + b"a"

    # Window 1 takes the prior window output as its TARGET source segment
    # and exercises the near address cache.
    src_seg = bytes(prefix)
    w1 = WindowBuilder(len(src_seg))
    w1.do_copy(4, 1, src_seg, mode=0)        # near slot <- 1
    w1.do_copy(4, 1, src_seg, mode=2)        # NEAR0 delta 0
    w1.do_copy(4, 5, src_seg, mode=2)        # NEAR0 (now 1) delta 4
    good = stream(w0.window_bytes(0),
                  w1.window_bytes(2, len(src_seg), 0))
    res = decode(good, b"")
    assert res.target == prefix + src_seg[1:5] + src_seg[1:5] + src_seg[5:9]

    # Corrupt the *last* near-mode encoded delta (offset inside the address
    # section) so the COPY start points at a not-yet-generated byte.
    bad = bytearray(good)
    # Locate final address byte: last COPY uses NEAR0 delta 4 -> single 0x04.
    assert bad[-1] == 0x04
    bad[-1] = 0x60                            # delta 96 -> address beyond here
    with pytest.raises(VcdiffError) as ei:
        decode(bytes(bad), b"")
    assert ei.value.window_index == 1
    assert ei.value.offset == len(bad) - 1
    assert "has not been generated" in ei.value.message

    # Decoder retains no partial output from the failed stream.
    assert decode(good, b"").target != b""  # control
    with pytest.raises(VcdiffError):
        decode(bytes(bad), b"")


# ---------------------------------------------------------------------------
# Header / indicator policy
# ---------------------------------------------------------------------------

class TestHeaderPolicy:
    def test_bad_magic(self):
        with pytest.raises(VcdiffError) as ei:
            decode(b"\x00" * 8)
        assert ei.value.offset == 0

    def test_bad_version_byte(self):
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC[:3] + b"\x01\x00")
        assert "version" in ei.value.message

    def test_secondary_decompress_rejected(self):
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC[:3] + b"\x00\x01")
        assert "VCD_DECOMPRESS" in ei.value.message

    def test_codetable_rejected(self):
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC[:3] + b"\x00\x02")
        assert "code table" in ei.value.message

    def test_reserved_header_bits(self):
        with pytest.raises(VcdiffError):
            decode(MAGIC[:3] + b"\x00\x04")

    def test_window_both_source_bits_rejected(self):
        body = vint(0) + b"\x00" + vint(0) * 3
        win = b"\x03" + vint(1) + vint(0) + vint(len(body)) + body
        with pytest.raises(VcdiffError):
            decode(MAGIC + win, b"x")

    def test_delta_datacomp_rejected(self):
        body = vint(0) + b"\x01" + vint(0) * 3
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "VCD_DATACOMP" in ei.value.message

    def test_source_segment_outside_dictionary(self):
        body = vint(0) + b"\x00" + vint(0) * 3
        win = b"\x01" + vint(5) + vint(0) + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win, b"abc")
        assert "dictionary" in ei.value.message


# ---------------------------------------------------------------------------
# Section lengths / truncation / trailing bytes
# ---------------------------------------------------------------------------

class TestStructural:
    def _empty_window(self, data_len=0, inst_len=0, addr_len=0,
                      payload=b""):
        body = vint(0) + b"\x00" + vint(data_len) + vint(inst_len) + vint(addr_len)
        body += payload
        return b"\x00" + vint(len(body)) + body

    def test_declared_sections_exceed_window(self):
        body = vint(0) + b"\x00" + vint(2) + vint(2) + vint(2)
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "exceed" in ei.value.message

    def test_trailing_bytes_in_window(self):
        body = vint(0) + b"\x00" + vint(1) + vint(0) + vint(0) + b"\xaa"
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "trailing" in ei.value.message

    def test_unconsumed_data_bytes_rejected(self):
        # ADD of 1 byte claims the section fully; instead emit RUN-less junk:
        # use ADD opcode index 2 (implicit size 1) but declare 2 data bytes.
        body = vint(1) + b"\x00" + vint(2) + vint(1) + vint(0) + b"AB" + bytes([2])
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "trailing" in ei.value.message

    def test_unconsumed_address_bytes_rejected(self):
        src = b"abcdef"
        inst = bytes([20])                  # implicit COPY size 4 SELF
        addr = vint(0) + vint(0)            # one extra address integer
        body = vint(4) + b"\x00" + vint(0) + vint(len(inst)) + vint(len(addr))
        body += inst + addr
        win = b"\x01" + vint(6) + vint(0) + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win, src)
        assert "address section" in ei.value.message

    def test_produced_length_mismatch(self):
        # Declare target length 5 but one ADD of 1.
        body = vint(5) + b"\x00" + vint(1) + vint(1) + vint(0) + b"X" + bytes([2])
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "produced 1" in ei.value.message

    def test_window_delta_length_too_big(self):
        body = vint(0) + b"\x00" + vint(0) * 3
        win = b"\x00" + vint(len(body) + 3) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win)
        assert "exceeds remaining" in ei.value.message

    @pytest.mark.parametrize("cut", range(5, 6))
    def test_truncated_header(self, cut):
        with pytest.raises(VcdiffError):
            decode(MAGIC[:cut - 0])

    def test_every_prefix_is_rejected(self):
        src = b"abcdefghij"
        wb = WindowBuilder(len(src))
        wb.add(b"XY")
        wb.do_copy(4, 2, src, mode=0)
        wb.run(3, ord("z"))
        full = stream(wb.window_bytes(1, len(src), 0))
        # No proper prefix of a valid stream may decode successfully.
        for cut in range(0, len(full)):
            with pytest.raises(VcdiffError):
                decode(full[:cut], src)

    def test_no_windows_rejected(self):
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC)
        assert "no windows" in ei.value.message


# ---------------------------------------------------------------------------
# Limits: window count and output size
# ---------------------------------------------------------------------------

class TestLimits:
    def test_more_than_eight_windows_rejected(self):
        body = vint(0) + b"\x00" + vint(0) * 3
        win = b"\x00" + vint(len(body)) + body
        with pytest.raises(VcdiffError) as ei:
            decode(MAGIC + win * 9)
        assert "more than 8" in ei.value.message
        assert ei.value.window_index == 8
    def test_exactly_eight_windows_ok(self):
        body = vint(0) + b"\x00" + vint(0) * 3
        win = b"\x00" + vint(len(body)) + body
        res = decode(MAGIC + win * 8)
        assert len(res.windows) == 8

    def test_output_at_limit_accepted(self):
        n = MAX_TARGET_BYTES
        wb = WindowBuilder(0)
        wb.run(n, 0x41)
        res = decode(stream(wb.window_bytes(0)))
        assert len(res.target) == n

    def test_output_one_byte_over_limit_rejected(self):
        n = MAX_TARGET_BYTES + 1
        wb = WindowBuilder(0)
        wb.run(n, 0x41)
        with pytest.raises(VcdiffError) as ei:
            decode(stream(wb.window_bytes(0)))
        assert "524288" in ei.value.message

    def test_limit_accumulates_across_windows(self):
        w0 = WindowBuilder(0)
        w0.run(MAX_TARGET_BYTES - 2, 0x41)
        w1 = WindowBuilder(0)
        w1.add(b"ABC")                       # 3 bytes -> one over
        with pytest.raises(VcdiffError):
            decode(stream(w0.window_bytes(0), w1.window_bytes(0)))


# ---------------------------------------------------------------------------
# Fuzz: random instruction sequences against the reference builder
# ---------------------------------------------------------------------------

def test_fuzz_roundtrip():
    rng = random.Random(20261003)
    for trial in range(60):
        src = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        wb = WindowBuilder(len(src))
        steps = rng.randrange(1, 12)
        for _ in range(steps):
            choice = rng.randrange(3)
            if choice == 0:
                wb.add(bytes(rng.randrange(256) for _ in range(rng.randrange(1, 20))))
            elif choice == 1:
                wb.run(rng.randrange(1, 12), rng.randrange(256))
            else:
                here = len(src) + wb.produced
                if here == 0:
                    wb.add(b"x")
                    continue
                addr = rng.randrange(here)
                if addr < len(src):
                    # RFC section 3: a copy must stay fully inside S...
                    max_size = min(30, len(src) - addr)
                else:
                    # ...or fully inside T; forward overlap is permitted.
                    max_size = 30
                size = rng.randrange(1, max_size + 1)
                # Choose an address mode that encodes cleanly here.
                modes = [0, 1]
                for j in range(4):
                    if addr >= wb.near[j]:
                        modes.append(2 + j)
                mode = rng.choice(modes)
                wb.do_copy(size, addr, src, mode=mode)
        res = decode(stream(wb.window_bytes(1 if src else 0,
                                            len(src), 0)), src)
        assert res.target == bytes(wb.target), trial
